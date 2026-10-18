//! The tunnel data path (FR-020..FR-025): three threads around one UDP link.
//!
//! * `tun->esp`: reads IP packets from the adapter, drops non-IPv4 and
//!   multicast/broadcast, encrypts and sends them.
//! * `udp->tun`: demultiplexes UDP-4500 payloads -- a zero non-ESP marker is
//!   IKE (answers gateway liveness checks, handles DELETE), anything else is
//!   ESP, which is decrypted, replay-checked and written to the adapter.
//! * `timer`: NAT keepalive, DPD probing, gateway-lost detection, SA lifetime.
//!
//! The first thread to see a terminal condition reports an [`ExitReason`];
//! [`DataPath::stop`] joins everything.

use crate::traits::{is_timeout, TunDevice, UdpLink};
use ike::constants::{ExchangeType, PayloadType, ProtocolId};
use ike::esp::{EspInbound, EspOutbound};
use ike::payloads::DeletePayload;
use ike::sa::Initiator;
use ipc_proto::Stats;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const TARGET: &str = "datapath";

/// Liveness and lifetime tunables.
#[derive(Clone, Debug)]
pub struct DataPathConfig {
    pub keepalive: Duration,
    /// Send a DPD probe after this much inbound silence.
    pub dpd_idle: Duration,
    /// Declare the gateway lost if the probe is unanswered this long.
    pub dpd_timeout: Duration,
    /// Retransmit an unanswered probe at this interval.
    pub dpd_retransmit: Duration,
    /// Reconnect after this long (no in-place rekey in v1).
    pub lifetime: Duration,
    /// Granularity of the timer thread and socket polls.
    pub tick: Duration,
}

impl Default for DataPathConfig {
    fn default() -> Self {
        DataPathConfig {
            keepalive: Duration::from_secs(20),
            dpd_idle: Duration::from_secs(30),
            dpd_timeout: Duration::from_secs(30),
            dpd_retransmit: Duration::from_secs(10),
            lifetime: Duration::from_secs(8 * 3600),
            tick: Duration::from_millis(250),
        }
    }
}

/// Why the data path ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    UserStop,
    GatewayLost,
    DeletedByGateway,
    Lifetime,
    TunFailed,
}

#[derive(Default)]
pub struct Counters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub dropped_in: AtomicU64,
    pub dropped_out: AtomicU64,
    pub filtered_out: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> Stats {
        Stats {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            dropped_in: self.dropped_in.load(Ordering::Relaxed),
            dropped_out: self.dropped_out.load(Ordering::Relaxed),
            filtered_out: self.filtered_out.load(Ordering::Relaxed),
        }
    }
}

/// IKE SA state shared by the inbound and timer threads.
struct IkeShared {
    ike: Initiator,
    next_msg_id: u32,
    /// Outstanding DPD probe: (message id, encoded request, first sent, last sent).
    pending_dpd: Option<(u32, Vec<u8>, Instant, Instant)>,
    /// Responder side of the IKE SA (RFC 7296 §2.2): the message id of the
    /// last gateway request we processed and our response to it, re-sent
    /// verbatim if the gateway retransmits that request. `None` until the
    /// gateway's first request, which carries message id 0.
    last_peer_request: Option<(u32, Option<Vec<u8>>)>,
}

pub struct DataPath {
    stop: Arc<AtomicBool>,
    tun: Arc<dyn TunDevice>,
    link: Arc<dyn UdpLink>,
    ike: Arc<Mutex<IkeShared>>,
    exit_rx: Receiver<ExitReason>,
    threads: Vec<JoinHandle<()>>,
    pub counters: Arc<Counters>,
}

fn send_ike(link: &dyn UdpLink, msg: &[u8]) {
    let mut framed = Vec::with_capacity(4 + msg.len());
    framed.extend_from_slice(&[0, 0, 0, 0]);
    framed.extend_from_slice(msg);
    let _ = link.send(&framed);
}

fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

impl DataPath {
    /// Start relaying. Takes ownership of the IKE SA and both ESP halves.
    pub fn start(
        ike: Initiator,
        next_msg_id: u32,
        esp_out: EspOutbound,
        esp_in: EspInbound,
        link: Arc<dyn UdpLink>,
        tun: Arc<dyn TunDevice>,
        cfg: DataPathConfig,
    ) -> DataPath {
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let ike = Arc::new(Mutex::new(IkeShared {
            ike,
            next_msg_id,
            pending_dpd: None,
            last_peer_request: None,
        }));
        let (exit_tx, exit_rx) = channel();
        let epoch = Instant::now();
        let last_rx = Arc::new(AtomicU64::new(0)); // ms since epoch of last authentic inbound

        let threads = vec![
            spawn_outbound(
                stop.clone(),
                tun.clone(),
                link.clone(),
                esp_out,
                counters.clone(),
                exit_tx.clone(),
            ),
            spawn_inbound(
                stop.clone(),
                tun.clone(),
                link.clone(),
                esp_in,
                ike.clone(),
                counters.clone(),
                exit_tx.clone(),
                last_rx.clone(),
                epoch,
                cfg.tick,
            ),
            spawn_timer(
                stop.clone(),
                link.clone(),
                ike.clone(),
                exit_tx,
                last_rx,
                epoch,
                cfg,
            ),
        ];

        DataPath {
            stop,
            tun,
            link,
            ike,
            exit_rx,
            threads,
            counters,
        }
    }

    /// Wait up to `timeout` for the data path to end on its own.
    pub fn wait_exit(&self, timeout: Duration) -> Option<ExitReason> {
        match self.exit_rx.recv_timeout(timeout) {
            Ok(r) => Some(r),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some(ExitReason::TunFailed),
        }
    }

    pub fn stats(&self) -> Stats {
        self.counters.snapshot()
    }

    /// Stop all threads. With `send_delete`, tell the gateway the IKE SA is
    /// gone (FR-024). Returns the final counters.
    pub fn stop(mut self, send_delete: bool) -> Stats {
        self.stop.store(true, Ordering::SeqCst);
        self.tun.shutdown();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        if send_delete {
            let st = self.ike.lock().unwrap();
            if let Ok(del) = st.ike.build_delete(st.next_msg_id) {
                send_ike(self.link.as_ref(), &del);
                info!(target: TARGET, "sent IKE DELETE");
            }
        }
        self.counters.snapshot()
    }
}

fn spawn_outbound(
    stop: Arc<AtomicBool>,
    tun: Arc<dyn TunDevice>,
    link: Arc<dyn UdpLink>,
    mut esp: EspOutbound,
    c: Arc<Counters>,
    exit: Sender<ExitReason>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("tun->esp".into())
        .spawn(move || loop {
            let pkt = match tun.recv() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    if !stop.load(Ordering::SeqCst) {
                        warn!(target: TARGET, error = %e, "adapter read failed");
                        let _ = exit.send(ExitReason::TunFailed);
                    }
                    break;
                }
            };
            if stop.load(Ordering::SeqCst) {
                break;
            }
            // IPv4 only; never tunnel multicast (224/4) or limited broadcast (FR-025).
            if pkt.len() < 20
                || pkt[0] >> 4 != 4
                || (224..=239).contains(&pkt[16])
                || pkt[16..20] == [255; 4]
            {
                c.filtered_out.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match esp.encrypt(4, &pkt) {
                Ok(out) => {
                    if link.send(&out).is_ok() {
                        c.packets_out.fetch_add(1, Ordering::Relaxed);
                        c.bytes_out.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    } else {
                        c.dropped_out.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    // Sequence space exhausted: the SA must be replaced.
                    let _ = exit.send(ExitReason::Lifetime);
                    break;
                }
            }
        })
        .expect("spawn tun->esp")
}

#[allow(clippy::too_many_arguments)]
fn spawn_inbound(
    stop: Arc<AtomicBool>,
    tun: Arc<dyn TunDevice>,
    link: Arc<dyn UdpLink>,
    mut esp: EspInbound,
    ike: Arc<Mutex<IkeShared>>,
    c: Arc<Counters>,
    exit: Sender<ExitReason>,
    last_rx: Arc<AtomicU64>,
    epoch: Instant,
    tick: Duration,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("udp->tun".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !stop.load(Ordering::SeqCst) {
                let n = match link.recv(&mut buf, tick) {
                    Ok(n) => n,
                    Err(e) if is_timeout(&e) => continue,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                };
                let data = &buf[..n];
                if n == 1 && data[0] == 0xff {
                    continue; // NAT keepalive
                }
                if n >= 4 && data[..4] == [0, 0, 0, 0] {
                    if let Some(reason) =
                        handle_ike(&data[4..], &ike, link.as_ref(), &last_rx, epoch)
                    {
                        let _ = exit.send(reason);
                        break;
                    }
                    continue;
                }
                match esp.decrypt(data) {
                    Ok((next_header, inner)) => {
                        last_rx.store(now_ms(epoch), Ordering::Relaxed);
                        if next_header == 4 && !inner.is_empty() && tun.send(&inner).is_ok() {
                            c.packets_in.fetch_add(1, Ordering::Relaxed);
                            c.bytes_in.fetch_add(inner.len() as u64, Ordering::Relaxed);
                        } else if next_header != 59 {
                            // 59 = "no next header" (dummy/TFC packet), silently ignored.
                            c.dropped_in.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        c.dropped_in.fetch_add(1, Ordering::Relaxed);
                        debug!(target: TARGET, error = ?e, len = n, "dropped inbound ESP");
                    }
                }
            }
        })
        .expect("spawn udp->tun")
}

/// Handle an inbound IKE message on the established SA. Returns an exit
/// reason when the gateway deleted the SA.
///
/// An authentic message is not necessarily a fresh one: an on-path attacker
/// can replay anything the gateway sent earlier. So only messages that cannot
/// be replays refresh `last_rx`: the response to the outstanding DPD probe,
/// and a gateway request carrying the next expected message id (RFC 7296
/// §2.2, window of one). A retransmission of the previous request gets the
/// cached response; anything else is dropped.
fn handle_ike(
    msg: &[u8],
    ike: &Mutex<IkeShared>,
    link: &dyn UdpLink,
    last_rx: &AtomicU64,
    epoch: Instant,
) -> Option<ExitReason> {
    let mut st = ike.lock().unwrap();
    let inbound = match st.ike.decrypt_inbound(msg) {
        Ok(m) => m,
        Err(_) => {
            debug!(target: TARGET, "ignored undecryptable IKE message");
            return None;
        }
    };
    if inbound.is_response() {
        if matches!(&st.pending_dpd, Some((id, ..)) if *id == inbound.message_id) {
            last_rx.store(now_ms(epoch), Ordering::Relaxed);
            debug!(target: TARGET, "DPD answered");
            st.pending_dpd = None;
        }
        return None;
    }
    let expected = match &st.last_peer_request {
        None => Some(0),
        Some((id, _)) => id.checked_add(1),
    };
    if expected != Some(inbound.message_id) {
        match &st.last_peer_request {
            Some((id, resp)) if *id == inbound.message_id => {
                if let Some(resp) = resp {
                    send_ike(link, resp);
                }
                debug!(target: TARGET, id, "re-sent response to retransmitted gateway request");
            }
            _ => {
                debug!(target: TARGET, id = inbound.message_id, "dropped gateway request outside the message-id window");
            }
        }
        return None;
    }
    if inbound.exchange != ExchangeType::Informational as u8 {
        debug!(target: TARGET, exchange = inbound.exchange, "ignored gateway request (no rekey support)");
        return None;
    }
    last_rx.store(now_ms(epoch), Ordering::Relaxed);
    let deleted = inbound
        .payloads
        .iter()
        .filter(|p| p.payload_type == PayloadType::Delete as u8)
        .filter_map(|p| DeletePayload::decode(&p.data).ok())
        .any(|d| d.protocol_id == ProtocolId::Ike as u8 || d.protocol_id == ProtocolId::Esp as u8);
    let resp = st
        .ike
        .build_informational_response(inbound.message_id, &[])
        .ok();
    if let Some(resp) = &resp {
        send_ike(link, resp);
    }
    st.last_peer_request = Some((inbound.message_id, resp));
    if deleted {
        info!(target: TARGET, "gateway deleted the SA");
        return Some(ExitReason::DeletedByGateway);
    }
    debug!(target: TARGET, "answered gateway liveness check");
    None
}

fn spawn_timer(
    stop: Arc<AtomicBool>,
    link: Arc<dyn UdpLink>,
    ike: Arc<Mutex<IkeShared>>,
    exit: Sender<ExitReason>,
    last_rx: Arc<AtomicU64>,
    epoch: Instant,
    cfg: DataPathConfig,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("timer".into())
        .spawn(move || {
            let mut last_keepalive = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(cfg.tick);
                let now = Instant::now();
                if now.duration_since(last_keepalive) >= cfg.keepalive {
                    let _ = link.send(&[0xff]);
                    last_keepalive = now;
                }
                if epoch.elapsed() >= cfg.lifetime {
                    info!(target: TARGET, "SA lifetime reached");
                    let _ = exit.send(ExitReason::Lifetime);
                    break;
                }
                let idle = Duration::from_millis(
                    now_ms(epoch).saturating_sub(last_rx.load(Ordering::Relaxed)),
                );
                let mut st = ike.lock().unwrap();
                match &mut st.pending_dpd {
                    Some((_, req, first, last)) => {
                        if now.duration_since(*first) >= cfg.dpd_timeout {
                            warn!(target: TARGET, "gateway did not answer liveness checks");
                            let _ = exit.send(ExitReason::GatewayLost);
                            break;
                        }
                        if now.duration_since(*last) >= cfg.dpd_retransmit {
                            send_ike(link.as_ref(), req);
                            *last = now;
                        }
                    }
                    None if idle >= cfg.dpd_idle => {
                        let id = st.next_msg_id;
                        if let Ok(req) = st.ike.build_informational_request(id, &[]) {
                            st.next_msg_id += 1;
                            send_ike(link.as_ref(), &req);
                            debug!(target: TARGET, id, "sent DPD probe");
                            st.pending_dpd = Some((id, req, now, now));
                        }
                    }
                    None => {}
                }
            }
        })
        .expect("spawn timer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ike::constants::{dh, encr, integ, prf, IdType, TransformType, FLAG_RESPONSE};
    use ike::crypto::{KeyLengths, Prf};
    use ike::message::{Message, RawPayload};
    use ike::payloads::{IdPayload, KePayload, Proposal, SaPayload, Transform};
    use ike::sa::InitiatorConfig;
    use std::io;
    use std::net::SocketAddr;
    use zeroize::Zeroizing;

    /// Records every datagram the data path sends.
    #[derive(Default)]
    struct RecLink(Mutex<Vec<Vec<u8>>>);

    impl UdpLink for RecLink {
        fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
        fn recv(&self, _buf: &mut [u8], _timeout: Duration) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 4500).into())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(([127, 0, 0, 1], 4500).into())
        }
    }

    fn transform(transform_type: TransformType, transform_id: u16, key: Option<u16>) -> Transform {
        Transform {
            transform_type: transform_type as u8,
            transform_id,
            key_length: key,
        }
    }

    /// An initiator holding IKE SA keys (as after IKE_SA_INIT).
    fn keyed_initiator() -> Initiator {
        let proposals = SaPayload {
            proposals: vec![Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Ike as u8,
                spi: vec![],
                transforms: vec![
                    transform(TransformType::Encr, encr::AES_CBC, Some(256)),
                    transform(TransformType::Prf, prf::HMAC_SHA2_256, None),
                    transform(TransformType::Integ, integ::HMAC_SHA2_256_128, None),
                    transform(TransformType::Dh, dh::CURVE25519, None),
                ],
            }],
        };
        let cfg = InitiatorConfig {
            proposals: proposals.clone(),
            dh_group: dh::CURVE25519,
            prf: Prf::HmacSha256,
            key_lengths: KeyLengths {
                prf_key: 32,
                integ_key: 32,
                encr_key: 32,
            },
            idi: IdPayload {
                id_type: IdType::Rfc822Addr as u8,
                id_data: b"client@test".to_vec(),
            },
            psk: Zeroizing::new(b"psk".to_vec()),
        };
        let mut init = Initiator::new(cfg, [0x11; 8], vec![0xAA; 32]);
        init.build_ike_sa_init(&[0x42; 32], &[]);
        let raw = |t: PayloadType, data: Vec<u8>| RawPayload {
            payload_type: t as u8,
            critical: false,
            data,
        };
        let reply = Message {
            initiator_spi: [0x11; 8],
            responder_spi: [0x22; 8],
            exchange_type: ExchangeType::IkeSaInit as u8,
            flags: FLAG_RESPONSE,
            message_id: 0,
            payloads: vec![
                raw(PayloadType::Sa, proposals.encode()),
                raw(
                    PayloadType::Ke,
                    KePayload {
                        dh_group: dh::CURVE25519,
                        key_exchange_data: vec![0x43; 32],
                    }
                    .encode(),
                ),
                raw(PayloadType::Nonce, vec![0xBB; 32]),
            ],
        }
        .to_bytes();
        init.process_ike_sa_init_reply(&reply, &[0x99; 32]).unwrap();
        init
    }

    const STALE: u64 = u64::MAX;

    struct Fixture {
        ike: Mutex<IkeShared>,
        link: RecLink,
        last_rx: AtomicU64,
        epoch: Instant,
    }

    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                ike: Mutex::new(IkeShared {
                    ike: keyed_initiator(),
                    next_msg_id: 5,
                    pending_dpd: None,
                    last_peer_request: None,
                }),
                link: RecLink::default(),
                last_rx: AtomicU64::new(STALE),
                epoch: Instant::now(),
            }
        }

        /// An empty INFORMATIONAL message as the gateway would send it.
        fn gateway_msg(&self, flags: u8, message_id: u32) -> Vec<u8> {
            let st = self.ike.lock().unwrap();
            let keys = st.ike.keys().unwrap();
            ike::sk::encrypt_message(
                st.ike.initiator_spi(),
                st.ike.responder_spi().unwrap(),
                ExchangeType::Informational as u8,
                flags,
                message_id,
                0,
                &[],
                &st.ike.negotiated().unwrap().suite,
                &keys.sk_er,
                &keys.sk_ar,
            )
        }

        /// True if `dgram` is our response to gateway request `message_id`.
        fn is_response_to(&self, dgram: &[u8], message_id: u32) -> bool {
            let st = self.ike.lock().unwrap();
            let keys = st.ike.keys().unwrap();
            let msg = &dgram[4..];
            dgram[..4] == [0, 0, 0, 0]
                && msg[19] & FLAG_RESPONSE != 0
                && msg[20..24] == message_id.to_be_bytes()
                && ike::sk::decrypt_message(
                    msg,
                    &st.ike.negotiated().unwrap().suite,
                    &keys.sk_ei,
                    &keys.sk_ai,
                )
                .is_ok()
        }

        /// Deliver `msg`; returns (refreshed liveness, datagrams sent back).
        fn deliver(&self, msg: &[u8]) -> (bool, Vec<Vec<u8>>) {
            self.last_rx.store(STALE, Ordering::Relaxed);
            let exit = handle_ike(msg, &self.ike, &self.link, &self.last_rx, self.epoch);
            assert_eq!(exit, None);
            let sent = std::mem::take(&mut *self.link.0.lock().unwrap());
            (self.last_rx.load(Ordering::Relaxed) != STALE, sent)
        }
    }

    #[test]
    fn gateway_requests_follow_the_message_id_window() {
        let f = Fixture::new();
        let req0 = f.gateway_msg(0, 0);

        // The gateway's first request carries id 0: processed and answered.
        let (fresh, sent) = f.deliver(&req0);
        assert!(fresh);
        assert_eq!(sent.len(), 1);
        assert!(f.is_response_to(&sent[0], 0));
        let resp0 = sent[0].clone();

        // A retransmission (or replay) of it gets the very same response and
        // is not proof of liveness.
        let (fresh, sent) = f.deliver(&req0);
        assert!(!fresh);
        assert_eq!(sent, vec![resp0.clone()]);

        // A request that skips ahead is outside the window.
        let (fresh, sent) = f.deliver(&f.gateway_msg(0, 2));
        assert!(!fresh);
        assert!(sent.is_empty());

        // The next expected id is processed.
        let (fresh, sent) = f.deliver(&f.gateway_msg(0, 1));
        assert!(fresh);
        assert_eq!(sent.len(), 1);
        assert!(f.is_response_to(&sent[0], 1));

        // An older request is dropped silently.
        let (fresh, sent) = f.deliver(&req0);
        assert!(!fresh);
        assert!(sent.is_empty());
    }

    #[test]
    fn first_gateway_request_must_have_id_zero() {
        let f = Fixture::new();
        let (fresh, sent) = f.deliver(&f.gateway_msg(0, 1));
        assert!(!fresh);
        assert!(sent.is_empty());
    }

    #[test]
    fn only_the_answer_to_the_outstanding_probe_proves_liveness() {
        let f = Fixture::new();
        // A response to an earlier exchange (e.g. a replayed IKE_AUTH reply)
        // while no probe is outstanding.
        let (fresh, sent) = f.deliver(&f.gateway_msg(FLAG_RESPONSE, 1));
        assert!(!fresh);
        assert!(sent.is_empty());

        let now = Instant::now();
        f.ike.lock().unwrap().pending_dpd = Some((5, vec![], now, now));
        let (fresh, _) = f.deliver(&f.gateway_msg(FLAG_RESPONSE, 4));
        assert!(!fresh);
        assert!(f.ike.lock().unwrap().pending_dpd.is_some());

        let answer = f.gateway_msg(FLAG_RESPONSE, 5);
        let (fresh, _) = f.deliver(&answer);
        assert!(fresh);
        assert!(f.ike.lock().unwrap().pending_dpd.is_none());

        // Replaying that answer later proves nothing.
        let (fresh, _) = f.deliver(&answer);
        assert!(!fresh);
    }
}
