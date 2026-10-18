//! Test doubles for every platform trait, plus [`MockResponder`]: a small
//! in-process IKEv2 *responder* (gateway) built from `ike` primitives, so the
//! real session/data-path code can be exercised end-to-end over loopback UDP.
//!
//! Nothing here is secure; [`InsecureMockProtector`] in particular must never
//! protect real secrets.

use crate::traits::*;
use ike::constants::{
    notify, AuthMethod, ExchangeType, IdType, PayloadType, ProtocolId, FLAG_RESPONSE,
};
use ike::crypto::{self, IkeKeys, Prf};
use ike::dh::{DhGroup, DhKeypair};
use ike::eap::{self, Eap};
use ike::esp::{ChildSa, EspCipher};
use ike::message::{parse_payload_chain, write_payload_chain, Message, RawPayload};
use ike::payloads::*;
use ike::sa::negotiate_from_proposal;
use ike::sk::{self, Suite};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Secret protector / journal
// ---------------------------------------------------------------------------

/// NOT SECURE: reversible obfuscation for tests and `--mock` mode only.
pub struct InsecureMockProtector;

impl SecretProtector for InsecureMockProtector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = b"MOCK".to_vec();
        out.extend(plain.iter().map(|b| b ^ 0x5a));
        Ok(out)
    }
    fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let body = blob
            .strip_prefix(b"MOCK")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a mock blob"))?;
        Ok(Zeroizing::new(body.iter().map(|b| b ^ 0x5a).collect()))
    }
}

/// In-memory journal.
#[derive(Default)]
pub struct MemJournal {
    pub entries: Mutex<Vec<NetChange>>,
}

impl JournalStore for MemJournal {
    fn load(&self) -> io::Result<Vec<NetChange>> {
        Ok(self.entries.lock().unwrap().clone())
    }
    fn save(&self, changes: &[NetChange]) -> io::Result<()> {
        *self.entries.lock().unwrap() = changes.to_vec();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Network configuration
// ---------------------------------------------------------------------------

/// Records applied changes; tests assert it is empty after cleanup.
#[derive(Default)]
pub struct MockNetConfig {
    pub applied: Mutex<Vec<NetChange>>,
    /// Fail the n-th `apply` call (0-based), to test rollback.
    pub fail_apply_at: Mutex<Option<usize>>,
    /// When set, `prepare` answers a `Dns` change with a `ResolvConf` backup
    /// holding this text (the Linux no-resolved path).
    pub dns_backup: Mutex<Option<String>>,
    applies: AtomicUsize,
}

impl NetConfig for MockNetConfig {
    fn prepare(&self, change: &NetChange) -> io::Result<Option<NetChange>> {
        Ok(match (change, self.dns_backup.lock().unwrap().as_ref()) {
            (NetChange::Dns { .. }, Some(b)) => Some(NetChange::ResolvConf { backup: b.clone() }),
            _ => None,
        })
    }
    fn apply(&self, change: &NetChange) -> io::Result<()> {
        let n = self.applies.fetch_add(1, Ordering::SeqCst);
        if *self.fail_apply_at.lock().unwrap() == Some(n) {
            return Err(io::Error::other("injected failure"));
        }
        self.applied.lock().unwrap().push(change.clone());
        Ok(())
    }
    fn revert(&self, change: &NetChange) -> io::Result<()> {
        let mut a = self.applied.lock().unwrap();
        if let Some(i) = a.iter().rposition(|c| c == change) {
            a.remove(i);
        }
        Ok(())
    }
    fn best_route(&self, _dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)> {
        Ok((99, Ipv4Addr::new(192, 0, 2, 1)))
    }
}

// ---------------------------------------------------------------------------
// TUN
// ---------------------------------------------------------------------------

/// A TUN device backed by channels.
pub struct MockTunDevice {
    from_os_tx: Mutex<Sender<Vec<u8>>>,
    from_os_rx: Mutex<Receiver<Vec<u8>>>,
    to_os_tx: Mutex<Sender<Vec<u8>>>,
    to_os_rx: Mutex<Receiver<Vec<u8>>>,
    shut: AtomicBool,
}

impl MockTunDevice {
    fn new() -> Self {
        let (a, b) = channel();
        let (c, d) = channel();
        MockTunDevice {
            from_os_tx: Mutex::new(a),
            from_os_rx: Mutex::new(b),
            to_os_tx: Mutex::new(c),
            to_os_rx: Mutex::new(d),
            shut: AtomicBool::new(false),
        }
    }
    /// Simulate the OS routing a packet into the tunnel.
    pub fn inject(&self, pkt: Vec<u8>) {
        let _ = self.from_os_tx.lock().unwrap().send(pkt);
    }
    /// A packet the tunnel delivered to the OS.
    pub fn delivered(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.to_os_rx.lock().unwrap().recv_timeout(timeout).ok()
    }
    pub fn is_shut(&self) -> bool {
        self.shut.load(Ordering::SeqCst)
    }
}

impl TunDevice for MockTunDevice {
    fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        let rx = self.from_os_rx.lock().unwrap();
        loop {
            if self.shut.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if let Ok(p) = rx.recv_timeout(Duration::from_millis(50)) {
                return Ok(Some(p));
            }
        }
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        let _ = self.to_os_tx.lock().unwrap().send(packet.to_vec());
        Ok(())
    }
    fn shutdown(&self) {
        self.shut.store(true, Ordering::SeqCst);
    }
    fn if_id(&self) -> u64 {
        7
    }
}

#[derive(Default)]
pub struct MockTunFactory {
    pub device: Mutex<Option<Arc<MockTunDevice>>>,
    pub stale_removed: AtomicUsize,
    pub fail: AtomicBool,
}

impl MockTunFactory {
    pub fn current(&self) -> Option<Arc<MockTunDevice>> {
        self.device.lock().unwrap().clone()
    }
}

impl TunFactory for MockTunFactory {
    fn create(&self) -> io::Result<Arc<dyn TunDevice>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected TUN failure"));
        }
        let d = Arc::new(MockTunDevice::new());
        *self.device.lock().unwrap() = Some(d.clone());
        Ok(d)
    }
    fn remove_stale(&self) -> io::Result<()> {
        self.stale_removed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A minimal IPv4 header + payload (for data-path tests).
pub fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        0,
        0,
        0,
        64,
        1,
        0,
        0,
    ];
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

// ---------------------------------------------------------------------------
// Mock IKEv2 responder
// ---------------------------------------------------------------------------

/// Behaviour of the [`MockResponder`].
#[derive(Clone)]
pub struct ResponderConfig {
    /// The PSK the gateway uses for its own AUTH and to check ours.
    pub psk: Vec<u8>,
    pub username: String,
    pub password: String,
    /// Reply INVALID_KE_PAYLOAD unless the client offers this group.
    pub require_group: Option<DhGroup>,
    pub assign_ip: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub remote_ts: (Ipv4Addr, Ipv4Addr),
    /// Choose the AES-CBC ESP proposal instead of AES-GCM.
    pub esp_cbc: bool,
    /// Stop answering anything once established (gateway-lost test).
    pub silent_after_established: bool,
    /// Never answer IKE_SA_INIT (unreachable test).
    pub ignore_sa_init: bool,
    /// Impostor test: answer the MS-CHAPv2 response with EAP-Success directly,
    /// skipping the MS-CHAPv2 Success (authenticator response).
    pub skip_mschap_success: bool,
    /// Impostor test: omit the gateway AUTH from the final EAP IKE_AUTH reply.
    pub omit_final_auth: bool,
    /// Impostor test: key the final EAP gateway AUTH with the PSK, not the MSK.
    pub final_auth_with_psk: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        ResponderConfig {
            psk: b"gateway-psk".to_vec(),
            username: "alice".into(),
            password: "correct horse".into(),
            require_group: None,
            assign_ip: Some(Ipv4Addr::new(10, 10, 0, 2)),
            dns: vec![Ipv4Addr::new(10, 10, 0, 1)],
            remote_ts: (Ipv4Addr::new(10, 10, 0, 0), Ipv4Addr::new(10, 10, 255, 255)),
            esp_cbc: false,
            silent_after_established: false,
            ignore_sa_init: false,
            skip_mschap_success: false,
            omit_final_auth: false,
            final_auth_with_psk: false,
        }
    }
}

/// What the responder observed (for assertions).
#[derive(Clone, Debug, Default)]
pub struct ResponderObs {
    pub sa_init_count: u32,
    pub saw_eap_identity: bool,
    pub established: bool,
    pub got_delete: bool,
    pub esp_echoed: u64,
    pub dpd_answered: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EapStage {
    Start,
    Identity,
    Challenge,
    Success,
    AwaitAuth,
    Done,
}

struct RespSa {
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    prf: Prf,
    suite: Suite,
    keys: IkeKeys,
    sa_init_req: Vec<u8>,
    sa_init_resp: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    stage: EapStage,
    ac: [u8; 16],
    msk: Option<[u8; 64]>,
    client_child: Option<SaPayload>,
    child: Option<ChildSa>,
    last: Option<(u32, Vec<u8>)>,
    peer: Option<SocketAddr>,
    /// IDi body from the first IKE_AUTH (part of the initiator's signed octets).
    idi: Vec<u8>,
}

pub struct MockResponder {
    pub ike_port: u16,
    pub natt_port: u16,
    obs: Arc<Mutex<ResponderObs>>,
    sa: Arc<Mutex<Option<RespSa>>>,
    natt_sock: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl MockResponder {
    pub fn start(cfg: ResponderConfig) -> MockResponder {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        a.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        b.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let obs = Arc::new(Mutex::new(ResponderObs::default()));
        let sa: Arc<Mutex<Option<RespSa>>> = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let cfg = Arc::new(cfg);

        let t1 = {
            let (a, obs, sa, stop, cfg) = (
                a.clone(),
                obs.clone(),
                sa.clone(),
                stop.clone(),
                cfg.clone(),
            );
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while !stop.load(Ordering::SeqCst) {
                    if let Ok((n, from)) = a.recv_from(&mut buf) {
                        if let Some(reply) = handle_sa_init(&buf[..n], &cfg, &obs, &sa) {
                            let _ = a.send_to(&reply, from);
                        }
                    }
                }
            })
        };
        let t2 = {
            let (b, obs, sa, stop, cfg) = (
                b.clone(),
                obs.clone(),
                sa.clone(),
                stop.clone(),
                cfg.clone(),
            );
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65535];
                while !stop.load(Ordering::SeqCst) {
                    if let Ok((n, from)) = b.recv_from(&mut buf) {
                        for out in handle_natt(&buf[..n], from, &cfg, &obs, &sa) {
                            let _ = b.send_to(&out, from);
                        }
                    }
                }
            })
        };
        MockResponder {
            ike_port: a.local_addr().unwrap().port(),
            natt_port: b.local_addr().unwrap().port(),
            obs,
            sa,
            natt_sock: b,
            stop,
            threads: vec![t1, t2],
        }
    }

    pub fn obs(&self) -> ResponderObs {
        self.obs.lock().unwrap().clone()
    }

    /// Send a gateway-initiated INFORMATIONAL DELETE of the IKE SA.
    pub fn send_delete(&self) {
        let g = self.sa.lock().unwrap();
        let Some(sa) = g.as_ref() else { return };
        let Some(peer) = sa.peer else { return };
        let del = DeletePayload {
            protocol_id: ProtocolId::Ike as u8,
            spis: vec![],
        };
        let msg = encrypt_resp(
            sa,
            ExchangeType::Informational as u8,
            0,
            0,
            &[raw(PayloadType::Delete, del.encode())],
        );
        let _ = self.natt_sock.send_to(&marker(&msg), peer);
    }

    /// Send a gateway-initiated empty INFORMATIONAL request (a liveness
    /// check) with message id `msg_id`. Returns the datagram so a test can
    /// replay it.
    pub fn send_liveness_check(&self, msg_id: u32) -> Option<Vec<u8>> {
        let g = self.sa.lock().unwrap();
        let sa = g.as_ref()?;
        let peer = sa.peer?;
        let msg = encrypt_resp(sa, ExchangeType::Informational as u8, 0, msg_id, &[]);
        let dgram = marker(&msg);
        let _ = self.natt_sock.send_to(&dgram, peer);
        Some(dgram)
    }

    /// Re-send a datagram captured earlier, as an on-path attacker would.
    pub fn replay(&self, dgram: &[u8]) {
        let g = self.sa.lock().unwrap();
        if let Some(peer) = g.as_ref().and_then(|sa| sa.peer) {
            let _ = self.natt_sock.send_to(dgram, peer);
        }
    }
}

impl Drop for MockResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn raw(t: PayloadType, data: Vec<u8>) -> RawPayload {
    RawPayload {
        payload_type: t as u8,
        critical: false,
        data,
    }
}

fn marker(msg: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0];
    v.extend_from_slice(msg);
    v
}

fn handle_sa_init(
    data: &[u8],
    cfg: &ResponderConfig,
    obs: &Mutex<ResponderObs>,
    slot: &Mutex<Option<RespSa>>,
) -> Option<Vec<u8>> {
    if cfg.ignore_sa_init {
        return None;
    }
    let msg = Message::parse(data).ok()?;
    if msg.exchange_type != ExchangeType::IkeSaInit as u8 {
        return None;
    }
    obs.lock().unwrap().sa_init_count += 1;
    let ke = KePayload::decode(&msg.find(PayloadType::Ke)?.data).ok()?;
    let group = DhGroup::from_transform_id(ke.dh_group)?;
    if let Some(req) = cfg.require_group {
        if req != group {
            let n = NotifyPayload {
                protocol_id: 0,
                notify_type: notify::INVALID_KE_PAYLOAD,
                spi: vec![],
                data: req.transform_id().to_be_bytes().to_vec(),
            };
            let reply = Message {
                initiator_spi: msg.initiator_spi,
                responder_spi: [0; 8],
                exchange_type: ExchangeType::IkeSaInit as u8,
                flags: FLAG_RESPONSE,
                message_id: 0,
                payloads: vec![raw(PayloadType::Notify, n.encode())],
            };
            return Some(reply.to_bytes());
        }
    }
    let offered = SaPayload::decode(&msg.find(PayloadType::Sa)?.data).ok()?;
    let chosen = offered.proposals.first()?.clone();
    let neg = negotiate_from_proposal(&chosen)?;
    let ni = msg.find(PayloadType::Nonce)?.data.clone();
    let kp = DhKeypair::generate(group);
    let shared = kp.compute_shared(&ke.key_exchange_data).ok()?;
    let nr = ike::rng::nonce(32);
    let spi_r = ike::rng::spi();
    let natd = |t| NotifyPayload {
        protocol_id: 0,
        notify_type: t,
        spi: vec![],
        data: ike::rng::nonce(20),
    };
    let reply = Message {
        initiator_spi: msg.initiator_spi,
        responder_spi: spi_r,
        exchange_type: ExchangeType::IkeSaInit as u8,
        flags: FLAG_RESPONSE,
        message_id: 0,
        payloads: vec![
            raw(
                PayloadType::Sa,
                SaPayload {
                    proposals: vec![chosen],
                }
                .encode(),
            ),
            raw(
                PayloadType::Ke,
                KePayload {
                    dh_group: ke.dh_group,
                    key_exchange_data: kp.public().to_vec(),
                }
                .encode(),
            ),
            raw(PayloadType::Nonce, nr.clone()),
            raw(
                PayloadType::Notify,
                natd(notify::NAT_DETECTION_SOURCE_IP).encode(),
            ),
            raw(
                PayloadType::Notify,
                natd(notify::NAT_DETECTION_DESTINATION_IP).encode(),
            ),
        ],
    }
    .to_bytes();
    let seed = crypto::skeyseed(neg.prf, &ni, &nr, &shared);
    let keys = crypto::derive_ike_keys(
        neg.prf,
        &seed,
        &ni,
        &nr,
        msg.initiator_spi,
        spi_r,
        neg.key_lengths,
    );
    *slot.lock().unwrap() = Some(RespSa {
        spi_i: msg.initiator_spi,
        spi_r,
        prf: neg.prf,
        suite: neg.suite,
        keys,
        sa_init_req: data.to_vec(),
        sa_init_resp: reply.clone(),
        ni,
        nr,
        stage: EapStage::Start,
        ac: [0; 16],
        msk: None,
        client_child: None,
        child: None,
        last: None,
        peer: None,
        idi: Vec::new(),
    });
    Some(reply)
}

fn encrypt_resp(
    sa: &RespSa,
    exchange: u8,
    flags: u8,
    msg_id: u32,
    payloads: &[RawPayload],
) -> Vec<u8> {
    let mut inner = Vec::new();
    write_payload_chain(payloads, &mut inner);
    let first = payloads.first().map(|p| p.payload_type).unwrap_or(0);
    sk::encrypt_message(
        sa.spi_i,
        sa.spi_r,
        exchange,
        flags,
        msg_id,
        first,
        &inner,
        &sa.suite,
        &sa.keys.sk_er,
        &sa.keys.sk_ar,
    )
}

fn responder_auth(sa: &RespSa, key: &[u8], idr: &IdPayload) -> RawPayload {
    let signed = crypto::responder_signed_octets(
        sa.prf,
        &sa.sa_init_resp,
        &sa.ni,
        &sa.keys.sk_pr,
        &idr.signed_octets(),
    );
    let auth = AuthPayload {
        auth_method: AuthMethod::SharedKeyMic as u8,
        auth_data: crypto::psk_auth(sa.prf, key, &signed),
    };
    raw(PayloadType::Auth, auth.encode())
}

fn initiator_auth_ok(sa: &RespSa, inner: &[RawPayload], idi_body: &[u8], key: &[u8]) -> bool {
    let Some(a) = inner
        .iter()
        .find(|p| p.payload_type == PayloadType::Auth as u8)
    else {
        return false;
    };
    let Ok(auth) = AuthPayload::decode(&a.data) else {
        return false;
    };
    let signed =
        crypto::initiator_signed_octets(sa.prf, &sa.sa_init_req, &sa.nr, &sa.keys.sk_pi, idi_body);
    ike::ct_eq(&crypto::psk_auth(sa.prf, key, &signed), &auth.auth_data)
}

fn gw_id() -> IdPayload {
    IdPayload {
        id_type: IdType::Fqdn as u8,
        id_data: b"mock-gw".to_vec(),
    }
}

/// Final payloads: CP reply, chosen Child SA, TSi/TSr. Also keys our ChildSa.
fn established_payloads(sa: &mut RespSa, cfg: &ResponderConfig) -> Vec<RawPayload> {
    let mut out = Vec::new();
    let mut attrs = Vec::new();
    if let Some(ip) = cfg.assign_ip {
        attrs.push((cfg::INTERNAL_IP4_ADDRESS, ip.octets().to_vec()));
    }
    for d in &cfg.dns {
        attrs.push((cfg::INTERNAL_IP4_DNS, d.octets().to_vec()));
    }
    out.push(raw(
        PayloadType::Cp,
        ConfigPayload {
            cfg_type: cfg::CFG_REPLY,
            attributes: attrs,
        }
        .encode(),
    ));
    let offered = sa
        .client_child
        .clone()
        .unwrap_or(SaPayload { proposals: vec![] });
    let idx = if cfg.esp_cbc { 1 } else { 0 };
    if let Some(mut p) = offered.proposals.get(idx).cloned() {
        let client_spi = [p.spi[0], p.spi[1], p.spi[2], p.spi[3]];
        let our_spi = [0x0b, 0xad, 0xf0, 0x0d];
        p.spi = our_spi.to_vec();
        let cipher = if cfg.esp_cbc {
            EspCipher::Aes256CbcSha256
        } else {
            EspCipher::Aes256Gcm16
        };
        let km = crypto::derive_child_keys(
            sa.prf,
            &sa.keys.sk_d,
            &sa.ni,
            &sa.nr,
            None,
            cipher.keymat_len(),
        );
        let half = km.len() / 2;
        let mut swapped = km[half..].to_vec();
        swapped.extend_from_slice(&km[..half]);
        sa.child = Some(ChildSa::from_keymat(cipher, &swapped, client_spi, our_spi));
        out.push(raw(
            PayloadType::Sa,
            SaPayload { proposals: vec![p] }.encode(),
        ));
    }
    out.push(raw(PayloadType::Tsi, ike::proposals::ts_any_v4().encode()));
    let ts = TsPayload {
        selectors: vec![TrafficSelector {
            ts_type: ike::constants::TsType::Ipv4AddrRange as u8,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: cfg.remote_ts.0.octets().to_vec(),
            end_addr: cfg.remote_ts.1.octets().to_vec(),
        }],
    };
    out.push(raw(PayloadType::Tsr, ts.encode()));
    out
}

fn handle_natt(
    data: &[u8],
    from: SocketAddr,
    cfg: &ResponderConfig,
    obs: &Mutex<ResponderObs>,
    slot: &Mutex<Option<RespSa>>,
) -> Vec<Vec<u8>> {
    let mut g = slot.lock().unwrap();
    let Some(sa) = g.as_mut() else { return vec![] };
    if cfg.silent_after_established && obs.lock().unwrap().established {
        return vec![];
    }
    if data.len() == 1 {
        return vec![]; // keepalive
    }
    sa.peer = Some(from);
    if data.len() >= 4 && data[..4] != [0, 0, 0, 0] {
        // ESP: echo back with swapped addresses.
        let Some(child) = sa.child.as_mut() else {
            return vec![];
        };
        let Ok((nh, mut inner)) = child.decrypt(data) else {
            return vec![];
        };
        if nh == 4 && inner.len() >= 20 {
            let (a, b) = inner.split_at_mut(16);
            a[12..16].swap_with_slice(&mut b[..4]);
            obs.lock().unwrap().esp_echoed += 1;
            return child
                .encrypt(4, &inner)
                .map(|p| vec![p])
                .unwrap_or_default();
        }
        return vec![];
    }
    let msg = &data[4..];
    if msg.len() < 28 || msg[..8] != sa.spi_i {
        return vec![];
    }
    let exchange = msg[18];
    let msg_id = u32::from_be_bytes([msg[20], msg[21], msg[22], msg[23]]);
    if msg[19] & FLAG_RESPONSE != 0 {
        return vec![]; // response to our DELETE etc.
    }
    if let Some((id, bytes)) = &sa.last {
        if *id == msg_id {
            return vec![marker(bytes)]; // retransmission
        }
    }
    let Ok((first, inner)) = sk::decrypt_message(msg, &sa.suite, &sa.keys.sk_ei, &sa.keys.sk_ai)
    else {
        return vec![];
    };
    let Ok(inner) = parse_payload_chain(first, &inner) else {
        return vec![];
    };
    let find = |t: PayloadType| inner.iter().find(|p| p.payload_type == t as u8);

    let reply_payloads: Vec<RawPayload> = if exchange == ExchangeType::Informational as u8 {
        let mut o = obs.lock().unwrap();
        if find(PayloadType::Delete).is_some() {
            o.got_delete = true;
        } else {
            o.dpd_answered += 1;
        }
        vec![]
    } else if exchange == ExchangeType::IkeAuth as u8 {
        if let Some(s) = find(PayloadType::Sa) {
            sa.client_child = SaPayload::decode(&s.data).ok();
        }
        if let Some(b) = find(PayloadType::Idi) {
            sa.idi = b.data.clone();
        }
        let idi_body = sa.idi.clone();
        match (
            sa.stage,
            find(PayloadType::Auth).is_some(),
            find(PayloadType::Eap),
        ) {
            (EapStage::Start, true, _) => {
                // PSK mode.
                if !initiator_auth_ok(sa, &inner, &idi_body, &cfg.psk) {
                    let n = NotifyPayload {
                        protocol_id: 0,
                        notify_type: notify::AUTHENTICATION_FAILED,
                        spi: vec![],
                        data: vec![],
                    };
                    vec![raw(PayloadType::Notify, n.encode())]
                } else {
                    let id = gw_id();
                    let mut v = vec![
                        raw(PayloadType::Idr, id.encode()),
                        responder_auth(sa, &cfg.psk, &id),
                    ];
                    v.extend(established_payloads(sa, cfg));
                    sa.stage = EapStage::Done;
                    obs.lock().unwrap().established = true;
                    v
                }
            }
            (EapStage::Start, false, _) => {
                let id = gw_id();
                sa.stage = EapStage::Identity;
                let req = Eap {
                    code: eap::EAP_REQUEST,
                    identifier: 1,
                    type_: Some(eap::TYPE_IDENTITY),
                    data: vec![],
                };
                vec![
                    raw(PayloadType::Idr, id.encode()),
                    responder_auth(sa, &cfg.psk, &id),
                    raw(PayloadType::Eap, req.encode()),
                ]
            }
            (stage, false, Some(e)) => {
                let Ok(pkt) = Eap::parse(&e.data) else {
                    return vec![];
                };
                match (stage, pkt.type_) {
                    (EapStage::Identity, Some(eap::TYPE_IDENTITY)) => {
                        obs.lock().unwrap().saw_eap_identity = true;
                        ike::rng::fill(&mut sa.ac);
                        let mut d = vec![eap::MS_CHALLENGE, 1, 0, 0, 16];
                        d.extend_from_slice(&sa.ac);
                        d.extend_from_slice(b"mock");
                        let l = (d.len() as u16).to_be_bytes();
                        d[2] = l[0];
                        d[3] = l[1];
                        sa.stage = EapStage::Challenge;
                        let r = Eap {
                            code: eap::EAP_REQUEST,
                            identifier: 2,
                            type_: Some(eap::TYPE_MSCHAPV2),
                            data: d,
                        };
                        vec![raw(PayloadType::Eap, r.encode())]
                    }
                    (EapStage::Challenge, Some(eap::TYPE_MSCHAPV2)) if pkt.data.len() >= 54 => {
                        let mut peer = [0u8; 16];
                        peer.copy_from_slice(&pkt.data[5..21]);
                        let mut ntr = [0u8; 24];
                        ntr.copy_from_slice(&pkt.data[29..53]);
                        let expect = eap::generate_nt_response(
                            &sa.ac,
                            &peer,
                            cfg.username.as_bytes(),
                            &cfg.password,
                        );
                        if expect == ntr && cfg.skip_mschap_success {
                            sa.msk = Some(eap::eap_msk(&cfg.password, &ntr));
                            sa.stage = EapStage::AwaitAuth;
                            let r = Eap {
                                code: eap::EAP_SUCCESS,
                                identifier: 3,
                                type_: None,
                                data: vec![],
                            };
                            vec![raw(PayloadType::Eap, r.encode())]
                        } else if expect == ntr {
                            sa.msk = Some(eap::eap_msk(&cfg.password, &ntr));
                            let s = eap::generate_authenticator_response(
                                &cfg.password,
                                &ntr,
                                &peer,
                                &sa.ac,
                                cfg.username.as_bytes(),
                            );
                            let mut d = vec![eap::MS_SUCCESS, 1, 0, 0];
                            d.extend_from_slice(s.as_bytes());
                            d.extend_from_slice(b" M=ok");
                            let l = (d.len() as u16).to_be_bytes();
                            d[2] = l[0];
                            d[3] = l[1];
                            sa.stage = EapStage::Success;
                            let r = Eap {
                                code: eap::EAP_REQUEST,
                                identifier: 3,
                                type_: Some(eap::TYPE_MSCHAPV2),
                                data: d,
                            };
                            vec![raw(PayloadType::Eap, r.encode())]
                        } else {
                            let r = Eap {
                                code: eap::EAP_FAILURE,
                                identifier: 3,
                                type_: None,
                                data: vec![],
                            };
                            vec![raw(PayloadType::Eap, r.encode())]
                        }
                    }
                    (EapStage::Success, Some(eap::TYPE_MSCHAPV2)) => {
                        sa.stage = EapStage::AwaitAuth;
                        let r = Eap {
                            code: eap::EAP_SUCCESS,
                            identifier: 4,
                            type_: None,
                            data: vec![],
                        };
                        vec![raw(PayloadType::Eap, r.encode())]
                    }
                    _ => return vec![],
                }
            }
            (EapStage::AwaitAuth, true, _) => {
                let msk = sa.msk.unwrap_or([0; 64]);
                if !initiator_auth_ok(sa, &inner, &idi_body, &msk) {
                    let n = NotifyPayload {
                        protocol_id: 0,
                        notify_type: notify::AUTHENTICATION_FAILED,
                        spi: vec![],
                        data: vec![],
                    };
                    vec![raw(PayloadType::Notify, n.encode())]
                } else {
                    let id = gw_id();
                    let mut v = if cfg.omit_final_auth {
                        vec![]
                    } else if cfg.final_auth_with_psk {
                        vec![responder_auth(sa, &cfg.psk, &id)]
                    } else {
                        vec![responder_auth(sa, &msk, &id)]
                    };
                    v.extend(established_payloads(sa, cfg));
                    sa.stage = EapStage::Done;
                    obs.lock().unwrap().established = true;
                    v
                }
            }
            _ => return vec![],
        }
    } else {
        return vec![];
    };
    let out = encrypt_resp(sa, exchange, FLAG_RESPONSE, msg_id, &reply_payloads);
    sa.last = Some((msg_id, out.clone()));
    vec![marker(&out)]
}
