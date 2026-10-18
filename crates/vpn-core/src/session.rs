//! IKEv2 session establishment (the protocol flow proven by the `ike-connect`
//! prototype, rebuilt over the platform traits):
//!
//! 1. IKE_SA_INIT to gateway:port (source port 500 if available), with NAT-D,
//!    retransmission (FR-019) and one INVALID_KE group switch (FR-018).
//! 2. Float to gateway:4500 from an *ephemeral* local port (FR-011). Windows'
//!    kernel claims inbound UDP-ESP addressed to local port 4500, so a high
//!    local port keeps ESP flowing to our user-mode socket.
//! 3. IKE_AUTH with PSK, or PSK gateway auth + EAP-MSCHAPv2. The gateway's
//!    AUTH is verified before any user credential is sent (FR-014).
//! 4. Mode-config address/DNS, traffic selectors and the ESP Child SA.
//!
//! A user-mode client cannot emit raw ESP (IP protocol 50), so UDP
//! encapsulation is always required. With `force_encap` the NAT_DETECTION_
//! SOURCE_IP hash is computed over a random address (strongSwan's `encap=yes`
//! technique), which makes the gateway treat us as NATed and accept UDP-ESP
//! even on a NAT-free path.

use crate::traits::{is_timeout, UdpFactory, UdpLink};
use ike::constants::{notify, AuthMethod, IdType as IkeIdType, PayloadType};
use ike::crypto::{KeyLengths, Prf};
use ike::dh::{DhGroup, DhKeypair};
use ike::eap::{self, Eap};
use ike::esp::ChildSa;
use ike::message::{Message, RawPayload};
use ike::payloads::{
    cfg, AuthPayload, ConfigPayload, IdPayload, KePayload, NotifyPayload, SaPayload, TsPayload,
};
use ike::proposals::{self, ChildSelectError};
use ike::sa::{nat_detection_hash, Initiator, InitiatorConfig};
use ipc_proto::ErrorCode;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use zeroize::Zeroizing;

const TARGET: &str = "session";

/// How the user authenticates.
pub enum AuthParams {
    /// Mutual pre-shared key.
    Psk,
    /// PSK gateway authentication, then EAP-MSCHAPv2 for the user.
    Eap {
        username: String,
        password: Zeroizing<String>,
    },
}

/// Everything needed for one connection attempt.
pub struct SessionParams {
    pub gateway_host: String,
    pub port: u16,
    pub id_type: ipc_proto::IdType,
    pub local_id: String,
    pub dh: DhGroup,
    pub psk: Zeroizing<Vec<u8>>,
    pub auth: AuthParams,
}

/// Transport tunables.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Gateway NAT-T port (4500; configurable for tests).
    pub natt_port: u16,
    /// Try to use local source port 500 for IKE_SA_INIT.
    pub bind_source_500: bool,
    /// Per-attempt reply timeouts; the request is sent once per entry.
    pub retransmit: Vec<Duration>,
    /// Force UDP encapsulation via a non-matching NAT-D source hash.
    pub force_encap: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            natt_port: 4500,
            bind_source_500: true,
            retransmit: vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
            ],
            force_encap: true,
        }
    }
}

/// Progress milestones reported while establishing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// IKE_SA_INIT completed; authentication is starting.
    Authenticating,
}

/// A fully established IKE SA + Child SA.
pub struct Established {
    pub ike: Initiator,
    pub link: Arc<dyn UdpLink>,
    /// Current remote endpoint (gateway NAT-T port).
    pub gateway: SocketAddrV4,
    /// The SA runs NAT-T: a NAT was detected or encapsulation was forced.
    pub nat_detected: bool,
    /// Next message id for initiator requests on the IKE SA.
    pub next_msg_id: u32,
    pub child: ChildSa,
    pub assigned_ip: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub remote_ranges: Vec<(Ipv4Addr, Ipv4Addr)>,
    pub ike_suite: String,
    pub esp_suite: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub code: ErrorCode,
    pub message: String,
    /// The attempt was aborted by the user (not a failure to report).
    pub cancelled: bool,
}

impl SessionError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        SessionError {
            code,
            message: message.into(),
            cancelled: false,
        }
    }
    fn cancelled() -> Self {
        SessionError {
            code: ErrorCode::Internal,
            message: "cancelled".into(),
            cancelled: true,
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Map a gateway error notify to an error code + user message (FR-018).
pub fn notify_error(t: u16, during_eap: bool) -> SessionError {
    let code = match t {
        notify::NO_PROPOSAL_CHOSEN => ErrorCode::NoProposalChosen,
        notify::INVALID_KE_PAYLOAD => ErrorCode::InvalidKe,
        notify::COOKIE => ErrorCode::CookieRequired,
        notify::AUTHENTICATION_FAILED => ErrorCode::UserAuthFailed,
        notify::TS_UNACCEPTABLE => ErrorCode::TsUnacceptable,
        notify::INTERNAL_ADDRESS_FAILURE => ErrorCode::NoAddressAssigned,
        _ => ErrorCode::Internal,
    };
    let message = if t == notify::AUTHENTICATION_FAILED {
        if during_eap {
            "Authentication failed: wrong username or password".to_string()
        } else {
            "Authentication failed: the gateway rejected the pre-shared key or identity".to_string()
        }
    } else {
        ike::notify::user_message(t)
    };
    SessionError::new(code, message)
}

/// IKE transport over a UDP link, with the RFC 3948 non-ESP marker on 4500.
struct Wire<'a> {
    link: Arc<dyn UdpLink>,
    marker: bool,
    cfg: &'a SessionConfig,
    cancel: &'a AtomicBool,
}

impl Wire<'_> {
    fn send(&self, msg: &[u8]) -> std::io::Result<()> {
        if self.marker {
            let mut framed = Vec::with_capacity(4 + msg.len());
            framed.extend_from_slice(&[0, 0, 0, 0]);
            framed.extend_from_slice(msg);
            self.link.send(&framed)?;
        } else {
            self.link.send(msg)?;
        }
        Ok(())
    }

    /// Send `req` and wait for the matching response (same SPIi and message
    /// id, response flag), retransmitting per `cfg.retransmit`.
    fn exchange(&self, req: &[u8], spi_i: [u8; 8], msg_id: u32) -> Result<Vec<u8>, SessionError> {
        let mut buf = vec![0u8; 65535];
        for timeout in &self.cfg.retransmit {
            self.send(req).map_err(|e| {
                SessionError::new(
                    ErrorCode::GatewayUnreachable,
                    format!("Could not send to the gateway: {e}"),
                )
            })?;
            let deadline = Instant::now() + *timeout;
            loop {
                if self.cancel.load(Ordering::SeqCst) {
                    return Err(SessionError::cancelled());
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let slice = (deadline - now).min(Duration::from_millis(250));
                let n = match self.link.recv(&mut buf, slice) {
                    Ok(n) => n,
                    Err(e) if is_timeout(&e) => continue,
                    // e.g. ICMP port unreachable surfaces as ConnectionReset.
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                let data = if self.marker {
                    if n < 4 || buf[..4] != [0, 0, 0, 0] {
                        continue; // ESP or NAT keepalive, not IKE
                    }
                    &buf[4..n]
                } else {
                    &buf[..n]
                };
                if data.len() < ike::message::HEADER_LEN || data[..8] != spi_i {
                    continue;
                }
                let flags = data[19];
                let id = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                if id == msg_id && flags & ike::constants::FLAG_RESPONSE != 0 {
                    return Ok(data.to_vec());
                }
            }
        }
        Err(SessionError::new(
            ErrorCode::GatewayUnreachable,
            "Gateway did not respond",
        ))
    }
}

fn raw(t: PayloadType, data: Vec<u8>) -> RawPayload {
    RawPayload {
        payload_type: t as u8,
        critical: false,
        data,
    }
}

fn ip_port(addr: SocketAddr) -> (Vec<u8>, u16) {
    match addr {
        SocketAddr::V4(a) => (a.ip().octets().to_vec(), a.port()),
        SocketAddr::V6(a) => (a.ip().octets().to_vec(), a.port()),
    }
}

fn find(payloads: &[RawPayload], t: PayloadType) -> Option<&RawPayload> {
    payloads.iter().find(|p| p.payload_type == t as u8)
}

/// Relative strength of a supported DH group (higher is stronger):
/// Curve25519 > MODP-2048 > MODP-1536. Used to refuse INVALID_KE downgrades.
fn dh_strength(g: DhGroup) -> u8 {
    match g {
        DhGroup::Modp1536 => 0,
        DhGroup::Modp2048 => 1,
        DhGroup::Curve25519 => 2,
    }
}

/// Establish the IKE SA and Child SA. Blocking; honours `cancel`.
pub fn establish(
    udp: &dyn UdpFactory,
    params: &SessionParams,
    cfg: &SessionConfig,
    cancel: &AtomicBool,
    on_phase: &mut dyn FnMut(Phase),
) -> Result<Established, SessionError> {
    let gw = udp
        .resolve(&params.gateway_host, params.port)
        .map_err(|e| {
            SessionError::new(
                ErrorCode::GatewayUnreachable,
                format!("Could not resolve gateway {}: {e}", params.gateway_host),
            )
        })?;
    info!(target: TARGET, gateway = %gw, "connecting");

    let idi = identity(params)?;
    let mut dh = params.dh;
    let mut ke_retry_done = false;

    let (init, nat_detected) = loop {
        // --- IKE_SA_INIT ---
        let link = if cfg.bind_source_500 {
            match udp.connect(500, gw) {
                Ok(l) => l,
                Err(_) => {
                    warn!(target: TARGET, "UDP source port 500 is busy (Windows IKEEXT?); using an ephemeral port");
                    udp_connect(udp, 0, gw)?
                }
            }
        } else {
            udp_connect(udp, 0, gw)?
        };
        let wire = Wire {
            link: link.clone(),
            marker: params.port == cfg.natt_port,
            cfg,
            cancel,
        };
        let local = link.local_addr().map_err(io_err)?;

        let icfg = InitiatorConfig {
            proposals: proposals::ike_proposals(dh),
            dh_group: dh.transform_id(),
            prf: Prf::HmacSha256,
            key_lengths: KeyLengths {
                prf_key: 32,
                integ_key: 32,
                encr_key: 32,
            },
            idi: idi.clone(),
            psk: params.psk.clone(),
        };
        let spi_i = ike::rng::spi();
        let mut init = Initiator::new(icfg, spi_i, ike::rng::nonce(32));
        let kp = DhKeypair::generate(dh);

        let (local_ip, local_port) = ip_port(local);
        let src_ip = if cfg.force_encap {
            ike::rng::nonce(4)
        } else {
            local_ip.clone()
        };
        let natd_src = NotifyPayload {
            protocol_id: 0,
            notify_type: notify::NAT_DETECTION_SOURCE_IP,
            spi: vec![],
            data: nat_detection_hash(spi_i, [0; 8], &src_ip, local_port),
        };
        let natd_dst = NotifyPayload {
            protocol_id: 0,
            notify_type: notify::NAT_DETECTION_DESTINATION_IP,
            spi: vec![],
            data: nat_detection_hash(spi_i, [0; 8], &gw.ip().octets(), gw.port()),
        };
        let req = init.build_ike_sa_init(
            kp.public(),
            &[
                raw(PayloadType::Notify, natd_src.encode()),
                raw(PayloadType::Notify, natd_dst.encode()),
            ],
        );
        info!(target: TARGET, dh = proposals::dh_name(dh), local = %local, "=> IKE_SA_INIT");
        let reply = wire.exchange(&req, spi_i, 0)?;
        let msg = Message::parse(&reply).map_err(|_| {
            SessionError::new(
                ErrorCode::Internal,
                "Malformed IKE_SA_INIT reply from the gateway",
            )
        })?;

        if let Some(n) = ike::notify::first_error(&msg.payloads) {
            if n.notify_type == notify::INVALID_KE_PAYLOAD && !ke_retry_done {
                if let Some(g) = ike::notify::requested_dh_group(&n) {
                    // The IKE_SA_INIT reply is unauthenticated: never let it
                    // move us to a group weaker than the profile's (CWE-757).
                    if dh_strength(g) < dh_strength(params.dh) {
                        warn!(target: TARGET, configured = proposals::dh_name(params.dh), requested = proposals::dh_name(g), "gateway wants a weaker DH group than configured; refusing to downgrade");
                        return Err(SessionError::new(
                            ErrorCode::InvalidKe,
                            format!(
                                "The gateway requires DH group {}, which is weaker than the configured {} (INVALID_KE_PAYLOAD)",
                                proposals::dh_name(g),
                                proposals::dh_name(params.dh)
                            ),
                        ));
                    }
                    warn!(target: TARGET, requested = proposals::dh_name(g), "gateway wants another DH group; retrying");
                    dh = g;
                    ke_retry_done = true;
                    continue;
                }
            }
            return Err(notify_error(n.notify_type, false));
        }
        if ike::notify::find(&msg.payloads, notify::COOKIE).is_some() {
            return Err(notify_error(notify::COOKIE, false));
        }

        let ke = msg
            .find(PayloadType::Ke)
            .and_then(|p| KePayload::decode(&p.data).ok())
            .ok_or_else(|| {
                SessionError::new(ErrorCode::Internal, "IKE_SA_INIT reply has no KE payload")
            })?;
        if ke.dh_group != dh.transform_id() {
            return Err(SessionError::new(
                ErrorCode::InvalidKe,
                "The gateway answered with a different DH group",
            ));
        }
        let shared = kp.compute_shared(&ke.key_exchange_data).map_err(|_| {
            SessionError::new(
                ErrorCode::Internal,
                "The gateway sent an invalid DH public value",
            )
        })?;
        init.process_ike_sa_init_reply(&reply, &shared)
            .map_err(|_| {
                SessionError::new(
                    ErrorCode::UnsupportedCipher,
                    "The gateway chose an IKE proposal this client does not support",
                )
            })?;

        // NAT detection from the responder's NAT-D notifies (RFC 7296 §2.23).
        let spi_r = msg.responder_spi;
        let exp_src = nat_detection_hash(spi_i, spi_r, &gw.ip().octets(), gw.port());
        let exp_dst = nat_detection_hash(spi_i, spi_r, &local_ip, local_port);
        let nat = msg
            .payloads
            .iter()
            .filter_map(|p| {
                (p.payload_type == PayloadType::Notify as u8)
                    .then(|| NotifyPayload::decode(&p.data).ok())
                    .flatten()
            })
            .any(|n| {
                (n.notify_type == notify::NAT_DETECTION_SOURCE_IP && n.data != exp_src)
                    || (n.notify_type == notify::NAT_DETECTION_DESTINATION_IP && n.data != exp_dst)
            });
        let neg = init.negotiated().expect("negotiated after SA_INIT");
        info!(target: TARGET, suite = %proposals::describe_ike(&neg, dh), nat, "<= IKE_SA_INIT");
        // Forced encapsulation makes the gateway see us as NATed, so the SA
        // runs NAT-T whether or not the path really has a NAT.
        break ((init, dh), nat || cfg.force_encap);
    };
    let (init, dh) = init;
    on_phase(Phase::Authenticating);

    // --- float to NAT-T from an ephemeral local port ---
    let natt = SocketAddrV4::new(*gw.ip(), cfg.natt_port);
    let link = udp_connect(udp, 0, natt)?;
    info!(target: TARGET, remote = %natt, local = %link.local_addr().map_err(io_err)?, "floating to NAT-T");
    let wire = Wire {
        link: link.clone(),
        marker: true,
        cfg,
        cancel,
    };

    let mut child_spi = [0u8; 4];
    while child_spi == [0; 4] {
        ike::rng::fill(&mut child_spi);
    }
    let child = proposals::child_proposals(child_spi);
    let ts = proposals::ts_any_v4();

    let (inner, next_msg_id) = match &params.auth {
        AuthParams::Psk => psk_auth(&init, &wire, &child, &ts)?,
        AuthParams::Eap { username, password } => {
            eap_auth(&init, &wire, &child, &ts, username, password)?
        }
    };

    let neg = init.negotiated().expect("negotiated");
    let ike_suite = proposals::describe_ike(&neg, dh);
    finish(
        init,
        link,
        natt,
        nat_detected,
        next_msg_id,
        &inner,
        child_spi,
        ike_suite,
    )
}

fn identity(p: &SessionParams) -> Result<IdPayload, SessionError> {
    let (id_type, id_data) = match p.id_type {
        ipc_proto::IdType::Fqdn => (IkeIdType::Fqdn, p.local_id.as_bytes().to_vec()),
        ipc_proto::IdType::Email => (IkeIdType::Rfc822Addr, p.local_id.as_bytes().to_vec()),
        ipc_proto::IdType::Ipv4 => {
            let ip: Ipv4Addr = p.local_id.parse().map_err(|_| {
                SessionError::new(
                    ErrorCode::ProfileInvalid,
                    "The local identity is not a valid IPv4 address",
                )
            })?;
            (IkeIdType::Ipv4Addr, ip.octets().to_vec())
        }
    };
    Ok(IdPayload {
        id_type: id_type as u8,
        id_data,
    })
}

fn udp_connect(
    udp: &dyn UdpFactory,
    port: u16,
    peer: SocketAddrV4,
) -> Result<Arc<dyn UdpLink>, SessionError> {
    udp.connect(port, peer).map_err(|e| {
        SessionError::new(
            ErrorCode::GatewayUnreachable,
            format!("Could not open a UDP socket to {peer}: {e}"),
        )
    })
}

fn io_err(e: std::io::Error) -> SessionError {
    SessionError::new(ErrorCode::Internal, format!("socket error: {e}"))
}

/// Decrypt an IKE_AUTH reply; surface cleartext and encrypted error notifies.
fn decrypt_reply(
    init: &Initiator,
    reply: &[u8],
    during_eap: bool,
) -> Result<Vec<RawPayload>, SessionError> {
    if let Ok(m) = Message::parse(reply) {
        if m.find(PayloadType::Sk).is_none() {
            if let Some(n) = ike::notify::first_error(&m.payloads) {
                return Err(notify_error(n.notify_type, during_eap));
            }
        }
    }
    let inner = init.decrypt(reply).map_err(|_| {
        SessionError::new(
            ErrorCode::Internal,
            "Could not decrypt the gateway's IKE_AUTH reply",
        )
    })?;
    if let Some(n) = ike::notify::first_error(&inner) {
        return Err(notify_error(n.notify_type, during_eap));
    }
    Ok(inner)
}

fn gateway_auth_error(e: ike::sa::Error) -> SessionError {
    let detail = match e {
        ike::sa::Error::UnsupportedAuthMethod(m) => {
            format!(
                "the gateway used authentication method {m}, but only pre-shared key is supported"
            )
        }
        ike::sa::Error::MissingPayload(_) => "the gateway did not send its identity/AUTH".into(),
        _ => "the gateway's AUTH does not match the pre-shared key".into(),
    };
    SessionError::new(
        ErrorCode::GatewayAuthFailed,
        format!("Gateway authentication failed: {detail}"),
    )
}

fn psk_auth(
    init: &Initiator,
    wire: &Wire,
    child: &SaPayload,
    ts: &TsPayload,
) -> Result<(Vec<RawPayload>, u32), SessionError> {
    let cp = raw(PayloadType::Cp, ConfigPayload::request_defaults().encode());
    let req = init
        .build_ike_auth_message(child, ts, ts, &[cp])
        .map_err(|_| SessionError::new(ErrorCode::Internal, "Could not build IKE_AUTH"))?;
    info!(target: TARGET, "=> IKE_AUTH (PSK)");
    let reply = wire.exchange(&req, init.initiator_spi(), 1)?;
    let inner = decrypt_reply(init, &reply, false)?;
    init.verify_responder_psk_auth(&inner)
        .map_err(gateway_auth_error)?;
    info!(target: TARGET, "<= IKE_AUTH (gateway AUTH verified)");
    Ok((inner, 2))
}

fn eap_auth(
    init: &Initiator,
    wire: &Wire,
    child: &SaPayload,
    ts: &TsPayload,
    username: &str,
    password: &str,
) -> Result<(Vec<RawPayload>, u32), SessionError> {
    // IKE_AUTH #1: IDi, CP(request), SA, TSi, TSr -- no AUTH (EAP mode).
    let p1 = vec![
        init.idi_raw(),
        raw(PayloadType::Cp, ConfigPayload::request_defaults().encode()),
        raw(PayloadType::Sa, child.encode()),
        raw(PayloadType::Tsi, ts.encode()),
        raw(PayloadType::Tsr, ts.encode()),
    ];
    let m1 = init
        .encrypt(1, &p1)
        .map_err(|_| SessionError::new(ErrorCode::Internal, "Could not build IKE_AUTH"))?;
    info!(target: TARGET, "=> IKE_AUTH #1 (EAP start)");
    let r1 = wire.exchange(&m1, init.initiator_spi(), 1)?;
    let inner = decrypt_reply(init, &r1, false)?;
    // Gateway identity first: nothing user-related is sent before this passes.
    init.verify_responder_psk_auth(&inner)
        .map_err(gateway_auth_error)?;
    info!(target: TARGET, "<= IKE_AUTH #1 (gateway AUTH verified)");
    // The final MSK-keyed AUTH is computed over this IDr (RFC 7296 §2.16).
    let idr = find(&inner, PayloadType::Idr)
        .cloned()
        .ok_or_else(|| gateway_auth_error(ike::sa::Error::MissingPayload(PayloadType::Idr)))?;

    let mut eap_bytes = find(&inner, PayloadType::Eap)
        .map(|p| p.data.clone())
        .ok_or_else(|| {
            SessionError::new(
                ErrorCode::Internal,
                "The gateway did not start EAP; is this an EAP-enabled gateway?",
            )
        })?;
    let mut msg_id = 2u32;
    let mut mschap: Option<(eap::MsChapResponse, [u8; 16])> = None;
    // Set only once the gateway's MS-CHAPv2 authenticator response verifies.
    let mut authenticator_verified = false;
    let mut rounds = 0;

    loop {
        rounds += 1;
        if rounds > 16 {
            return Err(SessionError::new(
                ErrorCode::Internal,
                "EAP did not converge",
            ));
        }
        let pkt = Eap::parse(&eap_bytes).map_err(|_| {
            SessionError::new(ErrorCode::Internal, "Malformed EAP packet from the gateway")
        })?;
        match pkt.code {
            eap::EAP_SUCCESS => {
                if !authenticator_verified {
                    return Err(SessionError::new(
                        ErrorCode::GatewayAuthFailed,
                        "Gateway authentication failed: EAP-Success without a verified MS-CHAPv2 authenticator response",
                    ));
                }
                info!(target: TARGET, "<= EAP-Success");
                break;
            }
            eap::EAP_FAILURE => {
                return Err(SessionError::new(
                    ErrorCode::UserAuthFailed,
                    "Authentication failed: wrong username or password",
                ));
            }
            eap::EAP_REQUEST => {
                let (rtype, rdata) = match pkt.type_ {
                    Some(eap::TYPE_IDENTITY) => {
                        info!(target: TARGET, "EAP-Request/Identity");
                        (eap::TYPE_IDENTITY, username.as_bytes().to_vec())
                    }
                    Some(eap::TYPE_MSCHAPV2) => {
                        let op = *pkt.data.first().ok_or_else(short_mschap)?;
                        match op {
                            eap::MS_CHALLENGE => {
                                if pkt.data.len() < 21 || pkt.data[4] != 16 {
                                    return Err(short_mschap());
                                }
                                let ms_id = pkt.data[1];
                                let mut ac = [0u8; 16];
                                ac.copy_from_slice(&pkt.data[5..21]);
                                let r = eap::make_response(&ac, username, password);
                                let data = eap::build_mschap_response_data(
                                    ms_id,
                                    &r.peer_challenge,
                                    &r.nt_response,
                                    username,
                                );
                                mschap = Some((r, ac));
                                authenticator_verified = false;
                                info!(target: TARGET, "EAP-MSCHAPv2 challenge answered");
                                (eap::TYPE_MSCHAPV2, data)
                            }
                            eap::MS_SUCCESS => {
                                // Mutual auth: check the authenticator response "S=<40 hex>".
                                let (r, ac) = mschap.as_ref().ok_or_else(short_mschap)?;
                                let expect = eap::generate_authenticator_response(
                                    password,
                                    &r.nt_response,
                                    &r.peer_challenge,
                                    ac,
                                    username.as_bytes(),
                                );
                                let got = pkt.data.get(4..4 + expect.len()).unwrap_or_default();
                                if !ike::ct_eq(got, expect.as_bytes()) {
                                    return Err(SessionError::new(
                                        ErrorCode::GatewayAuthFailed,
                                        "Gateway authentication failed: invalid MS-CHAPv2 authenticator response",
                                    ));
                                }
                                authenticator_verified = true;
                                info!(target: TARGET, "EAP-MSCHAPv2 success (authenticator verified)");
                                (eap::TYPE_MSCHAPV2, vec![eap::MS_SUCCESS])
                            }
                            eap::MS_FAILURE => {
                                return Err(SessionError::new(
                                    ErrorCode::UserAuthFailed,
                                    "Authentication failed: wrong username or password",
                                ));
                            }
                            other => {
                                return Err(SessionError::new(
                                    ErrorCode::Internal,
                                    format!("Unexpected MS-CHAPv2 opcode {other}"),
                                ));
                            }
                        }
                    }
                    other => {
                        info!(target: TARGET, offered = ?other, "EAP method not supported; sending Nak for MSCHAPv2");
                        (eap::TYPE_NAK, vec![eap::TYPE_MSCHAPV2])
                    }
                };
                let resp = Eap {
                    code: eap::EAP_RESPONSE,
                    identifier: pkt.identifier,
                    type_: Some(rtype),
                    data: rdata,
                };
                let out = init
                    .encrypt(msg_id, &[raw(PayloadType::Eap, resp.encode())])
                    .map_err(|_| {
                        SessionError::new(ErrorCode::Internal, "Could not build EAP message")
                    })?;
                let rr = wire.exchange(&out, init.initiator_spi(), msg_id)?;
                msg_id += 1;
                let inner = decrypt_reply(init, &rr, true)?;
                eap_bytes = find(&inner, PayloadType::Eap)
                    .map(|p| p.data.clone())
                    .ok_or_else(|| {
                        SessionError::new(
                            ErrorCode::Internal,
                            "The gateway sent no EAP payload during EAP",
                        )
                    })?;
            }
            other => {
                return Err(SessionError::new(
                    ErrorCode::Internal,
                    format!("Unexpected EAP code {other}"),
                ))
            }
        }
    }

    // Final IKE_AUTH: AUTH keyed with the EAP MSK (RFC 7296 §2.16).
    let (r, _) = mschap.ok_or_else(|| {
        SessionError::new(
            ErrorCode::Internal,
            "EAP completed without MS-CHAPv2 (no key for the final AUTH)",
        )
    })?;
    let auth_val = init
        .compute_auth_with_key(&r.msk)
        .map_err(|_| SessionError::new(ErrorCode::Internal, "Could not compute the final AUTH"))?;
    let auth = AuthPayload {
        auth_method: AuthMethod::SharedKeyMic as u8,
        auth_data: auth_val,
    };
    let fm = init
        .encrypt(msg_id, &[raw(PayloadType::Auth, auth.encode())])
        .map_err(|_| SessionError::new(ErrorCode::Internal, "Could not build the final AUTH"))?;
    info!(target: TARGET, "=> IKE_AUTH (final AUTH)");
    let fr = wire.exchange(&fm, init.initiator_spi(), msg_id)?;
    msg_id += 1;
    let inner = decrypt_reply(init, &fr, true)?;
    // The gateway's MSK-keyed AUTH is mandatory: it is what proves the gateway
    // knows the user's credential, not just the shared PSK. Per RFC 7296 §2.16
    // this reply carries AUTH without IDr, so verify it over IKE_AUTH #1's IDr.
    let auth = find(&inner, PayloadType::Auth)
        .cloned()
        .ok_or_else(|| gateway_auth_error(ike::sa::Error::MissingPayload(PayloadType::Auth)))?;
    init.verify_responder_auth_with_key(&[idr, auth], &r.msk)
        .map_err(gateway_auth_error)?;
    info!(target: TARGET, "<= IKE_AUTH (EAP complete)");
    Ok((inner, msg_id))
}

fn short_mschap() -> SessionError {
    SessionError::new(
        ErrorCode::Internal,
        "Malformed MS-CHAPv2 packet from the gateway",
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    init: Initiator,
    link: Arc<dyn UdpLink>,
    gateway: SocketAddrV4,
    nat_detected: bool,
    next_msg_id: u32,
    inner: &[RawPayload],
    our_spi: [u8; 4],
    ike_suite: String,
) -> Result<Established, SessionError> {
    // Mode-config.
    let cp = find(inner, PayloadType::Cp).and_then(|p| ConfigPayload::decode(&p.data).ok());
    let assigned_ip = cp
        .as_ref()
        .and_then(|c| c.attribute(cfg::INTERNAL_IP4_ADDRESS))
        .filter(|a| a.len() == 4)
        .map(|a| Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        .ok_or_else(|| {
            SessionError::new(
                ErrorCode::NoAddressAssigned,
                "Gateway did not assign an address",
            )
        })?;
    let dns: Vec<Ipv4Addr> = cp
        .as_ref()
        .map(|c| {
            c.attributes
                .iter()
                .filter(|(t, v)| *t == cfg::INTERNAL_IP4_DNS && v.len() == 4)
                .map(|(_, v)| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
                .collect()
        })
        .unwrap_or_default();

    // Child SA.
    let sa = find(inner, PayloadType::Sa)
        .and_then(|p| SaPayload::decode(&p.data).ok())
        .ok_or_else(|| {
            SessionError::new(ErrorCode::Internal, "The gateway did not create a Child SA")
        })?;
    let (cipher, out_spi) = proposals::select_child(&sa).map_err(|e| match e {
        ChildSelectError::UnsupportedCipher => SessionError::new(
            ErrorCode::UnsupportedCipher,
            "The gateway chose an ESP cipher this client does not support",
        ),
        ChildSelectError::Malformed => {
            SessionError::new(ErrorCode::Internal, "Malformed Child SA from the gateway")
        }
    })?;
    let keymat = init
        .child_keymat(cipher.keymat_len())
        .map_err(|_| SessionError::new(ErrorCode::Internal, "Could not derive Child SA keys"))?;
    let child = ChildSa::from_keymat(cipher, &keymat, out_spi, our_spi);

    // Remote traffic selectors.
    let mut remote_ranges: Vec<(Ipv4Addr, Ipv4Addr)> = find(inner, PayloadType::Tsr)
        .and_then(|p| TsPayload::decode(&p.data).ok())
        .map(|ts| {
            ts.selectors
                .iter()
                .filter(|s| s.start_addr.len() == 4 && s.end_addr.len() == 4)
                .map(|s| {
                    let a = &s.start_addr;
                    let b = &s.end_addr;
                    (
                        Ipv4Addr::new(a[0], a[1], a[2], a[3]),
                        Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if remote_ranges.is_empty() {
        remote_ranges.push((Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    }

    info!(
        target: TARGET,
        ip = %assigned_ip,
        dns = ?dns,
        esp = cipher.name(),
        remote_ts = ?remote_ranges,
        "Child SA established"
    );
    Ok(Established {
        ike: init,
        link,
        gateway,
        nat_detected,
        next_msg_id,
        child,
        assigned_ip,
        dns,
        remote_ranges,
        ike_suite,
        esp_suite: cipher.name().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_strength_orders_groups() {
        assert!(dh_strength(DhGroup::Curve25519) > dh_strength(DhGroup::Modp2048));
        assert!(dh_strength(DhGroup::Modp2048) > dh_strength(DhGroup::Modp1536));
    }
}
