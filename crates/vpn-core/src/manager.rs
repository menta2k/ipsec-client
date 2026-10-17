//! The single-tunnel connection state machine (data-model.md).
//!
//! A worker thread owns the session lifecycle: establish -> configure network
//! (journaled) -> relay -> tear down (reverse journal), with auto-reconnect.
//! Every transition is published as `Event::State`; while connected a
//! `Event::Session` with fresh counters is published every second.

use crate::datapath::{DataPath, DataPathConfig, ExitReason};
use crate::events::EventBus;
use crate::profile::Profile;
use crate::routes;
use crate::session::{
    establish, AuthParams, Established, Phase, SessionConfig, SessionError, SessionParams,
};
use crate::store::{ProfileSecrets, ProfileStore, StoreError};
use crate::traits::*;
use ike::dh::DhGroup;
use ipc_proto::{
    AuthMode, ConnectionState, DhGroupSel, ErrorCode, Event, RequestError, SecretString,
    SessionInfo,
};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

const TARGET: &str = "manager";

/// Engine tunables.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub session: SessionConfig,
    pub datapath: DataPathConfig,
    /// Delay before each auto-reconnect attempt.
    pub reconnect_backoff: Vec<Duration>,
    /// Session-info publish interval while connected.
    pub stats_interval: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            session: SessionConfig::default(),
            datapath: DataPathConfig::default(),
            reconnect_backoff: vec![
                Duration::from_secs(5),
                Duration::from_secs(15),
                Duration::from_secs(30),
            ],
            stats_interval: Duration::from_secs(1),
        }
    }
}

/// Platform dependencies of the engine.
pub struct Deps {
    pub udp: Arc<dyn UdpFactory>,
    pub tun: Arc<dyn TunFactory>,
    pub net: Arc<dyn NetConfig>,
    pub journal: Arc<dyn JournalStore>,
    pub store: Arc<ProfileStore>,
    pub bus: EventBus,
    pub config: EngineConfig,
}

/// A request rejected synchronously (maps to `Response::Failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectError {
    pub code: RequestError,
    pub message: String,
}

impl RejectError {
    fn new(code: RequestError, message: impl Into<String>) -> Self {
        RejectError {
            code,
            message: message.into(),
        }
    }
}

struct ConnectPlan {
    profile: Profile,
    secrets: ProfileSecrets,
    /// A one-shot password supplied with Connect (dropped after first use
    /// unless it was saved, FR-032).
    password_saved: bool,
}

enum Cmd {
    Connect(Box<ConnectPlan>),
    Disconnect,
    Shutdown(Sender<()>),
}

struct Shared {
    state: Mutex<ConnectionState>,
    session: Mutex<Option<SessionInfo>>,
    cancel: AtomicBool,
    bus: EventBus,
}

impl Shared {
    fn set_state(&self, s: ConnectionState) {
        {
            let mut cur = self.state.lock().unwrap();
            if *cur == s {
                return;
            }
            *cur = s.clone();
        }
        match &s {
            ConnectionState::Error { code, message } => {
                info!(target: TARGET, state = s.label(), code = ?code, "{message}")
            }
            _ => info!(target: TARGET, state = s.label(), "state changed"),
        }
        self.bus.publish(Event::State { state: s });
    }
}

/// Handle to the engine; cheap to share across IPC connection threads.
pub struct ConnectionManager {
    cmd_tx: Mutex<Sender<Cmd>>,
    shared: Arc<Shared>,
    store: Arc<ProfileStore>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ConnectionManager {
    /// Start the worker. Call [`recover`] first on service start.
    pub fn start(deps: Deps) -> Arc<ConnectionManager> {
        let shared = Arc::new(Shared {
            state: Mutex::new(ConnectionState::Disconnected),
            session: Mutex::new(None),
            cancel: AtomicBool::new(false),
            bus: deps.bus.clone(),
        });
        let store = deps.store.clone();
        let (tx, rx) = channel();
        let sh = shared.clone();
        let worker = std::thread::Builder::new()
            .name("manager".into())
            .spawn(move || worker(deps, sh, rx))
            .expect("spawn manager");
        Arc::new(ConnectionManager {
            cmd_tx: Mutex::new(tx),
            shared,
            store,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn state(&self) -> ConnectionState {
        self.shared.state.lock().unwrap().clone()
    }

    pub fn session(&self) -> Option<SessionInfo> {
        self.shared.session.lock().unwrap().clone()
    }

    /// The id of the profile currently in use, if a tunnel is active.
    pub fn active_profile(&self) -> Option<String> {
        match self.state() {
            ConnectionState::Connecting { profile_id, .. }
            | ConnectionState::Authenticating { profile_id }
            | ConnectionState::Connected { profile_id } => Some(profile_id),
            _ => None,
        }
    }

    /// Validate and start a connection. Progress arrives as events.
    pub fn connect(
        &self,
        id: &str,
        password: Option<SecretString>,
        save_password: bool,
    ) -> Result<(), RejectError> {
        let mut state = self.shared.state.lock().unwrap();
        if state.is_active() {
            return Err(RejectError::new(
                RequestError::AlreadyConnected,
                "Already connected",
            ));
        }
        let profile = self
            .store
            .get(id)
            .ok_or_else(|| RejectError::new(RequestError::NotFound, "Profile not found"))?;
        let given = password.filter(|p| !p.is_empty());
        if save_password && profile.auth == AuthMode::Eap {
            if let Some(pw) = &given {
                self.store
                    .set_password(id, pw.expose())
                    .map_err(store_reject)?;
            }
        }
        let mut secrets = self.store.load_secrets(id).map_err(store_reject)?;
        let password_saved = secrets.password.is_some() && (given.is_none() || save_password);
        if let Some(pw) = given {
            secrets.password = Some(Zeroizing::new(pw.expose().to_string()));
        }
        if profile.auth == AuthMode::Eap && secrets.password.is_none() {
            return Err(RejectError::new(
                RequestError::MissingSecret,
                "A password is required for this profile",
            ));
        }
        self.shared.cancel.store(false, Ordering::SeqCst);
        let new_state = ConnectionState::Connecting {
            profile_id: profile.id.clone(),
            attempt: 1,
        };
        *state = new_state.clone();
        drop(state);
        info!(target: TARGET, profile = %profile.name, "connect requested");
        self.shared.bus.publish(Event::State { state: new_state });
        let plan = ConnectPlan {
            profile,
            secrets,
            password_saved,
        };
        self.cmd_tx
            .lock()
            .unwrap()
            .send(Cmd::Connect(Box::new(plan)))
            .map_err(|_| RejectError::new(RequestError::Internal, "engine stopped"))
    }

    pub fn disconnect(&self) -> Result<(), RejectError> {
        if !self.state().is_active() {
            return Err(RejectError::new(
                RequestError::NotConnected,
                "Not connected",
            ));
        }
        info!(target: TARGET, "disconnect requested");
        self.shared.cancel.store(true, Ordering::SeqCst);
        self.cmd_tx
            .lock()
            .unwrap()
            .send(Cmd::Disconnect)
            .map_err(|_| RejectError::new(RequestError::Internal, "engine stopped"))
    }

    /// Tear down any tunnel, clean up, and stop the worker (service stop).
    pub fn shutdown(&self) {
        self.shared.cancel.store(true, Ordering::SeqCst);
        let (ack_tx, ack_rx) = channel();
        if self
            .cmd_tx
            .lock()
            .unwrap()
            .send(Cmd::Shutdown(ack_tx))
            .is_ok()
        {
            let _ = ack_rx.recv_timeout(Duration::from_secs(20));
        }
        if let Some(w) = self.worker.lock().unwrap().take() {
            let _ = w.join();
        }
    }
}

fn store_reject(e: StoreError) -> RejectError {
    match e {
        StoreError::NotFound => RejectError::new(RequestError::NotFound, "Profile not found"),
        StoreError::MissingSecret(_) => {
            RejectError::new(RequestError::MissingSecret, e.to_string())
        }
        StoreError::Invalid(_) => RejectError::new(RequestError::Invalid, e.to_string()),
        StoreError::NameTaken => RejectError::new(RequestError::NameTaken, e.to_string()),
        StoreError::Io(_) => RejectError::new(RequestError::Internal, e.to_string()),
    }
}

/// Undo network changes left by a previous unclean exit (FR-008).
pub fn recover(tun: &dyn TunFactory, net: &dyn NetConfig, journal: &dyn JournalStore) {
    match journal.load() {
        Ok(changes) if !changes.is_empty() => {
            warn!(target: TARGET, count = changes.len(), "reverting network changes from a previous run");
            for c in changes.iter().rev() {
                if let Err(e) = net.revert(c) {
                    warn!(target: TARGET, change = ?c, error = %e, "revert failed");
                }
            }
            let _ = journal.save(&[]);
        }
        Ok(_) => {}
        Err(e) => warn!(target: TARGET, error = %e, "could not read the network journal"),
    }
    if let Err(e) = tun.remove_stale() {
        warn!(target: TARGET, error = %e, "could not remove a stale adapter");
    }
}

fn worker(deps: Deps, shared: Arc<Shared>, rx: Receiver<Cmd>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Connect(plan) => {
                if let Some(ack) = run_session(&deps, &shared, &rx, *plan) {
                    let _ = ack.send(());
                    return;
                }
            }
            Cmd::Disconnect => {}
            Cmd::Shutdown(ack) => {
                let _ = ack.send(());
                return;
            }
        }
    }
}

/// Outcome of polling the command channel during a session.
enum Interrupt {
    None,
    Stop,
    Shutdown(Sender<()>),
}

fn poll_cmds(rx: &Receiver<Cmd>, shared: &Shared) -> Interrupt {
    loop {
        match rx.try_recv() {
            Ok(Cmd::Disconnect) => return Interrupt::Stop,
            Ok(Cmd::Shutdown(ack)) => return Interrupt::Shutdown(ack),
            Ok(Cmd::Connect(_)) => continue, // rejected earlier by state check
            Err(TryRecvError::Empty) => {
                return if shared.cancel.load(Ordering::SeqCst) {
                    Interrupt::Stop
                } else {
                    Interrupt::None
                }
            }
            Err(TryRecvError::Disconnected) => return Interrupt::Stop,
        }
    }
}

fn dh_of(sel: DhGroupSel) -> DhGroup {
    match sel {
        DhGroupSel::Modp2048 => DhGroup::Modp2048,
        DhGroupSel::Modp1536 => DhGroup::Modp1536,
        DhGroupSel::X25519 => DhGroup::Curve25519,
    }
}

fn params_for(plan: &ConnectPlan) -> SessionParams {
    let p = &plan.profile;
    SessionParams {
        gateway_host: p.gateway.clone(),
        port: p.port,
        id_type: p.id_type,
        local_id: p.local_id.clone(),
        dh: dh_of(p.dh_group),
        psk: plan.secrets.psk.clone(),
        auth: match p.auth {
            AuthMode::Psk => AuthParams::Psk,
            AuthMode::Eap => AuthParams::Eap {
                username: p.username.clone(),
                password: plan.secrets.password.clone().unwrap_or_default(),
            },
        },
    }
}

/// All secrets are saved, so a reconnect needs no user input.
fn can_reconnect_unattended(plan: &ConnectPlan) -> bool {
    plan.profile.has_all_secrets()
        && (plan.profile.auth == AuthMode::Psk || plan.secrets.password.is_some())
}

fn reconnectable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::GatewayUnreachable | ErrorCode::GatewayLost | ErrorCode::DeletedByGateway
    )
}

/// Run one connection (with reconnects) until it ends. Returns the shutdown
/// ack if a shutdown was requested meanwhile.
fn run_session(
    deps: &Deps,
    shared: &Shared,
    rx: &Receiver<Cmd>,
    mut plan: ConnectPlan,
) -> Option<Sender<()>> {
    let profile_id = plan.profile.id.clone();
    let mut failures: usize = 0;
    let mut attempt: u32 = 1;
    loop {
        shared.set_state(ConnectionState::Connecting {
            profile_id: profile_id.clone(),
            attempt,
        });
        let params = params_for(&plan);
        let result = establish(
            deps.udp.as_ref(),
            &params,
            &deps.config.session,
            &shared.cancel,
            &mut |ph| {
                if ph == Phase::Authenticating {
                    shared.set_state(ConnectionState::Authenticating {
                        profile_id: profile_id.clone(),
                    });
                }
            },
        );
        drop(params);

        let failure: SessionError = match result {
            Err(e) if e.cancelled => {
                shared.set_state(ConnectionState::Disconnected);
                return drain_shutdown(rx);
            }
            Err(e) => e,
            Ok(est) => {
                if !plan.password_saved {
                    plan.secrets.password = None; // one-shot password: do not retain
                }
                failures = 0;
                match run_connected(deps, shared, rx, &plan, est) {
                    Ended::UserStop(ack) => {
                        shared.set_state(ConnectionState::Disconnected);
                        return ack.or_else(|| drain_shutdown(rx));
                    }
                    Ended::Lifetime if can_reconnect_unattended(&plan) => {
                        info!(target: TARGET, "SA lifetime reached; reconnecting");
                        attempt = 1;
                        continue;
                    }
                    Ended::Lifetime => SessionError::new(
                        ErrorCode::GatewayLost,
                        "The session lifetime was reached; please reconnect",
                    ),
                    Ended::Failed(e) => e,
                }
            }
        };

        // Failure: retry if eligible, else report.
        let can_retry = plan.profile.auto_reconnect
            && can_reconnect_unattended(&plan)
            && reconnectable(failure.code)
            && failures < deps.config.reconnect_backoff.len();
        if can_retry {
            let delay = deps.config.reconnect_backoff[failures];
            failures += 1;
            attempt += 1;
            warn!(target: TARGET, reason = %failure.message, delay_s = delay.as_secs(), "reconnecting");
            shared.set_state(ConnectionState::Connecting {
                profile_id: profile_id.clone(),
                attempt,
            });
            let until = Instant::now() + delay;
            while Instant::now() < until {
                match poll_cmds(rx, shared) {
                    Interrupt::None => std::thread::sleep(Duration::from_millis(50)),
                    Interrupt::Stop => {
                        shared.set_state(ConnectionState::Disconnected);
                        return None;
                    }
                    Interrupt::Shutdown(ack) => {
                        shared.set_state(ConnectionState::Disconnected);
                        return Some(ack);
                    }
                }
            }
            continue;
        }
        error!(target: TARGET, code = ?failure.code, "connection failed: {}", failure.message);
        shared.set_state(ConnectionState::Error {
            code: failure.code,
            message: failure.message,
        });
        return drain_shutdown(rx);
    }
}

/// After a session ended, consume a pending Shutdown (so the caller can ack).
fn drain_shutdown(rx: &Receiver<Cmd>) -> Option<Sender<()>> {
    while let Ok(cmd) = rx.try_recv() {
        if let Cmd::Shutdown(ack) = cmd {
            return Some(ack);
        }
    }
    None
}

enum Ended {
    UserStop(Option<Sender<()>>),
    Lifetime,
    Failed(SessionError),
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_connected(
    deps: &Deps,
    shared: &Shared,
    rx: &Receiver<Cmd>,
    plan: &ConnectPlan,
    est: Established,
) -> Ended {
    let Established {
        ike,
        link,
        gateway,
        nat_detected,
        next_msg_id,
        child,
        assigned_ip,
        dns,
        remote_ranges,
        ike_suite,
        esp_suite,
    } = est;

    let send_delete = |ike: &ike::sa::Initiator| {
        if let Ok(del) = ike.build_delete(next_msg_id) {
            let mut f = vec![0, 0, 0, 0];
            f.extend_from_slice(&del);
            let _ = link.send(&f);
        }
    };

    let tun = match deps.tun.create() {
        Ok(t) => t,
        Err(e) => {
            send_delete(&ike);
            return Ended::Failed(SessionError::new(
                ErrorCode::TunError,
                format!("Could not create the virtual adapter: {e}"),
            ));
        }
    };
    let applied = match apply_network(
        deps,
        tun.as_ref(),
        *gateway.ip(),
        assigned_ip,
        &dns,
        &remote_ranges,
    ) {
        Ok(a) => a,
        Err(e) => {
            send_delete(&ike);
            tun.shutdown();
            return Ended::Failed(e);
        }
    };

    let plan_routes = routes::plan(&remote_ranges, *gateway.ip());
    let mut info = SessionInfo {
        profile_id: plan.profile.id.clone(),
        profile_name: plan.profile.name.clone(),
        gateway: gateway.to_string(),
        nat_detected,
        assigned_ip: Some(assigned_ip.to_string()),
        dns: dns.iter().map(|d| d.to_string()).collect(),
        ike_suite,
        esp_suite,
        remote_ts: plan_routes
            .tunnel_routes
            .iter()
            .map(|c| c.to_string())
            .collect(),
        connected_since_unix: Some(unix_now()),
        stats: Default::default(),
    };
    *shared.session.lock().unwrap() = Some(info.clone());
    shared.bus.publish(Event::Session {
        session: info.clone(),
    });
    shared.set_state(ConnectionState::Connected {
        profile_id: plan.profile.id.clone(),
    });

    let (esp_out, esp_in) = child.split();
    let dp = DataPath::start(
        ike,
        next_msg_id,
        esp_out,
        esp_in,
        link,
        tun.clone(),
        deps.config.datapath.clone(),
    );

    let mut last_pub = Instant::now();
    let (reason, ack) = loop {
        if let Some(r) = dp.wait_exit(Duration::from_millis(100)) {
            break (r, None);
        }
        match poll_cmds(rx, shared) {
            Interrupt::None => {}
            Interrupt::Stop => break (ExitReason::UserStop, None),
            Interrupt::Shutdown(ack) => break (ExitReason::UserStop, Some(ack)),
        }
        if last_pub.elapsed() >= deps.config.stats_interval {
            last_pub = Instant::now();
            info.stats = dp.stats();
            *shared.session.lock().unwrap() = Some(info.clone());
            shared.bus.publish(Event::Session {
                session: info.clone(),
            });
        }
    };

    if reason == ExitReason::UserStop {
        shared.set_state(ConnectionState::Disconnecting);
    }
    let send_del = matches!(
        reason,
        ExitReason::UserStop | ExitReason::Lifetime | ExitReason::TunFailed
    );
    let stats = dp.stop(send_del);
    revert_network(deps, &applied);
    drop(tun);
    *shared.session.lock().unwrap() = None;
    info!(
        target: TARGET,
        reason = ?reason,
        bytes_in = stats.bytes_in,
        bytes_out = stats.bytes_out,
        "tunnel closed"
    );
    match reason {
        ExitReason::UserStop => Ended::UserStop(ack),
        ExitReason::Lifetime => Ended::Lifetime,
        ExitReason::GatewayLost => Ended::Failed(SessionError::new(
            ErrorCode::GatewayLost,
            "Gateway lost: no response to liveness checks",
        )),
        ExitReason::DeletedByGateway => Ended::Failed(SessionError::new(
            ErrorCode::DeletedByGateway,
            "Disconnected by gateway",
        )),
        ExitReason::TunFailed => Ended::Failed(SessionError::new(
            ErrorCode::TunError,
            "The virtual adapter failed",
        )),
    }
}

/// Apply adapter address, routes and DNS, journaling each change first.
fn apply_network(
    deps: &Deps,
    tun: &dyn TunDevice,
    gateway: Ipv4Addr,
    ip: Ipv4Addr,
    dns: &[Ipv4Addr],
    remote: &[(Ipv4Addr, Ipv4Addr)],
) -> Result<Vec<NetChange>, SessionError> {
    let if_id = tun.if_id();
    let plan = routes::plan(remote, gateway);
    let mut changes = vec![NetChange::AdapterAddress {
        if_id,
        addr: ip,
        prefix: 32,
    }];
    if plan.gateway_host_route {
        let (gw_if, next_hop) = deps.net.best_route(gateway).map_err(|e| {
            SessionError::new(
                ErrorCode::NetConfigError,
                format!("Could not find the route to the gateway: {e}"),
            )
        })?;
        changes.push(NetChange::Route {
            if_id: gw_if,
            dest: gateway,
            prefix: 32,
            next_hop,
        });
    }
    for c in &plan.tunnel_routes {
        changes.push(NetChange::Route {
            if_id,
            dest: c.addr,
            prefix: c.prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
        });
    }
    if !dns.is_empty() {
        changes.push(NetChange::Dns {
            if_id,
            servers: dns.to_vec(),
        });
    }

    let mut applied: Vec<NetChange> = Vec::new();
    let fail = |applied: &[NetChange], c: &NetChange, e: std::io::Error| {
        revert_network(deps, applied);
        SessionError::new(
            ErrorCode::NetConfigError,
            format!("Could not configure the network ({c:?}): {e}"),
        )
    };
    for c in changes {
        // The platform may need an extra change journaled first (e.g. the
        // resolv.conf backup), so a crash can still restore the original.
        let extra = deps.net.prepare(&c).map_err(|e| fail(&applied, &c, e))?;
        for step in extra.into_iter().chain(std::iter::once(c)) {
            applied.push(step.clone());
            let journaled = deps.journal.save(&applied);
            if let Err(e) = journaled.and_then(|_| deps.net.apply(&step)) {
                applied.pop();
                return Err(fail(&applied, &step, e));
            }
        }
    }
    info!(target: TARGET, changes = applied.len(), full_tunnel = plan.full_tunnel, "network configured");
    Ok(applied)
}

fn revert_network(deps: &Deps, applied: &[NetChange]) {
    for (i, c) in applied.iter().enumerate().rev() {
        if let Err(e) = deps.net.revert(c) {
            warn!(target: TARGET, change = ?c, error = %e, "could not revert network change");
        }
        let _ = deps.journal.save(&applied[..i]);
    }
    let _ = deps.journal.save(&[]);
}
