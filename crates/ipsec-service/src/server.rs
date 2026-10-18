//! Platform-neutral IPC server: one thread per connection.
//!
//! Every frame is untrusted (FR-005): malformed input closes the connection,
//! unknown operations are rejected, and no response ever carries a secret.

use ipc_proto::client::{server_handshake, Stream};
use ipc_proto::framing::{read_frame, write_frame};
use ipc_proto::*;
use std::io;
use std::sync::Arc;
use tracing::{debug, info, warn};
use vpn_core::logbuf::LOG_REPLY_BYTES;
use vpn_core::store::StoreError;
use vpn_core::{EventBus, LogBuffer, ProfileStore, RejectError, SettingsStore};

/// Who is on the other end of a connection, as attested by the OS (003
/// research R4). Never derived from anything the client sends.
#[derive(Clone, Debug, Default)]
pub struct Peer {
    /// Windows: elevated member of Administrators, or LocalSystem.
    /// Linux: uid 0.
    pub is_admin: bool,
    /// For the log: pid / user / elevation.
    pub desc: String,
}

/// What the server needs from a connection engine (real or simulated).
pub trait Engine: Send + Sync {
    fn state(&self) -> ConnectionState;
    fn session(&self) -> Option<SessionInfo>;
    fn active_profile(&self) -> Option<String>;
    fn connect(
        &self,
        id: &str,
        password: Option<SecretString>,
        save_password: bool,
    ) -> Result<(), RejectError>;
    fn disconnect(&self) -> Result<(), RejectError>;
    /// Connect from the sign-in screen (003): profile must be available at
    /// sign-in, the password must be typed for EAP, nothing is saved.
    fn connect_at_sign_in(
        &self,
        id: &str,
        password: Option<SecretString>,
    ) -> Result<(), RejectError>;
    /// The signed-in user signed out (003): disconnect unless the policy
    /// keeps tunnels; returns once the network is restored.
    fn on_signout(&self, policy: Policy) -> bool;
    fn shutdown(&self);
}

impl Engine for vpn_core::ConnectionManager {
    fn state(&self) -> ConnectionState {
        vpn_core::ConnectionManager::state(self)
    }
    fn session(&self) -> Option<SessionInfo> {
        vpn_core::ConnectionManager::session(self)
    }
    fn active_profile(&self) -> Option<String> {
        vpn_core::ConnectionManager::active_profile(self)
    }
    fn connect(
        &self,
        id: &str,
        password: Option<SecretString>,
        save_password: bool,
    ) -> Result<(), RejectError> {
        vpn_core::ConnectionManager::connect(self, id, password, save_password)
    }
    fn disconnect(&self) -> Result<(), RejectError> {
        vpn_core::ConnectionManager::disconnect(self)
    }
    fn connect_at_sign_in(
        &self,
        id: &str,
        password: Option<SecretString>,
    ) -> Result<(), RejectError> {
        vpn_core::ConnectionManager::connect_at_sign_in(self, id, password)
    }
    fn on_signout(&self, policy: Policy) -> bool {
        vpn_core::ConnectionManager::on_signout(self, policy)
    }
    fn shutdown(&self) {
        vpn_core::ConnectionManager::shutdown(self)
    }
}

/// Accepts client connections (named pipe or Unix socket).
pub trait Listener: Send + Sync {
    /// The next connection and the OS-attested identity of its peer.
    fn accept(&self) -> io::Result<(Box<dyn Stream>, Peer)>;
    /// Unblock `accept` and refuse further connections.
    fn close(&self);
}

pub struct ServerCtx {
    pub engine: Arc<dyn Engine>,
    pub store: Arc<ProfileStore>,
    pub settings: Arc<SettingsStore>,
    pub bus: EventBus,
    pub logs: LogBuffer,
    pub service_name: String,
}

/// Accept loop; returns when the listener is closed.
pub fn run_accept_loop(
    listener: Arc<dyn Listener>,
    ctx: Arc<ServerCtx>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                warn!(target: "ipc", error = %e, "accept failed");
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("ipc-conn".into())
            .spawn(move || serve(stream, peer, &ctx));
    }
}

/// Longest error text, in bytes, that a client's frame can put in a log field.
const PEER_ERROR_MAX: usize = 512;

/// A frame-read error made safe to log (CWE-117). serde quotes the client's
/// own text in its messages (an unknown `type` or `op` value, CR/LF
/// included), so every non-printable character is escaped and the text is
/// capped, cut between characters, never inside an escape.
fn peer_error(e: &io::Error) -> String {
    let mut out = String::new();
    for c in e.to_string().chars() {
        let end = out.len();
        out.extend(c.escape_debug());
        if out.len() > PEER_ERROR_MAX {
            out.truncate(end);
            out.push_str(" [truncated]");
            break;
        }
    }
    out
}

/// Serve one client connection until it closes.
pub fn serve(mut stream: Box<dyn Stream>, peer: Peer, ctx: &ServerCtx) {
    let client = match server_handshake(&mut stream, &ctx.service_name) {
        Ok(c) => c,
        Err(e) => {
            debug!(target: "ipc", error = %peer_error(&e), "handshake rejected");
            return;
        }
    };
    debug!(target: "ipc", client = %client, peer = %peer.desc, admin = peer.is_admin, "client connected");
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == io::ErrorKind::InvalidData {
                    warn!(target: "ipc", error = %peer_error(&e), "malformed frame; closing connection");
                }
                return;
            }
        };
        let req = match frame {
            Frame::Request { body } => body,
            _ => {
                let _ = write_frame(
                    &mut stream,
                    &failed(RequestError::Invalid, "expected a Request frame"),
                );
                return;
            }
        };
        if matches!(req, Request::Subscribe) {
            stream_events(stream, ctx);
            return;
        }
        let resp = handle(req, &peer, &client, ctx);
        if write_frame(&mut stream, &Frame::Response { body: resp }).is_err() {
            return;
        }
    }
}

fn failed(code: RequestError, message: impl Into<String>) -> Frame {
    Frame::Response {
        body: Response::Failed {
            code,
            message: message.into(),
        },
    }
}

fn reject(e: RejectError) -> Response {
    Response::Failed {
        code: e.code,
        message: e.message,
    }
}

fn store_err(e: StoreError) -> Response {
    let code = match &e {
        StoreError::NotFound => RequestError::NotFound,
        StoreError::Invalid(_) => RequestError::Invalid,
        StoreError::NameTaken => RequestError::NameTaken,
        StoreError::MissingSecret(_) => RequestError::MissingSecret,
        StoreError::Io(_) => RequestError::Internal,
    };
    Response::Failed {
        code,
        message: e.to_string(),
    }
}

fn admin_required() -> Response {
    Response::Failed {
        code: RequestError::AdminRequired,
        message: "Administrator rights are required for this change".into(),
    }
}

/// Dispatch one request. `peer` decides administrator-only operations;
/// `client` is the self-reported name from `Hello`, used for logging only.
pub fn handle(req: Request, peer: &Peer, client: &str, ctx: &ServerCtx) -> Response {
    let admin_only = match &req {
        Request::SetSignIn { .. } | Request::SetPolicy { .. } | Request::ImportProfile { .. } => {
            true
        }
        // A profile offered at the sign-in screen is connected as LocalSystem
        // there, so what it connects to is an administrator's decision (003).
        Request::UpdateProfile { id, .. } => ctx.store.get(id).is_some_and(|p| p.sign_in),
        _ => false,
    };
    if admin_only && !peer.is_admin {
        warn!(target: "ipc", client, peer = %peer.desc, "administrator request refused");
        return admin_required();
    }
    match req {
        Request::GetStatus => Response::Status {
            state: ctx.engine.state(),
            session: ctx.engine.session(),
        },
        Request::ListProfiles => Response::Profiles {
            profiles: ctx.store.list(),
        },
        Request::CreateProfile { profile } => match ctx.store.create(&profile) {
            Ok(v) => {
                info!(target: "ipc", name = %v.name, "profile created");
                ctx.bus.publish(Event::ProfilesChanged);
                Response::Profile { profile: v }
            }
            Err(e) => store_err(e),
        },
        Request::UpdateProfile { id, profile } => match ctx.store.update(&id, &profile) {
            Ok(v) => {
                info!(target: "ipc", name = %v.name, "profile updated");
                ctx.bus.publish(Event::ProfilesChanged);
                Response::Profile { profile: v }
            }
            Err(e) => store_err(e),
        },
        Request::DeleteProfile { id } => {
            if ctx.engine.active_profile().as_deref() == Some(id.as_str()) {
                return Response::Failed {
                    code: RequestError::Invalid,
                    message: "Disconnect before deleting the profile in use".into(),
                };
            }
            match ctx.store.delete(&id) {
                Ok(()) => {
                    info!(target: "ipc", "profile deleted");
                    ctx.bus.publish(Event::ProfilesChanged);
                    Response::Ok
                }
                Err(e) => store_err(e),
            }
        }
        Request::Connect {
            id,
            password,
            save_password,
        } => {
            info!(target: "ipc", client, peer = %peer.desc, origin = "app", "connect requested");
            match ctx.engine.connect(&id, password, save_password) {
                Ok(()) => Response::Ok,
                Err(e) => reject(e),
            }
        }
        Request::Disconnect => match ctx.engine.disconnect() {
            Ok(()) => Response::Ok,
            Err(e) => reject(e),
        },
        Request::GetLogs { max } => Response::Logs {
            lines: ctx
                .logs
                .recent_within(max.min(MAX_LOG_LINES) as usize, LOG_REPLY_BYTES),
        },
        Request::Subscribe => Response::Failed {
            code: RequestError::Invalid,
            message: "Subscribe ends a connection".into(),
        },
        Request::ListSignInProfiles => Response::SignInProfiles {
            profiles: ctx.store.sign_in_profiles(),
        },
        Request::ConnectAtSignIn { id, password } => {
            info!(target: "ipc", client, peer = %peer.desc, origin = "sign_in_screen", "connect requested at sign-in");
            match ctx.engine.connect_at_sign_in(&id, password) {
                Ok(()) => Response::Ok,
                Err(e) => reject(e),
            }
        }
        Request::SetSignIn { id, enabled } => match ctx.store.set_sign_in(&id, enabled) {
            Ok(v) => {
                info!(target: "ipc", name = ?v.name, enabled, peer = %peer.desc, "sign-in availability changed");
                ctx.bus.publish(Event::ProfilesChanged);
                Response::Profile { profile: v }
            }
            Err(e) => store_err(e),
        },
        Request::GetPolicy => Response::Policy {
            policy: ctx.settings.get(),
        },
        Request::SetPolicy { policy } => match ctx.settings.set(policy) {
            Ok(()) => {
                info!(target: "ipc", keep_tunnel_on_signout = policy.keep_tunnel_on_signout, peer = %peer.desc, "sign-out policy changed");
                Response::Policy { policy }
            }
            Err(e) => Response::Failed {
                code: RequestError::Internal,
                message: format!("Could not save the policy: {e}"),
            },
        },
        Request::ImportProfile { profile, sign_in } => match ctx.store.import(&profile, sign_in) {
            Ok(v) => {
                info!(target: "ipc", name = %v.name, sign_in, peer = %peer.desc, "profile imported");
                ctx.bus.publish(Event::ProfilesChanged);
                Response::Profile { profile: v }
            }
            Err(e) => store_err(e),
        },
    }
}

/// Subscription mode: snapshot, then push events until the client goes away.
fn stream_events(mut stream: Box<dyn Stream>, ctx: &ServerCtx) {
    // Subscribe before taking the snapshot so no event is lost in between.
    let rx = ctx.bus.subscribe();
    let snapshot = Response::Subscribed {
        state: ctx.engine.state(),
        session: ctx.engine.session(),
        recent_logs: ctx.logs.recent_within(500, LOG_REPLY_BYTES),
    };
    if write_frame(&mut stream, &Frame::Response { body: snapshot }).is_err() {
        return;
    }
    // `recv` also fails once the bus has dropped this subscriber for falling
    // a full queue behind (`vpn_core::events::SUBSCRIBER_QUEUE_LIMIT`); the
    // stream is then closed and the client must resubscribe.
    while let Ok(ev) = rx.recv() {
        if write_frame(&mut stream, &Frame::Event { body: ev }).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_proto::client::{CommandClient, EventStream};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use vpn_core::mock::InsecureMockProtector;
    use vpn_core::SettingsStore;

    #[derive(Default)]
    struct FakeEngine {
        connected: Mutex<Option<String>>,
        last_password: Mutex<Option<String>>,
        sign_in_connects: Mutex<Vec<(String, Option<String>)>>,
    }

    impl Engine for FakeEngine {
        fn state(&self) -> ConnectionState {
            match &*self.connected.lock().unwrap() {
                Some(id) => ConnectionState::Connected {
                    profile_id: id.clone(),
                },
                None => ConnectionState::Disconnected,
            }
        }
        fn session(&self) -> Option<SessionInfo> {
            None
        }
        fn active_profile(&self) -> Option<String> {
            self.connected.lock().unwrap().clone()
        }
        fn connect(
            &self,
            id: &str,
            password: Option<SecretString>,
            _save: bool,
        ) -> Result<(), RejectError> {
            *self.last_password.lock().unwrap() = password.map(|p| p.expose().to_string());
            *self.connected.lock().unwrap() = Some(id.to_string());
            Ok(())
        }
        fn disconnect(&self) -> Result<(), RejectError> {
            self.connected
                .lock()
                .unwrap()
                .take()
                .map(|_| ())
                .ok_or(RejectError {
                    code: RequestError::NotConnected,
                    message: "Not connected".into(),
                })
        }
        fn connect_at_sign_in(
            &self,
            id: &str,
            password: Option<SecretString>,
        ) -> Result<(), RejectError> {
            self.sign_in_connects
                .lock()
                .unwrap()
                .push((id.to_string(), password.map(|p| p.expose().to_string())));
            Ok(())
        }
        fn on_signout(&self, _policy: Policy) -> bool {
            false
        }
        fn shutdown(&self) {}
    }

    fn settings_path() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir()
            .join(format!("ipsec-server-test-{}-{n}", std::process::id()))
            .join("settings.json")
    }

    fn ctx() -> (Arc<ServerCtx>, Arc<FakeEngine>) {
        let engine = Arc::new(FakeEngine::default());
        let bus = EventBus::new();
        let ctx = Arc::new(ServerCtx {
            engine: engine.clone(),
            store: Arc::new(ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap()),
            settings: Arc::new(SettingsStore::open(settings_path()).0),
            bus: bus.clone(),
            logs: LogBuffer::new(100, Some(bus)),
            service_name: "test".into(),
        });
        (ctx, engine)
    }

    fn connect(ctx: &Arc<ServerCtx>) -> TcpStream {
        connect_as(ctx, false)
    }

    /// A served connection whose peer is (or is not) an administrator.
    fn connect_as(ctx: &Arc<ServerCtx>, is_admin: bool) -> TcpStream {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let ctx = ctx.clone();
        let peer = Peer {
            is_admin,
            desc: format!("test admin={is_admin}"),
        };
        std::thread::spawn(move || serve(Box::new(s), peer, &ctx));
        c
    }

    fn failed_code(r: Result<Response, ipc_proto::ClientError>) -> RequestError {
        match r {
            Err(ipc_proto::ClientError::Failed { code, .. }) => code,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// Every connect is logged with its origin and the OS-attested peer
    /// (003 FR-015).
    #[test]
    fn connects_are_logged_with_origin_and_peer() {
        use tracing_subscriber::prelude::*;
        let (ctx, _) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        ctx.store.set_sign_in(&id, true).unwrap();
        let peer = Peer {
            is_admin: false,
            desc: "pid=4242 user=TEST\\alice".into(),
        };
        let sub = tracing_subscriber::registry().with(ctx.logs.layer());
        tracing::subscriber::with_default(sub, || {
            handle(
                Request::Connect {
                    id: id.clone(),
                    password: Some(SecretString::new("pw")),
                    save_password: false,
                },
                &peer,
                "gui",
                &ctx,
            );
            handle(
                Request::ConnectAtSignIn {
                    id: id.clone(),
                    password: Some(SecretString::new("pw")),
                },
                &peer,
                "plap",
                &ctx,
            );
        });
        let lines: Vec<String> = ctx.logs.recent(50).into_iter().map(|l| l.message).collect();
        let find = |origin: &str| {
            lines
                .iter()
                .find(|m| m.contains(&format!("origin={origin}")))
                .unwrap_or_else(|| panic!("no origin={origin} line in {lines:?}"))
                .clone()
        };
        let app = find("app");
        assert!(
            app.contains("pid=4242") && app.contains("client=gui"),
            "{app}"
        );
        let sign_in = find("sign_in_screen");
        assert!(
            sign_in.contains("pid=4242") && sign_in.contains("client=plap"),
            "{sign_in}"
        );
        assert!(
            !lines
                .iter()
                .any(|m| m.contains("pw\"") || m.contains("=pw")),
            "{lines:?}"
        );
    }

    /// A maximum-size self-reported client name is cut in the audit lines
    /// and cannot push the OS-attested peer out of them.
    #[test]
    fn huge_client_name_is_bounded_and_keeps_peer() {
        use tracing_subscriber::prelude::*;
        use vpn_core::logbuf::{MAX_FIELD_BYTES, MAX_LINE_BYTES, TRUNCATED};
        let (ctx, _) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        let peer = Peer {
            is_admin: false,
            desc: "pid=4242 user=TEST\\alice".into(),
        };
        let client = "c".repeat(ipc_proto::framing::MAX_FRAME);
        let sub = tracing_subscriber::registry().with(ctx.logs.layer());
        tracing::subscriber::with_default(sub, || {
            handle(
                Request::SetPolicy {
                    policy: Policy {
                        keep_tunnel_on_signout: true,
                    },
                },
                &peer,
                &client,
                &ctx,
            );
            handle(
                Request::Connect {
                    id: id.clone(),
                    password: None,
                    save_password: false,
                },
                &peer,
                &client,
                &ctx,
            );
        });
        let lines = ctx.logs.recent(50);
        let find = |start: &str| {
            lines
                .iter()
                .find(|l| l.message.starts_with(start))
                .unwrap_or_else(|| panic!("no {start} line"))
                .message
                .clone()
        };
        let kept = format!(" client={}{TRUNCATED} ", "c".repeat(MAX_FIELD_BYTES));
        for m in [
            find("administrator request refused"),
            find("connect requested"),
        ] {
            assert!(m.len() <= MAX_LINE_BYTES + TRUNCATED.len(), "{}", m.len());
            assert!(m.contains(&kept), "client not cut");
            assert!(m.contains(" peer=pid=4242 user=TEST\\alice"), "peer lost");
        }
        assert!(find("connect requested").ends_with(" origin=app"));
    }

    /// A ring full of maximum-size lines that escape worst on the wire is
    /// still served in one frame by GetLogs and the Subscribe snapshot, and a
    /// subscriber still receives such a line as a Log event.
    #[test]
    fn worst_case_log_replies_fit_one_frame() {
        use ipc_proto::framing::MAX_FRAME;
        use tracing_subscriber::prelude::*;
        use vpn_core::logbuf::LOG_CAPACITY;
        let bus = EventBus::new();
        let ctx = Arc::new(ServerCtx {
            engine: Arc::new(FakeEngine::default()),
            store: Arc::new(ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap()),
            settings: Arc::new(SettingsStore::open(settings_path()).0),
            bus: bus.clone(),
            logs: LogBuffer::new(LOG_CAPACITY, Some(bus)),
            service_name: "test".into(),
        });
        let peer = Peer {
            is_admin: false,
            desc: "pid=4242 user=TEST\\alice".into(),
        };
        // A control character takes six bytes once serialized.
        let client = "\u{1}".repeat(MAX_FRAME);
        let refused = || {
            handle(
                Request::SetPolicy {
                    policy: Policy {
                        keep_tunnel_on_signout: true,
                    },
                },
                &peer,
                &client,
                &ctx,
            )
        };
        let logging = tracing::Dispatch::new(tracing_subscriber::registry().with(ctx.logs.layer()));
        tracing::dispatcher::with_default(&logging, || {
            for _ in 0..LOG_CAPACITY {
                refused();
            }
        });

        let reply = Frame::Response {
            body: handle(Request::GetLogs { max: MAX_LOG_LINES }, &peer, "t", &ctx),
        };
        assert!(serde_json::to_vec(&reply).unwrap().len() <= MAX_FRAME);
        match reply {
            Frame::Response {
                body: Response::Logs { lines },
            } => {
                assert!(!lines.is_empty());
                assert!(lines.iter().all(|l| l.message.contains("peer=pid=4242")));
            }
            r => panic!("{r:?}"),
        }

        let (snap, mut events) = EventStream::over(Box::new(connect(&ctx)), "t").unwrap();
        assert!(!snap.recent_logs.is_empty());
        tracing::dispatcher::with_default(&logging, || {
            refused();
        });
        match events.next_event().unwrap() {
            Event::Log { line } => assert!(line.message.contains("peer=pid=4242")),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn admin_only_requests_are_refused_for_other_users() {
        let (ctx, _) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        let mut c = CommandClient::over(Box::new(connect_as(&ctx, false)), "t").unwrap();
        assert_eq!(
            failed_code(c.request(Request::SetSignIn {
                id: id.clone(),
                enabled: true
            })),
            RequestError::AdminRequired
        );
        assert_eq!(
            failed_code(c.request(Request::SetPolicy {
                policy: Policy {
                    keep_tunnel_on_signout: true
                }
            })),
            RequestError::AdminRequired
        );
        let mut imported = edit();
        imported.name = "Imported".into();
        assert_eq!(
            failed_code(c.request(Request::ImportProfile {
                profile: imported,
                sign_in: true
            })),
            RequestError::AdminRequired
        );
        // Nothing changed.
        assert!(ctx.store.sign_in_profiles().is_empty());
        assert_eq!(ctx.settings.get(), Policy::default());
        assert_eq!(ctx.store.list().len(), 1);
    }

    #[test]
    fn only_administrators_edit_sign_in_profiles() {
        let (ctx, _) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        ctx.store.set_sign_in(&id, true).unwrap();
        let mut repointed = edit();
        repointed.gateway = "attacker.example".into();

        let mut user = CommandClient::over(Box::new(connect_as(&ctx, false)), "t").unwrap();
        assert_eq!(
            failed_code(user.request(Request::UpdateProfile {
                id: id.clone(),
                profile: repointed.clone(),
            })),
            RequestError::AdminRequired
        );
        let kept = ctx.store.get(&id).unwrap();
        assert!(kept.sign_in && kept.gateway == "vpn.example.com");

        // Profiles not offered at sign-in stay editable by anyone.
        let mut home = edit();
        home.name = "Home".into();
        let home_id = ctx.store.create(&home).unwrap().id;
        home.gateway = "home.example.com".into();
        assert!(matches!(
            user.request(Request::UpdateProfile {
                id: home_id,
                profile: home,
            })
            .unwrap(),
            Response::Profile { .. }
        ));

        let mut admin = CommandClient::over(Box::new(connect_as(&ctx, true)), "t").unwrap();
        match admin
            .request(Request::UpdateProfile {
                id,
                profile: repointed,
            })
            .unwrap()
        {
            Response::Profile { profile } => {
                assert!(profile.sign_in && profile.gateway == "attacker.example")
            }
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn administrators_manage_sign_in_and_policy() {
        let (ctx, _) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        let (_, mut events) = EventStream::over(Box::new(connect(&ctx)), "t").unwrap();
        let mut admin = CommandClient::over(Box::new(connect_as(&ctx, true)), "t").unwrap();

        match admin
            .request(Request::SetSignIn {
                id: id.clone(),
                enabled: true,
            })
            .unwrap()
        {
            Response::Profile { profile } => assert!(profile.sign_in),
            r => panic!("{r:?}"),
        }
        while events.next_event().unwrap() != Event::ProfilesChanged {}

        let keep = Policy {
            keep_tunnel_on_signout: true,
        };
        assert_eq!(
            admin.request(Request::SetPolicy { policy: keep }).unwrap(),
            Response::Policy { policy: keep }
        );
        assert_eq!(ctx.settings.get(), keep);

        let mut imported = edit();
        imported.name = "Lab".into();
        match admin
            .request(Request::ImportProfile {
                profile: imported,
                sign_in: true,
            })
            .unwrap()
        {
            Response::Profile { profile } => assert!(profile.sign_in && profile.name == "Lab"),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn anyone_may_list_sign_in_profiles_read_policy_and_connect_at_sign_in() {
        let (ctx, engine) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        ctx.store.set_sign_in(&id, true).unwrap();
        let mut c = CommandClient::over(Box::new(connect(&ctx)), "plap").unwrap();

        let listed = c.request(Request::ListSignInProfiles).unwrap();
        let wire = serde_json::to_string(&listed).unwrap();
        assert!(
            !wire.contains("SuperSecret") && !wire.contains("vpn.example.com"),
            "{wire}"
        );
        match listed {
            Response::SignInProfiles { profiles } => {
                assert_eq!(profiles.len(), 1);
                assert_eq!(profiles[0].username, "alice");
            }
            r => panic!("{r:?}"),
        }
        assert_eq!(
            c.request(Request::GetPolicy).unwrap(),
            Response::Policy {
                policy: Policy::default()
            }
        );
        assert_eq!(
            c.request(Request::ConnectAtSignIn {
                id: id.clone(),
                password: Some(SecretString::new("typed")),
            })
            .unwrap(),
            Response::Ok
        );
        assert_eq!(
            *engine.sign_in_connects.lock().unwrap(),
            vec![(id, Some("typed".to_string()))]
        );
        // A sign-in connect never goes through the normal connect path.
        assert!(engine.last_password.lock().unwrap().is_none());
    }

    fn edit() -> ProfileEdit {
        ProfileEdit {
            name: "Office".into(),
            gateway: "vpn.example.com".into(),
            local_id: "me".into(),
            username: "alice".into(),
            psk: SecretUpdate::Set(SecretString::new("SuperSecretPSK")),
            password: SecretUpdate::Set(SecretString::new("SuperSecretPassword")),
            ..Default::default()
        }
    }

    #[test]
    fn profile_crud_and_no_secrets_in_responses() {
        let (ctx, _) = ctx();
        let mut c = CommandClient::over(Box::new(connect(&ctx)), "t").unwrap();
        let created = match c
            .request(Request::CreateProfile { profile: edit() })
            .unwrap()
        {
            Response::Profile { profile } => profile,
            r => panic!("{r:?}"),
        };
        assert!(created.has_psk && created.has_password);
        let list = c.request(Request::ListProfiles).unwrap();
        let wire = serde_json::to_string(&list).unwrap();
        assert!(!wire.contains("SuperSecret"), "secret leaked: {wire}");
        assert!(matches!(
            c.request(Request::CreateProfile { profile: edit() }),
            Err(ipc_proto::ClientError::Failed {
                code: RequestError::NameTaken,
                ..
            })
        ));
        assert!(matches!(
            c.request(Request::DeleteProfile { id: created.id })
                .unwrap(),
            Response::Ok
        ));
    }

    #[test]
    fn connect_disconnect_and_delete_guard() {
        let (ctx, engine) = ctx();
        let id = ctx.store.create(&edit()).unwrap().id;
        let mut c = CommandClient::over(Box::new(connect(&ctx)), "t").unwrap();
        let r = c.request(Request::Connect {
            id: id.clone(),
            password: Some(SecretString::new("pw")),
            save_password: false,
        });
        assert!(matches!(r.unwrap(), Response::Ok));
        assert_eq!(engine.last_password.lock().unwrap().as_deref(), Some("pw"));
        // The profile in use cannot be deleted.
        assert!(matches!(
            c.request(Request::DeleteProfile { id }),
            Err(ipc_proto::ClientError::Failed {
                code: RequestError::Invalid,
                ..
            })
        ));
        assert!(matches!(
            c.request(Request::Disconnect).unwrap(),
            Response::Ok
        ));
        assert!(matches!(
            c.request(Request::Disconnect),
            Err(ipc_proto::ClientError::Failed {
                code: RequestError::NotConnected,
                ..
            })
        ));
    }

    #[test]
    fn subscription_receives_profile_events() {
        let (ctx, _) = ctx();
        let (snap, mut events) = EventStream::over(Box::new(connect(&ctx)), "t").unwrap();
        assert_eq!(snap.state, ConnectionState::Disconnected);
        let mut c = CommandClient::over(Box::new(connect(&ctx)), "t").unwrap();
        c.request(Request::CreateProfile { profile: edit() })
            .unwrap();
        // A log line and/or ProfilesChanged arrive; ProfilesChanged must be among them.
        loop {
            if events.next_event().unwrap() == Event::ProfilesChanged {
                break;
            }
        }
    }

    #[test]
    fn garbage_closes_connection_without_panic() {
        use std::io::{Read, Write};
        let (ctx, _) = ctx();
        let mut s = connect(&ctx);
        s.write_all(&[5, 0, 0, 0, b'{', b'{', b'{', b'{', b'{'])
            .unwrap();
        let mut buf = [0u8; 64];
        // The server closes (read returns 0 or an error) instead of crashing.
        let n = s.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0);
        // And still serves new clients.
        let mut c = CommandClient::over(Box::new(connect(&ctx)), "t").unwrap();
        assert!(matches!(
            c.request(Request::GetStatus).unwrap(),
            Response::Status { .. }
        ));
    }

    /// A client cannot forge log lines (CWE-117): serde quotes an unknown
    /// `type` or `op` value, CR/LF and ESC included, in the error that is
    /// logged for a bad first frame and for a bad request.
    #[test]
    fn malformed_frames_cannot_forge_log_lines() {
        use std::io::{Cursor, Read, Write};
        use tracing_subscriber::prelude::*;

        /// A client that sends a fixed byte script and ignores the replies.
        struct Scripted(Cursor<Vec<u8>>);
        impl Read for Scripted {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Write for Scripted {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        /// What the log file layer writes.
        #[derive(Clone, Default)]
        struct File(Arc<Mutex<Vec<u8>>>);
        impl Write for File {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        fn frame(json: serde_json::Value) -> Vec<u8> {
            let body = json.to_string();
            let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
            bytes.extend_from_slice(body.as_bytes());
            bytes
        }

        const FORGED: &str = "\r\n2026-01-01T00:00:00Z  WARN ipc: forged\u{1b}[2J";
        let hello = frame(serde_json::json!({
            "type": "Hello",
            "protocol_version": PROTOCOL_VERSION,
            "client": "t",
        }));
        let bad_request = frame(serde_json::json!({
            "type": "Request",
            // Long enough that the logged error is capped.
            "body": { "op": format!("GetStatus{FORGED}{}", "\n".repeat(4096)) },
        }));
        let scripts = [
            // Rejected by the handshake; logged at DEBUG.
            (
                frame(serde_json::json!({ "type": format!("Hello{FORGED}") })),
                "handshake rejected",
            ),
            // A good Hello, then a bad request; logged at WARN.
            ([hello, bad_request].concat(), "malformed frame"),
        ];

        let (ctx, _) = ctx();
        let file = File::default();
        let writer = file.clone();
        // No level filter: DEBUG and WARN both reach the ring and the file
        // layer, configured as in `logging::init`.
        let sub = tracing_subscriber::registry().with(ctx.logs.layer()).with(
            tracing_subscriber::fmt::layer()
                .with_writer(move || writer.clone())
                .with_ansi(false),
        );
        tracing::subscriber::with_default(sub, || {
            for (input, _) in &scripts {
                let stream = Scripted(Cursor::new(input.clone()));
                serve(Box::new(stream), Peer::default(), &ctx);
            }
        });

        let file = String::from_utf8(file.0.lock().unwrap().clone()).unwrap();
        let ring = ctx.logs.recent(100);
        // One file line per event, and no raw control characters anywhere.
        assert_eq!(file.lines().count(), ring.len(), "{file}");
        assert!(!file.contains('\r') && !file.contains('\u{1b}'), "{file}");
        assert!(
            !ring.iter().any(|l| l.message.chars().any(char::is_control)),
            "{ring:?}"
        );
        for (_, msg) in &scripts {
            // The client's text is kept, escaped, on the event's own line.
            let line = file.lines().find(|l| l.contains(msg)).expect(msg);
            assert!(line.contains("forged"), "{file}");
            let entry = ring.iter().find(|l| l.message.contains(msg)).expect(msg);
            assert!(entry.message.contains("forged"), "{ring:?}");
            assert!(entry.message.len() < PEER_ERROR_MAX + 100, "{ring:?}");
        }
        assert!(file.contains("[truncated]"), "{file}");
    }
}
