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
use vpn_core::store::StoreError;
use vpn_core::{EventBus, LogBuffer, ProfileStore, RejectError};

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
    fn shutdown(&self) {
        vpn_core::ConnectionManager::shutdown(self)
    }
}

/// Accepts client connections (named pipe or Unix socket).
pub trait Listener: Send + Sync {
    fn accept(&self) -> io::Result<Box<dyn Stream>>;
    /// Unblock `accept` and refuse further connections.
    fn close(&self);
}

pub struct ServerCtx {
    pub engine: Arc<dyn Engine>,
    pub store: Arc<ProfileStore>,
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
        let stream = match listener.accept() {
            Ok(s) => s,
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
            .spawn(move || serve(stream, &ctx));
    }
}

/// Serve one client connection until it closes.
pub fn serve(mut stream: Box<dyn Stream>, ctx: &ServerCtx) {
    let client = match server_handshake(&mut stream, &ctx.service_name) {
        Ok(c) => c,
        Err(e) => {
            debug!(target: "ipc", error = %e, "handshake rejected");
            return;
        }
    };
    debug!(target: "ipc", client = %client, "client connected");
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == io::ErrorKind::InvalidData {
                    warn!(target: "ipc", error = %e, "malformed frame; closing connection");
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
        let resp = handle(req, ctx);
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

/// Dispatch one request.
pub fn handle(req: Request, ctx: &ServerCtx) -> Response {
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
        } => match ctx.engine.connect(&id, password, save_password) {
            Ok(()) => Response::Ok,
            Err(e) => reject(e),
        },
        Request::Disconnect => match ctx.engine.disconnect() {
            Ok(()) => Response::Ok,
            Err(e) => reject(e),
        },
        Request::GetLogs { max } => Response::Logs {
            lines: ctx.logs.recent(max.min(MAX_LOG_LINES) as usize),
        },
        Request::Subscribe => Response::Failed {
            code: RequestError::Invalid,
            message: "Subscribe ends a connection".into(),
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
        recent_logs: ctx.logs.recent(500),
    };
    if write_frame(&mut stream, &Frame::Response { body: snapshot }).is_err() {
        return;
    }
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

    #[derive(Default)]
    struct FakeEngine {
        connected: Mutex<Option<String>>,
        last_password: Mutex<Option<String>>,
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
        fn shutdown(&self) {}
    }

    fn ctx() -> (Arc<ServerCtx>, Arc<FakeEngine>) {
        let engine = Arc::new(FakeEngine::default());
        let bus = EventBus::new();
        let ctx = Arc::new(ServerCtx {
            engine: engine.clone(),
            store: Arc::new(ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap()),
            bus: bus.clone(),
            logs: LogBuffer::new(100, Some(bus)),
            service_name: "test".into(),
        });
        (ctx, engine)
    }

    fn connect(ctx: &Arc<ServerCtx>) -> TcpStream {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let ctx = ctx.clone();
        std::thread::spawn(move || serve(Box::new(s), &ctx));
        c
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
}
