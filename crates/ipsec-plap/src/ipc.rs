//! Bounded-time access to the service for the sign-in screen (003 research
//! R2/R3). Every call runs on a short-lived worker thread and the caller waits
//! with a deadline, so a hung or missing service can never freeze LogonUI.
//! A timed-out worker is abandoned; it ends when its pipe does.

#![forbid(unsafe_code)]

use crate::logic::{ApiError, ServiceApi, StateEvents};
use ipc_proto::client::{connect_stream, Stream};
use ipc_proto::{
    ClientError, CommandClient, ConnectionState, Event, EventStream, Request, Response,
    SecretString, SignInProfile,
};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

/// Client name sent in `Hello`; the service logs it.
pub const CLIENT_NAME: &str = "plap";
/// Limit for every call except the connect itself (FR-008).
pub const CALL_LIMIT: Duration = Duration::from_secs(3);

/// Opens a raw stream to the service.
pub type Connector = Arc<dyn Fn() -> io::Result<Box<dyn Stream>> + Send + Sync>;

static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// Worker threads still running code from this module. The DLL must not be
/// unloaded while this is non-zero (`DllCanUnloadNow`).
pub fn live_workers() -> usize {
    LIVE_WORKERS.load(Ordering::SeqCst)
}

struct WorkerGuard;

impl WorkerGuard {
    fn new() -> Self {
        LIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
        WorkerGuard
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Run `f` on a worker and wait at most `limit` for its result.
fn bounded<T: Send + 'static>(
    limit: Duration,
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let (tx, rx) = mpsc::channel();
    let guard = WorkerGuard::new();
    let spawned = std::thread::Builder::new()
        .name("plap-ipc".into())
        .spawn(move || {
            let _guard = guard;
            let _ = tx.send(f());
        });
    if spawned.is_err() {
        return Err(ApiError::Unavailable);
    }
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(RecvTimeoutError::Timeout) => Err(ApiError::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(ApiError::Unavailable),
    }
}

/// Errors before or during the handshake: the service is not there (or not
/// compatible).
fn connect_error(e: ClientError) -> ApiError {
    match e {
        ClientError::VersionMismatch { .. } | ClientError::Protocol(_) => ApiError::OutOfDate,
        ClientError::Failed { code, message } => ApiError::Failed { code, message },
        _ => ApiError::Unavailable,
    }
}

/// Errors after a successful handshake. A service that predates 003 cannot
/// parse the new requests and closes the connection: report "out of date".
fn request_error(e: ClientError) -> ApiError {
    match e {
        ClientError::Failed { code, message } => ApiError::Failed { code, message },
        ClientError::Io(ref io)
            if matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            ApiError::OutOfDate
        }
        ClientError::Protocol(_) | ClientError::VersionMismatch { .. } => ApiError::OutOfDate,
        _ => ApiError::Unavailable,
    }
}

/// [`ServiceApi`] over the service's pipe.
pub struct PipeApi {
    connector: Connector,
    limit: Duration,
}

impl Default for PipeApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeApi {
    /// The real service endpoint, whose owner is verified before anything is
    /// sent to it.
    pub fn new() -> Self {
        #[cfg(windows)]
        ipc_proto::client::set_pipe_owner_probe(crate::pipe_owner::owner_sid);
        Self::with(Arc::new(connect_stream), CALL_LIMIT)
    }

    pub fn with(connector: Connector, limit: Duration) -> Self {
        PipeApi { connector, limit }
    }

    fn request(&self, req: Request) -> Result<Response, ApiError> {
        let connector = self.connector.clone();
        bounded(self.limit, move || {
            let stream = connector().map_err(|_| ApiError::Unavailable)?;
            let mut client = CommandClient::over(stream, CLIENT_NAME).map_err(connect_error)?;
            client.request(req).map_err(request_error)
        })
    }
}

fn unexpected(r: Response) -> ApiError {
    ApiError::Failed {
        code: ipc_proto::RequestError::Internal,
        message: format!("unexpected response from the VPN service: {r:?}"),
    }
}

impl ServiceApi for PipeApi {
    fn status(&self) -> Result<ConnectionState, ApiError> {
        match self.request(Request::GetStatus)? {
            Response::Status { state, .. } => Ok(state),
            r => Err(unexpected(r)),
        }
    }

    fn list(&self) -> Result<Vec<SignInProfile>, ApiError> {
        match self.request(Request::ListSignInProfiles)? {
            Response::SignInProfiles { profiles } => Ok(profiles),
            r => Err(unexpected(r)),
        }
    }

    fn connect(&self, id: &str, password: Option<SecretString>) -> Result<(), ApiError> {
        let req = Request::ConnectAtSignIn {
            id: id.to_string(),
            password,
        };
        match self.request(req)? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    fn disconnect(&self) -> Result<(), ApiError> {
        match self.request(Request::Disconnect)? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    fn events(&self) -> Result<Box<dyn StateEvents>, ApiError> {
        let (tx, rx) = mpsc::channel::<ConnectionState>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), ApiError>>();
        let connector = self.connector.clone();
        let guard = WorkerGuard::new();
        std::thread::Builder::new()
            .name("plap-events".into())
            .spawn(move || {
                let _guard = guard;
                let stream = match connector() {
                    Ok(s) => s,
                    Err(_) => return drop(ready_tx.send(Err(ApiError::Unavailable))),
                };
                let mut events = match EventStream::over(stream, CLIENT_NAME) {
                    Ok((_, ev)) => ev,
                    Err(e) => return drop(ready_tx.send(Err(connect_error(e)))),
                };
                let _ = ready_tx.send(Ok(()));
                while let Ok(ev) = events.next_event() {
                    if let Event::State { state } = ev {
                        if tx.send(state).is_err() {
                            return; // the sign-in screen stopped listening
                        }
                    }
                }
            })
            .map_err(|_| ApiError::Unavailable)?;
        match ready_rx.recv_timeout(self.limit) {
            Ok(Ok(())) => Ok(Box::new(PipeEvents { rx })),
            Ok(Err(e)) => Err(e),
            Err(RecvTimeoutError::Timeout) => Err(ApiError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(ApiError::Unavailable),
        }
    }
}

struct PipeEvents {
    rx: mpsc::Receiver<ConnectionState>,
}

impl StateEvents for PipeEvents {
    fn next(&mut self, wait: Duration) -> Result<Option<ConnectionState>, ApiError> {
        match self.rx.recv_timeout(wait) {
            Ok(s) => Ok(Some(s)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(ApiError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_proto::client::server_handshake;
    use ipc_proto::framing::{read_frame, write_frame};
    use ipc_proto::{AuthMode, Frame};
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    /// A loopback "service": each accepted connection is handled by `serve`.
    fn server(serve: impl Fn(TcpStream) + Send + Sync + 'static) -> Connector {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let serve = Arc::new(serve);
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let serve = serve.clone();
                std::thread::spawn(move || serve(s));
            }
        });
        Arc::new(move || Ok(Box::new(TcpStream::connect(addr)?) as Box<dyn Stream>))
    }

    /// Handshake, then answer each request with `answer(req)`.
    fn answering(answer: fn(Request) -> Response) -> Connector {
        server(move |mut s| {
            if server_handshake(&mut s, "fake").is_err() {
                return;
            }
            while let Ok(Frame::Request { body }) = read_frame(&mut s) {
                let _ = write_frame(&mut s, &Frame::Response { body: answer(body) });
            }
        })
    }

    #[test]
    fn requests_are_answered() {
        let api = PipeApi::with(
            answering(|req| match req {
                Request::GetStatus => Response::Status {
                    state: ConnectionState::Disconnected,
                    session: None,
                },
                Request::ListSignInProfiles => Response::SignInProfiles {
                    profiles: vec![SignInProfile {
                        id: "a".into(),
                        name: "Office".into(),
                        auth: AuthMode::Eap,
                        username: "alice".into(),
                    }],
                },
                Request::ConnectAtSignIn { password, .. } => {
                    assert_eq!(password.unwrap().expose(), "pw");
                    Response::Ok
                }
                _ => Response::Ok,
            }),
            Duration::from_secs(3),
        );
        assert_eq!(api.status().unwrap(), ConnectionState::Disconnected);
        assert_eq!(api.list().unwrap()[0].name, "Office");
        api.connect("a", Some(SecretString::new("pw"))).unwrap();
        api.disconnect().unwrap();
    }

    #[test]
    fn refusals_carry_the_service_message() {
        let api = PipeApi::with(
            answering(|_| Response::Failed {
                code: ipc_proto::RequestError::NotAvailableAtSignIn,
                message: "This connection is not available at sign-in".into(),
            }),
            Duration::from_secs(3),
        );
        assert_eq!(
            api.connect("a", None),
            Err(ApiError::Failed {
                code: ipc_proto::RequestError::NotAvailableAtSignIn,
                message: "This connection is not available at sign-in".into()
            })
        );
    }

    #[test]
    fn a_hung_service_times_out_within_the_limit() {
        // Accepts and then never says anything (not even Hello).
        let api = PipeApi::with(
            server(|s| {
                std::thread::sleep(Duration::from_secs(5));
                drop(s);
            }),
            Duration::from_millis(200),
        );
        let t = Instant::now();
        assert_eq!(api.status(), Err(ApiError::Timeout));
        assert!(matches!(api.events().err(), Some(ApiError::Timeout)));
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn a_missing_service_is_unavailable() {
        let api = PipeApi::with(
            Arc::new(|| Err(io::Error::from(io::ErrorKind::NotFound))),
            Duration::from_secs(1),
        );
        assert_eq!(api.list(), Err(ApiError::Unavailable));
        assert!(matches!(api.events().err(), Some(ApiError::Unavailable)));
    }

    #[test]
    fn a_service_that_drops_unknown_requests_is_out_of_date() {
        // A 001 service: handshake fine, then closes on a request it cannot parse.
        let api = PipeApi::with(
            server(|mut s| {
                if server_handshake(&mut s, "old").is_ok() {
                    let _ = read_frame(&mut s);
                }
            }),
            Duration::from_secs(3),
        );
        assert_eq!(api.list(), Err(ApiError::OutOfDate));
    }

    #[test]
    fn events_are_delivered_and_quiet_periods_tick() {
        let api = PipeApi::with(
            server(|mut s| {
                if server_handshake(&mut s, "fake").is_err() {
                    return;
                }
                let _ = read_frame(&mut s); // Subscribe
                let snap = Response::Subscribed {
                    state: ConnectionState::Disconnected,
                    session: None,
                    recent_logs: vec![],
                };
                let _ = write_frame(&mut s, &Frame::Response { body: snap });
                for state in [
                    ConnectionState::Connecting {
                        profile_id: "a".into(),
                        attempt: 1,
                    },
                    ConnectionState::Connected {
                        profile_id: "a".into(),
                    },
                ] {
                    let _ = write_frame(
                        &mut s,
                        &Frame::Event {
                            body: Event::State { state },
                        },
                    );
                }
                std::thread::sleep(Duration::from_secs(2));
            }),
            Duration::from_secs(3),
        );
        let mut ev = api.events().unwrap();
        let wait = Duration::from_secs(2);
        assert!(matches!(
            ev.next(wait).unwrap(),
            Some(ConnectionState::Connecting { .. })
        ));
        assert!(matches!(
            ev.next(wait).unwrap(),
            Some(ConnectionState::Connected { .. })
        ));
        assert_eq!(ev.next(Duration::from_millis(50)).unwrap(), None);
    }
}
