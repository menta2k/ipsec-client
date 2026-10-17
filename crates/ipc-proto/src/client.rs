//! Blocking client side of the protocol, plus handshake helpers shared with the
//! service.
//!
//! Two connections are used (research R3): a command connection (strict
//! request -> response) and an event connection (after `Subscribe` the service
//! only writes). Neither connection ever reads and writes concurrently, which
//! keeps synchronous Windows pipe handles from serializing against themselves.

use crate::framing::{read_frame, write_frame};
use crate::messages::*;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Windows named-pipe path of the service endpoint.
pub const PIPE_NAME: &str = r"\\.\pipe\IpsecClient.v1";

/// Socket of the Linux system service (002 contracts/linux-system-integration.md).
pub const SYSTEM_SOCKET: &str = "/run/ipsec-client/ipsec-client.sock";

/// Environment variable that overrides the system socket (tests, developers).
pub const SOCKET_ENV: &str = "IPSEC_CLIENT_SOCKET";

/// Environment variable that overrides the Windows pipe name for tests (003
/// research R3/R9). The installed service never reads it, and LogonUI's
/// environment is fixed by the system, so it cannot redirect real clients.
pub const PIPE_ENV: &str = "IPSEC_CLIENT_PIPE";

/// The per-user endpoint: the named pipe on Windows; on Unix the socket the
/// mock service (`run --mock`) listens on.
pub fn endpoint() -> PathBuf {
    #[cfg(windows)]
    {
        windows_pipe(&|k| std::env::var_os(k))
    }
    #[cfg(not(windows))]
    {
        user_socket(&|k| std::env::var_os(k), &std::env::temp_dir())
    }
}

/// Every endpoint a client should try, in order (002 research R6).
pub fn endpoints() -> Vec<PathBuf> {
    endpoint_candidates(
        Os::current(),
        |k| std::env::var_os(k),
        &std::env::temp_dir(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Os {
    Windows,
    Linux,
    OtherUnix,
}

impl Os {
    fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::OtherUnix
        }
    }
}

type Env<'a> = &'a dyn Fn(&str) -> Option<std::ffi::OsString>;

fn windows_pipe(env: Env<'_>) -> PathBuf {
    env(PIPE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(PIPE_NAME))
}

fn user_socket(env: Env<'_>, tmp: &std::path::Path) -> PathBuf {
    if let Some(dir) = env("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("ipsec-client.sock");
    }
    let user = env("UID")
        .or_else(|| env("USER"))
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    tmp.join(format!("ipsec-client-{user}.sock"))
}

/// Linux: override, system socket, then the per-user (mock) socket.
/// Windows keeps its single pipe; other Unixes have no system service.
fn endpoint_candidates(
    os: Os,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    tmp: &std::path::Path,
) -> Vec<PathBuf> {
    match os {
        Os::Windows => vec![windows_pipe(&env)],
        Os::Linux => {
            let mut v: Vec<PathBuf> = env(SOCKET_ENV).map(PathBuf::from).into_iter().collect();
            v.push(PathBuf::from(SYSTEM_SOCKET));
            v.push(user_socket(&env, tmp));
            v
        }
        Os::OtherUnix => vec![user_socket(&env, tmp)],
    }
}

/// A connected byte stream to the service.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
    /// Nothing is listening there; try the next candidate.
    TryNext,
    /// The endpoint exists but access control refused us. Never fall through:
    /// that would silently land an unauthorized user on another service.
    Unauthorized,
    Fail,
}

fn classify(kind: io::ErrorKind) -> Attempt {
    match kind {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Attempt::TryNext,
        io::ErrorKind::PermissionDenied => Attempt::Unauthorized,
        _ => Attempt::Fail,
    }
}

/// Connect to the first reachable endpoint of `paths`.
fn connect_first(paths: &[PathBuf]) -> io::Result<Box<dyn Stream>> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no service endpoint");
    for p in paths {
        match connect_stream_at(p) {
            Ok(s) => return Ok(s),
            Err(e) if classify(e.kind()) == Attempt::TryNext => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Open a raw stream to the service.
pub fn connect_stream() -> io::Result<Box<dyn Stream>> {
    connect_first(&endpoints())
}

/// How a failure to reach the service is reported.
fn connect_error(e: io::Error) -> ClientError {
    match classify(e.kind()) {
        Attempt::Unauthorized => ClientError::Unauthorized,
        _ => ClientError::Unavailable(e),
    }
}

/// Open a raw stream to an explicit endpoint path.
pub fn connect_stream_at(path: &std::path::Path) -> io::Result<Box<dyn Stream>> {
    #[cfg(windows)]
    {
        // All pipe instances busy (ERROR_PIPE_BUSY = 231): retry briefly.
        let mut tries = 0;
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(f) => return Ok(Box::new(f)),
                Err(e) if e.raw_os_error() == Some(231) && tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(unix)]
    {
        Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
    }
}

/// Errors seen by clients.
#[derive(Debug)]
pub enum ClientError {
    /// The service is not running / endpoint unavailable.
    Unavailable(io::Error),
    /// The service is running but this user may not control it (Linux:
    /// not in the `ipsec-client` group).
    Unauthorized,
    /// Client and service protocol versions differ.
    VersionMismatch {
        service: u32,
        client: u32,
    },
    /// The service violated the protocol (unexpected frame).
    Protocol(String),
    /// A request failed on the service side.
    Failed {
        code: RequestError,
        message: String,
    },
    Io(io::Error),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unavailable(e) => write!(f, "service not running ({e})"),
            ClientError::Unauthorized => f.write_str("not authorized to control the VPN service"),
            ClientError::VersionMismatch { service, client } => write!(
                f,
                "client and service versions are incompatible (service protocol {service}, client {client})"
            ),
            ClientError::Protocol(m) => write!(f, "protocol error: {m}"),
            ClientError::Failed { message, .. } => f.write_str(message),
            ClientError::Io(e) => write!(f, "connection error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Client half of the handshake on an already-open stream.
pub fn client_handshake<S: Read + Write>(
    s: &mut S,
    client_name: &str,
) -> Result<String, ClientError> {
    write_frame(
        s,
        &Frame::Hello {
            protocol_version: PROTOCOL_VERSION,
            client: client_name.to_string(),
        },
    )?;
    match read_frame(s)? {
        Frame::HelloOk {
            protocol_version,
            service,
        } if protocol_version == PROTOCOL_VERSION => Ok(service),
        Frame::HelloOk {
            protocol_version, ..
        } => Err(ClientError::VersionMismatch {
            service: protocol_version,
            client: PROTOCOL_VERSION,
        }),
        Frame::Error {
            code: HandshakeError::VersionMismatch,
            message,
        } => {
            let service = message
                .split_whitespace()
                .find_map(|w| w.parse().ok())
                .unwrap_or(0);
            Err(ClientError::VersionMismatch {
                service,
                client: PROTOCOL_VERSION,
            })
        }
        other => Err(ClientError::Protocol(format!(
            "unexpected handshake reply {other:?}"
        ))),
    }
}

/// Service half of the handshake. On mismatch it replies with an error frame
/// and returns `Err`; the caller must then close the connection.
pub fn server_handshake<S: Read + Write>(s: &mut S, service_name: &str) -> io::Result<String> {
    match read_frame(s)? {
        Frame::Hello {
            protocol_version,
            client,
        } if protocol_version == PROTOCOL_VERSION => {
            write_frame(
                s,
                &Frame::HelloOk {
                    protocol_version: PROTOCOL_VERSION,
                    service: service_name.to_string(),
                },
            )?;
            Ok(client)
        }
        Frame::Hello {
            protocol_version, ..
        } => {
            let _ = write_frame(
                s,
                &Frame::Error {
                    code: HandshakeError::VersionMismatch,
                    message: format!(
                        "service speaks protocol {PROTOCOL_VERSION}, client sent {protocol_version}"
                    ),
                },
            );
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protocol version mismatch",
            ))
        }
        _ => {
            let _ = write_frame(
                s,
                &Frame::Error {
                    code: HandshakeError::ProtocolError,
                    message: "expected Hello".into(),
                },
            );
            Err(io::Error::new(io::ErrorKind::InvalidData, "expected Hello"))
        }
    }
}

/// Command connection: one request, one response.
pub struct CommandClient {
    stream: Box<dyn Stream>,
    pub service_name: String,
}

impl CommandClient {
    /// Connect to the default endpoint and perform the handshake.
    pub fn connect(client_name: &str) -> Result<Self, ClientError> {
        let stream = connect_stream().map_err(connect_error)?;
        Self::over(stream, client_name)
    }

    /// Use an already-open stream (tests, custom endpoints).
    pub fn over(mut stream: Box<dyn Stream>, client_name: &str) -> Result<Self, ClientError> {
        let service_name = client_handshake(&mut stream, client_name)?;
        Ok(CommandClient {
            stream,
            service_name,
        })
    }

    /// Send a request and wait for its response. `Failed` responses become
    /// `ClientError::Failed`.
    pub fn request(&mut self, req: Request) -> Result<Response, ClientError> {
        write_frame(&mut self.stream, &Frame::Request { body: req })?;
        match read_frame(&mut self.stream)? {
            Frame::Response {
                body: Response::Failed { code, message },
            } => Err(ClientError::Failed { code, message }),
            Frame::Response { body } => Ok(body),
            other => Err(ClientError::Protocol(format!(
                "expected Response, got {other:?}"
            ))),
        }
    }
}

/// Snapshot returned when subscribing.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub state: ConnectionState,
    pub session: Option<SessionInfo>,
    pub recent_logs: Vec<LogLine>,
}

/// Event connection: yields pushed events until the service goes away.
pub struct EventStream {
    stream: Box<dyn Stream>,
}

impl EventStream {
    /// Connect to the default endpoint and subscribe.
    pub fn subscribe(client_name: &str) -> Result<(Snapshot, Self), ClientError> {
        let stream = connect_stream().map_err(connect_error)?;
        Self::over(stream, client_name)
    }

    pub fn over(
        mut stream: Box<dyn Stream>,
        client_name: &str,
    ) -> Result<(Snapshot, Self), ClientError> {
        client_handshake(&mut stream, client_name)?;
        write_frame(
            &mut stream,
            &Frame::Request {
                body: Request::Subscribe,
            },
        )?;
        match read_frame(&mut stream)? {
            Frame::Response {
                body:
                    Response::Subscribed {
                        state,
                        session,
                        recent_logs,
                    },
            } => Ok((
                Snapshot {
                    state,
                    session,
                    recent_logs,
                },
                EventStream { stream },
            )),
            other => Err(ClientError::Protocol(format!(
                "expected Subscribed, got {other:?}"
            ))),
        }
    }

    /// Block for the next event.
    pub fn next_event(&mut self) -> Result<Event, ClientError> {
        match read_frame(&mut self.stream)? {
            Frame::Event { body } => Ok(body),
            other => Err(ClientError::Protocol(format!(
                "expected Event, got {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + 'a {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| std::ffi::OsString::from(v))
        }
    }

    #[test]
    fn linux_candidates_prefer_override_then_system_then_user_socket() {
        let tmp = PathBuf::from("/tmp");
        let all = endpoint_candidates(
            Os::Linux,
            env(&[
                ("IPSEC_CLIENT_SOCKET", "/x/test.sock"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]),
            &tmp,
        );
        assert_eq!(
            all,
            [
                PathBuf::from("/x/test.sock"),
                PathBuf::from(SYSTEM_SOCKET),
                PathBuf::from("/run/user/1000/ipsec-client.sock"),
            ]
        );
        let plain = endpoint_candidates(Os::Linux, env(&[("USER", "bob")]), &tmp);
        assert_eq!(
            plain,
            [
                PathBuf::from(SYSTEM_SOCKET),
                PathBuf::from("/tmp/ipsec-client-bob.sock"),
            ]
        );
    }

    #[test]
    fn windows_pipe_can_be_overridden_for_tests() {
        let tmp = PathBuf::from("/tmp");
        let win = endpoint_candidates(
            Os::Windows,
            env(&[("IPSEC_CLIENT_PIPE", r"\\.\pipe\IpsecClient.test.7")]),
            &tmp,
        );
        assert_eq!(win, [PathBuf::from(r"\\.\pipe\IpsecClient.test.7")]);
        // The pipe override means nothing on Linux.
        let lin = endpoint_candidates(Os::Linux, env(&[("IPSEC_CLIENT_PIPE", "/x")]), &tmp);
        assert!(!lin.contains(&PathBuf::from("/x")));
    }

    #[test]
    fn other_unix_has_no_system_socket_and_windows_only_the_pipe() {
        let tmp = PathBuf::from("/tmp");
        let mac = endpoint_candidates(Os::OtherUnix, env(&[("XDG_RUNTIME_DIR", "/r")]), &tmp);
        assert_eq!(mac, [PathBuf::from("/r/ipsec-client.sock")]);
        let win = endpoint_candidates(
            Os::Windows,
            env(&[("IPSEC_CLIENT_SOCKET", "/ignored")]),
            &tmp,
        );
        assert_eq!(win, [PathBuf::from(PIPE_NAME)]);
    }

    #[test]
    fn permission_denied_stops_the_search_others_fall_through() {
        use io::ErrorKind::*;
        assert_eq!(classify(NotFound), Attempt::TryNext);
        assert_eq!(classify(ConnectionRefused), Attempt::TryNext);
        assert_eq!(classify(PermissionDenied), Attempt::Unauthorized);
        assert_eq!(classify(TimedOut), Attempt::Fail);
    }

    #[test]
    fn refused_by_access_control_is_reported_as_unauthorized() {
        let e = connect_error(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(e, ClientError::Unauthorized), "{e:?}");
        assert!(e.to_string().contains("not authorized"));
        let e = connect_error(io::Error::from(io::ErrorKind::NotFound));
        assert!(matches!(e, ClientError::Unavailable(_)), "{e:?}");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_socket_yields_unauthorized_not_fallback() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses file permissions, so the check is meaningless there.
        if std::fs::metadata("/proc/self")
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0
            })
            .unwrap_or(false)
        {
            return;
        }
        let dir = std::env::temp_dir().join(format!("ipc-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s.sock");
        let _ = std::fs::remove_file(&sock);
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let fallback = dir.join("missing.sock");
        let r = connect_first(&[sock.clone(), fallback]);
        assert_eq!(
            r.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    use std::net::{TcpListener, TcpStream};

    /// Loopback TCP stands in for the pipe/socket in tests (same byte stream).
    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        (c, s)
    }

    #[test]
    fn handshake_and_request() {
        let (c, mut s) = pair();
        let srv = std::thread::spawn(move || {
            assert_eq!(server_handshake(&mut s, "svc").unwrap(), "gui");
            match read_frame(&mut s).unwrap() {
                Frame::Request {
                    body: Request::GetStatus,
                } => {}
                f => panic!("{f:?}"),
            }
            write_frame(
                &mut s,
                &Frame::Response {
                    body: Response::Status {
                        state: ConnectionState::Disconnected,
                        session: None,
                    },
                },
            )
            .unwrap();
            match read_frame(&mut s).unwrap() {
                Frame::Request {
                    body: Request::Disconnect,
                } => {}
                f => panic!("{f:?}"),
            }
            write_frame(
                &mut s,
                &Frame::Response {
                    body: Response::Failed {
                        code: RequestError::NotConnected,
                        message: "no".into(),
                    },
                },
            )
            .unwrap();
        });
        let mut cl = CommandClient::over(Box::new(c), "gui").unwrap();
        assert_eq!(cl.service_name, "svc");
        assert!(matches!(
            cl.request(Request::GetStatus).unwrap(),
            Response::Status { .. }
        ));
        assert!(matches!(
            cl.request(Request::Disconnect),
            Err(ClientError::Failed {
                code: RequestError::NotConnected,
                ..
            })
        ));
        srv.join().unwrap();
    }

    #[test]
    fn version_mismatch_is_reported() {
        let (mut c, mut s) = pair();
        let srv = std::thread::spawn(move || server_handshake(&mut s, "svc"));
        write_frame(
            &mut c,
            &Frame::Hello {
                protocol_version: 99,
                client: "old".into(),
            },
        )
        .unwrap();
        match read_frame(&mut c).unwrap() {
            Frame::Error {
                code: HandshakeError::VersionMismatch,
                ..
            } => {}
            f => panic!("{f:?}"),
        }
        assert!(srv.join().unwrap().is_err());
    }

    #[test]
    fn subscribe_then_events() {
        let (c, mut s) = pair();
        let srv = std::thread::spawn(move || {
            server_handshake(&mut s, "svc").unwrap();
            assert!(matches!(
                read_frame(&mut s).unwrap(),
                Frame::Request {
                    body: Request::Subscribe
                }
            ));
            write_frame(
                &mut s,
                &Frame::Response {
                    body: Response::Subscribed {
                        state: ConnectionState::Disconnected,
                        session: None,
                        recent_logs: vec![],
                    },
                },
            )
            .unwrap();
            write_frame(
                &mut s,
                &Frame::Event {
                    body: Event::ProfilesChanged,
                },
            )
            .unwrap();
        });
        let (snap, mut ev) = EventStream::over(Box::new(c), "gui").unwrap();
        assert_eq!(snap.state, ConnectionState::Disconnected);
        assert_eq!(ev.next_event().unwrap(), Event::ProfilesChanged);
        srv.join().unwrap();
        assert!(ev.next_event().is_err()); // service closed
    }
}
