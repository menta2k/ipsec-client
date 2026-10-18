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
use std::sync::OnceLock;

/// Windows named-pipe path of the service endpoint.
pub const PIPE_NAME: &str = r"\\.\pipe\IpsecClient.v1";

/// Owners (string SIDs) a client accepts for [`PIPE_NAME`]: LocalSystem and
/// BUILTIN\Administrators. The service creates the pipe with owner
/// Administrators (`O:BA`), and so does an elevated `ipsec-service run`.
///
/// Windows lets a process assign as owner only its own user or a group its
/// token may assign as owner (or any SID with `SeRestorePrivilege`, which only
/// privileged accounts hold), so an ordinary user cannot create a pipe owned by
/// either. Owner and DACL belong to the pipe *name*: they are set by
/// whoever creates the first instance, and every later instance shares them.
/// The service's DACL gives only SYSTEM and Administrators
/// `FILE_CREATE_PIPE_INSTANCE`, so nobody else can add instances next to the
/// service's. Together this means an impostor can serve the name only by
/// creating it while the service is not running, and then the owner gives it
/// away.
pub const TRUSTED_PIPE_OWNERS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// Reports the owner SID (string form, e.g. `S-1-5-18`) of the named pipe
/// behind an open client handle. Supplied by OS-binding code, because this
/// crate has no `unsafe`.
pub type PipeOwnerProbe = fn(&std::fs::File) -> io::Result<String>;

static PIPE_OWNER_PROBE: OnceLock<PipeOwnerProbe> = OnceLock::new();

/// Install the owner check used before anything is sent over [`PIPE_NAME`].
/// Every Windows client binary calls this at startup (the GUI, the sign-in
/// provider, the service CLI). Later calls are ignored. Without a probe,
/// connecting to [`PIPE_NAME`] fails.
pub fn set_pipe_owner_probe(probe: PipeOwnerProbe) {
    let _ = PIPE_OWNER_PROBE.set(probe);
}

/// `SECURITY_IDENTIFICATION` for `CreateFile`: the server may learn who the
/// client is but cannot act as the client.
#[cfg(windows)]
const SECURITY_IDENTIFICATION: u32 = 1 << 16;

/// True for the service's well-known name (pipe names are case-insensitive).
/// Names from [`PIPE_ENV`] are not checked: tests and developers run their own
/// unprivileged servers there, and only the user can set that variable.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_service_pipe(path: &std::path::Path) -> bool {
    path.as_os_str().eq_ignore_ascii_case(PIPE_NAME)
}

/// Decide whether the server of [`PIPE_NAME`] may receive requests, from the
/// owner the probe reported (`None`: no probe installed). Fails closed.
#[cfg_attr(not(windows), allow(dead_code))]
fn check_service_pipe_owner(owner: Option<io::Result<String>>) -> io::Result<()> {
    let owner = match owner {
        None => {
            return Err(io::Error::other(format!(
                "cannot verify who serves {PIPE_NAME}: no owner check installed"
            )))
        }
        Some(Err(e)) => {
            return Err(io::Error::other(format!(
                "cannot verify who serves {PIPE_NAME}: {e}"
            )))
        }
        Some(Ok(owner)) => owner,
    };
    if TRUSTED_PIPE_OWNERS.contains(&owner.as_str()) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "refusing {PIPE_NAME}: it is owned by {owner}, not by SYSTEM or Administrators, \
             so it is not the IpsecClient service"
        )))
    }
}

/// Socket of the Linux system service (002 contracts/linux-system-integration.md).
pub const SYSTEM_SOCKET: &str = "/run/ipsec-client/ipsec-client.sock";

/// Socket of the macOS system service (004 contracts/macos-system-integration.md):
/// in a root-owned directory that only root and the VPN group can enter.
pub const MACOS_SYSTEM_SOCKET: &str = "/var/run/ipsec-client/ipsec-client.sock";

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
    Mac,
    OtherUnix,
}

impl Os {
    fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::Mac
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

/// A candidate endpoint, tagged with how far it is trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Candidate {
    /// Connected as is: the Windows pipe, the system socket in the
    /// root-created runtime directory, or an explicit `IPSEC_CLIENT_SOCKET`.
    Fixed(PathBuf),
    /// The per-user (mock) socket. It may sit in a shared temp directory, so
    /// it is only used if its listener runs as this user.
    PerUser(PathBuf),
}

impl Candidate {
    fn into_path(self) -> PathBuf {
        match self {
            Candidate::Fixed(p) | Candidate::PerUser(p) => p,
        }
    }
}

/// Linux and macOS: override, system socket, then the per-user (mock) socket.
/// Windows keeps its single pipe; other Unixes have no system service.
fn candidates(
    os: Os,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    tmp: &std::path::Path,
) -> Vec<Candidate> {
    match os {
        Os::Windows => vec![Candidate::Fixed(windows_pipe(&env))],
        Os::Linux | Os::Mac => {
            let system = if os == Os::Linux {
                SYSTEM_SOCKET
            } else {
                MACOS_SYSTEM_SOCKET
            };
            let mut v: Vec<Candidate> = env(SOCKET_ENV)
                .map(|p| Candidate::Fixed(PathBuf::from(p)))
                .into_iter()
                .collect();
            v.push(Candidate::Fixed(PathBuf::from(system)));
            v.push(Candidate::PerUser(user_socket(&env, tmp)));
            v
        }
        Os::OtherUnix => vec![Candidate::PerUser(user_socket(&env, tmp))],
    }
}

fn endpoint_candidates(
    os: Os,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    tmp: &std::path::Path,
) -> Vec<PathBuf> {
    candidates(os, env, tmp)
        .into_iter()
        .map(Candidate::into_path)
        .collect()
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

/// Connect to the first reachable endpoint of `candidates`.
fn connect_first(candidates: &[Candidate]) -> io::Result<Box<dyn Stream>> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no service endpoint");
    for c in candidates {
        let r = match c {
            Candidate::Fixed(p) => connect_stream_at(p),
            #[cfg(unix)]
            Candidate::PerUser(p) => connect_own(p, rustix::process::geteuid().as_raw()),
            #[cfg(not(unix))]
            Candidate::PerUser(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "per-user sockets exist only on Unix",
            )),
        };
        match r {
            Ok(s) => return Ok(s),
            Err(e) if classify(e.kind()) == Attempt::TryNext => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Connect to a per-user socket, refusing it unless its listener runs as
/// `me`. The check happens before anything is written, so a socket planted
/// in a shared temp directory never receives a request (or its secrets).
/// A refusal is `ErrorKind::Other`: the search stops there.
#[cfg(unix)]
fn connect_own(path: &std::path::Path, me: u32) -> io::Result<Box<dyn Stream>> {
    let refuse = |uid: u32| {
        io::Error::other(format!(
            "refusing per-user socket {}: it belongs to uid {uid}, not to this user (uid {me})",
            path.display()
        ))
    };
    // macOS and the BSDs: rustix has no safe getpeereid, so check who owns
    // the socket entry itself (without following a symlink).
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::symlink_metadata(path)?.uid();
        if owner != me {
            return Err(refuse(owner));
        }
    }
    let s = std::os::unix::net::UnixStream::connect(path)?;
    // Linux: ask the kernel who is actually listening (SO_PEERCRED).
    #[cfg(target_os = "linux")]
    {
        let peer = rustix::net::sockopt::socket_peercred(&s).map_err(|e| {
            io::Error::other(format!(
                "refusing per-user socket {}: cannot read its listener's credentials ({e})",
                path.display()
            ))
        })?;
        if peer.uid.as_raw() != me {
            return Err(refuse(peer.uid.as_raw()));
        }
    }
    Ok(Box::new(s))
}

/// Open a raw stream to the service.
pub fn connect_stream() -> io::Result<Box<dyn Stream>> {
    connect_first(&candidates(
        Os::current(),
        |k| std::env::var_os(k),
        &std::env::temp_dir(),
    ))
}

/// How a failure to reach the service is reported.
fn connect_error(e: io::Error) -> ClientError {
    match classify(e.kind()) {
        Attempt::Unauthorized => ClientError::Unauthorized,
        _ => ClientError::Unavailable(e),
    }
}

/// Open a raw stream to an explicit endpoint path. On Windows, the service's
/// [`PIPE_NAME`] is accepted only after its owner passed
/// [`TRUSTED_PIPE_OWNERS`], before a single byte is written.
pub fn connect_stream_at(path: &std::path::Path) -> io::Result<Box<dyn Stream>> {
    #[cfg(windows)]
    {
        open_pipe(path, is_service_pipe(path))
    }
    #[cfg(unix)]
    {
        Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
    }
}

/// Like [`connect_stream_at`] on [`PIPE_NAME`], but for any pipe path: the
/// owner check is always applied. Lets tests exercise the check on private
/// pipe names.
#[cfg(windows)]
pub fn connect_verified_pipe_at(path: &std::path::Path) -> io::Result<Box<dyn Stream>> {
    open_pipe(path, true)
}

#[cfg(windows)]
fn open_pipe(path: &std::path::Path, verify_owner: bool) -> io::Result<Box<dyn Stream>> {
    use std::os::windows::fs::OpenOptionsExt;
    // All pipe instances busy (ERROR_PIPE_BUSY = 231): retry briefly.
    let mut tries = 0;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)
        {
            Ok(f) => {
                if verify_owner {
                    // On failure `f` is dropped unused: nothing was sent.
                    check_service_pipe_owner(PIPE_OWNER_PROBE.get().map(|probe| probe(&f)))?;
                }
                return Ok(Box::new(f));
            }
            Err(e) if e.raw_os_error() == Some(231) && tries < 20 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
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
        let bsd = endpoint_candidates(Os::OtherUnix, env(&[("XDG_RUNTIME_DIR", "/r")]), &tmp);
        assert_eq!(bsd, [PathBuf::from("/r/ipsec-client.sock")]);
        let win = endpoint_candidates(
            Os::Windows,
            env(&[("IPSEC_CLIENT_SOCKET", "/ignored")]),
            &tmp,
        );
        assert_eq!(win, [PathBuf::from(PIPE_NAME)]);
    }

    #[test]
    fn macos_tries_override_then_system_socket_then_per_user() {
        // 004 data-model.md: client endpoint candidates.
        let tmp = PathBuf::from("/private/tmp");
        let mac = candidates(
            Os::Mac,
            env(&[("IPSEC_CLIENT_SOCKET", "/x/test.sock"), ("USER", "bob")]),
            &tmp,
        );
        assert_eq!(
            mac,
            [
                Candidate::Fixed(PathBuf::from("/x/test.sock")),
                Candidate::Fixed(PathBuf::from(MACOS_SYSTEM_SOCKET)),
                Candidate::PerUser(PathBuf::from("/private/tmp/ipsec-client-bob.sock")),
            ]
        );
        assert_eq!(
            endpoint_candidates(Os::Mac, env(&[("USER", "bob")]), &tmp),
            [
                PathBuf::from("/var/run/ipsec-client/ipsec-client.sock"),
                PathBuf::from("/private/tmp/ipsec-client-bob.sock"),
            ]
        );
        // The Linux system socket and the Windows pipe override mean nothing.
        let mac = endpoint_candidates(Os::Mac, env(&[("IPSEC_CLIENT_PIPE", "/p")]), &tmp);
        assert!(!mac.contains(&PathBuf::from(SYSTEM_SOCKET)));
        assert!(!mac.contains(&PathBuf::from("/p")));
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
    fn only_the_service_name_gets_the_owner_check() {
        assert!(is_service_pipe(std::path::Path::new(PIPE_NAME)));
        assert!(is_service_pipe(std::path::Path::new(
            r"\\.\PIPE\ipsecclient.V1"
        )));
        assert!(!is_service_pipe(std::path::Path::new(
            r"\\.\pipe\IpsecClient.test.7"
        )));
    }

    #[test]
    fn service_pipe_must_be_owned_by_system_or_administrators() {
        assert!(check_service_pipe_owner(Some(Ok("S-1-5-18".into()))).is_ok());
        assert!(check_service_pipe_owner(Some(Ok("S-1-5-32-544".into()))).is_ok());
        // An interactive user's own pipe (name squatted while the service is
        // stopped), other well-known accounts, and junk are refused.
        for owner in [
            "S-1-5-21-1539688708-418911152-364561277-1001",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-5-4",
            "S-1-5-32-545",
            "S-1-5-18-1",
            "",
        ] {
            let e = check_service_pipe_owner(Some(Ok(owner.into()))).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::Other, "{owner}");
            assert!(e.to_string().contains("not the IpsecClient service"), "{e}");
            // Not reported as "not authorized": that is a different banner.
            assert!(matches!(connect_error(e), ClientError::Unavailable(_)));
        }
    }

    #[test]
    fn service_pipe_check_fails_closed() {
        let e = check_service_pipe_owner(None).unwrap_err();
        assert!(e.to_string().contains("no owner check installed"), "{e}");
        let e =
            check_service_pipe_owner(Some(Err(io::Error::from(io::ErrorKind::PermissionDenied))))
                .unwrap_err();
        assert!(e.to_string().contains("cannot verify"), "{e}");
        assert!(matches!(connect_error(e), ClientError::Unavailable(_)));
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
        let r = connect_first(&[Candidate::Fixed(sock.clone()), Candidate::Fixed(fallback)]);
        assert_eq!(
            r.err().map(|e| e.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_per_user_socket_is_checked() {
        let tmp = PathBuf::from("/tmp");
        let lin = candidates(
            Os::Linux,
            env(&[("IPSEC_CLIENT_SOCKET", "/x/test.sock"), ("USER", "bob")]),
            &tmp,
        );
        assert_eq!(
            lin,
            [
                Candidate::Fixed(PathBuf::from("/x/test.sock")),
                Candidate::Fixed(PathBuf::from(SYSTEM_SOCKET)),
                Candidate::PerUser(PathBuf::from("/tmp/ipsec-client-bob.sock")),
            ]
        );
        let bsd = candidates(Os::OtherUnix, env(&[("XDG_RUNTIME_DIR", "/r")]), &tmp);
        assert_eq!(
            bsd,
            [Candidate::PerUser(PathBuf::from("/r/ipsec-client.sock"))]
        );
        let win = candidates(Os::Windows, env(&[]), &tmp);
        assert_eq!(win, [Candidate::Fixed(PathBuf::from(PIPE_NAME))]);
    }

    /// A fresh directory under the temp dir, with `mode`.
    #[cfg(unix)]
    fn scratch_dir(tag: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ipc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn own_per_user_socket_connects() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        // Straight in the (possibly shared) temp dir.
        let shared = std::env::temp_dir().join(format!("ipc-own-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&shared);
        let _l1 = UnixListener::bind(&shared).unwrap();
        assert!(connect_first(&[Candidate::PerUser(shared.clone())]).is_ok());
        let _ = std::fs::remove_file(&shared);
        // In a private directory, like $XDG_RUNTIME_DIR.
        let private = scratch_dir("own-private", 0o700);
        let _l2 = UnixListener::bind(private.join("s.sock")).unwrap();
        assert!(connect_first(&[Candidate::PerUser(private.join("s.sock"))]).is_ok());
        let _ = std::fs::remove_dir_all(&private);
        // In a directory this user owns but cannot write to: no file is
        // created to learn who we are.
        let ro = scratch_dir("own-ro", 0o700);
        let _l3 = UnixListener::bind(ro.join("s.sock")).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = connect_first(&[Candidate::PerUser(ro.join("s.sock"))]);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_ok(), "{:?}", r.err());
        assert_eq!(std::fs::read_dir(&ro).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&ro);
    }

    #[cfg(unix)]
    #[test]
    fn foreign_per_user_socket_is_refused_before_anything_is_written() {
        use std::os::unix::net::UnixListener;
        let dir = scratch_dir("foreign", 0o700);
        let sock = dir.join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        // Pretend to be someone else: the listener (this process) is then
        // a different user.
        let other = rustix::process::geteuid().as_raw().wrapping_add(1);
        let e = connect_own(&sock, other).err().expect("must be refused");
        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert!(e.to_string().contains("refusing"), "{e}");
        assert_eq!(classify(e.kind()), Attempt::Fail, "must not fall through");
        assert!(matches!(connect_error(e), ClientError::Unavailable(_)));
        // The listener got either no connection at all or one that carried
        // zero bytes.
        l.set_nonblocking(true).unwrap();
        let received = match l.accept() {
            Ok((mut s, _)) => {
                s.set_nonblocking(false).unwrap();
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).unwrap();
                buf.len()
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(received, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn missing_per_user_socket_still_falls_through() {
        use std::os::unix::net::UnixListener;
        let dir = scratch_dir("missing", 0o700);
        let missing = dir.join("missing.sock");
        let r = connect_first(&[Candidate::PerUser(missing.clone())]);
        assert_eq!(r.err().map(|e| e.kind()), Some(io::ErrorKind::NotFound));
        let good = dir.join("good.sock");
        let _l = UnixListener::bind(&good).unwrap();
        assert!(connect_first(&[Candidate::PerUser(missing), Candidate::Fixed(good)]).is_ok());
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
