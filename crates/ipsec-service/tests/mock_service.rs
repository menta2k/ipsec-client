//! Integration test: start the real `ipsec-service run --mock` binary and drive
//! it through the real IPC endpoint (the DACL-protected named pipe on Windows,
//! the Unix socket elsewhere) with the GUI's client library.

use ipc_proto::client::{connect_stream_at, Stream};
use ipc_proto::*;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A mock service on its own endpoint, killed on drop.
struct Service {
    child: Child,
    endpoint: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Service {
    fn open(&self) -> Box<dyn Stream> {
        connect_stream_at(&self.endpoint).expect("connect to mock service")
    }
    fn command(&self, name: &str) -> CommandClient {
        CommandClient::over(self.open(), name).expect("handshake")
    }
}

/// Start `run --mock`. On Windows it gets a private pipe name (003 T010), so
/// the test runs even next to an installed service. On Unix the per-user
/// socket is used; skip if something already listens there.
fn start(tag: &str) -> Option<Service> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ipsec-service"));
    cmd.args(["run", "--mock"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let endpoint = if cfg!(windows) {
        let pipe = format!(r"\\.\pipe\IpsecClient.test.{}.{tag}", std::process::id());
        cmd.env(ipc_proto::client::PIPE_ENV, &pipe);
        PathBuf::from(pipe)
    } else {
        let p = ipc_proto::client::endpoint();
        if connect_stream_at(&p).is_ok() {
            eprintln!("a mock service is already running; skipping");
            return None;
        }
        p
    };
    let svc = Service {
        child: cmd.spawn().expect("spawn ipsec-service"),
        endpoint,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(s) = connect_stream_at(&svc.endpoint) {
            if CommandClient::over(s, "probe").is_ok() {
                return Some(svc);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("mock service did not come up");
}

#[test]
fn gui_flow_against_mock_service() {
    let Some(svc) = start("gui") else { return };
    let (snap, mut events) = EventStream::over(svc.open(), "test").expect("subscribe");
    assert!(!snap.state.is_active());
    let mut c = svc.command("test");

    let name = format!("it-{}", std::process::id());
    let profile = match c
        .request(Request::CreateProfile {
            profile: ProfileEdit {
                name: name.clone(),
                gateway: "vpn.example.com".into(),
                local_id: "me".into(),
                username: "alice".into(),
                psk: SecretUpdate::Set(SecretString::new("psk-value")),
                ..Default::default()
            },
        })
        .expect("create")
    {
        Response::Profile { profile } => profile,
        r => panic!("{r:?}"),
    };
    assert!(profile.has_psk && !profile.has_password);

    // EAP without a password is refused synchronously.
    assert!(matches!(
        c.request(Request::Connect {
            id: profile.id.clone(),
            password: None,
            save_password: false
        }),
        Err(ClientError::Failed {
            code: RequestError::MissingSecret,
            ..
        })
    ));

    c.request(Request::Connect {
        id: profile.id.clone(),
        password: Some(SecretString::new("pw")),
        save_password: false,
    })
    .expect("connect");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "no Connected event; saw {saw:?}");
        if let Event::State { state } = events.next_event().expect("event") {
            saw.push(state.label());
            if matches!(state, ConnectionState::Connected { .. }) {
                break;
            }
        }
    }
    assert!(saw.contains(&"Authenticating"));
    match c.request(Request::GetStatus).unwrap() {
        Response::Status {
            session: Some(s), ..
        } => assert!(s.assigned_ip.is_some()),
        r => panic!("{r:?}"),
    }

    c.request(Request::Disconnect).expect("disconnect");
    loop {
        if let Event::State {
            state: ConnectionState::Disconnected,
        } = events.next_event().expect("event")
        {
            break;
        }
    }
    c.request(Request::DeleteProfile { id: profile.id })
        .expect("delete");
}

/// True if this process runs with a high-integrity (elevated) token.
#[cfg(windows)]
fn elevated() -> bool {
    // Full path: a POSIX `whoami` (e.g. Git Bash) may shadow it on PATH.
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Command::new(PathBuf::from(root).join("System32").join("whoami.exe"))
        .arg("/groups")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"))
        .unwrap_or(false)
}

/// 003 T009: administrator-only requests are judged by the OS-attested
/// identity of the pipe client.
#[cfg(windows)]
#[test]
fn admin_requests_follow_the_client_token() {
    let Some(svc) = start("admin") else { return };
    let mut c = svc.command("test");
    let r = c.request(Request::SetPolicy {
        policy: Policy {
            keep_tunnel_on_signout: true,
        },
    });
    if elevated() {
        assert_eq!(
            r.expect("elevated admin may change the policy"),
            Response::Policy {
                policy: Policy {
                    keep_tunnel_on_signout: true
                }
            }
        );
    } else {
        assert!(
            matches!(
                r,
                Err(ClientError::Failed {
                    code: RequestError::AdminRequired,
                    ..
                })
            ),
            "{r:?}"
        );
    }
    // Reading is open to everyone.
    assert!(matches!(
        c.request(Request::GetPolicy).unwrap(),
        Response::Policy { .. }
    ));
}
