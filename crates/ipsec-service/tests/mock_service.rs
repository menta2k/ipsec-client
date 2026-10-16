//! Integration test: start the real `ipsec-service run --mock` binary and drive
//! it through the real IPC endpoint (the DACL-protected named pipe on Windows,
//! the Unix socket elsewhere) with the GUI's client library.

use ipc_proto::*;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start() -> Option<Service> {
    if CommandClient::connect("probe").is_ok() {
        eprintln!("an ipsec-service is already running; skipping");
        return None;
    }
    let child = Command::new(env!("CARGO_BIN_EXE_ipsec-service"))
        .args(["run", "--mock"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ipsec-service");
    let svc = Service(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if CommandClient::connect("probe").is_ok() {
            return Some(svc);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("mock service did not come up");
}

#[test]
fn gui_flow_against_mock_service() {
    let Some(_svc) = start() else { return };
    let (snap, mut events) = EventStream::subscribe("test").expect("subscribe");
    assert!(!snap.state.is_active());
    let mut c = CommandClient::connect("test").expect("connect");

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
