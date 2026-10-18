//! End-to-end test of the macOS service against the `vpn-core` mock gateway
//! (004 T021). It only runs inside the setup of `tests/macos-e2e/run.sh`, as
//! root, so it is `#[ignore]`:
//!
//! ```text
//! sudo tests/macos-e2e/run.sh
//! ```
//!
//! The service under test is `ipsec-service run`, reached at
//! `$IPSEC_CLIENT_SOCKET`; the gateway is `mock_gateway 10.99.0.1` on a
//! `lo0` alias. Secrets and addresses match `vpn-core/examples/mock_gateway.rs`.

#![cfg(target_os = "macos")]

use ipc_proto::client::connect_stream_at;
use ipc_proto::*;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const GATEWAY: &str = "10.99.0.1";
const ASSIGNED: &str = "10.10.0.2";
const VPN_DNS: &str = "10.10.0.1";
/// Behind the gateway, which echoes everything back.
const REMOTE_HOST: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 9);

fn socket() -> PathBuf {
    std::env::var_os(client::SOCKET_ENV)
        .map(PathBuf::from)
        .expect("IPSEC_CLIENT_SOCKET must point at the service under test (use run.sh)")
}

fn command() -> CommandClient {
    CommandClient::over(connect_stream_at(&socket()).expect("connect"), "e2e").expect("hello")
}

/// State changes, read on a thread so waits can time out instead of hanging.
fn states() -> Receiver<ConnectionState> {
    let (_, mut events) =
        EventStream::over(connect_stream_at(&socket()).expect("connect"), "e2e-events")
            .expect("subscribe");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(ev) = events.next_event() {
            if let Event::State { state } = ev {
                if tx.send(state).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

fn wait_for(
    rx: &Receiver<ConnectionState>,
    what: &str,
    limit: Duration,
    done: impl Fn(&ConnectionState) -> bool,
) -> ConnectionState {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(s) if done(&s) => return s,
            Ok(s) => seen.push(s.label()),
            Err(_) => panic!("timed out waiting for {what}; saw {seen:?}"),
        }
    }
}

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {args:?}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// The utun interface holding the VPN address, if any.
fn tunnel_interface() -> Option<String> {
    let all = sh(&["ifconfig"]);
    let mut current = None;
    for line in all.lines() {
        if !line.starts_with(['\t', ' ']) {
            current = line.split(':').next().map(str::to_string);
        } else if line.trim().starts_with(&format!("inet {ASSIGNED} ")) {
            return current.filter(|n| n.starts_with("utun"));
        }
    }
    None
}

/// The interface the kernel would use for `REMOTE_HOST`.
fn route_interface() -> Option<String> {
    sh(&["route", "-n", "get", &REMOTE_HOST.to_string()])
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string))
}

fn system_dns() -> String {
    sh(&["scutil", "--dns"])
}

fn create(c: &mut CommandClient, edit: ProfileEdit) -> String {
    match c
        .request(Request::CreateProfile { profile: edit })
        .expect("create profile")
    {
        Response::Profile { profile } => profile.id,
        r => panic!("{r:?}"),
    }
}

fn profile(name: &str, auth: AuthMode) -> ProfileEdit {
    ProfileEdit {
        name: name.into(),
        gateway: GATEWAY.into(),
        local_id: "client.example".into(),
        auth,
        username: "alice".into(),
        psk: SecretUpdate::Set(SecretString::new("gateway-psk")),
        ..Default::default()
    }
}

/// A datagram to `REMOTE_HOST` comes back from the gateway's echo with the
/// addresses swapped, i.e. to our own socket: utun, ESP and back.
fn echo_through_tunnel() {
    let s = UdpSocket::bind((ASSIGNED.parse::<Ipv4Addr>().unwrap(), 0)).expect("bind VPN address");
    let port = s.local_addr().unwrap().port();
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = [0u8; 64];
    for _ in 0..10 {
        s.send_to(b"through-the-utun", (REMOTE_HOST, port))
            .expect("send");
        if let Ok((n, from)) = s.recv_from(&mut buf) {
            assert_eq!(&buf[..n], b"through-the-utun");
            assert_eq!(from.ip(), REMOTE_HOST);
            return;
        }
    }
    panic!("no echo through the tunnel");
}

fn connect_use_disconnect(id: &str, password: Option<&str>) {
    let dns_before = system_dns();
    assert_eq!(tunnel_interface(), None, "leftover utun before connect");

    let rx = states();
    let mut c = command();
    c.request(Request::Connect {
        id: id.into(),
        password: password.map(SecretString::new),
        save_password: false,
    })
    .expect("connect request");
    wait_for(&rx, "Connected", Duration::from_secs(30), |s| {
        assert!(
            !matches!(s, ConnectionState::Error { .. }),
            "connection failed: {s:?}"
        );
        matches!(s, ConnectionState::Connected { .. })
    });

    let session = match c.request(Request::GetStatus).expect("status") {
        Response::Status {
            session: Some(s), ..
        } => s,
        r => panic!("no session: {r:?}"),
    };
    assert_eq!(session.assigned_ip.as_deref(), Some(ASSIGNED));
    assert!(
        session.dns.iter().any(|d| d == VPN_DNS),
        "{:?}",
        session.dns
    );
    assert!(session.nat_detected, "forced encapsulation is NAT-T");

    let utun = tunnel_interface().expect("a utun with the VPN address");
    assert_eq!(
        route_interface().as_deref(),
        Some(utun.as_str()),
        "route via the utun"
    );
    assert!(
        system_dns().contains(VPN_DNS),
        "VPN DNS applied:\n{}",
        system_dns()
    );
    echo_through_tunnel();

    c.request(Request::Disconnect).expect("disconnect");
    wait_for(&rx, "Disconnected", Duration::from_secs(15), |s| {
        *s == ConnectionState::Disconnected
    });
    assert_eq!(tunnel_interface(), None, "utun left behind");
    assert_ne!(
        route_interface().as_deref(),
        Some(utun.as_str()),
        "route left"
    );
    let dns_after = system_dns();
    assert!(!dns_after.contains(VPN_DNS), "VPN DNS left:\n{dns_after}");
    assert_eq!(
        dns_after.matches("nameserver[").count(),
        dns_before.matches("nameserver[").count(),
        "resolver configuration restored"
    );
}

#[test]
#[ignore]
fn e2e_psk_and_eap_against_the_mock_gateway() {
    let mut c = command();
    let psk = create(&mut c, profile("e2e-psk", AuthMode::Psk));
    let eap = create(&mut c, profile("e2e-eap", AuthMode::Eap));

    connect_use_disconnect(&psk, None);
    connect_use_disconnect(&eap, Some("correct horse"));

    // A wrong password fails with the app's message and changes nothing.
    let rx = states();
    c.request(Request::Connect {
        id: eap,
        password: Some(SecretString::new("wrong password")),
        save_password: false,
    })
    .expect("connect request");
    match wait_for(&rx, "an error", Duration::from_secs(30), |s| {
        matches!(s, ConnectionState::Error { .. })
    }) {
        ConnectionState::Error { code, .. } => assert_eq!(code, ErrorCode::UserAuthFailed),
        s => panic!("{s:?}"),
    }
    assert_eq!(tunnel_interface(), None);
}

/// For `tests/macos-e2e/daemon.sh`: connect the PSK profile (creating it if
/// needed) and leave the tunnel up, so the script can crash or stop the
/// daemon underneath it.
#[test]
#[ignore]
fn daemon_connect_and_stay() {
    let mut c = command();
    let existing = match c.request(Request::ListProfiles).expect("list") {
        Response::Profiles { profiles } => profiles
            .into_iter()
            .find(|p| p.name == "daemon-psk")
            .map(|p| p.id),
        r => panic!("{r:?}"),
    };
    let id = existing.unwrap_or_else(|| create(&mut c, profile("daemon-psk", AuthMode::Psk)));
    let rx = states();
    c.request(Request::Connect {
        id,
        password: None,
        save_password: false,
    })
    .expect("connect request");
    wait_for(&rx, "Connected", Duration::from_secs(30), |s| {
        assert!(
            !matches!(s, ConnectionState::Error { .. }),
            "connection failed: {s:?}"
        );
        matches!(s, ConnectionState::Connected { .. })
    });
    assert!(tunnel_interface().is_some());
    assert!(system_dns().contains(VPN_DNS));
}

/// For `tests/macos-e2e/daemon.sh` (004 T039): connect the way the GUI does
/// (`CommandClient::connect`, with the client's ownership check) as whoever
/// runs it, and check the outcome named by `E2E_EXPECT`:
/// `allowed`, `denied` (not in the VPN group) or `impostor` (a socket that
/// root does not own; refused before anything is sent).
#[test]
#[ignore]
fn access_check() {
    let expect = std::env::var("E2E_EXPECT").expect("E2E_EXPECT=allowed|denied|impostor");
    let r = CommandClient::connect("e2e-access");
    match (expect.as_str(), r) {
        ("allowed", Ok(mut c)) => {
            c.request(Request::ListProfiles).expect("list profiles");
        }
        ("denied", Err(ClientError::Unauthorized)) => {}
        ("impostor", Err(ClientError::Unavailable(e))) => {
            assert!(e.to_string().contains("not the IpsecClient service"), "{e}");
        }
        (want, Ok(_)) => panic!("expected {want}, but connected"),
        (want, Err(e)) => panic!("expected {want}, got {e:?}"),
    }
}
