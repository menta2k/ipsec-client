//! End-to-end test against a real strongSwan gateway (002 T037, research
//! R11). It only runs inside the network namespaces that
//! `tests/linux-e2e/run.sh` sets up, so it is `#[ignore]`:
//!
//! ```text
//! sudo tests/linux-e2e/run.sh
//! ```
//!
//! The service under test is `ipsec-service run` in `vpn-cli`, reached at
//! `$IPSEC_CLIENT_SOCKET`; its DNS goes to the file in `$E2E_RESOLV_CONF`.
//! Identities and secrets match tests/linux-e2e/swanctl.conf.

#![cfg(target_os = "linux")]

use ipc_proto::client::connect_stream_at;
use ipc_proto::*;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const GATEWAY: &str = "10.99.0.1";
const PROTECTED_HOST: &str = "10.99.1.1";
const PROTECTED_NET: &str = "10.99.1.0/24";
const VPN_DNS: &str = "10.99.1.53";

fn socket() -> PathBuf {
    std::env::var_os(client::SOCKET_ENV)
        .map(PathBuf::from)
        .expect("IPSEC_CLIENT_SOCKET must point at the service under test (use run.sh)")
}

fn resolv_conf() -> PathBuf {
    std::env::var_os("E2E_RESOLV_CONF")
        .map(PathBuf::from)
        .expect("E2E_RESOLV_CONF must name the service's resolv.conf (use run.sh)")
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

fn sh(args: &[&str]) -> (bool, String) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {args:?}: {e}"));
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn tunnel_devices() -> Vec<String> {
    let (_, links) = sh(&["ip", "-o", "link", "show"]);
    links
        .lines()
        .filter_map(|l| l.split(": ").nth(1))
        .filter(|name| name.starts_with("ipsec"))
        .map(str::to_string)
        .collect()
}

fn protected_route() -> String {
    sh(&["ip", "route", "show", PROTECTED_NET])
        .1
        .trim()
        .to_string()
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

fn psk_profile() -> ProfileEdit {
    ProfileEdit {
        name: "e2e-psk".into(),
        gateway: GATEWAY.into(),
        local_id: "psk-client.test".into(),
        auth: AuthMode::Psk,
        psk: SecretUpdate::Set(SecretString::new("e2e-psk-secret")),
        ..Default::default()
    }
}

fn eap_profile() -> ProfileEdit {
    ProfileEdit {
        name: "e2e-eap".into(),
        gateway: GATEWAY.into(),
        local_id: "eap-client.test".into(),
        auth: AuthMode::Eap,
        username: "alice".into(),
        psk: SecretUpdate::Set(SecretString::new("e2e-eap-gateway-secret")),
        ..Default::default()
    }
}

/// Connect, check the tunnel works and is configured, disconnect, check that
/// everything is undone.
fn connect_use_disconnect(id: &str, password: Option<&str>) {
    let before_resolv = std::fs::read_to_string(resolv_conf()).expect("read resolv.conf");
    assert!(
        tunnel_devices().is_empty(),
        "leftover device before connect"
    );
    assert!(
        protected_route().is_empty(),
        "leftover route before connect"
    );

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
    let ip = session.assigned_ip.expect("assigned address");
    assert!(ip.starts_with("10.99.2."), "address from the pool: {ip}");
    assert!(
        session.dns.iter().any(|d| d == VPN_DNS),
        "{:?}",
        session.dns
    );
    assert!(
        session.nat_detected,
        "forced encapsulation must look like NAT"
    );

    assert_eq!(tunnel_devices().len(), 1, "one tunnel device");
    assert!(
        protected_route().contains("dev ipsec"),
        "route: {}",
        protected_route()
    );
    let resolv = std::fs::read_to_string(resolv_conf()).unwrap();
    assert!(
        resolv.contains(&format!("nameserver {VPN_DNS}")),
        "{resolv}"
    );

    let (ok, out) = sh(&["ping", "-c", "3", "-W", "2", PROTECTED_HOST]);
    assert!(ok, "ping through the tunnel failed:\n{out}");

    c.request(Request::Disconnect).expect("disconnect");
    wait_for(&rx, "Disconnected", Duration::from_secs(15), |s| {
        *s == ConnectionState::Disconnected
    });
    assert!(
        tunnel_devices().is_empty(),
        "device left: {:?}",
        tunnel_devices()
    );
    assert!(
        protected_route().is_empty(),
        "route left: {}",
        protected_route()
    );
    assert_eq!(
        std::fs::read_to_string(resolv_conf()).unwrap(),
        before_resolv,
        "resolv.conf restored exactly"
    );
}

#[test]
#[ignore]
fn e2e_psk_and_eap_against_strongswan() {
    let mut c = command();
    let psk = create(&mut c, psk_profile());
    let eap = create(&mut c, eap_profile());

    connect_use_disconnect(&psk, None);
    connect_use_disconnect(&eap, Some("alice-password"));

    // A wrong password fails with the app's message and changes nothing.
    let rx = states();
    c.request(Request::Connect {
        id: eap,
        password: Some(SecretString::new("wrong-password")),
        save_password: false,
    })
    .expect("connect request");
    let failed = wait_for(&rx, "an error", Duration::from_secs(30), |s| {
        matches!(s, ConnectionState::Error { .. })
    });
    match failed {
        ConnectionState::Error { code, .. } => assert_eq!(code, ErrorCode::UserAuthFailed),
        s => panic!("{s:?}"),
    }
    assert!(tunnel_devices().is_empty());
    assert!(protected_route().is_empty());
}
