//! End-to-end tests: the real session driver, data path and state machine
//! against the in-process `MockResponder` over loopback UDP, with mock TUN and
//! network configuration (quickstart.md "Build & unit-test").

use ipc_proto::*;
use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Once, OnceLock};
use std::time::{Duration, Instant};
use vpn_core::datapath::DataPathConfig;
use vpn_core::manager::recover;
use vpn_core::mock::*;
use vpn_core::session::SessionConfig;
use vpn_core::traits::{JournalStore, NetChange, NetConfig};
use vpn_core::*;

const PSK: &str = "gateway-psk";
const PASSWORD: &str = "correct horse";

fn logs() -> &'static LogBuffer {
    static LOGS: OnceLock<LogBuffer> = OnceLock::new();
    static INIT: Once = Once::new();
    let b = LOGS.get_or_init(|| LogBuffer::new(100_000, None));
    INIT.call_once(|| {
        use tracing_subscriber::prelude::*;
        let sub = tracing_subscriber::registry().with(
            b.layer()
                .with_filter(tracing_subscriber::filter::LevelFilter::TRACE),
        );
        let _ = tracing::subscriber::set_global_default(sub);
    });
    b
}

struct Harness {
    mgr: Arc<ConnectionManager>,
    tun: Arc<MockTunFactory>,
    net: Arc<MockNetConfig>,
    journal: Arc<MemJournal>,
    events: Receiver<Event>,
    resp: MockResponder,
    profile_id: String,
}

fn harness(rcfg: ResponderConfig, edit: impl FnOnce(&mut ProfileEdit)) -> Harness {
    harness_with(rcfg, edit, |_| {})
}

fn harness_with(
    rcfg: ResponderConfig,
    edit: impl FnOnce(&mut ProfileEdit),
    net_setup: impl FnOnce(&MockNetConfig),
) -> Harness {
    logs();
    let resp = MockResponder::start(rcfg);
    let store = Arc::new(ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap());
    let mut e = ProfileEdit {
        name: "Mock".into(),
        gateway: "127.0.0.1".into(),
        port: resp.ike_port,
        local_id: "client.example".into(),
        username: "alice".into(),
        psk: SecretUpdate::Set(SecretString::new(PSK)),
        ..Default::default()
    };
    edit(&mut e);
    let profile_id = store.create(&e).unwrap().id;
    let tun = Arc::new(MockTunFactory::default());
    let net = Arc::new(MockNetConfig::default());
    net_setup(&net);
    let journal = Arc::new(MemJournal::default());
    let bus = EventBus::new();
    let events = bus.subscribe();
    let config = EngineConfig {
        session: SessionConfig {
            natt_port: resp.natt_port,
            bind_source_500: false,
            retransmit: vec![Duration::from_millis(300); 3],
            force_encap: true,
        },
        datapath: DataPathConfig {
            keepalive: Duration::from_millis(200),
            dpd_idle: Duration::from_millis(400),
            dpd_timeout: Duration::from_millis(800),
            dpd_retransmit: Duration::from_millis(200),
            lifetime: Duration::from_secs(3600),
            tick: Duration::from_millis(50),
        },
        reconnect_backoff: vec![Duration::from_millis(50); 3],
        stats_interval: Duration::from_millis(200),
    };
    let mgr = ConnectionManager::start(Deps {
        udp: Arc::new(vpn_core::traits::StdUdpFactory),
        tun: tun.clone(),
        net: net.clone(),
        journal: journal.clone(),
        store,
        bus,
        config,
    });
    Harness {
        mgr,
        tun,
        net,
        journal,
        events,
        resp,
        profile_id,
    }
}

impl Harness {
    fn connect(&self, password: Option<&str>) {
        self.mgr
            .connect(&self.profile_id, password.map(SecretString::new), false)
            .unwrap();
    }

    /// Wait for a state matching `pred`, returning it.
    fn wait_state(&self, what: &str, pred: impl Fn(&ConnectionState) -> bool) -> ConnectionState {
        let deadline = Instant::now() + Duration::from_secs(10);
        if pred(&self.mgr.state()) {
            return self.mgr.state();
        }
        while Instant::now() < deadline {
            if let Ok(Event::State { state }) = self.events.recv_timeout(Duration::from_millis(100))
            {
                if pred(&state) {
                    return state;
                }
            }
            if pred(&self.mgr.state()) {
                return self.mgr.state();
            }
        }
        panic!(
            "timed out waiting for {what}; state is {:?}",
            self.mgr.state()
        );
    }

    fn wait_connected(&self) {
        self.wait_state("Connected", |s| {
            matches!(s, ConnectionState::Connected { .. })
        });
    }

    fn wait_error(&self) -> ErrorCode {
        match self.wait_state("Error", |s| matches!(s, ConnectionState::Error { .. })) {
            ConnectionState::Error { code, .. } => code,
            _ => unreachable!(),
        }
    }

    fn assert_clean(&self) {
        assert!(
            self.net.applied.lock().unwrap().is_empty(),
            "network changes left: {:?}",
            self.net.applied.lock().unwrap()
        );
        assert!(
            self.journal.load().unwrap().is_empty(),
            "journal not cleared"
        );
    }
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

// ---------------------------------------------------------------- US1 (EAP)

#[test]
fn eap_connect_ping_and_disconnect() {
    let h = harness(ResponderConfig::default(), |_| {});
    h.connect(Some(PASSWORD));
    h.wait_connected();

    let s = h.mgr.session().expect("session info");
    assert_eq!(s.assigned_ip.as_deref(), Some("10.10.0.2"));
    assert_eq!(s.dns, vec!["10.10.0.1".to_string()]);
    assert_eq!(s.remote_ts, vec!["10.10.0.0/16".to_string()]);
    assert!(s.esp_suite.contains("GCM"));
    {
        let applied = h.net.applied.lock().unwrap();
        assert!(applied.contains(&NetChange::AdapterAddress {
            if_id: 7,
            addr: Ipv4Addr::new(10, 10, 0, 2),
            prefix: 32
        }));
        assert!(applied.contains(&NetChange::Route {
            if_id: 7,
            dest: Ipv4Addr::new(10, 10, 0, 0),
            prefix: 16,
            next_hop: Ipv4Addr::UNSPECIFIED
        }));
        assert!(applied.iter().any(|c| matches!(c, NetChange::Dns { .. })));
        assert_eq!(h.journal.load().unwrap().len(), applied.len());
    }

    // Data path: the mock gateway echoes with swapped addresses.
    let dev = h.tun.current().unwrap();
    let src = Ipv4Addr::new(10, 10, 0, 2);
    let dst = Ipv4Addr::new(10, 10, 5, 5);
    dev.inject(ipv4_packet(src, dst, b"ping payload"));
    let back = dev
        .delivered(Duration::from_secs(3))
        .expect("echo through the tunnel");
    assert_eq!(back, ipv4_packet(dst, src, b"ping payload"));
    // Multicast is never tunneled.
    dev.inject(ipv4_packet(src, Ipv4Addr::new(224, 0, 0, 251), b"mdns"));
    wait_until("stats", || {
        h.mgr
            .session()
            .map(|s| {
                s.stats.packets_in >= 1 && s.stats.filtered_out >= 1 && s.stats.dropped_out == 0
            })
            .unwrap_or(false)
    });

    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
    wait_until("gateway saw DELETE", || h.resp.obs().got_delete);
    assert!(dev.is_shut());
    assert!(h.mgr.session().is_none());
    h.assert_clean();
}

#[test]
fn wrong_password_reports_user_auth_failure() {
    let h = harness(
        ResponderConfig {
            password: "something else".into(),
            ..Default::default()
        },
        |_| {},
    );
    h.connect(Some(PASSWORD));
    assert_eq!(h.wait_error(), ErrorCode::UserAuthFailed);
    match h.mgr.state() {
        ConnectionState::Error { message, .. } => {
            assert!(message.contains("wrong username or password"))
        }
        s => panic!("{s:?}"),
    }
    h.assert_clean();
}

#[test]
fn gateway_auth_mismatch_aborts_before_credentials() {
    let h = harness(
        ResponderConfig {
            psk: b"impostor".to_vec(),
            ..Default::default()
        },
        |_| {},
    );
    h.connect(Some(PASSWORD));
    assert_eq!(h.wait_error(), ErrorCode::GatewayAuthFailed);
    assert!(
        !h.resp.obs().saw_eap_identity,
        "EAP identity must not be sent to an unverified gateway"
    );
    h.assert_clean();
}

#[test]
fn eap_requires_password() {
    let h = harness(ResponderConfig::default(), |_| {});
    let err = h.mgr.connect(&h.profile_id, None, false).unwrap_err();
    assert_eq!(err.code, RequestError::MissingSecret);
    assert_eq!(h.mgr.state(), ConnectionState::Disconnected);
}

#[test]
fn second_connect_is_rejected() {
    let h = harness(ResponderConfig::default(), |_| {});
    h.connect(Some(PASSWORD));
    let err = h
        .mgr
        .connect(&h.profile_id, Some(SecretString::new(PASSWORD)), false)
        .unwrap_err();
    assert_eq!(err.code, RequestError::AlreadyConnected);
    h.wait_connected();
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
}

// ---------------------------------------------------------------- US2 (PSK)

#[test]
fn psk_connect_with_cbc_child() {
    let h = harness(
        ResponderConfig {
            esp_cbc: true,
            ..Default::default()
        },
        |e| {
            e.auth = AuthMode::Psk;
            e.username.clear();
        },
    );
    h.connect(None);
    h.wait_connected();
    assert!(h.mgr.session().unwrap().esp_suite.contains("CBC"));
    let dev = h.tun.current().unwrap();
    dev.inject(ipv4_packet(
        Ipv4Addr::new(10, 10, 0, 2),
        Ipv4Addr::new(10, 10, 1, 1),
        b"x",
    ));
    assert!(dev.delivered(Duration::from_secs(3)).is_some());
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
    h.assert_clean();
}

#[test]
fn psk_mismatch_reports_auth_failure() {
    let h = harness(
        ResponderConfig {
            psk: b"other".to_vec(),
            ..Default::default()
        },
        |e| {
            e.auth = AuthMode::Psk;
            e.username.clear();
        },
    );
    h.connect(None);
    assert_eq!(h.wait_error(), ErrorCode::UserAuthFailed);
    h.assert_clean();
}

#[test]
fn invalid_ke_switches_group_once() {
    let h = harness(
        ResponderConfig {
            require_group: Some(ike::dh::DhGroup::Curve25519),
            ..Default::default()
        },
        |e| {
            e.dh_group = DhGroupSel::Modp2048;
        },
    );
    h.connect(Some(PASSWORD));
    h.wait_connected();
    assert_eq!(h.resp.obs().sa_init_count, 2);
    assert!(h.mgr.session().unwrap().ike_suite.contains("Curve25519"));
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
}

// ---------------------------------------------------------------- edge cases

#[test]
fn unreachable_gateway() {
    let h = harness(
        ResponderConfig {
            ignore_sa_init: true,
            ..Default::default()
        },
        |_| {},
    );
    h.connect(Some(PASSWORD));
    assert_eq!(h.wait_error(), ErrorCode::GatewayUnreachable);
    assert_eq!(h.resp.obs().sa_init_count, 0);
    h.assert_clean();
}

#[test]
fn no_address_assigned() {
    let h = harness(
        ResponderConfig {
            assign_ip: None,
            ..Default::default()
        },
        |_| {},
    );
    h.connect(Some(PASSWORD));
    assert_eq!(h.wait_error(), ErrorCode::NoAddressAssigned);
    h.assert_clean();
}

#[test]
fn gateway_lost_cleans_up() {
    let h = harness(
        ResponderConfig {
            silent_after_established: true,
            ..Default::default()
        },
        |_| {},
    );
    h.connect(Some(PASSWORD));
    h.wait_connected();
    assert_eq!(h.wait_error(), ErrorCode::GatewayLost);
    h.assert_clean();
}

#[test]
fn deleted_by_gateway() {
    let h = harness(ResponderConfig::default(), |_| {});
    h.connect(Some(PASSWORD));
    h.wait_connected();
    h.resp.send_delete();
    assert_eq!(h.wait_error(), ErrorCode::DeletedByGateway);
    h.assert_clean();
}

#[test]
fn auto_reconnect_after_gateway_delete() {
    let h = harness(ResponderConfig::default(), |e| {
        e.auto_reconnect = true;
        e.password = SecretUpdate::Set(SecretString::new(PASSWORD));
    });
    h.connect(None);
    h.wait_connected();
    h.resp.send_delete();
    h.wait_state("reconnect attempt", |s| {
        matches!(s, ConnectionState::Connecting { attempt: 2, .. })
    });
    h.wait_connected();
    assert_eq!(h.resp.obs().sa_init_count, 2);
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
    h.assert_clean();
}

#[test]
fn network_failure_rolls_back() {
    let h = harness_with(
        ResponderConfig::default(),
        |_| {},
        |net| {
            *net.fail_apply_at.lock().unwrap() = Some(1);
        },
    );
    h.connect(Some(PASSWORD));
    assert_eq!(h.wait_error(), ErrorCode::NetConfigError);
    h.assert_clean();
    wait_until("DELETE after failed setup", || h.resp.obs().got_delete);
}

#[test]
fn prepared_backup_is_journaled_before_dns_and_reverted_last() {
    let h = harness_with(
        ResponderConfig::default(),
        |_| {},
        |net| {
            *net.dns_backup.lock().unwrap() = Some("nameserver 192.0.2.1\n".into());
        },
    );
    h.connect(Some(PASSWORD));
    h.wait_connected();
    let backup = NetChange::ResolvConf {
        backup: "nameserver 192.0.2.1\n".into(),
    };
    let is_dns = |c: &NetChange| matches!(c, NetChange::Dns { .. });
    for (what, list) in [
        ("journal", h.journal.load().unwrap()),
        ("applied", h.net.applied.lock().unwrap().clone()),
    ] {
        let b = list.iter().position(|c| *c == backup);
        let d = list.iter().position(is_dns);
        assert!(
            matches!((b, d), (Some(b), Some(d)) if b + 1 == d),
            "{what}: backup must come right before DNS: {list:?}"
        );
    }
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
    h.assert_clean();
}

#[test]
fn shutdown_while_connected_cleans_up() {
    let h = harness(ResponderConfig::default(), |_| {});
    h.connect(Some(PASSWORD));
    h.wait_connected();
    h.mgr.shutdown();
    h.assert_clean();
    wait_until("gateway saw DELETE", || h.resp.obs().got_delete);
}

// ---------------------------------------------------------------- US6 recovery

#[test]
fn recover_replays_journal() {
    let net = MockNetConfig::default();
    let journal = MemJournal::default();
    let tun = MockTunFactory::default();
    let changes = vec![
        NetChange::AdapterAddress {
            if_id: 7,
            addr: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 32,
        },
        NetChange::Route {
            if_id: 7,
            dest: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8,
            next_hop: Ipv4Addr::UNSPECIFIED,
        },
    ];
    for c in &changes {
        net.apply(c).unwrap();
    }
    journal.save(&changes).unwrap();
    recover(&tun, &net, &journal);
    assert!(net.applied.lock().unwrap().is_empty());
    assert!(journal.load().unwrap().is_empty());
    assert_eq!(
        tun.stale_removed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

// ---------------------------------------------------------------- SC-003

#[test]
fn logs_never_contain_secrets() {
    let h = harness(ResponderConfig::default(), |_| {});
    h.connect(Some(PASSWORD));
    h.wait_connected();
    h.mgr.disconnect().unwrap();
    h.wait_state("Disconnected", |s| *s == ConnectionState::Disconnected);
    let lines = logs().recent(100_000);
    assert!(
        lines
            .iter()
            .any(|l| l.message.contains("Child SA established")),
        "logs were captured"
    );
    for l in &lines {
        let m = &l.message;
        assert!(
            !m.contains(PASSWORD) && !m.contains(PSK),
            "secret leaked into log: {m}"
        );
    }
    // Session info and events carry no secrets either.
    let info = format!("{:?}", h.mgr.session());
    assert!(!info.contains(PASSWORD) && !info.contains(PSK));
}
