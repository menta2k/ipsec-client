//! Wires engine, store, logging and the IPC listener together. Shared by the
//! SCM service, console mode (`run`) and mock mode (`run --mock`).

use crate::server::{run_accept_loop, Engine, Listener, ServerCtx};
use crate::{logging, paths};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use vpn_core::logbuf::LOG_CAPACITY;
use vpn_core::{EventBus, LogBuffer, ProfileStore};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Real tunnels (Windows elevated; Linux with CAP_NET_ADMIN).
    Real,
    /// Simulated engine, any OS, no privileges.
    Mock,
}

pub struct Host {
    engine: Arc<dyn Engine>,
    settings: Arc<vpn_core::SettingsStore>,
    listener: Arc<dyn Listener>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    _log_guard: Option<WorkerGuard>,
}

fn store_io(e: vpn_core::store::StoreError) -> io::Error {
    io::Error::other(e.to_string())
}

pub fn start(mode: Mode, console: bool) -> io::Result<Host> {
    let dir = paths::data_dir(mode == Mode::Mock);
    let bus = EventBus::new();
    let ring = LogBuffer::new(LOG_CAPACITY, Some(bus.clone()));

    let (engine, store, listener, guard): Parts = match mode {
        Mode::Mock => {
            std::fs::create_dir_all(&dir)?;
            let guard = logging::init(None, console, &ring);
            tracing::warn!(target: "host", dir = %dir.display(), "MOCK MODE: simulated tunnels, secrets NOT protected");
            let store = Arc::new(
                ProfileStore::open(
                    Some(dir.join("profiles.json")),
                    Arc::new(vpn_core::mock::InsecureMockProtector),
                )
                .map_err(store_io)?,
            );
            let engine = crate::simulate::SimulatedEngine::new(store.clone(), bus.clone());
            info!(target: "host", endpoint = %mock_endpoint().display(), "listening");
            (engine, store, mock_listener()?, guard)
        }
        Mode::Real => real_parts(&dir, console, &bus, &ring)?,
    };

    let (settings, problem) = vpn_core::SettingsStore::open(dir.join("settings.json"));
    if let Some(e) = problem {
        tracing::warn!(target: "host", error = %e, "settings unreadable; using defaults");
    }
    let settings = Arc::new(settings);
    let ctx = Arc::new(ServerCtx {
        engine: engine.clone(),
        store,
        settings: settings.clone(),
        bus,
        logs: ring,
        service_name: format!("ipsec-service {}", env!("CARGO_PKG_VERSION")),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let accept = {
        let (l, s) = (listener.clone(), stop.clone());
        std::thread::Builder::new()
            .name("ipc-accept".into())
            .spawn(move || run_accept_loop(l, ctx, s))?
    };
    info!(target: "host", mode = ?mode, "service ready");
    Ok(Host {
        engine,
        settings,
        listener,
        stop,
        accept: Some(accept),
        _log_guard: guard,
    })
}

#[cfg(windows)]
fn mock_listener() -> io::Result<Arc<dyn Listener>> {
    use crate::windows::pipe::{PipeListener, PIPE_SDDL};
    // `endpoint()` honours IPSEC_CLIENT_PIPE so tests can run beside an
    // installed service.
    let pipe = ipc_proto::client::endpoint();
    let l = PipeListener::bind(&pipe.to_string_lossy(), PIPE_SDDL).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot open the IPC pipe (is the real service running?): {e}"),
        )
    })?;
    Ok(Arc::new(l))
}

/// The per-user socket, or `$IPSEC_CLIENT_SOCKET` (tests run on private
/// sockets; GUI clients on Linux try that variable first).
#[cfg(unix)]
fn mock_endpoint() -> std::path::PathBuf {
    std::env::var_os(ipc_proto::client::SOCKET_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(ipc_proto::client::endpoint)
}

#[cfg(windows)]
fn mock_endpoint() -> std::path::PathBuf {
    ipc_proto::client::endpoint()
}

#[cfg(unix)]
fn mock_listener() -> io::Result<Arc<dyn Listener>> {
    Ok(Arc::new(crate::unix::UnixSocketListener::bind(
        mock_endpoint(),
        0o600,
    )?))
}

/// Engine, profile store, IPC listener and log-writer guard of one host.
type Parts = (
    Arc<dyn Engine>,
    Arc<ProfileStore>,
    Arc<dyn Listener>,
    Option<WorkerGuard>,
);

#[cfg(windows)]
fn real_parts(
    dir: &std::path::Path,
    console: bool,
    bus: &EventBus,
    ring: &LogBuffer,
) -> io::Result<Parts> {
    use crate::windows::{
        dpapi::DpapiProtector, netconfig::IpHelperNetConfig, pipe, secure_dir,
        wintun_tun::WintunFactory,
    };
    use vpn_core::traits::{FileJournal, StdUdpFactory};
    use vpn_core::{ConnectionManager, Deps, EngineConfig};

    secure_dir(dir)?;
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs)?;
    let guard = logging::init(Some(&logs), console, ring);
    info!(target: "host", version = env!("CARGO_PKG_VERSION"), "starting");

    let tun = Arc::new(WintunFactory::load()?);
    let net = Arc::new(IpHelperNetConfig);
    let journal = Arc::new(FileJournal {
        path: dir.join("netstate.json"),
    });
    // FR-008: undo anything a previous unclean exit left behind, before
    // accepting clients.
    vpn_core::manager::recover(tun.as_ref(), net.as_ref(), journal.as_ref());

    let store = Arc::new(
        ProfileStore::open(Some(dir.join("profiles.json")), Arc::new(DpapiProtector))
            .map_err(store_io)?,
    );
    let mgr = ConnectionManager::start(Deps {
        udp: Arc::new(StdUdpFactory),
        tun,
        net,
        journal,
        store: store.clone(),
        bus: bus.clone(),
        config: EngineConfig::default(),
    });
    let listener = Arc::new(pipe::PipeListener::bind(
        ipc_proto::client::PIPE_NAME,
        pipe::PIPE_SDDL,
    )?);
    info!(target: "host", endpoint = ipc_proto::client::PIPE_NAME, "listening");
    Ok((mgr, store, listener, guard))
}

/// Linux (002): TUN over /dev/net/tun, iproute2/resolvectl, machine-key
/// secrets, and the group-restricted system socket.
#[cfg(target_os = "linux")]
fn real_parts(
    dir: &std::path::Path,
    console: bool,
    bus: &EventBus,
    ring: &LogBuffer,
) -> io::Result<Parts> {
    use crate::linux::netconfig::{LinuxNetConfig, SystemRunner};
    use crate::linux::tun::LinuxTunFactory;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use vpn_core::keyfile::KeyFileProtector;
    use vpn_core::traits::{FileJournal, StdUdpFactory};
    use vpn_core::{ConnectionManager, Deps, EngineConfig};

    // systemd's StateDirectory= already creates it 0700; this covers `run`
    // started by hand as root.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs)?;
    // Console output goes to stdout, which journald captures under systemd.
    let guard = logging::init(Some(&logs), console, ring);
    info!(target: "host", version = env!("CARGO_PKG_VERSION"), "starting");

    let tun = Arc::new(LinuxTunFactory);
    // Tests in network namespaces cannot use the host's systemd-resolved
    // (it does not see the namespace's interfaces): they force the
    // resolv.conf path with their own file.
    let net = Arc::new(match std::env::var_os("IPSEC_CLIENT_RESOLV_CONF") {
        Some(path) => LinuxNetConfig::with_dns(
            SystemRunner,
            crate::linux::netconfig::DnsMode::ResolvConf(path.into()),
        ),
        None => LinuxNetConfig::detect(SystemRunner, std::path::PathBuf::from("/etc/resolv.conf")),
    });
    info!(target: "host", dns = ?net.dns_mode(), "network configuration");
    let journal = Arc::new(FileJournal {
        path: dir.join("netstate.json"),
    });
    // FR-005: undo whatever a previous unclean exit left behind (the TUN
    // device itself is already gone; its gateway route and DNS may not be).
    vpn_core::manager::recover(tun.as_ref(), net.as_ref(), journal.as_ref());

    let store = Arc::new(
        ProfileStore::open(
            Some(dir.join("profiles.json")),
            Arc::new(KeyFileProtector::new(dir.join("secret.key"))),
        )
        .map_err(store_io)?,
    );
    let mgr = ConnectionManager::start(Deps {
        udp: Arc::new(StdUdpFactory),
        tun,
        net,
        journal,
        store: store.clone(),
        bus: bus.clone(),
        config: EngineConfig::default(),
    });

    let socket = paths::socket_path();
    if let Some(parent) = socket.parent() {
        // systemd's RuntimeDirectory= (0750, group ipsec-client) normally
        // exists already.
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(parent)?;
        }
    }
    // 0660: members of the service's group may connect (research R5).
    let listener = Arc::new(crate::unix::UnixSocketListener::bind(
        socket.clone(),
        0o660,
    )?);
    info!(target: "host", endpoint = %socket.display(), "listening");
    Ok((mgr, store, listener, guard))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn real_parts(
    _dir: &std::path::Path,
    _console: bool,
    _bus: &EventBus,
    _ring: &LogBuffer,
) -> io::Result<Parts> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the real VPN service is available on Windows and Linux; use `run --mock`",
    ))
}

impl Host {
    /// A callable for the SCM handler: the signed-in user signed out (003
    /// FR-012). Applies the current policy; returns once the network is
    /// restored (or immediately if there is nothing to do).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn signout_hook(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let (engine, settings) = (self.engine.clone(), self.settings.clone());
        move || engine.on_signout(settings.get())
    }

    /// Tear down any tunnel (with full network cleanup), then stop serving.
    pub fn stop(mut self) {
        info!(target: "host", "stopping");
        self.engine.shutdown();
        self.stop.store(true, Ordering::SeqCst);
        self.listener.close();
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
        info!(target: "host", "stopped");
    }
}
