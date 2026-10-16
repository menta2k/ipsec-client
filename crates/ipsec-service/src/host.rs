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
    /// Real tunnels (Windows, elevated).
    Real,
    /// Simulated engine, any OS, no privileges.
    Mock,
}

pub struct Host {
    engine: Arc<dyn Engine>,
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
            (engine, store, mock_listener()?, guard)
        }
        Mode::Real => real_parts(&dir, console, &bus, &ring)?,
    };

    let ctx = Arc::new(ServerCtx {
        engine: engine.clone(),
        store,
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
    info!(target: "host", mode = ?mode, endpoint = %ipc_proto::client::endpoint().display(), "service ready");
    Ok(Host {
        engine,
        listener,
        stop,
        accept: Some(accept),
        _log_guard: guard,
    })
}

#[cfg(windows)]
fn mock_listener() -> io::Result<Arc<dyn Listener>> {
    use crate::windows::pipe::{PipeListener, PIPE_SDDL};
    let l = PipeListener::bind(ipc_proto::client::PIPE_NAME, PIPE_SDDL).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot open the IPC pipe (is the real service running?): {e}"),
        )
    })?;
    Ok(Arc::new(l))
}

#[cfg(unix)]
fn mock_listener() -> io::Result<Arc<dyn Listener>> {
    Ok(Arc::new(crate::unix::UnixSocketListener::bind(
        ipc_proto::client::endpoint(),
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
    Ok((mgr, store, listener, guard))
}

#[cfg(not(windows))]
fn real_parts(
    _dir: &std::path::Path,
    _console: bool,
    _bus: &EventBus,
    _ring: &LogBuffer,
) -> io::Result<Parts> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the real VPN service is only available on Windows in this version; use `run --mock`",
    ))
}

impl Host {
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
