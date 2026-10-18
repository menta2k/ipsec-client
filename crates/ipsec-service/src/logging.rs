//! Logging setup (research R11): rolling daily file (7 kept), the in-memory
//! ring served over IPC, and stderr in console mode. `IPSEC_LOG=debug` raises
//! the level.

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use vpn_core::LogBuffer;

pub fn level() -> LevelFilter {
    match std::env::var("IPSEC_LOG")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        _ => LevelFilter::INFO,
    }
}

/// Install the global subscriber. Keep the returned guard alive to flush the
/// file writer.
pub fn init(log_dir: Option<&Path>, console: bool, ring: &LogBuffer) -> Option<WorkerGuard> {
    let lvl = level();
    let (file_layer, guard) = match log_dir.and_then(|d| {
        tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("service")
            .filename_suffix("log")
            .max_log_files(7)
            .build(d)
            .ok()
    }) {
        Some(appender) => {
            let (nb, guard) = tracing_appender::non_blocking(appender);
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(nb)
                .with_ansi(false)
                .with_filter(lvl);
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };
    let console_layer = console.then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(lvl)
    });
    // macOS: the real service also reports to the unified log (004 R8).
    #[cfg(target_os = "macos")]
    let system_layer = log_dir.map(|_| crate::macos::syslog::SyslogLayer::system());
    #[cfg(not(target_os = "macos"))]
    let system_layer: Option<tracing_subscriber::layer::Identity> = None;
    let _ = tracing_subscriber::registry()
        .with(ring.layer().with_filter(lvl))
        .with(file_layer)
        .with(console_layer)
        .with(system_layer)
        .try_init();
    guard
}
