//! `ipsec-service`: the privileged half of the IPsec client.
//!
//! See contracts/service-cli.md for the command line.

mod host;
mod linux;
mod logging;
mod macos;
mod paths;
mod plc_cli;
mod server;
mod simulate;
#[cfg(unix)]
mod unix;
mod unix_cmd;
#[cfg(windows)]
mod windows;

use host::Mode;

const USAGE: &str = "\
usage: ipsec-service <command>

commands:
  install        register the IpsecClient service (auto-start, LocalSystem) and start it
  uninstall      stop the service (with network cleanup) and remove it
  start | stop   control the installed service
  run            run in the foreground (Ctrl-C stops cleanly)
  run --mock     run a simulated engine (no privileges, any OS) for GUI development
  cleanup        undo network changes left by an unclean exit
  service        entry point used by the Service Control Manager
  plc …          Pre-Login Connect: sign-in profiles and sign-out policy
  profile import <file.json> [--sign-in]
                 create or update profiles (administrator)
  access-group [<name>]
                 macOS: show or set the group allowed to control the VPN";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["run"] => run_console(Mode::Real),
        ["run", "--mock"] => run_console(Mode::Mock),
        ["install"] => manage("install", Manage::Install),
        ["uninstall"] => manage("uninstall", Manage::Uninstall),
        ["start"] => manage("start", Manage::Start),
        ["stop"] => manage("stop", Manage::Stop),
        ["cleanup"] => cleanup(),
        ["access-group"] => access_group(None),
        ["access-group", name] => access_group(Some(name)),
        ["service"] => service_entry(),
        ["plc", ..] | ["profile", ..] => {
            plc_cli::main(&args.iter().map(String::as_str).collect::<Vec<_>>())
        }
        ["-h"] | ["--help"] | ["help"] => {
            println!("{USAGE}");
            0
        }
        _ => {
            eprintln!("{USAGE}");
            2
        }
    };
    std::process::exit(code);
}

fn run_console(mode: Mode) -> i32 {
    #[cfg(windows)]
    if mode == Mode::Real && !windows::is_elevated() {
        eprintln!("error: `run` needs an elevated (Administrator) prompt; use `run --mock` for development");
        return 5;
    }
    #[cfg(target_os = "macos")]
    if mode == Mode::Real {
        if !macos::sys::is_root() {
            eprintln!("error: `run` needs root (sudo); use `run --mock` for development");
            return 5;
        }
        let running = macos::launchd::is_running(&unix_cmd::SystemRunner);
        if let Err(e) = macos::launchd::refuse_if_running("run", running) {
            eprintln!("error: {e}");
            return 5;
        }
    }
    let host = match host::start(mode, true) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        eprintln!("warning: could not install the Ctrl-C handler: {e}");
    }
    let _ = rx.recv();
    host.stop();
    0
}

#[cfg_attr(
    all(unix, not(any(target_os = "linux", target_os = "macos"))),
    allow(dead_code)
)]
enum Manage {
    Install,
    Uninstall,
    Start,
    Stop,
}

#[cfg(windows)]
fn manage(what: &str, m: Manage) -> i32 {
    let r = match m {
        Manage::Install => windows::service::install(),
        Manage::Uninstall => windows::service::uninstall(),
        Manage::Start => windows::service::start(),
        Manage::Stop => windows::service::stop(),
    };
    match r {
        Ok(()) => {
            println!("{what}: ok");
            0
        }
        Err(e) => {
            let code = windows::service::exit_code(&e);
            if code == 5 {
                eprintln!("{what}: access denied (run from an elevated prompt)");
            } else {
                eprintln!("{what}: {e}");
            }
            code
        }
    }
}

/// Linux: wrappers around systemctl (002 contracts/service-cli-linux.md).
#[cfg(target_os = "linux")]
fn manage(what: &str, m: Manage) -> i32 {
    use linux::systemd::{run, unit_installed, Verb};
    let verb = match m {
        Manage::Install => Verb::Install,
        Manage::Uninstall => Verb::Uninstall,
        Manage::Start => Verb::Start,
        Manage::Stop => Verb::Stop,
    };
    match run(verb, &linux::netconfig::SystemRunner, unit_installed()) {
        Ok(()) => {
            println!("{what}: ok");
            0
        }
        Err(e) => {
            if e.code == 5 {
                eprintln!("{what}: access denied (run with sudo): {}", e.message);
            } else {
                eprintln!("{what}: {}", e.message);
            }
            e.code
        }
    }
}

/// macOS: a LaunchDaemon driven with launchctl (004
/// contracts/service-cli-macos.md).
#[cfg(target_os = "macos")]
fn manage(what: &str, m: Manage) -> i32 {
    use macos::launchd::{run, Verb};
    if !macos::sys::is_root() {
        eprintln!("{what}: access denied (run with sudo)");
        return 5;
    }
    let verb = match m {
        Manage::Install => Verb::Install,
        Manage::Uninstall => Verb::Uninstall,
        Manage::Start => Verb::Start,
        Manage::Stop => Verb::Stop,
    };
    let prepared = match verb {
        Verb::Install => macos_install_files(),
        Verb::Start if !macos::launchd::is_loaded(&unix_cmd::SystemRunner) => {
            run(Verb::Install, &unix_cmd::SystemRunner).map_err(|e| e.message)
        }
        _ => Ok(()),
    };
    if let Err(e) = prepared {
        eprintln!("{what}: {e}");
        return 1;
    }
    match run(verb, &unix_cmd::SystemRunner) {
        Ok(()) => {
            if verb == Verb::Uninstall {
                let _ = std::fs::remove_file(macos::launchd::PLIST_PATH);
            }
            println!("{what}: ok");
            0
        }
        Err(e) => {
            eprintln!("{what}: {}", e.message);
            e.code
        }
    }
}

/// `install` on macOS: the binary must already be in place (the package puts
/// it there); write the plist if missing and create the directories.
#[cfg(target_os = "macos")]
fn macos_install_files() -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let bin = std::path::Path::new(paths::SERVICE_BINARY);
    if !bin.exists() {
        return Err(format!(
            "{} is missing; install the package, or copy this binary there first",
            bin.display()
        ));
    }
    let plist = std::path::Path::new(macos::launchd::PLIST_PATH);
    if !plist.exists() {
        std::fs::write(plist, macos::launchd::render_plist())
            .and_then(|()| std::fs::set_permissions(plist, std::fs::Permissions::from_mode(0o644)))
            .map_err(|e| format!("cannot write {}: {e}", plist.display()))?;
    }
    let dir = paths::data_dir(false);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let logs = paths::log_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&logs)
        .map_err(|e| format!("cannot create {}: {e}", logs.display()))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn manage(what: &str, _m: Manage) -> i32 {
    eprintln!("{what}: the service can be installed on Windows, Linux and macOS only");
    1
}

#[cfg(windows)]
fn cleanup() -> i32 {
    if !windows::is_elevated() {
        eprintln!("cleanup: access denied (run from an elevated prompt)");
        return 5;
    }
    let dir = paths::data_dir(false);
    let journal = vpn_core::traits::FileJournal {
        path: dir.join("netstate.json"),
    };
    let net = windows::netconfig::IpHelperNetConfig;
    match windows::wintun_tun::WintunFactory::load() {
        Ok(tun) => vpn_core::manager::recover(&tun, &net, &journal),
        Err(e) => {
            eprintln!("cleanup: {e}");
            return 1;
        }
    }
    println!("cleanup: ok");
    0
}

/// Linux: replay and clear the change journal without starting a session.
/// The TUN device itself is never left behind (it is not persistent).
#[cfg(target_os = "linux")]
fn cleanup() -> i32 {
    let dir = paths::data_dir(false);
    let journal_path = dir.join("netstate.json");
    if let Err(e) = std::fs::metadata(&journal_path) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!(
                "cleanup: access denied to {} (run with sudo)",
                dir.display()
            );
            return 5;
        }
    }
    let journal = vpn_core::traits::FileJournal { path: journal_path };
    let net = linux::netconfig::LinuxNetConfig::detect(
        linux::netconfig::SystemRunner,
        std::path::PathBuf::from("/etc/resolv.conf"),
    );
    vpn_core::manager::recover(&linux::tun::LinuxTunFactory, &net, &journal);
    println!("cleanup: ok");
    0
}

/// macOS: replay and clear the change journal (the utun is never left
/// behind). Refused while the daemon owns the journal.
#[cfg(target_os = "macos")]
fn cleanup() -> i32 {
    if !macos::sys::is_root() {
        eprintln!("cleanup: access denied (run with sudo)");
        return 5;
    }
    let running = macos::launchd::is_running(&unix_cmd::SystemRunner);
    if let Err(e) = macos::launchd::refuse_if_running("cleanup", running) {
        eprintln!("{e}");
        return 5;
    }
    let journal = vpn_core::traits::FileJournal {
        path: paths::data_dir(false).join("netstate.json"),
    };
    let net = macos::netconfig::MacNetConfig::new(unix_cmd::SystemRunner, macos::SysIfNames);
    vpn_core::manager::recover(&macos::utun::MacTunFactory, &net, &journal);
    println!("cleanup: ok");
    0
}

/// macOS: show or change the group whose members may control the VPN
/// (004 contracts/service-cli-macos.md).
#[cfg(target_os = "macos")]
fn access_group(name: Option<&str>) -> i32 {
    use macos::group;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let runner = unix_cmd::SystemRunner;
    let dir = paths::data_dir(false);
    let Some(name) = name else {
        if macos::sys::is_root() {
            let configured = vpn_core::SettingsStore::open(dir.join("settings.json"))
                .0
                .access_group();
            let r = group::resolve_or_admin(configured.as_deref(), &runner);
            println!("{} (gid {})", r.name, r.gid);
            if let Some(w) = r.warning {
                eprintln!("warning: {w}");
            }
            return 0;
        }
        // Without root the data directory is closed; the socket directory
        // shows the group the running service applied.
        let sock = paths::socket_path();
        let sock_dir = sock.parent().unwrap_or(std::path::Path::new("/"));
        return match std::fs::metadata(sock_dir) {
            Ok(m) => {
                println!(
                    "gid {} (from {}; run with sudo for the configured name)",
                    m.gid(),
                    sock_dir.display()
                );
                0
            }
            Err(e) => {
                eprintln!("access-group: the service is not running ({e}); run with sudo");
                1
            }
        };
    };
    if !macos::sys::is_root() {
        eprintln!("access-group: access denied (run with sudo)");
        return 5;
    }
    if !group::valid_name(name) {
        eprintln!(
            "access-group: '{name}' is not a valid group name (1-32 characters: letters, digits, _ . -)"
        );
        return 2;
    }
    let stored = if name == group::DEFAULT_GROUP {
        None
    } else if group::lookup(name, &runner).is_some() {
        Some(name.to_string())
    } else {
        eprintln!("access-group: group '{name}' does not exist");
        return 1;
    };
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
    {
        eprintln!("access-group: cannot create {}: {e}", dir.display());
        return 1;
    }
    let (settings, problem) = vpn_core::SettingsStore::open(dir.join("settings.json"));
    if let Some(e) = problem {
        // Saving now would replace the other settings with defaults.
        eprintln!("access-group: {e}; fix or remove the file first");
        return 1;
    }
    if let Err(e) = settings.set_access_group(stored) {
        eprintln!("access-group: cannot save the setting: {e}");
        return 1;
    }
    if let Err(e) = macos::launchd::restart(&runner) {
        eprintln!("access-group: saved, but {}", e.message);
        return e.code;
    }
    println!("access-group: {name}");
    0
}

#[cfg(not(target_os = "macos"))]
fn access_group(_name: Option<&str>) -> i32 {
    eprintln!("access-group: available on macOS only");
    2
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn cleanup() -> i32 {
    eprintln!("cleanup: available on Windows, Linux and macOS only");
    1
}

#[cfg(windows)]
fn service_entry() -> i32 {
    match windows::service::run_dispatcher() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("service: {e} (this command is started by the Service Control Manager)");
            1
        }
    }
}

/// macOS: the launchd entry point; `run` without console output.
#[cfg(target_os = "macos")]
fn service_entry() -> i32 {
    if !macos::sys::is_root() {
        eprintln!("service: started by launchd as root; use `run` by hand");
        return 5;
    }
    let host = match host::start(Mode::Real, false) {
        Ok(h) => h,
        Err(e) => {
            // launchd writes stderr to the service.out file.
            eprintln!("error: {e}");
            return 1;
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(e) = ctrlc::set_handler(move || {
        let _ = tx.send(());
    }) {
        eprintln!("warning: could not install the SIGTERM handler: {e}");
    }
    let _ = rx.recv();
    host.stop();
    0
}

#[cfg(all(unix, not(target_os = "macos")))]
fn service_entry() -> i32 {
    eprintln!("service: not used on this system; use `run` (the service manager supervises it)");
    2
}
