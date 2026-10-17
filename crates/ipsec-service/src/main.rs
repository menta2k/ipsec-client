//! `ipsec-service`: the privileged half of the IPsec client.
//!
//! See contracts/service-cli.md for the command line.

mod host;
mod linux;
mod logging;
mod paths;
mod server;
mod simulate;
#[cfg(unix)]
mod unix;
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
  service        entry point used by the Service Control Manager";

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
        ["service"] => service_entry(),
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

#[allow(dead_code)]
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

#[cfg(not(windows))]
fn manage(what: &str, _m: Manage) -> i32 {
    eprintln!("{what}: the service can only be installed on Windows in this version");
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

#[cfg(not(windows))]
fn cleanup() -> i32 {
    eprintln!("cleanup: only available on Windows");
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

#[cfg(not(windows))]
fn service_entry() -> i32 {
    eprintln!("service: only available on Windows");
    1
}
