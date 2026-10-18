//! `install` / `uninstall` / `start` / `stop` on macOS (004
//! contracts/service-cli-macos.md): a system LaunchDaemon driven with
//! `launchctl`. Rendering and command generation are portable and tested.

use crate::paths::{LAUNCHD_LABEL, SERVICE_BINARY};
use crate::unix_cmd::CommandRunner;

/// Where the daemon's plist is installed.
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/net.ipsec-client.service.plist";

/// launchd's stdout/stderr file for the daemon.
pub const OUT_PATH: &str = "/Library/Logs/IpsecClient/service.out";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Install,
    Uninstall,
    Start,
    Stop,
}

/// A failed verb: the exit code (1, or 5 for access denied) and a message.
#[derive(Debug, PartialEq, Eq)]
pub struct VerbError {
    pub code: i32,
    pub message: String,
}

/// The daemon's plist (004 contracts/macos-system-integration.md).
pub fn render_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{SERVICE_BINARY}</string>
        <string>service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{OUT_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{OUT_PATH}</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
    )
}

fn target() -> String {
    format!("system/{LAUNCHD_LABEL}")
}

/// The `launchctl` invocations for a verb, in order.
pub fn commands(verb: Verb) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match verb {
        Verb::Install => vec![s(&["launchctl", "bootstrap", "system", PLIST_PATH])],
        Verb::Uninstall => vec![s(&["launchctl", "bootout", &target()])],
        Verb::Start => vec![s(&["launchctl", "kickstart", &target()])],
        Verb::Stop => vec![s(&["launchctl", "kill", "TERM", &target()])],
    }
}

/// True if the daemon is loaded (bootstrapped), whether or not it runs.
pub fn is_loaded(runner: &dyn CommandRunner) -> bool {
    runner
        .run(&["launchctl", "print", &target()])
        .map(|o| o.status_ok)
        .unwrap_or(false)
}

/// Whether `launchctl print` output shows the daemon running (it stays
/// loaded but not running after `stop`).
pub fn parse_running(print_out: &str) -> bool {
    print_out.lines().any(|l| l.trim() == "state = running")
}

/// True if the daemon is loaded and its process is running.
pub fn is_running(runner: &dyn CommandRunner) -> bool {
    runner
        .run(&["launchctl", "print", &target()])
        .map(|o| o.status_ok && parse_running(&o.stdout))
        .unwrap_or(false)
}

/// `run` and `cleanup` own the tunnel and the journal, so they refuse while
/// the daemon runs (004 contracts/service-cli-macos.md, exit 5).
pub fn refuse_if_running(what: &str, running: bool) -> Result<(), String> {
    if running {
        Err(format!(
            "{what}: the service is running under launchd; `sudo ipsec-service stop` first"
        ))
    } else {
        Ok(())
    }
}

/// Restart the daemon if it is loaded (`kickstart -k`), so it picks up new
/// settings; nothing to do otherwise.
pub fn restart(runner: &dyn CommandRunner) -> Result<(), VerbError> {
    if !is_loaded(runner) {
        return Ok(());
    }
    let out = runner
        .run(&["launchctl", "kickstart", "-k", &target()])
        .map_err(|e| VerbError {
            code: 1,
            message: format!("cannot run launchctl: {e}"),
        })?;
    if out.status_ok {
        return Ok(());
    }
    let msg = format!("{} {}", out.stderr.trim(), out.stdout.trim());
    Err(VerbError {
        code: if denied(&msg) { 5 } else { 1 },
        message: format!("restarting the service failed: {}", msg.trim()),
    })
}

fn denied(msg: &str) -> bool {
    [
        "Operation not permitted",
        "Permission denied",
        "Not privileged",
        "error 150",
        ": 150:",
    ]
    .iter()
    .any(|m| msg.contains(m))
}

/// "already loaded" on install or "not loaded" on uninstall is success.
fn already_done(verb: Verb, msg: &str) -> bool {
    match verb {
        Verb::Install => msg.contains("already loaded") || msg.contains("service already"),
        Verb::Uninstall => {
            msg.contains("No such process") || msg.contains("Could not find service")
        }
        _ => false,
    }
}

/// Run a verb's `launchctl` commands.
pub fn run(verb: Verb, runner: &dyn CommandRunner) -> Result<(), VerbError> {
    for argv in commands(verb) {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let out = runner.run(&args).map_err(|e| VerbError {
            code: 1,
            message: format!("cannot run launchctl: {e}"),
        })?;
        if out.status_ok {
            continue;
        }
        let msg = format!("{} {}", out.stderr.trim(), out.stdout.trim());
        let msg = msg.trim();
        if already_done(verb, msg) {
            continue;
        }
        let code = if denied(msg) { 5 } else { 1 };
        let hint = if code == 5 && matches!(verb, Verb::Install | Verb::Start) {
            " (run with sudo; if you are root, the daemon may be turned off under \
             System Settings > General > Login Items)"
        } else {
            ""
        };
        return Err(VerbError {
            code,
            message: format!("`{}` failed: {msg}{hint}", args.join(" ")),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_cmd::fake::{fail, ok, FakeRunner};

    #[test]
    fn plist_has_the_contract_keys() {
        let p = render_plist();
        for needle in [
            "<key>Label</key>\n    <string>net.ipsec-client.service</string>",
            "<string>/Library/PrivilegedHelperTools/ipsec-service</string>\n        <string>service</string>",
            "<key>RunAtLoad</key>\n    <true/>",
            "<key>SuccessfulExit</key>\n        <false/>",
            "<key>ThrottleInterval</key>\n    <integer>5</integer>",
            "<key>StandardErrorPath</key>\n    <string>/Library/Logs/IpsecClient/service.out</string>",
            "<key>ProcessType</key>\n    <string>Interactive</string>",
        ] {
            assert!(p.contains(needle), "missing {needle}");
        }
        assert!(p.starts_with("<?xml"));
        assert!(p.trim_end().ends_with("</plist>"));
    }

    #[test]
    fn packaged_plist_matches_the_rendered_one() {
        // The installer ships this file; `install` writes `render_plist()`.
        let packaged = include_str!("../../../../packaging/macos/net.ipsec-client.service.plist");
        assert_eq!(packaged.replace("\r\n", "\n"), render_plist());
    }

    #[test]
    fn verbs_map_to_launchctl() {
        let line = |v| {
            commands(v)
                .into_iter()
                .map(|a| a.join(" "))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            line(Verb::Install),
            ["launchctl bootstrap system /Library/LaunchDaemons/net.ipsec-client.service.plist"]
        );
        assert_eq!(
            line(Verb::Uninstall),
            ["launchctl bootout system/net.ipsec-client.service"]
        );
        assert_eq!(
            line(Verb::Start),
            ["launchctl kickstart system/net.ipsec-client.service"]
        );
        assert_eq!(
            line(Verb::Stop),
            ["launchctl kill TERM system/net.ipsec-client.service"]
        );
    }

    #[test]
    fn denied_maps_to_5_with_the_login_items_hint() {
        let r = FakeRunner::new();
        r.on(
            "launchctl bootstrap",
            fail("Bootstrap failed: 1: Operation not permitted"),
        );
        let e = run(Verb::Install, &r).unwrap_err();
        assert_eq!(e.code, 5);
        assert!(e.message.contains("Login Items"), "{}", e.message);

        let r = FakeRunner::new();
        r.on("launchctl kill", fail("Not privileged to signal service."));
        let e = run(Verb::Stop, &r).unwrap_err();
        assert_eq!(e.code, 5);
        assert!(!e.message.contains("Login Items"));
    }

    #[test]
    fn idempotent_install_and_uninstall() {
        let r = FakeRunner::new();
        r.on(
            "launchctl bootstrap",
            fail("Bootstrap failed: 5: service already loaded"),
        );
        assert_eq!(run(Verb::Install, &r), Ok(()));
        let r = FakeRunner::new();
        r.on(
            "launchctl bootout",
            fail("Boot-out failed: 3: No such process"),
        );
        assert_eq!(run(Verb::Uninstall, &r), Ok(()));
        let r = FakeRunner::new();
        r.on("launchctl kickstart", fail("Could not find service"));
        assert_eq!(run(Verb::Start, &r).unwrap_err().code, 1);
    }

    #[test]
    fn running_is_read_from_print() {
        let running = "system/net.ipsec-client.service = {
	active count = 1
	state = running
	pid = 412
}";
        let stopped = "system/net.ipsec-client.service = {
	state = not running
}";
        assert!(parse_running(running));
        assert!(!parse_running(stopped));
        let r = FakeRunner::new();
        r.on("launchctl print", ok(running));
        assert!(is_running(&r));
        let r = FakeRunner::new();
        r.on("launchctl print", ok(stopped));
        assert!(!is_running(&r), "stopped but still loaded");
        let r = FakeRunner::new();
        r.on("launchctl print", fail("Could not find service"));
        assert!(!is_running(&r));
    }

    #[test]
    fn run_and_cleanup_refuse_only_while_running() {
        assert_eq!(refuse_if_running("run", false), Ok(()));
        let e = refuse_if_running("cleanup", true).unwrap_err();
        assert!(e.starts_with("cleanup: "), "{e}");
        assert!(e.contains("ipsec-service stop"), "{e}");
    }

    #[test]
    fn restart_kicks_only_a_loaded_daemon() {
        let r = FakeRunner::new();
        r.on("launchctl print", fail("Could not find service"));
        assert_eq!(restart(&r), Ok(()));
        assert!(!r.calls().iter().any(|c| c.contains("kickstart")));
        let r = FakeRunner::new();
        assert_eq!(restart(&r), Ok(()));
        assert_eq!(
            r.calls().last().unwrap(),
            "launchctl kickstart -k system/net.ipsec-client.service"
        );
        let r = FakeRunner::new();
        r.on(
            "launchctl kickstart",
            fail("Not privileged to signal service."),
        );
        assert_eq!(restart(&r).unwrap_err().code, 5);
    }

    #[test]
    fn loaded_check_uses_print() {
        let r = FakeRunner::new();
        assert!(is_loaded(&r));
        r.on("launchctl print", fail("Could not find service"));
        assert!(!is_loaded(&r));
        assert!(r
            .calls()
            .iter()
            .all(|c| c == "launchctl print system/net.ipsec-client.service"));
    }
}
