//! `install` / `uninstall` / `start` / `stop` on Linux (002
//! contracts/service-cli-linux.md): thin wrappers around `systemctl`. Packages
//! own the unit file; these commands never write one.

use super::netconfig::CommandRunner;
use std::path::Path;

pub const UNIT: &str = "ipsec-client.service";

/// Where systemd looks for unit files, most specific first.
const UNIT_DIRS: [&str; 3] = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

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

/// The `systemctl` invocations for a verb, in order.
pub fn commands(verb: Verb) -> Vec<Vec<&'static str>> {
    match verb {
        Verb::Install => vec![
            vec!["systemctl", "daemon-reload"],
            vec!["systemctl", "enable", "--now", UNIT],
        ],
        Verb::Uninstall => vec![vec!["systemctl", "disable", "--now", UNIT]],
        Verb::Start => vec![vec!["systemctl", "start", UNIT]],
        Verb::Stop => vec![vec!["systemctl", "stop", UNIT]],
    }
}

/// True if the unit file is installed in one of systemd's unit directories.
pub fn unit_installed() -> bool {
    UNIT_DIRS.iter().any(|d| Path::new(d).join(UNIT).exists())
}

fn denied(stderr: &str) -> bool {
    [
        "Access denied",
        "Interactive authentication required",
        "Permission denied",
        "Operation not permitted",
    ]
    .iter()
    .any(|m| stderr.contains(m))
}

/// Run a verb. `unit_present` is consulted for `install` only.
pub fn run(verb: Verb, runner: &dyn CommandRunner, unit_present: bool) -> Result<(), VerbError> {
    if verb == Verb::Install && !unit_present {
        return Err(VerbError {
            code: 1,
            message: format!(
                "{UNIT} is not installed; install the ipsec-client package (it provides the unit)"
            ),
        });
    }
    for argv in commands(verb) {
        let out = runner.run(&argv).map_err(|e| VerbError {
            code: 1,
            message: format!("cannot run systemctl ({e}); a systemd system is required"),
        })?;
        if !out.status_ok {
            let err = out.stderr.trim();
            return Err(VerbError {
                code: if denied(err) { 5 } else { 1 },
                message: format!("`{}` failed: {err}", argv.join(" ")),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::netconfig::fake::{fail, ok, FakeRunner};

    #[test]
    fn verbs_map_to_systemctl() {
        for (verb, expect) in [
            (
                Verb::Install,
                vec![
                    "systemctl daemon-reload",
                    "systemctl enable --now ipsec-client.service",
                ],
            ),
            (
                Verb::Uninstall,
                vec!["systemctl disable --now ipsec-client.service"],
            ),
            (Verb::Start, vec!["systemctl start ipsec-client.service"]),
            (Verb::Stop, vec!["systemctl stop ipsec-client.service"]),
        ] {
            let r = FakeRunner::new();
            run(verb, &r, true).unwrap();
            assert_eq!(r.calls(), expect, "{verb:?}");
        }
    }

    #[test]
    fn install_needs_the_packaged_unit() {
        let r = FakeRunner::new();
        let e = run(Verb::Install, &r, false).unwrap_err();
        assert_eq!(e.code, 1);
        assert!(
            e.message.contains("install the ipsec-client package"),
            "{}",
            e.message
        );
        assert!(r.calls().is_empty(), "nothing is run without the unit");
        // Other verbs do not check (systemctl reports a missing unit itself).
        run(Verb::Stop, &FakeRunner::new(), false).unwrap();
    }

    #[test]
    fn access_denied_is_exit_5_and_other_failures_exit_1() {
        let r = FakeRunner::new();
        r.on(
            "systemctl daemon-reload",
            fail("Failed to reload daemon: Access denied"),
        );
        let e = run(Verb::Install, &r, true).unwrap_err();
        assert_eq!(e.code, 5);
        assert_eq!(
            r.calls(),
            ["systemctl daemon-reload"],
            "stops at the first failure"
        );

        let r = FakeRunner::new();
        r.on(
            "systemctl start",
            fail("Failed to start ipsec-client.service: Interactive authentication required."),
        );
        assert_eq!(run(Verb::Start, &r, true).unwrap_err().code, 5);

        let r = FakeRunner::new();
        r.on(
            "systemctl stop",
            fail("Failed to stop ipsec-client.service: Unit ipsec-client.service not loaded."),
        );
        let e = run(Verb::Stop, &r, true).unwrap_err();
        assert_eq!(e.code, 1);
        assert!(e.message.contains("not loaded"), "{}", e.message);

        let r = FakeRunner::new();
        r.on("systemctl", ok(""));
        run(Verb::Uninstall, &r, true).unwrap();
    }
}
