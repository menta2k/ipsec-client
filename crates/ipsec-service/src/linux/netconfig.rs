//! Linux network configuration through the distribution's tools (002 research
//! R2/R3): `ip` (iproute2) for addresses and routes, `resolvectl` for DNS.
//!
//! Every command goes through [`CommandRunner`], so the exact argv the service
//! issues is unit-tested with [`FakeRunner`] on any OS.

use std::io;
use std::process::Command;

/// Result of one external command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs an external program; `argv[0]` is the program.
pub trait CommandRunner: Send + Sync {
    fn run(&self, argv: &[&str]) -> io::Result<Output>;
}

/// Runs commands with `std::process::Command`. Children inherit the service's
/// ambient capabilities (research R7).
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, argv: &[&str]) -> io::Result<Output> {
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let out = Command::new(prog).args(args).output()?;
        Ok(Output {
            status_ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
pub mod fake {
    use super::{CommandRunner, Output};
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;

    /// Records every argv and answers from a script of `(argv prefix, reply)`
    /// rules; the first matching rule is used (and consumed if `once`).
    /// Unmatched commands succeed with empty output.
    #[derive(Default)]
    pub struct FakeRunner {
        calls: Mutex<Vec<String>>,
        rules: Mutex<VecDeque<(String, Output, bool)>>,
    }

    impl FakeRunner {
        pub fn new() -> Self {
            Self::default()
        }

        /// Reply to commands starting with `prefix` (space-joined argv).
        pub fn on(&self, prefix: &str, reply: Output) -> &Self {
            self.rules
                .lock()
                .unwrap()
                .push_back((prefix.into(), reply, false));
            self
        }

        /// Like [`on`](Self::on) but only for the next matching command.
        pub fn once(&self, prefix: &str, reply: Output) -> &Self {
            self.rules
                .lock()
                .unwrap()
                .push_front((prefix.into(), reply, true));
            self
        }

        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    pub fn ok(stdout: &str) -> Output {
        Output {
            status_ok: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn fail(stderr: &str) -> Output {
        Output {
            status_ok: false,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[&str]) -> io::Result<Output> {
            let line = argv.join(" ");
            self.calls.lock().unwrap().push(line.clone());
            let mut rules = self.rules.lock().unwrap();
            if let Some(i) = rules
                .iter()
                .position(|(p, _, _)| line.starts_with(p.as_str()))
            {
                let (_, reply, once) = rules[i].clone();
                if once {
                    rules.remove(i);
                }
                return Ok(reply);
            }
            Ok(ok(""))
        }
    }

    #[test]
    fn records_calls_and_matches_rules_in_order() {
        let r = FakeRunner::new();
        r.on("ip -j link", ok("[]"));
        r.once("ip -j link", ok("[1]"));
        assert_eq!(r.run(&["ip", "-j", "link", "show"]).unwrap().stdout, "[1]");
        assert_eq!(r.run(&["ip", "-j", "link", "show"]).unwrap().stdout, "[]");
        assert!(r.run(&["true"]).unwrap().status_ok);
        assert_eq!(r.calls(), ["ip -j link show", "ip -j link show", "true"]);
    }
}
