//! External commands behind a seam (002 research R2, 004 research R2): the
//! Linux and macOS back-ends build argv (and, for `scutil`, standard input)
//! and run it through [`CommandRunner`], so tests check the exact commands
//! with [`fake::FakeRunner`] on any OS.

// On Windows only the unit tests use this module.
#![cfg_attr(windows, allow(dead_code))]

use std::io::{self, Write};
use std::process::{Command, Stdio};

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

    /// Like [`run`](Self::run), with `stdin` written to the program's
    /// standard input (macOS `scutil` scripts, 004 research R3).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn run_with_input(&self, argv: &[&str], _stdin: &[u8]) -> io::Result<Output> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{}: standard input not supported", argv.join(" ")),
        ))
    }
}

/// Runs commands with `std::process::Command`. On Linux, children inherit the
/// service's ambient capabilities (002 research R7).
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, argv: &[&str]) -> io::Result<Output> {
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        output(Command::new(prog).args(args).output()?)
    }

    fn run_with_input(&self, argv: &[&str], stdin: &[u8]) -> io::Result<Output> {
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Dropping the handle after the write closes the pipe (end of input).
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no stdin pipe"))?
            .write_all(stdin)?;
        output(child.wait_with_output()?)
    }
}

fn output(out: std::process::Output) -> io::Result<Output> {
    Ok(Output {
        status_ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

#[cfg(test)]
pub mod fake {
    use super::{CommandRunner, Output};
    use std::collections::VecDeque;
    use std::io;
    use std::sync::Mutex;

    /// Records every argv (and standard input) and answers from a script of
    /// `(argv prefix, reply)` rules; the first matching rule is used (and
    /// consumed if `once`). Unmatched commands succeed with empty output.
    #[derive(Default)]
    pub struct FakeRunner {
        calls: Mutex<Vec<String>>,
        inputs: Mutex<Vec<(String, String)>>,
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

        /// `(argv, stdin)` of every [`CommandRunner::run_with_input`] call.
        pub fn inputs(&self) -> Vec<(String, String)> {
            self.inputs.lock().unwrap().clone()
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

        fn run_with_input(&self, argv: &[&str], stdin: &[u8]) -> io::Result<Output> {
            self.inputs
                .lock()
                .unwrap()
                .push((argv.join(" "), String::from_utf8_lossy(stdin).into_owned()));
            self.run(argv)
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

    #[test]
    fn records_standard_input() {
        let r = FakeRunner::new();
        assert!(
            r.run_with_input(
                &["scutil"],
                b"show x
"
            )
            .unwrap()
            .status_ok
        );
        assert_eq!(r.calls(), ["scutil"]);
        assert_eq!(
            r.inputs(),
            [(
                "scutil".to_string(),
                "show x
"
                .to_string()
            )]
        );
    }
}
