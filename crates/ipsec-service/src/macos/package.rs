//! What the installer package puts on disk, and `uninstall` on macOS
//! (004 contracts/macos-system-integration.md, T044). The plan is a plain
//! list so its order is unit-tested; executing it is a thin loop.

use super::launchd::{self, Verb, VerbError, PLIST_PATH};
use crate::paths::{MACOS_DATA_DIR as DATA_DIR, MACOS_LOG_DIR as LOG_DIR, SERVICE_BINARY};
use crate::unix_cmd::CommandRunner;
use std::io;
use std::path::{Path, PathBuf};

pub const APP_BUNDLE: &str = "/Applications/IPsec Client.app";
pub const CLI_SYMLINK: &str = "/usr/local/bin/ipsec-service";
pub const PKG_IDS: [&str; 2] = ["net.ipsec-client.pkg.app", "net.ipsec-client.pkg.service"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Stop and unload the daemon (its SIGTERM handler reverts the network).
    Bootout,
    /// Delete a file, or a directory tree; missing is fine.
    Remove(PathBuf),
    /// Delete the symlink only if it still points at the service binary.
    RemoveSymlink(PathBuf),
    /// `pkgutil --forget <id>`; an unknown receipt is fine.
    Forget(&'static str),
}

/// The ordered steps of `uninstall`: the daemon first, then its files, the
/// app, the receipts, and with `remove_data` the profiles, keys and logs.
pub fn uninstall_plan(remove_data: bool) -> Vec<Step> {
    let mut plan = vec![
        Step::Bootout,
        Step::Remove(PLIST_PATH.into()),
        Step::RemoveSymlink(CLI_SYMLINK.into()),
        Step::Remove(SERVICE_BINARY.into()),
        Step::Remove(APP_BUNDLE.into()),
    ];
    plan.extend(PKG_IDS.iter().map(|id| Step::Forget(id)));
    if remove_data {
        plan.push(Step::Remove(DATA_DIR.into()));
        plan.push(Step::Remove(LOG_DIR.into()));
    }
    plan
}

/// File operations, so tests can record them.
pub trait Fs {
    fn remove(&self, path: &Path) -> io::Result<()>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
}

pub struct RealFs;

impl Fs for RealFs {
    fn remove(&self, path: &Path) -> io::Result<()> {
        let r = match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
            Ok(_) => std::fs::remove_file(path),
            Err(e) => Err(e),
        };
        match r {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }
}

/// Run the plan. Stops at the first failure, except that a receipt which is
/// not there (a build installed by hand) does not count.
pub fn execute(plan: &[Step], runner: &dyn CommandRunner, fs: &dyn Fs) -> Result<(), VerbError> {
    let fail = |message: String| VerbError { code: 1, message };
    for step in plan {
        match step {
            Step::Bootout => launchd::run(Verb::Uninstall, runner)?,
            Step::Remove(p) => fs
                .remove(p)
                .map_err(|e| fail(format!("cannot remove {}: {e}", p.display())))?,
            Step::RemoveSymlink(p) => {
                if fs
                    .read_link(p)
                    .is_ok_and(|t| t == Path::new(SERVICE_BINARY))
                {
                    fs.remove(p)
                        .map_err(|e| fail(format!("cannot remove {}: {e}", p.display())))?;
                }
            }
            Step::Forget(id) => {
                // Missing receipts ("No receipt for ...") are expected.
                let _ = runner.run(&["pkgutil", "--forget", id]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_cmd::fake::{fail, FakeRunner};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeFs {
        removed: Mutex<Vec<String>>,
        link_target: Option<PathBuf>,
    }

    impl Fs for FakeFs {
        fn remove(&self, path: &Path) -> io::Result<()> {
            self.removed
                .lock()
                .unwrap()
                .push(path.to_string_lossy().replace('\\', "/"));
            Ok(())
        }
        fn read_link(&self, _path: &Path) -> io::Result<PathBuf> {
            self.link_target
                .clone()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    #[test]
    fn plan_order_keeps_data_unless_asked() {
        let keep = uninstall_plan(false);
        assert_eq!(keep[0], Step::Bootout, "the daemon goes first");
        assert!(!keep.contains(&Step::Remove(DATA_DIR.into())));
        assert!(!keep.contains(&Step::Remove(LOG_DIR.into())));
        let all = uninstall_plan(true);
        assert_eq!(&all[..keep.len()], &keep[..]);
        assert_eq!(
            &all[keep.len()..],
            [Step::Remove(DATA_DIR.into()), Step::Remove(LOG_DIR.into())]
        );
    }

    #[test]
    fn executes_in_order_and_forgets_both_receipts() {
        let r = FakeRunner::new();
        r.on("pkgutil --forget", fail("No receipt for 'x' found at '/'."));
        let fs = FakeFs {
            link_target: Some(SERVICE_BINARY.into()),
            ..Default::default()
        };
        assert_eq!(execute(&uninstall_plan(true), &r, &fs), Ok(()));
        assert_eq!(
            r.calls(),
            [
                "launchctl bootout system/net.ipsec-client.service",
                "pkgutil --forget net.ipsec-client.pkg.app",
                "pkgutil --forget net.ipsec-client.pkg.service",
            ]
        );
        assert_eq!(
            *fs.removed.lock().unwrap(),
            [
                PLIST_PATH,
                CLI_SYMLINK,
                SERVICE_BINARY,
                APP_BUNDLE,
                DATA_DIR,
                LOG_DIR
            ]
        );
    }

    #[test]
    fn foreign_symlink_is_left_alone_and_a_failed_bootout_stops() {
        let r = FakeRunner::new();
        let fs = FakeFs {
            link_target: Some("/opt/homebrew/bin/something-else".into()),
            ..Default::default()
        };
        execute(&uninstall_plan(false), &r, &fs).unwrap();
        assert!(!fs
            .removed
            .lock()
            .unwrap()
            .contains(&CLI_SYMLINK.to_string()));

        let r = FakeRunner::new();
        r.on(
            "launchctl bootout",
            fail("Boot-out failed: 1: Operation not permitted"),
        );
        let fs = FakeFs::default();
        assert_eq!(execute(&uninstall_plan(true), &r, &fs).unwrap_err().code, 5);
        assert!(fs.removed.lock().unwrap().is_empty(), "nothing removed");
    }
}
