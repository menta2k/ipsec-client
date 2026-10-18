//! The system service's control socket (004 research R5).
//!
//! The socket lives in a directory owned by root and the VPN group with mode
//! 0750, and is itself 0660, so the kernel refuses everyone else before any
//! byte is read. Each accepted peer's uid, gid and pid are logged.

use super::sys;
use crate::server::{Listener, Peer};
use ipc_proto::client::Stream;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;

pub struct MacSocketListener {
    listener: UnixListener,
    path: PathBuf,
    closed: AtomicBool,
}

/// Whether an existing socket directory may be used: owned by root, and not
/// writable by anyone else (otherwise someone else could replace the socket).
pub fn dir_is_trusted(owner_uid: u32, mode: u32) -> bool {
    owner_uid == 0 && mode & 0o022 == 0
}

impl MacSocketListener {
    /// Create `dir` (root:`gid`, 0750) if needed, then bind `dir/<name>` with
    /// mode 0660 and group `gid`.
    pub fn bind(path: PathBuf, gid: u32) -> io::Result<Self> {
        let dir = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "socket path has no directory")
        })?;
        prepare_dir(dir, gid)?;
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
        std::os::unix::fs::chown(&path, Some(0), Some(gid))?;
        Ok(MacSocketListener {
            listener,
            path,
            closed: AtomicBool::new(false),
        })
    }
}

fn prepare_dir(dir: &Path, gid: u32) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) => {
            if !m.is_dir() || !dir_is_trusted(m.uid(), m.mode()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} exists but is not a root-owned directory closed to others; remove it and restart the service",
                        dir.display()
                    ),
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o750).create(dir)?;
        }
        Err(e) => return Err(e),
    }
    std::os::unix::fs::chown(dir, Some(0), Some(gid))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
}

impl Listener for MacSocketListener {
    fn accept(&self) -> io::Result<(Box<dyn Stream>, Peer)> {
        let (s, _) = self.listener.accept()?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other("listener closed"));
        }
        let peer = match sys::peer_cred(s.as_raw_fd()) {
            Ok((uid, gid, pid)) => {
                info!(target: "ipc", uid, gid, pid, "client connected");
                Peer {
                    is_admin: uid == 0,
                    desc: format!("pid {pid}, uid {uid}"),
                }
            }
            Err(e) => {
                tracing::warn!(target: "ipc", error = %e, "peer credentials unavailable");
                Peer::default()
            }
        };
        Ok((Box::new(s), peer))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Wake the blocked accept with a throwaway connection.
        let _ = UnixStream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_root_owned_directories_closed_to_others_are_trusted() {
        assert!(dir_is_trusted(0, 0o750));
        assert!(dir_is_trusted(0, 0o700));
        assert!(!dir_is_trusted(501, 0o750));
        assert!(!dir_is_trusted(0, 0o770));
        assert!(!dir_is_trusted(0, 0o757));
    }

    #[test]
    fn peer_credentials_name_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let (uid, _gid, pid) = sys::peer_cred(a.as_raw_fd()).unwrap();
        assert_eq!(pid, std::process::id() as i32);
        // The owner of a file this process creates is its effective uid.
        let probe = std::env::temp_dir().join(format!("ipsec-peercred-{}", std::process::id()));
        std::fs::write(&probe, b"").unwrap();
        let me = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_file(&probe);
        assert_eq!(uid, me);
    }
}
