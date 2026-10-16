//! Unix-domain-socket listener (mock mode on Linux/macOS). The socket file is
//! created with mode 0600 so only the owning user can connect.

use crate::server::Listener;
use ipc_proto::client::Stream;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct UnixSocketListener {
    listener: UnixListener,
    path: PathBuf,
    closed: AtomicBool,
}

impl UnixSocketListener {
    pub fn bind(path: PathBuf) -> io::Result<Self> {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(UnixSocketListener {
            listener,
            path,
            closed: AtomicBool::new(false),
        })
    }
}

impl Listener for UnixSocketListener {
    fn accept(&self) -> io::Result<Box<dyn Stream>> {
        let (s, _) = self.listener.accept()?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other("listener closed"));
        }
        Ok(Box::new(s))
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Wake the blocked accept with a throwaway connection.
        let _ = UnixStream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}
