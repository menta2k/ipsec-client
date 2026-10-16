//! DACL-restricted named-pipe listener (research R3, Constitution II).
//!
//! * DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`: SYSTEM and
//!   Administrators full control, interactive users read/write; nobody else.
//! * `PIPE_REJECT_REMOTE_CLIENTS`: local connections only.
//! * `FILE_FLAG_FIRST_PIPE_INSTANCE`: fail if someone else already owns the
//!   name (pipe squatting).
//!
//! The next instance is created as soon as one connects, so clients rarely
//! see "no instance". Each connected instance becomes a `std::fs::File`.

use super::{wide, SecurityDescriptor};
use crate::server::Listener;
use ipc_proto::client::Stream;
use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
const BUF: u32 = 64 * 1024;

struct Handle(HANDLE);
// SAFETY: a pipe handle may be used from any thread.
unsafe impl Send for Handle {}

pub struct PipeListener {
    name: Vec<u16>,
    path: String,
    sd: SecurityDescriptor,
    pending: Mutex<Option<Handle>>,
    closed: AtomicBool,
}

impl PipeListener {
    pub fn bind(path: &str, sddl: &str) -> io::Result<Self> {
        let sd = SecurityDescriptor::from_sddl(sddl)?;
        let l = PipeListener {
            name: wide(path),
            path: path.to_string(),
            sd,
            pending: Mutex::new(None),
            closed: AtomicBool::new(false),
        };
        let first = l.create_instance(true)?;
        *l.pending.lock().unwrap() = Some(first);
        Ok(l)
    }

    fn create_instance(&self, first: bool) -> io::Result<Handle> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: `name` is NUL-terminated; `sa` and its descriptor outlive the call.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUF,
                BUF,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Handle(h))
    }
}

impl Listener for PipeListener {
    fn accept(&self) -> io::Result<Box<dyn Stream>> {
        let h = match self.pending.lock().unwrap().take() {
            Some(h) => h,
            None => self.create_instance(false)?,
        };
        // SAFETY: `h.0` is a valid server pipe handle; synchronous connect.
        let ok = unsafe { ConnectNamedPipe(h.0, std::ptr::null_mut()) };
        // SAFETY: reading the thread's last-error value.
        if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            let e = io::Error::last_os_error();
            // SAFETY: we own the handle and close it once.
            unsafe { CloseHandle(h.0) };
            return Err(e);
        }
        if self.closed.load(Ordering::SeqCst) {
            // SAFETY: as above.
            unsafe { CloseHandle(h.0) };
            return Err(io::Error::other("listener closed"));
        }
        // Have the next instance ready before handing this one off.
        if let Ok(next) = self.create_instance(false) {
            *self.pending.lock().unwrap() = Some(next);
        }
        // SAFETY: ownership of the connected handle moves into the File.
        Ok(Box::new(unsafe { File::from_raw_handle(h.0 as _) }))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Wake a blocked ConnectNamedPipe by connecting to ourselves.
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path);
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        if let Some(h) = self.pending.lock().unwrap().take() {
            // SAFETY: unconnected instance we own.
            unsafe { CloseHandle(h.0) };
        }
    }
}
