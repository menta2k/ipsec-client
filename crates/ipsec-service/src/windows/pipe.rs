//! DACL-restricted named-pipe listener (research R3, Constitution II).
//!
//! * Owner Administrators (`O:BA`), which clients require (with SYSTEM) before
//!   they send anything (`ipc_proto::client::TRUSTED_PIPE_OWNERS`). SYSTEM and
//!   elevated administrators may assign that owner; ordinary users cannot.
//! * DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)`: SYSTEM and
//!   Administrators full control; interactive users read/write
//!   (`FILE_GENERIC_READ | FILE_GENERIC_WRITE`) **without**
//!   `FILE_CREATE_PIPE_INSTANCE` (0x4), so they cannot add server instances
//!   next to the service's and receive other users' requests. No one else is
//!   admitted. Owner and DACL are per pipe name: the first instance sets them.
//! * `PIPE_REJECT_REMOTE_CLIENTS`: local connections only.
//! * `FILE_FLAG_FIRST_PIPE_INSTANCE`: fail if someone else already owns the
//!   name (pipe squatting).
//!
//! The next instance is created as soon as one connects, so clients rarely
//! see "no instance". Each connected instance becomes a `std::fs::File`.

use super::{wide, SecurityDescriptor};
use crate::server::{Listener, Peer};
use ipc_proto::client::Stream;
use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// The service's pipe (and an elevated `run`): see the module docs.
pub const PIPE_SDDL: &str = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";

/// `run --mock` runs as the user, who can neither assign owner Administrators
/// nor add instances under [`PIPE_SDDL`]'s DACL. Same DACL, the default owner
/// (the user), plus OWNER RIGHTS: `FILE_CREATE_PIPE_INSTANCE` and the owner's
/// usual `READ_CONTROL | WRITE_DAC`. Clients refuse such a pipe on the
/// service's name, so mock mode must run on a private `IPSEC_CLIENT_PIPE`.
pub const MOCK_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)(A;;0x60004;;;OW)";

const BUF: u32 = 64 * 1024;

/// Owner SID (string form) of the named pipe behind a client handle. Installed
/// as `ipc_proto`'s pipe owner probe by the CLI (`plc_cli`).
pub fn owner_sid(pipe: &File) -> io::Result<String> {
    use std::os::windows::io::AsRawHandle;
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open for the duration of the call (borrowed from
    // `pipe`); on success `sd` is a LocalAlloc'd descriptor that `owner`
    // points into, freed by the guard below.
    let rc = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _sd = SecurityDescriptor(sd);
    if owner.is_null() {
        return Err(io::Error::other("the pipe has no owner"));
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `owner` points into `_sd`, alive here; `text` receives a
    // LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(owner, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` is a NUL-terminated wide string; it is read, then freed
    // exactly once.
    unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as _);
        Ok(s)
    }
}

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
    fn accept(&self) -> io::Result<(Box<dyn Stream>, Peer)> {
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
        // OS-attested client identity for administrator-only requests.
        let peer = super::peer::pipe_peer(h.0);
        // SAFETY: ownership of the connected handle moves into the File.
        Ok((Box::new(unsafe { File::from_raw_handle(h.0 as _) }), peer))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER};
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, WinInteractiveSid, SECURITY_MAX_SID_SIZE,
    };

    /// The DACL every pipe of the service has, without the owner (a test that
    /// is not elevated cannot assign owner Administrators).
    fn service_dacl() -> &'static str {
        PIPE_SDDL.strip_prefix("O:BA").expect("explicit owner")
    }

    fn private_name(tag: &str) -> String {
        format!(r"\\.\pipe\IpsecClient.f13.{}.{tag}", std::process::id())
    }

    /// True if this process's token contains NT AUTHORITY\INTERACTIVE.
    fn interactive() -> bool {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = sid.len() as u32;
        let mut member = 0;
        // SAFETY: the buffer holds `len` bytes; a null token means our own.
        unsafe {
            CreateWellKnownSid(
                WinInteractiveSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr() as PSID,
                &mut len,
            ) != 0
                && CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr() as PSID, &mut member)
                    != 0
                && member != 0
        }
    }

    #[test]
    fn sddl_owner_and_instance_rights() {
        assert!(PIPE_SDDL.starts_with("O:BA"), "{PIPE_SDDL}");
        // FILE_GENERIC_READ | FILE_GENERIC_WRITE (0x12019f) minus
        // FILE_CREATE_PIPE_INSTANCE (0x4).
        assert_eq!(0x12_0089 | 0x12_0116, 0x12_019f);
        assert_eq!(0x12_019f & !0x4, 0x12_019b);
        assert!(service_dacl().contains("(A;;0x12019b;;;IU)"));
        assert!(!service_dacl().contains("GW;;;IU"));
        // Mock mode: same DACL, no forced owner, OWNER RIGHTS may add instances.
        assert_eq!(
            MOCK_PIPE_SDDL,
            format!("{}(A;;0x60004;;;OW)", service_dacl())
        );
        for sddl in [PIPE_SDDL, MOCK_PIPE_SDDL] {
            SecurityDescriptor::from_sddl(sddl).expect(sddl);
        }
    }

    /// F13: an interactive user must not be able to add an instance to the
    /// service's pipe (it would receive other users' requests). The first
    /// instance is created here with the service's DACL; adding a second is
    /// what an impostor would do.
    #[test]
    fn interactive_users_cannot_add_instances_to_the_service_pipe() {
        if super::super::is_elevated() {
            eprintln!("skipped: elevated (Administrators may add instances)");
            return;
        }
        // Control: the previous DACL (IU GRGW) let them.
        let old = PipeListener::bind(
            &private_name("old"),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
        )
        .expect("bind old DACL");
        let added = old
            .create_instance(false)
            .expect("IU GRGW admits a 2nd instance");
        // SAFETY: an unconnected instance we own, closed once.
        unsafe { CloseHandle(added.0) };

        let name = private_name("new");
        let l = PipeListener::bind(&name, service_dacl()).expect("bind service DACL");
        let e = l
            .create_instance(false)
            .err()
            .expect("2nd instance refused");
        assert_eq!(e.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32), "{e}");

        // Interactive users can still open the pipe as clients.
        if interactive() {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name)
                .expect("client open under the service DACL");
        }
    }

    /// Only SYSTEM and elevated administrators can make a pipe whose owner
    /// passes the client's check; an elevated `run` does (`O:BA`).
    #[test]
    fn only_administrators_can_create_a_pipe_clients_trust() {
        ipc_proto::client::set_pipe_owner_probe(owner_sid);
        let name = private_name("owner");
        if super::super::is_elevated() {
            let l = PipeListener::bind(&name, PIPE_SDDL).expect("elevated bind");
            // A second listening instance, one per client below.
            let extra = l
                .create_instance(false)
                .expect("administrators add instances");
            let c = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name)
                .unwrap();
            assert_eq!(owner_sid(&c).unwrap(), "S-1-5-32-544");
            ipc_proto::client::connect_verified_pipe_at(name.as_ref())
                .expect("elevated `run` is accepted");
            // SAFETY: an instance we own, closed once.
            unsafe { CloseHandle(extra.0) };
            return;
        }
        for sddl in [PIPE_SDDL.to_string(), format!("O:SY{}", service_dacl())] {
            let e = PipeListener::bind(&name, &sddl).err().expect(&sddl);
            assert_eq!(
                e.raw_os_error(),
                Some(ERROR_INVALID_OWNER as i32),
                "{sddl}: {e}"
            );
        }
    }

    /// The name squatted while the service is stopped: a pipe created by an
    /// ordinary user. The client refuses it before writing anything.
    #[test]
    fn client_refuses_a_pipe_owned_by_an_ordinary_user() {
        if super::super::is_elevated() {
            eprintln!("skipped: elevated (the test pipe would be owned by Administrators)");
            return;
        }
        ipc_proto::client::set_pipe_owner_probe(owner_sid);
        let name = private_name("squat");
        let l = PipeListener::bind(&name, MOCK_PIPE_SDDL).expect("bind as the user");
        let server = std::thread::spawn(move || {
            let mut got = Vec::new();
            match l.accept() {
                Ok((mut s, _)) => {
                    let _ = s.read_to_end(&mut got); // ends when the client closes
                }
                // ERROR_NO_DATA: the client came and went before the accept.
                Err(e) => assert_eq!(e.raw_os_error(), Some(232), "{e}"),
            }
            got
        });
        let e = ipc_proto::client::connect_verified_pipe_at(name.as_ref())
            .err()
            .expect("refused");
        assert!(e.to_string().contains("not the IpsecClient service"), "{e}");
        assert!(
            server.join().unwrap().is_empty(),
            "bytes reached the impostor"
        );

        // Unverified paths (IPSEC_CLIENT_PIPE) still reach the mock's pipe.
        let l = PipeListener::bind(&private_name("mock"), MOCK_PIPE_SDDL).unwrap();
        let t = std::thread::spawn(move || l.accept().map(|_| ()));
        let c = ipc_proto::client::connect_stream_at(private_name("mock").as_ref())
            .expect("override path is not checked");
        t.join().unwrap().unwrap();
        drop(c);
    }

    #[test]
    fn mock_owner_can_add_instances() {
        let l = PipeListener::bind(&private_name("mockadd"), MOCK_PIPE_SDDL).unwrap();
        let h = l.create_instance(false).expect("owner adds an instance");
        // SAFETY: an unconnected instance we own, closed once.
        unsafe { CloseHandle(h.0) };
    }
}
