//! Windows: who owns the service's named pipe. `ipc_proto` (which has no
//! `unsafe`) calls this before it sends anything over
//! `\\.\pipe\IpsecClient.v1`, and refuses a pipe that SYSTEM or
//! Administrators do not own, so passwords and PSKs cannot reach another
//! user's process that took the name. This is the GUI's only `unsafe`.

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

/// Memory returned by Win32 that must be released with `LocalFree`.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: LocalAlloc'd by the API that returned it; freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Owner SID (string form, e.g. `S-1-5-18`) of the named pipe behind a client
/// handle: the probe for `ipc_proto::client::set_pipe_owner_probe`.
pub fn owner_sid(pipe: &File) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open for the duration of the call (borrowed from
    // `pipe`); on success `sd` is a LocalAlloc'd descriptor that `owner`
    // points into.
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
    let _sd = Local(sd);
    if owner.is_null() {
        return Err(io::Error::other("the pipe has no owner"));
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `owner` points into `_sd`, alive here; `text` receives a
    // LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(owner, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = Local(text.cast());
    let wide = text.0 as *const u16;
    // SAFETY: a NUL-terminated wide string, read before `text` frees it.
    let s = unsafe {
        let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(wide, len))
    };
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ipsec-gui-owner-{}-{tag}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn reports_the_owner_as_a_sid_string() {
        // Any handle with READ_CONTROL works; a fresh file is ours.
        let p = temp_file("sid");
        let f = File::open(&p).unwrap();
        let sid = owner_sid(&f).unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert_eq!(owner_sid(&f).unwrap(), sid);
        drop(f);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_handle_that_cannot_read_the_owner_is_an_error() {
        let p = temp_file("noread");
        // FILE_READ_DATA only: no READ_CONTROL.
        let f = std::fs::OpenOptions::new()
            .access_mode(0x1)
            .open(&p)
            .unwrap();
        assert!(owner_sid(&f).is_err());
        drop(f);
        let _ = std::fs::remove_file(p);
    }
}
