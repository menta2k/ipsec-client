//! OS binding (Windows): who owns the service's named pipe. `ipc_proto`
//! calls this before it sends anything over `\\.\pipe\IpsecClient.v1`, and
//! refuses a pipe that SYSTEM or Administrators do not own, so a sign-in
//! password cannot reach a process that took the name.

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

/// Memory returned by Win32 that must be released with `LocalFree`.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: LocalAlloc'd by the API that returned it; freed once.
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

/// Owner SID (string form, e.g. `S-1-5-18`) of the named pipe behind a client
/// handle: the probe for `ipc_proto::client::set_pipe_owner_probe`.
pub fn owner_sid(pipe: &File) -> io::Result<String> {
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle is open for the duration of the call (borrowed from
    // `pipe`); on success `sd` is a LocalAlloc'd descriptor that `owner`
    // points into.
    let rc = unsafe {
        GetSecurityInfo(
            HANDLE(pipe.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let _sd = Local(sd.0);
    if owner.0.is_null() {
        return Err(io::Error::other("the pipe has no owner"));
    }
    let mut text = PWSTR::null();
    // SAFETY: `owner` points into `_sd`, alive here; `text` receives a
    // LocalAlloc'd string.
    unsafe { ConvertSidToStringSidW(owner, &mut text) }.map_err(io::Error::other)?;
    let _text = Local(text.0.cast());
    // SAFETY: a NUL-terminated wide string, read before `_text` frees it.
    Ok(String::from_utf16_lossy(unsafe { text.as_wide() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_owner_as_a_sid_string() {
        // Any handle with READ_CONTROL works; a fresh file is ours.
        let p = std::env::temp_dir().join(format!("ipsec-plap-owner-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let f = File::open(&p).unwrap();
        let sid = owner_sid(&f).unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        drop(f);
        let _ = std::fs::remove_file(p);
    }
}
