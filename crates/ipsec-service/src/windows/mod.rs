//! Windows platform layer: SCM host, Wintun, IP Helper, DPAPI, named pipes,
//! directory ACLs and the event log. All `unsafe` in the workspace lives here.

pub mod dpapi;
pub mod eventlog;
pub mod netconfig;
pub mod pipe;
pub mod service;
pub mod wintun_tun;

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

/// NUL-terminated UTF-16.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// An owned security descriptor parsed from SDDL (freed with `LocalFree`).
pub struct SecurityDescriptor(pub PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let s = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `s` is a valid NUL-terminated wide string; `sd` receives a
        // LocalAlloc'd descriptor that we own and free in Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                s.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from ConvertStringSecurityDescriptor... and
        // is freed exactly once.
        unsafe { LocalFree(self.0 as _) };
    }
}

// SAFETY: the descriptor is immutable after creation and only read by Win32.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

/// Restrict a directory to SYSTEM + Administrators (full control, inherited),
/// removing inherited entries such as Users:read.
pub fn secure_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let sd = SecurityDescriptor::from_sddl("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let mut present = 0i32;
    let mut defaulted = 0i32;
    let mut dacl = std::ptr::null_mut();
    // SAFETY: `sd.0` is a valid descriptor; out-params are valid pointers.
    let ok = unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let p = wide(path.as_os_str());
    // SAFETY: `p` is NUL-terminated; `dacl` points into `sd`, alive for the call.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// True if the current process token is elevated / running as SYSTEM.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: standard token query on our own process; handle closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}
