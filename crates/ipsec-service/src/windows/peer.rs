//! Who is on the other end of a pipe connection (003 research R4).
//!
//! The service decides administrator-only requests from the client process's
//! token, which the OS attests, never from anything the client sends:
//! `is_admin` = LocalSystem, or an **elevated** token that is a member of
//! BUILTIN\Administrators (a non-elevated admin's filtered token has that
//! group deny-only, so `CheckTokenMembership` already says no; elevation is
//! checked as well for clarity).

use crate::server::Peer;
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation, IsWellKnownSid,
    LookupAccountSidW, SecurityIdentification, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE,
    TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The decision itself, kept pure so it is unit-tested.
pub fn is_admin(is_system: bool, elevated: bool, admin_member: bool) -> bool {
    is_system || (elevated && admin_member)
}

/// Identify the client of a connected server pipe handle. Any failure yields
/// a non-admin peer: the safe default.
pub fn pipe_peer(pipe: HANDLE) -> Peer {
    match identify(pipe) {
        Ok(p) => p,
        Err(e) => Peer {
            is_admin: false,
            desc: format!("unidentified client ({e})"),
        },
    }
}

/// Closes a handle when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: we own the handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn identify(pipe: HANDLE) -> io::Result<Peer> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a connected server pipe handle owned by the caller.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
        return Err(last_err());
    }
    // SAFETY: plain query of another process by id; handle owned below.
    let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0.is_null() {
        return Err(last_err());
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid process handle; the token handle is owned below.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) } == 0 {
        return Err(last_err());
    }
    let token = Owned(token);

    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size we pass.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_err());
    }
    let elevated = elev.TokenIsElevated != 0;

    // TOKEN_USER is followed by the SID it points to; 256 bytes is ample.
    let mut user_buf = [0u64; 32];
    // SAFETY: the buffer is 8-byte aligned and its size is passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_buf.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&user_buf) as u32,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_err());
    }
    // SAFETY: GetTokenInformation(TokenUser) filled a TOKEN_USER at the start.
    let user_sid: PSID = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    // SAFETY: `user_sid` points into `user_buf`, which outlives these calls.
    let is_system = unsafe { IsWellKnownSid(user_sid, WinLocalSystemSid) } != 0;

    // CheckTokenMembership needs an impersonation token.
    let mut imp: HANDLE = std::ptr::null_mut();
    // SAFETY: valid primary token with TOKEN_DUPLICATE; result owned below.
    if unsafe { DuplicateToken(token.0, SecurityIdentification, &mut imp) } == 0 {
        return Err(last_err());
    }
    let imp = Owned(imp);
    let mut admins = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut admins_len = admins.len() as u32;
    // SAFETY: the buffer holds SECURITY_MAX_SID_SIZE bytes, as passed.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admins.as_mut_ptr() as PSID,
            &mut admins_len,
        )
    };
    if ok == 0 {
        return Err(last_err());
    }
    let mut member = 0;
    // SAFETY: impersonation token and a valid SID buffer.
    if unsafe { CheckTokenMembership(imp.0, admins.as_mut_ptr() as PSID, &mut member) } == 0 {
        return Err(last_err());
    }

    let admin = is_admin(is_system, elevated, member != 0);
    Ok(Peer {
        is_admin: admin,
        desc: format!(
            "pid={pid} user={} elevated={elevated} admin={admin}",
            account_name(user_sid)
        ),
    })
}

/// `DOMAIN\name` for a SID, or `?` if it cannot be resolved.
fn account_name(sid: PSID) -> String {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let (mut nlen, mut dlen) = (name.len() as u32, domain.len() as u32);
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: buffers and their lengths are passed together; `sid` is valid.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut nlen,
            domain.as_mut_ptr(),
            &mut dlen,
            &mut kind,
        )
    };
    if ok == 0 {
        return "?".into();
    }
    format!(
        "{}\\{}",
        String::from_utf16_lossy(&domain[..dlen as usize]),
        String::from_utf16_lossy(&name[..nlen as usize])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_decision() {
        assert!(is_admin(true, false, false), "LocalSystem");
        assert!(is_admin(false, true, true), "elevated administrator");
        assert!(!is_admin(false, false, true), "non-elevated administrator");
        assert!(!is_admin(false, true, false), "elevated non-member");
        assert!(!is_admin(false, false, false), "standard user");
    }

    #[test]
    fn a_bad_handle_yields_a_non_admin_peer() {
        let p = pipe_peer(std::ptr::null_mut());
        assert!(!p.is_admin);
        assert!(p.desc.starts_with("unidentified client"), "{}", p.desc);
    }
}
