//! DPAPI secret protection (research R7, amended by security finding F8).
//!
//! The service runs as LocalSystem and seals secrets with SYSTEM's own DPAPI
//! key ([`Scope::Account`]), so no other account on the machine can decrypt
//! them, even one that manages to read `profiles.json`. Those blobs carry the
//! [`ACCOUNT_MAGIC`] prefix.
//!
//! Blobs written by older versions (and by `ipsec-service run`, which runs as
//! an administrator and cannot use SYSTEM's key) are machine-scope and have no
//! prefix. They still decrypt, and the service re-seals them under its own key
//! at startup ([`vpn_core::ProfileStore::reseal_legacy`]).

use std::io;
use vpn_core::traits::SecretProtector;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroizing;

const ENTROPY: &[u8] = b"IpsecClient/profile-secret/v1";

/// Prefix of account-scope blobs. A raw DPAPI blob starts with its version
/// (`01 00 00 00`), so it can never begin with these bytes.
pub const ACCOUNT_MAGIC: &[u8] = b"IPSC/acct/1:";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Sealed with the running account's own DPAPI key (SYSTEM for the
    /// service). Only that account can decrypt.
    Account,
    /// Sealed with the machine key: any process on this machine can decrypt.
    /// Used only when not running as LocalSystem (`ipsec-service run`).
    Machine,
}

pub struct DpapiProtector {
    scope: Scope,
}

impl DpapiProtector {
    pub fn with_scope(scope: Scope) -> Self {
        DpapiProtector { scope }
    }

    /// Account scope when running as LocalSystem (the installed service),
    /// machine scope otherwise, so secrets saved from `run` stay usable by
    /// the service (which re-seals them at its next start).
    pub fn for_this_process() -> Self {
        Self::with_scope(if running_as_local_system() {
            Scope::Account
        } else {
            Scope::Machine
        })
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }
}

/// True if this process's token user is LocalSystem.
fn running_as_local_system() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // TOKEN_USER is followed by the SID it points to; 256 bytes is ample.
    let mut user_buf = [0u64; 32];
    let mut len = 0u32;
    // SAFETY: standard token query on our own process; the buffer is 8-byte
    // aligned and its size is passed; the handle is closed before returning.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let ok = GetTokenInformation(
            token,
            TokenUser,
            user_buf.as_mut_ptr() as *mut _,
            std::mem::size_of_val(&user_buf) as u32,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return false;
        }
        let sid = (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
    }
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copy out and free a DPAPI output blob.
///
/// SAFETY: `out` must have been filled by CryptProtectData/CryptUnprotectData.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
    LocalFree(out.pbData as _);
    v
}

impl SecretProtector for DpapiProtector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let flags = match self.scope {
            Scope::Account => CRYPTPROTECT_UI_FORBIDDEN,
            Scope::Machine => CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
        };
        // SAFETY: input/entropy point to live slices for the call; `out` is
        // allocated by DPAPI and released in `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                flags,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: filled by CryptProtectData above.
        let sealed = unsafe { take(out) };
        Ok(match self.scope {
            Scope::Account => [ACCOUNT_MAGIC, &sealed].concat(),
            Scope::Machine => sealed,
        })
    }

    fn unprotect(&self, data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        // DPAPI records the scope inside the blob; only our prefix is ours.
        let data = data.strip_prefix(ACCOUNT_MAGIC).unwrap_or(data);
        let input = blob(data);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: filled by CryptUnprotectData. Wipe the DPAPI buffer before
        // freeing it so the plaintext does not linger on the heap.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData as _);
            Ok(Zeroizing::new(v))
        }
    }

    fn needs_reseal(&self, data: &[u8]) -> bool {
        self.scope == Scope::Account && !data.starts_with(ACCOUNT_MAGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_in_both_scopes() {
        for scope in [Scope::Account, Scope::Machine] {
            let p = DpapiProtector::with_scope(scope);
            let blob = p.protect(b"s3cret").unwrap();
            assert!(!blob.windows(6).any(|w| w == b"s3cret"));
            assert_eq!(blob.starts_with(ACCOUNT_MAGIC), scope == Scope::Account);
            assert_eq!(&*p.unprotect(&blob).unwrap(), b"s3cret");
            assert!(!p.needs_reseal(&blob));
            assert!(p.unprotect(b"garbage").is_err());
        }
    }

    #[test]
    fn legacy_machine_blobs_open_and_are_flagged_for_reseal() {
        let legacy = DpapiProtector::with_scope(Scope::Machine)
            .protect(b"old")
            .unwrap();
        let account = DpapiProtector::with_scope(Scope::Account);
        assert_eq!(&*account.unprotect(&legacy).unwrap(), b"old");
        assert!(account.needs_reseal(&legacy));
        // Machine scope never asks for a reseal (it would be a no-op).
        assert!(!DpapiProtector::with_scope(Scope::Machine).needs_reseal(&legacy));
    }

    #[test]
    fn account_blobs_are_not_machine_readable() {
        // The account blob's DPAPI payload, stripped of our prefix, is a
        // user-scope blob: it does not carry CRYPTPROTECT_LOCAL_MACHINE.
        // (Decrypting it as another account cannot be exercised here; this
        // checks the flag DPAPI recorded instead.)
        let blob = DpapiProtector::with_scope(Scope::Account)
            .protect(b"x")
            .unwrap();
        let raw = &blob[ACCOUNT_MAGIC.len()..];
        // DPAPI_BLOB: version(4) provider(16) mkversion(4) mkguid(16) flags(4)
        let flags = u32::from_le_bytes(raw[40..44].try_into().unwrap());
        assert_eq!(flags & CRYPTPROTECT_LOCAL_MACHINE, 0);
        let legacy = DpapiProtector::with_scope(Scope::Machine)
            .protect(b"x")
            .unwrap();
        let flags = u32::from_le_bytes(legacy[40..44].try_into().unwrap());
        assert_ne!(flags & CRYPTPROTECT_LOCAL_MACHINE, 0);
    }
}
