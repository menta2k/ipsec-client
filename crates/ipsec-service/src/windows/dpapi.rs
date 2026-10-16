//! DPAPI secret protection (research R7): machine scope, so the LocalSystem
//! service can decrypt regardless of the logged-in user, plus fixed
//! application entropy. The profile file itself is ACL'd to SYSTEM/Admins.

use std::io;
use vpn_core::traits::SecretProtector;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

const ENTROPY: &[u8] = b"IpsecClient/profile-secret/v1";

pub struct DpapiProtector;

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
        // SAFETY: input/entropy point to live slices for the call; `out` is
        // allocated by DPAPI and released in `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: filled by CryptProtectData above.
        Ok(unsafe { take(out) })
    }

    fn unprotect(&self, data: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = DpapiProtector;
        let blob = p.protect(b"s3cret").unwrap();
        assert!(!blob.windows(6).any(|w| w == b"s3cret"));
        assert_eq!(&*p.unprotect(&blob).unwrap(), b"s3cret");
        assert!(p.unprotect(b"garbage").is_err());
    }
}
