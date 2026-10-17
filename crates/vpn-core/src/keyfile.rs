//! Machine-key secret protector (002 research R4): the Linux counterpart of
//! DPAPI machine scope. Secrets are sealed with AES-256-GCM under a random
//! 256-bit key kept in a file only the service account can read.
//!
//! Blob: `0x01 ‖ nonce(12) ‖ ciphertext ‖ tag(16)`, AAD `"ipsec-client secret v1"`.

use crate::traits::SecretProtector;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AAD: &[u8] = b"ipsec-client secret v1";

type MachineKey = Zeroizing<[u8; 32]>;

pub struct KeyFileProtector {
    path: PathBuf,
    /// Loaded (or created) key; the lock also serializes first-time creation.
    key: Mutex<Option<MachineKey>>,
}

impl KeyFileProtector {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            key: Mutex::new(None),
        }
    }

    /// The machine key; with `create`, a missing key file is generated.
    fn key(&self, create: bool) -> io::Result<MachineKey> {
        let mut slot = self.key.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = slot.as_ref() {
            return Ok(k.clone());
        }
        let key = match std::fs::read(&self.path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    invalid(format!("{} is not a 32-byte key", self.path.display()))
                })?;
                Zeroizing::new(arr)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                let mut k = Zeroizing::new([0u8; 32]);
                getrandom::getrandom(&mut k[..]).map_err(|e| io::Error::other(e.to_string()))?;
                write_private(&self.path, &k[..])?;
                k
            }
            Err(e) => return Err(e),
        };
        *slot = Some(key.clone());
        Ok(key)
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Atomically write `data` to `path`, readable only by the owner on unix.
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

impl SecretProtector for KeyFileProtector {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let key = self.key(true)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: AAD,
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(invalid("protected secret is truncated"));
        }
        if blob[0] != VERSION {
            return Err(invalid(format!("unknown secret format {}", blob[0])));
        }
        let key = self.key(false)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));
        let (nonce, sealed) = blob[1..].split_at(NONCE_LEN);
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: AAD,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid("protected secret failed authentication"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ipsec-keyfile-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d.join("secret.key")
    }

    fn invalid(r: io::Result<Zeroizing<Vec<u8>>>) -> bool {
        matches!(r, Err(e) if e.kind() == io::ErrorKind::InvalidData)
    }

    #[test]
    fn round_trip_and_random_nonce() {
        let p = KeyFileProtector::new(tmp("rt"));
        let a = p.protect(b"hunter2").unwrap();
        let b = p.protect(b"hunter2").unwrap();
        assert_ne!(a, b, "nonce must be random");
        assert_eq!(a[0], 1);
        assert_eq!(a.len(), 1 + 12 + 7 + 16);
        assert_eq!(&p.unprotect(&a).unwrap()[..], b"hunter2");
        assert_eq!(&p.unprotect(&b).unwrap()[..], b"hunter2");
    }

    #[test]
    fn tampering_version_and_length_are_rejected() {
        let p = KeyFileProtector::new(tmp("tamper"));
        let blob = p.protect(b"secret").unwrap();
        for i in [0usize, 1, 13, blob.len() - 1] {
            let mut t = blob.clone();
            t[i] ^= 0x01;
            assert!(invalid(p.unprotect(&t)), "flip at {i} accepted");
        }
        assert!(invalid(p.unprotect(&blob[..28])));
        assert!(invalid(p.unprotect(&[])));
    }

    #[test]
    fn a_different_key_cannot_open_the_blob() {
        let blob = KeyFileProtector::new(tmp("k1")).protect(b"x").unwrap();
        let other = KeyFileProtector::new(tmp("k2"));
        other.protect(b"create key").unwrap();
        assert!(invalid(other.unprotect(&blob)));
    }

    #[test]
    fn unprotect_without_key_fails_and_creates_nothing() {
        let path = tmp("nokey");
        let blob = KeyFileProtector::new(tmp("src")).protect(b"x").unwrap();
        let p = KeyFileProtector::new(&path);
        assert!(p.unprotect(&blob).is_err());
        assert!(!path.exists(), "unprotect must never create a key");
    }

    #[test]
    fn protect_creates_a_private_32_byte_key_once() {
        let path = tmp("create");
        let p = KeyFileProtector::new(&path);
        p.protect(b"a").unwrap();
        let key = std::fs::read(&path).unwrap();
        assert_eq!(key.len(), 32);
        p.protect(b"b").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), key, "key must be reused");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_key_file_is_an_error_not_a_panic() {
        let path = tmp("corrupt");
        std::fs::write(&path, b"short").unwrap();
        let p = KeyFileProtector::new(&path);
        assert!(p.protect(b"x").is_err());
        assert!(p.unprotect(&[1; 40]).is_err());
    }
}
