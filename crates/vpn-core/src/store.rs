//! Persistent, machine-wide profile store with protector-encrypted secrets.

use crate::profile::{validate, FieldError, Profile};
use crate::traits::SecretProtector;
use ipc_proto::{AuthMode, ProfileEdit, ProfileView, SecretUpdate};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    Invalid(FieldError),
    NameTaken,
    MissingSecret(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("profile not found"),
            StoreError::Invalid(e) => write!(f, "invalid profile: {e}"),
            StoreError::NameTaken => f.write_str("a profile with this name already exists"),
            StoreError::MissingSecret(what) => write!(f, "the profile has no saved {what}"),
            StoreError::Io(e) => write!(f, "profile storage error: {e}"),
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// Decrypted secrets for one connection attempt (zeroized on drop).
pub struct ProfileSecrets {
    pub psk: Zeroizing<Vec<u8>>,
    pub password: Option<Zeroizing<String>>,
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    profiles: Vec<Profile>,
}

/// Thread-safe profile store. With `path == None` it is memory-only (tests).
pub struct ProfileStore {
    path: Option<PathBuf>,
    protector: Arc<dyn SecretProtector>,
    profiles: Mutex<Vec<Profile>>,
}

impl ProfileStore {
    /// Open (or create empty) the store at `path`.
    pub fn open(
        path: Option<PathBuf>,
        protector: Arc<dyn SecretProtector>,
    ) -> Result<Self, StoreError> {
        let profiles = match &path {
            Some(p) => match std::fs::read(p) {
                Ok(bytes) => {
                    let f: StoreFile = serde_json::from_slice(&bytes)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    f.profiles
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            },
            None => Vec::new(),
        };
        Ok(ProfileStore {
            path,
            protector,
            profiles: Mutex::new(profiles),
        })
    }

    pub fn list(&self) -> Vec<ProfileView> {
        self.profiles
            .lock()
            .unwrap()
            .iter()
            .map(Profile::view)
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<Profile> {
        self.profiles
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }

    pub fn create(&self, edit: &ProfileEdit) -> Result<ProfileView, StoreError> {
        validate(edit).map_err(StoreError::Invalid)?;
        let mut list = self.profiles.lock().unwrap();
        Self::check_name(&list, &edit.name, None)?;
        let mut p = Profile {
            id: new_id(),
            name: String::new(),
            gateway: String::new(),
            port: 500,
            local_id: String::new(),
            id_type: edit.id_type,
            dh_group: edit.dh_group,
            auth: edit.auth,
            username: String::new(),
            auto_reconnect: false,
            psk_blob: None,
            password_blob: None,
        };
        p.apply_fields(edit);
        self.apply_secret(&mut p.psk_blob, &edit.psk)?;
        self.apply_secret(&mut p.password_blob, &edit.password)?;
        if p.auth == AuthMode::Psk {
            p.password_blob = None;
        }
        let view = p.view();
        list.push(p);
        self.persist(&list)?;
        Ok(view)
    }

    pub fn update(&self, id: &str, edit: &ProfileEdit) -> Result<ProfileView, StoreError> {
        validate(edit).map_err(StoreError::Invalid)?;
        let mut list = self.profiles.lock().unwrap();
        Self::check_name(&list, &edit.name, Some(id))?;
        let idx = list
            .iter()
            .position(|p| p.id == id)
            .ok_or(StoreError::NotFound)?;
        let mut p = list[idx].clone();
        p.apply_fields(edit);
        self.apply_secret(&mut p.psk_blob, &edit.psk)?;
        self.apply_secret(&mut p.password_blob, &edit.password)?;
        if p.auth == AuthMode::Psk {
            p.password_blob = None;
        }
        let view = p.view();
        list[idx] = p;
        self.persist(&list)?;
        Ok(view)
    }

    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let mut list = self.profiles.lock().unwrap();
        let before = list.len();
        list.retain(|p| p.id != id);
        if list.len() == before {
            return Err(StoreError::NotFound);
        }
        self.persist(&list)
    }

    /// Store (or replace) the saved password of a profile.
    pub fn set_password(&self, id: &str, password: &str) -> Result<(), StoreError> {
        let mut list = self.profiles.lock().unwrap();
        let idx = list
            .iter()
            .position(|p| p.id == id)
            .ok_or(StoreError::NotFound)?;
        let blob = self.protector.protect(password.as_bytes())?;
        list[idx].password_blob = Some(to_hex(&blob));
        self.persist(&list)
    }

    /// Decrypt the stored secrets of a profile. The PSK is mandatory; the
    /// password is returned if saved.
    pub fn load_secrets(&self, id: &str) -> Result<ProfileSecrets, StoreError> {
        let p = self.get(id).ok_or(StoreError::NotFound)?;
        let psk_blob = p
            .psk_blob
            .as_deref()
            .ok_or(StoreError::MissingSecret("pre-shared key"))?;
        let psk = self.unprotect_hex(psk_blob)?;
        let password = match p.password_blob.as_deref() {
            Some(b) => {
                let raw = self.unprotect_hex(b)?;
                let s = std::str::from_utf8(&raw).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "password is not UTF-8")
                })?;
                Some(Zeroizing::new(s.to_string()))
            }
            None => None,
        };
        Ok(ProfileSecrets { psk, password })
    }

    fn unprotect_hex(&self, blob: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let raw = from_hex(blob)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt secret blob"))?;
        Ok(self.protector.unprotect(&raw)?)
    }

    fn apply_secret(
        &self,
        slot: &mut Option<String>,
        upd: &SecretUpdate,
    ) -> Result<(), StoreError> {
        match upd {
            SecretUpdate::Keep => {}
            SecretUpdate::Clear => *slot = None,
            SecretUpdate::Set(s) if s.is_empty() => *slot = None,
            SecretUpdate::Set(s) => {
                let blob = self.protector.protect(s.expose().as_bytes())?;
                *slot = Some(to_hex(&blob));
            }
        }
        Ok(())
    }

    fn check_name(list: &[Profile], name: &str, except_id: Option<&str>) -> Result<(), StoreError> {
        let name = name.trim().to_lowercase();
        if list
            .iter()
            .any(|p| Some(p.id.as_str()) != except_id && p.name.to_lowercase() == name)
        {
            return Err(StoreError::NameTaken);
        }
        Ok(())
    }

    fn persist(&self, list: &[Profile]) -> Result<(), StoreError> {
        if let Some(path) = &self.path {
            let f = StoreFile {
                version: 1,
                profiles: list.to_vec(),
            };
            let body = serde_json::to_vec_pretty(&f).map_err(io::Error::from)?;
            atomic_write(path, &body)?;
        }
        Ok(())
    }
}

/// Write a file atomically: temp file in the same directory, then rename.
pub fn atomic_write(path: &Path, body: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    to_hex(&b)
}

pub(crate) fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::InsecureMockProtector;
    use ipc_proto::SecretString;

    fn edit(name: &str) -> ProfileEdit {
        ProfileEdit {
            name: name.into(),
            gateway: "vpn.example.com".into(),
            local_id: "laptop".into(),
            username: "alice".into(),
            psk: SecretUpdate::Set(SecretString::new("TopSecretPSK")),
            password: SecretUpdate::Set(SecretString::new("Hunter2Password")),
            ..Default::default()
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        std::env::temp_dir()
            .join(format!("ipsec-store-{tag}-{}", to_hex(&b)))
            .join("profiles.json")
    }

    #[test]
    fn crud_persists_and_hides_secrets() {
        let path = temp_path("crud");
        let prot = Arc::new(InsecureMockProtector);
        let store = ProfileStore::open(Some(path.clone()), prot.clone()).unwrap();
        let v = store.create(&edit("Office")).unwrap();
        assert!(v.has_psk && v.has_password);

        // Plaintext secrets must not appear in the file.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("TopSecretPSK") && !raw.contains("Hunter2Password"));

        // Reopen: still there, secrets decrypt.
        let store2 = ProfileStore::open(Some(path.clone()), prot).unwrap();
        assert_eq!(store2.list().len(), 1);
        let s = store2.load_secrets(&v.id).unwrap();
        assert_eq!(&*s.psk, b"TopSecretPSK");
        assert_eq!(
            s.password.as_deref().map(|p| p.as_str()),
            Some("Hunter2Password")
        );

        // Keep/Clear semantics.
        let mut e = edit("Office");
        e.psk = SecretUpdate::Keep;
        e.password = SecretUpdate::Clear;
        let v2 = store2.update(&v.id, &e).unwrap();
        assert!(v2.has_psk && !v2.has_password);

        store2.delete(&v.id).unwrap();
        assert!(store2.list().is_empty());
        assert!(matches!(store2.delete(&v.id), Err(StoreError::NotFound)));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn name_unique_case_insensitive() {
        let store = ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap();
        let a = store.create(&edit("Office")).unwrap();
        assert!(matches!(
            store.create(&edit("office")),
            Err(StoreError::NameTaken)
        ));
        // Renaming a profile to its own name is fine.
        assert!(store.update(&a.id, &edit("OFFICE")).is_ok());
    }

    #[test]
    fn invalid_rejected_and_missing_psk_reported() {
        let store = ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap();
        let mut bad = edit("X");
        bad.gateway = String::new();
        assert!(matches!(store.create(&bad), Err(StoreError::Invalid(_))));
        let mut nopsk = edit("Y");
        nopsk.psk = SecretUpdate::Keep;
        let v = store.create(&nopsk).unwrap();
        assert!(matches!(
            store.load_secrets(&v.id),
            Err(StoreError::MissingSecret(_))
        ));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(
            from_hex(&to_hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }
}
