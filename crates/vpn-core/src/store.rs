//! Persistent, machine-wide profile store with protector-encrypted secrets.

use crate::profile::{validate, FieldError, Profile};
use crate::traits::SecretProtector;
use ipc_proto::{AuthMode, ProfileEdit, ProfileView, SecretUpdate, SignInProfile};
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
            sign_in: false,
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

    /// Make a profile available (or not) at the sign-in screen (003). The
    /// caller is responsible for the administrator check.
    pub fn set_sign_in(&self, id: &str, enabled: bool) -> Result<ProfileView, StoreError> {
        let mut list = self.profiles.lock().unwrap();
        let p = list
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(StoreError::NotFound)?;
        p.sign_in = enabled;
        let view = p.view();
        self.persist(&list)?;
        Ok(view)
    }

    /// Profiles offered at the sign-in screen, in their minimal form.
    pub fn sign_in_profiles(&self) -> Vec<SignInProfile> {
        self.profiles
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.sign_in)
            .map(Profile::sign_in_view)
            .collect()
    }

    /// Unattended deployment (003): update the profile with the same name
    /// (case-insensitive) or create it, then set its sign-in availability.
    pub fn import(&self, edit: &ProfileEdit, sign_in: bool) -> Result<ProfileView, StoreError> {
        let existing = self
            .profiles
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(edit.name.trim()))
            .map(|p| p.id.clone());
        let view = match existing {
            Some(id) => self.update(&id, edit)?,
            None => self.create(edit)?,
        };
        self.set_sign_in(&view.id, sign_in)
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
    /// password is returned if saved. A secret that can no longer be
    /// decrypted (lost or replaced machine key, corrupt blob) counts as not
    /// saved, so the user is asked for it again instead of the connect failing
    /// (002 FR-014).
    pub fn load_secrets(&self, id: &str) -> Result<ProfileSecrets, StoreError> {
        let p = self.get(id).ok_or(StoreError::NotFound)?;
        let psk = p
            .psk_blob
            .as_deref()
            .and_then(|b| self.unprotect_or_warn(&p.name, "pre-shared key", b))
            .ok_or(StoreError::MissingSecret("pre-shared key"))?;
        let password = match p.password_blob.as_deref() {
            Some(b) => {
                let Some(raw) = self.unprotect_or_warn(&p.name, "password", b) else {
                    return Ok(ProfileSecrets {
                        psk,
                        password: None,
                    });
                };
                let s = std::str::from_utf8(&raw).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "password is not UTF-8")
                })?;
                Some(Zeroizing::new(s.to_string()))
            }
            None => None,
        };
        Ok(ProfileSecrets { psk, password })
    }

    fn unprotect_or_warn(
        &self,
        profile: &str,
        what: &str,
        blob: &str,
    ) -> Option<Zeroizing<Vec<u8>>> {
        match self.unprotect_hex(blob) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    profile,
                    error = %e,
                    "saved {what} cannot be decrypted; treating it as not saved"
                );
                None
            }
        }
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
    use ipc_proto::{SecretString, SignInProfile};

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

    /// Opens blobs like the mock protector, but refuses those whose plaintext
    /// starts with `refuse` (simulating a lost or replaced machine key).
    struct PickyProtector {
        refuse: &'static str,
    }

    impl SecretProtector for PickyProtector {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            InsecureMockProtector.protect(plain)
        }
        fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            let plain = InsecureMockProtector.unprotect(blob)?;
            if plain.starts_with(self.refuse.as_bytes()) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad key"));
            }
            Ok(plain)
        }
    }

    #[test]
    fn unreadable_secrets_count_as_not_saved() {
        // FR-014 (002): profiles still load; an undecryptable password is
        // simply absent, and an undecryptable PSK is reported as missing.
        let path = temp_path("unreadable");
        let store =
            ProfileStore::open(Some(path.clone()), Arc::new(InsecureMockProtector)).unwrap();
        let id = store.create(&edit("Office")).unwrap().id;

        let pw_lost = ProfileStore::open(
            Some(path.clone()),
            Arc::new(PickyProtector { refuse: "Hunter2" }),
        )
        .unwrap();
        assert_eq!(pw_lost.list().len(), 1);
        let s = pw_lost.load_secrets(&id).unwrap();
        assert_eq!(&s.psk[..], b"TopSecretPSK");
        assert!(s.password.is_none());

        let psk_lost = ProfileStore::open(
            Some(path),
            Arc::new(PickyProtector {
                refuse: "TopSecret",
            }),
        )
        .unwrap();
        assert!(matches!(
            psk_lost.load_secrets(&id),
            Err(StoreError::MissingSecret(_))
        ));
    }

    #[test]
    fn sign_in_flag_defaults_off_for_001_files() {
        let path = temp_path("signin001");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"version":1,"profiles":[{"id":"p1","name":"Old","gateway":"g","port":500,
               "local_id":"l","id_type":"fqdn","dh_group":"modp2048","auth":"psk"}]}"#,
        )
        .unwrap();
        let store = ProfileStore::open(Some(path), Arc::new(InsecureMockProtector)).unwrap();
        assert!(!store.list()[0].sign_in);
        assert!(store.sign_in_profiles().is_empty());
    }

    #[test]
    fn sign_in_flag_persists_survives_edits_and_lists_minimal_view() {
        let path = temp_path("signin");
        let prot = Arc::new(InsecureMockProtector);
        let store = ProfileStore::open(Some(path.clone()), prot.clone()).unwrap();
        let office = store.create(&edit("Office")).unwrap();
        store.create(&edit("Home")).unwrap();

        let v = store.set_sign_in(&office.id, true).unwrap();
        assert!(v.sign_in);
        assert!(matches!(
            store.set_sign_in("nope", true),
            Err(StoreError::NotFound)
        ));

        // A normal edit (rename) keeps the flag.
        let mut renamed = edit("Office HQ");
        renamed.psk = SecretUpdate::Keep;
        renamed.password = SecretUpdate::Keep;
        assert!(store.update(&office.id, &renamed).unwrap().sign_in);

        let reopened = ProfileStore::open(Some(path), prot).unwrap();
        assert_eq!(
            reopened.sign_in_profiles(),
            vec![SignInProfile {
                id: office.id.clone(),
                name: "Office HQ".into(),
                auth: AuthMode::Eap,
                username: "alice".into(),
            }]
        );

        reopened.delete(&office.id).unwrap();
        assert!(reopened.sign_in_profiles().is_empty());
    }

    #[test]
    fn import_creates_or_updates_by_name_and_sets_the_flag() {
        let store = ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap();
        let created = store.import(&edit("Office"), true).unwrap();
        assert!(created.sign_in);
        assert_eq!(store.list().len(), 1);

        let mut again = edit("office");
        again.gateway = "vpn2.example.com".into();
        let updated = store.import(&again, false).unwrap();
        assert_eq!(updated.id, created.id, "matched case-insensitively");
        assert_eq!(updated.gateway, "vpn2.example.com");
        assert!(!updated.sign_in);
        assert_eq!(store.list().len(), 1);

        let mut bad = edit("Broken");
        bad.gateway = String::new();
        assert!(matches!(
            store.import(&bad, true),
            Err(StoreError::Invalid(_))
        ));
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
