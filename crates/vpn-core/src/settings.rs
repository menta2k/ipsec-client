//! Machine-wide settings persisted next to the profiles (003 data-model.md):
//! `settings.json` = `{ "version": 1, "keep_tunnel_on_signout": false }`,
//! plus on macOS the optional `"access_group": "<name>"` (004 data-model.md),
//! which only the service's command line changes.

use crate::store::atomic_write;
use ipc_proto::Policy;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Default, Serialize, Deserialize)]
struct File {
    version: u32,
    #[serde(flatten)]
    policy: Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_group: Option<String>,
}

pub struct SettingsStore {
    path: PathBuf,
    state: Mutex<File>,
}

impl SettingsStore {
    /// Load the settings. A missing file gives the defaults; an unreadable or
    /// corrupt one also gives the defaults (the service must still start) and
    /// returns the problem so the caller can log it.
    pub fn open(path: PathBuf) -> (Self, Option<io::Error>) {
        let (state, problem) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<File>(&bytes) {
                Ok(f) => (f, None),
                Err(e) => (
                    File::default(),
                    Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}; using defaults", path.display()),
                    )),
                ),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (File::default(), None),
            Err(e) => (File::default(), Some(e)),
        };
        let store = SettingsStore {
            path,
            state: Mutex::new(state),
        };
        (store, problem)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, File> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self) -> Policy {
        self.lock().policy
    }

    /// Persist atomically, then take effect.
    pub fn set(&self, policy: Policy) -> io::Result<()> {
        self.update(|f| f.policy = policy)
    }

    /// The group allowed to control the VPN, if one was configured.
    pub fn access_group(&self) -> Option<String> {
        self.lock().access_group.clone()
    }

    /// Set (`Some`) or clear (`None`, back to the default) the access group.
    pub fn set_access_group(&self, group: Option<String>) -> io::Result<()> {
        self.update(|f| f.access_group = group)
    }

    /// Apply `change` to a copy, persist it, and only then make it current.
    fn update(&self, change: impl FnOnce(&mut File)) -> io::Result<()> {
        let mut cur = self.lock();
        let mut next = cur.clone();
        change(&mut next);
        next.version = 1;
        let body = serde_json::to_vec_pretty(&next).map_err(io::Error::other)?;
        atomic_write(&self.path, &body)?;
        *cur = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        let d =
            std::env::temp_dir().join(format!("ipsec-settings-{tag}-{}", crate::store::to_hex(&b)));
        std::fs::create_dir_all(&d).unwrap();
        d.join("settings.json")
    }

    #[test]
    fn missing_file_gives_defaults_without_problem() {
        let (s, problem) = SettingsStore::open(temp("missing"));
        assert!(problem.is_none());
        assert_eq!(s.get(), Policy::default());
    }

    #[test]
    fn set_persists_and_reopens() {
        let path = temp("rt");
        let (s, _) = SettingsStore::open(path.clone());
        let keep = Policy {
            keep_tunnel_on_signout: true,
        };
        s.set(keep).unwrap();
        assert_eq!(s.get(), keep);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"version\": 1"), "{raw}");
        assert!(raw.contains("\"keep_tunnel_on_signout\": true"), "{raw}");
        let (again, problem) = SettingsStore::open(path);
        assert!(problem.is_none());
        assert_eq!(again.get(), keep);
    }

    #[test]
    fn access_group_defaults_to_absent_and_round_trips() {
        let path = temp("group");
        let (s, _) = SettingsStore::open(path.clone());
        assert_eq!(s.access_group(), None);
        s.set_access_group(Some("vpn-users".into())).unwrap();
        // Changing the policy keeps the group, and the other way round.
        let keep = Policy {
            keep_tunnel_on_signout: true,
        };
        s.set(keep).unwrap();
        let (again, problem) = SettingsStore::open(path.clone());
        assert!(problem.is_none());
        assert_eq!(again.access_group().as_deref(), Some("vpn-users"));
        assert_eq!(again.get(), keep);
        again.set_access_group(None).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("access_group"), "{raw}");
        assert!(raw.contains("\"keep_tunnel_on_signout\": true"), "{raw}");
    }

    #[test]
    fn files_without_access_group_still_load() {
        let path = temp("old");
        std::fs::write(
            &path,
            br#"{ "version": 1, "keep_tunnel_on_signout": true }"#,
        )
        .unwrap();
        let (s, problem) = SettingsStore::open(path);
        assert!(problem.is_none());
        assert_eq!(s.access_group(), None);
        assert!(s.get().keep_tunnel_on_signout);
    }

    #[test]
    fn corrupt_file_gives_defaults_and_reports() {
        let path = temp("corrupt");
        std::fs::write(&path, b"{ not json").unwrap();
        let (s, problem) = SettingsStore::open(path);
        assert_eq!(s.get(), Policy::default());
        assert_eq!(problem.unwrap().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn failed_write_leaves_policy_unchanged() {
        let dir = temp("ro");
        // A directory where the file should be makes the write fail.
        std::fs::create_dir_all(&dir).unwrap();
        let (s, _) = SettingsStore::open(dir);
        assert!(s
            .set(Policy {
                keep_tunnel_on_signout: true
            })
            .is_err());
        assert_eq!(s.get(), Policy::default());
    }
}
