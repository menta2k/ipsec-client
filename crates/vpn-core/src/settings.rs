//! Machine-wide settings persisted next to the profiles (003 data-model.md):
//! `settings.json` = `{ "version": 1, "keep_tunnel_on_signout": false }`.

use crate::store::atomic_write;
use ipc_proto::Policy;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    #[serde(flatten)]
    policy: Policy,
}

pub struct SettingsStore {
    path: PathBuf,
    policy: Mutex<Policy>,
}

impl SettingsStore {
    /// Load the settings. A missing file gives the defaults; an unreadable or
    /// corrupt one also gives the defaults (the service must still start) and
    /// returns the problem so the caller can log it.
    pub fn open(path: PathBuf) -> (Self, Option<io::Error>) {
        let (policy, problem) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<File>(&bytes) {
                Ok(f) => (f.policy, None),
                Err(e) => (
                    Policy::default(),
                    Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}; using defaults", path.display()),
                    )),
                ),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Policy::default(), None),
            Err(e) => (Policy::default(), Some(e)),
        };
        let store = SettingsStore {
            path,
            policy: Mutex::new(policy),
        };
        (store, problem)
    }

    pub fn get(&self) -> Policy {
        *self.policy.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Persist atomically, then take effect.
    pub fn set(&self, policy: Policy) -> io::Result<()> {
        let mut cur = self.policy.lock().unwrap_or_else(|e| e.into_inner());
        let body =
            serde_json::to_vec_pretty(&File { version: 1, policy }).map_err(io::Error::other)?;
        atomic_write(&self.path, &body)?;
        *cur = policy;
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
