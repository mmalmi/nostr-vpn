use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{normalize_runtime_network_id, write_private_file_preserving_user_owner};
use crate::fips_control::SignedRoster;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRosterStore {
    #[serde(default)]
    pub rosters: HashMap<String, SignedRoster>,
}

impl SignedRosterStore {
    pub fn latest_for(&self, network_id: &str) -> Option<&SignedRoster> {
        let key = normalize_runtime_network_id(network_id);
        self.rosters.get(&key)
    }

    pub fn upsert(&mut self, signed_roster: SignedRoster) -> Result<bool> {
        signed_roster.verify()?;
        let key = normalize_runtime_network_id(&signed_roster.network_id()?);
        if key.is_empty() {
            return Ok(false);
        }
        let incoming_hash = signed_roster.artifact_hash();
        let replace = match self.rosters.get(&key) {
            None => true,
            Some(existing) if existing.verify().is_err() => true,
            Some(existing) if existing.signed_at() < signed_roster.signed_at() => true,
            Some(existing) if existing.artifact_hash() == incoming_hash => return Ok(false),
            Some(_) => false,
        };
        if !replace {
            return Ok(false);
        }
        self.rosters.insert(key, signed_roster);
        Ok(true)
    }

    fn retain_valid(&mut self) {
        self.rosters.retain(|network_id, signed_roster| {
            signed_roster.network_id().is_ok_and(|signed_network_id| {
                normalize_runtime_network_id(network_id)
                    == normalize_runtime_network_id(&signed_network_id)
            }) && signed_roster.verify().is_ok()
        });
    }
}

pub fn signed_rosters_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("signed-rosters.json")
}

pub fn load_signed_rosters(path: &Path) -> Result<SignedRosterStore> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(SignedRosterStore::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read signed roster store {}", path.display()));
        }
    };

    let mut store = match serde_json::from_str::<SignedRosterStore>(&raw) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "discarding unreadable signed roster store {}: {error}",
                path.display()
            );
            return Ok(SignedRosterStore::default());
        }
    };
    store.retain_valid();
    Ok(store)
}

pub fn write_signed_rosters(path: &Path, store: &SignedRosterStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(store)
        .with_context(|| format!("failed to serialize signed roster store {}", path.display()))?;
    write_private_file_preserving_user_owner(path, raw.as_bytes())
        .with_context(|| format!("failed to write signed roster store {}", path.display()))
}

pub fn upsert_signed_roster(path: &Path, signed_roster: SignedRoster) -> Result<bool> {
    let mut store = load_signed_rosters(path)?;
    let changed = store.upsert(signed_roster)?;
    if changed {
        write_signed_rosters(path, &store)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fips_control::NetworkRoster;
    use nostr_sdk::prelude::Keys;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(label: &str) -> Self {
            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!(
                "nvpn-signed-rosters-{label}-{pid}-{now_nanos}-{seq}"
            ));
            fs::create_dir_all(&path).expect("create scratch dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn signed_roster(signed_at: u64) -> SignedRoster {
        let admin = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let roster = NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member],
            admins: vec![admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at,
        };
        SignedRoster::sign("mesh", roster, &admin).expect("sign roster")
    }

    #[test]
    fn upsert_keeps_newer_signed_roster() {
        let mut store = SignedRosterStore::default();
        let older = signed_roster(10);
        let newer = signed_roster(20);

        assert!(store.upsert(older.clone()).unwrap());
        assert!(store.upsert(newer.clone()).unwrap());
        assert!(!store.upsert(older).unwrap());

        assert_eq!(
            store.latest_for("mesh").unwrap().signed_at(),
            newer.signed_at()
        );
    }

    #[test]
    fn write_and_load_round_trip() {
        let dir = ScratchDir::new("round-trip");
        let path = dir.path().join("signed-rosters.json");
        let signed = signed_roster(10);
        let mut store = SignedRosterStore::default();
        store.upsert(signed.clone()).unwrap();

        write_signed_rosters(&path, &store).unwrap();
        let restored = load_signed_rosters(&path).unwrap();

        assert_eq!(
            restored.latest_for("mesh").unwrap().artifact_hash(),
            signed.artifact_hash()
        );
    }
}
