use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, anyhow, ensure};
use nostr_sdk::Event;

use super::{UpdateEventCache, UpdateRef, fs};

/// Merge before writing: concurrent or delayed checks must never lower the
/// signed watermark. Provider-only callers retain the same rule in process.
pub(super) fn update_watermark(
    reference: &UpdateRef,
    config_path: Option<&Path>,
    incoming: Option<Event>,
) -> Result<UpdateEventCache> {
    let Some(config_path) = config_path else {
        static ROOTS: OnceLock<Mutex<HashMap<String, UpdateEventCache>>> = OnceLock::new();
        let mut roots = ROOTS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| anyhow!("update watermark lock poisoned"))?;
        let cache = roots
            .entry(reference.resolver_key())
            .or_insert(UpdateEventCache::new(reference)?);
        if let Some(event) = incoming {
            cache.ingest_event(event)?;
        }
        return Ok(cache.clone());
    };
    let path = crate::control_pubsub::control_pubsub_store_path(config_path)
        .with_file_name("update-announcement.json");
    let _lock = incoming
        .as_ref()
        .map(|_| lock_watermark(&path))
        .transpose()?;
    let mut cache = UpdateEventCache::new(reference)?;
    match fs::read(&path) {
        Ok(bytes) => {
            cache.ingest_event(serde_json::from_slice(&bytes)?)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(event) = incoming {
        cache.ingest_event(event)?;
        if let Some(latest) = cache.latest() {
            crate::config::write_private_file_preserving_user_owner(
                &path,
                &serde_json::to_vec(latest.as_event())?,
            )
            .context("failed to save update announcement watermark")?;
        }
    }
    Ok(cache)
}

fn lock_watermark(path: &Path) -> Result<File> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(path.with_extension("lock"))?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file(),
        "update watermark lock must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.nlink() == 1,
            "update watermark lock must have one link"
        );
        let parent_owner = fs::metadata(parent)
            .ok()
            .map(|meta| (meta.uid(), meta.gid()));
        if let Some((uid, gid)) = crate::config::preferred_private_file_owner(
            Some((metadata.uid(), metadata.gid())),
            parent_owner,
        ) && (uid, gid) != (metadata.uid(), metadata.gid())
        {
            std::os::unix::fs::fchown(&lock, Some(uid), Some(gid))?;
        }
        lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    lock.try_lock()
        .map_err(|error| anyhow!("another update check is saving its announcement: {error}"))?;
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::super::{ProductUpdateMode, secure_selection_with_pubsub};
    use super::*;
    use nostr_pubsub::{EventBus, EventSource, InMemoryEventBus, VerifiedEvent};
    use nostr_sdk::{EventBuilder, Keys, Kind, Tag, TagKind, Timestamp, ToBech32};
    use std::sync::Arc;
    use std::time::Duration;

    async fn check_announcement(
        reference: &UpdateRef,
        config_path: Option<&Path>,
        event: Event,
        source: EventSource,
    ) {
        let provider = Arc::new(InMemoryEventBus::default());
        let check = secure_selection_with_pubsub(
            "9999.0.0",
            ProductUpdateMode::Cli,
            provider.clone(),
            reference.clone(),
            config_path,
        );
        let delivery = async {
            tokio::time::sleep(Duration::from_millis(25)).await;
            provider
                .publish(
                    VerifiedEvent::try_from(event).expect("verified announcement"),
                    source,
                )
                .await
                .expect("deliver announcement");
        };
        let (result, ()) = tokio::join!(check, delivery);
        let error = match result {
            Ok(_) => panic!("an old or local-only announcement cannot confirm an update check"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("inconclusive"),
            "unexpected failure: {error}"
        );
    }

    #[tokio::test]
    async fn independently_built_checks_keep_newest_root_after_inconclusive_check() {
        let directory =
            std::env::temp_dir().join(format!("nvpn-watermark-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("cache directory");
        let path = directory.join("config.toml");
        // A configured updater reloads from disk. Provider-only callers share
        // an in-process watermark even when every call builds a new resolver.
        for config_path in [Some(path.as_path()), None] {
            let keys = Keys::generate();
            let reference = UpdateRef {
                npub: keys.public_key().to_bech32().expect("publisher"),
                tree_name: "releases/watermark-test".to_string(),
                path: None,
            };
            let root = |timestamp| {
                EventBuilder::new(Kind::Custom(30_064), "")
                    .tags([
                        Tag::identifier(&reference.tree_name),
                        Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
                        Tag::custom(TagKind::Custom("hash".into()), ["ab".repeat(32)]),
                    ])
                    .custom_created_at(Timestamp::from_secs(timestamp))
                    .sign_with_keys(&keys)
                    .expect("signed announcement")
            };
            let newest = root(2);
            let older = root(1);
            check_announcement(
                &reference,
                config_path,
                newest.clone(),
                EventSource::local_index("local"),
            )
            .await;
            assert_eq!(
                update_watermark(&reference, config_path, None)
                    .expect("persisted watermark")
                    .latest()
                    .expect("newest event")
                    .as_event()
                    .id,
                newest.id
            );
            check_announcement(
                &reference,
                config_path,
                older.clone(),
                EventSource::peer("peer"),
            )
            .await;
            let merged = update_watermark(&reference, config_path, Some(older))
                .expect("merge delayed writer");
            assert_eq!(
                merged.latest().expect("newest event").as_event().id,
                newest.id
            );
        }
        std::fs::remove_dir_all(directory).expect("remove test cache");
    }
}
