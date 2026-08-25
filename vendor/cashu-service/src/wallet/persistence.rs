use anyhow::{bail, Context, Result};
use fs2::FileExt;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use super::{
    cashu_wallet_db_path, cashu_wallet_dir, cashu_wallet_seed_path, read_wallet_seed,
    write_wallet_seed,
};

const WAL_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Storage for the exact 64-byte seed used by CDK.
///
/// Platform applications should implement this with Keychain, Keystore, or an
/// equivalent non-interactive secret store. An unavailable store must return
/// an error, not `None`; `None` means that no seed has ever been stored.
pub trait CashuWalletSeedStore: Send + Sync {
    fn load_seed(&self) -> Result<Option<[u8; 64]>>;
    fn store_seed(&self, seed: &[u8; 64]) -> Result<()>;
}

/// The legacy file-backed store used by command-line and server deployments.
/// Mobile applications should use a platform-secure implementation instead.
#[derive(Debug, Clone)]
pub struct FileCashuWalletSeedStore {
    path: PathBuf,
}

impl FileCashuWalletSeedStore {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn for_data_dir(data_dir: &Path) -> Self {
        Self::new(cashu_wallet_seed_path(data_dir))
    }
}

impl CashuWalletSeedStore for FileCashuWalletSeedStore {
    fn load_seed(&self) -> Result<Option<[u8; 64]>> {
        if !self.path.exists() {
            return Ok(None);
        }
        read_wallet_seed(&self.path).map(Some)
    }

    fn store_seed(&self, seed: &[u8; 64]) -> Result<()> {
        if self.path.exists() {
            let existing = read_wallet_seed(&self.path)?;
            if existing != *seed {
                bail!(
                    "refusing to replace the existing Cashu wallet seed at {}",
                    self.path.display()
                );
            }
            return Ok(());
        }
        write_wallet_seed(&self.path, seed)
    }
}

pub(crate) fn acquire_wallet_writer_lock(data_dir: &Path) -> Result<File> {
    let lock_path = cashu_wallet_dir(data_dir).join("wallet.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open Cashu wallet lock {}", lock_path.display()))?;
    FileExt::try_lock_exclusive(&lock).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::anyhow!(
                "the Cashu wallet at {} is already in use by another process",
                cashu_wallet_dir(data_dir).display()
            )
        } else {
            anyhow::anyhow!(error).context(format!(
                "failed to lock Cashu wallet {}",
                cashu_wallet_dir(data_dir).display()
            ))
        }
    })?;
    Ok(lock)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedWalletSeed {
    pub(crate) seed: [u8; 64],
    pub(crate) remove_legacy_after_database_open: bool,
}

/// Resolve one wallet seed without ever generating over an existing database.
///
/// When `migrate_legacy_seed` is true, `cashu/seed.json` is treated as a
/// migration source. It remains in place until the caller successfully opens
/// the CDK database and calls [`finalize_legacy_seed_migration`].
pub(crate) fn resolve_wallet_seed(
    data_dir: &Path,
    store: &dyn CashuWalletSeedStore,
    migrate_legacy_seed: bool,
) -> Result<ResolvedWalletSeed> {
    let stored = store
        .load_seed()
        .context("failed to load the Cashu wallet seed from secure storage")?;
    let legacy_path = cashu_wallet_seed_path(data_dir);
    let legacy = if migrate_legacy_seed && legacy_path.exists() {
        Some(
            read_wallet_seed(&legacy_path)
                .context("failed to read the legacy Cashu wallet seed")?,
        )
    } else {
        None
    };

    match (stored, legacy) {
        (Some(stored), Some(legacy)) => {
            if stored != legacy {
                bail!(
                    "the Cashu wallet seed in secure storage does not match {}",
                    legacy_path.display()
                );
            }
            Ok(ResolvedWalletSeed {
                seed: stored,
                remove_legacy_after_database_open: true,
            })
        }
        (Some(stored), None) => Ok(ResolvedWalletSeed {
            seed: stored,
            remove_legacy_after_database_open: false,
        }),
        (None, Some(legacy)) => {
            store
                .store_seed(&legacy)
                .context("failed to migrate the Cashu wallet seed into secure storage")?;
            let verified = store
                .load_seed()
                .context("failed to verify the migrated Cashu wallet seed")?;
            if verified != Some(legacy) {
                bail!("secure storage did not preserve the wallet seed exactly");
            }
            Ok(ResolvedWalletSeed {
                seed: legacy,
                remove_legacy_after_database_open: true,
            })
        }
        (None, None) => {
            if cashu_wallet_database_exists(data_dir) {
                bail!(
                    "the Cashu wallet database exists at {} but its seed is missing from secure storage",
                    cashu_wallet_db_path(data_dir).display()
                );
            }

            let mut seed = [0_u8; 64];
            rand::thread_rng().fill_bytes(&mut seed);
            store
                .store_seed(&seed)
                .context("failed to store a new Cashu wallet seed")?;
            let verified = store
                .load_seed()
                .context("failed to verify the new Cashu wallet seed")?;
            if verified != Some(seed) {
                bail!("secure storage did not preserve the wallet seed exactly");
            }
            Ok(ResolvedWalletSeed {
                seed,
                remove_legacy_after_database_open: false,
            })
        }
    }
}

pub(crate) fn finalize_legacy_seed_migration(
    data_dir: &Path,
    resolved: ResolvedWalletSeed,
) -> Result<()> {
    if !resolved.remove_legacy_after_database_open {
        return Ok(());
    }

    let legacy_path = cashu_wallet_seed_path(data_dir);
    match fs::remove_file(&legacy_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove migrated Cashu wallet seed {}",
                legacy_path.display()
            )
        }),
    }
}

#[must_use]
pub fn cashu_wallet_database_files(data_dir: &Path) -> Vec<PathBuf> {
    let database = cashu_wallet_db_path(data_dir);
    let mut files = Vec::with_capacity(1 + WAL_SIDECARS.len());
    files.push(database.clone());
    files.extend(
        WAL_SIDECARS
            .iter()
            .map(|suffix| PathBuf::from(format!("{}{}", database.display(), suffix))),
    );
    files
}

#[must_use]
pub fn cashu_wallet_database_exists(data_dir: &Path) -> bool {
    cashu_wallet_database_files(data_dir)
        .iter()
        .any(|path| path.exists())
}

/// Move a wallet database and every SQLite sidecar into a recovery directory.
///
/// This is an explicit recovery operation: normal startup never deletes or
/// silently recreates an unreadable wallet. The entire WAL family is moved
/// while holding the same cross-process lock used by [`CashuWalletService`].
/// If a move fails, already-moved files are rolled back before returning.
pub fn preserve_cashu_wallet_database(data_dir: &Path) -> Result<Option<PathBuf>> {
    fs::create_dir_all(cashu_wallet_dir(data_dir))
        .context("failed to create the Cashu wallet directory")?;
    let _writer_lock = acquire_wallet_writer_lock(data_dir)?;
    let existing: Vec<PathBuf> = cashu_wallet_database_files(data_dir)
        .into_iter()
        .filter(|path| path.exists())
        .collect();
    if existing.is_empty() {
        return Ok(None);
    }

    let recovery_dir = cashu_wallet_dir(data_dir)
        .join("recovery")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&recovery_dir).with_context(|| {
        format!(
            "failed to create Cashu wallet recovery directory {}",
            recovery_dir.display()
        )
    })?;

    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(existing.len());
    for source in existing {
        let file_name = source
            .file_name()
            .context("Cashu wallet database path has no file name")?;
        let destination = recovery_dir.join(file_name);
        if let Err(move_error) = fs::rename(&source, &destination) {
            let mut rollback_errors = Vec::new();
            for (rollback_source, rollback_destination) in moved.iter().rev() {
                if let Err(error) = fs::rename(rollback_destination, rollback_source) {
                    rollback_errors.push(format!("{}: {error}", rollback_source.display()));
                }
            }
            let _ = fs::remove_dir(&recovery_dir);
            if rollback_errors.is_empty() {
                return Err(move_error).with_context(|| {
                    format!(
                        "failed to preserve Cashu wallet database file {}",
                        source.display()
                    )
                });
            }
            bail!(
                "failed to preserve Cashu wallet database file {}: {}; rollback also failed for {}",
                source.display(),
                move_error,
                rollback_errors.join(", ")
            );
        }
        moved.push((source, destination));
    }

    Ok(Some(recovery_dir))
}
