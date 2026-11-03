//! A consistent SQLite snapshot includes proofs, operation recovery and service journals.
//! The application must encrypt the returned bytes and keep the seed in secure storage.
use super::*;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;

const MAX_DATABASE_BYTES: usize = 32 * 1024 * 1024;
const RESTORE_MARKER: &str = "restore.pending";
const RESTORE_TEMP: &str = "restore.sqlite.new";
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn private_file(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("Could not create private wallet recovery file")
}
fn validate_database(bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() >= 100
            && bytes.len() <= MAX_DATABASE_BYTES
            && bytes.starts_with(b"SQLite format 3\0"),
        "Invalid or oversized wallet database backup"
    );
    Ok(())
}
impl CashuWalletService {
    /// No mint requests or proof export: VACUUM INTO takes a consistent database
    /// snapshot while the service's money-operation authority is held.
    pub async fn export_wallet_database(&self) -> Result<Vec<u8>> {
        let _guard = self.lock_operation().await;
        let source = cashu_wallet_db_path(self.data_dir());
        let destination =
            cashu_wallet_dir(self.data_dir()).join(format!("export-{}.sqlite", Uuid::new_v4()));
        let temporary = Temporary(destination.clone());
        private_file(&destination)?;
        let database = rusqlite::Connection::open_with_flags(
            &source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        database.busy_timeout(std::time::Duration::from_secs(5))?;
        database.execute(
            "VACUUM INTO ?1",
            [destination
                .to_str()
                .context("Invalid wallet backup destination")?],
        )?;
        anyhow::ensure!(
            fs::metadata(&destination)?.len() <= MAX_DATABASE_BYTES as u64,
            "Wallet backup exceeds its size limit"
        );
        let bytes = fs::read(&destination)?;
        validate_database(&bytes)?;
        drop(temporary);
        Ok(bytes)
    }
}
/// Install only into an absent wallet, under its normal cross-process writer
/// lock. The platform must save and verify the imported secure seed first.
/// A crash can resume only the same authenticated backup; it cannot overwrite
/// an existing wallet or replace an active profile's funds.
pub fn restore_wallet_database(data_dir: &Path, bytes: &[u8]) -> Result<()> {
    validate_database(bytes)?;
    let directory = cashu_wallet_dir(data_dir);
    fs::create_dir_all(&directory)?;
    let _lock = super::persistence::acquire_wallet_writer_lock(data_dir)?;
    let marker = directory.join(RESTORE_MARKER);
    let temporary = directory.join(RESTORE_TEMP);
    let destination = cashu_wallet_db_path(data_dir);
    let digest = hex::encode(Sha256::digest(bytes));
    if marker.exists() {
        anyhow::ensure!(
            fs::read_to_string(&marker)? == digest,
            "A different wallet restore is pending"
        );
        if destination.exists() {
            anyhow::ensure!(
                fs::metadata(&destination)?.len() <= MAX_DATABASE_BYTES as u64
                    && fs::read(&destination)? == bytes,
                "Existing wallet funds were preserved"
            );
            require_review_flag(data_dir)?;
            fs::remove_file(&marker)?;
            return Ok(());
        }
    } else {
        anyhow::ensure!(
            !cashu_wallet_database_exists(data_dir),
            "Restore needs a new wallet; existing funds were preserved"
        );
        let mut file = private_file(&marker)?;
        file.write_all(digest.as_bytes())?;
        file.sync_all()?;
    }
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = private_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let database = rusqlite::Connection::open_with_flags(
        &temporary,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let valid: String = database.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    anyhow::ensure!(valid == "ok", "Wallet backup failed database validation");
    drop(database);
    fs::rename(&temporary, &destination)?;
    fs::File::open(&directory)?.sync_all()?;
    require_review_flag(data_dir)?;
    fs::remove_file(&marker)?;
    fs::File::open(&directory)?.sync_all()?;
    Ok(())
}
pub(super) fn restore_pending(data_dir: &Path) -> bool {
    cashu_wallet_dir(data_dir).join(RESTORE_MARKER).exists()
}

const REVIEW_REQUIRED: &str = "restored-review-required";
fn require_review_flag(data_dir: &Path) -> Result<()> {
    let path = cashu_wallet_dir(data_dir).join(REVIEW_REQUIRED);
    if !path.exists() {
        let mut file = private_file(&path)?;
        file.write_all(b"refresh-before-spending")?;
        file.sync_all()?;
    }
    Ok(())
}
impl CashuWalletService {
    pub(super) fn require_restored_review(&self) -> Result<()> {
        anyhow::ensure!(
            !cashu_wallet_dir(self.data_dir())
                .join(REVIEW_REQUIRED)
                .exists(),
            "Refresh the restored wallet before spending; stop using the original copy"
        );
        Ok(())
    }
    pub fn restored_review_required(&self) -> bool {
        cashu_wallet_dir(self.data_dir())
            .join(REVIEW_REQUIRED)
            .exists()
    }
    pub async fn review_restored_wallet(&self) -> Result<()> {
        use cdk::nuts::ProofsMethods;
        let _guard = self.lock_operation().await;
        if !self.restored_review_required() {
            return Ok(());
        }
        for wallet in self.repository().get_wallets().await {
            let proofs = wallet
                .get_proofs_with(Some(vec![State::Unspent]), None)
                .await?;
            anyhow::ensure!(
                proofs.len() <= 8192,
                "Restored wallet has too many proofs for one review"
            );
            for chunk in proofs.chunks(256) {
                let requested = chunk.to_vec();
                let expected: std::collections::HashSet<_> = requested.ys()?.into_iter().collect();
                let states = wallet.check_proofs_spent(requested).await?;
                let actual: std::collections::HashSet<_> =
                    states.iter().map(|state| state.y).collect();
                anyhow::ensure!(
                    states.len() == chunk.len()
                        && expected == actual
                        && states
                            .iter()
                            .all(|state| matches!(state.state, State::Unspent | State::Spent)),
                    "The mint did not return a complete restored-proof review"
                );
            }
        }
        fs::remove_file(cashu_wallet_dir(self.data_dir()).join(REVIEW_REQUIRED))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn snapshot_preserves_journal_and_restore_never_overwrites_wallet() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let service = CashuWalletService::open_file_backed(source.path())
            .await
            .unwrap();
        service
            .localstore()
            .kv_write("test", "journal", "pending", b"durable-operation")
            .await
            .unwrap();
        let snapshot = service.export_wallet_database().await.unwrap();
        let seed = FileCashuWalletSeedStore::for_data_dir(source.path())
            .load_seed()
            .unwrap()
            .unwrap();
        fs::create_dir_all(cashu_wallet_dir(target.path())).unwrap();
        FileCashuWalletSeedStore::for_data_dir(target.path())
            .store_seed(&seed)
            .unwrap();
        restore_wallet_database(target.path(), &snapshot).unwrap();
        assert!(restore_wallet_database(target.path(), &snapshot).is_err());
        let restored = CashuWalletService::open_file_backed(target.path())
            .await
            .unwrap();
        assert!(restored.restored_review_required());
        assert!(restored.require_restored_review().is_err());
        assert_eq!(
            restored
                .localstore()
                .kv_read("test", "journal", "pending")
                .await
                .unwrap()
                .unwrap(),
            b"durable-operation"
        );
        restored.review_restored_wallet().await.unwrap();
        assert!(!restored.restored_review_required());
        assert!(restore_wallet_database(source.path(), &snapshot).is_err());
    }
    #[test]
    fn malformed_database_is_rejected_before_creating_a_wallet() {
        let target = tempfile::tempdir().unwrap();
        assert!(restore_wallet_database(target.path(), b"not sqlite").is_err());
        assert!(!cashu_wallet_database_exists(target.path()));
    }
}
