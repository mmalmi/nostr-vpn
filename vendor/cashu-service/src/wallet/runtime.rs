use anyhow::{Context, Result};
use cdk::wallet::{WalletRepository, WalletRepositoryBuilder};
use cdk_sqlite::WalletSqliteDatabase;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

use super::persistence::{
    acquire_wallet_writer_lock, finalize_legacy_seed_migration, resolve_wallet_seed,
};
use super::{
    cashu_wallet_db_path, cashu_wallet_dir, CashuWalletSeedStore, FileCashuWalletSeedStore,
};

/// One process-wide owner for a CDK SQLite wallet.
///
/// The service holds an exclusive cross-process lock for its lifetime and a
/// Tokio mutex for money-moving operations. Consumers that want a different
/// database or ownership model can use CDK directly without this type.
pub struct CashuWalletService {
    data_dir: PathBuf,
    repository: WalletRepository,
    #[cfg(feature = "spilman-wallet-http")]
    pub(crate) http_client: reqwest::Client,
    localstore: Arc<WalletSqliteDatabase>,
    operation_lock: Mutex<()>,
    _writer_lock: File,
}

impl std::fmt::Debug for CashuWalletService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CashuWalletService")
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CashuWalletStartupRecoveryReport {
    pub wallets: usize,
    pub finalized_melts: usize,
    pub recovered_sagas: usize,
    pub compensated_sagas: usize,
    pub pending_sagas: usize,
    pub failed_sagas: usize,
    pub minted_amount: u64,
    pub warnings: Vec<String>,
}

impl CashuWalletService {
    /// Open a wallet backed by a caller-provided secure seed store.
    ///
    /// A verified `cashu/seed.json` is migrated into the store and removed only
    /// after CDK successfully opens the existing SQLite database.
    pub async fn open_with_seed_store(
        data_dir: impl AsRef<Path>,
        seed_store: Arc<dyn CashuWalletSeedStore>,
    ) -> Result<Self> {
        Self::open(data_dir.as_ref(), seed_store.as_ref(), true, None).await
    }

    /// Open a wallet whose mint requests use an explicit control-network proxy.
    /// The proxy is runtime-only and is never saved with wallet data.
    #[cfg(feature = "wallet-proxy")]
    pub async fn open_with_seed_store_and_proxy(
        data_dir: impl AsRef<Path>,
        seed_store: Arc<dyn CashuWalletSeedStore>,
        proxy: url::Url,
    ) -> Result<Self> {
        Self::open(data_dir.as_ref(), seed_store.as_ref(), true, Some(proxy)).await
    }

    /// Open the legacy file-backed deployment profile.
    ///
    /// This is intended for CLI/server environments. Mobile callers should use
    /// [`Self::open_with_seed_store`] with Keychain or Keystore.
    pub async fn open_file_backed(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        let seed_store = FileCashuWalletSeedStore::for_data_dir(data_dir);
        Self::open(data_dir, &seed_store, false, None).await
    }

    async fn open(
        data_dir: &Path,
        seed_store: &dyn CashuWalletSeedStore,
        migrate_legacy_seed: bool,
        proxy: Option<url::Url>,
    ) -> Result<Self> {
        fs::create_dir_all(cashu_wallet_dir(data_dir))
            .context("failed to create the Cashu wallet directory")?;
        let writer_lock = acquire_wallet_writer_lock(data_dir)?;
        anyhow::ensure!(
            !super::database_backup::restore_pending(data_dir),
            "A wallet restore is pending; resume it with the same encrypted backup"
        );
        let resolved = resolve_wallet_seed(data_dir, seed_store, migrate_legacy_seed)?;
        let localstore = Arc::new(
            WalletSqliteDatabase::new(cashu_wallet_db_path(data_dir))
                .await
                .context("failed to open Cashu wallet database")?,
        );
        #[cfg(feature = "spilman-wallet-http")]
        let http_client = match proxy.as_ref() {
            Some(proxy) => reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(proxy.as_str())?)
                .build()
                .context("failed to initialize mint control networking")?,
            None => reqwest::Client::new(),
        };
        let mut builder = WalletRepositoryBuilder::new()
            .localstore(localstore.clone())
            .seed(resolved.seed)
            // Leave headroom for direct channel settlement/refund requests.
            .with_rate_limiting_config(
                cdk::wallet::RateLimitConfig::try_new(5, 15).expect("nonzero mint budget"),
            );
        if let Some(proxy) = proxy {
            builder = builder.proxy_url(proxy);
        }
        let repository = builder
            .build()
            .await
            .context("failed to build Cashu wallet repository")?;

        finalize_legacy_seed_migration(data_dir, resolved)?;

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            repository,
            #[cfg(feature = "spilman-wallet-http")]
            http_client,
            localstore,
            operation_lock: Mutex::new(()),
            _writer_lock: writer_lock,
        })
    }

    /// Recover durable CDK operations after startup while keeping the service
    /// usable if individual mints are offline.
    pub async fn recover_startup_state(&self) -> CashuWalletStartupRecoveryReport {
        let _guard = self.lock_operation().await;
        let wallets = self.repository.get_wallets().await;
        let mut report = CashuWalletStartupRecoveryReport {
            wallets: wallets.len(),
            ..CashuWalletStartupRecoveryReport::default()
        };

        for wallet in wallets {
            match self.refresh_pending_wallet(&wallet).await {
                Ok(recovery) => {
                    report.finalized_melts += recovery.finalized_melts;
                    report.recovered_sagas += recovery.recovered_sagas;
                    report.compensated_sagas += recovery.compensated_sagas;
                    report.pending_sagas += recovery.pending_sagas;
                    report.failed_sagas += recovery.failed_sagas;
                    report.minted_amount += recovery.minted_amount;
                    report.warnings.extend(recovery.warnings);
                }
                Err(error) => report
                    .warnings
                    .push(format!("Failed to recover Cashu wallet: {error:#}")),
            }
        }

        report
    }

    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Start an operation with fresh HTTP connections after the caller may
    /// have changed its Internet route. Keep the wallet owner, database and
    /// durable operations; only recreate CDK's in-memory wallet clients.
    pub async fn refresh_network_connections(&self) -> Result<()> {
        let _guard = self.lock_operation().await;
        for wallet in self.repository.get_wallets().await {
            self.repository
                .create_wallet(wallet.mint_url.clone(), wallet.unit.clone(), None)
                .await
                .context("failed to refresh Cashu mint connections")?;
        }
        Ok(())
    }

    pub(crate) fn repository(&self) -> &WalletRepository {
        &self.repository
    }

    pub(super) fn localstore(&self) -> &Arc<WalletSqliteDatabase> {
        &self.localstore
    }

    pub(super) async fn lock_operation(&self) -> MutexGuard<'_, ()> {
        self.operation_lock.lock().await
    }
}

#[cfg(test)]
#[path = "runtime_network_tests.rs"]
mod network_tests;
