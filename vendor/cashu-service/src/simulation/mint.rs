use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use cdk::mint::{Mint, MintBuilder, MintMeltLimits};
use cdk::nuts::{CurrencyUnit, Id, PaymentMethod};
use cdk_common::nut00::KnownMethod;
use cdk_sqlite::MintSqliteDatabase;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{IssuerMode, PaymentNetwork, SimMintPayment};

/// A genuine CDK mint with SQLite storage and an isolated loopback HTTP API.
pub struct LocalMint {
    id: String,
    mode: IssuerMode,
    url: String,
    database_path: PathBuf,
    mint: Arc<Mint>,
    payment: Arc<SimMintPayment>,
    server: JoinHandle<()>,
}

impl fmt::Debug for LocalMint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMint")
            .field("id", &self.id)
            .field("mode", &self.mode)
            .field("url", &self.url)
            .field("database_path", &self.database_path)
            .finish_non_exhaustive()
    }
}

impl LocalMint {
    pub async fn start(
        root: impl AsRef<Path>,
        network: PaymentNetwork,
        id: impl Into<String>,
        mode: IssuerMode,
    ) -> Result<Self> {
        let id = id.into();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to reserve loopback mint address")?;
        let address = listener
            .local_addr()
            .context("failed to read loopback mint address")?;
        let url = format!("http://{address}");

        let root = root.as_ref().join("mints");
        fs::create_dir_all(&root).context("failed to create simulated mint directory")?;
        let database_path = root.join(format!(
            "{}.sqlite",
            hex::encode(&network.derive_seed(&id)[..12])
        ));
        let database = Arc::new(
            MintSqliteDatabase::new(database_path.clone())
                .await
                .context("failed to open simulated mint SQLite database")?,
        );
        let payment = Arc::new(
            network
                .payment_backend(id.clone(), mode)
                .context("failed to register simulated mint payment backend")?,
        );

        let mut builder = MintBuilder::new(database.clone())
            .with_name(format!("simulation-{id}"))
            .with_description("isolated CDK simulation mint".to_string())
            .with_urls(vec![url.clone()]);
        builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(KnownMethod::Bolt11),
                MintMeltLimits::new(1, 21_000_000_000_000),
                payment.clone(),
            )
            .await
            .context("failed to configure simulated mint payment backend")?;
        let mint = Arc::new(
            builder
                .build_with_seed(database, &network.derive_seed(&id))
                .await
                .context("failed to build simulated CDK mint")?,
        );
        let router = cdk_axum::create_mint_router(mint.clone(), vec!["bolt11".to_string()])
            .await
            .context("failed to create simulated mint HTTP router")?;
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Ok(Self {
            id,
            mode,
            url,
            database_path,
            mint,
            payment,
            server,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn mode(&self) -> IssuerMode {
        self.mode
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn mint(&self) -> &Arc<Mint> {
        &self.mint
    }

    pub fn payment(&self) -> &Arc<SimMintPayment> {
        &self.payment
    }

    pub fn active_sat_keyset(&self) -> Option<Id> {
        self.mint
            .get_active_keysets()
            .get(&CurrencyUnit::Sat)
            .copied()
    }
}

impl Drop for LocalMint {
    fn drop(&mut self) {
        self.server.abort();
    }
}
