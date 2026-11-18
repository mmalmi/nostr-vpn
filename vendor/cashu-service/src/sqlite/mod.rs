//! SQLite storage for CDK wallets and the simulation mint.
//!
//! The connection manager and executor come from cdk-sqlite 0.18.0 (MIT).
//! Keeping the adapter here lets packaged consumers use a patched bundled SQLite
//! while CDK's SQL implementation and migrations remain on their original release.

mod async_sqlite;
mod common;

/// CDK wallet database using the same schema as cdk-sqlite 0.18.0.
pub type WalletSqliteDatabase = cdk_sql_common::SQLWalletDatabase<common::SqliteConnectionManager>;

#[cfg(feature = "simulation")]
pub type MintSqliteDatabase = cdk_sql_common::SQLMintDatabase<common::SqliteConnectionManager>;
