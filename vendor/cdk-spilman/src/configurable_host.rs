//! Configurable SpilmanHost
//!
//! A generic, YAML-configurable implementation of [`SpilmanHost`] that tracks
//! usage via named **usage variables** — monotonically increasing integer
//! counters (e.g. `"requests"`, `"bytes"`, `"chars"`).
//!
//! The amount due for a channel is computed as a **linear combination**:
//!
//! ```text
//! amount_due = ceil(sum_over_var(accumulated[var] * price_per_unit[var]) / pricing_scale)
//! ```
//!
//! `pricing_scale` (default 1) lets you define prices with sub-unit precision.
//! For example, `pricing_scale: 1000` with `bytes: 1` means 0.001 sat per byte.
//!
//! The context JSON passed to [`SpilmanHost::get_amount_due`] and
//! [`SpilmanHost::record_payment`] contains the increments for each variable,
//! using the same keys:
//!
//! ```json
//! { "requests": 1, "bytes": 4096 }
//! ```
//!
//! # Example YAML configuration
//!
//! ```yaml
//! mints:
//!   "http://localhost:3338": [sat, msat, usd]
//! min_expiry_seconds: 3600
//!
//! # Optional: defaults to in-memory if omitted.
//! # storage:
//! #   type: sqlite
//! #   path: "./spilman.db"
//!
//! # Optional scaling divisor (default 1).
//! # pricing_scale: 1000
//!
//! pricing:
//!   sat:
//!     min_capacity: 10
//!     variables:
//!       chars: 1
//!       requests: 5
//!   msat:
//!     min_capacity: 10000
//!     variables:
//!       chars: 1000
//!       requests: 5000
//!   usd:
//!     min_capacity: 10
//!     max_amount_per_output: 64
//!     variables:
//!       chars: 1
//!       requests: 5
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    ChannelFunding, ChannelId, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanHost,
};
use cashu::nuts::{CurrencyUnit, Id, PublicKey, SecretKey};

// ============================================================================
// Configuration types
// ============================================================================

/// Per-unit pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitPricingConfig {
    /// Minimum channel capacity required for this unit.
    pub min_capacity: u64,

    /// Optional maximum amount per blinded output (for testing maximum_amount policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_output: Option<u64>,

    /// Mapping from usage variable name to price-per-unit.
    ///
    /// For example: `{ "chars": 1, "requests": 5 }` means 1 sat per char
    /// and 5 sat per request.
    pub variables: HashMap<String, u64>,
}

/// Storage backend configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StorageConfig {
    /// In-memory storage (default). All data lost on restart.
    #[default]
    #[serde(rename = "memory")]
    Memory,

    /// SQLite file-backed storage. Persists across restarts.
    #[serde(rename = "sqlite")]
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
    },
}

/// Top-level YAML configuration for [`ConfigurableHost`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurableHostConfig {
    /// Trusted mints, mapping each mint URL to the set of units trusted at
    /// that mint (e.g. `{ "http://localhost:3338": ["sat", "msat"] }`).
    pub mints: HashMap<String, Vec<String>>,

    /// Minimum channel expiry in seconds.
    #[serde(default = "default_min_expiry")]
    pub min_expiry_seconds: u64,

    /// Scaling divisor for the pricing linear combination.
    ///
    /// The amount due is `ceil(raw_total / pricing_scale)`.  Defaults to 1
    /// (no scaling).  Use a larger value to express sub-unit prices —
    /// e.g. `pricing_scale: 1000` with `bytes: 1` means 0.001 sat per byte.
    #[serde(default = "default_pricing_scale")]
    pub pricing_scale: u64,

    /// Storage backend. Defaults to in-memory if omitted.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Per-unit pricing. Keys are unit names (`"sat"`, `"msat"`, `"usd"`, …).
    pub pricing: HashMap<String, UnitPricingConfig>,
}

fn default_min_expiry() -> u64 {
    3600
}

fn default_pricing_scale() -> u64 {
    1
}

impl ConfigurableHostConfig {
    /// Parse a [`ConfigurableHostConfig`] from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))
    }
}

// ============================================================================
// Storage trait & types
// ============================================================================

/// Per-channel accumulated usage: `variable_name -> value`.
pub type UsageMap = HashMap<String, u64>;

/// Cached mint keyset metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetCacheEntry {
    /// Serialized `KeysetInfo` JSON for this cached mint keyset.
    pub info_json: String,
    /// Whether the mint reports this keyset as active.
    pub active: bool,
    /// Currency unit associated with the keyset.
    pub unit: CurrencyUnit,
}

/// Storage backend for [`ConfigurableHost`].
///
/// All methods are synchronous. Implementations must be thread-safe
/// (`Send + Sync`). The default implementation is [`MemoryStorage`];
/// [`SqliteStorage`] provides persistence across restarts.
pub trait SpilmanStorage: Send + Sync {
    // -- channel funding ------------------------------------------------------

    /// Get the stored funding data for a channel.
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Save funding data for a new channel.  Must be idempotent: if the
    /// channel already has funding, this call is a no-op.
    fn save_funding(&self, channel_id: &str, funding: ChannelFunding) -> Result<(), String>;

    // -- balance & payments ---------------------------------------------------

    /// Get the current balance for a channel.  Returns `None` if no payment
    /// has been recorded yet.
    fn get_balance(&self, channel_id: &str) -> Option<PaymentProof>;

    /// Update the balance for a channel.  Must be monotonic: only update if
    /// the new balance is strictly greater than the current one (or if no
    /// balance has been set yet).  Returns `Ok(())` even if the balance was
    /// not updated (monotonic no-op).
    fn update_balance(&self, channel_id: &str, payment: PaymentProof) -> Result<(), String>;

    // -- usage variables ------------------------------------------------------

    /// Get the accumulated usage for a channel.
    fn get_usage(&self, channel_id: &str) -> Option<UsageMap>;

    /// Increment usage variables for a channel.
    fn increment_usage(&self, channel_id: &str, increments: &UsageMap) -> Result<(), String>;

    // -- channel state --------------------------------------------------------

    /// Get the current state (Open, Closing, Closed).
    fn get_state(&self, channel_id: &str) -> ChannelState;

    /// Mark a channel as closing.  Returns `Err` if the channel does not
    /// exist or is already closed.
    fn mark_closing(&self, channel_id: &str, closing: ClosingData) -> Result<(), String>;

    /// Get the data for a closing channel.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;

    /// Mark a channel as closed.  Returns `Err` if already closed.
    fn mark_closed(&self, channel_id: &str, data: ClosedDataView) -> Result<(), String>;

    /// Get the data for a closed channel.
    fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView>;

    // -- keyset cache ---------------------------------------------------------

    /// Get a keyset from the cache.
    fn get_keyset(&self, mint: &str, keyset_id: &Id) -> Option<KeysetCacheEntry>;

    /// Insert or update a keyset in the cache.
    fn set_keyset(&self, mint: &str, keyset_id: Id, entry: KeysetCacheEntry) -> Result<(), String>;

    /// Get all active keyset IDs for a given mint and unit.
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;

    /// Returns `{ mint_url: { unit: [keyset_id, …] } }` for all active keysets.
    fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>>;

    /// Returns the set of units that have at least one active keyset.
    fn get_active_units(&self) -> std::collections::HashSet<String>;
}

mod storage;
pub use storage::{MemoryStorage, SqliteStorage};

// ============================================================================
// ConfigurableHost
// ============================================================================

/// A generic, YAML-configurable [`SpilmanHost`] implementation.
///
/// Tracks usage via named usage variables and computes pricing as a linear
/// combination.  Pluggable storage: [`MemoryStorage`] (default) or
/// [`SqliteStorage`] for persistence.
///
/// `Clone` is cheap (storage is behind `Arc`), which allows passing the host
/// by value to [`SpilmanBridge::new`] while sharing state with route handlers.
///
/// Construct via [`ConfigurableHost::new`] or [`ConfigurableHost::from_yaml`].
#[derive(Clone)]
pub struct ConfigurableHost {
    config: ConfigurableHostConfig,
    server_pubkey: PublicKey,
    server_secret_hex: String,
    storage: Arc<dyn SpilmanStorage>,
}

impl std::fmt::Debug for ConfigurableHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigurableHost")
            .field("config", &self.config)
            .field("server_pubkey", &self.server_pubkey)
            .finish_non_exhaustive()
    }
}

impl ConfigurableHost {
    /// Create a new host from an already-parsed config and a hex-encoded
    /// secret key.  The storage backend is determined by `config.storage`:
    /// - `StorageConfig::Memory` (default) — in-memory, lost on restart
    /// - `StorageConfig::Sqlite { path }` — SQLite file, persistent
    pub fn new(config: ConfigurableHostConfig, secret_key_hex: &str) -> Result<Self, String> {
        let storage: Arc<dyn SpilmanStorage> = match &config.storage {
            StorageConfig::Memory => Arc::new(MemoryStorage::new()),
            StorageConfig::Sqlite { path } => Arc::new(SqliteStorage::open(path)?),
        };
        Self::with_storage(config, secret_key_hex, storage)
    }

    /// Create a new host with an explicit storage backend, ignoring
    /// `config.storage`.  Useful for testing or custom backends.
    pub fn with_storage(
        config: ConfigurableHostConfig,
        secret_key_hex: &str,
        storage: Arc<dyn SpilmanStorage>,
    ) -> Result<Self, String> {
        let secret_key =
            SecretKey::from_hex(secret_key_hex).map_err(|e| format!("invalid secret key: {e}"))?;
        let server_pubkey = secret_key.public_key();

        // Validate: every unit trusted by at least one mint must have pricing.
        let trusted_units: std::collections::HashSet<&str> = config
            .mints
            .values()
            .flat_map(|units| units.iter().map(String::as_str))
            .collect();
        let priced_units: std::collections::HashSet<&str> =
            config.pricing.keys().map(String::as_str).collect();

        let mut missing: Vec<&str> = trusted_units.difference(&priced_units).copied().collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(format!(
                "units trusted by at least one mint but missing from pricing: {missing:?}"
            ));
        }

        // Warn: pricing entries that no mint trusts are dead config.
        let mut unused: Vec<&str> = priced_units.difference(&trusted_units).copied().collect();
        if !unused.is_empty() {
            unused.sort();
            tracing::warn!("pricing defined for units not trusted by any mint: {unused:?}");
        }

        Ok(Self {
            config,
            server_pubkey,
            server_secret_hex: secret_key_hex.to_string(),
            storage,
        })
    }

    /// Parse YAML and construct the host.
    pub fn from_yaml(yaml: &str, secret_key_hex: &str) -> Result<Self, String> {
        let config = ConfigurableHostConfig::from_yaml(yaml)?;
        Self::new(config, secret_key_hex)
    }

    // -- public accessors -----------------------------------------------------

    /// The server's public key.
    pub fn server_pubkey(&self) -> &PublicKey {
        &self.server_pubkey
    }

    /// The parsed configuration.
    pub fn config(&self) -> &ConfigurableHostConfig {
        &self.config
    }

    /// The pricing scale divisor (always >= 1).
    pub fn pricing_scale(&self) -> u64 {
        self.config.pricing_scale.max(1)
    }

    /// The trusted mints and their accepted units.
    pub fn mints(&self) -> &HashMap<String, Vec<String>> {
        &self.config.mints
    }

    /// Access the underlying storage backend.
    pub fn storage(&self) -> &dyn SpilmanStorage {
        &*self.storage
    }

    // -- keyset management (called by the server at startup / on refresh) -----

    /// Insert or update a keyset in the cache.
    pub fn set_keyset(
        &self,
        mint: &str,
        keyset_id: Id,
        entry: KeysetCacheEntry,
    ) -> Result<(), String> {
        self.storage.set_keyset(mint, keyset_id, entry)
    }

    /// Returns `{ mint: { unit: [keyset_id, …] } }` for active keysets.
    pub fn get_mints_units_keysets(&self) -> HashMap<String, HashMap<String, Vec<String>>> {
        self.storage.get_mints_units_keysets()
    }

    /// Returns the set of units that have at least one active keyset.
    pub fn get_active_units(&self) -> std::collections::HashSet<String> {
        self.storage.get_active_units()
    }

    // -- channel data accessors (for route handlers) --------------------------

    /// Get fully persisted funding data for a channel (for status endpoints,
    /// etc.). An interrupted initial save remains hidden until retry repairs
    /// its missing signed balance.
    pub fn get_funding_data(&self, channel_id: &str) -> Option<ChannelFunding> {
        let funding = self.storage.get_funding(channel_id)?;
        self.storage.get_balance(channel_id)?;
        Some(funding)
    }

    /// Get the current balance for a channel.
    pub fn get_balance(&self, channel_id: &str) -> Option<PaymentProof> {
        self.storage.get_balance(channel_id)
    }

    /// Get the accumulated usage for a channel.
    pub fn get_usage(&self, channel_id: &str) -> Option<UsageMap> {
        self.storage.get_usage(channel_id)
    }

    /// Check whether a channel is closed.
    pub fn is_closed(&self, channel_id: &str) -> bool {
        self.storage.get_closed_data(channel_id).is_some()
    }

    /// Get the closed channel data (for idempotent close responses).
    pub fn get_closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.storage.get_closed_data(channel_id)
    }

    // -- pricing helpers ------------------------------------------------------

    /// Get the unit for a channel from its stored params.
    fn channel_unit(&self, channel_id: &str) -> Option<String> {
        let funding = self.storage.get_funding(channel_id)?;
        let params: serde_json::Value = serde_json::from_str(&funding.params_json).ok()?;
        params.get("unit")?.as_str().map(String::from)
    }

    /// Compute the amount due for a channel given accumulated usage + pending
    /// increments from context.
    fn compute_amount_due(&self, channel_id: &str, context_json: Option<&String>) -> u64 {
        let unit = self.channel_unit(channel_id).unwrap_or_default();
        let unit_pricing = match self.config.pricing.get(&unit) {
            Some(p) => p,
            None => return 0,
        };

        // Get accumulated usage.
        let accumulated = self.storage.get_usage(channel_id).unwrap_or_default();

        // Parse pending increments from context.
        let pending: HashMap<String, u64> = context_json
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        // Linear combination over all priced variables.
        let mut total: u64 = 0;
        for (var_name, &price) in &unit_pricing.variables {
            let acc = accumulated.get(var_name).copied().unwrap_or(0);
            let pend = pending.get(var_name).copied().unwrap_or(0);
            total = total.saturating_add((acc + pend).saturating_mul(price));
        }

        // Apply pricing scale: ceil(total / scale).
        let scale = self.pricing_scale();
        total.div_ceil(scale)
    }

    /// Apply usage increments from context to the accumulated store.
    fn apply_usage_increments(&self, channel_id: &str, context_json: &str) -> Result<(), String> {
        let increments: HashMap<String, u64> = match serde_json::from_str(context_json) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        self.storage.increment_usage(channel_id, &increments)
    }

    /// Returns pricing filtered to only units with active keysets.
    pub fn get_active_pricing(&self) -> HashMap<String, &UnitPricingConfig> {
        let active_units = self.storage.get_active_units();
        self.config
            .pricing
            .iter()
            .filter(|(unit, _)| active_units.contains(*unit))
            .map(|(unit, cfg)| (unit.clone(), cfg))
            .collect()
    }
}

#[cfg(feature = "configurable-host-reqwest")]
impl ConfigurableHost {
    /// Fetch and cache keysets from every configured mint.
    ///
    /// Iterates over [`mints()`](Self::mints) and calls
    /// [`fetch_and_cache_keysets`](super::configurable_networking::fetch_and_cache_keysets)
    /// for each one.  Errors from individual mints are logged and collected;
    /// the method returns `Ok(())` if at least one mint succeeded, or `Err`
    /// with all failures if every mint failed.
    pub async fn initialize_keysets(&self) -> Result<(), String> {
        use super::configurable_networking::fetch_and_cache_keysets;

        let mint_urls: Vec<String> = self.mints().keys().cloned().collect();
        let mut errors = Vec::new();

        for mint_url in &mint_urls {
            match fetch_and_cache_keysets(self, mint_url).await {
                Ok(()) => {
                    tracing::info!("Cached keysets from {mint_url}");
                }
                Err(e) => {
                    tracing::error!("Failed to fetch keysets from {mint_url}: {e}");
                    errors.push(format!("{mint_url}: {e}"));
                }
            }
        }

        if errors.len() == mint_urls.len() && !mint_urls.is_empty() {
            Err(format!(
                "Failed to fetch keysets from all mints: {}",
                errors.join("; ")
            ))
        } else {
            Ok(())
        }
    }
}

/// Public view of closed channel data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedDataView {
    /// Expiry timestamp for the channel commitment.
    pub expiry_timestamp: u64,
    /// Final balance that was closed out of the channel.
    pub closed_amount: u64,
    /// Total value remaining after stage 1 fee handling.
    pub value_after_stage1: u64,
    /// Sum of proofs paid to the receiver.
    pub receiver_sum: u64,
    /// Sum of proofs returned to the sender.
    pub sender_sum: u64,
    /// Serialized receiver proofs JSON from the completed close.
    pub receiver_proofs_json: String,
    /// Serialized sender proofs JSON from the completed close.
    pub sender_proofs_json: String,
}

// ============================================================================
// SpilmanHost implementation
// ============================================================================

impl SpilmanHost for ConfigurableHost {
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        receiver_pubkey == &self.server_pubkey
    }

    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        let trusted_units = match self.config.mints.get(mint) {
            Some(units) => units,
            None => return false,
        };
        match self.storage.get_keyset(mint, keyset_id) {
            Some(entry) => {
                entry.active && trusted_units.iter().any(|u| u == &entry.unit.to_string())
            }
            None => false,
        }
    }

    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        self.get_funding_data(channel_id)
    }

    /// `save_funding` is called once per channel, when it first receives the
    /// funding token from the client.  The guards inside are defensive against
    /// concurrent first-payment races for the same channel.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.save_funding(channel_id, funding)?;
        self.storage.update_balance(channel_id, initial_payment)
    }

    fn get_amount_due(&self, channel_id: &str, context: Option<&String>) -> u64 {
        self.compute_amount_due(channel_id, context)
    }

    /// This is called where the server has decided to accept the payment, i.e.
    /// the balance is sufficient to cover the usage. This both keeps a copy
    /// of the payment, and it also updates the usage records for this channel
    /// so that the server keeps track of how much service has been provided on
    /// this channel.
    fn record_payment(
        &self,
        channel_id: &str,
        payment: PaymentProof,
        context: &String,
    ) -> Result<(), String> {
        self.storage.update_balance(channel_id, payment)?;
        self.apply_usage_increments(channel_id, context)
    }

    fn get_channel_state(&self, channel_id: &str) -> ChannelState {
        self.storage.get_state(channel_id)
    }

    fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.mark_closing(
            channel_id,
            ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            },
        )
    }

    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData> {
        self.storage.get_closing_data(channel_id)
    }

    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
        let cfg = self.config.pricing.get(unit)?;
        Some(ChannelPolicy {
            min_expiry_in_seconds: self.config.min_expiry_seconds,
            min_capacity: cfg.min_capacity,
            max_amount_per_output: cfg.max_amount_per_output,
        })
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs()
    }

    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        self.storage.get_balance(channel_id)
    }

    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.storage.get_active_keyset_ids(mint, unit)
    }

    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        self.storage
            .get_keyset(mint, keyset_id)
            .map(|e| e.info_json)
    }

    fn compute_channel_secret(
        &self,
        _receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        super::compute_channel_secret_from_hex(&self.server_secret_hex, sender_pubkey_hex)
    }

    fn sign_with_tweaked_key(
        &self,
        _signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        super::sign_with_tweaked_key_util(&self.server_secret_hex, message_hex, tweak_scalar_hex)
    }

    fn mark_channel_closed(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String> {
        self.storage.mark_closed(
            channel_id,
            ClosedDataView {
                expiry_timestamp,
                closed_amount: balance,
                value_after_stage1: receiver_sum + sender_sum,
                receiver_sum,
                sender_sum,
                receiver_proofs_json: receiver_proofs_json.to_string(),
                sender_proofs_json: sender_proofs_json.to_string(),
            },
        )
    }
}

#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod persistence_tests;
#[cfg(test)]
mod sqlite_tests;
#[cfg(test)]
mod test_support;
