//! Resolver trait and supporting types.

use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

use crate::alias::BitAlias;

/// Public error type returned by resolvers.
#[derive(Debug, Error)]
pub enum NamecoinError {
    #[error("namecoin: {0}")]
    Generic(String),
    #[error("namecoin: connection to {server} failed: {source}")]
    Transport {
        server: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("namecoin: name '{name}' not found")]
    NotFound { name: String },
    #[error("namecoin: name '{name}' has no `nostr.names` entry for '{local}'")]
    NoNostrEntry { name: String, local: String },
    #[error("namecoin: malformed value for '{name}': {reason}")]
    MalformedValue { name: String, reason: String },
    #[error("namecoin: expired record for '{name}'")]
    Expired { name: String },
    #[error("namecoin: import loop or unsupported depth resolving '{name}'")]
    ImportLimit { name: String },
    #[error("namecoin: invalid pubkey '{value}' for '{name}': {reason}")]
    InvalidPubkey {
        name: String,
        value: String,
        reason: String,
    },
}

/// Configuration shared by all built-in resolvers.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub timeout: Duration,
    pub cache_ttl_positive: Duration,
    pub cache_ttl_negative: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            cache_ttl_positive: Duration::from_secs(300),
            cache_ttl_negative: Duration::from_secs(30),
        }
    }
}

/// Resolver abstraction. Implementations are responsible for whatever
/// transport they need (`ElectrumX`, local namecoind RPC, mock, ...).
#[async_trait]
pub trait NamecoinResolver: Send + Sync {
    /// Resolve `alias` to a 32-byte hex Nostr pubkey (lowercase, 64 chars).
    async fn resolve_nostr_pubkey(&self, alias: &BitAlias) -> Result<String, NamecoinError>;
}

/// Validate that `value` is a 32-byte hex string. Returns the lowercased
/// canonical form on success.
pub(crate) fn validate_hex_pubkey(name: &str, value: &str) -> Result<String, NamecoinError> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NamecoinError::InvalidPubkey {
            name: name.to_string(),
            value: trimmed.to_string(),
            reason: "expected 64-char lowercase hex Nostr pubkey".to_string(),
        });
    }
    Ok(trimmed.to_ascii_lowercase())
}
