//! In-memory resolver used by tests and offline tooling.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::alias::BitAlias;
use crate::resolver::{NamecoinError, NamecoinResolver};

/// Toy resolver that returns canned results.
///
/// Inserts use the canonical alias display form (e.g. `alice@example.bit`
/// or `example.bit`).
#[derive(Default)]
pub struct MockResolver {
    entries: Mutex<HashMap<String, String>>,
}

impl MockResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-register an alias → hex pubkey mapping.
    pub fn insert(&self, alias: impl Into<String>, hex_pubkey: impl Into<String>) {
        let mut guard = self.entries.lock().expect("mock entries lock poisoned");
        guard.insert(alias.into(), hex_pubkey.into());
    }
}

#[async_trait]
impl NamecoinResolver for MockResolver {
    async fn resolve_nostr_pubkey(&self, alias: &BitAlias) -> Result<String, NamecoinError> {
        let key = alias.to_string();
        let guard = self.entries.lock().expect("mock entries lock poisoned");
        guard
            .get(&key)
            .cloned()
            .ok_or_else(|| NamecoinError::NoNostrEntry {
                name: alias.parent().to_string(),
                local: alias.local().to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::parse_bit_alias;

    #[tokio::test]
    async fn returns_inserted_pubkey() {
        let resolver = MockResolver::new();
        resolver.insert("alice@example.bit", "a".repeat(64));
        let alias = parse_bit_alias("alice@example.bit").unwrap();
        let hex = resolver.resolve_nostr_pubkey(&alias).await.unwrap();
        assert_eq!(hex, "a".repeat(64));
    }

    #[tokio::test]
    async fn missing_alias_returns_not_found() {
        let resolver = MockResolver::new();
        let alias = parse_bit_alias("alice@example.bit").unwrap();
        let err = resolver.resolve_nostr_pubkey(&alias).await.unwrap_err();
        assert!(matches!(err, NamecoinError::NoNostrEntry { .. }));
    }
}
