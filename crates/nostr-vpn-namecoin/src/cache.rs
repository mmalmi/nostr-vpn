//! TTL caching wrapper around any [`NamecoinResolver`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::alias::BitAlias;
use crate::resolver::{NamecoinError, NamecoinResolver};

#[derive(Clone)]
enum CachedOutcome {
    Hit(String),
    Miss(String),
}

struct Entry {
    outcome: CachedOutcome,
    expires_at: Instant,
}

/// Wraps an inner resolver with per-process TTL caching.
pub struct CachingResolver<R: NamecoinResolver> {
    inner: R,
    positive_ttl: Duration,
    negative_ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl<R: NamecoinResolver> CachingResolver<R> {
    pub fn new(inner: R, positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            inner,
            positive_ttl,
            negative_ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lookup(&self, key: &str) -> Option<CachedOutcome> {
        let mut guard = self.entries.lock().expect("cache lock poisoned");
        let now = Instant::now();
        if let Some(entry) = guard.get(key)
            && entry.expires_at > now
        {
            return Some(entry.outcome.clone());
        }
        // GC the stale entry if present.
        guard.remove(key);
        None
    }

    fn store(&self, key: String, outcome: CachedOutcome) {
        let ttl = match &outcome {
            CachedOutcome::Hit(_) => self.positive_ttl,
            CachedOutcome::Miss(_) => self.negative_ttl,
        };
        let mut guard = self.entries.lock().expect("cache lock poisoned");
        guard.insert(
            key,
            Entry {
                outcome,
                expires_at: Instant::now() + ttl,
            },
        );
    }
}

#[async_trait]
impl<R: NamecoinResolver> NamecoinResolver for CachingResolver<R> {
    async fn resolve_nostr_pubkey(&self, alias: &BitAlias) -> Result<String, NamecoinError> {
        let key = alias.to_string();
        if let Some(outcome) = self.lookup(&key) {
            return match outcome {
                CachedOutcome::Hit(hex) => Ok(hex),
                CachedOutcome::Miss(msg) => Err(NamecoinError::Generic(msg)),
            };
        }

        match self.inner.resolve_nostr_pubkey(alias).await {
            Ok(hex) => {
                self.store(key, CachedOutcome::Hit(hex.clone()));
                Ok(hex)
            }
            Err(error) => {
                // Cache only "stable" misses; treat transport errors as
                // transient and skip caching.
                let cacheable = matches!(
                    error,
                    NamecoinError::NotFound { .. }
                        | NamecoinError::NoNostrEntry { .. }
                        | NamecoinError::MalformedValue { .. }
                        | NamecoinError::Expired { .. }
                        | NamecoinError::InvalidPubkey { .. }
                );
                if cacheable {
                    self.store(key, CachedOutcome::Miss(error.to_string()));
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::parse_bit_alias;
    use crate::mock::MockResolver;
    use std::time::Duration;

    #[tokio::test]
    async fn positive_results_are_cached() {
        let mock = MockResolver::new();
        mock.insert("alice@example.bit", "a".repeat(64));
        let cached = CachingResolver::new(mock, Duration::from_secs(60), Duration::from_secs(10));
        let alias = parse_bit_alias("alice@example.bit").unwrap();

        let first = cached.resolve_nostr_pubkey(&alias).await.unwrap();
        let second = cached.resolve_nostr_pubkey(&alias).await.unwrap();
        assert_eq!(first, second);
    }
}
