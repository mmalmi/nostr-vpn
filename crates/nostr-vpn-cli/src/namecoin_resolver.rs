//! CLI-side helpers for hooking the Namecoin resolver into pubkey parsing.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use nostr_vpn_core::config::{AppConfig, ResolvedParticipant, resolve_participant_string};
#[cfg(test)]
use nostr_vpn_namecoin::MockResolver;
use nostr_vpn_namecoin::{
    CachingResolver, ElectrumXResolver, NamecoinError, NamecoinResolver, ResolverConfig,
    electrumx::parse_servers,
};

/// A boxed, dynamically-dispatched resolver handle so the CLI can plumb
/// either a real ElectrumX resolver or a `MockResolver` (tests) through
/// the same code paths.
#[derive(Clone)]
pub(crate) struct ResolverHandle {
    inner: Arc<dyn NamecoinResolver>,
}

impl ResolverHandle {
    pub(crate) fn new<R: NamecoinResolver + 'static>(resolver: R) -> Self {
        Self {
            inner: Arc::new(resolver),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_mock(mock: MockResolver) -> Self {
        Self::new(mock)
    }

    /// Build a resolver from the provided application config. Returns
    /// `Ok(None)` when the user has disabled Namecoin lookups so callers
    /// can still detect bare `.bit` inputs and emit a clean error.
    pub(crate) fn from_config(config: &AppConfig) -> Result<Option<Self>> {
        if !config.namecoin.enabled {
            return Ok(None);
        }
        let servers = parse_servers(&config.namecoin.electrumx_servers)?;
        if servers.is_empty() {
            return Ok(None);
        }
        let resolver_config = ResolverConfig {
            timeout: Duration::from_secs(config.namecoin.resolution_timeout_secs.max(1)),
            cache_ttl_positive: Duration::from_secs(config.namecoin.cache_ttl_secs.max(1)),
            cache_ttl_negative: Duration::from_secs(30),
        };
        let inner = ElectrumXResolver::new(servers, resolver_config.clone());
        let cached = CachingResolver::new(
            inner,
            resolver_config.cache_ttl_positive,
            resolver_config.cache_ttl_negative,
        );
        Ok(Some(Self::new(cached)))
    }
}

#[async_trait]
impl NamecoinResolver for ResolverHandle {
    async fn resolve_nostr_pubkey(
        &self,
        alias: &nostr_vpn_namecoin::BitAlias,
    ) -> Result<String, NamecoinError> {
        self.inner.resolve_nostr_pubkey(alias).await
    }
}

/// Convenience wrapper that runs `resolve_participant_string` with the
/// CLI-side resolver handle (if any).
pub(crate) async fn resolve_with_handle(
    value: &str,
    handle: Option<&ResolverHandle>,
) -> Result<ResolvedParticipant> {
    resolve_participant_string(value, handle).await
}
