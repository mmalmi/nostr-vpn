use std::sync::Arc;

use anyhow::{Context as _, Result};
use nostr_vpn_core::config::ExitDnsResolverConfig;
use nostr_vpn_core::secure_dns::{
    SecureDnsError, SecureDnsLookup, SecureDnsResolver, WireGuardDnsResolver,
};

use super::{ResolverState, SharedResolver};

pub(super) fn dns_resolver(config: &ExitDnsResolverConfig) -> Result<SharedResolver> {
    match config {
        ExitDnsResolverConfig::Doh { .. } => Ok(Arc::new(
            SecureDnsResolver::from_resolver_config(config)
                .context("failed to initialize encrypted DNS")?,
        )),
        ExitDnsResolverConfig::ThroughExit { servers } => Ok(Arc::new(
            WireGuardDnsResolver::new(servers)
                .context("failed to initialize DNS through the selected exit")?,
        )),
        ExitDnsResolverConfig::FailClosed => Ok(Arc::new(FailClosedDnsResolver)),
    }
}

struct FailClosedDnsResolver;

#[async_trait::async_trait]
impl SecureDnsLookup for FailClosedDnsResolver {
    async fn resolve(&self, _query: &[u8]) -> Result<Vec<u8>, SecureDnsError> {
        Err(SecureDnsError::ExitNotReady)
    }
}

pub(super) fn current_resolver(resolver: &ResolverState) -> Option<SharedResolver> {
    resolver.read().ok().map(|resolver| Arc::clone(&*resolver))
}
