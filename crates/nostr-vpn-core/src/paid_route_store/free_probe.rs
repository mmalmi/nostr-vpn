use super::*;
use std::net::{IpAddr, Ipv6Addr};

const FREE_PROBE_WINDOW_SECS: u64 = 24 * 60 * 60;
const MAX_FREE_PROBE_SOURCES: usize = 256;
const MAX_FREE_PROBE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteFreeProbeSource {
    pub buyer_pubkey: String,
    pub lease_id: String,
    pub granted_at_unix: u64,
    pub granted_bytes: u64,
}

impl PaidRouteStore {
    pub(super) fn claim_seller_free_probe(
        &mut self,
        buyer_pubkey: &str,
        lease_id: &str,
        source_ip: Option<IpAddr>,
        config: &PaidExitConfig,
        now_unix: u64,
    ) -> Result<()> {
        let source = source_ip
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .ok_or_else(|| {
                anyhow!(
                    "free probe requires a direct authenticated source address; use a paid channel"
                )
            })?;
        let key = match source {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => ip.to_string(),
                None => {
                    let prefix = u128::from(ip) & (u128::MAX << 64);
                    format!("{}/64", Ipv6Addr::from(prefix))
                }
            },
        };
        self.seller_free_probe_sources.retain(|_, grant| {
            now_unix.saturating_sub(grant.granted_at_unix) < FREE_PROBE_WINDOW_SECS
        });
        if self.seller_free_probe_sources.contains_key(&key) {
            return Err(anyhow!(
                "free probe already granted to this source address in the last 24 hours; use a paid channel"
            ));
        }
        if self
            .seller_free_probe_sources
            .values()
            .any(|grant| grant.buyer_pubkey == buyer_pubkey)
        {
            return Err(anyhow!(
                "free probe already granted to this buyer in the last 24 hours; use a paid channel"
            ));
        }
        let granted_bytes = config
            .channel
            .free_probe_units
            .saturating_add(config.channel.grace_units);
        let allocated = self
            .seller_free_probe_sources
            .values()
            .fold(0_u64, |total, grant| {
                total.saturating_add(grant.granted_bytes)
            });
        if self.seller_free_probe_sources.len() >= MAX_FREE_PROBE_SOURCES
            || allocated.saturating_add(granted_bytes) > MAX_FREE_PROBE_BYTES
        {
            return Err(anyhow!(
                "seller daily free-probe budget exhausted; use a paid channel"
            ));
        }
        self.seller_free_probe_sources.insert(
            key,
            PaidRouteFreeProbeSource {
                buyer_pubkey: buyer_pubkey.to_string(),
                lease_id: lease_id.to_string(),
                granted_at_unix: now_unix,
                granted_bytes,
            },
        );
        Ok(())
    }
}
