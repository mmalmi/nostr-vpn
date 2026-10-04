use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FipsDataPlaneCapability {
    pub endpoint_npub: String,
    pub network_scope: String,
    #[serde(default)]
    pub bridge_ok: bool,
}

impl FipsDataPlaneCapability {
    pub fn new(endpoint_npub: impl Into<String>, network_scope: impl Into<String>) -> Self {
        Self {
            endpoint_npub: endpoint_npub.into(),
            network_scope: network_scope.into(),
            bridge_ok: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "data_plane", rename_all = "snake_case")]
pub enum DataPlaneCapability {
    Fips { fips: FipsDataPlaneCapability },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshRoster {
    pub network_id: String,
    pub member_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    pub private_routes: Vec<String>,
    pub exit_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivatePacket {
    pub source_pubkey: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeerStatus {
    pub pubkey: String,
    pub connected: bool,
    pub endpoint_npub: String,
    pub transport_addr: Option<String>,
    pub transport_type: Option<String>,
    pub srtt_ms: Option<u64>,
    pub srtt_age_ms: Option<u64>,
    pub link_packets_sent: u64,
    pub link_packets_recv: u64,
    pub link_bytes_sent: u64,
    pub link_bytes_recv: u64,
    pub rekey_in_progress: bool,
    pub rekey_draining: bool,
    pub current_k_bit: Option<bool>,
    pub last_outbound_route: Option<String>,
    pub direct_probe_pending: bool,
    pub direct_probe_after_ms: Option<u64>,
    pub direct_probe_retry_count: u32,
    pub direct_probe_auto_reconnect: bool,
    pub direct_probe_expires_at_ms: Option<u64>,
    pub nostr_traversal_consecutive_failures: u32,
    pub nostr_traversal_in_cooldown: bool,
    pub nostr_traversal_cooldown_until_ms: Option<u64>,
    pub nostr_traversal_last_observed_skew_ms: Option<i64>,
    pub last_seen_at: Option<u64>,
    pub last_control_seen_at: Option<u64>,
    pub last_data_seen_at: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub error: Option<String>,
}

#[allow(
    clippy::double_must_use,
    reason = "async_trait adds must_use to generated Future-returning methods"
)]
#[async_trait]
pub trait PrivateMeshBackend: Send {
    async fn start(&mut self, roster: MeshRoster, routes: RoutePolicy) -> Result<()>;

    async fn send_private_packet(&self, packet: &[u8]) -> Result<()>;

    async fn recv_private_packet(&mut self) -> Result<Option<PrivatePacket>>;

    async fn peer_status(&self) -> Result<Vec<MeshPeerStatus>>;
}

#[cfg(test)]
mod tests {
    use super::{DataPlaneCapability, FipsDataPlaneCapability};

    #[test]
    fn fips_capability_advertises_endpoint_without_app_protocol() {
        let capability = FipsDataPlaneCapability::new("npub1example", "network-a");
        assert!(!capability.bridge_ok);

        let encoded = serde_json::to_value(DataPlaneCapability::Fips { fips: capability })
            .expect("capability should serialize");
        assert_eq!(encoded["data_plane"], "fips");
        assert_eq!(encoded["fips"]["endpoint_npub"], "npub1example");
        assert_eq!(encoded["fips"]["network_scope"], "network-a");
        assert!(encoded["fips"].get("protocol").is_none());
    }
}
