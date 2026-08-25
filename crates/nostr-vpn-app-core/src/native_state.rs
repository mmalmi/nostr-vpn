use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[allow(clippy::struct_excessive_bools)]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeParticipantState {
    pub npub: String,
    pub pubkey_hex: String,
    pub alias: String,
    pub magic_dns_alias: String,
    pub magic_dns_name: String,
    pub tunnel_ip: String,
    pub is_admin: bool,
    pub roster_accepted: bool,
    pub reachable: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub advertised_routes: Vec<String>,
    pub offers_exit_node: bool,
    pub fips_endpoint_npub: String,
    pub fips_endpoint_hints: Vec<String>,
    pub fips_transport_addr: String,
    pub fips_transport_type: String,
    pub fips_srtt_ms: u64,
    pub fips_srtt_age_ms: u64,
    pub fips_packets_sent: u64,
    pub fips_packets_recv: u64,
    pub fips_bytes_sent: u64,
    pub fips_bytes_recv: u64,
    pub fips_direct_probe_pending: bool,
    pub fips_direct_probe_after_ms: u64,
    pub fips_direct_probe_retry_count: u32,
    pub fips_direct_probe_auto_reconnect: bool,
    pub fips_direct_probe_expires_at_ms: u64,
    pub state: String,
    pub mesh_state: String,
    pub status_text: String,
    pub last_fips_control_seen_text: String,
    pub last_fips_data_seen_text: String,
    pub last_seen_text: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeOutboundJoinRequestState {
    pub recipient_npub: String,
    pub recipient_pubkey_hex: String,
    pub requested_at_text: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeInboundJoinRequestState {
    pub requester_npub: String,
    pub requester_pubkey_hex: String,
    pub requester_node_name: String,
    pub requested_at_text: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeNetworkState {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub network_id: String,
    pub local_is_admin: bool,
    pub join_requests_enabled: bool,
    pub join_request_admin_npub: String,
    pub admin_npubs: Vec<String>,
    pub outbound_join_request: Option<NativeOutboundJoinRequestState>,
    pub join_request_qr_code_or_link: String,
    pub inbound_join_requests: Vec<NativeInboundJoinRequestState>,
    pub online_count: u64,
    pub expected_count: u64,
    pub admins: Vec<String>,
    pub participants: Vec<NativeParticipantState>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHealthIssue {
    pub code: String,
    pub severity: String,
    pub summary: String,
    pub detail: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeNetworkSummary {
    pub default_interface: String,
    pub primary_ipv4: String,
    pub primary_ipv6: String,
    pub gateway_ipv4: String,
    pub gateway_ipv6: String,
    pub changed_at: u64,
    pub captive_portal: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeProbeStatus {
    pub state: String,
    pub detail: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePortMappingStatus {
    pub upnp: NativeProbeStatus,
    pub nat_pmp: NativeProbeStatus,
    pub pcp: NativeProbeStatus,
    pub active_protocol: String,
    pub external_endpoint: String,
    pub gateway: String,
    pub good_until: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeRelayState {
    pub url: String,
    pub status: String,
    pub enabled: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidExitSellerState {
    pub supported: bool,
    pub enabled: bool,
    pub status_text: String,
    pub provider_link: String,
    pub upstream: String,
    pub private_vpn_access: String,
    pub internet_text: String,
    pub public_ip_text: String,
    pub price_text: String,
    pub price_msat_per_gb: u64,
    pub accepted_mints: Vec<String>,
    pub max_channel_capacity_sat: u64,
    pub channel_expiry_secs: u64,
    pub channel_expiry_text: String,
    pub settlement_text: String,
    pub free_probe_units: u64,
    pub free_probe_text: String,
    pub grace_units: u64,
    pub grace_text: String,
    pub country_code: String,
    pub asn: u32,
    pub ipv4: bool,
    pub ipv6: bool,
    pub channel_credit_msat: u64,
    pub channel_credit_text: String,
    pub channel_credit_title_text: String,
    pub channel_credit_help_text: String,
    pub current_connection_count: u64,
    pub past_connection_count: u64,
    pub total_billable_bytes: u64,
    pub total_traffic_text: String,
    pub total_paid_msat: u64,
    pub total_paid_text: String,
    pub total_due_msat: u64,
    pub total_due_text: String,
    pub total_unpaid_msat: u64,
    pub total_unpaid_text: String,
    pub channels: Vec<NativePaidRouteChannelState>,
    pub sessions: Vec<NativePaidRouteSessionState>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteWalletMintState {
    pub url: String,
    pub label: String,
    pub is_default: bool,
    pub balance_known: bool,
    pub balance_msat: u64,
    pub balance_text: String,
    pub last_checked_unix: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteWalletState {
    pub default_mint: String,
    pub balance_known: bool,
    pub total_balance_msat: u64,
    pub total_balance_text: String,
    pub channel_balance_msat: u64,
    pub channel_balance_text: String,
    pub navigation_balance_text: String,
    pub fiat_currency: String,
    pub fiat_balance_text: String,
    pub exchange_rate_text: String,
    pub exchange_rate_status: String,
    pub exchange_rate_sources: String,
    pub exchange_rate_stale: bool,
    pub exchange_rate_updated_at_unix: u64,
    pub mints: Vec<NativePaidRouteWalletMintState>,
    pub last_action: NativePaidRouteWalletActionState,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteWalletActionState {
    pub kind: String,
    pub status_text: String,
    pub mint_url: String,
    pub amount_sat: u64,
    pub amount_text: String,
    pub fee_sat: u64,
    pub fee_text: String,
    pub quote_id: String,
    pub payment_request: String,
    pub token: String,
    pub operation_id: String,
    pub expires_at_unix: u64,
    pub preimage: String,
    pub token_state: String,
    pub token_redeemable: bool,
    pub token_memo: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRoutePaymentActionState {
    pub kind: String,
    pub status_text: String,
    pub payload_type: String,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub buyer_npub: String,
    pub seller_npub: String,
    pub envelope_json: String,
    pub paid_msat: u64,
    pub paid_text: String,
    pub delivered_units: u64,
    pub delivered_usage_text: String,
    pub amount_due_msat: u64,
    pub amount_due_text: String,
    pub unpaid_msat: u64,
    pub unpaid_text: String,
    pub allow_routing: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteOfferState {
    pub key: String,
    pub offer_id: String,
    pub seller_npub: String,
    pub status_text: String,
    pub price_text: String,
    pub price_msat_per_gb: u64,
    pub accepted_mints: Vec<String>,
    pub max_channel_capacity_sat: u64,
    pub channel_expiry_secs: u64,
    pub free_probe_units: u64,
    pub free_probe_text: String,
    pub grace_units: u64,
    pub grace_text: String,
    pub country_code: String,
    pub asn: u32,
    pub ipv4: bool,
    pub ipv6: bool,
    pub has_rating: bool,
    pub rating_score: i64,
    pub rating_updated_at_unix: u64,
    pub has_quality: bool,
    pub quality_text: String,
    pub bandwidth_text: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_ppm: u32,
    pub down_bps: u64,
    pub up_bps: u64,
    pub uptime_secs: u64,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub relay_urls: Vec<String>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteMarketFilterState {
    pub query: String,
    pub country_code: String,
    pub mint_url: String,
    pub require_ipv4: bool,
    pub require_ipv6: bool,
    pub sort: String,
}

impl Default for NativePaidRouteMarketFilterState {
    fn default() -> Self {
        Self {
            query: String::new(),
            country_code: String::new(),
            mint_url: String::new(),
            require_ipv4: false,
            require_ipv6: false,
            sort: "quality".to_string(),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteChannelState {
    pub channel_id: String,
    pub offer_id: String,
    pub role: String,
    pub status: String,
    pub mint_url: String,
    pub counterparty_npub: String,
    pub capacity_sat: u64,
    pub capacity_text: String,
    pub paid_msat: u64,
    pub paid_text: String,
    pub updated_at_unix: u64,
    pub expires_at_unix: u64,
    pub error: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteSessionState {
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub status_text: String,
    pub lifecycle_status: String,
    pub access_state: String,
    pub title_text: String,
    pub detail_text: String,
    pub settlement_text: String,
    pub collect_action_text: String,
    pub collect_action_help_text: String,
    pub payment_channel_ready: bool,
    pub allow_routing: bool,
    pub delivered_units: u64,
    pub usage_text: String,
    pub amount_due_msat: u64,
    pub amount_due_text: String,
    pub paid_msat: u64,
    pub paid_text: String,
    pub channel_balance_msat: u64,
    pub channel_balance_text: String,
    pub unpaid_msat: u64,
    pub unpaid_text: String,
    pub active_millis: u64,
    pub bytes: u64,
    pub packets: u64,
    pub realized_exit_ip: String,
    pub claimed_country_code: String,
    pub observed_country_code: String,
    pub country_claim_status: String,
    pub location_text: String,
    pub observed_asn: u32,
    pub has_quality: bool,
    pub quality_text: String,
    pub bandwidth_text: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_ppm: u32,
    pub down_bps: u64,
    pub up_bps: u64,
    pub updated_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePaidRouteMarketState {
    pub supported: bool,
    pub status_text: String,
    pub manual_provider_link: String,
    pub manual_provider_status_text: String,
    pub store_path: String,
    pub wallet: NativePaidRouteWalletState,
    pub last_payment_action: NativePaidRoutePaymentActionState,
    pub filter: NativePaidRouteMarketFilterState,
    pub offers: Vec<NativePaidRouteOfferState>,
    pub visible_offers: Vec<NativePaidRouteOfferState>,
    pub hidden_offer_count: u64,
    pub country_options: Vec<String>,
    pub channels: Vec<NativePaidRouteChannelState>,
    pub sessions: Vec<NativePaidRouteSessionState>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeAppState {
    pub rev: u64,
    pub platform: String,
    pub mobile: bool,
    pub vpn_control_supported: bool,
    pub cli_install_supported: bool,
    pub startup_settings_supported: bool,
    pub tray_behavior_supported: bool,
    pub runtime_status_detail: String,
    pub app_version: String,
    pub config_path: String,
    pub error: String,
    pub cli_installed: bool,
    pub service_supported: bool,
    pub service_enablement_supported: bool,
    pub service_installed: bool,
    pub service_disabled: bool,
    pub service_running: bool,
    pub service_status_detail: String,
    pub daemon_running: bool,
    pub vpn_enabled: bool,
    pub vpn_active: bool,
    pub vpn_status: String,
    pub daemon_binary_version: String,
    pub service_binary_version: String,
    pub expected_service_binary_version: String,
    pub own_npub: String,
    pub own_pubkey_hex: String,
    pub node_id: String,
    pub node_name: String,
    pub self_magic_dns_name: String,
    pub endpoint: String,
    pub tunnel_ip: String,
    pub listen_port: u32,
    pub relays: Vec<NativeRelayState>,
    pub nostr_pubsub_mode: String,
    pub nostr_pubsub_fanout: u32,
    pub nostr_pubsub_max_hops: u8,
    pub nostr_pubsub_max_event_bytes: u32,
    pub network_id: String,
    pub join_request_qr_code_or_link: String,
    pub internet_source: String,
    pub exit_node: String,
    pub exit_node_leak_protection: bool,
    pub exit_node_active: bool,
    pub exit_node_blocked: bool,
    pub exit_node_status_text: String,
    pub exit_dns_mode: String,
    pub exit_dns_doh_provider: String,
    pub exit_dns_custom_doh_url: String,
    pub exit_dns_custom_doh_bootstrap_ips: String,
    pub exit_dns_through_exit_servers: String,
    pub advertise_exit_node: bool,
    pub advertised_routes: Vec<String>,
    pub effective_advertised_routes: Vec<String>,
    pub wireguard_exit_enabled: bool,
    pub wireguard_exit_configured: bool,
    pub wireguard_exit_interface: String,
    pub wireguard_exit_address: String,
    pub wireguard_exit_private_key: String,
    pub wireguard_exit_peer_public_key: String,
    pub wireguard_exit_peer_preshared_key: String,
    pub wireguard_exit_endpoint: String,
    pub wireguard_exit_allowed_ips: String,
    pub wireguard_exit_dns: String,
    pub wireguard_exit_mtu: u16,
    pub wireguard_exit_persistent_keepalive_secs: u16,
    pub wireguard_exit_config: String,
    pub wallet_fiat_enabled: bool,
    pub wallet_fiat_currency: String,
    pub paid_exit_seller: NativePaidExitSellerState,
    pub paid_route_market: NativePaidRouteMarketState,
    pub fips_host_tunnel_enabled: bool,
    pub connect_to_non_roster_fips_peers: bool,
    pub fips_nostr_discovery_enabled: bool,
    pub fips_webrtc_enabled: bool,
    pub fips_bootstrap_enabled: bool,
    /// Editable bootstrap/transit peers (npub -> transport-tagged addresses).
    pub fips_bootstrap_peers: HashMap<String, Vec<String>>,
    /// Identity-neutral bootstrap defaults, so the UI can clear operator overrides.
    pub fips_bootstrap_peer_defaults: HashMap<String, Vec<String>>,
    pub fips_host_inbound_tcp_ports: String,
    pub magic_dns_suffix: String,
    pub magic_dns_status: String,
    pub autoconnect: bool,
    pub launch_on_startup: bool,
    pub close_to_tray_on_close: bool,
    pub connected_peer_count: u64,
    pub expected_peer_count: u64,
    pub fips_connected_peer_count: u64,
    pub fips_roster_peer_count: u64,
    pub non_fips_roster_peer_count: u64,
    pub mesh_ready: bool,
    pub health: Vec<NativeHealthIssue>,
    pub network: NativeNetworkSummary,
    pub port_mapping: NativePortMappingStatus,
    pub networks: Vec<NativeNetworkState>,
}
