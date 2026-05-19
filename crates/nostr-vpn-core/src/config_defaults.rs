use std::net::{IpAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use nostr_sdk::prelude::{Keys, PublicKey, ToBech32};
use uuid::Uuid;

use crate::network_routes::derive_mesh_tunnel_ip;

pub(crate) const LEGACY_NETWORK_ID_COMPAT_PREFIX: &str = "nostr-vpn:";

pub(crate) fn default_relays() -> Vec<String> {
    crate::config::DEFAULT_RELAYS
        .iter()
        .map(|relay| relay.to_string())
        .collect()
}

pub fn normalize_runtime_network_id(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix(LEGACY_NETWORK_ID_COMPAT_PREFIX)
        .unwrap_or(trimmed)
        .to_string()
}

pub fn normalize_nostr_pubkey(value: &str) -> Result<String> {
    PublicKey::parse(value)
        .map(|public_key| public_key.to_hex())
        .map_err(|error| anyhow::anyhow!("invalid participant pubkey '{value}': {error}"))
}

/// Outcome of resolving a CLI participant string: the canonical hex pubkey
/// plus the alias (if the user typed a `.bit` name) so callers can preserve
/// it for later display in `status`/`ip`/`whois` output.
#[derive(Debug, Clone)]
pub struct ResolvedParticipant {
    pub hex_pubkey: String,
    pub alias: Option<String>,
}

/// Async sibling of [`normalize_nostr_pubkey`] that additionally accepts
/// `.bit` aliases. Inputs that are already valid npub/hex are returned
/// unchanged (modulo canonicalization) without touching the resolver, so
/// existing call sites that never use aliases pay no network cost.
pub async fn resolve_participant_string<R>(
    value: &str,
    resolver: Option<&R>,
) -> Result<ResolvedParticipant>
where
    R: nostr_vpn_namecoin::NamecoinResolver + ?Sized,
{
    if let Some(alias) = nostr_vpn_namecoin::parse_bit_alias(value) {
        let resolver = resolver.ok_or_else(|| {
            anyhow::anyhow!("namecoin resolver disabled; cannot resolve '.bit' alias '{value}'")
        })?;
        let hex = resolver
            .resolve_nostr_pubkey(&alias)
            .await
            .map_err(|error| anyhow::anyhow!("failed to resolve '{value}': {error}"))?;
        let normalized = normalize_nostr_pubkey(&hex)?;
        return Ok(ResolvedParticipant {
            hex_pubkey: normalized,
            alias: Some(alias.to_string()),
        });
    }

    let normalized = normalize_nostr_pubkey(value)?;
    Ok(ResolvedParticipant {
        hex_pubkey: normalized,
        alias: None,
    })
}

pub(crate) fn default_nat_enabled() -> bool {
    true
}

pub(crate) fn default_nat_stun_servers() -> Vec<String> {
    vec![
        "stun:stun.iris.to:3478".to_string(),
        "stun:stun.l.google.com:19302".to_string(),
        "stun:stun.cloudflare.com:3478".to_string(),
    ]
}

pub(crate) const fn default_nat_discovery_timeout_secs() -> u64 {
    2
}

pub(crate) fn default_lan_discovery_enabled() -> bool {
    true
}

pub(crate) fn default_launch_on_startup() -> bool {
    true
}

pub(crate) fn default_autoconnect() -> bool {
    true
}

pub(crate) fn default_fips_advertise_endpoint() -> bool {
    true
}

pub(crate) fn default_close_to_tray_on_close() -> bool {
    true
}

pub(crate) fn default_network_enabled() -> bool {
    true
}

pub(crate) fn default_listen_for_join_requests() -> bool {
    true
}

pub(crate) fn is_true(value: &bool) -> bool {
    *value
}

pub(crate) fn default_node_id() -> String {
    Uuid::new_v4().to_string()
}

pub(crate) fn default_endpoint() -> String {
    "127.0.0.1:51820".to_string()
}

pub(crate) fn default_tunnel_ip() -> String {
    "10.44.0.1/32".to_string()
}

pub(crate) const fn default_listen_port() -> u16 {
    51820
}

pub(crate) fn default_network_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

pub(crate) fn needs_generated_network_id(value: &str) -> bool {
    value.trim().is_empty() || value.trim() == "nostr-vpn"
}

pub(crate) fn npub_for_pubkey_hex(pubkey_hex: &str) -> String {
    PublicKey::from_hex(pubkey_hex)
        .ok()
        .and_then(|public_key| public_key.to_bech32().ok())
        .unwrap_or_else(|| pubkey_hex.to_string())
}

pub(crate) fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub(crate) fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub fn maybe_autoconfigure_node(config: &mut crate::config::AppConfig) {
    config.ensure_defaults();

    if needs_endpoint_autoconfig(&config.node.endpoint)
        && let Some(ip) = detect_primary_ipv4()
    {
        config.node.endpoint = format!("{ip}:{}", config.node.listen_port);
    }

    let network_id = config.effective_network_id();
    if !network_id.is_empty()
        && needs_tunnel_ip_autoconfig(&config.node.tunnel_ip)
        && let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(&network_id, &own_pubkey)
    {
        config.node.tunnel_ip = tunnel_ip;
    }
}

pub fn needs_endpoint_autoconfig(endpoint: &str) -> bool {
    let value = endpoint.trim();
    if value.is_empty() {
        return true;
    }

    let host = value
        .rsplit_once(':')
        .map_or(value, |(host, _port)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');

    if matches!(host, "127.0.0.1" | "0.0.0.0" | "localhost" | "::1") {
        return true;
    }

    host.parse::<IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V4(ipv4) if ipv4_is_documentation(ipv4.octets())))
}

pub fn needs_tunnel_ip_autoconfig(tunnel_ip: &str) -> bool {
    let value = tunnel_ip.trim();
    value.is_empty() || value == "10.44.0.1/32"
}

fn ipv4_is_documentation(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn detect_primary_ipv4() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_ipv4() { Some(ip) } else { None }
}

pub(crate) fn generate_nostr_identity() -> (String, String) {
    let keys = Keys::generate();

    let secret_key = keys
        .secret_key()
        .to_bech32()
        .unwrap_or_else(|_| keys.secret_key().to_secret_hex());

    let public_key = keys
        .public_key()
        .to_bech32()
        .unwrap_or_else(|_| keys.public_key().to_hex());

    (secret_key, public_key)
}
