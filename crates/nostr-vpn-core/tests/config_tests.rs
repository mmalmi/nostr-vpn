use std::fs;

use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, NetworkConfig, default_node_name_for_hostname_or_pubkey,
    default_node_name_for_pubkey, default_node_name_from_hostname, derive_mesh_tunnel_ip,
    maybe_autoconfigure_node, needs_endpoint_autoconfig, needs_tunnel_ip_autoconfig,
    normalize_nostr_pubkey,
};

fn set_default_network_participants(config: &mut AppConfig, participants: Vec<String>) {
    config.ensure_defaults();
    if let Some(network) = config.networks.first_mut() {
        network.participants = participants;
    }
}

fn keep_endpoint_autoconfig_off(config: &mut AppConfig) {
    config.node.endpoint = "198.51.100.10:51820".to_string();
}

fn assert_generated_network_id(value: &str) {
    assert_ne!(value, "nostr-vpn");
    assert_eq!(value.len(), 16);
    assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
}

fn unique_temp_config_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "nostr-vpn-{name}-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

#[path = "config_tests/defaults.rs"]
mod defaults;
#[path = "config_tests/magic_dns.rs"]
mod magic_dns;
#[path = "config_tests/namecoin.rs"]
mod namecoin;
#[path = "config_tests/network.rs"]
mod network;
