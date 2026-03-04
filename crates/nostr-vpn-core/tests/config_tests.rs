use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, derive_mesh_tunnel_ip, derive_network_id_from_participants,
    maybe_autoconfigure_node, needs_endpoint_autoconfig, needs_tunnel_ip_autoconfig,
    normalize_nostr_pubkey,
};

#[test]
fn default_relays_match_hashtree_defaults() {
    assert_eq!(
        DEFAULT_RELAYS,
        [
            "wss://temp.iris.to",
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.primal.net",
            "wss://offchain.pub",
        ]
    );
}

#[test]
fn network_id_derivation_is_order_independent() {
    let left =
        derive_network_id_from_participants(&["b".to_string(), "a".to_string(), "c".to_string()]);
    let right =
        derive_network_id_from_participants(&["c".to_string(), "b".to_string(), "a".to_string()]);

    assert_eq!(left, right);
}

#[test]
fn generated_config_auto_populates_keys() {
    let config = AppConfig::generated();

    assert!(!config.node.private_key.is_empty());
    assert!(!config.node.public_key.is_empty());
    assert!(!config.nostr.secret_key.is_empty());
    assert!(!config.nostr.public_key.is_empty());
    assert!(!config.nostr.relays.is_empty());
    assert!(config.auto_disconnect_relays_when_mesh_ready);
    assert!(config.lan_discovery_enabled);
    assert!(config.launch_on_startup);
    assert!(config.close_to_tray_on_close);
}

#[test]
fn participants_are_normalized_to_hex_pubkeys() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");
    let hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.participants = vec![npub, hex.clone()];
    config.ensure_defaults();

    assert_eq!(config.participants, vec![hex]);
}

#[test]
fn normalize_accepts_npub() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");

    let normalized = normalize_nostr_pubkey(&npub).expect("normalize npub");

    assert_eq!(normalized, keys.public_key().to_hex());
}

#[test]
fn derive_mesh_tunnel_ip_is_deterministic_for_participant_member() {
    let participants = vec!["aa".to_string(), "bb".to_string(), "cc".to_string()];
    let tunnel_ip = derive_mesh_tunnel_ip(&participants, "bb").expect("tunnel ip");
    assert_eq!(tunnel_ip, "10.44.0.2/32");
}

#[test]
fn maybe_autoconfigure_node_assigns_tunnel_ip_from_participants() {
    let keys = Keys::generate();
    let own_hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = keys.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.participants = vec!["0".repeat(64), own_hex];
    config.node.tunnel_ip = "10.44.0.1/32".to_string();
    config.node.endpoint = "198.51.100.10:51820".to_string();

    maybe_autoconfigure_node(&mut config);

    assert_eq!(config.node.tunnel_ip, "10.44.0.2/32");
}

#[test]
fn endpoint_and_tunnel_autoconfig_detection_works() {
    assert!(needs_endpoint_autoconfig("127.0.0.1:51820"));
    assert!(needs_endpoint_autoconfig("0.0.0.0:51820"));
    assert!(!needs_endpoint_autoconfig("198.51.100.10:51820"));

    assert!(needs_tunnel_ip_autoconfig("10.44.0.1/32"));
    assert!(!needs_tunnel_ip_autoconfig("10.44.0.15/32"));
}

#[test]
fn lan_discovery_defaults_true_when_missing_from_toml() {
    let raw = r#"
network_id = "nostr-vpn"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
participants = []

[nostr]
relays = ["wss://temp.iris.to"]
secret_key = ""
public_key = ""

[node]
id = "node-id"
private_key = ""
public_key = ""
endpoint = "127.0.0.1:51820"
tunnel_ip = "10.44.0.1/32"
listen_port = 51820
"#;

    let config: AppConfig = toml::from_str(raw).expect("parse config");
    assert!(config.lan_discovery_enabled);
}

#[test]
fn close_to_tray_defaults_true_when_missing_from_toml() {
    let raw = r#"
network_id = "nostr-vpn"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
lan_discovery_enabled = true
participants = []

[nostr]
relays = ["wss://temp.iris.to"]
secret_key = ""
public_key = ""

[node]
id = "node-id"
private_key = ""
public_key = ""
endpoint = "127.0.0.1:51820"
tunnel_ip = "10.44.0.1/32"
listen_port = 51820
"#;

    let config: AppConfig = toml::from_str(raw).expect("parse config");
    assert!(config.close_to_tray_on_close);
}

#[test]
fn launch_on_startup_defaults_true_when_missing_from_toml() {
    let raw = r#"
network_id = "nostr-vpn"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
lan_discovery_enabled = true
close_to_tray_on_close = true
participants = []

[nostr]
relays = ["wss://temp.iris.to"]
secret_key = ""
public_key = ""

[node]
id = "node-id"
private_key = ""
public_key = ""
endpoint = "127.0.0.1:51820"
tunnel_ip = "10.44.0.1/32"
listen_port = 51820
"#;

    let config: AppConfig = toml::from_str(raw).expect("parse config");
    assert!(config.launch_on_startup);
}

#[test]
fn reciprocal_participant_configs_share_effective_network_id() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let alice_hex = alice.public_key().to_hex();
    let bob_hex = bob.public_key().to_hex();

    let mut alice_config = AppConfig::generated();
    alice_config.nostr.secret_key = alice.secret_key().to_secret_hex();
    alice_config.nostr.public_key = alice_hex.clone();
    alice_config.participants = vec![bob_hex.clone()];
    maybe_autoconfigure_node(&mut alice_config);

    let mut bob_config = AppConfig::generated();
    bob_config.nostr.secret_key = bob.secret_key().to_secret_hex();
    bob_config.nostr.public_key = bob_hex.clone();
    bob_config.participants = vec![alice_hex.clone()];
    maybe_autoconfigure_node(&mut bob_config);

    assert_eq!(
        alice_config.effective_network_id(),
        bob_config.effective_network_id()
    );

    assert_ne!(alice_config.node.tunnel_ip, bob_config.node.tunnel_ip);
    assert_eq!(
        derive_mesh_tunnel_ip(&alice_config.mesh_members_pubkeys(), &alice_hex)
            .expect("alice tunnel ip"),
        alice_config.node.tunnel_ip
    );
    assert_eq!(
        derive_mesh_tunnel_ip(&bob_config.mesh_members_pubkeys(), &bob_hex).expect("bob tunnel ip"),
        bob_config.node.tunnel_ip
    );
}

#[test]
fn magic_dns_aliases_are_generated_and_resolve_to_configured_participant() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    config.participants = vec![peer_hex.clone()];
    config.ensure_defaults();

    let alias = config.peer_alias(&peer_hex).expect("generated alias");
    let fqdn = config
        .magic_dns_name_for_participant(&peer_hex)
        .expect("magic dns fqdn");

    assert_eq!(
        config.resolve_magic_dns_query(&alias),
        Some(peer_hex.clone())
    );
    assert_eq!(
        config.resolve_magic_dns_query(&fqdn),
        Some(peer_hex.clone())
    );
}

#[test]
fn set_peer_alias_normalizes_and_blank_resets_to_default() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    config.participants = vec![peer_hex.clone()];
    config.ensure_defaults();

    let default_alias = config.peer_alias(&peer_hex).expect("default alias");
    let custom_alias = config
        .set_peer_alias(&peer_hex, "Home Server !!")
        .expect("set custom alias");
    assert_eq!(custom_alias, "home-server");
    assert_eq!(
        config
            .magic_dns_name_for_participant(&peer_hex)
            .expect("dns name"),
        "home-server.nvpn"
    );

    let reset_alias = config
        .set_peer_alias(&peer_hex, "   ")
        .expect("reset alias");
    assert_eq!(reset_alias, default_alias);
}

#[test]
fn peer_aliases_use_npub_keys_in_serialized_config() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    config.participants = vec![peer_hex.clone()];
    config.ensure_defaults();
    config
        .set_peer_alias(&peer_hex, "server-a")
        .expect("set alias");

    assert!(config.peer_aliases.contains_key(&peer_npub));
    assert!(!config.peer_aliases.contains_key(&peer_hex));
}
