use std::fs;

use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, NetworkConfig, derive_mesh_tunnel_ip,
    derive_network_id_from_participants, maybe_autoconfigure_node, needs_endpoint_autoconfig,
    needs_tunnel_ip_autoconfig, normalize_nostr_pubkey,
};

fn set_default_network_participants(config: &mut AppConfig, participants: Vec<String>) {
    config.ensure_defaults();
    if let Some(network) = config.networks.first_mut() {
        network.participants = participants;
    }
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

#[test]
fn default_relays_match_hashtree_defaults() {
    assert_eq!(
        DEFAULT_RELAYS,
        [
            "wss://temp.iris.to",
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.primal.net",
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
    assert!(!left.contains(':'));
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
    assert!(config.autoconnect);
    assert!(config.lan_discovery_enabled);
    assert!(config.launch_on_startup);
    assert!(config.close_to_tray_on_close);
    assert!(config.nat.enabled);
    assert!(!config.nat.stun_servers.is_empty());
    assert!(config.exit_node.is_empty());
    assert!(!config.node.advertise_exit_node);
    assert!(config.node.advertised_routes.is_empty());
    assert!(config.effective_advertised_routes().is_empty());
}

#[test]
fn default_routes_promote_to_exit_node_toggle() {
    let mut config = AppConfig::generated();
    config.node.advertised_routes = vec![
        "10.0.0.0/24".to_string(),
        "0.0.0.0/0".to_string(),
        "::/0".to_string(),
        "10.0.0.0/24".to_string(),
    ];

    config.ensure_defaults();

    assert!(config.node.advertise_exit_node);
    assert_eq!(
        config.node.advertised_routes,
        vec!["10.0.0.0/24".to_string()]
    );
    assert_eq!(
        config.effective_advertised_routes(),
        vec![
            "10.0.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            "::/0".to_string(),
        ]
    );
}

#[test]
fn exit_node_normalizes_from_npub() {
    let peer = Keys::generate();
    let peer_hex = peer.public_key().to_hex();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");

    let mut config = AppConfig::generated();
    config.exit_node = peer_npub;

    config.ensure_defaults();

    assert_eq!(config.exit_node, peer_hex);
}

#[test]
fn participants_are_normalized_to_hex_pubkeys() {
    let keys = Keys::generate();
    let npub = keys.public_key().to_bech32().expect("npub");
    let hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    set_default_network_participants(&mut config, vec![npub, hex.clone()]);
    config.ensure_defaults();

    assert_eq!(config.participant_pubkeys_hex(), vec![hex]);
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
    let tunnel_ip = derive_mesh_tunnel_ip("mesh-a", "bb").expect("tunnel ip");
    assert_eq!(
        tunnel_ip,
        derive_mesh_tunnel_ip("mesh-a", "bb").expect("tunnel ip")
    );
    assert_ne!(
        tunnel_ip,
        derive_mesh_tunnel_ip("mesh-b", "bb").expect("different mesh id changes ip")
    );
}

#[test]
fn maybe_autoconfigure_node_assigns_tunnel_ip_from_participants() {
    let keys = Keys::generate();
    let own_hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = keys.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    set_default_network_participants(&mut config, vec!["0".repeat(64), own_hex.clone()]);
    config.node.tunnel_ip = "10.44.0.1/32".to_string();
    config.node.endpoint = "198.51.100.10:51820".to_string();

    maybe_autoconfigure_node(&mut config);

    assert_eq!(
        config.node.tunnel_ip,
        derive_mesh_tunnel_ip(&config.effective_network_id(), &own_hex).expect("derived ip")
    );
}

#[test]
fn active_network_network_id_takes_precedence_over_participant_hash() {
    let keys = Keys::generate();
    let peer = Keys::generate();
    let own_hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-fixed".to_string();
    config.nostr.secret_key = keys.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    set_default_network_participants(&mut config, vec![peer.public_key().to_hex()]);

    config.ensure_defaults();

    assert_eq!(config.effective_network_id(), "mesh-fixed");
}

#[test]
fn legacy_prefixed_network_ids_are_normalized_at_runtime() {
    let mut config = AppConfig::generated();
    config.networks[0].network_id = "nostr-vpn:1234abcd5678ef90".to_string();

    config.ensure_defaults();

    assert_eq!(config.networks[0].network_id, "nostr-vpn:1234abcd5678ef90");
    assert_eq!(config.effective_network_id(), "1234abcd5678ef90");
}

#[test]
fn default_network_id_stays_placeholder_without_participants() {
    let mut config = AppConfig::generated();

    maybe_autoconfigure_node(&mut config);

    assert_eq!(config.effective_network_id(), "nostr-vpn");
}

#[test]
fn legacy_top_level_network_id_is_ignored_when_loading_current_config_schema() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();
    let expected_network_id =
        derive_network_id_from_participants(&[own_hex.clone(), peer_hex.clone()]);
    let raw = format!(
        r#"
network_id = "mesh-legacy"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
lan_discovery_enabled = true
launch_on_startup = true
autoconnect = true
close_to_tray_on_close = true

[[networks]]
id = "network-1"
name = "Network 1"
enabled = true
network_id = "nostr-vpn"
participants = ["{peer_hex}"]

[nostr]
relays = ["wss://temp.iris.to"]
secret_key = "{secret_key}"
public_key = "{own_hex}"

[node]
id = "node-id"
private_key = ""
public_key = ""
endpoint = "127.0.0.1:51820"
tunnel_ip = "10.44.0.1/32"
listen_port = 51820
"#,
        secret_key = own.secret_key().to_secret_hex(),
    );

    let mut config: AppConfig = toml::from_str(&raw).expect("parse config");
    config.ensure_defaults();

    assert_eq!(config.effective_network_id(), expected_network_id);
}

#[test]
fn tunnel_ip_stays_stable_when_roster_changes_if_network_id_is_fixed() {
    let mut keys = vec![Keys::generate(), Keys::generate(), Keys::generate()];
    keys.sort_by_key(|entry| entry.public_key().to_hex());

    let own = keys.remove(1);
    let low = keys.remove(0).public_key().to_hex();
    let high = keys.remove(0).public_key().to_hex();
    let own_hex = own.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-fixed".to_string();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    set_default_network_participants(&mut config, vec![high.clone()]);
    config.node.tunnel_ip = "10.44.0.1/32".to_string();

    maybe_autoconfigure_node(&mut config);
    let first_ip = config.node.tunnel_ip.clone();

    set_default_network_participants(&mut config, vec![high, low]);
    config.node.tunnel_ip = "10.44.0.1/32".to_string();
    maybe_autoconfigure_node(&mut config);

    assert_eq!(config.node.tunnel_ip, first_ip);
    assert_ne!(config.node.tunnel_ip, "10.44.0.1/32");
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
[[networks]]
id = "network-1"
name = "Network 1"
enabled = true
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
fn save_omits_legacy_lan_discovery_flag() {
    let path = unique_temp_config_path("omit-legacy-lan-discovery");
    let config = AppConfig::generated();

    config.save(&path).expect("save config");
    let raw = fs::read_to_string(&path).expect("read saved config");
    let _ = fs::remove_file(&path);

    assert!(!raw.contains("lan_discovery_enabled"));
}

#[test]
fn close_to_tray_defaults_true_when_missing_from_toml() {
    let raw = r#"
network_id = "nostr-vpn"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
lan_discovery_enabled = true
[[networks]]
id = "network-1"
name = "Network 1"
enabled = true
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
[[networks]]
id = "network-1"
name = "Network 1"
enabled = true
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
fn autoconnect_defaults_true_when_missing_from_toml() {
    let raw = r#"
network_id = "nostr-vpn"
node_name = "node"
auto_disconnect_relays_when_mesh_ready = true
lan_discovery_enabled = true
launch_on_startup = true
close_to_tray_on_close = true
[[networks]]
id = "network-1"
name = "Network 1"
enabled = true
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
    assert!(config.autoconnect);
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
    set_default_network_participants(&mut alice_config, vec![bob_hex.clone()]);
    maybe_autoconfigure_node(&mut alice_config);

    let mut bob_config = AppConfig::generated();
    bob_config.nostr.secret_key = bob.secret_key().to_secret_hex();
    bob_config.nostr.public_key = bob_hex.clone();
    set_default_network_participants(&mut bob_config, vec![alice_hex.clone()]);
    maybe_autoconfigure_node(&mut bob_config);

    assert_ne!(alice_config.effective_network_id(), "nostr-vpn");
    assert_ne!(bob_config.effective_network_id(), "nostr-vpn");
    assert!(!alice_config.effective_network_id().contains(':'));
    assert!(!bob_config.effective_network_id().contains(':'));
    assert_eq!(
        alice_config.effective_network_id(),
        bob_config.effective_network_id()
    );

    assert_ne!(alice_config.node.tunnel_ip, bob_config.node.tunnel_ip);
    assert_eq!(
        derive_mesh_tunnel_ip(&alice_config.effective_network_id(), &alice_hex)
            .expect("alice tunnel ip"),
        alice_config.node.tunnel_ip
    );
    assert_eq!(
        derive_mesh_tunnel_ip(&bob_config.effective_network_id(), &bob_hex).expect("bob tunnel ip"),
        bob_config.node.tunnel_ip
    );
}

#[test]
fn active_network_helpers_ignore_inactive_networks() {
    let own_keys = Keys::generate();
    let own_hex = own_keys.public_key().to_hex();
    let peer_a = Keys::generate().public_key().to_hex();
    let peer_b = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own_keys.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks = vec![
        NetworkConfig {
            id: "network-1".to_string(),
            name: "oma".to_string(),
            enabled: true,
            network_id: "mesh-home".to_string(),
            participants: vec![peer_a.clone()],
        },
        NetworkConfig {
            id: "network-2".to_string(),
            name: "lauri".to_string(),
            enabled: false,
            network_id: "mesh-work".to_string(),
            participants: vec![peer_b.clone()],
        },
    ];
    config.ensure_defaults();

    assert_eq!(config.effective_network_id(), "mesh-home");
    assert_eq!(config.participant_pubkeys_hex(), vec![peer_a.clone()]);

    let mut expected_all = vec![peer_a.clone(), peer_b];
    expected_all.sort();
    assert_eq!(config.all_participant_pubkeys_hex(), expected_all);

    let mut expected_members = vec![peer_a, own_hex];
    expected_members.sort();
    assert_eq!(config.mesh_members_pubkeys(), expected_members);

    let meshes = config.enabled_network_meshes();
    assert_eq!(meshes.len(), 1);
    assert_eq!(meshes[0].network_id, "mesh-home");
}

#[test]
fn activating_one_network_disables_the_others() {
    let mut config = AppConfig::generated();
    let first_id = config.networks[0].id.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    let second_id = config.add_network("Work");
    config
        .network_by_id_mut(&second_id)
        .expect("second network")
        .network_id = "mesh-work".to_string();

    config
        .set_network_enabled(&second_id, true)
        .expect("activate second network");

    assert_eq!(config.enabled_network_count(), 1);
    assert!(
        !config
            .network_by_id(&first_id)
            .expect("first network")
            .enabled
    );
    assert!(
        config
            .network_by_id(&second_id)
            .expect("second network")
            .enabled
    );
    assert_eq!(config.effective_network_id(), "mesh-work");
}

#[test]
fn cannot_disable_the_last_active_network() {
    let mut config = AppConfig::generated();
    let active_id = config.networks[0].id.clone();

    let error = config
        .set_network_enabled(&active_id, false)
        .expect_err("last active network should stay active");

    assert!(error.to_string().contains("active network"));
    assert_eq!(config.enabled_network_count(), 1);
    assert!(
        config
            .network_by_id(&active_id)
            .expect("active network")
            .enabled
    );
}

#[test]
fn added_networks_start_inactive_with_their_own_mesh_slot() {
    let mut config = AppConfig::generated();
    let original_active_id = config.networks[0].id.clone();

    let added_id = config.add_network("Work");

    assert_eq!(config.enabled_network_count(), 1);
    assert!(
        config
            .network_by_id(&original_active_id)
            .expect("original active network")
            .enabled
    );

    let added = config.network_by_id(&added_id).expect("added network");
    assert!(!added.enabled);
    assert_eq!(added.network_id, "nostr-vpn");
}

#[test]
fn explicit_network_id_takes_precedence_over_participant_hash() {
    let keys = Keys::generate();
    let peer = Keys::generate();
    let own_hex = keys.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-fixed".to_string();
    config.nostr.secret_key = keys.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    set_default_network_participants(&mut config, vec![peer.public_key().to_hex()]);

    config.ensure_defaults();

    assert_eq!(config.effective_network_id(), "mesh-fixed");
}

#[test]
fn set_network_mesh_id_updates_the_selected_network() {
    let mut config = AppConfig::generated();
    let original_active_id = config.networks[0].id.clone();
    let added_id = config.add_network("Work");

    config
        .set_network_mesh_id(&added_id, "mesh-work")
        .expect("mesh id should update");

    assert_eq!(
        config
            .network_by_id(&added_id)
            .expect("saved network")
            .network_id,
        "mesh-work"
    );
    assert_eq!(
        config
            .network_by_id(&original_active_id)
            .expect("active network")
            .network_id,
        "nostr-vpn"
    );
    assert_eq!(config.effective_network_id(), "nostr-vpn");
}

#[test]
fn set_network_mesh_id_rejects_empty_values() {
    let mut config = AppConfig::generated();
    let active_id = config.networks[0].id.clone();

    let error = config
        .set_network_mesh_id(&active_id, "   ")
        .expect_err("empty mesh id should fail");

    assert_eq!(error.to_string(), "network id cannot be empty");
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.ensure_defaults();
    config
        .set_peer_alias(&peer_hex, "server-a")
        .expect("set alias");

    assert!(config.peer_aliases.contains_key(&peer_npub));
    assert!(!config.peer_aliases.contains_key(&peer_hex));
}

#[test]
fn save_serializes_user_facing_pubkeys_as_npubs() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let own_npub = own.public_key().to_bech32().expect("own npub");
    let peer_hex = peer.public_key().to_hex();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    config.exit_node = peer_hex.clone();
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.ensure_defaults();

    let path = unique_temp_config_path("save-serializes-user-facing-pubkeys");
    config.save(&path).expect("save config");
    let raw = fs::read_to_string(&path).expect("read saved config");
    let _ = fs::remove_file(&path);

    assert!(raw.contains(&format!("public_key = \"{own_npub}\"")));
    assert!(raw.contains(&format!("exit_node = \"{peer_npub}\"")));
    assert!(raw.contains(&format!("participants = [\"{peer_npub}\"]")));
    assert!(!raw.contains(&peer_hex));
}

#[test]
fn save_and_load_round_trip_keeps_runtime_pubkeys_normalized() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.exit_node = peer_hex.clone();
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.ensure_defaults();

    let path = unique_temp_config_path("save-load-roundtrip");
    config.save(&path).expect("save config");
    let loaded = AppConfig::load(&path).expect("load config");
    let _ = fs::remove_file(&path);

    assert_eq!(loaded.participant_pubkeys_hex(), vec![peer_hex.clone()]);
    assert_eq!(loaded.exit_node, peer_hex);
    assert_eq!(
        loaded.own_nostr_pubkey_hex().expect("own pubkey hex"),
        own_hex
    );
}

#[test]
fn default_aliases_prefer_animals_and_stay_unique() {
    let own = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_a = Keys::generate().public_key().to_hex();
    let peer_b = Keys::generate().public_key().to_hex();
    let peer_c = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    set_default_network_participants(
        &mut config,
        vec![peer_a.clone(), peer_b.clone(), peer_c.clone()],
    );
    config.ensure_defaults();

    let alias_a = config.peer_alias(&peer_a).expect("alias a");
    let alias_b = config.peer_alias(&peer_b).expect("alias b");
    let alias_c = config.peer_alias(&peer_c).expect("alias c");

    assert!(!alias_a.starts_with("peer-"));
    assert!(!alias_b.starts_with("peer-"));
    assert!(!alias_c.starts_with("peer-"));

    let mut aliases = std::collections::HashSet::new();
    assert!(aliases.insert(alias_a));
    assert!(aliases.insert(alias_b));
    assert!(aliases.insert(alias_c));
}
