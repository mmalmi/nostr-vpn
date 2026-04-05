use super::*;

#[test]
fn default_relays_match_hashtree_defaults() {
    assert_eq!(
        DEFAULT_RELAYS,
        [
            "wss://temp.iris.to",
            "wss://relay.damus.io",
            "wss://relay.snort.social",
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
    assert!(!config.node_name.trim().is_empty());
    assert_ne!(config.node_name, "nostr-vpn-node");
    assert!(!config.nostr.relays.is_empty());
    assert!(!config.auto_disconnect_relays_when_mesh_ready);
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.exit_node = peer_npub;

    config.ensure_defaults();

    assert_eq!(config.exit_node, peer_hex);
}

#[test]
fn stale_exit_node_is_cleared_when_not_in_active_network_roster() {
    let peer = Keys::generate();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");

    let mut config = AppConfig::generated();
    config.exit_node = peer_npub;

    config.ensure_defaults();

    assert!(config.exit_node.is_empty());
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
fn join_requests_enabled_is_true_when_any_network_listens() {
    let mut config = AppConfig::generated();
    config.networks[0].listen_for_join_requests = false;
    let network_id = config.add_network("Other");
    config
        .set_network_join_requests_enabled(&network_id, true)
        .expect("enable join requests");

    assert!(config.join_requests_enabled());
}

#[test]
fn generated_network_defaults_local_identity_to_admin() {
    let config = AppConfig::generated();
    let own_pubkey = config.own_nostr_pubkey_hex().expect("own pubkey");

    assert_eq!(config.active_network_admin_pubkeys_hex(), vec![own_pubkey]);
}

#[test]
fn apply_admin_signed_shared_roster_replaces_members_from_known_admin() {
    let own = Keys::generate();
    let current_admin = Keys::generate();
    let new_admin = Keys::generate();
    let member = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let current_admin_hex = current_admin.public_key().to_hex();
    let new_admin_hex = new_admin.public_key().to_hex();
    let member_hex = member.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![current_admin_hex.clone()];
    config.networks[0].participants = vec![current_admin_hex.clone()];
    config.ensure_defaults();

    let changed = config
        .apply_admin_signed_shared_roster(
            "mesh-home",
            "Home",
            vec![current_admin_hex.clone(), member_hex.clone(), own_hex],
            vec![current_admin_hex.clone(), new_admin_hex.clone()],
            std::collections::HashMap::new(),
            1_726_000_000,
            &current_admin_hex,
        )
        .expect("apply shared roster");

    assert!(changed);
    assert_eq!(config.networks[0].name, "Home");
    let mut expected_participants = vec![current_admin_hex.clone(), member_hex.clone()];
    expected_participants.sort();
    assert_eq!(config.networks[0].participants, expected_participants);
    let mut expected_admins = vec![new_admin_hex, current_admin.public_key().to_hex()];
    expected_admins.sort();
    assert_eq!(config.networks[0].admins, expected_admins);
    assert_eq!(config.networks[0].shared_roster_updated_at, 1_726_000_000);
}

#[test]
fn apply_admin_signed_shared_roster_ignores_unknown_signer() {
    let known_admin = Keys::generate();
    let unknown_admin = Keys::generate();
    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![known_admin.public_key().to_hex()];
    config.ensure_defaults();

    let changed = config
        .apply_admin_signed_shared_roster(
            "mesh-home",
            "Home",
            vec![known_admin.public_key().to_hex()],
            vec![known_admin.public_key().to_hex()],
            std::collections::HashMap::new(),
            1_726_000_000,
            &unknown_admin.public_key().to_hex(),
        )
        .expect("ignore unknown signer");

    assert!(!changed);
}

#[test]
fn shared_network_roster_includes_network_aliases() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();
    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.node_name = "helios-admin".to_string();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![own_hex.clone()];
    config.networks[0].participants = vec![peer_hex.clone()];
    config.ensure_defaults();
    config
        .set_peer_alias(&peer_hex, "garden-node")
        .expect("peer alias");

    let roster = config
        .shared_network_roster(&config.networks[0].id)
        .expect("shared roster");

    assert_eq!(
        roster.aliases.get(&own_hex).map(String::as_str),
        Some("helios-admin")
    );
    assert_eq!(
        roster.aliases.get(&peer_hex).map(String::as_str),
        Some("garden-node")
    );
}

#[test]
fn apply_admin_signed_shared_roster_applies_aliases_for_members() {
    let own = Keys::generate();
    let current_admin = Keys::generate();
    let member = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let current_admin_hex = current_admin.public_key().to_hex();
    let member_hex = member.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![current_admin_hex.clone()];
    config.networks[0].participants = vec![current_admin_hex.clone()];
    config.ensure_defaults();

    let changed = config
        .apply_admin_signed_shared_roster(
            "mesh-home",
            "Home",
            vec![current_admin_hex.clone(), member_hex.clone(), own_hex],
            vec![current_admin_hex.clone()],
            std::collections::HashMap::from([
                (current_admin_hex.clone(), "home-server".to_string()),
                (member_hex.clone(), "alice-phone".to_string()),
            ]),
            1_726_000_000,
            &current_admin_hex,
        )
        .expect("apply shared roster");

    assert!(changed);
    assert_eq!(
        config.peer_alias(&current_admin_hex).as_deref(),
        Some("home-server")
    );
    assert_eq!(
        config.peer_alias(&member_hex).as_deref(),
        Some("alice-phone")
    );
}

#[test]
fn apply_admin_signed_shared_roster_clears_removed_exit_node() {
    let own = Keys::generate();
    let current_admin = Keys::generate();
    let removed_exit = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let current_admin_hex = current_admin.public_key().to_hex();
    let removed_exit_hex = removed_exit.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![current_admin_hex.clone()];
    config.networks[0].participants = vec![current_admin_hex.clone(), removed_exit_hex.clone()];
    config.exit_node = removed_exit_hex.clone();
    config.ensure_defaults();

    let changed = config
        .apply_admin_signed_shared_roster(
            "mesh-home",
            "Home",
            vec![current_admin_hex.clone(), own_hex],
            vec![current_admin_hex.clone()],
            std::collections::HashMap::new(),
            1_726_000_000,
            &current_admin_hex,
        )
        .expect("apply shared roster");

    assert!(changed);
    assert!(config.exit_node.is_empty());
}

#[test]
fn set_peer_alias_marks_member_network_roster_changed() {
    let peer_hex = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].participants = vec![peer_hex.clone()];
    config.ensure_defaults();
    assert_eq!(config.networks[0].shared_roster_updated_at, 0);

    config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set peer alias");

    assert!(config.networks[0].shared_roster_updated_at > 0);
}

#[test]
fn record_inbound_join_request_ignores_mismatched_mesh_id() {
    let requester = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-home".to_string();

    let recorded = config
        .record_inbound_join_request("mesh-other", &requester, "alice-phone", 1_726_000_000)
        .expect("record join request");

    assert!(recorded.is_none());
    assert!(config.networks[0].inbound_join_requests.is_empty());
}

#[test]
fn record_inbound_join_request_updates_matching_listening_network() {
    let requester = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].name = "Home".to_string();
    config.networks[0].network_id = "mesh-home".to_string();

    let recorded = config
        .record_inbound_join_request("mesh-home", &requester, "alice-phone", 1_726_000_000)
        .expect("record join request");

    assert_eq!(recorded.as_deref(), Some("Home"));
    assert_eq!(config.networks[0].inbound_join_requests.len(), 1);
    assert_eq!(
        config.networks[0].inbound_join_requests[0].requester,
        requester
    );
    assert_eq!(
        config.networks[0].inbound_join_requests[0].requester_node_name,
        "alice-phone"
    );
}
