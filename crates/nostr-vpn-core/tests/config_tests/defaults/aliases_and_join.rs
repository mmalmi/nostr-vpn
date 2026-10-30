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
    config.networks[0].devices = vec![peer_hex.clone()];
    config.ensure_defaults();
    config
        .set_peer_alias(&own_hex, "helios-admin")
        .expect("own alias");
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
    let own_npub = own.public_key().to_bech32().expect("own npub");
    let current_admin_hex = current_admin.public_key().to_hex();
    let member_hex = member.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].admins = vec![current_admin_hex.clone()];
    config.networks[0].devices = vec![current_admin_hex.clone()];
    config
        .peer_aliases
        .insert(own_npub, "old-local".to_string());
    config.ensure_defaults();
    assert_eq!(config.self_magic_dns_label().as_deref(), Some("old-local"));

    let changed = config
        .apply_admin_signed_shared_roster(admin_signed_roster_update(
            "mesh-home",
            "Home",
            vec![
                current_admin_hex.clone(),
                member_hex.clone(),
                own_hex.clone(),
            ],
            vec![current_admin_hex.clone()],
            std::collections::HashMap::from([
                (own_hex.clone(), "iphone".to_string()),
                (current_admin_hex.clone(), "home-server".to_string()),
                (member_hex.clone(), "alice-phone".to_string()),
            ]),
            1_726_000_000,
            &current_admin_hex,
            "hash",
        ), None)
        .expect("apply shared roster");

    assert!(changed);
    assert_eq!(config.self_magic_dns_label().as_deref(), Some("iphone"));
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
    config.networks[0].devices = vec![current_admin_hex.clone(), removed_exit_hex.clone()];
    config.exit_node = removed_exit_hex.clone();
    config.ensure_defaults();

    let changed = config
        .apply_admin_signed_shared_roster(admin_signed_roster_update(
            "mesh-home",
            "Home",
            vec![current_admin_hex.clone(), own_hex],
            vec![current_admin_hex.clone()],
            std::collections::HashMap::new(),
            1_726_000_000,
            &current_admin_hex,
            "hash",
        ), None)
        .expect("apply shared roster");

    assert!(changed);
    assert!(config.exit_node.is_empty());
}

#[test]
fn set_peer_alias_marks_member_network_roster_changed() {
    let peer_hex = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].devices = vec![peer_hex.clone()];
    config.ensure_defaults();
    assert_eq!(config.networks[0].shared_roster_updated_at, 0);

    config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set peer alias");

    assert!(config.networks[0].shared_roster_updated_at > 0);
}

#[test]
fn set_peer_alias_bumps_shared_roster_timestamp_past_previous_value() {
    let own = Keys::generate();
    let peer_hex = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own.public_key().to_hex();
    config.networks[0].devices = vec![peer_hex.clone()];
    config.networks[0].admins = vec![config.nostr.public_key.clone()];
    config.ensure_defaults();
    config.networks[0].shared_roster_updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();

    let previous = config.networks[0].shared_roster_updated_at;
    config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set peer alias");

    assert!(config.networks[0].shared_roster_updated_at > previous);
}

#[test]
fn record_inbound_join_request_ignores_mismatched_mesh_id() {
    let requester = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-home".to_string();
    let join_secret = config.networks[0].join_secret.clone();

    let recorded = config
        .record_inbound_join_request(
            "mesh-other",
            &join_secret,
            &requester,
            "alice-phone",
            1_726_000_000,
        )
        .expect("record join request");

    assert!(recorded.is_none());
    assert!(config.networks[0].inbound_join_requests.is_empty());
}

#[test]
fn grouped_hex_network_ids_normalize_to_compact_lowercase() {
    assert_eq!(normalize_runtime_network_id(" FD5F-4753 "), "fd5f4753");
    assert_eq!(normalize_runtime_network_id("----"), "");
    assert_eq!(normalize_runtime_network_id("mesh-home"), "mesh-home");
}

#[test]
fn record_inbound_join_request_updates_matching_listening_network() {
    let requester = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].name = "Home".to_string();
    config.networks[0].network_id = "mesh-home".to_string();
    let join_secret = config.networks[0].join_secret.clone();

    let recorded = config
        .record_inbound_join_request(
            "mesh-home",
            &join_secret,
            &requester,
            "alice-phone",
            1_726_000_000,
        )
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

#[test]
fn record_inbound_join_request_ignores_wrong_join_secret() {
    let requester = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    config.networks[0].network_id = "mesh-home".to_string();
    config.networks[0].join_secret = "expected-secret".to_string();

    let recorded = config
        .record_inbound_join_request(
            "mesh-home",
            "wrong-secret",
            &requester,
            "alice-phone",
            1_726_000_000,
        )
        .expect("record join request");

    assert!(recorded.is_none());
    assert!(config.networks[0].inbound_join_requests.is_empty());
}

#[test]
fn reject_inbound_join_request_removes_matching_request() {
    let requester = Keys::generate().public_key().to_hex();
    let other = Keys::generate().public_key().to_hex();
    let mut config = AppConfig::generated();
    let network_id = config.networks[0].id.clone();
    config.networks[0].network_id = "mesh-home".to_string();
    let join_secret = config.networks[0].join_secret.clone();

    config
        .record_inbound_join_request(
            "mesh-home",
            &join_secret,
            &requester,
            "alice-phone",
            1_726_000_000,
        )
        .expect("record requester");
    config
        .record_inbound_join_request(
            "mesh-home",
            &join_secret,
            &other,
            "bob-phone",
            1_726_000_001,
        )
        .expect("record other");

    config
        .reject_inbound_join_request(&network_id, &requester)
        .expect("reject join request");

    assert_eq!(config.networks[0].inbound_join_requests.len(), 1);
    assert_eq!(config.networks[0].inbound_join_requests[0].requester, other);
}
