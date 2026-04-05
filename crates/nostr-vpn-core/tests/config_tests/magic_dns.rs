use super::*;

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
fn self_magic_dns_name_uses_node_name_and_resolves_to_own_pubkey() {
    let own = Keys::generate();
    let own_hex = own.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex.clone();
    config.node_name = "My Pocket Router".to_string();
    config.ensure_defaults();

    assert_eq!(
        config.self_magic_dns_label().as_deref(),
        Some("my-pocket-router")
    );
    assert_eq!(
        config.self_magic_dns_name().as_deref(),
        Some("my-pocket-router.nvpn")
    );
    assert_eq!(
        config.resolve_magic_dns_query("my-pocket-router"),
        Some(own_hex.clone())
    );
    assert_eq!(
        config.resolve_magic_dns_query("my-pocket-router.nvpn"),
        Some(own_hex)
    );
}

#[test]
fn self_magic_dns_label_keeps_node_name_and_suffixes_colliding_peer_aliases() {
    let own = Keys::generate();
    let peer = Keys::generate();
    let own_hex = own.public_key().to_hex();
    let peer_hex = peer.public_key().to_hex();

    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own_hex;
    config.node_name = "Home Server".to_string();
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.ensure_defaults();

    let assigned_peer_alias = config
        .set_peer_alias(&peer_hex, "home-server")
        .expect("set colliding alias");

    assert_eq!(
        config.self_magic_dns_name().as_deref(),
        Some("home-server.nvpn")
    );
    assert_eq!(assigned_peer_alias, "home-server-2");
    assert_eq!(
        config.peer_alias(&peer_hex).as_deref(),
        Some("home-server-2")
    );
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.exit_node = peer_hex.clone();
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
    set_default_network_participants(&mut config, vec![peer_hex.clone()]);
    config.exit_node = peer_hex.clone();
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
