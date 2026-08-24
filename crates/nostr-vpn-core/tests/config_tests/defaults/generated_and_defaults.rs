#[test]
fn default_relays_match_hashtree_defaults() {
    assert!(DEFAULT_RELAYS.is_empty());
}

#[test]
fn generated_config_auto_populates_keys() {
    let config = AppConfig::generated();

    assert!(!config.nostr.secret_key.is_empty());
    assert!(!config.nostr.public_key.is_empty());
    assert!(!config.node_name.trim().is_empty());
    assert_ne!(config.node_name, "nostr-vpn-node");
    assert!(config.nostr.relays.is_empty());
    assert!(config.nostr.disabled_relays.is_empty());
    assert!(config.autoconnect);
    assert!(config.lan_discovery_enabled);
    assert!(config.launch_on_startup);
    assert!(config.close_to_tray_on_close);
    assert!(config.nat.enabled);
    assert!(!config.nat.stun_servers.is_empty());
    assert!(config.exit_node.is_empty());
    assert!(!config.exit_node_leak_protection);
    assert!(!config.fips_host_tunnel_enabled);
    assert!(!config.fips_advertise_public_endpoint);
    assert!(!config.connect_to_non_roster_fips_peers);
    assert!(config.fips_host_inbound_tcp_ports.is_empty());
    assert!(!config.node.advertise_exit_node);
    assert!(config.node.advertised_routes.is_empty());
    assert!(config.node.connected_udp.is_default());
    assert_eq!(config.node.connected_udp.enabled, None);
    assert!(config.effective_advertised_routes().is_empty());
    assert_eq!(config.enabled_network_count(), 0);
    assert!(!config.networks[0].enabled);
    assert!(config.effective_network_id().is_empty());
    assert_eq!(config.networks[0].network_id.len(), 8);
    assert!(
        config.networks[0]
            .network_id
            .chars()
            .all(|ch| ch.is_ascii_hexdigit())
    );
    assert!(!config.networks[0].join_secret.is_empty());
}

#[test]
fn connected_udp_defaults_do_not_serialize() {
    let config = AppConfig::generated();
    let encoded = toml::to_string(&config).expect("serialize config");

    assert!(!encoded.contains("connected_udp"));
}

#[test]
fn connected_udp_overrides_round_trip() {
    let config: AppConfig = toml::from_str(
        r#"
[node.connected_udp]
enabled = false
fd_reserve = 512
"#,
    )
    .expect("parse connected udp config");

    assert_eq!(config.node.connected_udp.enabled, Some(false));
    assert_eq!(config.node.connected_udp.fd_reserve, Some(512));

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("[node.connected_udp]"));
    assert!(encoded.contains("enabled = false"));
    assert!(encoded.contains("fd_reserve = 512"));
}

#[test]
fn fips_public_endpoint_advertise_accepts_legacy_config_key() {
    let config: AppConfig =
        toml::from_str("fips_advertise_endpoint = false").expect("parse config");

    assert!(!config.fips_advertise_public_endpoint);
}

#[test]
fn fips_public_endpoint_advertise_defaults_off_when_missing() {
    let config: AppConfig = toml::from_str("").expect("parse empty config");

    assert!(!config.fips_advertise_public_endpoint);
}

#[test]
fn fips_public_endpoint_advertise_serializes_new_config_key() {
    let mut config = AppConfig::generated();
    config.fips_advertise_public_endpoint = true;

    let encoded = toml::to_string(&config).expect("serialize config");

    assert!(encoded.contains("fips_advertise_public_endpoint = true"));
    assert!(!encoded.contains("fips_advertise_endpoint = true"));
}

#[test]
fn mesh_mtu_experiment_fields_load_but_do_not_serialize() {
    let config: AppConfig = toml::from_str(
        r#"
mesh_mtu_profile = "lan"
mesh_underlay_udp_mtu = 1420
mesh_tunnel_mtu = 1290
"#,
    )
    .expect("parse config with legacy mtu experiment fields");

    assert_eq!(config.mesh_mtu_profile, "lan");
    assert_eq!(config.mesh_underlay_udp_mtu, 1420);
    assert_eq!(config.mesh_tunnel_mtu, 1290);

    let encoded = toml::to_string(&config).expect("serialize config");

    assert!(!encoded.contains("mesh_mtu_profile"));
    assert!(!encoded.contains("mesh_underlay_udp_mtu"));
    assert!(!encoded.contains("mesh_tunnel_mtu"));
}

#[test]
fn fips_discovery_defaults_on_with_public_native_bootstrap_peers() {
    let config = AppConfig::generated();

    assert!(config.fips_nostr_discovery_enabled);
    assert!(!config.fips_webrtc_enabled);
    assert!(config.fips_bootstrap_enabled);
    assert_eq!(config.fips_bootstrap_peers.len(), 2);
    assert_eq!(config.fips_bootstrap_peer_endpoints().len(), 2);
}

#[test]
fn fips_webrtc_is_explicitly_opt_in_and_round_trips() {
    let default_config: AppConfig = toml::from_str("").expect("parse empty config");
    assert!(!default_config.fips_webrtc_enabled);
    assert!(!toml::to_string(&default_config)
        .expect("serialize default config")
        .contains("fips_webrtc_enabled"));

    let enabled = AppConfig {
        fips_webrtc_enabled: true,
        ..AppConfig::default()
    };
    let encoded = toml::to_string(&enabled).expect("serialize enabled config");
    assert!(encoded.contains("fips_webrtc_enabled = true"));
    let decoded: AppConfig = toml::from_str(&encoded).expect("parse enabled config");
    assert!(decoded.fips_webrtc_enabled);
    assert!(decoded.fips_nostr_discovery_enabled);
}

#[test]
fn fips_bootstrap_peers_are_public_editable_and_resettable() {
    let mut config = AppConfig::generated();
    assert_eq!(DEFAULT_FIPS_BOOTSTRAP_PEERS.len(), 2);
    assert_eq!(config.fips_bootstrap_peers.len(), 2);

    // Editable: replacing the list normalizes keys to npub, keeps non-empty
    // addresses, and drops entries with an invalid pubkey key.
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8".to_string(),
        vec!["tcp:45.79.10.10:443".to_string(), "  ".to_string()],
    );
    custom.insert(
        "not-a-valid-pubkey".to_string(),
        vec!["45.79.10.11:2121".to_string()],
    );
    config.set_fips_bootstrap_peers(custom);
    assert_eq!(config.fips_bootstrap_peers.len(), 1);
    let addrs = config.fips_bootstrap_peer_endpoints();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].1, vec!["tcp:45.79.10.10:443".to_string()]);

    // Editing persists across a serialize/load round trip.
    let encoded = toml::to_string(&config).expect("serialize");
    let decoded: AppConfig = toml::from_str(&encoded).expect("parse");
    assert_eq!(decoded.fips_bootstrap_peers.len(), 1);

    // Resettable to the public native UDP seed default.
    config.reset_fips_bootstrap_peers();
    assert_eq!(config.fips_bootstrap_peers, default_fips_bootstrap_peers());
}

#[test]
fn fips_bootstrap_disabled_yields_no_peers() {
    let config = AppConfig {
        fips_bootstrap_enabled: false,
        ..AppConfig::default()
    };

    assert!(config.fips_bootstrap_peer_endpoints().is_empty());
}

#[test]
fn fips_discovery_off_and_default_bootstrap_round_trip() {
    let config = AppConfig {
        fips_nostr_discovery_enabled: false,
        fips_bootstrap_enabled: true,
        ..AppConfig::default()
    };

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("fips_nostr_discovery_enabled = false"));
    assert!(!encoded.contains("fips_bootstrap_enabled"));

    let decoded: AppConfig = toml::from_str(&encoded).expect("parse config");
    assert!(!decoded.fips_nostr_discovery_enabled);
    assert!(decoded.fips_bootstrap_enabled);
}

#[test]
fn fips_bootstrap_opt_out_round_trip() {
    let config = AppConfig {
        fips_bootstrap_enabled: false,
        ..AppConfig::default()
    };

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("fips_bootstrap_enabled = false"));

    let decoded: AppConfig = toml::from_str(&encoded).expect("parse config");
    assert!(!decoded.fips_bootstrap_enabled);
    assert!(decoded.fips_bootstrap_peer_endpoints().is_empty());
}

#[test]
fn fips_discovery_and_bootstrap_default_on_when_missing() {
    let config: AppConfig = toml::from_str("").expect("parse empty config");

    assert!(config.fips_nostr_discovery_enabled);
    assert!(config.fips_bootstrap_enabled);
    assert!(!config.connect_to_non_roster_fips_peers);
}

#[test]
fn fips_non_roster_peer_opt_in_round_trips() {
    let config = AppConfig {
        connect_to_non_roster_fips_peers: true,
        ..AppConfig::default()
    };

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("connect_to_non_roster_fips_peers = true"));

    let decoded: AppConfig = toml::from_str(&encoded).expect("parse config");
    assert!(decoded.connect_to_non_roster_fips_peers);
}

#[test]
fn fips_host_tunnel_is_default_off_but_opt_in_persists() {
    let default_config: AppConfig = toml::from_str("").expect("parse empty config");
    assert!(!default_config.fips_host_tunnel_enabled);

    let config = AppConfig {
        fips_host_tunnel_enabled: true,
        ..AppConfig::default()
    };

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("fips_host_tunnel_enabled = true"));

    let decoded: AppConfig = toml::from_str(&encoded).expect("parse config");
    assert!(decoded.fips_host_tunnel_enabled);
}

#[test]
fn fips_host_inbound_ports_are_normalized() {
    let mut config = AppConfig {
        fips_host_inbound_tcp_ports: vec![443, 22, 22],
        ..AppConfig::default()
    };

    config.ensure_defaults();

    assert_eq!(config.fips_host_inbound_tcp_ports, vec![22, 443]);
}

#[test]
fn exit_node_leak_protection_defaults_off_when_missing() {
    let config: AppConfig = toml::from_str("").expect("parse empty config");

    assert!(!config.exit_node_leak_protection);
}

#[test]
fn exit_node_leak_protection_on_is_preserved() {
    let config = AppConfig {
        exit_node_leak_protection: true,
        ..AppConfig::default()
    };

    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(encoded.contains("exit_node_leak_protection = true"));

    let decoded: AppConfig = toml::from_str(&encoded).expect("parse config");
    assert!(decoded.exit_node_leak_protection);
}

#[test]
fn magic_dns_suffix_is_fixed_and_not_serialized() {
    let mut config: AppConfig =
        toml::from_str(r#"magic_dns_suffix = "custom.test""#).expect("parse legacy suffix");

    config.ensure_defaults();

    assert_eq!(config.magic_dns_suffix, "nvpn");
    let encoded = toml::to_string(&config).expect("serialize config");
    assert!(!encoded.contains("magic_dns_suffix"));
}

#[test]
fn generated_config_can_start_without_networks() {
    let mut config = AppConfig::generated_without_networks();

    assert!(config.networks.is_empty());
    config.ensure_defaults();

    assert!(config.networks.is_empty());
    assert!(config.effective_network_id().is_empty());
    assert!(config.enabled_network_meshes().is_empty());
    assert!(config.participant_pubkeys_hex().is_empty());
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
