#[test]
fn daemon_peer_age_secs_rejects_far_future_timestamp() {
    assert_eq!(daemon_peer_age_secs(120, 119), Some(1));
    assert_eq!(daemon_peer_age_secs(120, 122), Some(0));
    assert_eq!(daemon_peer_age_secs(120, 180), None);
}

#[test]
fn daemon_peer_transport_labels_routed_peers_as_via_mesh() {
    assert_eq!(daemon_peer_transport_label(true, "", ""), "via mesh");
    assert_eq!(
        daemon_peer_transport_label(true, "relayed", "ignored"),
        "via mesh"
    );
    assert_eq!(daemon_peer_transport_label(false, "", ""), "pending");
    assert_eq!(
        daemon_peer_transport_label(true, "ethernet", "02996cffb087"),
        "ethernet 02996cffb087"
    );
}

#[test]
fn fips_runtime_state_counts_direct_roster_and_other_peers() {
    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    let roster_peer = Keys::generate().public_key().to_hex();
    let routed_roster_peer = Keys::generate().public_key().to_hex();
    let other_peer = Keys::generate().public_key().to_hex();
    config.networks[0].devices = vec![roster_peer.clone(), routed_roster_peer.clone()];
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    let fips_peer_statuses = [
        MeshPeerStatus {
            pubkey: roster_peer,
            connected: true,
            endpoint_npub: "npub1roster".to_string(),
            transport_addr: Some("203.0.113.8:9000".to_string()),
            transport_type: Some("udp".to_string()),
            srtt_ms: Some(5),
            srtt_age_ms: Some(50),
            link_packets_sent: 0,
            link_packets_recv: 0,
            link_bytes_sent: 0,
            link_bytes_recv: 0,
            rekey_in_progress: true,
            rekey_draining: true,
            current_k_bit: Some(true),
            last_outbound_route: Some("fallback-route".to_string()),
            direct_probe_pending: false,
            direct_probe_after_ms: None,
            direct_probe_retry_count: 0,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: None,
            nostr_traversal_consecutive_failures: 4,
            nostr_traversal_in_cooldown: true,
            nostr_traversal_cooldown_until_ms: Some(123_456),
            nostr_traversal_last_observed_skew_ms: Some(-125),
            last_seen_at: Some(100),
            last_control_seen_at: Some(90),
            last_data_seen_at: Some(100),
            tx_bytes: 0,
            rx_bytes: 0,
            error: None,
        },
        MeshPeerStatus {
            pubkey: routed_roster_peer,
            connected: true,
            endpoint_npub: "npub1routed".to_string(),
            transport_addr: None,
            transport_type: None,
            srtt_ms: Some(8),
            srtt_age_ms: Some(80),
            link_packets_sent: 0,
            link_packets_recv: 0,
            link_bytes_sent: 0,
            link_bytes_recv: 0,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: false,
            direct_probe_after_ms: None,
            direct_probe_retry_count: 0,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: None,
            nostr_traversal_consecutive_failures: 0,
            nostr_traversal_in_cooldown: false,
            nostr_traversal_cooldown_until_ms: None,
            nostr_traversal_last_observed_skew_ms: None,
            last_seen_at: Some(100),
            last_control_seen_at: Some(90),
            last_data_seen_at: Some(100),
            tx_bytes: 0,
            rx_bytes: 0,
            error: None,
        },
        MeshPeerStatus {
            pubkey: other_peer,
            connected: true,
            endpoint_npub: "npub1other".to_string(),
            transport_addr: Some("203.0.113.9:9000".to_string()),
            transport_type: Some("udp".to_string()),
            srtt_ms: Some(13),
            srtt_age_ms: Some(130),
            link_packets_sent: 0,
            link_packets_recv: 0,
            link_bytes_sent: 0,
            link_bytes_recv: 0,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: false,
            direct_probe_after_ms: None,
            direct_probe_retry_count: 0,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: None,
            nostr_traversal_consecutive_failures: 0,
            nostr_traversal_in_cooldown: false,
            nostr_traversal_cooldown_until_ms: None,
            nostr_traversal_last_observed_skew_ms: None,
            last_seen_at: Some(100),
            last_control_seen_at: Some(90),
            last_data_seen_at: Some(100),
            tx_bytes: 0,
            rx_bytes: 0,
            error: None,
        },
    ];

    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: true,
        expected_peers: 2,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &fips_peer_statuses,
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "VPN on",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });

    assert_eq!(state.connected_peer_count, 2);
    assert_eq!(state.fips_direct_roster_peer_count, 1);
    assert_eq!(state.fips_other_peer_count, 1);
    let rekey_peer = state
        .peers
        .iter()
        .find(|peer| peer.fips_endpoint_npub == "npub1roster")
        .expect("roster peer status");
    assert!(rekey_peer.fips_rekey_in_progress);
    assert!(rekey_peer.fips_rekey_draining);
    assert_eq!(rekey_peer.fips_current_k_bit, Some(true));
    assert_eq!(rekey_peer.fips_last_outbound_route, "fallback-route");
    assert_eq!(rekey_peer.fips_nostr_traversal_failures, 4);
    assert!(rekey_peer.fips_nostr_traversal_in_cooldown);
    assert_eq!(
        rekey_peer.fips_nostr_traversal_cooldown_until_ms,
        Some(123_456)
    );
    assert_eq!(
        rekey_peer.fips_nostr_traversal_last_observed_skew_ms,
        Some(-125)
    );
    assert_eq!(rekey_peer.last_fips_control_seen_at, Some(90));
    assert_eq!(rekey_peer.last_fips_data_seen_at, Some(100));
}

#[test]
fn daemon_runtime_state_marks_peers_unreachable_when_vpn_is_off() {
    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    let peer_pubkey = Keys::generate().public_key().to_hex();
    config.networks[0].devices = vec![peer_pubkey.clone()];
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    let peer_status = MeshPeerStatus {
        pubkey: peer_pubkey,
        connected: true,
        endpoint_npub: "npub1endpoint".to_string(),
        transport_addr: Some("127.0.0.1:9000".to_string()),
        transport_type: Some("loopback".to_string()),
        srtt_ms: Some(3),
        srtt_age_ms: Some(30),
        link_packets_sent: 10,
        link_packets_recv: 11,
        link_bytes_sent: 120,
        link_bytes_recv: 130,
        rekey_in_progress: false,
        rekey_draining: false,
        current_k_bit: None,
        last_outbound_route: None,
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        nostr_traversal_consecutive_failures: 0,
        nostr_traversal_in_cooldown: false,
        nostr_traversal_cooldown_until_ms: None,
        nostr_traversal_last_observed_skew_ms: None,
        last_seen_at: Some(100),
        last_control_seen_at: Some(90),
        last_data_seen_at: Some(100),
        tx_bytes: 200,
        rx_bytes: 300,
        error: None,
    };

    let fips_peer_statuses = [peer_status];
    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: false,
        vpn_active: false,
        expected_peers: 1,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &fips_peer_statuses,
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "Paused",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });

    assert!(!state.vpn_active);
    assert!(!state.vpn_enabled);
    assert_eq!(state.connected_peer_count, 0);
    assert_eq!(state.fips_other_peer_count, 0);
    assert!(!state.mesh_ready);
    assert_eq!(state.peers.len(), 1);
    assert!(!state.peers[0].reachable);
    assert!(state.peers[0].runtime_endpoint.is_none());

    config.networks[0].devices.clear();
    let pre_pairing = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: false,
        expected_peers: 0,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &fips_peer_statuses,
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "Waiting for approval",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });
    assert_eq!(pre_pairing.connected_peer_count, 0);
    assert_eq!(pre_pairing.fips_other_peer_count, 1);
}

#[test]
fn macos_route_delete_error_is_absent_matches_missing_route_output() {
    assert!(macos_route_delete_error_is_absent(
        "command failed: route -n delete -ifscope utun100 default\nstdout: not in table\nstderr:"
    ));
    assert!(macos_route_delete_error_is_absent(
        "command failed: route -n delete -ifscope utun100 -net 0.0.0.0/1\nstdout: route: bad interface name\nstderr:"
    ));
    assert!(macos_route_delete_error_is_absent(
        "command failed: route -n delete -host 203.0.113.8\nstdout:\nstderr: route: writing to routing socket: No such process"
    ));
    assert!(!macos_route_delete_error_is_absent(
        "command failed: route -n delete -host 203.0.113.8\nstdout:\nstderr: permission denied"
    ));
}

#[test]
fn macos_route_monitor_observes_route_and_interface_changes() {
    let mut route_add = [0_u8; 4];
    route_add[3] = 0x01;
    assert!(crate::macos_network::macos_route_message_is_underlay_relevant(
        &route_add
    ));

    let mut route_delete = [0_u8; 4];
    route_delete[3] = 0x02;
    assert!(crate::macos_network::macos_route_message_is_underlay_relevant(
        &route_delete
    ));

    let mut route_change = [0_u8; 4];
    route_change[3] = 0x03;
    assert!(crate::macos_network::macos_route_message_is_underlay_relevant(
        &route_change
    ));

    let mut new_addr = [0_u8; 4];
    new_addr[3] = 0x0c;
    assert!(crate::macos_network::macos_route_message_is_underlay_relevant(
        &new_addr
    ));

    let mut if_info = [0_u8; 4];
    if_info[3] = 0x0e;
    assert!(crate::macos_network::macos_route_message_is_underlay_relevant(
        &if_info
    ));
}

#[test]
fn macos_tunnel_default_route_cleanup_targets_only_split_defaults() {
    assert_eq!(
        crate::macos_network::macos_tunnel_default_route_targets(),
        &["0.0.0.0/1", "128.0.0.0/1"]
    );
    assert!(!crate::macos_network::macos_tunnel_default_route_targets()
        .contains(&"0.0.0.0/0"));
}

#[test]
fn macos_paid_exit_endpoint_bypass_targets_are_deterministic_host_routes() {
    let hosts = vec![
        "65.109.48.91".parse().unwrap(),
        "203.0.113.7".parse().unwrap(),
        "65.109.48.91".parse().unwrap(),
    ];

    assert_eq!(
        crate::macos_network::macos_endpoint_bypass_targets_for_hosts(&hosts),
        vec!["203.0.113.7/32", "65.109.48.91/32"]
    );
}

#[test]
fn broad_fips_routes_require_endpoint_bypass() {
    assert!(!crate::route_targets_require_endpoint_bypass(&[
        "10.44.1.2/32".to_string(),
        "fd00::1/128".to_string(),
    ]));
    assert!(crate::route_targets_require_endpoint_bypass(&[
        "10.44.1.0/24".to_string(),
    ]));
    assert!(crate::route_targets_require_endpoint_bypass(&[
        "0.0.0.0/0".to_string(),
    ]));
}

#[test]
fn macos_interface_names_from_ifconfig_list_parses_interfaces() {
    assert_eq!(
        crate::macos_network::macos_interface_names_from_ifconfig_list(
            "lo0 gif0 stf0 anpi0 en0 en1 utun0 utun100\n"
        ),
        vec![
            "lo0", "gif0", "stf0", "anpi0", "en0", "en1", "utun0", "utun100"
        ]
    );
}

#[test]
fn macos_ipconfig_router_from_output_parses_ip_and_ip_mult_formats() {
    assert_eq!(
        crate::macos_network::macos_ipconfig_router_from_output("router (ip): 192.168.64.1\n"),
        Some("192.168.64.1".parse().unwrap())
    );
    assert_eq!(
        crate::macos_network::macos_ipconfig_router_from_output(
            "router (ip_mult): {192.168.64.1}\n"
        ),
        Some("192.168.64.1".parse().unwrap())
    );
}

#[test]
fn macos_tunnel_ipv4_netmask_uses_host_route() {
    assert_eq!(crate::macos_tunnel_ipv4_netmask(), "255.255.255.255");
}
