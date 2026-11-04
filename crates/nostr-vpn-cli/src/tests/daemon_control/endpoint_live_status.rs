fn endpoint_live_sample(pubkey: &str) -> MeshPeerStatus {
    MeshPeerStatus {
        pubkey: pubkey.to_string(),
        connected: true,
        endpoint_npub: String::new(),
        transport_addr: Some("192.0.2.2:51820".to_string()),
        transport_type: Some("udp".to_string()),
        srtt_ms: None,
        srtt_age_ms: None,
        link_packets_sent: 11,
        link_packets_recv: 12,
        link_bytes_sent: 1100,
        link_bytes_recv: 1200,
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
        // These mesh/presence fields must not become link counters or freshness.
        last_seen_at: Some(123),
        last_control_seen_at: Some(120),
        last_data_seen_at: Some(122),
        tx_bytes: 9000,
        rx_bytes: 8000,
        error: None,
    }
}

fn endpoint_live_config(npub: String) -> DaemonFipsEndpointPeerState {
    DaemonFipsEndpointPeerState {
        npub,
        addresses: vec![DaemonFipsEndpointPeerAddressState {
            addr: "tcp://192.0.2.1:443".to_string(),
            seen_at_ms: Some(100),
            priority: 100,
        }],
        auto_reconnect: true,
        discovery_fallback_transit: true,
        live: None,
    }
}

fn endpoint_live_runtime_state(
    endpoints: &[DaemonFipsEndpointPeerState],
    samples: &[MeshPeerStatus],
) -> DaemonRuntimeState {
    let mut config = AppConfig::generated();
    config.networks[0].devices.clear();
    let tunnel_runtime = CliTunnelRuntime::new("test0");
    build_daemon_runtime_state(DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: false,
        vpn_active: false,
        expected_peers: 0,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: samples,
        fips_relay_statuses: &[],
        fips_endpoint_peers: endpoints,
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "Paused",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    })
}

#[test]
fn fips_endpoint_live_projects_normalized_key_sample_while_vpn_paused() {
    use nostr_sdk::prelude::ToBech32;

    let key = Keys::generate().public_key();
    let sample = endpoint_live_sample(&key.to_hex());
    for encoded in [key.to_hex(), key.to_bech32().unwrap()] {
        let configured = endpoint_live_config(encoded);
        let state = endpoint_live_runtime_state(
            std::slice::from_ref(&configured),
            std::slice::from_ref(&sample),
        );
        assert!(!state.vpn_active);
        assert_eq!(state.connected_peer_count, 0);
        assert_eq!(state.fips_other_peer_count, 1);
        assert!(state.peers.is_empty());
        let endpoint = &state.fips_endpoint_peers[0];
        assert_eq!(endpoint.npub, configured.npub);
        assert_eq!(endpoint.addresses, configured.addresses);
        assert!(endpoint.auto_reconnect);
        assert!(endpoint.discovery_fallback_transit);
        assert!(
            configured.live.is_none(),
            "projection must not mutate config"
        );
        assert_eq!(
            serde_json::to_value(&endpoint.live).unwrap(),
            serde_json::json!({
                "connected": true,
                "transport_addr": "192.0.2.2:51820",
                "transport_type": "udp",
                "packets_sent": 11,
                "packets_recv": 12,
                "bytes_sent": 1100,
                "bytes_recv": 1200
            })
        );
        let encoded = serde_json::to_value(&state).unwrap();
        let decoded: DaemonRuntimeState = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.fips_endpoint_peers, state.fips_endpoint_peers);
    }
}

#[test]
fn fips_endpoint_live_requires_matching_sample_and_drops_previous_projection() {
    let key = Keys::generate().public_key().to_hex();
    let sample = endpoint_live_sample(&key);
    let configured = endpoint_live_config(key);
    let previous = endpoint_live_runtime_state(&[configured], &[sample]);
    assert!(previous.fips_endpoint_peers[0].live.is_some());

    let missing = endpoint_live_runtime_state(&previous.fips_endpoint_peers, &[]);
    let unrelated = endpoint_live_sample(&Keys::generate().public_key().to_hex());
    let mismatched = endpoint_live_runtime_state(&previous.fips_endpoint_peers, &[unrelated]);
    let invalid = endpoint_live_runtime_state(
        &[endpoint_live_config("invalid-npub".to_string())],
        &[endpoint_live_sample("invalid-npub")],
    );
    for state in [missing, mismatched, invalid] {
        let endpoint = &state.fips_endpoint_peers[0];
        assert!(endpoint.live.is_none());
        assert!(
            serde_json::to_value(endpoint)
                .unwrap()
                .get("live")
                .is_none()
        );
        assert_eq!(endpoint.addresses[0].addr, "tcp://192.0.2.1:443");
    }
}

#[test]
fn fips_endpoint_live_preserves_pending_zeroes_and_counter_resets() {
    let key = Keys::generate().public_key().to_hex();
    let configured = endpoint_live_config(key.clone());
    let mut sample = endpoint_live_sample(&key);
    let previous = endpoint_live_runtime_state(&[configured], &[sample.clone()]);
    let repeated = endpoint_live_runtime_state(&previous.fips_endpoint_peers, &[sample.clone()]);
    assert_eq!(repeated.fips_endpoint_peers, previous.fips_endpoint_peers);

    sample.connected = false;
    sample.transport_addr = None;
    sample.transport_type = None;
    sample.link_packets_sent = 0;
    sample.link_packets_recv = 0;
    sample.link_bytes_sent = 0;
    sample.link_bytes_recv = 0;
    let reset = endpoint_live_runtime_state(&previous.fips_endpoint_peers, &[sample]);
    assert_eq!(
        serde_json::to_value(&reset.fips_endpoint_peers[0].live).unwrap(),
        serde_json::json!({
            "connected": false,
            "packets_sent": 0,
            "packets_recv": 0,
            "bytes_sent": 0,
            "bytes_recv": 0
        })
    );
}

#[test]
fn fips_endpoint_live_accepts_legacy_state_without_fabricating_partial_samples() {
    let legacy = serde_json::json!({"npub": "configured-seed"});
    let decoded: DaemonFipsEndpointPeerState = serde_json::from_value(legacy.clone()).unwrap();
    assert!(decoded.live.is_none());
    assert!(serde_json::to_value(decoded).unwrap().get("live").is_none());

    let mut incomplete = legacy;
    incomplete["live"] = serde_json::json!({"connected": false});
    assert!(serde_json::from_value::<DaemonFipsEndpointPeerState>(incomplete).is_err());
}
