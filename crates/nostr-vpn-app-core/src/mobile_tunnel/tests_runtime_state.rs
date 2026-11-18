    #[test]
    fn mobile_runtime_state_marks_authenticated_endpoint_peer_reachable() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = FipsMeshRuntime::with_local_routes(config.peers.clone(), vec![]);
        let endpoint_node_addr = *PeerIdentity::from_npub(&config.peers[0].endpoint_npub)
            .expect("endpoint identity")
            .node_addr();
        let endpoint_peer = FipsEndpointPeer {
            npub: config.peers[0].endpoint_npub.clone(),
            node_addr: endpoint_node_addr,
            connected: true,
            transport_addr: Some("192.168.50.10:51820".to_string()),
            transport_type: Some("udp".to_string()),
            link_id: 7,
            srtt_ms: Some(14),
            srtt_age_ms: Some(250),
            packets_sent: 3,
            packets_recv: 4,
            bytes_sent: 120,
            bytes_recv: 240,
            rekey_in_progress: true,
            rekey_draining: false,
            current_k_bit: Some(true),
            last_outbound_route: Some("direct".to_string()),
            direct_probe_pending: true,
            direct_probe_after_ms: Some(98_765),
            direct_probe_retry_count: 4,
            direct_probe_auto_reconnect: true,
            direct_probe_expires_at_ms: Some(123_456),
            nostr_traversal_consecutive_failures: 3,
            nostr_traversal_in_cooldown: true,
            nostr_traversal_cooldown_until_ms: Some(99_000),
            nostr_traversal_last_observed_skew_ms: Some(-75),
        };
        let other_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("other endpoint npub");
        let other_node_addr = *PeerIdentity::from_npub(&other_npub)
            .expect("other endpoint identity")
            .node_addr();
        let other_endpoint_peer = FipsEndpointPeer {
            npub: other_npub,
            node_addr: other_node_addr,
            ..endpoint_peer.clone()
        };

        let state = mobile_runtime_state_with_tun_counters(
            &config,
            &mesh,
            &HashMap::new(),
            vec![endpoint_peer, other_endpoint_peer],
            Vec::new(),
            MobileTunCounters::default(),
            1_778_998_000,
        );

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 1);
        assert_eq!(state.fips_direct_roster_peer_count, 1);
        assert_eq!(state.fips_other_peer_count, 1);
        assert!(state.mesh_ready);
        assert_eq!(state.peers[0].participant_pubkey, peer);
        assert!(state.peers[0].reachable);
        assert_eq!(state.peers[0].fips_transport_type, "udp");
        assert_eq!(state.peers[0].fips_srtt_ms, Some(14));
        assert_eq!(state.peers[0].fips_srtt_age_ms, Some(250));
        assert!(state.peers[0].direct_probe_pending);
        assert_eq!(state.peers[0].direct_probe_after_ms, Some(98_765));
        assert_eq!(state.peers[0].direct_probe_retry_count, 4);
        assert!(state.peers[0].direct_probe_auto_reconnect);
        assert_eq!(state.peers[0].direct_probe_expires_at_ms, Some(123_456));
        assert_eq!(state.peers[0].fips_nostr_traversal_failures, 3);
        assert!(state.peers[0].fips_nostr_traversal_in_cooldown);
        assert_eq!(
            state.peers[0].fips_nostr_traversal_cooldown_until_ms,
            Some(99_000)
        );
        assert_eq!(
            state.peers[0].fips_nostr_traversal_last_observed_skew_ms,
            Some(-75)
        );
    }

    #[test]
    fn mobile_runtime_state_marks_recent_control_presence_reachable_without_link() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = FipsMeshRuntime::with_local_routes(config.peers.clone(), vec![]);
        let now = 1_778_998_000;
        let mut presence = HashMap::new();
        presence.insert(
            peer.to_string(),
            MobilePeerPresence {
                last_seen_at: Some(now - 10),
                last_control_seen_at: Some(now - 10),
                last_data_seen_at: Some(now - 20),
                rtt_ms: Some(91),
                tx_bytes: 32,
                rx_bytes: 64,
                ..MobilePeerPresence::default()
            },
        );

        let state = mobile_runtime_state_with_tun_counters(
            &config,
            &mesh,
            &presence,
            Vec::new(),
            Vec::new(),
            MobileTunCounters::default(),
            now,
        );

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 1);
        assert!(state.mesh_ready);
        assert!(state.peers[0].reachable);
        assert_eq!(state.peers[0].fips_srtt_ms, Some(91));
        assert_eq!(state.peers[0].tx_bytes, 32);
        assert_eq!(state.peers[0].rx_bytes, 64);
        assert_eq!(state.peers[0].last_fips_seen_at, Some(now - 10));
        assert_eq!(state.peers[0].last_fips_control_seen_at, Some(now - 10));
        assert_eq!(state.peers[0].last_fips_data_seen_at, Some(now - 20));
    }
