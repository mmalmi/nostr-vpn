    #[test]
    fn mobile_runtime_state_rejects_far_future_presence_without_link() {
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
                last_seen_at: Some(now + 60),
                last_control_seen_at: Some(now + 60),
                last_data_seen_at: Some(now + 60),
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
        assert_eq!(state.connected_peer_count, 0);
        assert!(!state.mesh_ready);
        assert!(!state.peers[0].reachable);
        assert_eq!(state.peers[0].last_mesh_seen_at, 0);
        assert_eq!(state.peers[0].last_fips_seen_at, None);
        assert_eq!(state.peers[0].last_fips_control_seen_at, None);
        assert_eq!(state.peers[0].last_fips_data_seen_at, None);
        assert_eq!(state.peers[0].last_handshake_at, None);
        assert_eq!(state.peers[0].error.as_deref(), Some("fips link pending"));
    }
