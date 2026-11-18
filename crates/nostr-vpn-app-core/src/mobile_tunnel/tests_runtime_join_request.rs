    #[test]
    fn mobile_admin_records_inbound_join_request_from_unknown_sender() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-join-request-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");

        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Home".to_string(),
            enabled: true,
            network_id: "mesh-home".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![own.clone()],
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
        let requester = Keys::generate().public_key().to_hex();
        let app_config = Arc::new(RwLock::new(app));
        let dirty = AtomicBool::new(false);
        let request = MeshJoinRequest {
            network_id: "mesh-home".to_string(),
            join_secret: "join-secret".to_string(),
            requester_node_name: "iPhone".to_string(),
        };

        assert!(
            record_mobile_join_request(
                &app_config,
                &dirty,
                Some(&config_path),
                &requester,
                1_778_998_000,
                &request,
            )
            .expect("record join request")
        );
        assert!(dirty.load(Ordering::Relaxed));

        let saved = AppConfig::load(&config_path).expect("load persisted config");
        assert_eq!(saved.networks[0].inbound_join_requests.len(), 1);
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester,
            requester
        );
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester_node_name,
            "iPhone"
        );
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requested_at,
            1_778_998_000
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
