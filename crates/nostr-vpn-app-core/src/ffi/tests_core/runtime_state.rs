    #[test]
    fn remove_network_allows_returning_to_setup() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-remove-last-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        let network_id = runtime.config.networks[0].id.clone();
        runtime.config.clear_pending_nostr_join_request();
        runtime
            .config
            .save(&runtime.config_path)
            .expect("persist completed prior join");

        runtime.dispatch(NativeAppAction::RemoveNetwork { network_id });

        let state = runtime.state();
        assert!(state.error.is_empty(), "{}", state.error);
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());
        assert!(state.join_request_qr_code_or_link.starts_with("nvpn://join-request/"));
        assert_eq!(state.expected_peer_count, 0);

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks.is_empty());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(saved.pending_nostr_join_request.is_none());
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert!(saved.pending_nostr_join_request.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn inactive_saved_network_actions_are_real_config_mutations() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-saved-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let peer = Keys::generate();
        let peer_hex = peer.public_key().to_hex();
        let peer_npub = peer.public_key().to_bech32().expect("peer npub");
        let admin_one = Keys::generate();
        let admin_one_hex = admin_one.public_key().to_hex();
        let admin_one_npub = admin_one.public_key().to_bech32().expect("admin one npub");
        let admin_two = Keys::generate();
        let admin_two_hex = admin_two.public_key().to_hex();
        let admin_two_npub = admin_two.public_key().to_bech32().expect("admin two npub");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        let active_id = create_test_network(&mut runtime, "Home");
        let saved_id = create_test_network(&mut runtime, "Work");
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        runtime
            .config
            .network_by_id_mut(&saved_id)
            .expect("saved network")
            .admins
            .push(own_pubkey);
        assert!(
            runtime
                .config
                .network_by_id(&active_id)
                .expect("active network")
                .enabled
        );
        assert!(
            !runtime
                .config
                .network_by_id(&saved_id)
                .expect("saved network")
                .enabled
        );
        runtime.dispatch(NativeAppAction::RenameNetwork {
            network_id: saved_id.clone(),
            name: "Office".to_string(),
        });
        runtime.dispatch(NativeAppAction::SetNetworkMeshId {
            network_id: saved_id.clone(),
            mesh_id: "ABCD-1234-EF56".to_string(),
        });
        runtime.dispatch(NativeAppAction::SetNetworkJoinRequestsEnabled {
            network_id: saved_id.clone(),
            enabled: true,
        });
        assert!(
            runtime.daemon_running,
            "mobile join listening should activate the mobile tunnel"
        );
        runtime.dispatch(NativeAppAction::AddParticipant {
            network_id: saved_id.clone(),
            npub: peer_npub.clone(),
            alias: Some("Desk Peer".to_string()),
        });
        assert!(
            runtime.last_error.is_empty(),
            "active mobile tunnel save used the desktop service: {}",
            runtime.last_error
        );
        runtime.dispatch(NativeAppAction::AddAdmin {
            network_id: saved_id.clone(),
            npub: admin_one_npub.clone(),
        });
        runtime.dispatch(NativeAppAction::AddAdmin {
            network_id: saved_id.clone(),
            npub: admin_two_npub.clone(),
        });
        runtime.dispatch(NativeAppAction::SetParticipantAlias {
            npub: peer_npub.clone(),
            alias: "Renamed Peer".to_string(),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let state = runtime.state();
        let saved_state = state
            .networks
            .iter()
            .find(|network| network.id == saved_id)
            .expect("saved network state");
        assert!(!saved_state.enabled);
        assert_eq!(saved_state.name, "Office");
        assert_eq!(saved_state.network_id, "abcd1234ef56");
        assert!(saved_state.join_requests_enabled);
        let peer_state = saved_state
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer_hex)
            .expect("peer participant state");
        assert_eq!(peer_state.magic_dns_alias, "renamed-peer");

        let saved_config = runtime
            .config
            .network_by_id(&saved_id)
            .expect("saved network config");
        assert_eq!(saved_config.name, "Office");
        assert_eq!(saved_config.network_id, "abcd1234ef56");
        assert!(saved_config.listen_for_join_requests);
        assert!(saved_config.devices.contains(&peer_hex));
        assert!(saved_config.admins.contains(&admin_one_hex));
        assert!(saved_config.admins.contains(&admin_two_hex));
        assert_eq!(
            runtime.config.peer_alias(&peer_hex).as_deref(),
            Some("renamed-peer")
        );

        runtime.dispatch(NativeAppAction::RemoveAdmin {
            network_id: saved_id.clone(),
            npub: admin_one_npub,
        });
        runtime.dispatch(NativeAppAction::RemoveParticipant {
            network_id: saved_id.clone(),
            npub: peer_npub,
        });
        runtime.dispatch(NativeAppAction::SetNetworkEnabled {
            network_id: saved_id.clone(),
            enabled: true,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let saved_config = runtime
            .config
            .network_by_id(&saved_id)
            .expect("saved network config");
        assert!(saved_config.enabled);
        assert!(!saved_config.devices.contains(&peer_hex));
        assert!(!saved_config.admins.contains(&admin_one_hex));
        assert!(saved_config.admins.contains(&admin_two_hex));
        assert!(
            !runtime
                .config
                .network_by_id(&active_id)
                .expect("previously active network")
                .enabled
        );

        let persisted = AppConfig::load(&runtime.config_path).expect("load persisted config");
        let persisted_saved = persisted
            .network_by_id(&saved_id)
            .expect("persisted saved network");
        assert!(persisted_saved.enabled);
        assert_eq!(persisted_saved.name, "Office");
        assert_eq!(persisted_saved.network_id, "abcd1234ef56");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn connect_vpn_allows_a_pending_device_approval_without_a_network() {
        let dir = unique_service_test_dir("nvpn-pending-approval-connect");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("persist isolated mobile config");

        runtime.dispatch(NativeAppAction::ConnectVpn);
        let state = runtime.state();

        assert!(state.error.is_empty(), "{}", state.error);
        assert!(state.vpn_enabled);
        assert!(state.vpn_active);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn manual_join_starts_the_approval_transport() {
        let dir = unique_service_test_dir("nvpn-manual-join-connect");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("persist isolated mobile config");
        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");

        runtime.dispatch(NativeAppAction::ManualAddNetwork {
            admin_npub,
            mesh_network_id: "manual-join-mesh".to_string(),
        });
        let state = runtime.state();

        assert!(state.error.is_empty(), "{}", state.error);
        assert!(
            state.vpn_enabled,
            "manual join cannot receive the signed roster without the FIPS transport"
        );
        assert!(state.vpn_active);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_vpn_requires_a_network_or_pending_device_approval() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config.clear_pending_nostr_join_request();

        runtime.dispatch(NativeAppAction::ConnectVpn);
        let state = runtime.state();

        assert!(state.error.contains("Create or join a network first"));
        assert!(!state.vpn_enabled);
        assert!(!state.vpn_active);
    }

    #[test]
    fn native_counts_keep_peer_and_device_totals_separate() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime.config.networks[0].devices = vec![peer_pubkey.to_string()];

        let state = runtime.state();
        let network = &state.networks[0];

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 0);
        assert_eq!(network.expected_count, 2);
        assert_eq!(network.online_count, 0);
        assert_eq!(network.participants.len(), 2);
        assert!(network.participants.iter().any(|participant| {
            participant.pubkey_hex == own_pubkey
                && !participant.reachable
                && participant.state == "off"
                && participant.mesh_state == "off"
        }));
    }

    #[test]
    fn state_displays_default_self_magic_dns_name_without_persisting_alias() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.config.node_name = "Umbrel Box".to_string();
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];

        let state = runtime.state();
        let network = &state.networks[0];
        let self_participant = network
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == own_pubkey)
            .expect("self participant");

        assert_eq!(state.self_magic_dns_name, "umbrel-box.nvpn");
        assert_eq!(self_participant.magic_dns_name, "umbrel-box.nvpn");
        assert_eq!(runtime.config.peer_alias(&own_pubkey), None);
    }

    #[test]
    fn self_admin_alias_action_updates_network_state_for_ui_shells() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-self-alias-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime.config.networks[0].devices = Vec::new();

        runtime.dispatch(NativeAppAction::SetParticipantAlias {
            npub: npub_for_pubkey_hex(&own_pubkey),
            alias: "My iPhone".to_string(),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let state = runtime.state();
        let network = &state.networks[0];
        assert!(network.local_is_admin);
        let self_participant = network
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == own_pubkey)
            .expect("self participant");
        assert_eq!(self_participant.magic_dns_alias, "my-iphone");
        assert_eq!(self_participant.magic_dns_name, "my-iphone.nvpn");
        assert_eq!(state.self_magic_dns_name, "my-iphone.nvpn");

        let roster = runtime
            .config
            .shared_network_roster(&network.id)
            .expect("shared roster");
        assert_eq!(
            roster.aliases.get(&own_pubkey).map(String::as_str),
            Some("my-iphone")
        );

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(saved.peer_alias(&own_pubkey).as_deref(), Some("my-iphone"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn participant_endpoint_hint_action_updates_network_state_for_ui_shells() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-peer-hints-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let peer = Keys::generate();
        let peer_hex = peer.public_key().to_hex();
        let peer_npub = peer.public_key().to_bech32().expect("peer npub");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].devices = vec![peer_hex.clone()];

        runtime.dispatch(NativeAppAction::SetParticipantEndpointHints {
            npub: peer_npub.clone(),
            endpoint_hints: vec![
                "peer.example.com:51820".to_string(),
                " 192.168.1.23:51821 ".to_string(),
            ],
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let state = runtime.state();
        let participant = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer_hex)
            .expect("peer participant");
        assert_eq!(
            participant.fips_endpoint_hints,
            vec![
                "192.168.1.23:51821".to_string(),
                "peer.example.com:51820".to_string()
            ]
        );
        assert_eq!(state.fips_connected_peer_count, 0);
        assert_eq!(state.fips_roster_peer_count, 1);
        assert_eq!(state.non_fips_roster_peer_count, 0);

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(
            saved.fips_peer_endpoint_hints(&peer_npub),
            participant.fips_endpoint_hints
        );

        runtime.dispatch(NativeAppAction::SetParticipantEndpointHints {
            npub: peer_npub,
            endpoint_hints: Vec::new(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            runtime.state().networks[0]
                .participants
                .iter()
                .find(|participant| participant.pubkey_hex == peer_hex)
                .expect("peer participant")
                .fips_endpoint_hints
                .is_empty()
        );
        let state = runtime.state();
        assert_eq!(state.fips_roster_peer_count, 0);
        assert_eq!(state.non_fips_roster_peer_count, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_flags_blocked_exit_node_when_protection_is_enabled() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let exit_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        runtime.config.exit_node = exit_pubkey.to_string();
        runtime.config.exit_node_leak_protection = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![exit_pubkey.to_string()];
        runtime
            .config
            .set_peer_alias(exit_pubkey, "lab-exit")
            .unwrap();
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 0,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: exit_pubkey.to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                reachable: false,
                error: Some("fips link pending".to_string()),
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(
            state.exit_node_status_text,
            "Private exit · Blocked, waiting for lab-exit.nvpn"
        );
    }
