    #[test]
    fn settings_patch_enforces_exit_node_mutual_exclusion() {
        use nostr_sdk::prelude::{Keys, ToBech32};

        // Selecting a peer exit clears WG upstream, and selecting WG
        // upstream clears the peer exit — the daemon enforces this
        // so every UI can just push the new selection.
        let dir = unique_service_test_dir("nvpn-mutual-exit");

        let peer_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("peer npub");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        // Add the peer as a participant in the active network so the
        // ensure_defaults pass at save time doesn't clear our chosen
        // exit_node as "not a participant".
        if let Some(network) = runtime.config.networks.first_mut() {
            network.devices.push(peer_npub.clone());
        }

        // Start with WG upstream enabled.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(true),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        // Now push a peer exit. WG must clear.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node: Some(peer_npub.clone()),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(!runtime.config.wireguard_exit.enabled);
        assert_ne!(runtime.config.exit_node, "");

        // Flip back to WG: peer exit must clear.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(true),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        // Selecting Direct (clearing exit_node) leaves WG alone — the
        // user has to explicitly disable WG to go fully direct.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node: Some(String::new()),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_patch_persists_fips_controls() {
        let dir = unique_service_test_dir("nvpn-app-core-fips-host");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                fips_host_tunnel_enabled: Some(false),
                connect_to_non_roster_fips_peers: Some(false),
                fips_webrtc_enabled: Some(true),
                fips_host_inbound_tcp_ports: Some("443, 22, 22".to_string()),
                ..SettingsPatch::default()
            },
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(!saved.fips_host_tunnel_enabled);
        assert!(!saved.connect_to_non_roster_fips_peers);
        assert!(saved.fips_webrtc_enabled);
        assert_eq!(saved.fips_host_inbound_tcp_ports, vec![22, 443]);

        let state = runtime.state();
        assert!(!state.fips_host_tunnel_enabled);
        assert!(!state.connect_to_non_roster_fips_peers);
        assert!(state.fips_webrtc_enabled);
        assert_eq!(state.fips_host_inbound_tcp_ports, "22, 443");

        let _ = fs::remove_dir_all(&dir);
    }
