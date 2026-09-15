    #[test]
    fn native_state_reports_active_exit_node_when_selected_peer_is_reachable() {
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
        runtime
            .config
            .set_internet_source(InternetSource::PrivateVpn);
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
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: exit_pubkey.to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        assert!(!state.exit_node_blocked);
        assert!(state.exit_node_active);
        assert_eq!(
            state.exit_node_status_text,
            "Private exit · lab-exit.nvpn · Connected"
        );
    }

    #[test]
    fn native_state_flags_wireguard_exit_blocking_without_advertising_exit() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = false;
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.exit_node_leak_protection = true;
        runtime.config.node.advertise_exit_node = false;
        runtime
            .config
            .set_internet_source(InternetSource::WireGuard);
        runtime.config.wireguard_exit.address = "10.64.70.195/32".to_string();
        runtime.config.wireguard_exit.private_key = "client-private".to_string();
        runtime.config.wireguard_exit.peer_public_key = "provider-public".to_string();
        runtime.config.wireguard_exit.endpoint = "vpn.example.test:51820".to_string();
        runtime.config.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];

        let state = runtime.state();
        assert!(state.wireguard_exit_enabled);
        assert!(state.wireguard_exit_configured);
        assert!(!state.advertise_exit_node);
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(
            state.exit_node_status_text,
            "WireGuard exit · Blocked"
        );

        runtime.vpn_active = true;
        let state = runtime.state();
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(state.exit_node_status_text, "WireGuard exit · Blocked");

        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            wireguard_exit_ready: true,
            ..DaemonRuntimeState::default()
        });
        let state = runtime.state();
        assert!(!state.exit_node_blocked);
        assert!(state.exit_node_active);
        assert_eq!(state.exit_node_status_text, "WireGuard exit · Connected");
    }

    #[test]
    fn reachable_paid_peer_is_pending_until_its_session_can_route() {
        let dir = unique_service_test_dir("nvpn-paid-exit-ui-readiness");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let exit_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.config_path = dir.join("config.toml");
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        runtime
            .config
            .set_internet_source(InternetSource::PaidManual);
        runtime.config.exit_node = exit_pubkey.to_string();
        runtime.config.exit_node_leak_protection = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![exit_pubkey.to_string()];
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: exit_pubkey.to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert!(state.exit_node_status_text.contains("waiting"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn native_state_only_blocks_pending_automatic_exit_when_leak_protection_is_enabled() {
        let dir = unique_service_test_dir("nvpn-pending-automatic-exit-state");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.config_path = dir.join("config.toml");
        runtime.startup_error = None;
        runtime.vpn_enabled = true;
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .set_internet_source(InternetSource::PaidAutomatic);

        let state = runtime.state();

        assert!(!state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(state.exit_node_status_text, "Automatic paid exit · Selecting provider");

        runtime.config.exit_node_leak_protection = true;
        let state = runtime.state();
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(
            state.exit_node_status_text,
            "Automatic paid exit · Blocked"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn native_state_distinguishes_direct_and_manual_paid_internet() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        create_test_network(&mut runtime, "Home");

        assert_eq!(runtime.state().exit_node_status_text, "Direct internet");

        runtime
            .config
            .set_internet_source(InternetSource::PaidManual);
        assert_eq!(
            runtime.state().exit_node_status_text,
            "Manual paid exit · Pending"
        );
    }

    #[test]
    fn automatic_exit_confirmation_tracks_selection_probe_and_live_connection() {
        use nostr_vpn_core::paid_route_store::{
            OpenPaidRouteBuyerSessionRequest, UpdatePaidRouteSessionProbeRequest,
            update_paid_route_store,
        };
        use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

        let dir = unique_service_test_dir("nvpn-automatic-exit-confirmation");
        let mut runtime = NativeAppRuntime::from_startup_error(&anyhow!("test"));
        runtime.startup_error = None;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Buyer");
        runtime.config.set_internet_source(InternetSource::PaidAutomatic);
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            ..DaemonRuntimeState::default()
        });
        assert_eq!(runtime.state().exit_node_status_text,
            "Automatic paid exit · Selecting provider");

        let seller = Keys::generate();
        let seller_hex = seller.public_key().to_hex();
        let seller_npub = seller.public_key().to_bech32().unwrap();
        let now = unix_timestamp();
        let mut offer_config = PaidExitConfig { enabled: true, ..PaidExitConfig::default() };
        offer_config.location.country_code = "IE".to_string();
        offer_config.pricing.price_msat_per_gb = 25_000;
        offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
        offer_config.channel.free_probe_units = 1_048_576;
        let signed = signed_paid_exit_offer_from_config(
            "internet-exit", &seller, &offer_config, None, now,
        ).unwrap();
        let session = update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.upsert_signed_offer(signed, Vec::new(), now)?;
            store.upsert_wallet_mint("https://mint.example", "Test mint", Some(10_000), now);
            store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                offer_selector: "internet-exit".to_string(),
                buyer_npub: runtime.config.nostr_keys()?.public_key().to_bech32()?,
                mint_url: Some("https://mint.example".to_string()),
                channel_capacity_sat: Some(10),
                initial_paid_msat: 0,
                now_unix: now,
            })
        }).unwrap();
        runtime.config.select_public_paid_exit_node(&seller_npub).unwrap();
        let provider_name = "IE · 25 sat/GB";
        let connecting = runtime.state();
        assert!(!connecting.exit_node_active);
        assert_eq!(connecting.exit_node_status_text,
            format!("Automatic paid exit · Selected {provider_name} · Connecting"));

        runtime.daemon_state.as_mut().unwrap().peers.push(DaemonPeerState {
            participant_pubkey: seller_hex.clone(),
            reachable: true,
            ..DaemonPeerState::default()
        });
        assert!(!runtime.state().exit_node_active, "connection alone is not success");
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.acknowledge_buyer_session_open(&seller_hex, &session.lease_id, now)?;
            Ok(())
        }).unwrap();
        assert!(!runtime.state().exit_node_active, "admission alone is not success");
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.update_session_probe(UpdatePaidRouteSessionProbeRequest {
                session_id: session.session_id.clone(),
                realized_exit_ip: Some("198.51.100.42".to_string()),
                observed_country_code: None,
                observed_asn: None,
                quality: None,
                now_unix: now,
            })?;
            Ok(())
        }).unwrap();

        let active = runtime.state();
        assert!(active.exit_node_active);
        assert!(!active.exit_node_blocked);
        assert_eq!(active.exit_node_status_text,
            format!("Automatic paid exit · {provider_name} · 198.51.100.42 · Active"));
        assert!(!active.networks[0].participants.iter()
            .any(|peer| peer.pubkey_hex == seller_hex), "seller remains outside the private roster");

        runtime.daemon_state.as_mut().unwrap().peers[0].reachable = false;
        assert!(!runtime.state().exit_node_active, "old probe must not hide disconnection");
        assert_eq!(runtime.state().exit_node_status_text, connecting.exit_node_status_text);
        runtime.config.exit_node_leak_protection = true;
        assert!(runtime.state().exit_node_blocked);
        runtime.daemon_state.as_mut().unwrap().peers[0].reachable = true;
        runtime.daemon_state.as_mut().unwrap().vpn_active = false;
        assert!(!runtime.state().exit_node_active, "stopped tunnel must not show success");

        assert_paid_exit_funding_status(&mut runtime, &session.session_id, &session.channel_id, now);
        runtime.config.exit_node_leak_protection = false;
        assert!(!runtime.state().exit_node_blocked);
        runtime.config.set_internet_source(InternetSource::Direct);
        assert_eq!(runtime.state().exit_node_status_text, "Direct internet");
        let _ = fs::remove_dir_all(dir);
    }

    fn assert_paid_exit_funding_status(runtime: &mut NativeAppRuntime, session_id: &str, channel_id: &str, now: u64) {
        use nostr_vpn_core::paid_route_store::update_paid_route_store;
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.begin_buyer_session_open_attempt(session_id, now)?;
            store.begin_buyer_session_funding(session_id, now)?;
            store.channels.get_mut(channel_id).unwrap().error = "mint connection refused".to_string();
            Ok(())
        }).unwrap();
        let pending = runtime.state();
        assert!(!pending.exit_node_active);
        assert!(pending.exit_node_blocked);
        assert_eq!(pending.exit_node_status_text,
            "Automatic paid exit · Blocked · Payment unavailable · mint.example · Retrying");
        // A refund can put the mint into cooldown before this session has
        // attempted funding. No channel-local error must not mean "working".
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.channels.get_mut(channel_id).unwrap().error.clear();
            store.defer_buyer_mint_retry("https://mint.example", now, true, Some(600))
        }).unwrap();
        let cooldown = runtime.state();
        assert!(cooldown.exit_node_needs_attention);
        assert!(cooldown.exit_node_status_text.contains("Payment unavailable · mint.example · Retrying in"));
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.record_buyer_session_funding_shortfall(session_id, 12)?;
            store.upsert_wallet_mint("https://mint.example", "Mint", Some(10_000), now);
            Ok(())
        }).unwrap();
        assert_eq!(runtime.state().exit_node_status_text,
            "Automatic paid exit · Blocked · More funds needed · mint.example");
        assert!(runtime.state().exit_node_needs_attention);
        runtime.config.set_internet_source(InternetSource::PaidAutomatic);
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            let pending = store.open_buyer_session(nostr_vpn_core::paid_route_store::OpenPaidRouteBuyerSessionRequest {
                offer_selector: "internet-exit".to_string(),
                buyer_npub: runtime.config.nostr_keys()?.public_key().to_bech32()?,
                mint_url: Some("https://mint.example".to_string()),
                channel_capacity_sat: Some(3),
                initial_paid_msat: 0,
                now_unix: now + 1,
            })?;
            store.record_buyer_session_funding_shortfall(&pending.session_id, 5)?;
            store.upsert_wallet_mint("https://mint.example", "Mint", Some(3_000), now);
            store.selected_buyer_session_id.clear();
            Ok(())
        }).unwrap();
        assert!(runtime.state().exit_node_status_text.contains("More funds needed"),
            "reselection must preserve a known shortfall");
        assert!(runtime.state().exit_node_needs_attention);
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.upsert_wallet_mint("https://mint.example", "Mint", Some(0), now);
            Ok(())
        }).unwrap();
        assert!(runtime.state().exit_node_status_text.contains("Wallet empty"));
        update_paid_route_store(&nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path), |store| {
            store.upsert_wallet_mint("https://mint.example", "Mint", Some(20_000), now);
            Ok(())
        }).unwrap();
        runtime.config.exit_node_leak_protection = false;
        assert!(!runtime.state().exit_node_needs_attention, "a top-up clears the funding blocker");
        assert!(runtime.state().exit_node_status_text.ends_with("Selecting provider"));
    }
