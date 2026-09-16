    #[test]
    fn settings_patch_persists_paid_exit_seller_config() {
        let dir = unique_service_test_dir("nvpn-app-core-paid-exit");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.config_path = dir.join("config.toml");
        runtime.config.connect_to_non_roster_fips_peers = false;
        runtime.config.fips_nostr_discovery_enabled = false;
        runtime.config.fips_advertise_public_endpoint = false;
        runtime.config.nostr.pubsub.mode = NostrPubsubMode::Off;

        runtime
            .apply_settings_patch(SettingsPatch {
                paid_exit_enabled: Some(true),
                paid_exit_upstream: Some("wg".to_string()),
                paid_exit_price_msat_per_gb: Some(2_500),
                paid_exit_accepted_mints: Some(
                    "https://mint-b.example, https://mint-a.example".to_string(),
                ),
                paid_exit_max_channel_capacity_sat: Some(100),
                paid_exit_channel_expiry_secs: Some(3_600),
                paid_exit_free_probe_units: Some(65_536),
                paid_exit_grace_units: Some(131_072),
                paid_exit_country_code: Some("fi".to_string()),
                paid_exit_network_class: Some("residential".to_string()),
                paid_exit_asn: Some("AS12345".to_string()),
                paid_exit_ipv4: Some(false),
                paid_exit_ipv6: Some(true),
                paid_exit_rating_file: Some(" ratings.json ".to_string()),
                paid_exit_rating_relays: Some(vec![
                    " wss://ratings-b.example ".to_string(),
                    "wss://ratings-a.example,wss://ratings-b.example".to_string(),
                ]),
                paid_exit_trusted_rating_authors: Some(vec![
                    " npub1authorb ".to_string(),
                    "npub1authora,npub1authorb".to_string(),
                ]),
                paid_exit_rating_scope: Some(" fips.peer.test ".to_string()),
                ..SettingsPatch::default()
            })
            .expect("apply paid exit settings");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save paid exit settings");

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.paid_exit.enabled);
        assert!(!saved.connect_to_non_roster_fips_peers);
        assert!(!saved.fips_nostr_discovery_enabled);
        assert!(!saved.fips_advertise_public_endpoint);
        assert_eq!(saved.nostr.pubsub.mode, NostrPubsubMode::Relay);
        assert_eq!(saved.paid_exit.access.upstream.as_str(), "wireguard_exit");
        assert_eq!(saved.paid_exit.pricing.price_msat_per_gb, 2_500);
        assert_eq!(
            saved.paid_exit.channel.accepted_mints,
            vec!["https://mint-a.example", "https://mint-b.example"]
        );
        assert_eq!(saved.paid_exit.channel.max_channel_capacity_sat, 100);
        assert_eq!(saved.paid_exit.channel.channel_expiry_secs, 3_600);
        assert_eq!(saved.paid_exit.channel.free_probe_units, 65_536);
        assert_eq!(saved.paid_exit.location.network_class.as_str(), "residential");
        assert_eq!(saved.paid_exit.channel.grace_units, 131_072);
        assert_eq!(saved.paid_exit.location.country_code, "FI");
        assert_eq!(saved.paid_exit.location.asn, Some(12_345));
        assert!(saved.paid_exit.ip_support.ipv4);
        assert!(!saved.paid_exit.ip_support.ipv6);
        assert_eq!(saved.paid_exit.rating_discovery.file, "ratings.json");
        assert_eq!(
            saved.paid_exit.rating_discovery.relays,
            vec![
                "wss://ratings-a.example".to_string(),
                "wss://ratings-b.example".to_string()
            ]
        );
        assert_eq!(
            saved.paid_exit.rating_discovery.trusted_authors,
            vec!["npub1authora".to_string(), "npub1authorb".to_string()]
        );
        assert_eq!(saved.paid_exit.rating_discovery.scope, "fips.peer.test");

        let raw = fs::read_to_string(&runtime.config_path).expect("read persisted config");
        assert!(raw.contains("rating_discovery"));
        assert!(raw.contains("trusted_authors"));
        assert!(raw.contains("scope = \"fips.peer.test\""));
        assert!(raw.contains("wss://ratings-a.example"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_patch_rejects_every_invalid_paid_exit_mint_before_mutation() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        let before_node_name = runtime.config.node_name.clone();
        let before_enabled = runtime.config.paid_exit.enabled;
        let before_mints = runtime.config.paid_exit.channel.accepted_mints.clone();

        let error = runtime
            .apply_settings_patch(SettingsPatch {
                node_name: Some("must-not-change".to_string()),
                paid_exit_enabled: Some(true),
                paid_exit_accepted_mints: Some(
                    "https://mint.example, ftp://invalid.example".to_string(),
                ),
                ..SettingsPatch::default()
            })
            .expect_err("invalid mint must reject the whole patch");

        assert!(error.to_string().contains("unsupported mint URL scheme"));
        assert_eq!(runtime.config.node_name, before_node_name);
        assert_eq!(runtime.config.paid_exit.enabled, before_enabled);
        assert_eq!(
            runtime.config.paid_exit.channel.accepted_mints,
            before_mints
        );
    }

    #[test]
    fn paid_exit_wireguard_seller_waits_for_a_real_handshake() {
        let mut app = AppConfig::generated();
        app.paid_exit.enabled = true;
        app.paid_exit.pricing.price_msat_per_gb = 100;
        app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
        app.set_internet_source(InternetSource::WireGuard);
        app.wireguard_exit.address = "10.64.70.195/32".to_string();
        app.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.to_string();
        app.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.to_string();
        app.wireguard_exit.endpoint = "vpn.example.test:51820".to_string();
        let mut daemon_state = DaemonRuntimeState {
            paid_exit_seller_ready: true,
            ..DaemonRuntimeState::default()
        };

        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&daemon_state),
                &app.paid_exit,
                true,
                true,
            ),
            "Waiting for the WireGuard handshake"
        );

        daemon_state.wireguard_exit_ready = true;
        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&daemon_state),
                &app.paid_exit,
                true,
                true,
            ),
            "Selling internet is ready"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn disabled_seller_keeps_existing_channel_credit_visible() {
        use nostr_vpn_core::paid_route_store::{
            PaidRouteChannelRecord, PaidRouteChannelRole, PaidRouteLifecycleStatus,
            paid_route_store_file_path, update_paid_route_store,
        };
        use nostr_vpn_core::paid_routes::{
            PaidRoutePaymentState, PaidRouteSession, PaidRouteUsage,
        };

        let dir = unique_service_test_dir("nvpn-app-core-disabled-seller-credit");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.config_path = dir.join("config.toml");
        runtime.config.paid_exit.enabled = false;
        let store_path = paid_route_store_file_path(&runtime.config_path);
        update_paid_route_store(&store_path, |store| {
            let payment = PaidRoutePaymentState {
                channel_id: "seller-channel".to_string(),
                paid_msat: 25_000,
                ..PaidRoutePaymentState::default()
            };
            store.upsert_channel(PaidRouteChannelRecord {
                channel_id: "seller-channel".to_string(),
                offer_id: "internet-exit".to_string(),
                role: PaidRouteChannelRole::Seller,
                status: PaidRouteLifecycleStatus::Active,
                payment: payment.clone(),
                accepted_terms: Some(runtime.config.paid_exit.clone()),
                mint_url: "https://mint.example".to_string(),
                counterparty_npub: "buyer".to_string(),
                created_at_unix: 1,
                expires_at_unix: u64::MAX,
                updated_at_unix: 1,
                error: String::new(),
            });
            store.upsert_session(
                PaidRouteSession {
                    session_id: "seller-session".to_string(),
                    lease_id: "seller-lease".to_string(),
                    usage: PaidRouteUsage::default(),
                    payment,
                    realized_exit_ip: None,
                    observed_country_code: None,
                    observed_asn: None,
                    quality: None,
                },
                1,
            );
            Ok(())
        })
        .expect("persist seller channel");

        let state = runtime.paid_exit_seller_state(Some(&runtime.config), None, false);

        assert!(!state.enabled);
        assert_eq!(state.channels.len(), 1);
        assert_eq!(state.channels[0].channel_id, "seller-channel");
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.channel_credit_msat, 25_000);
        let _ = fs::remove_dir_all(dir);
    }
