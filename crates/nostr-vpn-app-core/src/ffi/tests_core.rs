    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};

    const TEST_WG_PRIVATE_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TEST_WG_PUBLIC_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const TEST_WG_PRESHARED_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    fn create_test_network(runtime: &mut NativeAppRuntime, name: &str) -> String {
        runtime.config.add_network(name)
    }

    #[test]
    fn advertised_routes_are_normalized_and_deduplicated() {
        assert_eq!(
            parse_advertised_routes(" 10.0.0.0/8,10.0.0.0/8\n::/0 "),
            vec!["10.0.0.0/8".to_string(), "::/0".to_string()]
        );
    }

    #[test]
    fn relay_urls_are_normalized_and_deduplicated() {
        assert_eq!(
            normalize_relay_urls(vec![
                " wss://relay.example\nwss://b.example ".to_string(),
                "wss://relay.example,wss://a.example".to_string(),
            ]),
            vec![
                "wss://a.example".to_string(),
                "wss://b.example".to_string(),
                "wss://relay.example".to_string(),
            ]
        );
    }

    #[test]
    fn action_error_text_preserves_context_chain() {
        let error = anyhow!("mint rejected the wallet keyset")
            .context("Failed to prepare Cashu payment token");

        assert_eq!(
            action_error_text(&error),
            "Failed to prepare Cashu payment token: mint rejected the wallet keyset"
        );
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn standalone_paid_exit_status_uses_runtime_readiness_not_vpn_activity() {
        let mut app = AppConfig::generated();
        app.paid_exit.enabled = true;
        app.paid_exit.pricing.price_msat_per_gb = 100;
        app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
        let daemon_state = DaemonRuntimeState {
            paid_exit_seller_ready: true,
            vpn_active: false,
            ..DaemonRuntimeState::default()
        };

        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&daemon_state),
                &app.paid_exit,
                false,
                true,
            ),
            "Selling internet is ready"
        );
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn paid_exit_status_reports_missing_upstream_before_listener() {
        let mut app = AppConfig::generated();
        app.paid_exit.enabled = true;
        app.set_internet_source(InternetSource::WireGuard);

        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&DaemonRuntimeState::default()),
                &app.paid_exit,
                false,
                true,
            ),
            "Configure WireGuard upstream before advertising"
        );

        let peer = Keys::generate().public_key().to_hex();
        app.set_internet_source(InternetSource::Direct);
        app.set_active_network_id("paid-exit-status-test")
            .expect("activate generated network");
        app.networks[0].devices.push(peer.clone());
        app.select_private_exit_node(&peer)
            .expect("select private exit");
        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&DaemonRuntimeState::default()),
                &app.paid_exit,
                true,
                true,
            ),
            "Waiting for the selected private exit"
        );
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn paid_exit_direct_provider_readiness_does_not_require_relays() {
        let mut app = AppConfig::generated();
        app.paid_exit.enabled = true;
        app.paid_exit.pricing.price_msat_per_gb = 100;
        app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
        app.nostr.disabled_relays = effective_config_relays(&app);
        let daemon_state = DaemonRuntimeState {
            paid_exit_seller_ready: true,
            ..DaemonRuntimeState::default()
        };

        assert!(effective_config_relays(&app).is_empty());
        assert_eq!(
            paid_exit::paid_exit_seller_status_text(
                &app,
                Some(&daemon_state),
                &app.paid_exit,
                false,
                true,
            ),
            "Selling internet is ready"
        );
    }

    #[test]
    fn empty_app_relay_config_exposes_fips_defaults() {
        let mut config = AppConfig::generated();
        config.nostr.relays.clear();

        let relays = effective_config_relays(&config);

        assert!(!relays.is_empty());
        assert!(relays.iter().all(|relay| relay.starts_with("wss://")));
        assert!(relays.contains(&"wss://temp.iris.to".to_string()));
    }

    #[test]
    fn disabled_app_relays_filter_effective_relays() {
        let mut config = AppConfig::generated();
        let defaults = effective_config_relays(&config);
        let disabled = defaults.first().expect("fips default relay").clone();
        config.nostr.disabled_relays = vec![disabled.clone()];

        let relays = effective_config_relays(&config);

        assert!(!relays.contains(&disabled));
    }

    #[test]
    fn default_config_path_matches_desktop_config_location() {
        let path = default_config_path();

        assert!(path.ends_with(Path::new("nvpn").join("config.toml")));
    }

    #[test]
    fn desktop_startup_persists_identity_without_join_request_material() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-seeded-config-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "node_name = \"iPhone\"\n").expect("write seeded config");

        let runtime = NativeAppRuntime::new(dir.to_str().expect("utf8 temp dir"), String::new())
            .expect("runtime starts");
        let saved = AppConfig::load(&config_path).expect("saved config loads");

        assert_eq!(runtime.config.node_name, "iPhone");
        assert_eq!(saved.node_name, "iPhone");
        assert!(saved.networks.is_empty());
        assert!(!saved.nostr.secret_key.trim().is_empty());
        assert!(!saved.nostr.public_key.trim().is_empty());
        let first_join_link = runtime.state().join_request_qr_code_or_link;
        assert!(first_join_link.is_empty());
        assert!(saved.pending_nostr_join_request.is_none());
        let raw = fs::read_to_string(&config_path).expect("read persisted config");
        assert!(raw.contains("[nostr]"));
        assert!(raw.contains("public_key"));
        assert!(!raw.contains("pending_nostr_join_request"));

        drop(runtime);
        let reloaded = NativeAppRuntime::new(dir.to_str().expect("utf8 temp dir"), String::new())
            .expect("runtime reloads");
        assert!(reloaded.state().join_request_qr_code_or_link.is_empty());

        drop(reloaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn host_runtimes_do_not_own_or_lock_the_cashu_wallet() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-wallet-owner-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let data_dir = dir.to_str().expect("utf8 temp dir");

        let first = NativeAppRuntime::new(data_dir, String::new()).expect("first runtime starts");
        let second = NativeAppRuntime::new(data_dir, String::new())
            .expect("a second GUI runtime must not contend for the daemon wallet");
        assert!(!dir.join("cashu/wallet.lock").exists());
        drop(second);
        drop(first);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(all(feature = "paid-exit", unix))]
    #[test]
    fn host_wallet_refresh_uses_daemon_cli_after_runtime_startup() {
        use std::os::unix::fs::PermissionsExt as _;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-daemon-wallet-{nonce}"));
        fs::create_dir_all(&dir).expect("create daemon wallet test dir");
        let calls_path = dir.join("wallet-cli-calls.txt");
        let script_path = dir.join("fake-nvpn");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '%s\\n' '{{\"cashu\":{{\"totals\":[{{\"unit\":\"sat\",\"balance\":21}}],\"entries\":[{{\"mint_url\":\"https://mint.example\",\"unit\":\"sat\",\"balance\":21}}],\"warnings\":[],\"legacy_state_detected\":false}},\"activity\":null}}'\n",
            calls_path.display()
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let mut runtime = NativeAppRuntime::new(
            dir.to_str().expect("utf8 temp dir"),
            String::new(),
        )
        .expect("runtime starts without opening a wallet");
        runtime.nvpn_bin = Some(script_path);
        runtime
            .refresh_paid_route_wallet(false)
            .expect("wallet refresh delegates to daemon CLI");

        let store = nostr_vpn_core::paid_route_store::load_paid_route_store(
            &nostr_vpn_core::paid_route_store::paid_route_store_file_path(&runtime.config_path),
        )
        .expect("load synchronized paid route store");
        let mint = store
            .wallet
            .mints
            .iter()
            .find(|mint| mint.url == "https://mint.example")
            .expect("daemon wallet mint synchronized");
        assert_eq!(mint.balance_msat, Some(21_000));
        let calls = fs::read_to_string(calls_path).expect("read fake nvpn calls");
        assert!(calls.contains("paid-exit wallet --config"), "{calls}");
        assert!(calls.contains("--json show"), "{calls}");
        assert!(!dir.join("cashu/wallet.lock").exists());

        drop(runtime);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_migrates_plaintext_config_secrets() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-secret-migration-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("config.toml");
        let mut config = AppConfig::generated_without_networks();
        config.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.to_string();
        config.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.to_string();
        config.wireguard_exit.peer_preshared_key = TEST_WG_PRESHARED_KEY.to_string();
        let nostr_secret = config.nostr.secret_key.clone();
        fs::write(
            &path,
            config.plaintext_toml().expect("encode plaintext config"),
        )
        .expect("write plaintext config");

        let runtime = NativeAppRuntime::new_with_config_path(path.clone(), String::new(), None)
            .expect("runtime starts");
        let raw = fs::read_to_string(&path).expect("read migrated config");
        let loaded = AppConfig::load(&path).expect("load migrated config");
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete migrated secrets");

        assert_eq!(runtime.config.nostr.secret_key, nostr_secret);
        assert!(!raw.contains(&nostr_secret));
        assert!(!raw.contains(TEST_WG_PRIVATE_KEY));
        assert!(!raw.contains(TEST_WG_PRESHARED_KEY));
        assert_eq!(loaded.nostr.secret_key, nostr_secret);
        assert_eq!(loaded.wireguard_exit.private_key, TEST_WG_PRIVATE_KEY);
        assert_eq!(
            loaded.wireguard_exit.peer_preshared_key,
            TEST_WG_PRESHARED_KEY
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_error_state_does_not_expose_generated_config_as_real_config() {
        let error = anyhow!("boom");
        let runtime = NativeAppRuntime::from_startup_error(&error);
        let state = runtime.state();

        assert_eq!(state.error, "boom");
        assert!(state.own_pubkey_hex.is_empty());
        assert!(state.node_name.is_empty());
        assert!(state.tunnel_ip.is_empty());
        assert!(state.network_id.is_empty());
        assert_eq!(state.expected_peer_count, 0);
        assert_eq!(state.connected_peer_count, 0);
        assert!(state.networks.is_empty());
    }

    #[test]
    fn ffi_startup_error_recovery_stays_on_requested_data_directory() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-startup-path-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "not valid toml").expect("write invalid config");

        let app = FfiApp::new(
            dir.to_str().expect("utf8 temp dir").to_string(),
            "test-version".to_string(),
        );
        let initial = app.state();
        assert_eq!(initial.config_path, config_path.display().to_string());
        assert!(!initial.error.is_empty());

        let refreshed = app.refresh();
        assert_eq!(refreshed.config_path, config_path.display().to_string());
        assert!(!refreshed.error.is_empty());
        assert_eq!(
            fs::read_to_string(&config_path).expect("read original config"),
            "not valid toml"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_error_blocks_config_mutation_until_real_config_loads() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-startup-guard-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "not valid toml").expect("write invalid config");

        let error = anyhow!("startup failed");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.config_path = config_path.clone();
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                node_name: Some("should-not-save".to_string()),
                ..SettingsPatch::default()
            },
        });

        assert!(runtime.last_error.contains("cannot modify VPN config"));
        assert_eq!(
            fs::read_to_string(&config_path).expect("read config"),
            "not valid toml"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_error_recovers_after_config_becomes_readable() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-startup-recover-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        let config = AppConfig {
            node_name: "real-config".to_string(),
            ..AppConfig::generated_without_networks()
        };
        config.save(&config_path).expect("save config");

        let error = anyhow!("startup failed");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.mobile_runtime = true;
        runtime.config_path = config_path;
        runtime.dispatch(NativeAppAction::Tick);
        let state = runtime.state();

        assert!(state.error.is_empty(), "{}", state.error);
        assert_eq!(state.node_name, "real-config");
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_config_has_no_network_until_created() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-create-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        let state = runtime.state();
        assert!(runtime.config.networks.is_empty());
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());

        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });

        let state = runtime.state();
        assert!(state.error.is_empty(), "{}", state.error);
        assert_eq!(runtime.config.networks.len(), 1);
        assert_eq!(state.networks.len(), 1);
        assert_eq!(state.networks[0].name, "Home");
        assert!(!state.network_id.is_empty());
        assert_eq!(state.expected_peer_count, 0);
        assert!(
            state.vpn_enabled && state.vpn_active,
            "a newly created mobile admin network must start listening before approval"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn creating_another_network_activates_the_new_network() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-switch-created-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        let home_id = runtime.config.active_network().id.clone();
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Work".to_string(),
        });

        let state = runtime.state();
        assert!(state.error.is_empty(), "{}", state.error);
        assert_eq!(runtime.config.networks.len(), 2);
        assert_eq!(runtime.config.enabled_network_count(), 1);
        assert_eq!(runtime.config.active_network().name, "Work");
        assert!(!runtime.config.network_by_id(&home_id).expect("Home").enabled);
        assert_eq!(
            state.networks.iter().find(|network| network.enabled).map(|network| network.name.as_str()),
            Some("Work")
        );
        assert!(!state
            .networks
            .iter()
            .find(|network| network.id == home_id)
            .expect("Home state")
            .enabled);

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(saved.active_network().name, "Work");

        let _ = fs::remove_dir_all(&dir);
    }

    include!("tests_core/runtime_state.rs");
