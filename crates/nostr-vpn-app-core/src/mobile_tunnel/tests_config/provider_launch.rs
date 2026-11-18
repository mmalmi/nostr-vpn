    fn mobile_launch_redaction_fixture() -> (PathBuf, String, &'static str) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-launch-redaction-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.toml");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";

        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let secret_key = app.nostr.secret_key.clone();
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            join_secret: "join-secret".to_string(),
            devices: vec![peer.to_string()],
            removed_devices: Vec::new(),
            admins: vec![own.clone()],
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        }];
        app.wireguard_exit = WireGuardExitConfig {
            enabled: true,
            address: "10.99.99.2/32".to_string(),
            private_key: "client-private-key".to_string(),
            peer_public_key: "server-public-key".to_string(),
            peer_preshared_key: "client-peer-psk".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            ..WireGuardExitConfig::default()
        };
        app.note_active_network_roster_local_change()
            .expect("mark admin roster changed");
        app.save(&path).expect("save config");
        let queued_roster = SignedRoster::sign(
            "test",
            NetworkRoster {
                network_name: "Test".to_string(),
                devices: vec![peer.to_string()],
                admins: vec![own],
                aliases: HashMap::new(),
                signed_at: unix_timestamp(),
            },
            &app.nostr_keys().expect("admin keys"),
        )
        .expect("sign queued roster");
        let queued_control = JoinRosterControl::new(queued_roster, "request-secret")
            .expect("bind queued roster");
        nostr_vpn_core::join_delivery::queue_join_roster(&path, peer, &queued_control)
            .expect("queue mobile approval");
        (dir, secret_key, peer)
    }

    #[test]
    fn mobile_tunnel_launch_config_redacts_persisted_secrets() {
        let (dir, secret_key, peer) = mobile_launch_redaction_fixture();
        let path = dir.join("config.toml");

        let json = tunnel_config_json(dir.to_str().expect("utf8 temp dir"));
        assert!(!json.contains(&secret_key));
        assert!(!json.contains("join-secret"));
        assert!(!json.contains("client-private-key"));
        assert!(!json.contains("client-peer-psk"));
        assert!(json.contains("198.51.100.20:51820"));

        let launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&json).expect("launch config");
        assert_eq!(launch.queued_join_rosters.len(), 1);
        assert_eq!(launch.queued_join_rosters[0].recipient_npub, peer);
        assert!(launch.signed_roster.is_some());
        let launch_config = launch.tunnel;
        assert_eq!(launch_config.app_config_toml, "");
        assert_eq!(launch_config.identity_nsec, "");
        assert_eq!(launch_config.join_secret, "");
        assert_eq!(launch_config.pending_join_secret, "");
        assert_eq!(
            launch_config
                .wireguard_exit
                .as_ref()
                .expect("wireguard exit")
                .private_key,
            ""
        );

        let loaded = mobile_app_config(&launch_config).expect("load app config from path");
        let runtime_config =
            MobileTunnelConfig::from_app_with_config_path(&loaded, &path).expect("runtime config");
        assert_eq!(runtime_config.identity_nsec, secret_key);
        assert_eq!(
            runtime_config
                .wireguard_exit
                .as_ref()
                .expect("runtime wireguard")
                .private_key,
            "client-private-key"
        );

        let provider_json =
            tunnel_provider_options_config_json(dir.to_str().expect("utf8 temp dir"));
        assert!(provider_json.contains(&secret_key));
        assert!(provider_json.contains("join-secret"));
        assert!(provider_json.contains("client-private-key"));
        assert!(provider_json.contains("client-peer-psk"));

        let provider_launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&provider_json).expect("provider options config");
        assert_eq!(provider_launch.queued_join_rosters.len(), 1);
        assert_eq!(provider_launch.queued_join_rosters[0].recipient_npub, peer);
        assert!(provider_launch.signed_roster.is_some());
        assert_eq!(
            PathBuf::from(&provider_launch.private_state_config_path),
            path,
            "provider launch must retain only the private state anchor used for receipt and outbox sidecars"
        );
        let provider_config = provider_launch.tunnel;
        assert!(
            provider_config.config_path.is_empty(),
            "packet tunnel extension must not read the containing app's private config path"
        );
        assert_eq!(
            provider_config.route_targets, launch_config.route_targets,
            "saved and start-option configs must describe the same routes"
        );
        assert_eq!(
            provider_config.wireguard_exit.is_some(),
            launch_config.wireguard_exit.is_some(),
            "saved and start-option configs must agree on WireGuard exit state"
        );

        let provider_loaded =
            mobile_app_config(&provider_config).expect("load app config from embedded toml");
        let provider_runtime =
            MobileTunnelConfig::from_app_with_config_path(&provider_loaded, Path::new(""))
                .expect("provider runtime config");
        assert_eq!(provider_runtime.identity_nsec, secret_key);
        assert_eq!(
            provider_runtime
                .wireguard_exit
                .as_ref()
                .expect("provider runtime wireguard")
                .private_key,
            "client-private-key"
        );
        assert_eq!(provider_runtime.config_path, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provider_launch_persists_fresh_runtime_state_via_private_anchor() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-provider-runtime-state-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let config_path = dir.join("config.toml");
        let runtime_state_path = dir.join(MOBILE_RUNTIME_STATE_FILE);

        let mut app = AppConfig::generated_without_networks();
        app.ensure_defaults();
        app.fips_nostr_discovery_enabled = false;
        app.fips_webrtc_enabled = false;
        app.lan_discovery_enabled = false;
        app.nostr.relays.clear();
        app.save(&config_path).expect("save provider fixture");

        let provider_json =
            tunnel_provider_options_config_json(dir.to_str().expect("utf8 temp dir"));
        let launch: MobileTunnelLaunchConfig =
            serde_json::from_str(&provider_json).expect("provider launch config");
        assert_eq!(launch.tunnel.config_path, "");
        assert_eq!(
            PathBuf::from(&launch.private_state_config_path),
            config_path
        );

        let tunnel = MobileTunnel::start(&provider_json).expect("start provider tunnel");
        let deadline = Instant::now() + Duration::from_secs(2);
        let runtime_state = loop {
            if let Ok(bytes) = fs::read(&runtime_state_path)
                && let Ok(state) = serde_json::from_slice::<DaemonRuntimeState>(&bytes)
            {
                break state;
            }
            assert!(
                Instant::now() < deadline,
                "provider launch did not persist runtime state through its private anchor"
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        assert!(runtime_state.vpn_enabled);
        assert!(runtime_state.vpn_active);
        assert!(
            unix_timestamp().saturating_sub(runtime_state.updated_at) <= 1,
            "provider runtime state was not fresh"
        );

        drop(tunnel);
        let stopped_runtime_state = fs::read(&runtime_state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<DaemonRuntimeState>(&bytes).ok());
        let _ = fs::remove_dir_all(&dir);
        assert!(
            stopped_runtime_state
                .as_ref()
                .is_none_or(|state| !state.vpn_enabled && !state.vpn_active),
            "provider teardown left fresh active runtime state"
        );
    }

    #[test]
    fn provider_launch_offers_queued_file_without_reopening_private_config() {
        use nostr_vpn_core::file_transfers::{FileCommand, enqueue, read_state, stage_source};

        let dir = desktop_mobile_join_test_dir("provider-file-offer");
        let path = dir.join("config.toml");
        let peer = Keys::generate().public_key();
        let mut app = AppConfig::generated();
        app.fips_nostr_discovery_enabled = false;
        app.fips_bootstrap_enabled = false;
        app.fips_webrtc_enabled = false;
        app.lan_discovery_enabled = false;
        app.nostr.pubsub.mode = nostr_vpn_core::config::NostrPubsubMode::Off;
        app.networks[0].enabled = true;
        app.networks[0].devices.push(peer.to_hex());
        app.save(&path).unwrap();
        let launch = tunnel_provider_options_config_json(dir.to_str().unwrap());
        let source = dir.join("photo.jpg");
        fs::write(&source, b"file contents").unwrap();
        let staged = stage_source(&path, &source).unwrap();
        let id = enqueue(
            &path,
            FileCommand::Send {
                npub: peer.to_bech32().unwrap(),
                paths: vec![staged.to_str().unwrap().to_owned()],
            },
        ).unwrap();
        fs::remove_file(&path).unwrap();

        let tunnel = MobileTunnel::start(&launch).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(row) = read_state(&path).unwrap().into_iter().find(|row| row.id == id) {
                assert_ne!(row.status, "failed", "{:?}", row.error);
                if row.status == "offered" {
                    assert_eq!(row.peer_npub, peer.to_bech32().unwrap());
                    break;
                }
            }
            assert!(Instant::now() < deadline, "provider did not register the queued offer");
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(tunnel);
        fs::remove_dir_all(dir).unwrap();
    }
