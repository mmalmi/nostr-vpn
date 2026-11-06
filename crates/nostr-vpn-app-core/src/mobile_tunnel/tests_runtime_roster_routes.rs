    // A signed roster that reaches the running tunnel changes the routes the
    // host has to install. The runtime reports that through its interface
    // settings, so the Android service and the iOS provider can re-apply
    // them without the app.
    #[test]
    fn roster_updates_change_running_tunnel_interface_settings() {
        std::thread::Builder::new()
            .name("mobile-roster-routes".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mobile roster route test runtime")
                    .block_on(roster_updates_change_running_tunnel_interface_settings_inner());
            })
            .expect("spawn mobile roster route test")
            .join()
            .expect("mobile roster route test thread");
    }

    #[allow(clippy::too_many_lines)]
    async fn roster_updates_change_running_tunnel_interface_settings_inner() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-roster-routes-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");

        let admin = Keys::generate();
        let phone = Keys::generate();
        let laptop = Keys::generate();
        let admin_hex = admin.public_key().to_hex();
        let phone_hex = phone.public_key().to_hex();
        let laptop_hex = laptop.public_key().to_hex();
        let network_id = "mobile-roster-routes";
        let signed_at = unix_timestamp();
        let roster = |devices: &[&str], aliases: HashMap<String, String>, signed_at: u64| {
            SignedRoster::sign(
                network_id,
                NetworkRoster {
                    network_name: "Home".to_string(),
                    devices: devices.iter().map(|device| (*device).to_string()).collect(),
                    admins: vec![admin_hex.clone()],
                    aliases,
                    signed_at,
                },
                &admin,
            )
            .expect("signed test roster")
        };

        let mut phone_app = admin_join_request_app(
            &admin.secret_key().to_bech32().expect("admin secret"),
            &admin_hex,
            network_id,
        );
        phone_app.nostr.public_key = phone_hex.clone();
        phone_app.nostr.secret_key = phone.secret_key().to_bech32().expect("phone secret");
        phone_app.fips_nostr_discovery_enabled = false;
        phone_app.fips_bootstrap_enabled = false;
        phone_app.fips_bootstrap_peers.clear();
        phone_app.fips_websocket_seed_urls.clear();
        phone_app.nostr.relays.clear();
        assert!(
            phone_app
                .apply_verified_admin_signed_shared_roster(&roster(
                    &[&admin_hex, &phone_hex],
                    HashMap::new(),
                    signed_at,
                ))
                .expect("apply initial roster")
        );
        phone_app.save(&config_path).expect("save phone config");
        let phone_mobile = MobileTunnelConfig::from_app_with_config_path(&phone_app, &config_path)
            .expect("phone mobile config");
        let laptop_route = format!(
            "{}/32",
            strip_cidr(
                &derive_mesh_tunnel_ip(&phone_mobile.network_id, &laptop_hex)
                    .expect("laptop tunnel ip")
            )
        );
        assert!(!phone_mobile.route_targets.contains(&laptop_route));

        let endpoint = bind_local_mobile_endpoint(network_id, &phone_mobile).await;
        let state_control_runtime = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
            .await
            .expect("start phone state control");
        let state_control = state_control_runtime.sender();
        let app_config = Arc::new(RwLock::new(phone_app));
        let app_config_dirty = AtomicBool::new(false);
        let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
            phone_mobile.peers.clone(),
            vec![phone_mobile.local_address.clone()],
        ));
        let mesh_peers = Arc::new(RwLock::new(phone_mobile.peers.clone()));
        let peer_identities = Arc::new(RwLock::new(MobilePeerIdentityMap::default()));
        let peer_hints = Arc::new(RwLock::new(HashMap::new()));
        let presence = Arc::new(RwLock::new(HashMap::new()));
        let config_state = Arc::new(RwLock::new(phone_mobile));
        let interface_settings = MobileInterfaceSettingsRevision::default();
        let join_request_active = AtomicBool::new(false);
        let pending_join_roster_receipts = Arc::new(PendingJoinRosterReceiptQueue::default());
        let control = MobileEndpointReceiveContext {
            endpoint: endpoint.as_ref(),
            mesh: &mesh,
            mesh_peers: &mesh_peers,
            peer_identities: &peer_identities,
            peer_hints: &peer_hints,
            presence: &presence,
            config_state: &config_state,
            interface_settings: &interface_settings,
            app_config: &app_config,
            app_config_dirty: &app_config_dirty,
            pending_join_roster_receipts: &pending_join_roster_receipts,
            config_path: Some(&config_path),
            join_request_active: &join_request_active,
            state_control: &state_control,
        };
        let mut revision = interface_settings.subscribe();
        let routes = || {
            config_state
                .read()
                .expect("config state")
                .route_targets
                .clone()
        };

        apply_mobile_roster_frame(
            &control,
            Some(&roster(
                &[&admin_hex, &phone_hex, &laptop_hex],
                HashMap::new(),
                signed_at + 1,
            )),
        )
        .await
        .expect("apply roster adding the laptop");
        assert!(routes().contains(&laptop_route), "added member gets a route");
        assert!(revision.has_changed().expect("revision sender"));
        revision.mark_unchanged();

        let mut aliases = HashMap::new();
        aliases.insert(laptop_hex.clone(), "laptop".to_string());
        apply_mobile_roster_frame(
            &control,
            Some(&roster(
                &[&admin_hex, &phone_hex, &laptop_hex],
                aliases,
                signed_at + 2,
            )),
        )
        .await
        .expect("apply alias-only roster");
        assert!(
            !revision.has_changed().expect("revision sender"),
            "a roster that keeps the routes must not ask the host to re-apply them"
        );

        apply_mobile_roster_frame(
            &control,
            Some(&roster(
                &[&admin_hex, &phone_hex],
                HashMap::new(),
                signed_at + 3,
            )),
        )
        .await
        .expect("apply roster removing the laptop");
        assert!(!routes().contains(&laptop_route), "removed member loses its route");
        assert!(revision.has_changed().expect("revision sender"));

        let _ = std::fs::remove_dir_all(dir);
    }
