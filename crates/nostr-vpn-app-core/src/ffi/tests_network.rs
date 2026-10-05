    include!("tests_network/exit_state.rs");

    #[test]
    fn native_state_reports_routed_fips_peer_latency() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![peer_pubkey.to_string()];
        let now = unix_timestamp();
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            fips_other_peer_count: 2,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer_pubkey.to_string(),
                endpoint: "fips".to_string(),
                runtime_endpoint: Some("fips".to_string()),
                fips_endpoint_npub: "npub1peer".to_string(),
                fips_srtt_ms: Some(112),
                fips_srtt_age_ms: Some(789),
                direct_probe_pending: true,
                direct_probe_after_ms: Some(12_345),
                direct_probe_retry_count: 3,
                direct_probe_auto_reconnect: true,
                direct_probe_expires_at_ms: Some(67_890),
                last_fips_control_seen_at: Some(now.saturating_sub(120)),
                last_fips_data_seen_at: Some(now.saturating_sub(7_200)),
                last_fips_seen_at: Some(now),
                last_handshake_at: Some(now),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let peer = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer_pubkey)
            .expect("peer participant");

        assert_eq!(state.fips_connected_peer_count, 0);
        assert_eq!(state.fips_roster_peer_count, 1);
        assert_eq!(state.non_fips_roster_peer_count, 2);
        assert_eq!(peer.status_text, "online via mesh, probing direct (112 ms)");
        assert_eq!(peer.fips_srtt_ms, 112);
        assert_eq!(peer.fips_srtt_age_ms, 789);
        assert!(peer.fips_direct_probe_pending);
        assert_eq!(peer.fips_direct_probe_after_ms, 12_345);
        assert_eq!(peer.fips_direct_probe_retry_count, 3);
        assert!(peer.fips_direct_probe_auto_reconnect);
        assert_eq!(peer.fips_direct_probe_expires_at_ms, 67_890);
        assert_eq!(peer.last_fips_control_seen_text, "seen 2m ago");
        assert_eq!(peer.last_fips_data_seen_text, "seen 2h ago");
    }

    #[test]
    fn native_state_rejects_far_future_fips_presence() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![peer_pubkey.to_string()];
        let future_seen_at = unix_timestamp() + 60;
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 0,
            mesh_ready: false,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer_pubkey.to_string(),
                endpoint: "fips".to_string(),
                runtime_endpoint: Some("fips".to_string()),
                fips_endpoint_npub: "npub1peer".to_string(),
                last_fips_control_seen_at: Some(future_seen_at),
                last_fips_data_seen_at: Some(future_seen_at),
                last_mesh_seen_at: future_seen_at,
                last_fips_seen_at: Some(future_seen_at),
                last_handshake_at: Some(future_seen_at),
                reachable: false,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let peer = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer_pubkey)
            .expect("peer participant");

        assert!(!peer.reachable);
        assert_eq!(peer.state, "offline");
        assert_eq!(peer.mesh_state, "absent");
        assert_eq!(peer.status_text, "offline");
        assert_eq!(peer.last_fips_control_seen_text, "");
        assert_eq!(peer.last_fips_data_seen_text, "");
        assert_eq!(peer.last_seen_text, "");
    }

    #[test]
    fn native_state_counts_direct_fips_roster_peer() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].devices = vec![peer_pubkey.to_string()];
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer_pubkey.to_string(),
                fips_endpoint_npub: "npub1peer".to_string(),
                fips_transport_addr: "203.0.113.9:9000".to_string(),
                fips_transport_type: "udp".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();

        assert_eq!(state.fips_connected_peer_count, 1);
        assert_eq!(state.fips_roster_peer_count, 1);
        assert_eq!(state.non_fips_roster_peer_count, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn compact_join_bootstrap_is_added_by_admin_without_request_event() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let admin_dir =
            std::env::temp_dir().join(format!("nvpn-app-core-admin-join-request-{nonce}"));
        let joiner_dir =
            std::env::temp_dir().join(format!("nvpn-app-core-joiner-request-link-{nonce}"));
        fs::create_dir_all(&admin_dir).expect("create admin test dir");
        fs::create_dir_all(&joiner_dir).expect("create joiner test dir");

        let error = anyhow!("boom");
        let mut admin = NativeAppRuntime::from_startup_error(&error);
        admin.startup_error = None;
        admin.last_error.clear();
        admin.mobile_runtime = true;
        admin.config_path = admin_dir.join("config.toml");
        admin.config.node_name = "Admin Mac".to_string();
        let admin_pubkey = admin
            .config
            .own_nostr_pubkey_hex()
            .expect("admin pubkey");
        let admin_network_id = create_test_network(&mut admin, "Home");
        admin.config.networks[0].network_id = "8d4f34f5425bc50e".to_string();
        admin.config.networks[0].admins = vec![admin_pubkey.clone()];

        let mut joiner = NativeAppRuntime::from_startup_error(&error);
        joiner.startup_error = None;
        joiner.mobile_runtime = true;
        joiner.config_path = joiner_dir.join("config.toml");
        joiner.config.node_name = "Pixel Phone".to_string();
        joiner.config.clear_pending_nostr_join_request();
        let joiner_pubkey = joiner
            .config
            .own_nostr_pubkey_hex()
            .expect("joiner pubkey");
        let requested_at = unix_timestamp();
        joiner
            .config
            .ensure_pending_nostr_join_request(requested_at)
            .expect("joiner request");
        let pending = joiner
            .config
            .pending_nostr_join_request
            .as_ref()
            .expect("pending request");
        let request_secret = pending.request.request_secret.clone();
        let bootstrap = nostr_vpn_core::identity_bridge::nostr_identity_device_approval_bootstrap(
            &pending.request,
        )
        .expect("joiner request bootstrap");
        let join_request = joiner
            .config
            .pending_nostr_join_request_link(crate::join_request_link::JOIN_REQUEST_LINK_PREFIX)
            .expect("joiner request link");
        assert!(join_request.starts_with("nvpn://join-request/"));
        let parsed_bootstrap =
            nostr_vpn_core::identity_bridge::parse_nostr_identity_device_approval_bootstrap(
                &join_request,
                &[crate::join_request_link::JOIN_REQUEST_LINK_PREFIX],
            )
            .expect("parse compact join request")
            .expect("join request bootstrap");
        assert_eq!(parsed_bootstrap, bootstrap);
        assert_eq!(
            nostr_vpn_core::config::normalize_nostr_pubkey(&parsed_bootstrap.device_app_key_npub)
                .expect("stable AppKey"),
            joiner_pubkey
        );
        assert_eq!(parsed_bootstrap.request_secret, request_secret);
        assert_ne!(
            nostr_vpn_core::config::normalize_nostr_pubkey(&parsed_bootstrap.request_npub)
                .expect("request key"),
            joiner_pubkey
        );

        admin
            .import_join_request(&join_request)
            .expect("import compact join request");

        assert!(admin.last_error.is_empty(), "{}", admin.last_error);
        assert_eq!(admin.queued_join_rosters.len(), 1);
        let signed_roster = &admin.queued_join_rosters[0].signed_roster;
        signed_roster.verify().expect("verify queued roster");
        let roster = signed_roster.roster().expect("decode queued roster");
        assert_eq!(signed_roster.network_id().unwrap(), "8d4f34f5425bc50e");
        assert!(roster.devices.contains(&joiner_pubkey));
        assert!(roster.admins.contains(&admin_pubkey));
        assert_eq!(
            signed_roster.signer_pubkey_hex().unwrap(),
            admin.config.own_nostr_pubkey_hex().unwrap()
        );
        assert!(admin.config.networks[0].devices.contains(&joiner_pubkey));
        assert_eq!(admin.config.networks[0].inbound_join_requests, [] as [nostr_vpn_core::config::PendingInboundJoinRequest; 0]);
        assert_eq!(
            admin.config.peer_alias(&joiner_pubkey).as_deref(),
            Some("pixel-phone")
        );
        let imported = admin
            .state()
            .networks
            .into_iter()
            .find(|network| network.id == admin_network_id)
            .expect("admin network");
        assert_eq!(imported.inbound_join_requests, [] as [crate::native_state::NativeInboundJoinRequestState; 0]);
        assert!(imported
            .join_request_qr_code_or_link
            .starts_with("nvpn://join-request/"));
        assert!(admin
            .state()
            .join_request_qr_code_or_link
            .starts_with("nvpn://join-request/"));

        assert!(
            joiner
                .config
                .apply_nostr_join_roster(&admin.queued_join_rosters[0], unix_timestamp())
                .expect("apply direct FIPS roster")
                .is_some(),
            "joiner should apply the accepted network"
        );
        joiner.save_config().expect("persist joined config");
        assert!(joiner.config.pending_nostr_join_request.is_some());
        assert_eq!(joiner.config.active_network().network_id, "8d4f34f5425bc50e");
        assert!(joiner.config.active_network_has_confirmed_local_identity());
        let persisted_joiner = AppConfig::load(&joiner.config_path).expect("reload joined iPhone");
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(persisted_joiner.pending_nostr_join_request.is_none());
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert!(persisted_joiner.pending_nostr_join_request.is_some());
        assert_eq!(
            persisted_joiner.active_network().network_id,
            "8d4f34f5425bc50e"
        );

        joiner.config = persisted_joiner;
        joiner.vpn_enabled = true;
        joiner.vpn_active = true;
        joiner.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 0,
            mesh_ready: false,
            peers: vec![DaemonPeerState {
                participant_pubkey: admin_pubkey.clone(),
                last_fips_seen_at: Some(unix_timestamp()),
                reachable: false,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });
        let reloaded_admin = joiner
            .state()
            .networks
            .into_iter()
            .find(|network| network.network_id == "8d4f34f5425bc50e")
            .and_then(|network| {
                network
                    .participants
                    .into_iter()
                    .find(|participant| participant.pubkey_hex == admin_pubkey)
            })
            .expect("persisted accepted admin participant");
        assert_eq!(reloaded_admin.state, "pending");
        assert!(
            reloaded_admin.roster_accepted,
            "transient FIPS reconnection must not undo durable signed-roster acceptance"
        );

        let _ = fs::remove_dir_all(&admin_dir);
        let _ = fs::remove_dir_all(&joiner_dir);
    }

    #[test]
    fn manual_join_seeds_only_the_out_of_band_admin_and_network_id() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-manual-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let admin_hex = normalize_nostr_pubkey(&admin_npub).expect("normalize admin");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::ManualAddNetwork {
            admin_npub,
            mesh_network_id: "8d4f-34f5-425b-c50e".to_string(),
        });

        let network = runtime.config.active_network();
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(network.network_id, "8d4f34f5425bc50e");
        assert_eq!(network.devices, vec![admin_hex.clone()]);
        assert_eq!(network.admins, vec![admin_hex.clone()]);
        assert_eq!(network.join_request_admin, admin_hex);
        assert_ne!(network.join_secret, "");
        assert!(network.outbound_join_request.is_none());
        assert!(runtime.vpn_enabled);
        let state = runtime.state();
        let pending_admin = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == network.admins[0])
            .expect("manual-join admin participant should be visible");
        assert_eq!(
            pending_admin.state, "pending",
            "an out-of-band admin row must remain pending until its signed roster arrives"
        );
        assert_eq!(pending_admin.status_text, "waiting for admin");

        let persisted = AppConfig::load(&runtime.config_path).expect("reload manual network");
        assert_eq!(persisted.active_network().network_id, "8d4f34f5425bc50e");

        runtime.dispatch(NativeAppAction::ManualAddNetwork {
            admin_npub: Keys::generate()
                .public_key()
                .to_bech32()
                .expect("second admin npub"),
            mesh_network_id: "8d4f34f5425bc50e".to_string(),
        });
        assert!(runtime.last_error.contains("already configured"));
        assert_eq!(runtime.config.networks.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mobile_tick_adopts_durably_applied_join_roster_from_tunnel() {
        let dir = unique_service_test_dir("nvpn-mobile-tunnel-roster-refresh");
        let config_path = dir.join("config.toml");
        let now = unix_timestamp();

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path.clone_from(&config_path);
        runtime.config.clear_pending_nostr_join_request();
        runtime
            .config
            .ensure_pending_nostr_join_request(now)
            .expect("create mobile join request");
        let consumed_request = runtime
            .config
            .pending_nostr_join_request
            .clone()
            .expect("pending mobile join request");
        runtime
            .config
            .save(&config_path)
            .expect("persist initial mobile config");

        let mut admin = AppConfig::generated();
        let admin_network_id = admin.networks[0].id.clone();
        admin.networks[0].network_id = "mobile-tunnel-refresh-mesh".to_string();
        admin.networks[0].admins = vec![admin.own_nostr_pubkey_hex().expect("admin pubkey")];
        let bootstrap = nostr_vpn_core::identity_bridge::nostr_identity_device_approval_bootstrap(
            &consumed_request.request,
        )
        .expect("join request bootstrap");
        let approved = prepare_join_approval(&admin, &admin_network_id, &bootstrap, now)
            .expect("prepare approved roster");

        let mut tunnel_config = runtime.config.clone();
        assert_eq!(
            nostr_vpn_core::join_roster_persistence::apply_join_roster_durably(
                &mut tunnel_config,
                &config_path,
                &approved.join_roster,
                now,
            )
            .expect("tunnel durably applies approved roster")
            .as_deref(),
            Some("mobile-tunnel-refresh-mesh")
        );
        assert!(tunnel_config.active_network_has_confirmed_local_identity());

        runtime.dispatch(NativeAppAction::Tick);

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.active_network_has_confirmed_local_identity());
        let state = runtime.state();
        assert!(
            state.networks[0]
                .participants
                .iter()
                .all(|participant| participant.roster_accepted),
            "foreground state must reflect the tunnel's accepted roster"
        );
        assert_ne!(
            runtime
                .config
                .pending_nostr_join_request
                .as_ref()
                .expect("mobile runtime keeps a fresh join request")
                .request
                .request_secret,
            consumed_request.request.request_secret,
            "foreground refresh must not resurrect the request consumed by the tunnel"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn join_approval_respects_disabled_autoconnect() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-offline-approval-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let script_path = dir.join("nvpn");
        let calls_path = dir.join("calls.txt");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "__CALLS__"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{"supported":false,"installed":false,"disabled":false,"loaded":false,"running":false,"pid":null,"label":"","binary_version":""}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  cat <<'JSON'
{"daemon":{"running":false,"state":null}}
JSON
  exit 0
fi
if [ "$1" = "start" ]; then
  exit 17
fi
exit 0
"#
        .replace("__CALLS__", &calls_literal);
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut admin = NativeAppRuntime::from_startup_error(&error);
        admin.startup_error = None;
        admin.last_error.clear();
        admin.mobile_runtime = false;
        admin.config_path = dir.join("config.toml");
        admin.nvpn_bin = Some(script_path);
        let admin_pubkey = admin
            .config
            .own_nostr_pubkey_hex()
            .expect("admin pubkey");
        create_test_network(&mut admin, "Home");
        admin.config.networks[0].admins = vec![admin_pubkey];
        admin.config.autoconnect = false;
        admin
            .config
            .save(&admin.config_path)
            .expect("save admin config");

        let mut joiner = AppConfig::generated_without_networks();
        joiner
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending join request");
        let joiner_pubkey = joiner.own_nostr_pubkey_hex().expect("joiner pubkey");
        let request = joiner
            .pending_nostr_join_request_link(crate::join_request_link::JOIN_REQUEST_LINK_PREFIX)
            .expect("join request link");

        admin.dispatch(NativeAppAction::ImportJoinRequest { request });

        assert!(admin.last_error.is_empty(), "{}", admin.last_error);
        assert!(admin.config.networks[0].devices.contains(&joiner_pubkey));
        assert_eq!(admin.queued_join_rosters.len(), 1);
        let calls = fs::read_to_string(calls_path).expect("read fake nvpn calls");
        assert!(
            !calls.lines().any(|line| line.starts_with("start ")),
            "autoconnect-disabled approval started networking: {calls}"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unsupported_compact_join_request_is_rejected_without_adding_device() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-compact-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut admin = NativeAppRuntime::from_startup_error(&error);
        admin.startup_error = None;
        admin.mobile_runtime = true;
        admin.config_path = dir.join("config.toml");
        let admin_pubkey = admin
            .config
            .own_nostr_pubkey_hex()
            .expect("admin pubkey");
        create_test_network(&mut admin, "Home");
        admin.config.networks[0].admins = vec![admin_pubkey];

        let joiner_pubkey = Keys::generate().public_key().to_hex();
        let compact = format!("nvpn://join-request?app_key={joiner_pubkey}");

        admin.dispatch(NativeAppAction::ImportJoinRequest { request: compact });

        assert!(
            admin.last_error.contains("unsupported join request link"),
            "{}",
            admin.last_error
        );
        assert!(!admin.config.networks[0].devices.contains(&joiner_pubkey));
        assert_eq!(admin.queued_join_rosters, [] as [nostr_vpn_core::fips_control::JoinRosterControl; 0]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_marks_reachable_join_admin_as_pending_until_join_is_accepted() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");

        let admin_hex = Keys::generate().public_key().to_hex();
        runtime.config.networks[0].network_id = "mesh-home".to_string();
        runtime.config.networks[0].devices = Vec::new();
        runtime.config.networks[0].admins = vec![admin_hex.clone()];
        runtime.config.networks[0].join_request_admin = admin_hex.clone();
        runtime.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin_hex.clone(),
            requested_at: 1_726_000_000,
        });
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: admin_hex.clone(),
                tunnel_ip: "10.44.135.191".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let admin = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == admin_hex)
            .expect("admin participant should be visible");

        assert!(admin.reachable);
        assert_eq!(admin.state, "pending");
        assert_eq!(admin.status_text, "join request sent");
        assert!(!admin.roster_accepted);
    }

    #[test]
    fn joined_device_keeps_join_request_qr() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-broadcast-joins-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("persist isolated mobile config");

        let state = runtime.state();
        assert!(state.join_request_qr_code_or_link.starts_with("nvpn://join-request/"));
        assert!(state.networks[0]
            .join_request_qr_code_or_link
            .starts_with("nvpn://join-request/"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn enabling_join_requests_starts_background_fips_listener() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-join-listener-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let calls_path = dir.join("calls.txt");
        let started_path = dir.join("started");
        let script_path = dir.join("nvpn");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let started_literal = started_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let service_running = cfg!(target_os = "macos");
        let service_pid = if service_running { "123" } else { "null" };
        let script = format!(
            r#"#!/bin/sh
CALLS="{calls_literal}"
STARTED="{started_literal}"
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":true,"disabled":false,"loaded":{service_running},"running":{service_running},"pid":{service_pid},"label":"fi.siriusbusiness.nvpn.test","binary_version":"test"}}
JSON
  exit 0
fi
if [ "$1" = "apply-config-daemon" ]; then
  cp "$3" "$5"
  exit 0
fi
if [ "$1" = "status" ]; then
  if [ -f "$STARTED" ]; then
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":false,"vpn_status":"Listening for join requests","expected_peer_count":0,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  else
    cat <<'JSON'
{{"daemon":{{"running":false,"state":null}}}}
JSON
  fi
  exit 0
fi
if [ "$1" = "start" ]; then
  touch "$STARTED"
  exit 0
fi
if [ "$1" = "resume" ] || [ "$1" = "reload" ]; then
  exit 0
fi
exit 0
"#
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = false;
        runtime.config_path = dir.join("config.toml");
        let network_id = create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].listen_for_join_requests = false;
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::SetNetworkJoinRequestsEnabled {
            network_id,
            enabled: true,
        });

        let calls = fs::read_to_string(&calls_path).expect("read fake nvpn calls");
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            started_path.exists(),
            "join listener daemon was not started"
        );
        assert!(calls.contains("start --daemon --connect --config"));
        assert!(runtime.config.networks[0].listen_for_join_requests);
        assert!(runtime.vpn_enabled);
        assert_eq!(runtime.vpn_status, "Listening for join requests");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_exposes_inbound_join_requests_for_ui_shells() {
        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "iPhone".to_string(),
                requested_at: 1_778_998_000,
            });

        let state = runtime.state();
        let request = state.networks[0]
            .inbound_join_requests
            .first()
            .expect("join request should be visible in native state");

        assert_eq!(request.requester_npub, requester_npub);
        assert_eq!(request.requester_pubkey_hex, requester_hex);
        assert_eq!(request.requester_node_name, "iPhone");
        assert_ne!(request.requested_at_text.trim(), "");

        let json = serde_json::to_value(&state).expect("serialize native state");
        assert_eq!(
            json["networks"][0]["inboundJoinRequests"][0]["requesterNpub"],
            requester_npub
        );
        assert_eq!(
            json["networks"][0]["inboundJoinRequests"][0]["requesterNodeName"],
            "iPhone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn desktop_tick_reloads_roster_edits_from_disk() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-desktop-reload-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let script_path = dir.join("nvpn");

        let script = r#"#!/bin/sh
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"fi.siriusbusiness.nvpn.test","binary_version":"test"}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  cat <<'JSON'
{"daemon":{"running":true,"state":{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":true,"vpn_status":"VPN on","expected_peer_count":1,"connected_peer_count":1,"mesh_ready":true,"peers":[]}}}
JSON
  exit 0
fi
exit 0
"#;
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = false;
        runtime.config_path = dir.join("config.toml");
        runtime.nvpn_bin = Some(script_path);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save initial config");
        assert_eq!(runtime.state().networks[0].participants.len(), 1);

        let peer_pubkey = Keys::generate().public_key().to_hex();
        let mut persisted = runtime.config.clone();
        persisted.networks[0].devices = vec![peer_pubkey.clone()];
        persisted
            .save(&runtime.config_path)
            .expect("save external roster edit");

        runtime.dispatch(NativeAppAction::Tick);
        let state = runtime.state();
        let network = &state.networks[0];

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(network.participants.len(), 2);
        assert!(network
            .participants
            .iter()
            .any(|participant| participant.pubkey_hex == peer_pubkey));
        assert_eq!(network.expected_count, 2);

        let _ = fs::remove_dir_all(&dir);
    }
