    #[test]
    fn accepting_join_request_uses_requester_node_name_as_alias() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-accept-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let network_id = runtime.config.networks[0].id.clone();
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "Linux Dev".to_string(),
                requested_at: 1_726_000_000,
            });

        runtime.dispatch(NativeAppAction::AcceptJoinRequest {
            network_id: network_id.clone(),
            requester_npub,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            runtime.config.networks[0].devices
                .contains(&requester_hex)
        );
        assert!(runtime.config.networks[0].inbound_join_requests.is_empty());
        assert_eq!(
            runtime.config.peer_alias(&requester_hex).as_deref(),
            Some("linux-dev")
        );
        assert_eq!(
            runtime.queued_join_rosters.len(),
            1,
            "accepting an inbound request must queue the signed roster back to the joiner"
        );
        let manual_token = nostr_vpn_core::join_requests::manual_join_request_token(
            &runtime.config.networks[0].network_id,
            &runtime.config.own_nostr_pubkey_hex().expect("admin pubkey"),
            &requester_hex,
        )
        .expect("manual join request token");
        runtime.queued_join_rosters[0]
            .verify_for_request(&manual_token)
            .expect("request-bound inbound join roster");

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(
            saved.peer_alias(&requester_hex).as_deref(),
            Some("linux-dev")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn adding_a_new_participant_queues_one_receipt_backed_manual_join_roster() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-manual-outbox-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let joiner_keys = Keys::generate();
        let joiner_npub = joiner_keys
            .public_key()
            .to_bech32()
            .expect("joiner npub");
        let joiner_hex = joiner_keys.public_key().to_hex();
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let network_entry_id = runtime.config.networks[0].id.clone();
        let mesh_network_id = runtime.config.networks[0].network_id.clone();
        let admin = runtime.config.own_nostr_pubkey_hex().expect("admin pubkey");

        let action = NativeAppAction::AddParticipant {
            network_id: network_entry_id,
            npub: joiner_npub,
            alias: Some("iPhone".to_string()),
        };
        runtime.dispatch(action.clone());
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(runtime.queued_join_rosters.len(), 1);
        assert_eq!(
            runtime.queued_join_rosters[0]
                .signed_roster
                .signer_pubkey_hex()
                .expect("manual roster signer"),
            admin
        );
        assert!(
            runtime.queued_join_rosters[0]
                .signed_roster
                .roster()
                .expect("manual roster")
                .devices
                .contains(&joiner_hex)
        );

        runtime.dispatch(action);
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(
            runtime.queued_join_rosters.len(),
            1,
            "re-adding an existing participant must not create another delivery"
        );
        assert_eq!(runtime.config.networks[0].network_id, mesh_network_id);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mobile_manual_approval_keeps_explicit_connect_intent_over_stopped_runtime_state() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-manual-connect-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let network_id = runtime.config.networks[0].id.clone();
        fs::write(
            dir.join(MOBILE_RUNTIME_STATE_FILE),
            serde_json::to_vec(&DaemonRuntimeState {
                updated_at: unix_timestamp(),
                vpn_enabled: false,
                vpn_active: false,
                vpn_status: "Disconnected".to_string(),
                ..DaemonRuntimeState::default()
            })
            .expect("encode stopped runtime state"),
        )
        .expect("persist stopped runtime state");

        let joiner = Keys::generate();
        runtime.dispatch(NativeAppAction::AddParticipant {
            network_id,
            npub: joiner.public_key().to_bech32().expect("joiner npub"),
            alias: None,
        });
        let state = runtime.state();

        assert!(state.error.is_empty(), "{}", state.error);
        assert!(
            state.vpn_enabled,
            "the explicit approval connect must survive an old stopped runtime snapshot"
        );
        assert!(state.vpn_active);
        assert_eq!(
            nostr_vpn_core::join_delivery::load_join_rosters(&runtime.config_path).len(),
            1,
            "the signed approval must remain queued until its durable acknowledgement"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    struct FailingJoinStartFixture {
        dir: std::path::PathBuf,
        config_path: std::path::PathBuf,
        calls_path: std::path::PathBuf,
        start_attempted_path: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl Drop for FailingJoinStartFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    fn runtime_with_failing_join_start(
        joiner_npub: &str,
        autoconnect: bool,
    ) -> (NativeAppRuntime, String, FailingJoinStartFixture) {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-join-start-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        let outbox_path = nostr_vpn_core::join_delivery::join_roster_outbox_directory(&config_path);
        let calls_path = dir.join("calls.txt");
        let start_attempted_path = dir.join("start-attempted");
        let script_path = dir.join("nvpn");
        let service_running = cfg!(target_os = "macos");
        let service_pid = if service_running { "123" } else { "null" };
        let script = format!(
            r#"#!/bin/sh
CALLS="{}"
START_ATTEMPTED="{}"
CONFIG="{}"
OUTBOX="{}"
JOINER="{}"
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
  printf '%s\n' '{{"daemon":{{"running":false,"state":null}}}}'
  exit 0
fi
if [ "$1" = "start" ]; then
  grep -q "$JOINER" "$CONFIG" || {{ printf '%s\n' 'joiner missing before start' >&2; exit 18; }}
  find "$OUTBOX" -type f -name '*.json' | grep -q . || {{ printf '%s\n' 'outbox missing before start' >&2; exit 19; }}
  touch "$START_ATTEMPTED"
  exit 17
fi
exit 0
"#,
            shell_literal(&calls_path),
            shell_literal(&start_attempted_path),
            shell_literal(&config_path),
            shell_literal(&outbox_path),
            joiner_npub,
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
        runtime.config_path = config_path.clone();
        runtime.nvpn_bin = Some(script_path);
        let network_id = create_test_network(&mut runtime, "Home");
        let admin = runtime.config.own_nostr_pubkey_hex().expect("admin pubkey");
        runtime.config.networks[0].admins = vec![admin];
        runtime.config.autoconnect = autoconnect;
        runtime.config.save(&config_path).expect("save admin config");

        (
            runtime,
            network_id,
            FailingJoinStartFixture {
                dir,
                config_path,
                calls_path,
                start_attempted_path,
            },
        )
    }

    #[cfg(unix)]
    fn assert_failed_join_start_was_durable(
        runtime: &NativeAppRuntime,
        fixture: &FailingJoinStartFixture,
        joiner_pubkey: &str,
    ) {
        assert!(
            runtime.last_error.contains("nvpn start failed"),
            "{}",
            runtime.last_error
        );
        assert!(
            fixture.start_attempted_path.exists(),
            "join approval did not reach the intentional start failure: {}",
            runtime.last_error
        );
        assert_eq!(
            nostr_vpn_core::join_delivery::load_join_rosters(&fixture.config_path).len(),
            1,
            "join approval must remain exactly once in the durable delivery outbox"
        );
        let persisted = AppConfig::load(&fixture.config_path).expect("load persisted admin config");
        assert!(
            persisted.networks[0].devices.contains(&joiner_pubkey.to_string()),
            "joiner must remain in the persisted participant roster"
        );
        assert!(
            persisted.autoconnect,
            "join approval must persist its networking intent"
        );
        let calls = fs::read_to_string(&fixture.calls_path).expect("read fake nvpn calls");
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.starts_with("start "))
                .count(),
            1,
            "join approval must make one start attempt: {calls}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn manual_admin_add_surfaces_start_failure_after_durable_roster_is_queued() {
        let joiner = Keys::generate();
        let joiner_npub = joiner.public_key().to_bech32().expect("joiner npub");
        let joiner_pubkey = joiner.public_key().to_hex();
        let (mut runtime, network_id, fixture) =
            runtime_with_failing_join_start(&joiner_npub, false);

        runtime.dispatch(NativeAppAction::AddParticipant {
            network_id,
            npub: joiner_npub,
            alias: Some("Pixel".to_string()),
        });

        assert_failed_join_start_was_durable(&runtime, &fixture, &joiner_pubkey);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn manual_admin_add_reloads_live_service_when_cached_runtime_state_is_off() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-live-service-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        let outbox_path = nostr_vpn_core::join_delivery::join_roster_outbox_directory(&config_path);
        let reload_path = dir.join("reload-applied");
        let start_path = dir.join("unexpected-start");
        let script_path = dir.join("nvpn");
        let script = format!(
            r#"#!/bin/sh
CONFIG="{}"
OUTBOX="{}"
RELOADED="{}"
STARTED="{}"
JOINER="{}"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"fi.siriusbusiness.nvpn.test","binary_version":"test"}}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  if [ -f "$RELOADED" ]; then
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":2,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":false,"vpn_status":"Waiting for participants","expected_peer_count":1,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  else
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":false,"vpn_status":"Waiting for participants","expected_peer_count":0,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  fi
  exit 0
fi
if [ "$1" = "reload" ]; then
  grep -q "$JOINER" "$CONFIG" || {{ printf '%s\n' 'joiner missing before reload' >&2; exit 18; }}
  find "$OUTBOX" -type f -name '*.json' | grep -q . || {{ printf '%s\n' 'outbox missing before reload' >&2; exit 19; }}
  touch "$RELOADED"
  exit 0
fi
if [ "$1" = "start" ]; then
  touch "$STARTED"
  exit 20
fi
exit 0
"#,
            shell_literal(&config_path),
            shell_literal(&outbox_path),
            shell_literal(&reload_path),
            shell_literal(&start_path),
            "__JOINER__",
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
        runtime.config_path = config_path.clone();
        runtime.nvpn_bin = Some(script_path);
        let network_id = create_test_network(&mut runtime, "Home");
        let admin = runtime.config.own_nostr_pubkey_hex().expect("admin pubkey");
        runtime.config.networks[0].admins = vec![admin];
        runtime.config.save(&config_path).expect("save admin config");
        runtime.service_running = false;
        runtime.daemon_running = false;

        let joiner = Keys::generate();
        let joiner_npub = joiner.public_key().to_bech32().expect("joiner npub");
        let joiner_hex = joiner.public_key().to_hex();
        let script = fs::read_to_string(runtime.nvpn_bin.as_ref().expect("fake nvpn path"))
            .expect("read fake nvpn")
            .replace("__JOINER__", &joiner_npub);
        fs::write(runtime.nvpn_bin.as_ref().expect("fake nvpn path"), script)
            .expect("update fake nvpn joiner");

        runtime.dispatch(NativeAppAction::AddParticipant {
            network_id,
            npub: joiner_npub,
            alias: Some("Pixel".to_string()),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(reload_path.exists(), "live service was not reloaded");
        assert!(!start_path.exists(), "join approval attempted a duplicate daemon start");
        let persisted = AppConfig::load(&config_path).expect("load persisted admin config");
        assert!(persisted.participant_pubkeys_hex().contains(&joiner_hex));
        assert_eq!(
            nostr_vpn_core::join_delivery::load_join_rosters(&config_path).len(),
            1,
            "delivery must remain queued for the live daemon"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn qr_join_approval_surfaces_start_failure_after_durable_roster_is_queued() {
        let mut joiner = AppConfig::generated_without_networks();
        joiner
            .ensure_pending_nostr_join_request(unix_timestamp())
            .expect("pending join request");
        let joiner_pubkey = joiner.own_nostr_pubkey_hex().expect("joiner pubkey");
        let joiner_npub = npub_for_pubkey_hex(&joiner_pubkey);
        let request = joiner
            .pending_nostr_join_request_link(crate::join_request_link::JOIN_REQUEST_LINK_PREFIX)
            .expect("join request link");
        let (mut runtime, _network_id, fixture) =
            runtime_with_failing_join_start(&joiner_npub, true);

        runtime.dispatch(NativeAppAction::ImportJoinRequest { request });

        assert_failed_join_start_was_durable(&runtime, &fixture, &joiner_pubkey);
    }

    #[test]
    fn accepting_join_request_requires_pending_request() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-accept-missing-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let network_id = runtime.config.networks[0].id.clone();

        runtime.dispatch(NativeAppAction::AcceptJoinRequest {
            network_id,
            requester_npub,
        });

        assert!(
            runtime.last_error.contains("no pending join request"),
            "{}",
            runtime.last_error
        );
        assert!(
            !runtime.config.networks[0].devices
                .contains(&requester_hex)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejecting_join_request_removes_it_without_adding_participant() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-reject-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let network_id = runtime.config.networks[0].id.clone();
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "Ubuntu Dev".to_string(),
                requested_at: 1_726_000_000,
            });

        runtime.dispatch(NativeAppAction::RejectJoinRequest {
            network_id,
            requester_npub,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            !runtime.config.networks[0].devices
                .contains(&requester_hex)
        );
        assert!(runtime.config.networks[0].inbound_join_requests.is_empty());

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks[0].inbound_join_requests.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
    fn shell_literal(path: &Path) -> String {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }
