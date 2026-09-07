fn activate_first_network(config: &mut AppConfig) {
    let network_id = config.networks[0].id.clone();
    config
        .set_network_enabled(&network_id, true)
        .expect("activate first network");
}

#[test]
fn daemon_runtime_state_requires_advertised_routes() {
    let raw = r#"{
  "updated_at": 1773650797,
  "vpn_enabled": true,
  "vpn_active": true,
  "vpn_status": "Connected",
  "expected_peer_count": 1,
  "connected_peer_count": 1,
  "mesh_ready": true,
  "peers": [
{
  "participant_pubkey": "ed91c2fcdf6857157e72497d67be9dad91d865db6407bb0440ca53129e10cb1f",
  "node_id": "6bea57f5-e06b-49d1-83b5-484ab0a3df12",
  "tunnel_ip": "10.44.0.239/32",
  "endpoint": "192.168.178.80:51820",
  "public_key": "+fi3YvMFH0JQFNuQPiPy5xBXNKvpaCKIbbbgrlXT5yw=",
  "last_mesh_seen_at": 1773650779,
  "last_fips_seen_at": 1773650779,
  "reachable": true,
  "last_handshake_at": null,
  "error": null
}
  ]
}"#;

    assert!(serde_json::from_str::<DaemonRuntimeState>(raw).is_err());
}

#[test]
fn read_daemon_state_trims_nul_padding() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-state-trim-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let state_path = dir.join("daemon.state.json");
    let mut raw = br#"{
  "updated_at": 1,
  "binary_version": "test",
  "vpn_enabled": true,
  "vpn_active": true,
  "vpn_status": "Ready",
  "expected_peer_count": 0,
  "connected_peer_count": 0,
  "mesh_ready": false
}"#
    .to_vec();
    raw.extend_from_slice(&[0, 0, b'\n']);
    fs::write(&state_path, raw).expect("write padded daemon state");

    let state = read_daemon_state(&state_path)
        .expect("read daemon state")
        .expect("daemon state should exist");
    assert_eq!(state.vpn_status, "Ready");

    let rewritten = fs::read(&state_path).expect("read rewritten daemon state");
    assert!(!rewritten.contains(&0));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn status_json_peers_preserves_daemon_reachability() {
    let peer = DaemonPeerState {
        participant_pubkey: Keys::generate().public_key().to_hex(),
        node_id: "peer".to_string(),
        tunnel_ip: "10.44.0.2/32".to_string(),
        endpoint: "fips".to_string(),
        runtime_endpoint: Some("203.0.113.2:9000".to_string()),
        fips_endpoint_npub: String::new(),
        fips_transport_addr: "203.0.113.2:9000".to_string(),
        fips_transport_type: "udp".to_string(),
        fips_srtt_ms: Some(7),
        fips_srtt_age_ms: Some(10),
        fips_packets_sent: 1,
        fips_packets_recv: 2,
        fips_bytes_sent: 3,
        fips_bytes_recv: 4,
        fips_rekey_in_progress: false,
        fips_rekey_draining: false,
        fips_current_k_bit: None,
        fips_last_outbound_route: String::new(),
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        fips_nostr_traversal_failures: 0,
        fips_nostr_traversal_in_cooldown: false,
        fips_nostr_traversal_cooldown_until_ms: None,
        fips_nostr_traversal_last_observed_skew_ms: None,
        tx_bytes: 5,
        rx_bytes: 6,
        public_key: String::new(),
        advertised_routes: Vec::new(),
        last_mesh_seen_at: 123,
        last_fips_seen_at: Some(123),
        last_fips_control_seen_at: Some(123),
        last_fips_data_seen_at: Some(123),
        reachable: true,
        last_handshake_at: Some(123),
        error: None,
    };

    let value = crate::status_json_peers(Some(std::slice::from_ref(&peer)), &[]);
    let peers = value.as_array().expect("status peers array");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["reachable"], true);
    assert_eq!(peers[0]["fips_srtt_ms"], 7);
    assert_eq!(peers[0]["fips_transport_type"], "udp");
}

#[cfg(unix)]
#[test]
fn atomic_runtime_write_creates_desktop_readable_file() {
    use std::os::unix::fs::PermissionsExt;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-runtime-mode-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("staged-config.toml");

    write_runtime_file_atomically(&path, b"secret = true\n").expect("write runtime file");
    let mode = fs::metadata(&path)
        .expect("runtime metadata")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(mode, 0o644);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_control_request_projects_desired_vpn_state_immediately() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-project-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let state_path = daemon_state_file_path(&config_path);
    let state = DaemonRuntimeState {
        updated_at: 1,
        vpn_enabled: true,
        vpn_active: true,
        vpn_status: "VPN on".to_string(),
        expected_peer_count: 1,
        connected_peer_count: 1,
        mesh_ready: true,
        ..DaemonRuntimeState::default()
    };
    write_daemon_state(&state_path, &state).expect("write daemon state");

    write_daemon_control_request(&config_path, DaemonControlRequest::Pause)
        .expect("write pause control request");
    let paused = read_daemon_state(&state_path)
        .expect("read projected daemon state")
        .expect("daemon state should exist");
    assert!(!paused.vpn_enabled);
    assert!(paused.vpn_active);
    assert_eq!(paused.vpn_status, "Turning VPN off");

    write_daemon_control_request(&config_path, DaemonControlRequest::Resume)
        .expect("write resume control request");
    let resumed = read_daemon_state(&state_path)
        .expect("read projected daemon state")
        .expect("daemon state should exist");
    assert!(resumed.vpn_enabled);
    assert_eq!(resumed.vpn_status, "VPN on");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_control_request_persists_desired_vpn_state() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-persist-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut config = AppConfig::generated();
    config.autoconnect = true;
    config.save(&config_path).expect("save config");

    write_daemon_control_request(&config_path, DaemonControlRequest::Pause)
        .expect("write pause control request");
    let paused = AppConfig::load(&config_path).expect("load paused config");
    assert!(!paused.autoconnect);

    write_daemon_control_request(&config_path, DaemonControlRequest::Resume)
        .expect("write resume control request");
    let resumed = AppConfig::load(&config_path).expect("load resumed config");
    assert!(resumed.autoconnect);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_start_honors_persisted_desired_vpn_state() {
    let mut config = AppConfig::generated();

    config.autoconnect = true;
    assert!(daemon_start_vpn_enabled(&config, false));
    assert!(!daemon_start_vpn_enabled(&config, true));

    config.autoconnect = false;
    assert!(!daemon_start_vpn_enabled(&config, false));
    assert!(!daemon_start_vpn_enabled(&config, true));
}

#[test]
fn daemon_state_freshness_allows_pid_namespace_status() {
    let state = DaemonRuntimeState {
        updated_at: 100,
        ..DaemonRuntimeState::default()
    };

    assert!(daemon_state_is_fresh(&state, 105, 10));
    assert!(!daemon_state_is_fresh(&state, 111, 10));
    assert!(daemon_state_is_fresh(&state, 99, 10));
    assert!(!daemon_state_is_fresh(&state, 50, 10));
    assert!(!daemon_state_is_fresh(
        &DaemonRuntimeState::default(),
        105,
        10
    ));
}

#[test]
fn daemon_log_compaction_leaves_small_log_untouched() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-log-small-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let log_path = dir.join("daemon.log");
    fs::write(&log_path, "short\n").expect("write daemon log");

    assert!(
        !compact_log_file_if_needed(&log_path, 64, 16).expect("compact daemon log"),
        "small logs should not be compacted"
    );
    assert_eq!(
        fs::read_to_string(&log_path).expect("read daemon log"),
        "short\n"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_log_compaction_keeps_line_aligned_tail() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-log-compact-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let log_path = dir.join("daemon.log");
    fs::write(&log_path, "old-0\nold-1\nold-2\nkeep-1\nkeep-2\n").expect("write daemon log");

    assert!(
        compact_log_file_if_needed(&log_path, 20, 14).expect("compact daemon log"),
        "oversized logs should be compacted"
    );
    let compacted = fs::read_to_string(&log_path).expect("read compacted daemon log");
    assert!(compacted.starts_with("[nvpn] daemon log compacted at "));
    assert!(!compacted.contains("old-0"));
    assert!(!compacted.contains("keep-1"));
    assert!(compacted.ends_with("keep-2\n"));

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn daemon_log_compaction_rejects_symlinked_log() {
    use std::os::unix::fs::symlink;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-log-symlink-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("target.log");
    let log_path = dir.join("daemon.log");
    fs::write(&target, "do-not-compact").expect("write target");
    symlink(&target, &log_path).expect("create daemon log symlink");

    let error = compact_log_file_if_needed(&log_path, 2, 1)
        .expect_err("symlinked daemon log should be rejected");

    assert!(error.to_string().contains("refusing to compact"));
    assert_eq!(
        fs::read_to_string(&target).expect("read target"),
        "do-not-compact"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn daemon_control_publication_does_not_follow_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-links-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join("private-file");
    let config = dir.join("config.toml");
    let control = daemon_control_file_path(&config);
    fs::write(&target, "keep private content").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

    for hard_link in [false, true] {
        if hard_link {
            fs::hard_link(&target, &control).unwrap();
        } else {
            symlink(&target, &control).unwrap();
        }
        write_daemon_control_request(&config, DaemonControlRequest::Stop).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep private content");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(take_daemon_control_request(&config), Some(DaemonControlRequest::Stop));
        assert!(!control.exists());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_log_and_permissions_reject_linked_files_before_mutation() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-runtime-links-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join("private-file");
    let runtime = dir.join("daemon.log");
    fs::write(&target, "keep private content").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();

    for hard_link in [false, true] {
        if hard_link {
            fs::hard_link(&target, &runtime).unwrap();
        } else {
            symlink(&target, &runtime).unwrap();
        }
        assert!(open_daemon_log_file(&runtime).is_err());
        assert!(compact_log_file_if_needed(&runtime, 2, 1).is_err());
        assert!(set_daemon_cleanup_file_permissions(&runtime).is_err());
        assert!(set_private_cache_file_permissions(&runtime).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep private content");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o640);
        fs::remove_file(&runtime).unwrap();
    }
    let mut log = open_daemon_log_file(&runtime).expect("create a regular daemon log");
    std::io::Write::write_all(&mut log, b"normal log entry\n").unwrap();
    assert_eq!(fs::read_to_string(&runtime).unwrap(), "normal log entry\n");
    assert_eq!(fs::metadata(&runtime).unwrap().permissions().mode() & 0o777, 0o644);
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_runtime_operations_reject_fifo_without_waiting_for_a_peer() {
    use std::os::unix::ffi::OsStrExt;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-runtime-fifo-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let runtime = dir.join("daemon.log");
    let path = std::ffi::CString::new(runtime.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(open_daemon_log_file(&runtime).is_err());
    assert!(compact_log_file_if_needed(&runtime, 2, 1).is_err());
    assert!(set_daemon_cleanup_file_permissions(&runtime).is_err());
    assert!(set_private_cache_file_permissions(&runtime).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn daemon_status_ignores_and_quarantines_corrupt_daemon_state() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-status-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    fs::write(&config_path, "").expect("write config placeholder");
    let state_path = dir.join("daemon.state.json");
    fs::write(&state_path, vec![0; 64]).expect("write corrupt daemon state");

    let status = crate::daemon_status(&config_path).expect("daemon status should succeed");
    assert!(status.state.is_none());
    assert!(!state_path.exists());

    let quarantined: Vec<_> = fs::read_dir(&dir)
        .expect("list temp dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with("daemon.state.json.corrupt-"))
        })
        .collect();
    assert_eq!(quarantined.len(), 1);

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn corrupt_network_cleanup_ownership_remains_fail_closed() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-cleanup-corrupt-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let cleanup_path = daemon_network_cleanup_file_path(&config_path);
    fs::create_dir_all(cleanup_path.parent().expect("cleanup parent"))
        .expect("create cleanup parent");
    fs::write(&cleanup_path, b"{not-valid-json").expect("write corrupt cleanup ownership");

    let error = read_daemon_network_cleanup_state(&cleanup_path)
        .expect_err("unreadable cleanup ownership must block repair/startup");
    assert!(
        error
            .to_string()
            .contains("refusing to discard unreadable network cleanup ownership")
    );
    assert!(
        cleanup_path.exists(),
        "a malformed ownership record must remain at its fail-closed path"
    );
    assert!(
        fs::read_dir(cleanup_path.parent().expect("cleanup parent"))
            .expect("list cleanup parent")
            .filter_map(|entry| entry.ok())
            .all(|entry| !entry.file_name().to_string_lossy().contains(".corrupt-")),
        "cleanup ownership must not be quarantined out of the startup path"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn daemon_network_cleanup_snapshot_is_durable_and_private() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-cleanup-mode-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let cleanup_path = daemon_network_cleanup_file_path(&dir.join("config.toml"));
    write_daemon_network_cleanup_state(&cleanup_path, &DaemonNetworkCleanupState::default())
        .expect("persist cleanup ownership privately");
    assert!(
        read_daemon_network_cleanup_state(&cleanup_path)
            .expect("read durable cleanup ownership")
            .is_some(),
        "cleanup ownership must survive durable readback"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&cleanup_path)
            .expect("cleanup metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "cleanup snapshots may contain WireGuard keys");

        #[cfg(target_os = "linux")]
        {
            let parent_mode = fs::metadata(cleanup_path.parent().expect("cleanup parent"))
                .expect("cleanup parent metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                parent_mode, 0o700,
                "Linux cleanup temp/final files need a private parent directory"
            );
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn persist_daemon_runtime_state_marks_vpn_on_as_active() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-state-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let state_path = dir.join("daemon.state.json");

    let mut config = AppConfig::generated();
    config.networks[0].devices = vec!["11".repeat(32)];
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    let relays = [crate::DaemonRelayState {
        url: "wss://relay.example".to_string(),
        status: "connected".to_string(),
    }];
    let fips_endpoint_peers = [crate::DaemonFipsEndpointPeerState {
        npub: "npub1configured".to_string(),
        addresses: vec![crate::DaemonFipsEndpointPeerAddressState {
            addr: "192.0.2.10:51820".to_string(),
            seen_at_ms: None,
            priority: 100,
        }],
        auto_reconnect: true,
        discovery_fallback_transit: false,
    }];

    crate::persist_daemon_runtime_state(
        &state_path,
        crate::DaemonRuntimeStateInput {
            app: &config,
            vpn_enabled: true,
            vpn_active: true,
            expected_peers: 1,
            tunnel_runtime: &tunnel_runtime,
            fips_peer_statuses: &[],
            fips_relay_statuses: &relays,
            fips_endpoint_peers: &fips_endpoint_peers,
            advertised_routes_by_participant: &std::collections::HashMap::new(),
            vpn_status: "VPN on",
            network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
            port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
        },
    )
    .expect("persist daemon runtime state");

    let state = read_daemon_state(&state_path)
        .expect("read daemon state")
        .expect("daemon state should exist");
    assert!(state.vpn_active);
    assert_eq!(state.vpn_status, "VPN on");
    #[cfg(unix)]
    {
        let count = state
            .open_file_descriptor_count
            .expect("daemon state should report open file descriptors");
        let limit = state
            .open_file_descriptor_soft_limit
            .expect("daemon state should report the soft file descriptor limit");
        let types = state
            .open_file_descriptor_types
            .as_ref()
            .expect("daemon state should report sanitized file descriptor types");
        assert!(count > 0);
        assert!(count < limit);
        assert_eq!(types.values().sum::<u64>(), count);
        assert!(types
            .keys()
            .all(|kind| ["event", "file", "other", "pipe", "socket"].contains(&kind.as_str())));
    }
    assert_eq!(state.relays.len(), 1);
    assert_eq!(state.relays[0].status, "connected");
    assert_eq!(state.fips_endpoint_peers.len(), 1);
    assert_eq!(state.fips_endpoint_peers[0].addresses[0].addr, "192.0.2.10:51820");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn fips_runtime_state_is_ready_without_waiting_for_every_peer() {
    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.networks[0].devices = vec!["11".repeat(32), "22".repeat(32)];
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");

    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: true,
        expected_peers: 2,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &[],
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "VPN on",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });

    assert_eq!(state.connected_peer_count, 0);
    assert!(state.vpn_enabled);
    assert!(state.mesh_ready);
    assert_eq!(state.vpn_status, "VPN on");
}

#[test]
fn fips_runtime_state_rejects_far_future_peer_timestamps() {
    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    let peer_pubkey = Keys::generate().public_key().to_hex();
    config.networks[0].devices = vec![peer_pubkey.clone()];
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_secs();

    let fips_peer_statuses = [MeshPeerStatus {
            pubkey: peer_pubkey,
            connected: false,
            endpoint_npub: "npub1endpoint".to_string(),
            transport_addr: None,
            transport_type: None,
            srtt_ms: None,
            srtt_age_ms: None,
            link_packets_sent: 0,
            link_packets_recv: 0,
            link_bytes_sent: 0,
            link_bytes_recv: 0,
            rekey_in_progress: false,
            rekey_draining: false,
            current_k_bit: None,
            last_outbound_route: None,
            direct_probe_pending: false,
            direct_probe_after_ms: None,
            direct_probe_retry_count: 0,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: None,
            nostr_traversal_consecutive_failures: 0,
            nostr_traversal_in_cooldown: false,
            nostr_traversal_cooldown_until_ms: None,
            nostr_traversal_last_observed_skew_ms: None,
            last_seen_at: Some(now + 60),
            last_control_seen_at: Some(now + 60),
            last_data_seen_at: Some(now + 60),
            tx_bytes: 0,
            rx_bytes: 0,
            error: Some("fips link pending".to_string()),
        }];
    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: true,
        expected_peers: 1,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &fips_peer_statuses,
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "VPN on",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });

    assert_eq!(state.peers.len(), 1);
    assert_eq!(state.peers[0].last_mesh_seen_at, 0);
    assert_eq!(state.peers[0].last_fips_seen_at, None);
    assert_eq!(state.peers[0].last_fips_control_seen_at, None);
    assert_eq!(state.peers[0].last_fips_data_seen_at, None);
    assert_eq!(state.peers[0].last_handshake_at, None);
}
