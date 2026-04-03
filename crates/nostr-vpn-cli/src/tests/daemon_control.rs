use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::control_daemon_request_for_test;
use crate::*;
use nostr_vpn_core::presence::PeerPresenceBook;

#[test]
fn daemon_runtime_state_requires_advertised_routes() {
    let raw = r#"{
  "updated_at": 1773650797,
  "session_active": true,
  "relay_connected": true,
  "session_status": "Connected",
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
  "presence_timestamp": 1773650779,
  "last_signal_seen_at": 1773650779,
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
  "session_active": true,
  "relay_connected": false,
  "session_status": "Ready",
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
    assert_eq!(state.session_status, "Ready");

    let rewritten = fs::read(&state_path).expect("read rewritten daemon state");
    assert!(!rewritten.contains(&0));

    let _ = fs::remove_dir_all(&dir);
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

#[test]
fn persist_daemon_runtime_state_marks_resuming_as_active() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-state-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let state_path = dir.join("daemon.state.json");

    let mut config = AppConfig::generated();
    config.networks[0].participants = vec!["11".repeat(32)];
    let presence = PeerPresenceBook::default();
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");

    crate::persist_daemon_runtime_state(
        &state_path,
        &config,
        true,
        1,
        &presence,
        &tunnel_runtime,
        None,
        "Resuming",
        false,
        &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
        &crate::LocalRelayOperatorRuntime::default(),
    )
    .expect("persist daemon runtime state");

    let state = read_daemon_state(&state_path)
        .expect("read daemon state")
        .expect("daemon state should exist");
    assert!(state.session_active);
    assert_eq!(state.session_status, "Resuming");
    assert!(!state.relay_connected);

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(target_os = "macos")]
#[test]
fn persist_daemon_network_cleanup_state_writes_and_clears_macos_state() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-cleanup-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    fs::write(&config_path, "").expect("write config placeholder");

    let mut tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    tunnel_runtime.endpoint_bypass_routes =
        vec!["203.0.113.10/32".to_string(), "198.51.100.9/32".to_string()];
    tunnel_runtime.original_default_route = Some(crate::MacosRouteSpec {
        gateway: Some("192.168.64.1".to_string()),
        interface: "en0".to_string(),
    });
    tunnel_runtime.exit_node_runtime.ipv4_forward_was_enabled = Some(false);
    tunnel_runtime.exit_node_runtime.pf_was_enabled = Some(false);

    persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
        .expect("persist daemon cleanup state");

    let cleanup_path = daemon_network_cleanup_file_path(&config_path);
    let cleanup = read_daemon_network_cleanup_state(&cleanup_path)
        .expect("read daemon cleanup state")
        .expect("cleanup state should exist");
    assert_eq!(cleanup.iface, "utun100");
    assert_eq!(
        cleanup.endpoint_bypass_routes,
        tunnel_runtime.endpoint_bypass_routes
    );
    assert_eq!(
        cleanup.original_default_route,
        tunnel_runtime.original_default_route
    );
    assert_eq!(cleanup.ipv4_forward_was_enabled, Some(false));
    assert_eq!(cleanup.pf_was_enabled, Some(false));

    persist_daemon_network_cleanup_state(&config_path, &crate::CliTunnelRuntime::new("utun100"))
        .expect("clear daemon cleanup state");
    assert!(!cleanup_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn macos_route_delete_error_is_absent_matches_missing_route_output() {
    assert!(macos_route_delete_error_is_absent(
        "command failed: route -n delete -ifscope utun100 default\nstdout: not in table\nstderr:"
    ));
    assert!(macos_route_delete_error_is_absent(
        "command failed: route -n delete -host 203.0.113.8\nstdout:\nstderr: route: writing to routing socket: No such process"
    ));
    assert!(!macos_route_delete_error_is_absent(
        "command failed: route -n delete -host 203.0.113.8\nstdout:\nstderr: permission denied"
    ));
}

#[test]
fn macos_default_routes_from_netstat_finds_underlay_and_utun_routes() {
    let routes = macos_default_routes_from_netstat(
        "Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
default            192.168.64.1       UGScg                 en0\n\
default            link#13            UCSIg               utun5\n\
default            link#26            UCSIg           bridge100      !\n",
    );

    assert_eq!(
        routes,
        vec![
            crate::MacosRouteSpec {
                gateway: Some("192.168.64.1".to_string()),
                interface: "en0".to_string(),
            },
            crate::MacosRouteSpec {
                gateway: None,
                interface: "utun5".to_string(),
            },
            crate::MacosRouteSpec {
                gateway: None,
                interface: "bridge100".to_string(),
            },
        ]
    );

    assert_eq!(
        macos_underlay_default_route_from_routes(&routes),
        Some(crate::MacosRouteSpec {
            gateway: Some("192.168.64.1".to_string()),
            interface: "en0".to_string(),
        })
    );
}

#[test]
fn macos_ifconfig_has_ipv4_matches_exact_interface_address() {
    let output = "utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
\tinet 10.44.10.23 --> 10.44.10.23 netmask 0xffffffff\n\
\tinet6 fe80::1%utun5 prefixlen 64 scopeid 0x8\n";

    assert!(macos_ifconfig_has_ipv4(
        output,
        Ipv4Addr::new(10, 44, 10, 23)
    ));
    assert!(!macos_ifconfig_has_ipv4(
        output,
        Ipv4Addr::new(10, 44, 10, 24)
    ));
}

#[test]
fn daemon_runtime_state_tracks_live_endpoint_and_listen_port() {
    let config = AppConfig::generated();
    let presence = PeerPresenceBook::default();
    let mut tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    tunnel_runtime.active_listen_port = Some(53083);
    let public_endpoint = crate::DiscoveredPublicSignalEndpoint {
        listen_port: 53083,
        endpoint: "203.0.113.8:53083".to_string(),
    };
    let state = crate::build_daemon_runtime_state(
        &config,
        true,
        0,
        &presence,
        &tunnel_runtime,
        Some(&public_endpoint),
        "Connected",
        true,
        &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
        &crate::LocalRelayOperatorRuntime::default(),
    );
    let daemon = crate::DaemonStatus {
        running: true,
        pid: Some(1),
        pid_file: std::path::PathBuf::from("/tmp/nvpn.pid"),
        log_file: std::path::PathBuf::from("/tmp/nvpn.log"),
        state_file: std::path::PathBuf::from("/tmp/nvpn.state.json"),
        state: Some(state.clone()),
    };

    assert_eq!(state.listen_port, 53083);
    assert_eq!(
        state.local_endpoint,
        crate::local_signal_endpoint(&config, 53083)
    );
    assert_eq!(state.advertised_endpoint, "203.0.113.8:53083");
    assert_eq!(
        crate::status_endpoint(&config, &daemon),
        "203.0.113.8:53083"
    );
    assert_eq!(crate::status_listen_port(&config, &daemon), 53083);
}

#[test]
fn daemon_pid_scan_matches_processes_for_config() {
    let config_path = Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml");
    let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
              97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
              55555 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /tmp/other.toml --iface utun100\n";
    let pids = daemon_pids_from_ps_output(ps, config_path);
    assert_eq!(pids, vec![42063, 97597]);
}

#[test]
fn daemon_pid_scan_ignores_shell_wrappers_that_mention_nvpn_daemon() {
    let config_path = Path::new("/root/.config/nvpn/config.toml");
    let ps = "2433278 bash -c set -e; nohup /root/nostr-vpn-current/target/debug/nvpn daemon --config /root/.config/nvpn/config.toml --iface utun100 >/root/.config/nvpn/launch.out 2>&1 </dev/null & sleep 5\n\
2433301 /root/nostr-vpn-current/target/debug/nvpn daemon --config /root/.config/nvpn/config.toml --iface utun100 --announce-interval-secs 20\n";

    let pids = daemon_pids_from_ps_output(ps, config_path);

    assert_eq!(pids, vec![2433301]);
}

#[test]
fn relay_operator_advertise_host_prefers_public_signal_endpoint() {
    let mut config = AppConfig::generated();
    config.node.endpoint = "192.168.1.40:51820".to_string();
    let public_endpoint = crate::DiscoveredPublicSignalEndpoint {
        listen_port: 51820,
        endpoint: "203.0.113.8:51820".to_string(),
    };

    assert_eq!(
        crate::relay_operator_advertise_host(&config, Some(&public_endpoint)),
        Some("203.0.113.8".to_string())
    );
}

#[test]
fn relay_operator_advertise_host_rejects_private_endpoint_without_public_mapping() {
    let mut config = AppConfig::generated();
    config.node.endpoint = "192.168.1.40:51820".to_string();
    assert_eq!(crate::relay_operator_advertise_host(&config, None), None);

    config.node.endpoint = "198.51.100.7:51820".to_string();
    assert_eq!(
        crate::relay_operator_advertise_host(&config, None),
        Some("198.51.100.7".to_string())
    );
}

#[test]
fn windows_daemon_pid_scan_matches_processes_for_config() {
    let config_path = Path::new("C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml");
    let cim_json = r#"[{"ProcessId":42063,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"},{"ProcessId":97597,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"},{"ProcessId":55555,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\temp\\other.toml\" --iface NostrVPN"}]"#;
    let pids = crate::daemon_pids_from_windows_cim_json(cim_json, config_path);
    assert_eq!(pids, vec![42063, 97597]);
}

#[test]
fn windows_daemon_pid_scan_accepts_single_process_object() {
    let config_path = Path::new("C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml");
    let cim_json = r#"{"ProcessId":42063,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"}"#;
    let pids = crate::daemon_pids_from_windows_cim_json(cim_json, config_path);
    assert_eq!(pids, vec![42063]);
}

#[test]
fn windows_service_bin_path_runs_hidden_service_daemon_with_same_config() {
    let executable = Path::new("C:\\Program Files\\Nostr VPN\\nvpn.exe");
    let config_path = Path::new("C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml");

    let command = windows_service_bin_path(executable, config_path, "nvpn", 20);

    assert!(command.starts_with("\"C:\\Program Files\\Nostr VPN\\nvpn.exe\""));
    assert!(command.contains(" daemon "));
    assert!(command.contains(" --service "));
    assert!(command.contains(" --config "));
    assert!(command.contains("\"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\""));
    assert!(command.contains(" --iface \"nvpn\""));
    assert!(command.contains(" --announce-interval-secs 20"));
}

#[test]
fn windows_tasklist_pid_parser_extracts_pids() {
    let output = "\"nvpn.exe\",\"9564\",\"Services\",\"0\",\"172,248 K\"\n\"nvpn.exe\",\"3496\",\"Console\",\"1\",\"19,472 K\"\n";
    assert_eq!(crate::tasklist_pids_from_output(output), vec![3496, 9564]);
}

#[test]
fn windows_tasklist_pid_parser_ignores_no_tasks_message() {
    let output = "INFO: No tasks are running which match the specified criteria.\r\n";
    assert!(crate::tasklist_pids_from_output(output).is_empty());
}

#[test]
fn recent_windows_daemon_pid_candidate_uses_fresh_state_and_single_other_process() {
    let state = DaemonRuntimeState {
        updated_at: 100,
        ..Default::default()
    };
    assert_eq!(
        crate::recent_windows_daemon_pid_candidate(Some(&state), 42, &[42, 9564], 103),
        Some(9564)
    );
    assert_eq!(
        crate::recent_windows_daemon_pid_candidate(Some(&state), 42, &[42, 9564], 106),
        None
    );
    assert_eq!(
        crate::recent_windows_daemon_pid_candidate(Some(&state), 42, &[42, 9564, 97597], 103),
        None
    );
    assert_eq!(
        crate::recent_windows_daemon_pid_candidate(None, 42, &[42, 9564], 103),
        None
    );
}

#[test]
fn visible_daemon_state_for_status_keeps_state_while_running() {
    let state = DaemonRuntimeState {
        session_active: true,
        ..Default::default()
    };

    let visible = crate::visible_daemon_state_for_status(true, Some(&state));
    assert!(visible.is_some());
    assert!(visible.expect("visible state").session_active);
}

#[test]
fn visible_daemon_state_for_status_hides_state_when_stopped() {
    let state = DaemonRuntimeState {
        session_active: true,
        ..Default::default()
    };

    assert!(crate::visible_daemon_state_for_status(false, Some(&state)).is_none());
}

#[test]
fn daemon_reload_config_uses_reloaded_network_id() {
    let mut app = AppConfig::generated();
    app.set_active_network_id("mesh-home")
        .expect("set initial network id");
    app.networks[0].participants = vec!["11".repeat(32)];
    let initial_network_id = app.effective_network_id();

    app.set_active_network_id("mesh-work")
        .expect("set reloaded network id");
    app.networks[0].participants = vec!["22".repeat(32)];
    let reloaded_network_id = app.effective_network_id();
    assert_ne!(initial_network_id, reloaded_network_id);

    let reload = build_daemon_reload_config(
        app,
        reloaded_network_id.clone(),
        &["wss://relay.example.com".to_string()],
    );

    assert_eq!(reload.network_id, reloaded_network_id);
    assert_eq!(reload.configured_participants, vec!["22".repeat(32)]);
    assert_eq!(reload.relays, vec!["wss://relay.example.com".to_string()]);
}

#[test]
fn daemon_pid_scan_excludes_current_pid_when_filtering_duplicates() {
    let config_path = Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml");
    let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
              97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n";
    let mut pids = daemon_pids_from_ps_output(ps, config_path);
    pids.retain(|pid| *pid != 97597);
    assert_eq!(pids, vec![42063]);
}

#[test]
fn default_cli_install_path_uses_nvpn_filename() {
    let path = default_cli_install_path();
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(if cfg!(target_os = "windows") {
            "nvpn.exe"
        } else {
            "nvpn"
        })
    );
}

#[test]
fn default_tunnel_iface_matches_platform() {
    let iface = crate::default_tunnel_iface();
    assert_eq!(
        iface,
        if cfg!(target_os = "windows") {
            "nvpn"
        } else {
            "utun100"
        }
    );
}

#[test]
fn install_cli_and_uninstall_cli_roundtrip_for_custom_path() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-install-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let target = dir.join("nvpn");

    install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: false,
    })
    .expect("install custom cli target");
    assert!(target.exists(), "installed target should exist");

    let duplicate = install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: false,
    });
    assert!(duplicate.is_err(), "install without --force should fail");

    install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: true,
    })
    .expect("force reinstall custom cli target");

    uninstall_cli(UninstallCliArgs {
        path: Some(target.clone()),
    })
    .expect("uninstall custom cli target");
    assert!(!target.exists(), "uninstall should remove target");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn apply_config_file_writes_target_config() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-apply-config-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let source = dir.join("source.toml");
    let target = dir.join("target.toml");
    let mut config = AppConfig::generated();
    config.node_name = "windows-box".to_string();
    config.networks[0].participants = vec!["ab".repeat(32)];
    config.save(&source).expect("save source config");

    apply_config_file(&source, &target).expect("apply config should succeed");

    let loaded = AppConfig::load(&target).expect("load target config");
    assert_eq!(loaded.node_name, "windows-box");
    assert_eq!(loaded.participant_pubkeys_hex(), vec!["ab".repeat(32)]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stage_daemon_config_apply_writes_staged_file() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-stage-config-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let source = dir.join("source.toml");
    let target = dir.join("config.toml");
    let mut config = AppConfig::generated();
    config.node_name = "staged-node".to_string();
    config.save(&source).expect("save source config");

    stage_daemon_config_apply(&target, &source).expect("stage config should succeed");

    let staged = daemon_staged_config_file_path(&target);
    let loaded = AppConfig::load(&staged).expect("load staged config");
    assert_eq!(loaded.node_name, "staged-node");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn update_daemon_config_from_staged_request_replaces_target_and_cleans_up() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-stage-apply-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let source = dir.join("source.toml");
    let target = dir.join("config.toml");
    let mut source_config = AppConfig::generated();
    source_config.node_name = "service-owned".to_string();
    source_config.save(&source).expect("save source config");

    let mut target_config = AppConfig::generated();
    target_config.node_name = "old-name".to_string();
    target_config.save(&target).expect("save target config");

    stage_daemon_config_apply(&target, &source).expect("stage config should succeed");
    update_daemon_config_from_staged_request(&target).expect("apply staged config");

    let loaded = AppConfig::load(&target).expect("load target config");
    assert_eq!(loaded.node_name, "service-owned");
    assert!(
        !daemon_staged_config_file_path(&target).exists(),
        "staged config should be cleaned up"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn kill_error_fallback_matcher_detects_permission_denied() {
    assert!(kill_error_requires_control_fallback(
        "kill -TERM 123 failed\nstderr: Operation not permitted"
    ));
    assert!(kill_error_requires_control_fallback(
        "kill -TERM 123 failed\nstderr: permission denied"
    ));
    assert!(!kill_error_requires_control_fallback(
        "kill -TERM 123 failed\nstderr: no such process"
    ));
}

#[test]
fn daemon_control_stop_request_roundtrip() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("config.toml");
    fs::write(&config, "node_name = \"test\"").expect("write config");

    request_daemon_stop(&config).expect("write stop request");
    assert!(
        take_daemon_control_request(&config) == Some(crate::DaemonControlRequest::Stop),
        "daemon should read stop request"
    );
    request_daemon_reload(&config).expect("write reload request");
    assert!(
        take_daemon_control_request(&config) == Some(crate::DaemonControlRequest::Reload),
        "daemon should read reload request"
    );
    control_daemon_request_for_test(&config, crate::DaemonControlRequest::Pause);
    assert!(
        take_daemon_control_request(&config) == Some(crate::DaemonControlRequest::Pause),
        "daemon should read pause request"
    );
    control_daemon_request_for_test(&config, crate::DaemonControlRequest::Resume);
    assert!(
        take_daemon_control_request(&config) == Some(crate::DaemonControlRequest::Resume),
        "daemon should read resume request"
    );
    let _ = fs::remove_file(daemon_control_file_path(&config));
    assert!(
        take_daemon_control_request(&config).is_none(),
        "without control file there should be no stop request"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_control_timeout_errors_use_generic_service_wording() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-timeout-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("config.toml");
    fs::write(&config, "node_name = \"test\"").expect("write config");

    let ack_error = crate::wait_for_daemon_control_ack(&config, Duration::from_millis(0))
        .expect_err("ack wait should time out");
    assert!(
        ack_error
            .to_string()
            .contains("background service may be busy or stuck")
    );
    assert!(!ack_error.to_string().contains("newer nvpn binary"));

    let result_error = crate::wait_for_daemon_control_result(
        &config,
        crate::DaemonControlRequest::Reload,
        Duration::from_millis(0),
    )
    .expect_err("result wait should time out");
    assert!(
        result_error
            .to_string()
            .contains("background service may be busy or stuck")
    );
    assert!(!result_error.to_string().contains("newer nvpn binary"));

    let session_error =
        crate::wait_for_daemon_session_active(&config, true, Duration::from_millis(0))
            .expect_err("session wait should time out");
    assert!(
        session_error
            .to_string()
            .contains("background service may be busy or stuck")
    );
    assert!(
        !session_error
            .to_string()
            .contains("older nvpn daemon binary is still running")
    );

    let _ = fs::remove_dir_all(&dir);
}
