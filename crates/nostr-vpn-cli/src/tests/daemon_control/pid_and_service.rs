#[test]
fn daemon_runtime_state_tracks_live_endpoint_and_listen_port() {
    let mut config = AppConfig::generated();
    config.node.endpoint = "198.51.100.10:51820".to_string();
    let mut tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    tunnel_runtime.active_listen_port = Some(53083);
    tunnel_runtime.paid_exit_seller_ready = true;
    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: false,
        expected_peers: 0,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &[],
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "Connected",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });
    let daemon = crate::DaemonStatus {
        running: true,
        pid: Some(1),
        pid_file: std::path::PathBuf::from("/tmp/nvpn.pid"),
        log_file: std::path::PathBuf::from("/tmp/nvpn.log"),
        state_file: std::path::PathBuf::from("/tmp/nvpn.state.json"),
        state: Some(state.clone()),
    };

    assert_eq!(state.listen_port, 53083);
    assert!(!state.vpn_active);
    assert!(state.paid_exit_seller_ready);
    let expected_endpoint = crate::local_signal_endpoint(&config, 53083);
    assert_eq!(state.local_endpoint, expected_endpoint);
    // advertised_endpoint now mirrors local_endpoint — fips-core owns
    // public-endpoint discovery and advertising.
    assert_eq!(state.advertised_endpoint, expected_endpoint);
    assert_eq!(crate::status_endpoint(&config, &daemon), expected_endpoint);
    assert_eq!(crate::status_listen_port(&config, &daemon), 53083);
}

#[test]
fn daemon_runtime_state_does_not_claim_an_unbound_configured_port() {
    let mut config = AppConfig::generated();
    config.node.endpoint = "198.51.100.10:51820".to_string();
    config.node.listen_port = 51820;
    let tunnel_runtime = crate::CliTunnelRuntime::new("utun100");
    let state = crate::build_daemon_runtime_state(crate::DaemonRuntimeStateInput {
        app: &config,
        vpn_enabled: true,
        vpn_active: true,
        expected_peers: 0,
        tunnel_runtime: &tunnel_runtime,
        fips_peer_statuses: &[],
        fips_relay_statuses: &[],
        fips_endpoint_peers: &[],
        advertised_routes_by_participant: &std::collections::HashMap::new(),
        vpn_status: "Connected",
        network: &nostr_vpn_core::diagnostics::NetworkSummary::default(),
        port_mapping: &nostr_vpn_core::diagnostics::PortMappingStatus::default(),
    });
    let daemon = crate::DaemonStatus {
        running: true,
        pid: Some(1),
        pid_file: "/tmp/nvpn.pid".into(),
        log_file: "/tmp/nvpn.log".into(),
        state_file: "/tmp/nvpn.state.json".into(),
        state: Some(state.clone()),
    };

    assert_eq!(state.listen_port, 0);
    assert!(state.advertised_endpoint.is_empty());
    assert_eq!(crate::status_listen_port(&config, &daemon), 0);
    assert!(crate::status_endpoint(&config, &daemon).is_empty());
}

#[test]
fn daemon_pid_scan_matches_processes_for_config() {
    let config_path = Path::new("/Users/example/Library/Application Support/nvpn/config.toml");
    let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n\
              97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n\
              55555 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /tmp/other.toml --iface utun100\n";
    let pids = daemon_pids_from_ps_output(ps, config_path);
    assert_eq!(pids, vec![42063, 97597]);
}

#[test]
fn daemon_pid_scan_ignores_exiting_processes_for_config() {
    let config_path = Path::new("/Users/example/Library/Application Support/nvpn/config.toml");
    let ps = "  42063 UNE /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n\
              97597 Ss /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n";

    let pids = daemon_pids_from_ps_output(ps, config_path);

    assert_eq!(pids, vec![97597]);
}

#[test]
fn daemon_pid_scan_matches_macos_service_helper_path() {
    // /Library/PrivilegedHelperTools/to.nostrvpn.nvpn is the stable
    // service-owned path the launchd plist points at. Its basename ends with
    // `.nvpn`, not `/nvpn`, so the original heuristic missed it and `nvpn
    // status` reported `daemon.running: false` even when the launchd daemon
    // was healthy.
    let config_path = Path::new("/Users/example/Library/Application Support/nvpn/config.toml");
    let ps = "  2853 Ss /Library/PrivilegedHelperTools/to.nostrvpn.nvpn daemon --service --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun --mesh-refresh-interval-secs 20\n";
    let pids = daemon_pids_from_ps_output(ps, config_path);
    assert_eq!(pids, vec![2853]);
}

#[test]
fn daemon_pid_scan_matches_macos_service_helper_with_config_suffix() {
    let config_path = Path::new("/tmp/custom/config.toml");
    let ps = "  3001 Ss /Library/PrivilegedHelperTools/to.nostrvpn.nvpn.tmp_custom daemon --service --config /tmp/custom/config.toml\n";
    let pids = daemon_pids_from_ps_output(ps, config_path);
    assert_eq!(pids, vec![3001]);
}

#[cfg(unix)]
#[test]
fn daemon_command_matches_canonicalized_config_path() {
    use std::os::unix::fs::symlink;

    let unique = format!(
        "nvpn-daemon-scan-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    let real_dir = root.join("real");
    let linked_dir = root.join("linked");
    fs::create_dir_all(&real_dir).expect("create real config directory");
    symlink(&real_dir, &linked_dir).expect("create config directory symlink");
    let real_config = real_dir.join("config.toml");
    let linked_config = linked_dir.join("config.toml");
    fs::write(&real_config, "").expect("create config");
    let canonical_config = fs::canonicalize(&real_config).expect("canonicalize real config");

    let command = format!(
        "/Library/PrivilegedHelperTools/to.nostrvpn.nvpn.test daemon --service --config {}",
        canonical_config.display()
    );
    assert!(daemon_command_matches_config(&command, &linked_config));

    fs::remove_dir_all(&root).expect("remove config fixture");
}

#[test]
fn daemon_pid_scan_ignores_shell_wrappers_that_mention_nvpn_daemon() {
    let config_path = Path::new("/root/.config/nvpn/config.toml");
    let ps = "2433278 bash -c set -e; nohup /root/nostr-vpn-current/target/debug/nvpn daemon --config /root/.config/nvpn/config.toml --iface utun100 >/root/.config/nvpn/launch.out 2>&1 </dev/null & sleep 5\n\
2433301 /root/nostr-vpn-current/target/debug/nvpn daemon --config /root/.config/nvpn/config.toml --iface utun100 --mesh-refresh-interval-secs 20\n";

    let pids = daemon_pids_from_ps_output(ps, config_path);

    assert_eq!(pids, vec![2433301]);
}

#[test]
fn windows_daemon_pid_scan_matches_processes_for_config() {
    let config_path = Path::new("C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml");
    let cim_json = r#"[{"ProcessId":42063,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"},{"ProcessId":97597,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"},{"ProcessId":55555,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\temp\\other.toml\" --iface NostrVPN"}]"#;
    let pids = crate::daemon_pids_from_windows_cim_json(cim_json, config_path);
    assert_eq!(pids, vec![42063, 97597]);
}

#[test]
fn windows_daemon_pid_scan_accepts_single_process_object() {
    let config_path = Path::new("C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml");
    let cim_json = r#"{"ProcessId":42063,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"}"#;
    let pids = crate::daemon_pids_from_windows_cim_json(cim_json, config_path);
    assert_eq!(pids, vec![42063]);
}

#[test]
fn windows_daemon_pid_record_requires_same_pid_and_config() {
    let config_path = Path::new("C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml");
    let exact_daemon = r#"{"ProcessId":1736,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"}"#;
    let reused_pid = r#"{"ProcessId":1736,"CommandLine":"\"C:\\Windows\\System32\\notepad.exe\""}"#;
    let other_config = r#"{"ProcessId":1736,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\temp\\other.toml\" --iface NostrVPN"}"#;
    let other_pid = r#"{"ProcessId":42063,"CommandLine":"\"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --config \"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\" --iface NostrVPN"}"#;

    assert!(crate::windows_daemon_pid_record_matches_cim(
        1736,
        exact_daemon,
        config_path
    ));
    assert!(!crate::windows_daemon_pid_record_matches_cim(
        1736,
        reused_pid,
        config_path
    ));
    assert!(!crate::windows_daemon_pid_record_matches_cim(
        1736,
        other_config,
        config_path
    ));
    assert!(!crate::windows_daemon_pid_record_matches_cim(
        1736,
        other_pid,
        config_path
    ));
}

#[test]
fn windows_service_bin_path_runs_hidden_service_daemon_with_same_config() {
    let executable = Path::new("C:\\Program Files\\Nostr VPN\\nvpn.exe");
    let config_path = Path::new("C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml");

    let command = windows_service_bin_path(executable, config_path, "nvpn", 60);

    assert!(command.starts_with("\"C:\\Program Files\\Nostr VPN\\nvpn.exe\""));
    assert!(command.contains(" daemon "));
    assert!(command.contains(" --service "));
    assert!(command.contains(" --config "));
    assert!(command.contains("\"C:\\Users\\Example\\AppData\\Roaming\\nvpn\\config.toml\""));
    assert!(command.contains(" --iface \"nvpn\""));
    assert!(command.contains(" --mesh-refresh-interval-secs 60"));
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
        vpn_active: true,
        ..Default::default()
    };

    let visible = crate::visible_daemon_state_for_status(true, Some(&state));
    assert!(visible.is_some());
    assert!(visible.expect("visible state").vpn_active);
}

#[test]
fn visible_daemon_state_for_status_hides_state_when_stopped() {
    let state = DaemonRuntimeState {
        vpn_active: true,
        ..Default::default()
    };

    assert!(crate::visible_daemon_state_for_status(false, Some(&state)).is_none());
}

#[test]
fn daemon_reload_config_uses_reloaded_network_id() {
    let mut app = AppConfig::generated();
    activate_first_network(&mut app);
    app.set_active_network_id("mesh-home")
        .expect("set initial network id");
    app.networks[0].devices = vec!["11".repeat(32)];
    let initial_network_id = app.effective_network_id();

    app.set_active_network_id("mesh-work")
        .expect("set reloaded network id");
    app.networks[0].devices = vec!["22".repeat(32)];
    let reloaded_network_id = app.effective_network_id();
    assert_ne!(initial_network_id, reloaded_network_id);

    let reload = build_daemon_reload_config(app, reloaded_network_id.clone());

    assert_eq!(reload.network_id, reloaded_network_id);
}

#[test]
fn daemon_pid_scan_excludes_current_pid_when_filtering_duplicates() {
    let config_path = Path::new("/Users/example/Library/Application Support/nvpn/config.toml");
    let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n\
              97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/example/Library/Application Support/nvpn/config.toml --iface utun100\n";
    let mut pids = daemon_pids_from_ps_output(ps, config_path);
    pids.retain(|pid| *pid != 97597);
    assert_eq!(pids, vec![42063]);
}

#[test]
fn unix_process_stat_treats_exiting_and_dead_states_as_not_running() {
    assert!(crate::unix_process_stat_counts_as_running("Ss"));
    assert!(!crate::unix_process_stat_counts_as_running("UNE"));
    assert!(!crate::unix_process_stat_counts_as_running("Z"));
}

#[test]
fn linux_proc_fields_preserve_full_daemon_command_and_reject_zombies() {
    let command = crate::linux_proc_cmdline_to_command(
        b"nvpn\0daemon\0--service\0--config\0/var/lib/nvpn/config.toml\0",
    )
    .expect("command");
    assert!(crate::daemon_command_matches_config(
        &command,
        Path::new("/var/lib/nvpn/config.toml")
    ));
    assert!(crate::linux_proc_stat_counts_as_running("123 (nvpn) S 1 2 3"));
    assert!(!crate::linux_proc_stat_counts_as_running("123 (nvpn) Z 1 2 3"));
}

#[test]
fn daemon_pid_scan_recognizes_a_role_named_nvpn_binary() {
    let config = Path::new("/etc/nvpn-paid-exit/config.toml");
    assert!(crate::daemon_command_matches_config(
        "/usr/local/libexec/nvpn-paid-exit daemon --service --daemon-instance paid-exit --config /etc/nvpn-paid-exit/config.toml",
        config
    ));
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
        } else if cfg!(target_os = "macos") {
            "utun"
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
