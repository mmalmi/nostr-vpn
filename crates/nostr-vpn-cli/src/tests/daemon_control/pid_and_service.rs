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
fn recent_state_file_daemon_pid_candidate_uses_fresh_state_and_single_other_process() {
    let state = DaemonRuntimeState {
        updated_at: 100,
        ..Default::default()
    };
    assert_eq!(
        crate::recent_state_file_daemon_pid_candidate(Some(&state), 42, &[42, 9564], 103),
        Some(9564)
    );
    assert_eq!(
        crate::recent_state_file_daemon_pid_candidate(Some(&state), 42, &[42, 9564], 106),
        None
    );
    assert_eq!(
        crate::recent_state_file_daemon_pid_candidate(Some(&state), 42, &[42, 9564, 97597], 103),
        None
    );
    assert_eq!(
        crate::recent_state_file_daemon_pid_candidate(None, 42, &[42, 9564], 103),
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
fn linux_proc_fields_preserve_full_daemon_command_and_reject_zombies() {
    assert!(crate::linux_proc_daemon_matches_config(
        b"nvpn\0daemon\0--service\0--config\0/var/lib/nvpn/config.toml\0",
        Path::new("/var/lib/nvpn/config.toml")
    ));
    assert!(crate::linux_proc_stat_counts_as_running("123 (nvpn) S 1 2 3"));
    assert!(!crate::linux_proc_stat_counts_as_running("123 (nvpn) Z 1 2 3"));
}

#[test]
fn linux_proc_daemon_detection_rejects_launchers_and_other_config_paths() {
    let config = Path::new("/var/lib/nvpn/config.toml");
    for launcher in ["sudo", "/usr/bin/timeout", "/usr/bin/strace", "env", "sh"] {
        let cmdline = format!(
            "{launcher}\0/path/nvpn\0daemon\0--config\0/var/lib/nvpn/config.toml\0"
        );
        assert!(
            !crate::linux_proc_daemon_matches_config(cmdline.as_bytes(), config),
            "launcher {launcher} is not the daemon"
        );
    }
    assert!(!crate::linux_proc_daemon_matches_config(
        b"/path/nvpn\0daemon\0--config\0/var/lib/nvpn/config.toml.other\0",
        config
    ));
    assert!(!crate::linux_proc_daemon_matches_config(
        b"/path/nvpn\0status\0--config\0/var/lib/nvpn/config.toml\0",
        config
    ));
}

#[test]
fn linux_proc_daemon_detection_preserves_spaces_and_config_equals_syntax() {
    let config = Path::new("/var/lib/nvpn test/config.toml");
    for cmdline in [
        b"/path with spaces/nvpn\0daemon\0--config\0/var/lib/nvpn test/config.toml\0".as_slice(),
        b"/path/nvpn-paid-exit\0daemon\0--service\0--config=/var/lib/nvpn test/config.toml\0".as_slice(),
    ] {
        assert!(crate::linux_proc_daemon_matches_config(cmdline, config));
    }
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
    let target = dir.join("custom path ' $HOME").join("nvpn");

    install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: false,
    })
    .expect("install custom cli target");
    assert!(target.exists(), "installed target should exist");
    let installed_len = fs::metadata(&target).unwrap().len();
    fs::write(&target, b"old executable").expect("create replacement fixture");

    let duplicate = install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: false,
    })
    .expect_err("install without --force should fail");
    assert_eq!(
        duplicate.to_string(),
        format!(
            "{} already exists (pass --force to overwrite)",
            target.display()
        )
    );
    assert_eq!(fs::read(&target).unwrap(), b"old executable");

    install_cli(InstallCliArgs {
        path: Some(target.clone()),
        force: true,
    })
    .expect("force reinstall custom cli target");
    assert_eq!(fs::metadata(&target).unwrap().len(), installed_len);

    uninstall_cli(UninstallCliArgs {
        path: Some(target.clone()),
    })
    .expect("uninstall custom cli target");
    assert!(!target.exists(), "uninstall should remove target");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn install_cli_permission_denied_preserves_cause_and_offers_recovery() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        eprintln!("permission-denied fixture requires an unprivileged user");
        return;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-install-denied-{nonce}"));
    fs::create_dir(&dir).expect("create temp dir");
    let existing = dir.join("existing ' $HOME");
    fs::write(&existing, b"keep existing executable").expect("create existing target");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("deny writes");

    // Exercise copy, parent creation, and --force removal through the installer.
    let results = [
        (dir.join("nvpn"), false, "failed to copy"),
        (
            dir.join("missing").join("nvpn"),
            false,
            "failed to create directory",
        ),
        (existing.clone(), true, "failed to remove"),
    ]
    .map(|(target, force, context)| {
        let result = install_cli(InstallCliArgs {
            path: Some(target.clone()),
            force,
        });
        (target, force, context, result)
    });

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("restore writes");
    let preserved = fs::read(&existing).expect("read existing target");
    fs::remove_dir_all(&dir).expect("remove temp dir");
    assert_eq!(preserved, b"keep existing executable");

    for (target, force, context, result) in results {
        let error = result.expect_err("install into read-only directory must fail");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let message = error.to_string();
        assert!(message.contains(&target.display().to_string()), "{message}");
        assert!(message.contains("Retry the same command with administrator privileges"));
        let force_flag = if force { " --force" } else { "" };
        assert!(message.contains(&format!(
            "nvpn install-cli{force_flag} --path \"$HOME/.local/bin/nvpn\""
        )));
        assert!(format!("{error:#}").contains(context), "{error:#}");
    }
}
