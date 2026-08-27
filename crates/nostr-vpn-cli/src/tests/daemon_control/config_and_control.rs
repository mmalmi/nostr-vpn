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
    activate_first_network(&mut config);
    config.node_name = "windows-box".to_string();
    config.networks[0].devices = vec!["ab".repeat(32)];
    config.save(&source).expect("save source config");

    apply_config_file(&source, &target).expect("apply config should succeed");

    let loaded = AppConfig::load(&target).expect("load target config");
    assert_eq!(loaded.node_name, "windows-box");
    assert_eq!(loaded.participant_pubkeys_hex(), vec!["ab".repeat(32)]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn load_or_default_config_migrates_plaintext_config_secrets() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-load-config-secrets-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("config.toml");
    let mut config = AppConfig::generated();
    config.wireguard_exit.private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
    config.wireguard_exit.peer_public_key =
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
    config.wireguard_exit.peer_preshared_key =
        "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".to_string();
    let nostr_secret = config.nostr.secret_key.clone();
    let wireguard_private_key = config.wireguard_exit.private_key.clone();
    let wireguard_peer_preshared_key = config.wireguard_exit.peer_preshared_key.clone();
    fs::write(
        &path,
        config.plaintext_toml().expect("encode plaintext config"),
    )
    .expect("write plaintext config");

    let loaded = load_or_default_config(&path).expect("load config");
    let raw = fs::read_to_string(&path).expect("read migrated config");
    AppConfig::delete_persisted_secrets_for_path(&path).expect("delete migrated secrets");

    assert_eq!(loaded.nostr.secret_key, nostr_secret);
    assert_eq!(loaded.wireguard_exit.private_key, wireguard_private_key);
    assert_eq!(
        loaded.wireguard_exit.peer_preshared_key,
        wireguard_peer_preshared_key
    );
    assert!(!raw.contains(&nostr_secret));
    assert!(!raw.contains(&wireguard_private_key));
    assert!(!raw.contains(&wireguard_peer_preshared_key));

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

    AppConfig::delete_persisted_secrets_for_path(&source).expect("delete source secrets");
    AppConfig::delete_persisted_secrets_for_path(&staged).expect("delete staged secrets");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_control_readiness_is_bound_to_the_current_process() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-ready-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("config.toml");

    write_daemon_control_ready(&config, 41).expect("write stale ready marker");
    assert!(
        !daemon_control_ready_for_pid(&config, 42),
        "a marker from a previous daemon must not make a new daemon controllable"
    );
    assert!(
        wait_for_daemon_control_ready(&config, 42, Duration::from_millis(20)).is_err(),
        "a caller must wait while only a stale daemon marker exists"
    );

    write_daemon_control_ready(&config, 42).expect("write current ready marker");
    wait_for_daemon_control_ready(&config, 42, Duration::from_millis(20))
        .expect("current daemon should be ready");
    let status = DaemonStatus {
        running: true,
        pid: Some(42),
        pid_file: dir.join("daemon.pid"),
        log_file: dir.join("daemon.log"),
        state_file: dir.join("daemon.state.json"),
        state: None,
    };
    crate::wait_for_running_daemon_control_ready(&config, &status)
        .expect("production control path should accept the current PID marker");
    clear_daemon_control_ready(&config);
    assert!(
        !daemon_control_ready_file_path(&config).exists(),
        "shutdown must remove the readiness marker"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_instance_lock_rejects_a_second_process_until_release() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-daemon-lock-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("config.toml");
    let other_config = dir.join("other").join("config.toml");

    let first = acquire_daemon_instance_lock(&config).expect("acquire first daemon lock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let lock_path = daemon_instance_lock_file_path(&config).expect("lock path");
        let parent = lock_path.parent().expect("lock parent");
        assert_eq!(
            fs::metadata(parent)
                .expect("lock parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let second = acquire_daemon_instance_lock(&other_config);
    assert!(
        second.is_err(),
        "a second daemon must not acquire the process-global lock through another config path"
    );
    drop(first);
    acquire_daemon_instance_lock(&config).expect("released daemon lock should be reusable");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn unix_daemon_instance_lock_uses_a_protected_system_runtime_path() {
    let path = production_unix_daemon_instance_lock_file_path();

    #[cfg(target_os = "linux")]
    assert_eq!(
        path,
        Path::new("/run/nvpn/to.nostrvpn.nvpn.daemon.instance.lock")
    );
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        path,
        Path::new("/var/run/nvpn/to.nostrvpn.nvpn.daemon.instance.lock")
    );
    assert!(
        !path.starts_with(std::env::temp_dir()),
        "a machine-global privileged daemon lock must not live in a public temporary directory"
    );
}

#[test]
fn explicit_daemon_instance_locks_are_scoped_and_validated() {
    let config = Path::new("/unused/config.toml");
    let first = daemon_instance_lock_file_path_for_instance(config, Some("seed-a"))
        .expect("valid instance path");
    let second = daemon_instance_lock_file_path_for_instance(config, Some("seed-b"))
        .expect("valid instance path");
    assert_ne!(first, second);
    assert!(first.to_string_lossy().contains("seed-a"));

    for invalid in ["", "Seed", "-seed", "seed/other", "seed.other", &"a".repeat(65)] {
        assert!(
            daemon_instance_lock_file_path_for_instance(config, Some(invalid)).is_err(),
            "invalid instance ID must be rejected: {invalid}"
        );
    }
}

#[cfg(unix)]
#[test]
fn unix_daemon_instance_lock_refuses_a_world_writable_parent() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-hostile-lock-parent-{nonce}"));
    fs::create_dir(&dir).expect("create hostile parent");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))
        .expect("make hostile parent writable");
    let path = dir.join("daemon.instance.lock");
    let expected_uid = fs::metadata(&dir).expect("parent metadata").uid();

    let error = match acquire_unix_daemon_instance_lock_at(&path, expected_uid) {
        Ok(_) => panic!("world-writable parent must be refused"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("not protected"),
        "unexpected error: {error:#}"
    );
    assert!(
        !path.exists(),
        "validation must happen before creating the lock file"
    );

    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn unix_daemon_instance_lock_refuses_a_symlink_substitution() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-hostile-lock-symlink-{nonce}"));
    fs::create_dir(&dir).expect("create protected parent");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .expect("protect parent");
    let victim = dir.join("victim");
    fs::write(&victim, b"must remain untouched").expect("write victim");
    let path = dir.join("daemon.instance.lock");
    symlink(&victim, &path).expect("substitute lock symlink");
    let expected_uid = fs::metadata(&dir).expect("parent metadata").uid();

    let error = match acquire_unix_daemon_instance_lock_at(&path, expected_uid) {
        Ok(_) => panic!("symlink lock must be refused"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("symlink"),
        "unexpected error: {error:#}"
    );
    assert_eq!(
        fs::read(&victim).expect("read victim"),
        b"must remain untouched"
    );

    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn unix_daemon_instance_lock_reports_a_protected_lock_as_already_running() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-protected-daemon-lock-{nonce}"));
    fs::create_dir(&dir).expect("create protected parent");
    let path = dir.join("daemon.instance.lock");
    fs::write(&path, b"").expect("create protected lock");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect lock");
    let expected_uid = fs::metadata(&dir).expect("parent metadata").uid();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000))
        .expect("make the protected parent non-traversable");

    let error = match acquire_unix_daemon_instance_lock_at(&path, expected_uid) {
        Ok(_) => panic!("a non-traversable protected lock must not be acquired"),
        Err(error) => error,
    };

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions for cleanup");
    let message = format!("{error:#}");
    assert!(
        message.contains("daemon already running or protected instance lock"),
        "a client must receive the safe singleton result, not a raw inspection error: {message}"
    );
    assert!(
        !message.contains("failed to inspect"),
        "the protected singleton case must not be reported as an unexpected inspection failure: \
         {message}"
    );

    let _ = fs::remove_dir_all(dir);
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

    AppConfig::delete_persisted_secrets_for_path(&source).expect("delete source secrets");
    AppConfig::delete_persisted_secrets_for_path(&target).expect("delete target secrets");
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
    write_daemon_control_request(&config, crate::DaemonControlRequest::Pause)
        .expect("write pause control request");
    assert!(
        take_daemon_control_request(&config) == Some(crate::DaemonControlRequest::Pause),
        "daemon should read pause request"
    );
    write_daemon_control_request(&config, crate::DaemonControlRequest::Resume)
        .expect("write resume control request");
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
fn daemon_control_result_preserves_the_full_error_chain() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-control-result-chain-test-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config = dir.join("config.toml");

    let error = anyhow::anyhow!("PowerShell command timed out")
        .context("install secure Windows DNS")
        .context("apply FIPS tunnel, routes, and DNS");
    write_daemon_control_result(&config, crate::DaemonControlRequest::Reload, Err(error))
        .expect("write failed reload result");

    let returned = crate::wait_for_daemon_control_result(
        &config,
        crate::DaemonControlRequest::Reload,
        Duration::from_millis(20),
    )
    .expect_err("failed daemon reload must be returned to its caller");
    assert_eq!(
        returned.to_string(),
        "apply FIPS tunnel, routes, and DNS: install secure Windows DNS: PowerShell command timed out",
        "the control result must retain the actionable inner failure"
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

    let vpn_error = crate::wait_for_daemon_vpn_enabled(&config, true, Duration::from_millis(0))
        .expect_err("vpn wait should time out");
    assert!(
        vpn_error
            .to_string()
            .contains("background service may be busy or stuck")
    );
    assert!(
        !vpn_error
            .to_string()
            .contains("older nvpn daemon binary is still running")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn daemon_control_wait_timeouts_allow_longer_mac_recovery_windows() {
    assert_eq!(
        crate::daemon_control_startup_ready_timeout(),
        Duration::from_secs(30)
    );
    assert!(
        crate::daemon_control_startup_ready_timeout()
            > crate::daemon_control_ack_timeout(crate::DaemonControlRequest::Reload)
    );
    assert_eq!(
        crate::daemon_control_ack_timeout(crate::DaemonControlRequest::Reload),
        Duration::from_secs(10)
    );
    assert_eq!(
        crate::daemon_control_result_timeout(crate::DaemonControlRequest::Reload),
        if cfg!(target_os = "windows") {
            Duration::from_secs(45)
        } else {
            Duration::from_secs(30)
        }
    );
    assert_eq!(
        crate::daemon_control_vpn_transition_timeout(crate::DaemonControlRequest::Reload),
        Duration::ZERO
    );

    if cfg!(target_os = "macos") {
        assert_eq!(
            crate::daemon_control_ack_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(15)
        );
        assert_eq!(
            crate::daemon_control_result_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(30)
        );
        assert_eq!(
            crate::daemon_control_vpn_transition_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(30)
        );
    } else {
        assert_eq!(
            crate::daemon_control_ack_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(10)
        );
        assert_eq!(
            crate::daemon_control_result_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(15)
        );
        assert_eq!(
            crate::daemon_control_vpn_transition_timeout(crate::DaemonControlRequest::Resume),
            Duration::from_secs(2)
        );
    }
}
