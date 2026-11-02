use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::CommandFactory;
use nostr_vpn_core::config::AppConfig;

use crate::*;

#[test]
fn clap_service_supports_install_uninstall_status() {
    let command = Cli::command();
    let service = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "service")
        .expect("service subcommand exists");
    for name in ["install", "enable", "disable", "uninstall", "status"] {
        assert!(
            service
                .get_subcommands()
                .any(|subcommand| subcommand.get_name() == name),
            "missing service subcommand {name}"
        );
    }
}

#[test]
fn linux_service_show_parser_extracts_running_state() {
    let show = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n";
    let (loaded, running, pid) = linux_service_status_from_show_output(show);
    assert!(loaded);
    assert!(running);
    assert_eq!(pid, Some(4242));
}

#[test]
fn linux_service_steps_avoid_now_flag() {
    use crate::service_management::{linux_service_disable_steps, linux_service_enable_steps};

    let unit = "nvpn.service";
    assert_eq!(
        linux_service_enable_steps(unit),
        [["enable", unit], ["start", unit]]
    );
    assert_eq!(
        linux_service_disable_steps(unit),
        [["stop", unit], ["disable", unit]]
    );
    for step in linux_service_enable_steps(unit)
        .into_iter()
        .chain(linux_service_disable_steps(unit))
    {
        assert!(
            !step.contains(&"--now"),
            "service steps must avoid the non-portable --now flag"
        );
    }
}

#[test]
fn macos_service_disabled_parser_extracts_disabled_state() {
    let output = r#"
        disabled services = {
            "to.nostrvpn.nvpn" => disabled
            "com.example.other" => enabled
        }
    "#;

    assert!(
        crate::macos_service::macos_service_disabled_from_print_disabled_output(
            output,
            "to.nostrvpn.nvpn"
        )
    );
    assert!(
        !crate::macos_service::macos_service_disabled_from_print_disabled_output(
            output,
            "com.example.other"
        )
    );
    assert!(
        !crate::macos_service::macos_service_disabled_from_print_disabled_output(
            output,
            "missing.service"
        )
    );
}

#[test]
fn macos_service_print_is_running_accepts_keepalive_states() {
    for state in ["running", "spawn scheduled", "waiting"] {
        let output = format!("system/to.nostrvpn.nvpn = {{\n\tstate = {state}\n}}\n");
        assert!(
            crate::macos_service::macos_service_print_is_running(&output),
            "expected running for state = {state}"
        );
    }
    assert!(!crate::macos_service::macos_service_print_is_running(
        "system/to.nostrvpn.nvpn = {\n\tstate = not running\n}\n"
    ));
}

#[test]
fn macos_service_plist_runs_service_supervised_daemon() {
    let plist = crate::macos_service::macos_service_plist_content(
        "to.nostrvpn.nvpn",
        Path::new("/Applications/Nostr VPN.app/Contents/MacOS/nvpn"),
        Path::new("/Users/example/Library/Application Support/nvpn/config.toml"),
        "utun100",
        60,
    );

    assert!(plist.contains("<string>daemon</string>"));
    assert!(plist.contains("<string>--service</string>"));
    assert!(plist.contains("<string>--config</string>"));
    assert!(
        plist.contains("<string>--mesh-refresh-interval-secs</string>\n    <string>60</string>")
    );
    assert!(plist.contains("<key>ProcessType</key>\n  <string>Interactive</string>"));
    // launchd must not open user-controlled paths as root before the daemon's
    // checked log opener gets to reject symlinks and hard links.
    assert!(!plist.contains("StandardOutPath"));
    assert!(!plist.contains("StandardErrorPath"));
}

#[test]
fn macos_service_plist_parser_extracts_service_executable() {
    let plist = crate::macos_service::macos_service_plist_content(
        "to.nostrvpn.nvpn",
        Path::new("/Applications/Nostr VPN.app/Contents/MacOS/nvpn"),
        Path::new("/Users/example/Library/Application Support/nvpn/config.toml"),
        "utun100",
        20,
    );

    assert_eq!(
        crate::macos_service::macos_service_executable_path_from_plist_contents(&plist).as_deref(),
        Some("/Applications/Nostr VPN.app/Contents/MacOS/nvpn")
    );
}

#[test]
fn macos_service_label_uses_stable_default_for_main_config() {
    let label = crate::macos_service::macos_service_label(&crate::default_config_path());
    assert_eq!(label, "to.nostrvpn.nvpn");
}

#[test]
fn macos_service_binary_uses_privileged_helper_copy() {
    assert_eq!(
        crate::macos_service::macos_service_binary_path(&crate::default_config_path()),
        Path::new("/Library/PrivilegedHelperTools/to.nostrvpn.nvpn")
    );
}

#[test]
fn macos_service_identity_scopes_non_default_configs() {
    let selected = Path::new("/tmp/nvpn-selected/config.toml");
    let unrelated = Path::new("/tmp/nvpn-unrelated/config.toml");
    let label = crate::macos_service::macos_service_label(selected);
    let selected_target = crate::macos_service::macos_service_target(selected);

    assert!(label.starts_with("to.nostrvpn.nvpn."));
    assert_eq!(selected_target, format!("system/{label}"));
    assert_ne!(
        selected_target,
        crate::macos_service::macos_service_target(unrelated)
    );
    assert_ne!(selected_target, format!("system/{MACOS_SERVICE_LABEL}"));
}

#[test]
fn macos_service_config_suffix_is_stable_sha256_hex() {
    let config = Path::new("/nvpn-service-suffix-stability/config.toml");
    let suffix = crate::macos_service::macos_service_config_suffix(config);

    assert_eq!(suffix, "98fad7f11f0c39f6");
    assert_eq!(
        suffix,
        crate::macos_service::macos_service_config_suffix(config)
    );
    assert_eq!(suffix.len(), 16);
    assert!(
        suffix
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    );
}

#[test]
fn macos_service_legacy_identity_targets_pre_sha256_installations() {
    let config = Path::new("/nvpn-service-suffix-stability/config.toml");
    let legacy = crate::macos_service::macos_service_legacy_identity(config)
        .expect("non-default config resolves a legacy service identity");
    let current_label = crate::macos_service::macos_service_label(config);

    assert!(legacy.label.starts_with("to.nostrvpn.nvpn."));
    assert_ne!(legacy.label, current_label);
    assert_eq!(legacy.target(), format!("system/{}", legacy.label));
    assert_eq!(
        legacy.plist_path,
        PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", legacy.label))
    );
    assert_eq!(
        legacy.binary_path,
        PathBuf::from(format!("/Library/PrivilegedHelperTools/{}", legacy.label))
    );
    assert_eq!(
        crate::macos_service::macos_service_legacy_identity(config)
            .expect("legacy identity is deterministic")
            .label,
        legacy.label
    );
    assert!(
        crate::macos_service::macos_service_legacy_identity(&crate::default_config_path())
            .is_none(),
        "default-config installs kept the fixed label across both schemes"
    );
}

#[test]
fn macos_service_upgrade_removes_legacy_artifacts_and_keeps_current() {
    // install-old: a pre-SHA-256 install left artifacts under the legacy
    // identity. upgrade then stop/uninstall must remove exactly those, even
    // after the service was reinstalled under the current identity.
    let config = Path::new("/nvpn-service-upgrade/config.toml");
    let legacy = crate::macos_service::macos_service_legacy_identity(config)
        .expect("legacy identity exists for a non-default config");
    let current_label = crate::macos_service::macos_service_label(config);
    assert_ne!(legacy.target(), format!("system/{current_label}"));

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("nvpn-macos-legacy-upgrade-{nonce}"));
    fs::create_dir(&root).expect("create fixture directory");
    let legacy_artifacts = [
        root.join(format!("{}.plist", legacy.label)),
        root.join(&legacy.label),
    ];
    let current_artifacts = [
        root.join(format!("{current_label}.plist")),
        root.join(&current_label),
    ];
    let unrelated = root.join("to.nostrvpn.nvpn.other");
    for path in legacy_artifacts
        .iter()
        .chain(&current_artifacts)
        .chain(std::iter::once(&unrelated))
    {
        fs::write(path, "fixture").expect("write artifact fixture");
    }

    crate::macos_service::macos_remove_service_artifacts(
        &legacy_artifacts[0],
        &legacy_artifacts[1],
    )
    .expect("cleanup of the legacy identity removes its artifacts");

    assert!(legacy_artifacts.iter().all(|path| !path.exists()));
    assert!(
        current_artifacts.iter().all(|path| path.exists()),
        "reinstalling under the current identity must not strand or clobber it"
    );
    assert!(unrelated.exists());
    fs::remove_dir_all(root).expect("remove fixture directory");
}

#[test]
fn macos_service_uninstall_removes_only_selected_artifacts() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("nvpn-macos-uninstall-{nonce}"));
    fs::create_dir(&root).expect("create fixture directory");
    let selected_label = crate::macos_service::macos_service_label(Path::new("/tmp/selected"));
    let other_label = crate::macos_service::macos_service_label(Path::new("/tmp/other"));
    let selected = [
        root.join(format!("{selected_label}.plist")),
        root.join(selected_label),
    ];
    let preserved = [
        root.join(MACOS_SERVICE_LABEL),
        root.join(&other_label),
        root.join(format!("{other_label}.plist")),
    ];
    for path in selected.iter().chain(&preserved) {
        fs::write(path, "fixture").expect("write artifact fixture");
    }

    crate::macos_service::macos_remove_service_artifacts(&selected[0], &selected[1])
        .expect("remove selected artifacts");
    crate::macos_service::macos_remove_service_artifacts(&selected[0], &selected[1])
        .expect("repeat selected cleanup");
    assert!(selected.iter().all(|path| !path.exists()));
    assert!(preserved.iter().all(|path| path.exists()));
    fs::remove_dir_all(root).expect("remove fixture directory");
}

#[test]
fn macos_service_activation_enables_before_bootstrap() {
    let config_path = crate::default_config_path();
    let plist_path = crate::macos_service::macos_service_plist_path(&config_path);
    let commands =
        crate::macos_service::macos_service_activation_commands(&config_path, &plist_path);

    assert_eq!(
        commands,
        vec![
            vec!["enable".to_string(), "system/to.nostrvpn.nvpn".to_string()],
            vec!["bootout".to_string(), "system/to.nostrvpn.nvpn".to_string()],
            vec![
                "bootstrap".to_string(),
                "system".to_string(),
                plist_path.display().to_string()
            ],
            vec![
                "kickstart".to_string(),
                "-k".to_string(),
                "system/to.nostrvpn.nvpn".to_string()
            ],
        ]
    );
}

#[test]
fn service_config_guard_preserves_existing_config_identity() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-service-config-guard-{nonce}"));
    fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let mut config = AppConfig {
        node_name: "existing-config".to_string(),
        ..AppConfig::default()
    };
    config.node.endpoint = "8.8.8.8:51820".to_string();
    config.save(&config_path).expect("save config");
    let before = AppConfig::load(&config_path).expect("load config before guard");

    crate::service_management::ensure_service_config_exists(&config_path)
        .expect("existing config should validate");

    let after = AppConfig::load(&config_path).expect("load config after guard");
    assert_eq!(after.node_name, before.node_name);
    assert_eq!(after.nostr.public_key, before.nostr.public_key);
    assert_eq!(after.node.endpoint, before.node.endpoint);
    assert_eq!(after.networks.len(), before.networks.len());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn service_config_guard_does_not_replace_invalid_existing_config() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-service-config-invalid-{nonce}"));
    fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    fs::write(&config_path, "not valid toml").expect("write invalid config");

    let err = crate::service_management::ensure_service_config_exists(&config_path)
        .expect_err("invalid existing config should fail");

    assert!(
        err.to_string().contains("failed to parse config TOML"),
        "{err}"
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("read invalid config"),
        "not valid toml"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn macos_stop_daemon_hint_prefers_launchd_guidance_for_service_pid() {
    let status = ServiceStatusView {
        supported: true,
        installed: true,
        disabled: false,
        loaded: true,
        running: true,
        pid: Some(4242),
        label: "to.nostrvpn.nvpn".to_string(),
        plist_path: "/Library/LaunchDaemons/to.nostrvpn.nvpn.plist".to_string(),
        binary_path: "/Applications/Nostr VPN.app/Contents/MacOS/nvpn".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let hint = crate::macos_stop_daemon_hint_from_service_status(&status, &[4242])
        .expect("launchd-managed service should produce a hint");
    assert!(hint.contains("launchd service to.nostrvpn.nvpn"));
    assert!(hint.contains("service disable"));
    assert!(hint.contains("service enable"));
}

#[test]
fn macos_stop_daemon_hint_ignores_non_service_pid() {
    let status = ServiceStatusView {
        supported: true,
        installed: true,
        disabled: false,
        loaded: true,
        running: true,
        pid: Some(4242),
        label: "to.nostrvpn.nvpn".to_string(),
        plist_path: "/Library/LaunchDaemons/to.nostrvpn.nvpn.plist".to_string(),
        binary_path: "/Applications/Nostr VPN.app/Contents/MacOS/nvpn".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    assert!(crate::macos_stop_daemon_hint_from_service_status(&status, &[31337]).is_none());
}

#[test]
fn linux_service_unit_runs_service_supervised_daemon() {
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        Path::new("/home/example/.config/nvpn/config.toml"),
        "nvpn",
        60,
        Path::new("/home/example/.local/state/nvpn/daemon.log"),
    )
    .expect("valid systemd service unit");

    assert!(unit.contains("ExecStart=\"/usr/local/bin/nvpn\" daemon --service --config"));
    assert!(unit.contains("After=nvpn-egress-guard.service network-online.target"));
    assert!(unit.contains("Requires=nvpn-egress-guard.service"));
    assert!(unit.contains("--iface \"nvpn\""));
    assert!(unit.contains("--mesh-refresh-interval-secs 60"));
    assert!(unit.contains("StandardOutput=append:/home/example/.local/state/nvpn/daemon.log"));
    assert!(unit.contains("StandardError=append:/home/example/.local/state/nvpn/daemon.log"));
    assert!(!unit.contains("StandardOutput=append:\""));
    assert!(!unit.contains("StandardError=append:\""));
}

#[test]
fn linux_service_binary_uses_stable_path_copy() {
    assert_eq!(
        linux_service_binary_path(),
        Path::new("/usr/local/bin/nvpn")
    );
}

#[test]
fn linux_service_unit_parser_extracts_service_executable() {
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        Path::new("/home/example/.config/nvpn/config.toml"),
        "nvpn",
        20,
        Path::new("/home/example/.local/state/nvpn/daemon.log"),
    )
    .expect("valid systemd service unit");

    assert_eq!(
        linux_service_executable_path_from_unit_contents(&unit).as_deref(),
        Some("/usr/local/bin/nvpn")
    );
}

#[test]
fn linux_service_unit_parser_extracts_exact_config_identity() {
    let config = Path::new("/home/example/Nostr VPN/config.toml");
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        config,
        "nvpn",
        20,
        Path::new("/home/example/.local/state/nvpn/daemon.log"),
    )
    .expect("valid systemd service unit");

    assert_eq!(
        linux_service_config_path_from_unit_contents(&unit).as_deref(),
        config.to_str()
    );
    assert!(linux_service_unit_matches_config(&unit, config));
    assert!(!linux_service_unit_matches_config(
        &unit,
        Path::new("/home/other/.config/nvpn/config.toml")
    ));
}

#[test]
fn linux_service_unit_rejects_injected_directives_in_every_input() {
    for injected in [
        "nvpn\nExecStartPost=/bin/false",
        "nvpn\rExecStartPost=/bin/false",
        "nvpn\0suffix",
    ] {
        for field in 0..4 {
            let executable = if field == 0 {
                injected
            } else {
                "/usr/local/bin/nvpn"
            };
            let config = if field == 1 {
                injected
            } else {
                "/etc/nvpn/config.toml"
            };
            let iface = if field == 2 { injected } else { "nvpn" };
            let log = if field == 3 {
                injected
            } else {
                "/var/log/nvpn.log"
            };
            assert!(
                crate::linux_service_unit_content(
                    Path::new(executable),
                    Path::new(config),
                    iface,
                    20,
                    Path::new(log)
                )
                .is_err(),
                "injected field {field} must be rejected before installing a unit"
            );
        }
    }
}

#[test]
fn linux_service_unit_keeps_specifiers_and_environment_references_literal() {
    let config = Path::new("/srv/nvpn/%n/${USER}/with \\\"quotes\\\"/config.toml");
    let log = Path::new("/srv/nvpn/%n/${USER}/daemon.log");
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        config,
        "${USER}",
        20,
        log,
    )
    .expect("literal metacharacters are supported");

    assert!(unit.contains("--config \"/srv/nvpn/%%n/$${USER}/"));
    assert!(unit.contains("--iface \"$${USER}\""));
    assert!(unit.contains("StandardOutput=append:/srv/nvpn/%%n/${USER}/daemon.log\n"));
    assert!(unit.contains("StandardError=append:/srv/nvpn/%%n/${USER}/daemon.log\n"));
    assert!(linux_service_unit_matches_config(&unit, config));
}

#[test]
fn windows_service_command_line_argv_splits_quoted_paths() {
    assert_eq!(
        windows_command_line_argv(
            r#""C:\Program Files\Nostr VPN\nvpn.exe" daemon --service --config "C:\my cfg.toml""#
        ),
        vec![
            r"C:\Program Files\Nostr VPN\nvpn.exe".to_string(),
            "daemon".to_string(),
            "--service".to_string(),
            "--config".to_string(),
            r"C:\my cfg.toml".to_string(),
        ]
    );
    assert_eq!(
        windows_command_line_argv(r"C:\nvpn.exe daemon --service"),
        vec![
            r"C:\nvpn.exe".to_string(),
            "daemon".to_string(),
            "--service".to_string(),
        ]
    );
    assert_eq!(windows_command_line_argv("   "), Vec::<String>::new());
    assert_eq!(windows_command_line_argv(r#""""#), vec![String::new()]);
}

#[test]
fn windows_service_command_line_parser_extracts_service_executable() {
    assert_eq!(
        windows_service_executable_from_command_line(
            r#""C:\Program Files\Nostr VPN\nvpn.exe" daemon --service --config "C:\Users\Example\AppData\Roaming\nvpn\config.toml""#,
        ),
        Some(Path::new(r"C:\Program Files\Nostr VPN\nvpn.exe").to_path_buf())
    );
    assert_eq!(
        windows_service_executable_from_command_line(r"C:\nvpn.exe daemon --service"),
        Some(Path::new(r"C:\nvpn.exe").to_path_buf())
    );
    assert_eq!(windows_service_executable_from_command_line("   "), None);
}

#[test]
fn windows_service_stop_state_machine_waits_for_pending_states() {
    assert_eq!(
        windows_service_stop_action(None),
        WindowsServiceStopAction::Complete
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::Stopped)),
        WindowsServiceStopAction::Complete
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::StopPending)),
        WindowsServiceStopAction::Wait
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::StartPending)),
        WindowsServiceStopAction::Wait
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::ContinuePending)),
        WindowsServiceStopAction::Wait
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::PausePending)),
        WindowsServiceStopAction::Wait
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::Running)),
        WindowsServiceStopAction::RequestStop
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::Paused)),
        WindowsServiceStopAction::RequestStop
    );
    assert_eq!(
        windows_service_stop_action(Some(WindowsServiceState::Unknown(99))),
        WindowsServiceStopAction::Unsupported
    );
}

#[test]
fn windows_stop_failure_is_joined_only_after_observing_stop_completion() {
    assert!(windows_service_stop_failure_is_joinable(None));
    assert!(windows_service_stop_failure_is_joinable(Some(
        WindowsServiceState::Stopped
    )));
    assert!(windows_service_stop_failure_is_joinable(Some(
        WindowsServiceState::StopPending
    )));
    assert!(!windows_service_stop_failure_is_joinable(Some(
        WindowsServiceState::Running
    )));
    assert!(!windows_service_stop_failure_is_joinable(Some(
        WindowsServiceState::StartPending
    )));
}

#[test]
fn windows_apply_config_uses_installed_enabled_service() {
    let enabled_service = ServiceStatusView {
        supported: true,
        installed: true,
        disabled: false,
        loaded: true,
        running: false,
        pid: None,
        label: "NvpnService".to_string(),
        plist_path: "NvpnService".to_string(),
        binary_path: r"C:\Program Files\Nostr VPN\nvpn.exe".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    assert!(windows_should_apply_config_via_service(&enabled_service));

    let disabled_service = ServiceStatusView {
        disabled: true,
        ..enabled_service.clone()
    };
    assert!(!windows_should_apply_config_via_service(&disabled_service));

    let missing_service = ServiceStatusView {
        installed: false,
        loaded: false,
        ..enabled_service
    };
    assert!(!windows_should_apply_config_via_service(&missing_service));
}

#[test]
fn linux_egress_guard_precedes_networking_and_has_no_release_on_stop() {
    let unit = crate::service_management::linux_guard_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        Path::new("/home/example/Nostr VPN/config.toml"),
    )
    .unwrap();
    assert!(unit.contains("DefaultDependencies=no"));
    assert!(unit.contains("After=local-fs.target"));
    assert!(unit.contains("Before=network-pre.target nvpn.service"));
    assert!(unit.contains("Wants=network-pre.target"));
    assert!(unit.contains("RemainAfterExit=yes"));
    assert!(unit.contains("ExecStart=\"/usr/local/bin/nvpn\" egress-guard --config \"/home/example/Nostr VPN/config.toml\""));
    assert!(!unit.contains("ExecStop"));
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_verifies_daemon_and_early_guard_unit_dependencies() {
    let directory =
        std::env::temp_dir().join(format!("nvpn-egress-units-{}", rand::random::<u64>()));
    std::fs::create_dir(&directory).unwrap();
    let guard = crate::service_management::linux_guard_service_unit_content(
        Path::new("/bin/true"),
        Path::new("/home/example/config.toml"),
    )
    .unwrap();
    let daemon = crate::linux_service_unit_content(
        Path::new("/bin/true"),
        Path::new("/home/example/config.toml"),
        "nvpn",
        60,
        Path::new("/tmp/nvpn.log"),
    )
    .unwrap();
    let guard_path = directory.join("nvpn-egress-guard.service");
    let daemon_path = directory.join("nvpn.service");
    std::fs::write(&guard_path, guard).unwrap();
    std::fs::write(&daemon_path, daemon).unwrap();
    let output = std::process::Command::new("systemd-analyze")
        .args(["verify", "--man=no"])
        .arg(&guard_path)
        .arg(&daemon_path)
        .output();
    std::fs::remove_dir_all(directory).unwrap();
    match output {
        Ok(output) => assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("systemd unit verification requires a systemd development host");
        }
        Err(error) => panic!("systemd verification: {error}"),
    }
}

#[cfg(unix)]
#[test]
fn linux_service_ownership_accepts_relative_and_symlink_config_identity() {
    let directory =
        std::env::temp_dir().join(format!("nvpn-service-config-{}", rand::random::<u64>()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("config.toml");
    std::fs::write(&path, "").unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    let link = directory.join("link.toml");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        &canonical,
        "nvpn",
        20,
        &directory.join("daemon.log"),
    )
    .unwrap();
    let mut relative = PathBuf::new();
    for _ in std::env::current_dir().unwrap().ancestors().skip(1) {
        relative.push("..");
    }
    relative.push(canonical.strip_prefix("/").unwrap());
    for alias in [&path, &link, &relative] {
        assert!(
            linux_service_unit_matches_config(&unit, alias),
            "equivalent configuration"
        );
    }
    assert!(!linux_service_unit_matches_config(
        &unit,
        &directory.join("other.toml")
    ));
    std::fs::remove_dir_all(directory).unwrap();
}
