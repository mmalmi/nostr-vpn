use std::path::Path;

use clap::CommandFactory;

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
fn macos_service_plist_runs_service_supervised_daemon() {
    let plist = crate::macos_service::macos_service_plist_content(
        "to.nostrvpn.nvpn",
        Path::new("/Applications/Nostr VPN.app/Contents/MacOS/nvpn"),
        Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml"),
        "utun100",
        20,
        Path::new("/Users/sirius/Library/Logs/nvpn/daemon.log"),
    );

    assert!(plist.contains("<string>daemon</string>"));
    assert!(plist.contains("<string>--service</string>"));
    assert!(plist.contains("<string>--config</string>"));
}

#[test]
fn macos_service_plist_parser_extracts_service_executable() {
    let plist = crate::macos_service::macos_service_plist_content(
        "to.nostrvpn.nvpn",
        Path::new("/Applications/Nostr VPN.app/Contents/MacOS/nvpn"),
        Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml"),
        "utun100",
        20,
        Path::new("/Users/sirius/Library/Logs/nvpn/daemon.log"),
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
fn macos_service_label_scopes_non_default_configs() {
    let label = crate::macos_service::macos_service_label(Path::new("/tmp/nvpn-debug/config.toml"));
    assert!(label.starts_with("to.nostrvpn.nvpn."));
    assert_ne!(label, "to.nostrvpn.nvpn");
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
        Path::new("/home/sirius/.config/nvpn/config.toml"),
        "nvpn",
        20,
        Path::new("/home/sirius/.local/state/nvpn/daemon.log"),
    );

    assert!(unit.contains("ExecStart=\"/usr/local/bin/nvpn\" daemon --service --config"));
    assert!(unit.contains("--iface \"nvpn\""));
    assert!(unit.contains("--announce-interval-secs 20"));
}

#[test]
fn linux_service_unit_parser_extracts_service_executable() {
    let unit = crate::linux_service_unit_content(
        Path::new("/usr/local/bin/nvpn"),
        Path::new("/home/sirius/.config/nvpn/config.toml"),
        "nvpn",
        20,
        Path::new("/home/sirius/.local/state/nvpn/daemon.log"),
    );

    assert_eq!(
        linux_service_executable_path_from_unit_contents(&unit).as_deref(),
        Some("/usr/local/bin/nvpn")
    );
}

#[test]
fn windows_service_query_parser_extracts_running_state() {
    let query = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n        PID                : 1234\n        FLAGS              :\n";
    let (running, pid) = windows_service_status_from_query_output(query);
    assert!(running);
    assert_eq!(pid, Some(1234));
}

#[test]
fn windows_service_config_parser_extracts_disabled_state() {
    let query = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 4   DISABLED\n        ERROR_CONTROL      : 1   NORMAL\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --service --config \"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\"\n";
    assert!(windows_service_disabled_from_qc_output(query));

    let auto_start = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n";
    assert!(!windows_service_disabled_from_qc_output(auto_start));
}

#[test]
fn windows_service_config_parser_extracts_binary_path() {
    let query = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Nostr VPN\\nvpn.exe\" daemon --service --config \"C:\\Users\\sirius\\AppData\\Roaming\\nvpn\\config.toml\"\n";
    assert_eq!(
        windows_service_binary_path_from_sc_qc_output(query),
        Some(Path::new(r"C:\Program Files\Nostr VPN\nvpn.exe").to_path_buf())
    );
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
