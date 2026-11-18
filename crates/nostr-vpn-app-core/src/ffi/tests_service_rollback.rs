    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn direct_exit_change_rolls_back_while_service_status_is_unavailable() {
        let dir = unique_service_test_dir("nvpn-app-core-config-while-starting");
        let script_path = write_starting_service_fake_nvpn(&dir);
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .select_public_paid_exit_node(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("select paid exit");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);
        runtime.daemon_status_grace_until = Some(Instant::now() + DAEMON_STARTUP_STATUS_GRACE);

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                internet_source: Some("direct".to_string()),
                ..SettingsPatch::default()
            },
        });

        assert!(
            runtime.last_error.contains("daemon status is unavailable"),
            "{}",
            runtime.last_error
        );
        assert_eq!(runtime.config.internet_source, InternetSource::PaidManual);
        assert!(!runtime.config.exit_node.is_empty());
        let state = runtime.state();
        assert_eq!(state.internet_source, "paid_manual");
        assert!(state.error.contains("daemon status is unavailable"));
        let saved = AppConfig::load(&runtime.config_path).expect("load restored config");
        assert_eq!(saved.internet_source, InternetSource::PaidManual);
        assert_eq!(
            saved.exit_node,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn failed_reload_restores_and_reapplies_the_previous_paid_exit_config() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_service_test_dir("nvpn-app-core-config-reload-rollback");
        let script_path = dir.join("nvpn");
        fs::write(
            &script_path,
            r#"#!/bin/sh
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  printf '%s\n' '{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"fi.siriusbusiness.nvpn.test","binary_version":"test"}'
  exit 0
fi
if [ "$1" = "status" ]; then
  printf '%s\n' '{"daemon":{"running":true,"state":null}}'
  exit 0
fi
if [ "$1" = "reload" ]; then
  printf 'reload\n' >> "$3.reloads"
  if [ ! -f "$3.first-reload" ]; then
    touch "$3.first-reload"
    echo "simulated reload failure" >&2
    exit 7
  fi
  grep -q 'internet_source = "paid_manual"' "$3" || exit 92
  exit 0
fi
exit 93
"#,
        )
        .expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .select_public_paid_exit_node(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("select paid exit");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save config");
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                internet_source: Some("direct".to_string()),
                ..SettingsPatch::default()
            },
        });

        assert!(
            runtime.last_error.contains("simulated reload failure"),
            "{}",
            runtime.last_error
        );
        assert_eq!(runtime.config.internet_source, InternetSource::PaidManual);
        assert!(!runtime.config.exit_node.is_empty());
        let state = runtime.state();
        assert_eq!(state.internet_source, "paid_manual");
        assert!(state.error.contains("simulated reload failure"));
        let saved = AppConfig::load(&runtime.config_path).expect("load restored config");
        assert_eq!(saved.internet_source, InternetSource::PaidManual);
        assert_eq!(saved.exit_node, runtime.config.exit_node);
        let calls = fs::read_to_string(format!("{}.reloads", runtime.config_path.display()))
            .expect("read fake nvpn reloads");
        assert_eq!(
            calls.lines().count(),
            2,
            "failed apply and rollback must each issue one reload:\n{calls}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn failed_wireguard_exit_reload_restores_the_previous_direct_config() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_service_test_dir("nvpn-app-core-wireguard-rollback");
        let script_path = dir.join("nvpn");
        fs::write(
            &script_path,
            r#"#!/bin/sh
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  printf '%s\n' '{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"fi.siriusbusiness.nvpn.test","binary_version":"test"}'
  exit 0
fi
if [ "$1" = "status" ]; then
  printf '%s\n' '{"daemon":{"running":true,"state":null}}'
  exit 0
fi
if [ "$1" = "reload" ]; then
  printf 'reload\n' >> "$3.reloads"
  if [ ! -f "$3.first-reload" ]; then
    touch "$3.first-reload"
    echo "simulated wireguard reload failure" >&2
    exit 7
  fi
  cp "$3" "$3.rollback" || exit 92
  exit 0
fi
exit 93
"#,
        )
        .expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        let previous_wireguard = runtime.config.wireguard_exit.clone();
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                internet_source: Some("wireguard".to_string()),
                wireguard_exit_enabled: Some(true),
                wireguard_exit_config: Some(
                    r"
[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.64.70.195/32, fc00:bbbb:bbbb:bb01::1:46c2/128

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.test:51820
"
                    .to_string(),
                ),
                ..SettingsPatch::default()
            },
        });

        assert!(
            runtime
                .last_error
                .contains("simulated wireguard reload failure"),
            "{}",
            runtime.last_error
        );
        assert_eq!(runtime.config.internet_source, InternetSource::Direct);
        assert!(!runtime.config.wireguard_exit.enabled);
        assert!(runtime.config.wireguard_exit.address.is_empty());
        let state = runtime.state();
        assert_eq!(state.internet_source, "direct");
        assert!(
            state.error.contains("restored previous configuration"),
            "{}",
            state.error
        );
        let saved = AppConfig::load(&runtime.config_path).expect("load restored config");
        assert_eq!(saved.internet_source, InternetSource::Direct);
        assert!(!saved.wireguard_exit.enabled);
        assert!(saved.wireguard_exit.address.is_empty());
        // Inspect the configuration seen by the rollback reload. Direct is
        // omitted by serde, and HashMap table order can change across saves.
        let reloaded: AppConfig = toml::from_str(
            &fs::read_to_string(dir.join("config.toml.rollback"))
                .expect("read config observed by rollback reload"),
        )
        .expect("parse config observed by rollback reload");
        assert_eq!(reloaded.internet_source, InternetSource::Direct);
        assert_eq!(reloaded.wireguard_exit, previous_wireguard);
        let calls = fs::read_to_string(format!("{}.reloads", runtime.config_path.display()))
            .expect("read fake nvpn reloads");
        assert_eq!(
            calls.lines().count(),
            2,
            "failed apply and rollback must each issue one reload:\n{calls}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
