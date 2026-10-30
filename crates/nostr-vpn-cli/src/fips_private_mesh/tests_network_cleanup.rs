    #[cfg(target_os = "linux")]
    #[test]
    fn linux_legacy_firewall_cleanup_does_not_require_iptables() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_CASE: &str = "NVPN_LEGACY_FIREWALL_TEST_CASE";
        if let Ok(case) = std::env::var(CHILD_CASE) {
            let mut state = crate::LinuxExitNodeRuntime::default();
            let result = super::cleanup_linux_forwarding_state("nvpn-test", &mut state);
            assert_eq!(result.is_ok(), case == "missing", "{case}: {result:?}");

            // Losing the tool must not erase ownership of rules we installed.
            state.ipv4_outbound_iface = Some("underlay-test".into());
            state.ipv4_tunnel_source_cidr = Some("10.44.0.0/16".into());
            assert!(super::cleanup_linux_forwarding_state("nvpn-test", &mut state).is_err());
            assert_eq!(state.ipv4_outbound_iface.as_deref(), Some("underlay-test"));
            assert_eq!(state.ipv4_tunnel_source_cidr.as_deref(), Some("10.44.0.0/16"));
            return;
        }

        let directory = std::env::temp_dir().join(format!(
            "nvpn-legacy-firewall-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        for case in ["missing", "permission", "locked", "delete-failed"] {
            if case != "missing" {
                for tool in ["iptables", "ip6tables"] {
                    let path = directory.join(tool);
                    std::fs::write(
                        &path,
                        if case == "delete-failed" {
                            "#!/bin/sh\n[ \"$1\" = -C ] && exit 0\nexit 4\n"
                        } else {
                            "#!/bin/sh\necho 'xtables lock unavailable' >&2\nexit 4\n"
                        },
                    )
                    .unwrap();
                    std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(if case == "permission" {
                            0o644
                        } else {
                            0o755
                        }),
                    )
                    .unwrap();
                }
            }
            // Child-local PATH keeps host firewall tools unreachable and avoids
            // changing the environment of concurrently running tests.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    std::thread::current().name().unwrap(),
                    "--nocapture",
                ])
                .env("PATH", &directory)
                .env(CHILD_CASE, case)
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[derive(Default)]
    struct FakeLinuxNetworkCleanupActions {
        events: Vec<&'static str>,
        forwarding_failures_remaining: usize,
        fd00_failures_remaining: usize,
        ipv4_restore_unblocked_by_forwarding_cleanup: bool,
        ipv4_restore_failures_remaining: usize,
        ipv4_restore_pending: bool,
        ipv6_restore_pending: bool,
        fail_route_cache_flush: bool,
    }

    impl super::LinuxNetworkCleanupActions for FakeLinuxNetworkCleanupActions {
        fn cleanup_endpoint_bypass_routes(&mut self) -> anyhow::Result<()> {
            self.events.push("endpoint");
            Ok(())
        }

        fn cleanup_fd00_main_rule(&mut self) -> anyhow::Result<()> {
            self.events.push("fd00-main-rule");
            if self.fd00_failures_remaining > 0 {
                self.fd00_failures_remaining -= 1;
                return Err(anyhow::anyhow!("synthetic fd00 rule cleanup failure"));
            }
            Ok(())
        }

        fn cleanup_forwarding_and_wireguard(&mut self) -> anyhow::Result<()> {
            self.events.push("forwarding-wireguard");
            if self.forwarding_failures_remaining > 0 {
                self.forwarding_failures_remaining -= 1;
                return Err(anyhow::anyhow!("synthetic forwarding cleanup failure"));
            }
            if self.ipv4_restore_unblocked_by_forwarding_cleanup {
                self.ipv4_restore_failures_remaining = 0;
            }
            Ok(())
        }

        fn restore_original_ipv4_default(&mut self) {
            self.events.push("restore-ipv4");
            if self.ipv4_restore_failures_remaining > 0 {
                self.ipv4_restore_failures_remaining -= 1;
            } else {
                self.ipv4_restore_pending = false;
            }
        }

        fn restore_original_ipv6_default(&mut self) {
            self.events.push("restore-ipv6");
            self.ipv6_restore_pending = false;
        }

        fn ipv4_default_restore_pending(&self) -> bool {
            self.ipv4_restore_pending
        }

        fn ipv6_default_restore_pending(&self) -> bool {
            self.ipv6_restore_pending
        }

        fn wait_before_default_restore_retry(&mut self) {
            self.events.push("wait-default-restore");
        }

        fn flush_route_cache(&mut self) -> anyhow::Result<()> {
            self.events.push("flush-route-cache");
            if self.fail_route_cache_flush {
                Err(anyhow::anyhow!("synthetic route cache flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(target_os = "linux")]
    static LINUX_PENDING_CLEANUP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn linux_cleanup_restores_defaults_after_forwarding_cleanup_exhausts_retries() {
        let mut actions = FakeLinuxNetworkCleanupActions {
            forwarding_failures_remaining: 3,
            ipv4_restore_failures_remaining: 1,
            ipv4_restore_pending: true,
            ipv6_restore_pending: true,
            fail_route_cache_flush: true,
            ..FakeLinuxNetworkCleanupActions::default()
        };

        let error = super::cleanup_linux_network_state_with_actions(&mut actions)
            .expect_err("forwarding and route-cache failures remain reportable");

        assert_eq!(
            actions.events,
            vec![
                "endpoint",
                "restore-ipv4",
                "restore-ipv6",
                "fd00-main-rule",
                "forwarding-wireguard",
                "forwarding-wireguard",
                "forwarding-wireguard",
                "restore-ipv4",
                "flush-route-cache",
            ]
        );
        assert!(!actions.ipv4_restore_pending);
        assert!(!actions.ipv6_restore_pending);
        let message = format!("{error:#}");
        assert!(message.contains("forwarding/WireGuard cleanup failed after three attempts"));
        assert!(message.contains("synthetic route cache flush failure"));
    }

    #[test]
    fn linux_cleanup_rechecks_default_after_forwarding_restores_alternate() {
        let mut actions = FakeLinuxNetworkCleanupActions {
            ipv4_restore_unblocked_by_forwarding_cleanup: true,
            ipv4_restore_failures_remaining: usize::MAX,
            ipv4_restore_pending: true,
            ..FakeLinuxNetworkCleanupActions::default()
        };

        super::cleanup_linux_network_state_with_actions(&mut actions)
            .expect("post-WireGuard secondary default completes saved-route cleanup");

        assert_eq!(
            actions.events,
            vec![
                "endpoint",
                "restore-ipv4",
                "restore-ipv6",
                "fd00-main-rule",
                "forwarding-wireguard",
                "restore-ipv4",
                "flush-route-cache",
            ]
        );
        assert!(!actions.ipv4_restore_pending);
    }

    #[test]
    fn linux_cleanup_retries_fd00_main_rule_removal_and_reports_its_failure() {
        let mut actions = FakeLinuxNetworkCleanupActions {
            fd00_failures_remaining: usize::MAX,
            ..FakeLinuxNetworkCleanupActions::default()
        };

        let error = super::cleanup_linux_network_state_with_actions(&mut actions)
            .expect_err("persistent fd00 rule cleanup failure remains reportable");

        assert_eq!(
            actions
                .events
                .iter()
                .filter(|event| **event == "fd00-main-rule")
                .count(),
            super::LINUX_NETWORK_CLEANUP_ATTEMPTS
        );
        assert!(
            format!("{error:#}")
                .contains("fd00::/8 main-table rule cleanup failed after three attempts")
        );
        assert!(
            format!("{error:#}").contains("synthetic fd00 rule cleanup failure")
        );
    }

    // The fd00::/8 journal records ownership, not intent: only the config
    // that created the rule removes it on teardown, while a pre-existing rule
    // is borrowed and left to its owner. A stub `ip` binary serves the rule
    // table from a state file so both sides of that contract run without
    // touching the host RPDB.
    #[cfg(target_os = "linux")]
    fn run_fd00_ownership_test_child(case: &str) {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_CASE: &str = "NVPN_FD00_OWNERSHIP_TEST_CASE";
        if let Ok(case) = std::env::var(CHILD_CASE) {
            let state_dir = std::path::PathBuf::from(
                std::env::var("NVPN_FD00_OWNERSHIP_STATE_DIR").expect("state directory"),
            );
            let log = state_dir.join("commands.log");
            let commands = || std::fs::read_to_string(&log).unwrap_or_default();
            // The stub stores the rule state as file content because the
            // child's stripped PATH offers no external file tools.
            let rule_present = || {
                std::fs::read_to_string(state_dir.join("rule-mode"))
                    .map(|mode| mode.trim() == "add")
                    .unwrap_or(false)
            };
            match case.as_str() {
                "pre-existing" => {
                    std::fs::write(state_dir.join("rule-mode"), b"add").unwrap();
                    // An identical rule already exists: it is borrowed, so it
                    // is not created again and not journaled for our cleanup.
                    assert!(!crate::ensure_linux_fd00_main_rule().unwrap());
                    assert_eq!(commands(), "");
                    let mut borrower = crate::LinuxNetworkCleanupState::default();
                    super::cleanup_linux_network_state_with_actions(&mut borrower).unwrap();
                    assert_eq!(
                        commands(),
                        "",
                        "a borrower's teardown must not remove a rule it did not create"
                    );
                    assert!(
                        rule_present(),
                        "a pre-existing rule must survive a borrower's teardown"
                    );
                }
                "created" => {
                    // The owner config starts while the rule is absent and
                    // creates it.
                    assert!(crate::ensure_linux_fd00_main_rule().unwrap());
                    assert_eq!(commands(), "add\n");
                    // A second config starting meanwhile finds the rule and
                    // borrows it without journaling ownership.
                    assert!(!crate::ensure_linux_fd00_main_rule().unwrap());
                    assert_eq!(commands(), "add\n");
                    let mut borrower = crate::LinuxNetworkCleanupState::default();
                    super::cleanup_linux_network_state_with_actions(&mut borrower).unwrap();
                    assert_eq!(
                        commands(),
                        "add\n",
                        "the borrower's stop must leave the owner's rule in place"
                    );
                    assert!(rule_present());
                    // The owner config stops and removes the rule it created.
                    let mut owner = crate::LinuxNetworkCleanupState::default();
                    owner.mesh_fd00_main_rule = true;
                    super::cleanup_linux_network_state_with_actions(&mut owner).unwrap();
                    assert_eq!(commands(), "add\ndel\n");
                    assert!(
                        !rule_present(),
                        "the owner's stop removes the rule it created"
                    );
                }
                other => panic!("unknown fd00 ownership case {other}"),
            }
            return;
        }

        let directory = std::env::temp_dir().join(format!(
            "nvpn-fd00-ownership-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let ip = directory.join("ip");
        std::fs::write(
            &ip,
            r#"#!/bin/sh
state_dir="$NVPN_FD00_OWNERSHIP_STATE_DIR"
if [ "$1" = -6 ] && [ "$2" = rule ]; then
  if [ "$3" = show ]; then
    mode=absent
    if [ -f "$state_dir/rule-mode" ]; then
      read mode < "$state_dir/rule-mode"
    fi
    if [ "$mode" = add ]; then
      printf '0:\tfrom all lookup local\n5265:\tfrom all to fd00::/8 lookup main\n32766:\tfrom all lookup main\n'
    else
      printf '0:\tfrom all lookup local\n32766:\tfrom all lookup main\n'
    fi
    exit 0
  fi
  if [ "$3" = add ]; then
    echo add > "$state_dir/rule-mode"
    echo add >> "$state_dir/commands.log"
    exit 0
  fi
  if [ "$3" = del ]; then
    echo del > "$state_dir/rule-mode"
    echo del >> "$state_dir/commands.log"
    exit 0
  fi
fi
exit 0
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state_dir = directory.join("state");
        std::fs::create_dir(&state_dir).unwrap();

        // Child-local PATH keeps the host `ip` unreachable and avoids
        // changing the environment of concurrently running tests.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                std::thread::current().name().unwrap(),
                "--nocapture",
            ])
            .env("PATH", &directory)
            .env(CHILD_CASE, case)
            .env("NVPN_FD00_OWNERSHIP_STATE_DIR", &state_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fd00_main_rule_cleanup_preserves_a_pre_existing_rule() {
        run_fd00_ownership_test_child("pre-existing");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fd00_main_rule_removal_follows_creation_across_two_configs() {
        run_fd00_ownership_test_child("created");
    }

    #[test]
    fn linux_cleanup_bounds_default_restore_retries() {
        let mut actions = FakeLinuxNetworkCleanupActions {
            ipv4_restore_failures_remaining: usize::MAX,
            ipv4_restore_pending: true,
            ..FakeLinuxNetworkCleanupActions::default()
        };

        let error = super::cleanup_linux_network_state_with_actions(&mut actions)
            .expect_err("persistent default-route failure remains reportable");

        assert_eq!(
            actions
                .events
                .iter()
                .filter(|event| **event == "restore-ipv4")
                .count(),
            super::LINUX_NETWORK_CLEANUP_ATTEMPTS + 1
        );
        assert_eq!(
            actions
                .events
                .iter()
                .filter(|event| **event == "wait-default-restore")
                .count(),
            super::LINUX_NETWORK_CLEANUP_ATTEMPTS - 1
        );
        assert!(actions.ipv4_restore_pending);
        assert!(
            format!("{error:#}").contains("failed to restore original IPv4 default route")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_failed_replacement_start_cleanup_survives_process_boundary() {
        let _guard = LINUX_PENDING_CLEANUP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = super::take_pending_linux_network_cleanup_state();
        assert!(
            prior.is_none(),
            "failed-start persistence test requires an empty in-process registry"
        );

        let expected_default = "default via 192.0.2.1 dev eth0 metric 100".to_string();
        super::replace_pending_linux_network_cleanup_state(Some(
            crate::LinuxNetworkCleanupState {
                iface: "nvpn-start-failure".to_string(),
                original_default_route: Some(expected_default.clone()),
                ..crate::LinuxNetworkCleanupState::default()
            },
        ));

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("nvpn-linux-start-cleanup-test-{nonce}"));
        std::fs::create_dir_all(&directory).expect("create temp directory");
        let config_path = directory.join("config.toml");
        let error = crate::persist_fips_private_tunnel_start_result(
            &config_path,
            Err::<(), _>(anyhow::anyhow!("synthetic replacement start failure")),
        )
        .expect_err("replacement start remains failed after persisting cleanup ownership");
        assert!(
            format!("{error:#}").contains("synthetic replacement start failure"),
            "the original replacement-start error must remain visible"
        );

        let pending = super::take_pending_linux_network_cleanup_state();
        assert!(
            pending.is_some(),
            "the failed start must retain in-process ownership until process exit"
        );
        let cleanup_path = crate::daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let saved = crate::read_daemon_network_cleanup_state(&cleanup_path)
            .expect("read cleanup ownership")
            .expect("cleanup ownership survives process-boundary readback");
        assert_eq!(saved.iface, "nvpn-start-failure");
        assert_eq!(saved.original_default_route, Some(expected_default));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_failed_stop_persists_only_remaining_cleanup_ownership() {
        let _guard = LINUX_PENDING_CLEANUP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = super::take_pending_linux_network_cleanup_state();
        assert!(
            prior.is_none(),
            "failed-stop persistence test requires an empty in-process registry"
        );

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("nvpn-linux-stop-cleanup-test-{nonce}"));
        std::fs::create_dir_all(&directory).expect("create temp directory");
        let config_path = directory.join("config.toml");
        let cleanup_path = crate::daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let stale_default = "default via 192.0.2.1 dev eth0 metric 100".to_string();
        crate::write_daemon_network_cleanup_state(
            &cleanup_path,
            &crate::LinuxNetworkCleanupState {
                iface: "nvpn-stop-failure".to_string(),
                original_default_route: Some(stale_default),
                ..crate::LinuxNetworkCleanupState::default()
            },
        )
        .expect("persist pre-stop cleanup ownership");

        let cleanup_error = Err(anyhow::anyhow!("synthetic partial cleanup failure"));
        super::record_linux_stop_cleanup_ownership(
            &cleanup_error,
            Some(crate::LinuxNetworkCleanupState {
                iface: "nvpn-stop-failure".to_string(),
                exit_node_runtime: crate::LinuxExitNodeRuntime {
                    ipv4_forward_was_enabled: Some(false),
                    ..crate::LinuxExitNodeRuntime::default()
                },
                ..crate::LinuxNetworkCleanupState::default()
            }),
        );
        crate::persist_fips_daemon_network_cleanup_state(&config_path, None)
            .expect("replace pre-stop ownership with remaining obligations");

        let saved = crate::read_daemon_network_cleanup_state(&cleanup_path)
            .expect("read remaining cleanup ownership")
            .expect("remaining cleanup ownership exists");
        assert_eq!(saved.iface, "nvpn-stop-failure");
        assert!(
            saved.original_default_route.is_none(),
            "a successfully restored default route must not be replayed after restart"
        );
        assert_eq!(
            saved.exit_node_runtime.ipv4_forward_was_enabled,
            Some(false),
            "the cleanup obligation that actually remains must stay persisted"
        );

        super::record_linux_stop_cleanup_ownership(&cleanup_error, None);
        crate::persist_fips_daemon_network_cleanup_state(&config_path, None)
            .expect("remove pre-stop ownership when no cleanup obligation remains");
        assert!(
            super::pending_linux_network_cleanup_state().is_none(),
            "an error without remaining ownership must not block the next start"
        );
        assert!(
            !cleanup_path.exists(),
            "an error without remaining ownership must remove the stale pre-stop file"
        );

        super::take_pending_linux_network_cleanup_state();
        let _ = std::fs::remove_dir_all(directory);
    }
