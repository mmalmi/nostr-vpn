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
                "forwarding-wireguard",
                "restore-ipv4",
                "flush-route-cache",
            ]
        );
        assert!(!actions.ipv4_restore_pending);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_magicdns_repair_only_reverts_the_recorded_configuration() {
        use std::os::unix::fs::PermissionsExt;

        const CHILD_CASE: &str = "NVPN_MAGICDNS_REPAIR_TEST_CASE";
        const LOG_ENV: &str = "NVPN_MAGICDNS_REPAIR_LOG";
        const EXPECT_REVERT_ENV: &str = "NVPN_MAGICDNS_REPAIR_EXPECT_REVERT";
        const FAKE_LO_DNS_ENV: &str = "NVPN_MAGICDNS_FAKE_LO_DNS";
        const FAKE_LO_DOMAIN_ENV: &str = "NVPN_MAGICDNS_FAKE_LO_DOMAIN";

        // Child: repair the recorded ownership against a fake resolvectl and
        // assert the per-link revert only happens while the link carries
        // exactly this configuration's resolver and routing domains.
        if let Ok(case) = std::env::var(CHILD_CASE) {
            let owned = nostr_vpn_core::magic_dns::MagicDnsResolverOwnership::new(
                "repair.example",
                std::net::Ipv4Addr::LOCALHOST,
                1053,
            );
            let mut state = crate::LinuxNetworkCleanupState {
                magic_dns_split_dns: Some(owned),
                ..crate::LinuxNetworkCleanupState::default()
            };
            crate::fips_private_mesh::repair_linux_network_cleanup_state(&mut state)
                .expect("recorded split DNS ownership must repair cleanly");
            assert!(
                state.magic_dns_split_dns.is_none(),
                "repaired ownership must leave the cleanup state"
            );
            let log = std::fs::read_to_string(std::env::var(LOG_ENV).expect("log path"))
                .unwrap_or_default();
            assert_eq!(
                log.contains("revert"),
                std::env::var(EXPECT_REVERT_ENV).as_deref() == Ok("1"),
                "{case}: unexpected resolvectl revert calls: {log}"
            );
            return;
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("nvpn-linux-magicdns-repair-{nonce}"));
        std::fs::create_dir_all(&directory).expect("create temp directory");
        let fake_resolvectl = directory.join("resolvectl");
        std::fs::write(
            &fake_resolvectl,
            "#!/bin/sh\nif [ \"$1\" = dns ] && [ \"$2\" = lo ]; then\n  echo \"Link 2 (lo): $NVPN_MAGICDNS_FAKE_LO_DNS\"\nfi\nif [ \"$1\" = domain ] && [ \"$2\" = lo ]; then\n  echo \"Link 2 (lo): $NVPN_MAGICDNS_FAKE_LO_DOMAIN\"\nfi\nif [ \"$1\" = revert ] && [ \"$2\" = lo ]; then\n  echo \"revert lo\" >> \"$NVPN_MAGICDNS_REPAIR_LOG\"\nfi\nexit 0\n",
        )
        .expect("write fake resolvectl");
        std::fs::set_permissions(
            &fake_resolvectl,
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("make fake resolvectl executable");
        let log_path = directory.join("resolvectl.log");

        // "owned": the link still carries exactly this configuration's
        // resolver and routing domains.
        // "second-configuration": another configuration reinstalled the link
        // settings; reverting them would tear down a running configuration.
        // "mixed-owner": another configuration added its own server and
        // domain while this configuration's settings are still present;
        // reverting the shared link would delete the foreign settings too,
        // so no resolvectl mutation may run at all.
        for (case, link_dns, link_domain, expect_revert) in [
            (
                "owned",
                "127.0.0.1:1053",
                "~fips ~repair.example",
                true,
            ),
            (
                "second-configuration",
                "127.0.0.1:2049",
                "~fips ~other.example",
                false,
            ),
            (
                "mixed-owner",
                "127.0.0.1:1053 127.0.0.1:2049",
                "~fips ~repair.example ~other.example",
                false,
            ),
        ] {
            let _ = std::fs::remove_file(&log_path);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    std::thread::current().name().unwrap(),
                    "--nocapture",
                ])
                .env("PATH", &directory)
                .env(CHILD_CASE, case)
                .env(LOG_ENV, &log_path)
                .env(EXPECT_REVERT_ENV, if expect_revert { "1" } else { "0" })
                .env(FAKE_LO_DNS_ENV, link_dns)
                .env(FAKE_LO_DOMAIN_ENV, link_domain)
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
