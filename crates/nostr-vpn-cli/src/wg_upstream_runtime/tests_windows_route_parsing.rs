    #[test]
    fn formats_native_windows_interface_guid_like_get_netadapter() {
        assert_eq!(
            format_windows_interface_guid(
                0x12345678,
                0x9abc,
                0xdef0,
                [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
            ),
            "12345678-9abc-def0-1234-56789abcdef0"
        );
    }

    #[test]
    fn parses_windows_default_route_from_route_print() {
        // Synthetic `route print -4 0.0.0.0` output. Only the
        // 0.0.0.0/0.0.0.0 row matters; all other content is meant to
        // be skipped by the parser.
        let sample = "\
===========================================================================
Interface List
 23...00 ff a1 b2 c3 d4 ......WireGuard Tunnel
 12...c0 d4 fe ff aa bb ......Realtek PCIe GbE
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
";
        let parsed = parse_windows_default_route_columns(sample).expect("default route parsed");
        assert_eq!(parsed.gateway, "192.168.1.1");
        assert_eq!(parsed.interface_ip, "192.168.1.42");
        assert_eq!(parsed.metric, 25);
    }

    #[test]
    fn skips_on_link_default_routes() {
        let sample = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link        10.0.0.1     50
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.42     25
";
        let parsed =
            parse_windows_default_route_columns(sample).expect("non-On-link default parsed");
        assert_eq!(parsed.gateway, "192.168.1.1");
        assert_eq!(parsed.interface_ip, "192.168.1.42");
        assert_eq!(parsed.metric, 25);
    }

    #[test]
    fn chooses_lowest_metric_windows_default_route() {
        let sample = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      172.20.0.1    172.20.0.22     75
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.42     25
";
        let parsed = parse_windows_default_route_columns(sample).expect("default route parsed");
        assert_eq!(parsed.gateway, "192.168.1.1");
        assert_eq!(parsed.interface_ip, "192.168.1.42");
        assert_eq!(parsed.metric, 25);
    }

    #[test]
    fn selects_next_ranked_physical_default_when_best_route_is_a_tunnel() {
        let sample = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        10.44.0.1      10.44.0.2      1
          0.0.0.0          0.0.0.0        10.77.0.1      10.77.0.2      2
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.42     25
";
        let route = select_windows_default_route_candidate(
            parse_windows_default_route_candidates(sample),
            &[77, 88],
            |address| match address {
                "10.44.0.2" => Ok(77),
                "10.77.0.2" => Ok(88),
                "192.168.1.42" => Ok(11),
                other => Err(anyhow!("unexpected address {other}")),
            },
        )
        .expect("eligible physical default route");

        assert_eq!(route, windows_underlay(11, "192.168.1.1", "192.168.1.42"));
    }

    #[test]
    fn returns_none_when_no_default_route_present() {
        let sample = "Active Routes:\n      127.0.0.0  255.0.0.0  On-link  127.0.0.1  331\n";
        assert!(parse_windows_default_route_columns(sample).is_none());
    }

    #[test]
    fn parses_sorted_windows_ipv6_default_routes() {
        let sample = "\
If Metric Network Destination Gateway
24 1 ::/0 On-link
4 25 ::/0 fe80::1
7 5 2001:db8::/64 On-link
";
        assert_eq!(
            parse_windows_ipv6_default_route_columns(sample),
            vec![
                WindowsIpv6DefaultRoute {
                    gateway: None,
                    interface_index: 24,
                    metric: 1,
                },
                WindowsIpv6DefaultRoute {
                    gateway: Some("fe80::1".parse().expect("gateway")),
                    interface_index: 4,
                    metric: 25,
                },
            ]
        );
    }

    #[test]
    fn resolves_default_route_from_the_sampled_adapter_inventory() {
        let mut physical = netdev::Interface::dummy();
        physical.index = 11;
        physical.ipv4 = vec!["192.0.2.147/24".parse().expect("physical address")];
        let mut tunnel = netdev::Interface::dummy();
        tunnel.index = 77;
        tunnel.ipv4 = vec!["10.44.0.2/24".parse().expect("tunnel address")];
        let output = "0.0.0.0 0.0.0.0 10.44.0.1 10.44.0.2 1\n\
                      0.0.0.0 0.0.0.0 198.51.100.1 198.51.100.2 2\n\
                      0.0.0.0 0.0.0.0 192.0.2.1 192.0.2.147 25";
        let route = select_windows_default_route_from_output(output, &[77], &[tunnel, physical])
            .expect("skip tunnel and address removed during sampling");
        assert_eq!(route, windows_underlay(11, "192.0.2.1", "192.0.2.147"));
        assert!(select_windows_default_route_from_output(output, &[], &[]).is_err());
    }

    #[test]
    fn parses_windows_interface_index_for_alias() {
        let sample = "\
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
  3          25        1500  connected     Ethernet
 11           5        1150  connected     nvpn
";
        assert_eq!(
            parse_windows_interface_index_for_alias(sample, "Ethernet"),
            Some(3)
        );
        assert_eq!(
            parse_windows_interface_index_for_alias(sample, "Loopback Pseudo-Interface 1"),
            Some(1)
        );
    }

    #[test]
    fn parses_windows_wireguard_latest_handshake_output() {
        assert!(
            !parse_windows_wireguard_latest_handshakes("abc\t0\n", "abc").expect("zero handshake")
        );
        assert!(
            parse_windows_wireguard_latest_handshakes("abc\t1778720702\n", "abc")
                .expect("completed handshake")
        );
        assert!(
            parse_windows_wireguard_latest_handshakes("other\t1778720702\n", "abc")
                .expect_err("another peer cannot satisfy the target handshake")
                .to_string()
                .contains("peer mismatch")
        );
    }

    #[test]
    fn windows_native_endpoint_comes_from_the_exact_active_peer() {
        assert_eq!(
            parse_windows_wireguard_peer_endpoint("abc\t198.51.100.42:51820\n", "abc")
                .expect("concrete endpoint"),
            "198.51.100.42:51820".parse::<SocketAddr>().expect("socket")
        );
        assert!(
            parse_windows_wireguard_peer_endpoint(
                "abc\t198.51.100.42:51820\nother\t192.0.2.9:51820\n",
                "abc",
            )
            .expect_err("multiple peers make endpoint ownership ambiguous")
            .to_string()
            .contains("peer mismatch")
        );
        assert!(
            parse_windows_wireguard_peer_endpoint("other\t192.0.2.9:51820\n", "abc")
                .expect_err("a DNS-resolved address from another peer must be rejected")
                .to_string()
                .contains("peer mismatch")
        );
    }

    #[test]
    fn windows_daemon_uses_only_native_owned_tunnel_state() {
        let source = include_str!("windows_daemon.rs");
        let config_source = include_str!("windows_native_config.rs");
        let route_source = include_str!("windows_system_routes.rs");
        let cleanup_source = include_str!("windows_native_ownership.rs");
        assert!(
            !source.contains("apply_daemon_wg_upstream_userspace"),
            "the daemon must surface native WireGuardNT failure instead of switching backends"
        );
        assert!(
            !source.contains("single_active_tunnel"),
            "handshake success must come from the requested tunnel only"
        );
        assert!(
            !source.contains(".args([\"show\", \"all\""),
            "handshake queries must be scoped to the requested tunnel"
        );
        assert!(
            cleanup_source.contains("impl Drop for WindowsNativeWireGuardTunnel"),
            "owned service/config state needs a final synchronous cleanup retry"
        );
        assert!(
            config_source.contains("impl Drop for OwnedWindowsNativeWireGuardConfig"),
            "partial config creation needs an owned cleanup guard"
        );
        let startup = source
            .split("async fn apply_daemon_wg_upstream_native")
            .nth(1)
            .and_then(|tail| tail.split("struct WindowsWireGuardTools").next())
            .expect("native startup source");
        assert!(
            !startup.contains("/uninstalltunnelservice"),
            "startup must never uninstall a same-name service it does not own"
        );
        let collision_guard = startup
            .find("ensure_windows_native_wireguard_service_absent")
            .expect("same-name service collision guard");
        let install = startup
            .find("create_windows_native_wireguard_service")
            .expect("atomic native service creation");
        assert!(
            collision_guard < install,
            "same-name service ownership must be rejected before native service creation"
        );
        let config_journal = startup
            .find("fsync native WireGuard config cleanup intent before creation")
            .expect("write-ahead config ownership");
        let config_create = startup
            .find("write_windows_native_wireguard_config")
            .expect("native config creation");
        let service_journal = startup
            .find("fsync native WireGuard service cleanup intent before creation")
            .expect("write-ahead service ownership");
        assert!(
            config_journal < config_create && service_journal < install,
            "config and Automatic service ownership must be fsynced before their first side effect"
        );
        assert!(
            !startup.contains("/installtunnelservice"),
            "WireGuard InstallTunnel can delete a stopped unowned same-name service"
        );
        let handshake = startup
            .find("wait_windows_native_wireguard_handshake")
            .expect("target-scoped handshake");
        let handshake_stimulus = startup
            .find("begin_windows_native_wireguard_handshake")
            .expect("native handshake stimulus");
        let keepalive_restore = startup
            .find("restore_windows_native_wireguard_keepalive")
            .expect("configured keepalive restore");
        let concrete_endpoint = startup
            .find("windows_native_wireguard_peer_endpoint")
            .expect("concrete target endpoint query");
        let route = startup
            .find("apply_windows_endpoint_bypass_route")
            .expect("endpoint route installation");
        assert!(
            handshake_stimulus < handshake
                && handshake < keepalive_restore
                && keepalive_restore < concrete_endpoint
                && concrete_endpoint < route,
            "the already-up adapter must be stimulated, verified, and restored before route ownership"
        );
        assert!(
            startup
                .matches("windows_native_wireguard_peer_endpoint")
                .count()
                >= 2,
            "startup must recheck a peer that roams while its first route is installed"
        );
        assert!(
            !startup.contains("resolve_windows_wireguard_endpoint"),
            "an independent DNS answer cannot define the native service's endpoint route"
        );
        assert!(
            config_source.contains("windows_native_wireguard_config_text(config)")
                && config_source.contains(
                    "\"[Interface]\\nTable = off\\n{interface}\\n\\n[Peer]\\n{peer}\""
                ),
            "native WireGuard must not install AllowedIPs routes before the verified handshake"
        );
        let route_apply = route_source
            .split("fn apply_windows_endpoint_bypass_route")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(target_os = \"windows\")]").next())
            .expect("native WireGuard route apply");
        assert!(
            route_apply.contains("true,\n        cleanup_journal_config_path"),
            "nVPN must install and journal the default route after handshake"
        );
    }

    #[test]
    fn windows_native_wireguard_disables_automatic_routes() {
        let config = WireGuardExitConfig {
            address: "10.64.70.195/32".to_string(),
            private_key: "private-key".to_string(),
            peer_public_key: "peer-key".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            ..WireGuardExitConfig::default()
        };
        let mut config = config;
        config.dns = vec!["10.64.0.1".to_string()];
        let text = windows_native_wireguard_config_text(&config)
            .expect("render managed native WireGuard config");
        assert!(text.starts_with("[Interface]\nTable = off\n"));
        assert_eq!(text.matches("Table = off").count(), 1);
        assert!(
            !text.contains("DNS ="),
            "nVPN applies provider DNS only after the verified handshake"
        );
        assert!(text.contains("[Peer]\n"));
        assert!(text.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(
            windows_native_wireguard_config_text(&WireGuardExitConfig::default()).is_err(),
            "an unexpected core config shape must fail closed"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn journaled_pending_cleanup_retry_retires_exact_durable_entries() {
        assert!(pending_windows_native_cleanup_snapshot().is_empty());
        assert!(pending_windows_route_cleanup_snapshot().is_empty());

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "nvpn-journaled-pending-cleanup-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test directory");
        let config_path = dir.join("config.toml");
        let cleanup_path = crate::daemon_network_cleanup_file_path(&config_path).expect("cleanup path");
        let owner_token = format!("nvpn-test-{nonce:032x}");
        let native = WindowsNativeWireGuardCleanupState {
            name: format!("nvpn-test-{:08x}", std::process::id()),
            config_path: windows_native_wireguard_config_path("nvpn-wg-exit", &owner_token),
            wireguard_exe: PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe"),
            owner_token,
            service_owned: true,
            config_owned: true,
        };
        let routes = WindowsRouteCleanupSnapshot::from_owned_routes(vec![WindowsRouteSpec {
            prefix: "203.0.113.254/32".to_string(),
            interface_index: 1,
            next_hop: "0.0.0.0".to_string(),
            metric: 1,
            interface_identity: Some("nvpn-test-route-does-not-exist".to_string()),
        }]);

        crate::persist_windows_native_wireguard_cleanup_intent(&config_path, &native)
            .expect("persist native ownership");
        crate::persist_windows_route_cleanup_intent(&config_path, &routes, true)
            .expect("persist route ownership");
        retain_pending_windows_native_cleanup(native);
        retain_pending_windows_route_cleanup(routes);

        retry_pending_windows_native_cleanup_journaled(&config_path)
            .expect("retire absent native ownership");
        retry_pending_windows_route_cleanup_journaled(&config_path)
            .expect("retire absent route ownership");
        crate::persist_fips_daemon_network_cleanup_state(&config_path, None)
            .expect("periodic persist after exact retirement");
        assert!(
            !cleanup_path.exists(),
            "successful journal-aware retries must leave no durable ownership"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_routes_are_journaled_and_adapter_bound_before_mutation() {
        let source = include_str!("windows_default_routes.rs");
        let runner = source
            .split("impl WindowsRouteCommandRunner for SystemWindowsRouteCommandRunner")
            .nth(1)
            .expect("system Windows route runner");
        let journaled_mutation = source
            .split("fn run_journaled_route_mutation")
            .nth(1)
            .and_then(|tail| tail.split("impl WindowsRouteCommandRunner").next())
            .expect("journaled route mutation implementation");
        let intent = journaled_mutation
            .find("persist_route_intent(route, true)")
            .expect("write-ahead route ownership");
        let mutation = journaled_mutation
            .find("operation()")
            .expect("route side effect callback");
        assert!(
            intent < mutation && runner.contains("run_journaled_route_mutation"),
            "route cleanup intent must be fsynced before netsh mutates the table"
        );
        assert!(
            runner.contains("resolve_windows_interface_identity(route.interface_index)")
                && runner.contains("refusing to touch a possibly reused interface index"),
            "route repair must bind ownership to a stable adapter identity and fail closed"
        );
    }

    #[test]
    fn windows_native_wireguard_secret_is_acl_protected_before_write() {
        let source = include_str!("windows_native_config.rs");
        let daemon_source = include_str!("windows_daemon.rs");
        let writer = source
            .split("fn write_windows_native_wireguard_config")
            .nth(1)
            .and_then(|tail| {
                tail.split("struct OwnedWindowsNativeWireGuardConfig")
                    .next()
            })
            .expect("native config writer source");
        let directory_acl = writer
            .find("restrict_and_verify_windows_native_wireguard_acl(&root, true)")
            .expect("directory ACL restriction and audit");
        let create = writer.find(".create_new(true)").expect("exclusive create");
        let no_reparse = writer
            .find(".custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)")
            .expect("non-reparse create");
        let file_acl = writer
            .find("restrict_and_verify_windows_native_wireguard_acl(&path, false)")
            .expect("file ACL restriction and audit");
        let owner_marker = writer
            .find("write_windows_native_wireguard_owner_marker")
            .expect("durable owner marker");
        let secret_write = writer
            .find("write_all(&mut file, config_text.as_bytes())")
            .expect("secret write");
        let sync = writer.find("file.sync_all()").expect("durable secret sync");
        assert!(
            directory_acl < owner_marker
                && owner_marker < create
                && create < no_reparse
                && no_reparse < file_acl
                && file_acl < secret_write
                && secret_write < sync,
            "durable ownership and directory/file safety must precede native WireGuard secrets"
        );
        let marker_writer = source
            .split("fn write_windows_native_wireguard_owner_marker")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn write_windows_native_wireguard_config")
                    .next()
            })
            .expect("native owner marker writer source");
        assert!(
            marker_writer.contains(".create_new(true)")
                && marker_writer.contains(".custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)")
                && marker_writer
                    .contains("restrict_and_verify_windows_native_wireguard_acl(&marker_path")
                && marker_writer.contains("marker.sync_all()")
                && source.contains(".join(owner_token)"),
            "the pre-config owner marker must be unique, ACL-protected, non-reparse, and durable"
        );
        assert!(
            daemon_source.contains("-Description {}")
                && include_str!("windows_native_ownership.rs")
                    .contains("$service.PathName -cne $expectedPath")
                && include_str!("windows_native_ownership.rs")
                    .contains("windows_native_wireguard_service_is_owned")
                && include_str!("windows_native_ownership.rs")
                    .contains("windows_powershell_literal(&format!(\"Name='{escaped_service_name}'\"))")
                && !include_str!("windows_native_ownership.rs")
                    .contains("-Filter \\\"Name='{escaped_service_name}'\\\""),
            "service cleanup must verify its exact binary path and durable owner token"
        );
        let cleanup_source = include_str!("windows_native_ownership.rs");
        let config_cleanup = cleanup_source
            .split("fn cleanup_windows_native_wireguard_config")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(crate) fn cleanup_windows_native_wireguard_state")
                    .next()
            })
            .expect("native config cleanup source");
        let ownership_audit = config_cleanup
            .find("windows_native_wireguard_config_is_owned")
            .expect("exact config ownership audit");
        let config_delete = config_cleanup
            .find("std::fs::remove_file(path)")
            .expect("owned config deletion");
        assert!(
            ownership_audit < config_delete
                && config_cleanup.contains("windows_native_wireguard_owner_marker_is_owned"),
            "repair must verify the exact durable marker before deleting a native config"
        );
    }

    #[test]
    fn prior_release_native_wireguard_config_layout_remains_auditable() {
        let root = std::path::Path::new("/ProgramData/nostr-vpn/wireguard");
        let owner_token = "nvpn-owner-token";
        let legacy = root.join("nvpn-wg-exit.conf");
        assert_eq!(
            classify_windows_native_wireguard_config_path(&legacy, root, owner_token)
                .expect("legacy config layout"),
            WindowsNativeWireGuardConfigLayout::Legacy
        );
        assert_eq!(
            windows_native_wireguard_legacy_owner_marker_path(&legacy),
            root.join("nvpn-wg-exit.conf:nvpn-owner"),
            "the prior release stored its exact owner token in this NTFS ADS"
        );

        let current = root.join(owner_token).join("nvpn-wg-exit.conf");
        assert_eq!(
            classify_windows_native_wireguard_config_path(&current, root, owner_token)
                .expect("current config layout"),
            WindowsNativeWireGuardConfigLayout::OwnerDirectory(
                root.join(owner_token)
            )
        );
        assert!(
            classify_windows_native_wireguard_config_path(
                &root.join("foreign").join("nvpn-wg-exit.conf"),
                root,
                owner_token,
            )
            .is_err(),
            "cleanup must not accept a config outside either exact owned layout"
        );
    }

    #[test]
    fn sanitizes_windows_native_wireguard_tunnel_name() {
        let config = WireGuardExitConfig {
            interface: " nvpn wg/exit ".to_string(),
            ..WireGuardExitConfig::default()
        };
        assert_eq!(
            windows_native_wireguard_tunnel_name(&config),
            "nvpn-wg-exit"
        );
        let long = WireGuardExitConfig {
            interface: "this-interface-name-is-far-too-long-for-wireguard".to_string(),
            ..WireGuardExitConfig::default()
        };
        let long_name = windows_native_wireguard_tunnel_name(&long);
        assert!(long_name.starts_with("nvpn-"));
        assert!(windows_wireguard_tunnel_name_is_valid(&long_name));
        let reserved = WireGuardExitConfig {
            interface: "CON".to_string(),
            ..WireGuardExitConfig::default()
        };
        let reserved_name = windows_native_wireguard_tunnel_name(&reserved);
        assert_ne!(reserved_name, "CON");
        assert!(windows_wireguard_tunnel_name_is_valid(&reserved_name));
    }
