#[test]
fn canonical_reconcile_removes_an_identical_reasserted_default() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let primary = initial.main_routes[0].clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial strict exit");
    runner.state.main_routes.push(primary.clone());

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&primary),
    )
    .expect("unchanged-fingerprint route reconciliation");

    assert!(
        runner
            .state
            .main_routes
            .iter()
            .all(|route| route.contains("dev nvwg0"))
    );
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime).expect("cleanup");
    assert_eq!(runner.state, initial);
}

#[test]
fn same_interface_reconnect_uses_the_fresh_default_for_endpoint_replacement() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let primary = runner.state.main_routes[0].clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial strict exit");
    let reconnected = "default via 192.0.2.254 dev eth0 metric 25".to_string();
    runner.state.main_routes.push(reconnected.clone());

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&primary),
    )
    .expect("same-interface gateway refresh");

    assert_eq!(
        runner.state.endpoint_routes["198.51.100.20/32"],
        vec!["198.51.100.20/32 via 192.0.2.254 dev eth0".to_string()],
        "the old managed /32 must not override the exact fresh default captured immediately before replacement"
    );
    assert_eq!(
        runtime.previous_default_route.as_deref(),
        Some(reconnected.as_str())
    );
}

#[test]
fn refreshed_underlay_details_replace_only_the_same_interface() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let primary = runner.state.main_routes[0].clone();
    let secondary = runner.state.main_routes[1].clone();
    let mut runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial apply");
    let refreshed_primary = "default via 192.0.2.254 dev eth0 src 192.0.2.44 metric 25".to_string();

    runtime.refresh_underlay_default_route(refreshed_primary.clone());

    assert!(!runtime.previous_main_default_routes.contains(&primary));
    assert!(runtime.previous_main_default_routes.contains(&secondary));
    assert!(
        runtime
            .previous_main_default_routes
            .contains(&refreshed_primary)
    );
    assert_eq!(
        runtime
            .underlay_default_route_for_interface("eth0")
            .expect("refreshed primary")
            .line,
        refreshed_primary
    );
}

#[test]
fn inflated_same_path_metric_does_not_poison_direct_route_cleanup() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    let primary = initial.main_routes[0].clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial strict exit");
    let inflated =
        "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 20010".to_string();
    runner.state.main_routes.push(inflated.clone());
    let mut runtime = runtime;
    runtime.refresh_underlay_default_route(inflated.clone());

    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&inflated),
    )
    .expect("reconcile de-prioritized same-path default");

    assert_eq!(runtime.previous_default_route.as_deref(), Some(primary.as_str()));
    assert!(runtime.previous_main_default_routes.contains(&primary));
    assert!(!runtime.previous_main_default_routes.contains(&inflated));
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime).expect("cleanup");
    assert_eq!(runner.state, initial);
}

#[test]
fn new_underlay_is_cached_and_switch_back_survives_reapply() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial_defaults = runner.state.main_routes.clone();
    let primary = initial_defaults[0].clone();
    let new_underlay = "default via 10.42.0.1 dev wlan0 src 10.42.0.20 metric 5".to_string();
    let mut runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some(&primary),
    )
    .expect("initial primary apply");

    assert_eq!(
        runtime.underlay_default_route_hints_with(&mut runner),
        std::slice::from_ref(&primary)
    );

    runner.usable_default_interfaces.remove("eth0");
    let hints = runtime
        .underlay_default_route_hints_with(&mut runner)
        .to_vec();
    assert_eq!(hints, initial_defaults);
    let usable_hints = hints
        .into_iter()
        .filter(|route| {
            crate::linux_default_route_spec_from_line(route)
                .is_some_and(|route| runner.ipv4_default_route_is_usable(&route))
        })
        .collect::<Vec<_>>();
    let alternate = lowest_metric_default_route(&usable_hints.join("\n"))
        .map(|(route, _)| route)
        .expect("carrier-up journal route");
    assert_eq!(alternate, initial_defaults[1]);
    runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&alternate),
    )
    .expect("fail over to captured alternate");
    assert!(runner.state.endpoint_routes["198.51.100.20/32"][0].contains("dev eth1"));
    runner.usable_default_interfaces.insert("eth0".to_string());

    runner.state.main_routes.push(new_underlay.clone());
    runtime.refresh_underlay_default_route(new_underlay.clone());
    let mut runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&new_underlay),
    )
    .expect("refresh onto newly activated underlay");
    assert!(
        runner
            .state
            .main_routes
            .iter()
            .all(|route| route.contains("dev nvwg0")),
        "a newly appearing physical default must be cached then removed under strict exit"
    );

    assert!(
        initial_defaults
            .iter()
            .chain(std::iter::once(&new_underlay))
            .all(|route| runtime.previous_main_default_routes.contains(route)),
        "runtime must retain old defaults for switch-back and add the new cleanup route"
    );

    runtime.refresh_underlay_default_route(primary.clone());
    let mut runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        Some(&primary),
    )
    .expect("switch back to original underlay");
    assert_eq!(
        runtime.underlay_default_route_hints_with(&mut runner),
        std::slice::from_ref(&primary),
        "only the active primary may feed later route selection"
    );
    for _ in 0..2 {
        let hint = lowest_metric_default_route(
            &runtime
                .underlay_default_route_hints_with(&mut runner)
                .join("\n"),
        )
        .map(|(route, _)| route)
        .expect("active underlay hint");
        runtime = apply_linux_wireguard_exit_upstream_with(
            &mut runner,
            &config(),
            "10.44.0.0/16",
            Some(&runtime),
            Some(&hint),
        )
        .expect("repeated WireGuard/DNS reapply");
    }
    assert_eq!(
        runner.state.endpoint_routes["198.51.100.20/32"],
        vec!["198.51.100.20/32 via 192.0.2.1 dev eth0 src 192.0.2.10".to_string()]
    );
    for route in initial_defaults
        .iter()
        .chain(std::iter::once(&new_underlay))
    {
        assert_eq!(
            runtime
                .previous_main_default_routes
                .iter()
                .filter(|candidate| *candidate == route)
                .count(),
            1,
            "every captured physical default must remain exactly once in the cleanup journal"
        );
    }
}

#[test]
fn failed_reapply_cleanup_preserves_new_and_restores_usable_defaults() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let saved_defaults = runner.state.main_routes.clone();
    let mut runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("apply");
    runtime.refresh_underlay_default_route(
        "default via 10.42.0.1 dev wlan0 src 10.42.0.20 metric 5".to_string(),
    );
    let fresh_physical = "default via 198.51.100.1 dev eth2 src 198.51.100.42".to_string();
    runner.fail_route_cache_once = true;
    apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        Some(&runtime),
        runtime.previous_default_route.as_deref(),
    )
    .expect_err("failed reapply rolls back before runtime cleanup");
    runner.state.main_routes.insert(0, fresh_physical.clone());
    runner.usable_default_interfaces.remove("wlan0");

    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime)
        .expect("cleanup after underlay handoff");

    assert_eq!(
        runner.state.main_routes,
        std::iter::once(fresh_physical)
            .chain(saved_defaults)
            .collect::<Vec<_>>(),
        "cleanup must delete the exact managed WG default, preserve the live physical route, \
         and restore every captured default that is still usable"
    );
    assert!(
        runner.commands.iter().any(|(_, args)| {
            args == &strings(&["-4", "route", "del", "default", "dev", "nvwg0"])
        })
    );
}

#[test]
fn handoff_cleanup_preserves_new_and_saved_defaults() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let captured = vec![
        "default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10".to_string(),
        "default dev nvwg0 src 10.77.0.2 metric 30".to_string(),
    ];
    let fresh_physical = "default via 198.51.100.1 dev eth2 src 198.51.100.42 metric 5".to_string();
    runner.state.main_routes = vec![
        fresh_physical.clone(),
        "default dev nvwg0 src 10.77.0.2".to_string(),
    ];

    restore_linux_main_default_snapshot(&mut runner, "nvwg0", &captured)
        .expect("handoff-aware cleanup");

    assert_eq!(
        runner.state.main_routes,
        vec![fresh_physical, captured[0].clone(), captured[1].clone()],
        "fresh physical state and all usable captured defaults must survive cleanup"
    );
}

#[test]
fn cleanup_skips_a_stale_primary_and_restores_the_healthy_secondary() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let captured = runner.state.main_routes.clone();
    runner.state.main_routes = vec!["default dev nvwg0 src 10.77.0.2".to_string()];
    runner.usable_default_interfaces.remove("eth0");

    restore_linux_main_default_snapshot(&mut runner, "nvwg0", &captured)
        .expect("restore healthy fallback");

    assert_eq!(
        runner.state.main_routes,
        vec![captured[1].clone()],
        "a link-down cached primary must not suppress or outrank the usable alternate"
    );
}

#[test]
fn cleanup_continues_restoring_alternates_after_one_route_fails() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let captured = runner.state.main_routes.clone();
    runner.state.main_routes = vec!["default dev nvwg0 src 10.77.0.2".to_string()];
    runner.fail_route_replace_once = Some("dev eth0".to_string());

    let error = restore_linux_main_default_snapshot(&mut runner, "nvwg0", &captured)
        .expect_err("the failed route remains reportable");

    assert!(format!("{error:#}").contains("synthetic route replacement failure"));
    assert_eq!(
        runner.state.main_routes,
        vec![captured[1].clone()],
        "a failed stale/primary restore must not prevent the healthy alternate"
    );
}

#[test]
fn transaction_rollback_restores_exact_defaults_even_if_a_physical_route_survives() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let captured = runner.state.main_routes.clone();
    runner.state.main_routes = vec![
        captured[1].clone(),
        "default dev nvwg0 src 10.77.0.2".to_string(),
    ];

    restore_linux_main_default_snapshot_exact(&mut runner, "nvwg0", &captured)
        .expect("exact transaction rollback");

    assert_eq!(runner.state.main_routes, captured);
    assert!(
        runner.commands.iter().any(|(_, args)| {
            args == &strings(&["-4", "route", "del", "default", "dev", "nvwg0"])
        })
    );
}

#[test]
fn transaction_rollback_preserves_a_new_physical_default() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let captured = runner.state.main_routes.clone();
    let fresh = "default via 198.51.100.1 dev eth2 src 198.51.100.42 metric 5".to_string();
    runner.state.main_routes = vec![fresh.clone(), "default dev nvwg0 src 10.77.0.2".to_string()];

    restore_linux_main_default_snapshot_exact(&mut runner, "nvwg0", &captured)
        .expect("handoff-safe transaction rollback");

    assert!(runner.state.main_routes.contains(&fresh));
    assert!(
        captured
            .iter()
            .all(|route| runner.state.main_routes.contains(route))
    );
}

#[test]
fn apply_replaces_kernel_wireguard_peer_set_and_clears_omitted_fields() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.wireguard_config = "\
[Interface]
PrivateKey = old-private

[Peer]
PublicKey = unrelated-peer
AllowedIPs = 10.99.0.0/16

[Peer]
PublicKey = peer-key
PresharedKey = stale-psk
AllowedIPs = 10.88.0.0/16
PersistentKeepalive = 55
"
    .to_string();
    let mut desired = config();
    desired.peer_preshared_key.clear();
    desired.persistent_keepalive_secs = 0;

    apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &desired,
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("replace WireGuard configuration");

    assert!(
        runner
            .commands
            .iter()
            .any(|(program, args)| program == "wg"
                && args.first().is_some_and(|arg| arg == "setconf")),
        "production apply must use replacement semantics"
    );
    assert!(
        !runner
            .commands
            .iter()
            .any(|(program, args)| program == "wg" && args.first().is_some_and(|arg| arg == "set")),
        "incremental `wg set` leaves unrelated peers and omitted peer fields behind"
    );
    assert!(
        runner
            .state
            .wireguard_config
            .contains("PublicKey = peer-key")
    );
    assert!(!runner.state.wireguard_config.contains("unrelated-peer"));
    assert!(!runner.state.wireguard_config.contains("PresharedKey"));
    assert!(
        !runner
            .state
            .wireguard_config
            .contains("PersistentKeepalive")
    );
}

#[test]
fn wireguard_apply_and_rollback_stream_exact_configs_over_stdin() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.wireguard_config = "\
[Interface]
PrivateKey = old-private
ListenPort = 41194

[Peer]
PublicKey = old-peer
PresharedKey = old-preshared
AllowedIPs = 10.99.0.0/16
"
    .to_string();
    let initial_config = runner.state.wireguard_config.clone();
    let desired = config();
    let desired_config = linux_wireguard_kernel_config(
        &desired,
        super::super::resolve_linux_wireguard_exit_endpoint(&desired.endpoint)
            .expect("numeric endpoint"),
    );
    runner.fail_route_cache_once = true;

    apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &desired,
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect_err("final apply failure must stream the exact rollback config");

    let setconf_calls = runner
        .stdin_commands
        .iter()
        .filter(|(program, args, _)| {
            program == "wg" && args == &strings(&["setconf", "nvwg0", "/dev/stdin"])
        })
        .collect::<Vec<_>>();
    assert_eq!(
        setconf_calls.len(),
        2,
        "apply and rollback must each use wg setconf /dev/stdin"
    );
    assert_eq!(
        setconf_calls[0].2,
        desired_config.as_bytes(),
        "apply must stream the desired config without rewriting it"
    );
    assert_eq!(
        setconf_calls[1].2,
        initial_config.as_bytes(),
        "rollback must stream the captured config byte-for-byte"
    );
    assert_eq!(runner.state.wireguard_config, initial_config);
    let setconf_commands = runner
        .commands
        .iter()
        .filter(|(program, args)| {
            program == "wg" && args.first().is_some_and(|arg| arg == "setconf")
        })
        .collect::<Vec<_>>();
    assert_eq!(setconf_commands.len(), 2);
    for (_, args) in setconf_commands {
        assert_eq!(
            args,
            &strings(&["setconf", "nvwg0", "/dev/stdin"]),
            "setconf must never receive a config file path"
        );
    }
    for (_, args) in &runner.commands {
        assert!(
            args.iter().all(|arg| ![
                "private-key",
                "peer-key",
                "old-private",
                "old-peer",
                "old-preshared"
            ]
            .iter()
            .any(|secret| arg.contains(secret))),
            "WireGuard secrets must never appear in command arguments: {args:?}"
        );
    }
}

#[test]
fn system_stdin_runner_reaps_early_failure_and_preserves_stderr() {
    let mut runner = SystemLinuxCommandRunner;
    let stdin = vec![b'x'; 1024 * 1024];
    let output = runner
        .output_with_stdin(
            "sh",
            &strings(&["-c", "printf 'setconf rejected' >&2; exit 23"]),
            &stdin,
        )
        .expect("child failure remains a command result even when stdin closes early");

    assert!(!output.success);
    assert_eq!(output.code, Some(23));
    assert_eq!(output.stderr, "setconf rejected");
}

#[test]
fn absent_policy_table_is_empty_but_other_route_errors_are_fatal() {
    let _guard = lock_tests();
    let missing = LinuxCommandOutput {
        success: false,
        code: Some(2),
        stdout: String::new(),
        stderr: "Error: ipv4: FIB table does not exist.\nDump terminated".to_string(),
    };
    assert!(linux_missing_fib_table_error(&missing));
    assert!(!linux_missing_fib_table_error(&LinuxCommandOutput {
        stderr: "RTNETLINK answers: Operation not permitted".to_string(),
        ..missing
    }));

    let mut runner = FakeRunner::existing();
    runner.state.table_routes.clear();
    runner.state.policy_rule_present = false;
    runner.table_missing_when_empty = true;
    let initial = runner.state.clone();
    let runtime = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect("missing dedicated table is initially empty");
    cleanup_linux_wireguard_exit_upstream_with(&mut runner, &runtime).expect("cleanup");
    assert_eq!(runner.state, initial);

    let mut denied = FakeRunner::existing();
    denied.table_error = Some("RTNETLINK answers: Operation not permitted".to_string());
    let error = apply_linux_wireguard_exit_upstream_with(
        &mut denied,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect_err("non-FIB route error must fail");
    assert!(error.to_string().contains("Operation not permitted"));
}

#[test]
fn capture_failure_after_link_creation_removes_link() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.link_exists = false;
    runner.fail_showconf = true;
    let error = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect_err("capture failure");
    assert!(error.to_string().contains("Unable to access interface"));
    assert!(!runner.state.link_exists);
}

#[test]
fn new_interface_cleanup_intent_precedes_link_creation() {
    let _guard = lock_tests();
    let journal_ready = Rc::new(Cell::new(false));
    let mut runner = FakeRunner::existing();
    runner.state.link_exists = false;
    runner.fail_showconf = true;
    runner.link_add_journal_ready = Some(Rc::clone(&journal_ready));
    let mut first_obligation = None;

    let failure = apply_linux_wireguard_exit_upstream_with_journal(
        &mut runner,
        &config(),
        LinuxWireGuardExitApplyContext {
            source_cidr: "10.44.0.0/16",
            mesh_iface: "nvpn0",
            previous_runtime: None,
            previous_default_route_hint: None,
        },
        super::super::resolve_linux_wireguard_exit_endpoint,
        |obligation| {
            first_obligation.get_or_insert_with(|| obligation.clone());
            if matches!(
                obligation,
                LinuxWireGuardExitCleanupObligation::CreatedInterface { interface }
                    if interface == "nvwg0"
            ) {
                journal_ready.set(true);
            }
            Ok(())
        },
    )
    .expect_err("capture fails after the journaled interface creation");

    assert!(failure.to_string().contains("Unable to access interface"));
    assert!(
        journal_ready.get(),
        "link creation never received a cleanup intent"
    );
    assert!(matches!(
        first_obligation,
        Some(LinuxWireGuardExitCleanupObligation::CreatedInterface { ref interface })
            if interface == "nvwg0"
    ));
    assert!(!runner.state.link_exists);
}

#[test]
fn capture_failure_retains_new_interface_until_cleanup_can_finish() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.link_exists = false;
    runner.fail_showconf = true;
    runner.fail_link_delete = true;

    let failure = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect_err("capture and immediate interface cleanup fail");
    let (_, cleanup) = failure.into_parts();
    let mut cleanup = cleanup.expect("new interface cleanup obligation");
    assert!(runner.state.link_exists);

    runner.fail_link_delete = false;
    cleanup_linux_wireguard_exit_obligation_with(&mut runner, &mut cleanup)
        .expect("retained interface cleanup");
    assert!(!runner.state.link_exists);
}

#[test]
fn failed_transaction_retains_exact_rollback_until_retry_succeeds() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    let initial = runner.state.clone();
    runner.fail_route_cache_once = true;
    runner.fail_restore_endpoint = true;

    let failure = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        Some("default via 192.0.2.1 dev eth0 src 192.0.2.10 metric 10"),
    )
    .expect_err("apply and immediate rollback fail");
    let (_, cleanup) = failure.into_parts();
    let mut cleanup = cleanup.expect("exact rollback obligation");

    runner.fail_restore_endpoint = false;
    cleanup_linux_wireguard_exit_obligation_with(&mut runner, &mut cleanup)
        .expect("retained exact rollback");
    assert_eq!(runner.state, initial);
}

#[test]
fn failed_link_creation_never_deletes_an_uncertain_same_name_interface() {
    let _guard = lock_tests();
    let mut runner = FakeRunner::existing();
    runner.state.link_exists = false;
    runner.fail_after_mutation = Some(1);
    let error = apply_linux_wireguard_exit_upstream_with(
        &mut runner,
        &config(),
        "10.44.0.0/16",
        None,
        None,
    )
    .expect_err("unacknowledged link creation");
    assert!(format!("{error:#}").contains("synthetic failure after mutation 1"));
    assert!(
        runner.state.link_exists,
        "a same-name interface observed after a failed add is not proven owned"
    );
}
