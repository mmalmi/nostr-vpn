use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeWindowsRouteEvent {
    Exists(WindowsRouteSpec),
    Add(WindowsRouteSpec),
    Set(WindowsRouteSpec),
    Delete(WindowsRouteSpec),
}

#[derive(Default)]
struct FakeWindowsRouteRunner {
    routes: HashSet<WindowsRouteSpec>,
    events: Vec<FakeWindowsRouteEvent>,
    fail_add: Option<WindowsRouteSpec>,
    fail_delete: Option<WindowsRouteSpec>,
    fail_deletes: HashSet<WindowsRouteSpec>,
    reject_interface_identity: bool,
}

impl WindowsRouteCommandRunner for FakeWindowsRouteRunner {
    fn route_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool> {
        self.events
            .push(FakeWindowsRouteEvent::Exists(route.clone()));
        Ok(self.routes.contains(route))
    }

    fn route_identity_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool> {
        self.events
            .push(FakeWindowsRouteEvent::Exists(route.clone()));
        Ok(self.routes.iter().any(|candidate| {
            candidate.prefix == route.prefix
                && candidate.interface_index == route.interface_index
                && candidate.next_hop == route.next_hop
        }))
    }

    fn verify_interface_identity(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        if self.reject_interface_identity {
            return Err(anyhow!(
                "interface {} stable identity no longer matches",
                route.interface_index
            ));
        }
        Ok(())
    }

    fn add_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.events.push(FakeWindowsRouteEvent::Add(route.clone()));
        if self.fail_add.as_ref() == Some(route) {
            return Err(anyhow!("injected add failure for {route:?}"));
        }
        if !self.routes.insert(route.clone()) {
            return Err(anyhow!("route already exists: {route:?}"));
        }
        Ok(())
    }

    fn set_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.events.push(FakeWindowsRouteEvent::Set(route.clone()));
        let existing = self.routes.iter().find(|candidate| {
            candidate.prefix == route.prefix
                && candidate.interface_index == route.interface_index
                && candidate.next_hop == route.next_hop
        });
        let existing = existing
            .cloned()
            .ok_or_else(|| anyhow!("route identity does not exist for set: {route:?}"))?;
        self.routes.remove(&existing);
        self.routes.insert(route.clone());
        Ok(())
    }

    fn delete_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.events
            .push(FakeWindowsRouteEvent::Delete(route.clone()));
        if self.fail_delete.as_ref() == Some(route) || self.fail_deletes.contains(route) {
            return Err(anyhow!("injected delete failure for {route:?}"));
        }
        let existing = self
            .routes
            .iter()
            .find(|candidate| {
                candidate.prefix == route.prefix
                    && candidate.interface_index == route.interface_index
                    && candidate.next_hop == route.next_hop
            })
            .cloned()
            .ok_or_else(|| anyhow!("route does not exist: {route:?}"))?;
        self.routes.remove(&existing);
        Ok(())
    }
}

fn windows_underlay(interface_index: u32, gateway: &str, address: &str) -> WindowsDefaultRoute {
    WindowsDefaultRoute {
        gateway: gateway.to_string(),
        interface_index,
        interface_ipv4: address.parse().expect("underlay address"),
    }
}

#[test]
fn windows_wg_underlay_refresh_installs_fresh_bypass_before_removing_stale() {
    let endpoint = "203.0.113.7".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let foreign = WindowsRouteSpec {
        prefix: "198.18.0.0/15".to_string(),
        interface_index: 31,
        next_hop: "198.51.100.254".to_string(),
        metric: 9,
        interface_identity: None,
    };
    let mut runner = FakeWindowsRouteRunner::default();
    runner.routes.insert(foreign.clone());
    let mut guard = WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        77,
        endpoint,
        old_underlay.clone(),
        true,
        true,
    )
    .expect("initial routes");
    runner.events.clear();

    assert!(
        guard
            .refresh_with(&mut runner, fresh_underlay.clone(), &[88])
            .expect("underlay refresh")
    );
    let fresh_bypass = WindowsRouteSpec::endpoint(endpoint, &fresh_underlay);
    let stale_bypass = WindowsRouteSpec::endpoint(endpoint, &old_underlay);
    let add_index = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(fresh_bypass.clone()))
        .expect("fresh bypass add");
    let delete_index = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Delete(stale_bypass.clone()))
        .expect("stale bypass delete");
    let stale_audit_index = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Exists(stale_bypass.clone()))
        .expect("stale bypass audit");
    let default_audit_index = runner
        .events
        .iter()
        .position(|event| {
            event == &FakeWindowsRouteEvent::Exists(WindowsRouteSpec::wireguard_default(77))
        })
        .expect("WireGuard default audit");
    assert!(
        add_index < delete_index,
        "fresh physical bypass must exist before stale bypass removal"
    );
    assert!(
        add_index < stale_audit_index && add_index < default_audit_index,
        "handoff must make the fresh physical bypass usable before auditing old/default routes"
    );
    assert!(runner.routes.contains(&fresh_bypass));
    assert!(!runner.routes.contains(&stale_bypass));
    assert!(
        runner
            .routes
            .contains(&WindowsRouteSpec::wireguard_default(77))
    );

    assert!(
        runner
            .routes
            .contains(&WindowsRouteSpec::wireguard_default_v6(77))
    );

    guard.revert_with(&mut runner).expect("cleanup");
    assert_eq!(runner.routes, HashSet::from([foreign]));
}

#[test]
fn windows_wg_underlay_refresh_repairs_default_after_fresh_bypass() {
    let endpoint = "203.0.113.8".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let fresh_bypass = WindowsRouteSpec::endpoint(endpoint, &fresh_underlay);
    let default = WindowsRouteSpec::wireguard_default(77);
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        77,
        endpoint,
        old_underlay,
        true,
        true,
    )
    .expect("initial routes");
    runner.routes.remove(&default);
    let default_v6 = WindowsRouteSpec::wireguard_default_v6(77);
    runner.routes.remove(&default_v6);
    runner.events.clear();

    guard
        .refresh_with(&mut runner, fresh_underlay, &[88])
        .expect("underlay refresh");

    let fresh_add = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(fresh_bypass.clone()))
        .expect("fresh bypass add");
    let default_add = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(default.clone()))
        .expect("default route repair");
    assert!(fresh_add < default_add);
    assert!(runner.routes.contains(&default));
    let default_v6_add = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(default_v6.clone()))
        .expect("IPv6 default route repair");
    assert!(fresh_add < default_v6_add);
    assert!(runner.routes.contains(&default_v6));
}

#[test]
fn windows_wg_endpoint_roam_installs_fresh_target_before_removing_stale() {
    let old_endpoint = "203.0.113.60".parse().expect("endpoint");
    let fresh_endpoint = "203.0.113.61".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        77,
        old_endpoint,
        underlay.clone(),
        false,
        false,
    )
    .expect("initial endpoint route");
    runner.events.clear();

    assert!(
        guard
            .reconcile_with(&mut runner, fresh_endpoint, underlay.clone(), &[88])
            .expect("endpoint roam")
    );
    let stale = WindowsRouteSpec::endpoint(old_endpoint, &underlay);
    let fresh = WindowsRouteSpec::endpoint(fresh_endpoint, &underlay);
    let add = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(fresh.clone()))
        .expect("fresh target add");
    let delete = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Delete(stale.clone()))
        .expect("stale target delete");
    assert!(add < delete);
    assert_eq!(guard.bypass_target, fresh_endpoint);

    guard.revert_with(&mut runner).expect("cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_wg_underlay_refresh_rolls_back_exactly_when_stale_removal_fails() {
    let endpoint = "203.0.113.8".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        77,
        endpoint,
        old_underlay.clone(),
        true,
        false,
    )
    .expect("initial routes");
    let before = runner.routes.clone();
    runner.fail_delete = Some(WindowsRouteSpec::endpoint(endpoint, &old_underlay));

    let error = guard
        .refresh_with(&mut runner, fresh_underlay, &[88])
        .expect_err("stale removal failure must abort refresh");
    assert!(
        error
            .to_string()
            .contains("remove stale WireGuard endpoint bypass route")
    );
    assert_eq!(
        runner.routes, before,
        "failed refresh must restore exact state"
    );
    assert_eq!(guard.underlay, old_underlay);
}

#[test]
fn windows_wg_underlay_refresh_retains_failed_rollback_for_later_cleanup() {
    let endpoint = "203.0.113.9".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let stale = WindowsRouteSpec::endpoint(endpoint, &old_underlay);
    let fresh = WindowsRouteSpec::endpoint(endpoint, &fresh_underlay);
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard =
        WindowsManagedDefaultRoutes::apply_with(&mut runner, 77, endpoint, old_underlay, true, false)
            .expect("initial routes");
    runner.fail_deletes.extend([stale, fresh.clone()]);

    guard
        .refresh_with(&mut runner, fresh_underlay, &[88])
        .expect_err("both stale removal and fresh rollback fail");
    assert!(runner.routes.contains(&fresh));
    assert_eq!(guard.orphaned_bypass_routes, vec![fresh]);

    runner.fail_deletes.clear();
    guard
        .revert_with(&mut runner)
        .expect("retained residual cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_fips_endpoint_routes_migrate_fresh_before_stale_and_preserve_unowned() {
    let endpoint_a = "203.0.113.20".parse().expect("endpoint");
    let endpoint_b = "203.0.113.21".parse().expect("endpoint");
    let endpoint_c = "203.0.113.22".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let old_unowned = WindowsRouteSpec::endpoint(endpoint_b, &old_underlay);
    let fresh_unowned = WindowsRouteSpec::endpoint(endpoint_c, &fresh_underlay);
    let foreign = WindowsRouteSpec {
        prefix: "198.18.0.0/15".to_string(),
        interface_index: 31,
        next_hop: "198.51.100.254".to_string(),
        metric: 9,
        interface_identity: None,
    };
    let mut runner = FakeWindowsRouteRunner::default();
    runner
        .routes
        .extend([old_unowned.clone(), fresh_unowned.clone(), foreign.clone()]);
    let mut guard = WindowsManagedEndpointRoutes::apply_with(
        &mut runner,
        &[endpoint_a, endpoint_b],
        old_underlay.clone(),
        &[77, 88],
    )
    .expect("initial FIPS endpoint bypasses");
    runner.events.clear();

    assert!(
        guard
            .reconcile_with(
                &mut runner,
                &[endpoint_b, endpoint_c],
                fresh_underlay.clone(),
                &[77, 88],
            )
            .expect("migrate FIPS endpoint bypasses")
    );

    let fresh_owned = WindowsRouteSpec::endpoint(endpoint_b, &fresh_underlay);
    let stale_owned = WindowsRouteSpec::endpoint(endpoint_a, &old_underlay);
    let fresh_add = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Add(fresh_owned.clone()))
        .expect("fresh owned bypass add");
    let stale_delete = runner
        .events
        .iter()
        .position(|event| event == &FakeWindowsRouteEvent::Delete(stale_owned.clone()))
        .expect("stale owned bypass delete");
    assert!(
        fresh_add < stale_delete,
        "every fresh endpoint bypass must be ready before stale owned cleanup"
    );
    assert!(runner.routes.contains(&old_unowned));
    assert!(runner.routes.contains(&fresh_unowned));
    assert!(runner.routes.contains(&fresh_owned));
    assert!(!runner.routes.contains(&stale_owned));

    guard.revert_with(&mut runner).expect("cleanup");
    assert_eq!(
        runner.routes,
        HashSet::from([old_unowned, fresh_unowned, foreign]),
        "cleanup must remove only exact routes created by this guard"
    );
}

#[test]
fn windows_fips_endpoint_migration_restores_old_owned_set_on_stale_failure() {
    let endpoint_a = "203.0.113.30".parse().expect("endpoint");
    let endpoint_b = "203.0.113.31".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedEndpointRoutes::apply_with(
        &mut runner,
        &[endpoint_a, endpoint_b],
        old_underlay.clone(),
        &[77, 88],
    )
    .expect("initial FIPS endpoint bypasses");
    let before = runner.routes.clone();
    runner.fail_delete = Some(WindowsRouteSpec::endpoint(endpoint_b, &old_underlay));

    let error = guard
        .reconcile_with(
            &mut runner,
            &[endpoint_a, endpoint_b],
            fresh_underlay,
            &[77, 88],
        )
        .expect_err("stale cleanup failure must roll back migration");
    assert!(
        error
            .to_string()
            .contains("remove stale FIPS endpoint bypass route")
    );
    assert_eq!(
        runner.routes, before,
        "failed migration must restore every old owned route and remove fresh owned routes"
    );
    assert_eq!(guard.underlay, old_underlay);
}

#[test]
fn windows_fips_endpoint_migration_retains_failed_compensation_for_cleanup() {
    let endpoint_a = "203.0.113.32".parse().expect("endpoint");
    let endpoint_b = "203.0.113.33".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let fresh_underlay = windows_underlay(22, "198.51.100.1", "198.51.100.77");
    let stale_b = WindowsRouteSpec::endpoint(endpoint_b, &old_underlay);
    let fresh_a = WindowsRouteSpec::endpoint(endpoint_a, &fresh_underlay);
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedEndpointRoutes::apply_with(
        &mut runner,
        &[endpoint_a, endpoint_b],
        old_underlay,
        &[77, 88],
    )
    .expect("initial FIPS endpoint bypasses");
    runner
        .fail_deletes
        .extend([stale_b.clone(), fresh_a.clone()]);

    guard
        .reconcile_with(
            &mut runner,
            &[endpoint_a, endpoint_b],
            fresh_underlay,
            &[77, 88],
        )
        .expect_err("stale cleanup and fresh rollback both fail");
    assert!(runner.routes.contains(&fresh_a));
    assert!(
        guard
            .routes
            .routes
            .iter()
            .any(|route| route.spec == fresh_a && route.owned)
    );

    runner.fail_deletes.clear();
    guard
        .revert_with(&mut runner)
        .expect("retained endpoint cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_fips_endpoint_routes_reject_both_tunnel_interfaces() {
    let endpoint = "203.0.113.40".parse().expect("endpoint");
    let underlay = windows_underlay(88, "192.0.2.1", "192.0.2.44");
    let mut runner = FakeWindowsRouteRunner::default();

    WindowsManagedEndpointRoutes::apply_with(&mut runner, &[endpoint], underlay, &[77, 88])
        .expect_err("WireGuard and FIPS interfaces must both be excluded");
    assert!(runner.events.is_empty());
}

#[test]
fn windows_fips_tunnel_routes_preserve_preexisting_exact_routes() {
    let preexisting = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("preexisting route spec");
    let owned = WindowsRouteSpec::direct("0.0.0.0/0", 77).expect("owned route spec");
    let mut runner = FakeWindowsRouteRunner::default();
    runner.routes.insert(preexisting.clone());

    let mut guard = WindowsManagedInterfaceRoutes::apply_with(
        &mut runner,
        77,
        &["10.44.0.0/16".to_string(), "0.0.0.0/0".to_string()],
    )
    .expect("apply FIPS tunnel routes");
    assert!(runner.routes.contains(&preexisting));
    assert!(runner.routes.contains(&owned));

    guard.revert_with(&mut runner).expect("cleanup");
    assert_eq!(
        runner.routes,
        HashSet::from([preexisting]),
        "cleanup must remove only the exact FIPS route created by this guard"
    );
}

#[test]
fn windows_fips_tunnel_route_reconcile_rolls_back_on_stale_cleanup_failure() {
    let old_a = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("old route spec");
    let old_b = WindowsRouteSpec::direct("10.45.0.0/16", 77).expect("old route spec");
    let fresh = WindowsRouteSpec::direct("0.0.0.0/0", 77).expect("fresh route spec");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedInterfaceRoutes::apply_with(
        &mut runner,
        77,
        &["10.44.0.0/16".to_string(), "10.45.0.0/16".to_string()],
    )
    .expect("initial FIPS tunnel routes");
    let before = runner.routes.clone();
    runner.fail_delete = Some(old_b.clone());

    let error = guard
        .reconcile_with(&mut runner, &["0.0.0.0/0".to_string()])
        .expect_err("stale FIPS route cleanup failure must abort");
    assert!(error.to_string().contains("remove stale FIPS tunnel route"));
    assert_eq!(
        runner.routes, before,
        "fresh route must be rolled back and already-removed stale routes restored"
    );
    assert!(runner.routes.contains(&old_a));
    assert!(runner.routes.contains(&old_b));
    assert!(!runner.routes.contains(&fresh));
}

#[test]
fn windows_fips_tunnel_reconcile_retains_failed_compensation_for_cleanup() {
    let old_a = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("old route spec");
    let old_b = WindowsRouteSpec::direct("10.45.0.0/16", 77).expect("old route spec");
    let fresh = WindowsRouteSpec::direct("0.0.0.0/0", 77).expect("fresh route spec");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedInterfaceRoutes::apply_with(
        &mut runner,
        77,
        &["10.44.0.0/16".to_string(), "10.45.0.0/16".to_string()],
    )
    .expect("initial FIPS tunnel routes");
    runner.fail_deletes.extend([old_b.clone(), fresh.clone()]);

    guard
        .reconcile_with(&mut runner, &["0.0.0.0/0".to_string()])
        .expect_err("stale cleanup and fresh rollback both fail");
    assert!(runner.routes.contains(&fresh));
    assert!(
        guard
            .routes
            .routes
            .iter()
            .any(|route| route.spec == fresh && route.owned)
    );

    runner.fail_deletes.clear();
    guard
        .revert_with(&mut runner)
        .expect("retained interface cleanup");
    assert!(runner.routes.is_empty());
    assert!(
        runner
            .events
            .iter()
            .any(|event| event == &FakeWindowsRouteEvent::Delete(old_a.clone()))
    );
}

#[test]
fn windows_route_reconcile_repairs_a_missing_owned_route() {
    let route = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("managed route");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard =
        WindowsManagedInterfaceRoutes::apply_with(&mut runner, 77, &["10.44.0.0/16".to_string()])
            .expect("initial route");
    runner.routes.remove(&route);

    assert!(
        guard
            .reconcile_with(&mut runner, &["10.44.0.0/16".to_string()])
            .expect("repair route")
    );
    assert!(runner.routes.contains(&route));
    guard.revert_with(&mut runner).expect("cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_owned_route_metric_drift_is_repaired_and_cleaned_by_identity() {
    let route = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("managed route");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard =
        WindowsManagedInterfaceRoutes::apply_with(&mut runner, 77, &["10.44.0.0/16".to_string()])
            .expect("initial route");
    let mut drifted = route.clone();
    drifted.metric = 99;
    runner.routes.remove(&route);
    runner.routes.insert(drifted);
    runner.events.clear();

    assert!(
        guard
            .reconcile_with(&mut runner, &["10.44.0.0/16".to_string()])
            .expect("repair owned metric drift")
    );
    assert!(runner.routes.contains(&route));
    assert!(
        runner
            .events
            .contains(&FakeWindowsRouteEvent::Set(route.clone()))
    );

    let mut drifted_again = route.clone();
    drifted_again.metric = 77;
    runner.routes.remove(&route);
    runner.routes.insert(drifted_again);
    guard
        .revert_with(&mut runner)
        .expect("identity-scoped cleanup after drift");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_wg_same_gateway_address_change_retains_owned_bypass() {
    let endpoint = "203.0.113.12".parse().expect("endpoint");
    let old_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let renewed_underlay = windows_underlay(11, "192.0.2.1", "192.0.2.99");
    let mut runner = FakeWindowsRouteRunner::default();
    let mut guard = WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        77,
        endpoint,
        old_underlay,
        true,
        true,
    )
    .expect("initial routes");
    let routes_before = runner.routes.clone();
    runner.events.clear();

    assert!(
        guard
            .refresh_with(&mut runner, renewed_underlay.clone(), &[88])
            .expect("address-only refresh")
    );
    assert_eq!(runner.routes, routes_before);
    assert!(
        runner
            .events
            .iter()
            .all(|event| matches!(event, FakeWindowsRouteEvent::Exists(_))),
        "address-only refresh should audit but not mutate exact routes"
    );
    assert!(guard.bypass_owned);
    assert_eq!(guard.underlay, renewed_underlay);

    let default_v6 = WindowsRouteSpec::wireguard_default_v6(77);
    runner.routes.remove(&default_v6);
    guard
        .reconcile_with(&mut runner, endpoint, renewed_underlay, &[88])
        .expect("repair missing IPv6 route on the unchanged underlay");
    assert_eq!(runner.routes, routes_before);
    assert!(guard.default_v6_owned);
}

#[test]
fn windows_wg_apply_rolls_back_routes_when_either_default_install_fails() {
    let endpoint = "203.0.113.9".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let foreign = WindowsRouteSpec {
        prefix: "10.0.0.0/8".to_string(),
        interface_index: 5,
        next_hop: "192.0.2.254".to_string(),
        metric: 3,
        interface_identity: None,
    };
    for failed_default in [
        WindowsRouteSpec::wireguard_default(77),
        WindowsRouteSpec::wireguard_default_v6(77),
    ] {
        let mut runner = FakeWindowsRouteRunner::default();
        runner.routes.insert(foreign.clone());
        runner.fail_add = Some(failed_default);

        let failure = WindowsManagedDefaultRoutes::apply_with(
            &mut runner,
            77,
            endpoint,
            underlay.clone(),
            true,
            true,
        )
        .expect_err("either default failure must abort apply");
        assert!(failure.cleanup.cleanup_snapshot().is_empty());
        assert_eq!(
            runner.routes,
            HashSet::from([foreign.clone()]),
            "failed IPv6 installation must remove both the owned IPv4 default and bypass"
        );
    }
}

#[test]
fn windows_wg_apply_retains_bypass_when_constructor_rollback_fails() {
    let endpoint = "203.0.113.13".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let bypass = WindowsRouteSpec::endpoint(endpoint, &underlay);
    let mut runner = FakeWindowsRouteRunner {
        fail_add: Some(WindowsRouteSpec::wireguard_default(77)),
        fail_delete: Some(bypass.clone()),
        ..Default::default()
    };

    let mut failure =
        WindowsManagedDefaultRoutes::apply_with(&mut runner, 77, endpoint, underlay, true, false)
            .expect_err("default add and bypass rollback fail");
    assert!(runner.routes.contains(&bypass));
    assert!(failure.cleanup.bypass_owned);

    runner.fail_add = None;
    runner.fail_delete = None;
    failure
        .cleanup
        .revert_with(&mut runner)
        .expect("retained constructor cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_endpoint_constructor_retains_failed_rollback() {
    let endpoint_a = "203.0.113.50".parse().expect("endpoint");
    let endpoint_b = "203.0.113.51".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let route_a = WindowsRouteSpec::endpoint(endpoint_a, &underlay);
    let route_b = WindowsRouteSpec::endpoint(endpoint_b, &underlay);
    let mut runner = FakeWindowsRouteRunner {
        fail_add: Some(route_b),
        fail_delete: Some(route_a.clone()),
        ..Default::default()
    };

    let mut failure = WindowsManagedEndpointRoutes::apply_with(
        &mut runner,
        &[endpoint_a, endpoint_b],
        underlay,
        &[77, 88],
    )
    .expect_err("second add and first rollback fail");
    assert!(runner.routes.contains(&route_a));

    runner.fail_add = None;
    runner.fail_delete = None;
    failure
        .cleanup
        .revert_with(&mut runner)
        .expect("retained endpoint constructor cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_interface_constructor_retains_failed_rollback() {
    let route_a = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("route A");
    let route_b = WindowsRouteSpec::direct("10.45.0.0/16", 77).expect("route B");
    let mut runner = FakeWindowsRouteRunner {
        fail_add: Some(route_b),
        fail_delete: Some(route_a.clone()),
        ..Default::default()
    };

    let mut failure = WindowsManagedInterfaceRoutes::apply_with(
        &mut runner,
        77,
        &["10.44.0.0/16".to_string(), "10.45.0.0/16".to_string()],
    )
    .expect_err("second add and first rollback fail");
    assert!(runner.routes.contains(&route_a));

    runner.fail_add = None;
    runner.fail_delete = None;
    failure
        .cleanup
        .revert_with(&mut runner)
        .expect("retained interface constructor cleanup");
    assert!(runner.routes.is_empty());
}

#[test]
fn windows_failed_active_guard_cleanup_is_snapshotted_and_retried_by_owned_identity() {
    let _registry = windows_pending_cleanup_registry_guard();
    let prior_pending = take_pending_windows_route_cleanup();
    assert!(
        prior_pending.is_empty(),
        "fake-runner cleanup test requires an empty pending registry"
    );

    let preexisting = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("preexisting route");
    let owned = WindowsRouteSpec::direct("10.45.0.0/16", 77).expect("owned route");
    let foreign_same_prefix = WindowsRouteSpec {
        prefix: owned.prefix.clone(),
        interface_index: 88,
        next_hop: "0.0.0.0".to_string(),
        metric: owned.metric,
        interface_identity: None,
    };
    let mut runner = FakeWindowsRouteRunner::default();
    runner
        .routes
        .extend([preexisting.clone(), foreign_same_prefix.clone()]);
    let mut guard = WindowsManagedInterfaceRoutes::apply_with(
        &mut runner,
        77,
        &["10.44.0.0/16".to_string(), "10.45.0.0/16".to_string()],
    )
    .expect("active route guard");
    assert_eq!(
        guard.routes.cleanup_snapshot().owned_routes,
        vec![owned.clone()],
        "live snapshots must exclude exact preexisting routes without disarming the guard"
    );
    runner.fail_delete = Some(owned.clone());

    guard
        .routes
        .revert_retaining_pending_with(&mut runner)
        .expect_err("active guard cleanup failure must be retained");
    let pending = take_pending_windows_route_cleanup();
    assert_eq!(pending.owned_routes, vec![owned.clone()]);

    let encoded = serde_json::to_string(&pending).expect("serialize cleanup snapshot");
    let mut replayed: WindowsRouteCleanupSnapshot =
        serde_json::from_str(&encoded).expect("deserialize cleanup snapshot");
    runner.fail_delete = None;
    replayed
        .retry_with(&mut runner)
        .expect("retry retained active cleanup");

    assert!(replayed.is_empty());
    assert_eq!(
        runner.routes,
        HashSet::from([preexisting, foreign_same_prefix]),
        "replay must delete only the exact route identity owned by the guard"
    );

    let endpoint = "203.0.113.70".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let owned_default = WindowsRouteSpec::wireguard_default_v6(77);
    let foreign_default = WindowsRouteSpec {
        prefix: owned_default.prefix.clone(),
        interface_index: 88,
        next_hop: "::".to_string(),
        metric: owned_default.metric,
        interface_identity: None,
    };
    let mut default_runner = FakeWindowsRouteRunner::default();
    default_runner.routes.insert(foreign_default.clone());
    let mut default_guard = WindowsManagedDefaultRoutes::apply_with(
        &mut default_runner,
        77,
        endpoint,
        underlay,
        true,
        true,
    )
    .expect("active full-default guard");
    let bypass = WindowsRouteSpec::endpoint(endpoint, &default_guard.underlay);
    assert_eq!(
        default_guard
            .cleanup_snapshot()
            .owned_routes
            .into_iter()
            .collect::<HashSet<_>>(),
        HashSet::from([
            WindowsRouteSpec::wireguard_default(77),
            owned_default.clone(),
            bypass
        ]),
        "full-default live snapshots must capture every exact owned route"
    );
    default_runner.fail_delete = Some(owned_default.clone());

    default_guard
        .revert_retaining_pending_with(&mut default_runner)
        .expect_err("full-default cleanup failure must be retained");
    let mut default_pending = take_pending_windows_route_cleanup();
    assert_eq!(default_pending.owned_routes, vec![owned_default]);

    default_runner.fail_delete = None;
    default_pending
        .retry_with(&mut default_runner)
        .expect("retry retained full-default cleanup");
    assert_eq!(default_runner.routes, HashSet::from([foreign_default]));
}

#[test]
fn windows_cleanup_refuses_route_on_reused_interface_index() {
    let mut route = WindowsRouteSpec::direct("10.44.0.0/16", 77).expect("owned route");
    route.interface_identity = Some("{original-tunnel-adapter}".to_string());
    let mut runner = FakeWindowsRouteRunner {
        routes: HashSet::from([route.clone()]),
        reject_interface_identity: true,
        ..Default::default()
    };
    let mut cleanup = WindowsRouteCleanupSnapshot::from_owned_routes(vec![route.clone()]);

    let error = cleanup
        .retry_with(&mut runner)
        .expect_err("a recycled interface index must fail closed");
    assert!(error.to_string().contains("stable identity"));
    assert!(runner.routes.contains(&route));
    assert!(
        runner
            .events
            .iter()
            .all(|event| !matches!(event, FakeWindowsRouteEvent::Delete(_))),
        "identity mismatch must be detected before any delete command"
    );
    assert_eq!(cleanup.owned_routes, vec![route]);
}

include!("tests_windows_route_migration.rs");

include!("tests_windows_route_delete.rs");
