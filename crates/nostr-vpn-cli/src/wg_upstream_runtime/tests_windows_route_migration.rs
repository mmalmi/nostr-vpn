#[test]
fn windows_legacy_route_journal_retires_physical_bypasses_but_cleans_tunnel_routes() {
    let serialized = r#"{
        "owned_routes": [
            {
                "prefix": "203.0.113.7/32",
                "interface_index": 11,
                "next_hop": "192.0.2.1",
                "metric": 1
            },
            {
                "prefix": "0.0.0.0/0",
                "interface_index": 77,
                "next_hop": "0.0.0.0",
                "metric": 1
            },
            {
                "prefix": "10.44.0.0/16",
                "interface_index": 77,
                "next_hop": "0.0.0.0",
                "metric": 1
            }
        ]
    }"#;
    let mut cleanup: WindowsRouteCleanupSnapshot =
        serde_json::from_str(serialized).expect("deserialize prior-release cleanup journal");
    assert!(
        cleanup
            .owned_routes
            .iter()
            .all(|route| route.interface_identity.is_none()),
        "the fixture must exercise the schema before stable adapter identities"
    );

    let endpoint = cleanup.owned_routes[0].clone();
    let tunnel_default = cleanup.owned_routes[1].clone();
    let tunnel_subnet = cleanup.owned_routes[2].clone();
    let mut runner = FakeWindowsRouteRunner::default();
    runner.routes.extend([
        endpoint.clone(),
        tunnel_default.clone(),
        tunnel_subnet.clone(),
    ]);

    cleanup
        .retry_with(&mut runner)
        .expect("migrate prior-release cleanup journal");

    assert!(cleanup.is_empty(), "legacy obligations must not brick startup");
    assert!(
        runner.routes.contains(&endpoint),
        "an identity-less route on a shared physical interface is not safe to delete"
    );
    assert!(
        !runner.routes.contains(&tunnel_default),
        "an owned tunnel default must not remain and break device internet"
    );
    assert!(
        !runner.routes.contains(&tunnel_subnet),
        "other exact on-link tunnel routes should be cleaned with the default"
    );
    assert!(
        !runner
            .events
            .iter()
            .any(|event| event == &FakeWindowsRouteEvent::Delete(endpoint.clone())),
        "migration must not issue an unscoped delete for a physical endpoint bypass"
    );
}

#[test]
fn windows_wg_cleanup_preserves_preexisting_exact_routes() {
    let endpoint = "203.0.113.10".parse().expect("endpoint");
    let underlay = windows_underlay(11, "192.0.2.1", "192.0.2.44");
    let bypass = WindowsRouteSpec::endpoint(endpoint, &underlay);
    let default = WindowsRouteSpec::wireguard_default(77);
    let mut runner = FakeWindowsRouteRunner::default();
    let default_v6 = WindowsRouteSpec::wireguard_default_v6(77);
    runner
        .routes
        .extend([bypass.clone(), default.clone(), default_v6.clone()]);

    let mut guard =
        WindowsManagedDefaultRoutes::apply_with(&mut runner, 77, endpoint, underlay, true, true)
            .expect("adopt preexisting exact routes without ownership");
    guard.revert_with(&mut runner).expect("cleanup");
    assert_eq!(
        runner.routes,
        HashSet::from([bypass, default, default_v6]),
        "cleanup must not remove routes it did not create"
    );
    assert!(
        runner
            .events
            .iter()
            .all(|event| !matches!(event, FakeWindowsRouteEvent::Delete(_)))
    );
}
