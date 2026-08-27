#[test]
fn macos_default_routes_from_netstat_finds_underlay_and_utun_routes() {
    let routes = macos_default_routes_from_netstat(
        "Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
default            192.168.64.1       UGScg                 en0\n\
default            link#13            UCSIg               utun5\n\
default            link#26            UCSIg           bridge100      !\n",
    );

    assert_eq!(
        routes,
        vec![
            MacosRouteSpec {
                gateway: Some("192.168.64.1".to_string()),
                interface: "en0".to_string(),
            },
            MacosRouteSpec {
                gateway: None,
                interface: "utun5".to_string(),
            },
            MacosRouteSpec {
                gateway: None,
                interface: "bridge100".to_string(),
            },
        ]
    );

    assert_eq!(
        macos_underlay_default_route_from_routes(&routes),
        Some(MacosRouteSpec {
            gateway: Some("192.168.64.1".to_string()),
            interface: "en0".to_string(),
        })
    );
}

#[test]
fn macos_underlay_selection_prefers_the_snapshot_interface_when_two_are_active() {
    let candidates = vec![
        MacosRouteSpec {
            gateway: Some("192.168.178.1".to_string()),
            interface: "en0".to_string(),
        },
        MacosRouteSpec {
            gateway: Some("10.168.32.48".to_string()),
            interface: "en1".to_string(),
        },
    ];

    assert_eq!(
        macos_underlay_route_from_candidates(&candidates, Some("en1")),
        Some(candidates[1].clone()),
        "the daemon snapshot, not interface enumeration order, owns the selected underlay"
    );
    assert_eq!(
        macos_underlay_route_from_candidates(&candidates, Some("en0")),
        Some(candidates[0].clone())
    );
}

#[test]
fn macos_selected_default_route_uses_kernel_global_route_during_handoff() {
    let route_get = "\
   route to: default
destination: default
       mask: default
    gateway: 10.168.32.48
  interface: en1
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";

    assert_eq!(
        macos_selected_default_route_from_route_get(route_get),
        Some(MacosRouteSpec {
            gateway: Some("10.168.32.48".to_string()),
            interface: "en1".to_string(),
        }),
        "the kernel-selected global default must win even while netstat still lists stale en0 first"
    );
}

#[test]
fn macos_endpoint_bypass_route_args_are_global_host_routes() {
    assert_eq!(
        macos_global_gateway_route_args(
            "add",
            "65.109.48.91/32",
            "192.168.64.1",
            Some("en2"),
        ),
        vec![
            "-n".to_string(),
            "add".to_string(),
            "-host".to_string(),
            "65.109.48.91".to_string(),
            "192.168.64.1".to_string(),
            "-ifp".to_string(),
            "en2".to_string(),
        ]
    );
    assert_eq!(
        macos_gateway_route_args("change", "0.0.0.0/0", "192.168.64.1", None),
        vec![
            "-n".to_string(),
            "change".to_string(),
            "default".to_string(),
            "192.168.64.1".to_string(),
        ]
    );
}

#[test]
fn macos_same_gateway_handoff_changes_only_an_owned_global_route() {
    let current = MacosManagedRoute {
        target: "203.0.113.9/32".to_string(),
        gateway: Some("192.168.64.1".to_string()),
        interface: Some("en2".to_string()),
    };
    let desired = MacosManagedRoute {
        interface: Some("en0".to_string()),
        ..current.clone()
    };
    let owned = "\
Destination        Gateway            Flags               Netif Expire\n\
203.0.113.9       192.168.64.1       UGHS                  en2\n";
    assert_eq!(
        macos_owned_global_gateway_route_transition(owned, &current, &desired),
        MacosOwnedGlobalGatewayRouteTransition::ChangeOwned,
    );

    let foreign = "\
Destination        Gateway            Flags               Netif Expire\n\
203.0.113.9       192.168.64.1       UGHS                  en7\n";
    assert_eq!(
        macos_owned_global_gateway_route_transition(foreign, &current, &desired),
        MacosOwnedGlobalGatewayRouteTransition::MissingOrUnowned,
        "same destination and gateway do not authorize changing a foreign interface",
    );

    let already_moved = owned.replace("en2", "en0");
    assert_eq!(
        macos_owned_global_gateway_route_transition(&already_moved, &current, &desired),
        MacosOwnedGlobalGatewayRouteTransition::AlreadyDesired,
    );
}

#[test]
fn macos_ifconfig_has_ipv4_matches_exact_interface_address() {
    let output = "utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\
\tinet 10.44.10.23 --> 10.44.10.23 netmask 0xffffffff\n\
\tinet6 fe80::1%utun5 prefixlen 64 scopeid 0x8\n";

    assert!(macos_ifconfig_has_ipv4(
        output,
        Ipv4Addr::new(10, 44, 10, 23)
    ));
    assert!(!macos_ifconfig_has_ipv4(
        output,
        Ipv4Addr::new(10, 44, 10, 24)
    ));
}

#[test]
fn split_default_cleanup_only_claims_the_route_owner() {
    let routes = "\
Routing tables\n\
Internet:\n\
Destination        Gateway            Flags               Netif Expire\n\
0/1                utun6              USc                 utun6       1161\n\
1.0.0.1            192.168.64.9       UGHS                  en9\n\
128.0/1            utun7              USc                 utun7\n\
default            192.168.64.1       UGScg                 en0\n";
    assert_eq!(
        macos_split_default_route_owners_from_netstat(routes, "0.0.0.0/1"),
        vec!["utun6".to_string()]
    );
    assert_eq!(
        macos_split_default_route_owners_from_netstat(routes, "128.0.0.0/1"),
        vec!["utun7".to_string()]
    );
    assert!(macos_split_default_route_owners_from_netstat(routes, "0.0.0.0/0").is_empty());
}

#[test]
fn managed_route_ownership_requires_exact_gateway_and_interface() {
    let routes = "\
Destination        Gateway            Flags               Netif Expire\n\
65.109.48.91       192.168.64.1       UGHS                  en0       1161\n\
65.109.48.92       10.0.0.1           UGHS                  en1\n\
65.109.48.93       192.168.64.1       UGHS                  en1\n\
0/1                utun6              USc                 utun6\n";
    assert!(macos_managed_route_present(
        routes,
        "65.109.48.91/32",
        Some("192.168.64.1"),
        Some("en0"),
    ));
    assert!(!macos_managed_route_present(
        routes,
        "65.109.48.91/32",
        Some("10.0.0.1"),
        Some("en0"),
    ));
    assert!(!macos_managed_route_present(
        routes,
        "65.109.48.91/32",
        Some("192.168.64.1"),
        Some("en1"),
    ));
    assert!(!macos_managed_route_present(
        routes,
        "65.109.48.93/32",
        Some("192.168.64.1"),
        Some("en2"),
    ));
    assert!(macos_managed_route_present(
        routes,
        "0.0.0.0/1",
        None,
        Some("utun6"),
    ));
    assert!(!macos_managed_route_present(
        routes,
        "0.0.0.0/1",
        None,
        Some("utun7"),
    ));
    assert!(
        !macos_managed_route_present(routes, "65.109.48.91/32", None, None),
        "cleanup without an owner must fail closed"
    );
}

#[test]
fn managed_route_set_detects_a_bypass_removed_during_default_route_update() {
    let owner = MacosRouteSpec {
        gateway: Some("192.168.64.1".to_string()),
        interface: "en0".to_string(),
    };
    let desired = vec![
        "65.109.48.91/32".to_string(),
        "65.109.48.92/32".to_string(),
    ];
    let complete = "\
Destination        Gateway            Flags               Netif Expire\n\
65.109.48.91       192.168.64.1       UGHS                  en0\n\
65.109.48.92       192.168.64.1       UGHS                  en0\n\
0/1                utun6              USc                 utun6\n";
    let missing_one = "\
Destination        Gateway            Flags               Netif Expire\n\
65.109.48.91       192.168.64.1       UGHS                  en0\n\
0/1                utun6              USc                 utun6\n";

    assert!(macos_global_managed_routes_present(
        complete, &desired, &owner
    ));
    assert!(!macos_global_managed_routes_present(
        missing_one,
        &desired,
        &owner,
    ));

    let scoped = "\
Destination        Gateway            Flags               Netif Expire\n\
65.109.48.91       192.168.64.1       UGHSI                 en0\n\
65.109.48.92       192.168.64.1       UGHSI                 en0\n\
0/1                utun6              USc                 utun6\n";
    assert!(macos_managed_route_present(
        scoped,
        "65.109.48.91/32",
        owner.gateway.as_deref(),
        Some(owner.interface.as_str()),
    ));
    assert!(
        !macos_global_managed_routes_present(scoped, &desired, &owner),
        "interface-scoped bypasses do not protect global transport sockets"
    );
}

#[test]
fn direct_transition_repairs_only_a_missing_physical_default() {
    let tunnel_only = vec![MacosRouteSpec {
        gateway: None,
        interface: "utun5".to_string(),
    }];
    assert!(macos_underlay_default_route_needs_restore(&tunnel_only));

    let physical_and_tunnel = vec![
        MacosRouteSpec {
            gateway: Some("192.168.64.1".to_string()),
            interface: "en0".to_string(),
        },
        MacosRouteSpec {
            gateway: None,
            interface: "utun5".to_string(),
        },
    ];
    assert!(!macos_underlay_default_route_needs_restore(
        &physical_and_tunnel
    ));
}

#[test]
fn underlay_restore_adds_without_changing_a_foreign_default() {
    assert_eq!(
        macos_add_underlay_default_route_args("192.168.64.1"),
        vec!["-n", "add", "default", "192.168.64.1"]
    );
}
