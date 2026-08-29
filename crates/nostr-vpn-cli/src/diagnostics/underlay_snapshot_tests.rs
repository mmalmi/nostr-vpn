use super::*;

#[test]
fn snapshot_change_detection_uses_fingerprint() {
    let left = NetworkSnapshot {
        default_interface: Some("en0".to_string()),
        primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
        ..NetworkSnapshot::default()
    };
    let right = NetworkSnapshot {
        default_interface: Some("en1".to_string()),
        ..left.clone()
    };
    assert!(right.changed_since(&left));
}

#[test]
fn empty_snapshot_does_not_replace_known_underlay() {
    let previous = NetworkSnapshot {
        default_interface: Some("en0".to_string()),
        primary_ipv4: Some(Ipv4Addr::new(192, 168, 64, 2)),
        gateway_ipv4: Some(Ipv4Addr::new(192, 168, 64, 1)),
        ..NetworkSnapshot::default()
    };
    assert_eq!(
        prefer_nonempty_network_snapshot(&previous, NetworkSnapshot::default()),
        previous
    );
}

#[test]
fn linux_underlay_selection_ignores_admin_up_route_after_carrier_loss() {
    let routes = vec![
        LinuxIpv4DefaultRoute {
            interface: "nvut42".to_string(),
            gateway: Ipv4Addr::UNSPECIFIED,
            source: None,
            metric: 0,
            on_link: false,
        },
        LinuxIpv4DefaultRoute {
            interface: "enp1s0".to_string(),
            gateway: Ipv4Addr::new(192, 168, 122, 1),
            source: Some(Ipv4Addr::new(192, 168, 122, 147)),
            metric: 100,
            on_link: false,
        },
        LinuxIpv4DefaultRoute {
            interface: "enp7s0".to_string(),
            gateway: Ipv4Addr::new(172, 31, 254, 1),
            source: Some(Ipv4Addr::new(172, 31, 254, 2)),
            metric: 600,
            on_link: false,
        },
    ];
    let selected = select_linux_underlay_default_route(
        &routes,
        |route| route.interface.as_str(),
        |route| route.metric,
        &["nvut42"],
        |route| route.interface == "enp7s0",
    )
    .expect("active replacement physical route");
    assert_eq!(selected.interface, "enp7s0");
}

#[test]
fn linux_returning_link_accepts_route_before_operstate_settles() {
    let mut interface = netdev::Interface::dummy();
    interface.name = "enp1s0".to_string();
    interface.flags = netdev::interface::flags::IFF_UP as u32;
    interface.oper_state = netdev::interface::state::OperState::Dormant;
    interface.ipv4 = vec!["192.168.122.103/24".parse().expect("current address")];

    assert!(linux_interface_state_usable(&interface, true, false));
    assert!(!linux_interface_state_usable(&interface, false, false));
}

#[test]
fn linux_underlay_selection_uses_cached_defaults_when_exit_owns_main_default() {
    let live_routes = vec![
        LinuxIpv4DefaultRoute {
            interface: "nvwg0".to_string(),
            gateway: Ipv4Addr::UNSPECIFIED,
            source: None,
            metric: 0,
            on_link: false,
        },
        LinuxIpv4DefaultRoute {
            interface: "enp7s0".to_string(),
            gateway: Ipv4Addr::new(172, 31, 254, 9),
            source: Some(Ipv4Addr::new(172, 31, 254, 9)),
            metric: 600,
            on_link: false,
        },
    ];
    let cached_routes = parse_linux_ipv4_default_route_hints(&[
        "default via 192.168.122.1 dev enp1s0 src 192.168.122.147 metric 100".to_string(),
        "default via 172.31.254.1 dev enp7s0 src 172.31.254.2 metric 600".to_string(),
    ]);
    let merged = merge_linux_ipv4_default_routes(&live_routes, &cached_routes);
    let selected = select_linux_underlay_default_route(
        &merged,
        |route| route.interface.as_str(),
        |route| route.metric,
        &["nvwg0"],
        |route| route.interface == "enp7s0",
    )
    .expect("carrier-up cached replacement underlay");

    assert_eq!(selected.interface, "enp7s0");
    assert_eq!(
        selected.gateway,
        Ipv4Addr::new(172, 31, 254, 9),
        "live gateway details must replace the cached route for the same interface"
    );
}

#[test]
fn linux_new_live_onlink_default_keeps_current_source_and_wins_selection() {
    let live_routes = parse_linux_ipv4_default_route_lines(
        "default via 198.51.100.1 dev wlan0 src 10.42.0.20 metric 50 onlink",
    );
    let cached_routes = parse_linux_ipv4_default_route_hints(&[
        "default via 192.0.2.1 dev eth0 src 192.0.2.20 metric 100".to_string(),
    ]);

    let merged = merge_linux_ipv4_default_routes(&live_routes, &cached_routes);
    let selected = select_linux_underlay_default_route(
        &merged,
        |route| route.interface.as_str(),
        |route| route.metric,
        &[],
        |route| route.interface == "wlan0",
    )
    .expect("new onlink carrier");

    assert_eq!(selected.source, Some(Ipv4Addr::new(10, 42, 0, 20)));
    assert!(selected.on_link);
}

#[test]
fn linux_underlay_selection_does_not_rebind_before_primary_carrier_loss() {
    let live_routes = vec![
        LinuxIpv4DefaultRoute {
            interface: "nvwg0".to_string(),
            gateway: Ipv4Addr::UNSPECIFIED,
            source: None,
            metric: 0,
            on_link: false,
        },
        LinuxIpv4DefaultRoute {
            interface: "enp7s0".to_string(),
            gateway: Ipv4Addr::new(172, 31, 254, 1),
            source: Some(Ipv4Addr::new(172, 31, 254, 2)),
            metric: 600,
            on_link: false,
        },
    ];
    let cached_routes = parse_linux_ipv4_default_route_hints(&[
        "default via 192.168.122.1 dev enp1s0 src 192.168.122.147 metric 100".to_string(),
        "default via 172.31.254.1 dev enp7s0 src 172.31.254.2 metric 600".to_string(),
    ]);
    let merged = merge_linux_ipv4_default_routes(&live_routes, &cached_routes);

    let selected = select_linux_underlay_default_route(
        &merged,
        |route| route.interface.as_str(),
        |route| route.metric,
        &["nvwg0"],
        |_| true,
    )
    .expect("cached primary remains usable before the carrier cut");

    assert_eq!(selected.interface, "enp1s0");
    assert_eq!(selected.gateway, Ipv4Addr::new(192, 168, 122, 1));
}

#[test]
fn linux_underlay_selection_rejects_cached_route_with_stale_source() {
    let cached_routes = parse_linux_ipv4_default_route_hints(&[
        "default via 192.168.122.1 dev enp1s0 src 192.168.122.147 metric 100".to_string(),
        "default via 172.31.254.1 dev enp7s0 src 172.31.254.2 metric 600".to_string(),
    ]);
    let stale_source = Ipv4Addr::new(192, 168, 122, 147);

    let selected = select_linux_underlay_default_route(
        &cached_routes,
        |route| route.interface.as_str(),
        |route| route.metric,
        &[],
        |route| route.source != Some(stale_source),
    )
    .expect("alternate with current source");

    assert_eq!(selected.interface, "enp7s0");
    assert_eq!(selected.source, Some(Ipv4Addr::new(172, 31, 254, 2)));
}

#[test]
fn linux_underlay_selection_accepts_new_lower_metric_live_default() {
    let live_routes = vec![LinuxIpv4DefaultRoute {
        interface: "wlan0".to_string(),
        gateway: Ipv4Addr::new(10, 42, 0, 1),
        source: Some(Ipv4Addr::new(10, 42, 0, 20)),
        metric: 50,
        on_link: false,
    }];
    let cached_routes = parse_linux_ipv4_default_route_hints(&[
        "default via 192.168.122.1 dev enp1s0 src 192.168.122.147 metric 100".to_string(),
        "default via 172.31.254.1 dev enp7s0 src 172.31.254.2 metric 600".to_string(),
    ]);
    let merged = merge_linux_ipv4_default_routes(&live_routes, &cached_routes);
    let selected = select_linux_underlay_default_route(
        &merged,
        |route| route.interface.as_str(),
        |route| route.metric,
        &["nvwg0"],
        |_| true,
    )
    .expect("new live underlay");

    assert_eq!(selected.interface, "wlan0");
    assert_eq!(selected.gateway, Ipv4Addr::new(10, 42, 0, 1));
}

#[test]
fn linux_cached_default_requires_its_gateway_on_the_current_interface_network() {
    let mut interface = netdev::Interface::dummy();
    interface.name = "enp1s0".to_string();
    interface.ipv4 = vec!["10.42.0.20/24".parse().expect("current address")];
    let stale = crate::linux_default_route_spec_from_line(
        "default via 192.168.122.1 dev enp1s0 src 192.168.122.147 metric 100",
    )
    .expect("stale route");
    let current = crate::linux_default_route_spec_from_line(
        "default via 10.42.0.1 dev enp1s0 src 10.42.0.20 metric 100",
    )
    .expect("current route");

    assert!(!crate::linux_ipv4_default_route_matches_interface(
        &stale, &interface
    ));
    assert!(crate::linux_ipv4_default_route_matches_interface(
        &current, &interface
    ));
}

#[test]
fn linux_cached_default_prefers_its_route_source_on_a_multi_address_interface() {
    let mut interface = netdev::Interface::dummy();
    interface.name = "enp1s0".to_string();
    interface.ipv4 = vec![
        "10.42.0.20/24".parse().expect("first address"),
        "192.0.2.44/24".parse().expect("preferred address"),
    ];
    let route = crate::linux_default_route_spec_from_line(
        "default via 192.0.2.1 dev enp1s0 src 192.0.2.44 metric 100",
    )
    .expect("route with preferred source");

    assert!(crate::linux_ipv4_default_route_matches_interface(
        &route, &interface
    ));
    assert_eq!(
        crate::linux_ipv4_default_route_primary_address(&route, &interface),
        Some(Ipv4Addr::new(192, 0, 2, 44))
    );
}

#[test]
fn linux_default_without_prefsrc_uses_the_address_on_the_gateway_network() {
    let mut interface = netdev::Interface::dummy();
    interface.name = "enp1s0".to_string();
    interface.ipv4 = vec![
        "10.42.0.20/24".parse().expect("unrelated first address"),
        "192.0.2.44/24".parse().expect("gateway-network address"),
    ];
    let route =
        crate::linux_default_route_spec_from_line("default via 192.0.2.1 dev enp1s0 metric 100")
            .expect("route without preferred source");

    assert_eq!(
        crate::linux_ipv4_default_route_primary_address(&route, &interface),
        Some(Ipv4Addr::new(192, 0, 2, 44))
    );
}

#[test]
fn linux_onlink_default_is_valid_but_does_not_guess_between_multiple_sources() {
    let mut interface = netdev::Interface::dummy();
    interface.name = "enp1s0".to_string();
    interface.ipv4 = vec![
        "10.42.0.20/24".parse().expect("first address"),
        "192.0.2.44/24".parse().expect("second address"),
    ];
    let route = crate::linux_default_route_spec_from_line(
        "default via 198.51.100.1 dev enp1s0 onlink metric 100",
    )
    .expect("onlink route");

    assert!(crate::linux_ipv4_default_route_matches_interface(
        &route, &interface
    ));
    assert_eq!(
        crate::linux_ipv4_default_route_primary_address(&route, &interface),
        None,
        "without prefsrc or a matching subnet, guessing the first address can bind FIPS to the wrong network"
    );
}

#[test]
fn linux_live_default_audit_ignores_cached_only_and_managed_routes() {
    let managed = LinuxIpv4DefaultRoute {
        interface: "nvwg0".to_string(),
        gateway: Ipv4Addr::UNSPECIFIED,
        source: None,
        metric: 0,
        on_link: false,
    };
    let physical = LinuxIpv4DefaultRoute {
        interface: "enp1s0".to_string(),
        gateway: Ipv4Addr::new(192, 0, 2, 1),
        source: None,
        metric: 100,
        on_link: false,
    };

    assert!(linux_live_unmanaged_ipv4_default_present(
        &[managed.clone(), physical],
        &["nvwg0"]
    ));
    assert!(!linux_live_unmanaged_ipv4_default_present(
        &[managed],
        &["nvwg0"]
    ));
    assert!(
        !linux_live_unmanaged_ipv4_default_present(&[], &["nvwg0"]),
        "cached physical defaults are deliberately outside the raw live-route audit"
    );
}

#[test]
fn linux_ipv6_default_route_parser_preserves_physical_fallback() {
    let routes = parse_linux_ipv6_default_routes(
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
         fe800000000000000000000000000001 00000064 00000000 00000000 00000003 enp7s0\n",
    );
    assert_eq!(
        routes,
        vec![LinuxIpv6DefaultRoute {
            interface: "enp7s0".to_string(),
            gateway: "fe80::1".parse().expect("gateway"),
            metric: 100,
        }]
    );
}

#[test]
fn windows_ipv4_snapshot_uses_routed_physical_adapter() {
    let mut physical = netdev::Interface::dummy();
    physical.index = 4;
    physical.name = "{PHYSICAL-ADAPTER-GUID}".to_string();
    physical.mtu = Some(1_500);
    physical.ipv4 = vec!["192.0.2.147/24".parse().expect("physical IPv4")];
    let route = crate::wg_upstream_runtime::WindowsDefaultRoute {
        gateway: "192.0.2.1".to_string(),
        interface_index: 4,
        interface_ipv4: Ipv4Addr::new(192, 0, 2, 147),
    };
    let snapshot = windows_network_snapshot_from_ipv4_route(&route, &[physical], &[])
        .expect("physical IPv4 snapshot");
    assert_eq!(snapshot.primary_ipv4, Some(Ipv4Addr::new(192, 0, 2, 147)));
    assert_eq!(snapshot.gateway_ipv4, Some(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn windows_ipv4_snapshot_skips_excluded_lowest_metric_default() {
    let mut tunnel = netdev::Interface::dummy();
    tunnel.index = 24;
    tunnel.name = "{WG-TUNNEL-GUID}".to_string();
    tunnel.friendly_name = Some("nvpn-wg-exit".to_string());
    tunnel.ipv4 = vec!["10.44.0.2/32".parse().expect("tunnel IPv4")];
    let mut physical = netdev::Interface::dummy();
    physical.index = 4;
    physical.name = "{PHYSICAL-ADAPTER-GUID}".to_string();
    physical.friendly_name = Some("Ethernet".to_string());
    physical.mtu = Some(1_500);
    physical.ipv4 = vec!["192.0.2.147/24".parse().expect("physical IPv4")];
    let interfaces = vec![tunnel, physical];
    let mut capture_exclusions = Vec::new();
    let snapshot =
        windows_network_snapshot_from_ipv4_capture(&interfaces, &["nvpn-wg-exit"], |excluded| {
            capture_exclusions.push(excluded.to_vec());
            Ok(crate::wg_upstream_runtime::WindowsDefaultRoute {
                gateway: "192.0.2.1".to_string(),
                interface_index: 4,
                interface_ipv4: Ipv4Addr::new(192, 0, 2, 147),
            })
        })
        .expect("physical IPv4 snapshot");

    assert_eq!(capture_exclusions, vec![vec![24]]);
    assert_eq!(
        snapshot.default_interface,
        Some("{PHYSICAL-ADAPTER-GUID}".to_string())
    );
    assert_eq!(snapshot.primary_ipv4, Some(Ipv4Addr::new(192, 0, 2, 147)));
    assert_eq!(snapshot.gateway_ipv4, Some(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn windows_ipv6_fallback_excludes_tunnel_and_selects_physical_route() {
    let mut tunnel = netdev::Interface::dummy();
    tunnel.index = 24;
    tunnel.name = "{FIPS-WINTUN-GUID}".to_string();
    tunnel.friendly_name = Some("nvpn-underlay-gate".to_string());
    tunnel.ipv6 = vec!["2001:db8:44::2/128".parse().expect("tunnel IPv6")];
    let mut physical = netdev::Interface::dummy();
    physical.index = 4;
    physical.name = "{PHYSICAL-ADAPTER-GUID}".to_string();
    physical.friendly_name = Some("Ethernet".to_string());
    physical.mtu = Some(1_500);
    physical.ipv6 = vec!["2001:db8:122::147/64".parse().expect("physical IPv6")];
    let routes = vec![
        crate::wg_upstream_runtime::WindowsIpv6DefaultRoute {
            gateway: None,
            interface_index: 24,
            metric: 1,
        },
        crate::wg_upstream_runtime::WindowsIpv6DefaultRoute {
            gateway: Some("fe80::1".parse().expect("gateway")),
            interface_index: 4,
            metric: 25,
        },
    ];
    let snapshot = windows_network_snapshot_from_ipv6_routes(
        &routes,
        &[tunnel, physical],
        &["nvpn-underlay-gate"],
    )
    .expect("physical IPv6 snapshot");
    assert_eq!(
        snapshot.primary_ipv6,
        Some("2001:db8:122::147".parse().expect("IPv6"))
    );
    assert_eq!(
        snapshot.gateway_ipv6,
        Some("fe80::1".parse().expect("gateway"))
    );
}
