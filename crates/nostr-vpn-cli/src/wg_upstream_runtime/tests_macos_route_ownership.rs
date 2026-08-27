    #[test]
    fn macos_wireguard_cleanup_never_touches_the_physical_default() {
        assert_eq!(
            MACOS_WG_DEFAULT_ROUTE_TARGETS,
            &["0.0.0.0/1", "128.0.0.0/1"]
        );
        assert!(!MACOS_WG_DEFAULT_ROUTE_TARGETS.contains(&"0.0.0.0/0"));
    }

    #[test]
    fn macos_wireguard_ipv4_endpoint_bypasses_split_defaults_on_selected_underlay() {
        let underlay = crate::MacosRouteSpec {
            gateway: Some("192.0.2.1".to_string()),
            interface: "en7".to_string(),
        };

        assert_eq!(
            macos_wg_endpoint_bypass_route(
                "203.0.113.9".parse().expect("IPv4 endpoint"),
                &underlay,
            ),
            Some(crate::MacosManagedRoute {
                target: "203.0.113.9/32".to_string(),
                gateway: Some("192.0.2.1".to_string()),
                interface: Some("en7".to_string()),
            })
        );
    }

    #[test]
    fn macos_wireguard_gateway_endpoint_uses_a_direct_underlay_route() {
        let underlay = crate::MacosRouteSpec {
            gateway: Some("192.168.64.1".to_string()),
            interface: "en0".to_string(),
        };

        assert_eq!(
            macos_wg_endpoint_bypass_route(
                "192.168.64.1".parse().expect("gateway endpoint"),
                &underlay,
            ),
            Some(crate::MacosManagedRoute {
                target: "192.168.64.1/32".to_string(),
                gateway: None,
                interface: Some("en0".to_string()),
            }),
            "a gateway routed via itself is collapsed into a scoped ARP route on macOS",
        );
    }

    #[test]
    fn macos_wireguard_ipv6_endpoint_needs_no_ipv4_bypass() {
        let underlay = crate::MacosRouteSpec {
            gateway: Some("192.0.2.1".to_string()),
            interface: "en7".to_string(),
        };

        assert_eq!(
            macos_wg_endpoint_bypass_route(
                "2001:db8::9".parse().expect("IPv6 endpoint"),
                &underlay,
            ),
            None
        );
    }

    #[test]
    fn macos_wireguard_cleanup_owns_endpoint_and_only_split_defaults() {
        let endpoint = crate::MacosManagedRoute {
            target: "203.0.113.9/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface: Some("en7".to_string()),
        };
        let guard = FullDefaultRoute {
            iface: "utun42".to_string(),
            endpoint_bypass_routes: vec![endpoint.clone()],
            reverted: true,
        };

        assert_eq!(
            guard.macos_managed_routes(),
            vec![
                endpoint,
                crate::MacosManagedRoute {
                    target: "0.0.0.0/1".to_string(),
                    gateway: None,
                    interface: Some("utun42".to_string()),
                },
                crate::MacosManagedRoute {
                    target: "128.0.0.0/1".to_string(),
                    gateway: None,
                    interface: Some("utun42".to_string()),
                },
            ]
        );
    }
