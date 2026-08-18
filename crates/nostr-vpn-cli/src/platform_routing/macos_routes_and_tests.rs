#[cfg(target_os = "macos")]
fn split_cidr<'a>(address: &'a str, default_prefix: &'a str) -> (&'a str, &'a str) {
    address.split_once('/').unwrap_or((address, default_prefix))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ipv4_route_source(address: &str) -> Option<String> {
    strip_cidr(address)
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| ip.to_string())
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_replace_args(
    target: &str,
    iface: &str,
    ipv4_route_source: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if linux_route_target_is_ipv6(target) {
        args.push("-6".to_string());
    } else if linux_route_target_is_ipv4(target) {
        args.push("-4".to_string());
    }
    args.extend([
        "route".to_string(),
        "replace".to_string(),
        target.to_string(),
        "dev".to_string(),
        iface.to_string(),
    ]);
    if linux_route_target_is_ipv4(target)
        && let Some(source) = ipv4_route_source
    {
        args.push("src".to_string());
        args.push(source.to_string());
    }
    args
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_tunnel_address_is_ipv4(address: &str) -> bool {
    strip_cidr(address).parse::<Ipv4Addr>().is_ok()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_tunnel_address_is_ipv6(address: &str) -> bool {
    strip_cidr(address).parse::<Ipv6Addr>().is_ok()
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_route_target_is_ipv4(target: &str) -> bool {
    strip_cidr(target).parse::<Ipv4Addr>().is_ok()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_route_target_is_ipv6(target: &str) -> bool {
    strip_cidr(target).parse::<Ipv6Addr>().is_ok()
}

#[cfg(target_os = "macos")]
fn apply_macos_route(iface: &str, target: &str) -> Result<()> {
    if linux_route_target_is_ipv6(target) {
        let (target_ip, prefix) = split_cidr(target, "128");
        let _ = ProcessCommand::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("-prefixlen")
            .arg(prefix)
            .arg(target_ip)
            .arg("-interface")
            .arg(iface)
            .status();
        return run_checked(
            ProcessCommand::new("route")
                .arg("add")
                .arg("-inet6")
                .arg("-prefixlen")
                .arg(prefix)
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        );
    }
    if target == "0.0.0.0/0" {
        eprintln!("tunnel: applying macOS default route via interface {iface}");
        return apply_macos_default_route(None, Some(iface));
    }
    apply_macos_route_spec(target, None, Some(iface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_route_family_helpers_detect_ipv4_and_ipv6_cidrs() {
        assert!(linux_tunnel_address_is_ipv4("10.44.0.1/32"));
        assert!(!linux_tunnel_address_is_ipv6("10.44.0.1/32"));
        assert!(linux_tunnel_address_is_ipv6("fd00::1/128"));
        assert!(!linux_tunnel_address_is_ipv4("fd00::1/128"));
        assert!(linux_route_target_is_ipv4("0.0.0.0/0"));
        assert!(!linux_route_target_is_ipv4("::/0"));
        assert!(linux_route_target_is_ipv6("::/0"));
        assert!(!linux_route_target_is_ipv6("10.44.0.0/16"));
    }

    #[test]
    fn linux_route_replace_args_selects_address_family() {
        assert_eq!(
            linux_route_replace_args("fd00::/8", "utun100", Some("10.44.0.1")),
            vec!["-6", "route", "replace", "fd00::/8", "dev", "utun100"]
        );
        assert_eq!(
            linux_route_replace_args("10.44.0.2/32", "utun100", Some("10.44.0.1")),
            vec![
                "-4",
                "route",
                "replace",
                "10.44.0.2/32",
                "dev",
                "utun100",
                "src",
                "10.44.0.1"
            ]
        );
    }

    #[test]
    fn linux_tunnel_address_reconciliation_removes_only_stale_owned_addresses() {
        let state = r#"[{
            "addr_info": [
                {"local": "10.44.0.1", "prefixlen": 32},
                {"local": "10.44.29.134", "prefixlen": 32},
                {"local": "fd00::134", "prefixlen": 128},
                {"local": "fe80::134", "prefixlen": 64}
            ]
        }]"#;
        let desired = vec![
            "10.44.29.134/32".to_string(),
            "fd00::134/128".to_string(),
        ];

        assert_eq!(
            stale_linux_interface_addresses_json(state, &desired).expect("stale addresses"),
            vec!["10.44.0.1/32"]
        );
    }

    #[test]
    fn wireguard_upstream_inbound_drop_rule_blocks_new_mesh_forwards() {
        assert_eq!(
            linux_wireguard_exit_inbound_drop_rule("nvpn-wg-exit", "nvpn0", "10.44.0.0/16"),
            vec![
                "FORWARD",
                "-i",
                "nvpn-wg-exit",
                "-o",
                "nvpn0",
                "-d",
                "10.44.0.0/16",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW,INVALID",
                "-m",
                "comment",
                "--comment",
                "nvpn-wg-upstream-inbound-drop",
                "-j",
                "DROP",
            ]
        );
    }

    #[test]
    fn linux_underlay_handoff_replaces_cached_route_and_endpoint_bypass_atomically() {
        let routes = "\
default dev nvut42 scope link src 10.44.33.93
default via 192.0.2.1 dev enp1s0 proto static src 192.0.2.10 metric 100
default via 198.51.100.2 dev enp7s0 proto static src 198.51.100.10 metric 700
default via 198.51.100.1 dev enp7s0 proto static src 198.51.100.10 metric 600
";
        assert_eq!(
            linux_default_route_from_output(routes)
                .expect("lowest-metric default")
                .dev,
            "nvut42"
        );
        let old = linux_default_route_from_output_for_interface(routes, Some("enp1s0"))
            .expect("old physical default");
        let replacement = linux_default_route_from_output_for_interface(routes, Some("enp7s0"))
            .expect("replacement physical default");
        assert_eq!(
            replacement.line,
            "default via 198.51.100.1 dev enp7s0 proto static src 198.51.100.10 metric 600"
        );

        let mut cached = Some(old.line);
        update_linux_underlay_default_route(&mut cached, replacement, "nvut42")
            .expect("cache replacement");
        let cached = cached.expect("replacement cached");
        let expected_bypass = LinuxEndpointBypassRoute {
                target: "203.0.113.9/32".to_string(),
                gateway: Some("198.51.100.1".to_string()),
                dev: "enp7s0".to_string(),
                src: Some("198.51.100.10".to_string()),
            };
        let managed = LinuxManagedEndpointBypassRoute {
            route: expected_bypass.clone(),
            previous_routes: vec![
                "203.0.113.9/32 via 192.0.2.1 dev enp1s0 src 192.0.2.10".to_string(),
            ],
            owned: true,
        };
        assert!(linux_endpoint_bypass_route_matches_line(
            &managed.route,
            "203.0.113.9 via 198.51.100.1 dev enp7s0 proto static \
             src 198.51.100.10 metric 1"
        ));
        assert!(!linux_endpoint_bypass_route_matches_line(
            &managed.route,
            "203.0.113.9/32 via 198.51.100.2 dev enp7s0 src 198.51.100.10"
        ));
        for stale_route in [
            "203.0.113.9 via 192.0.2.1 dev enp1s0 src 192.0.2.10",
            "203.0.113.9 dev nvut42 src 10.44.33.93",
        ] {
            assert_eq!(
                linux_endpoint_bypass_route_from_output(
                    "203.0.113.9".parse().unwrap(),
                    stale_route,
                    "nvut42",
                    Some(&cached),
                )
                .expect("refreshed physical endpoint bypass"),
                expected_bypass,
                "stale route must not survive underlay handoff: {stale_route}"
            );
        }
        for fresh_route in [
            LinuxEndpointBypassRoute {
                target: "203.0.113.9/32".to_string(),
                gateway: Some("198.51.100.2".to_string()),
                dev: "enp7s0".to_string(),
                src: Some("198.51.100.10".to_string()),
            },
            LinuxEndpointBypassRoute {
                target: "203.0.113.9/32".to_string(),
                gateway: Some("198.51.100.1".to_string()),
                dev: "enp7s0".to_string(),
                src: Some("198.51.100.11".to_string()),
            },
            LinuxEndpointBypassRoute {
                target: "203.0.113.9/32".to_string(),
                gateway: None,
                dev: "enp7s0".to_string(),
                src: Some("198.51.100.10".to_string()),
            },
        ] {
            let output = match (&fresh_route.gateway, &fresh_route.src) {
                (Some(gateway), Some(src)) => {
                    format!("203.0.113.9 via {gateway} dev enp7s0 src {src}")
                }
                (None, Some(src)) => format!("203.0.113.9 dev enp7s0 src {src}"),
                _ => unreachable!("fixture routes have a source address"),
            };
            assert_eq!(
                linux_endpoint_bypass_route_from_output(
                    "203.0.113.9".parse().unwrap(),
                    &output,
                    "nvut42",
                    Some(&cached),
                )
                .expect("fresh physical endpoint bypass"),
                fresh_route,
                "kernel-selected on-link/static/policy route must remain authoritative"
            );
        }
        assert_eq!(
            linux_route_replay_args(&cached).join(" "),
            cached,
            "Direct/cleanup restore must preserve the exact replacement route"
        );
    }

    #[test]
    fn linux_endpoint_bypass_derives_source_when_default_has_no_prefsrc() {
        let mut interface = netdev::Interface::dummy();
        interface.name = "enp7s0".to_string();
        interface.ipv4 = vec![
            "10.42.0.20/24".parse().expect("unrelated address"),
            "172.31.254.10/24".parse().expect("underlay address"),
        ];
        let route = linux_endpoint_bypass_route_from_output_with_interfaces(
            "10.231.254.2".parse().expect("endpoint"),
            "10.231.254.2 via 192.168.122.1 dev enp1s0 src 192.168.122.103",
            "nvpn-wg-exit",
            Some("default via 172.31.254.1 dev enp7s0 metric 600"),
            &[interface],
        )
        .expect("replacement endpoint route");

        assert_eq!(route.dev, "enp7s0");
        assert_eq!(route.gateway.as_deref(), Some("172.31.254.1"));
        assert_eq!(route.src.as_deref(), Some("172.31.254.10"));
    }

    #[test]
    fn linux_saved_default_never_overwrites_a_new_physical_underlay() {
        let saved = "default via 192.0.2.1 dev enp1s0 metric 100";
        let new_physical = LinuxDefaultRouteSpec {
            line: "default via 198.51.100.1 dev enp7s0 metric 100".to_string(),
            dev: "enp7s0".to_string(),
            gateway: Some("198.51.100.1".to_string()),
            source: None,
            metric: 100,
            on_link: false,
        };
        let owned = vec!["nvpn0".to_string(), "nvwg0".to_string()];
        assert!(!linux_saved_default_restore_required(
            saved,
            Some(&new_physical),
            &owned
        ));
    }

    #[test]
    fn linux_saved_default_replaces_only_an_owned_or_missing_overlay_default() {
        let saved = "default via 192.0.2.1 dev enp1s0 metric 100";
        let overlay = LinuxDefaultRouteSpec {
            line: "default dev nvwg0 metric 5".to_string(),
            dev: "nvwg0".to_string(),
            gateway: None,
            source: None,
            metric: 5,
            on_link: false,
        };
        let already_restored = LinuxDefaultRouteSpec {
            line: saved.to_string(),
            dev: "enp1s0".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            source: None,
            metric: 100,
            on_link: false,
        };
        let owned = vec!["nvpn0".to_string(), "nvwg0".to_string()];
        assert!(linux_saved_default_restore_required(
            saved,
            Some(&overlay),
            &owned
        ));
        assert!(linux_saved_default_restore_required(saved, None, &owned));
        assert!(!linux_saved_default_restore_required(
            saved,
            Some(&already_restored),
            &owned
        ));
    }

    #[test]
    fn exit_node_forward_rules_are_scoped_to_mesh_source_and_outbound_iface() {
        assert_eq!(
            linux_exit_node_forward_in_rule(
                "utun100",
                "enp41s0",
                "10.44.0.0/16",
                LinuxExitNodeIpFamily::V4
            ),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-o",
                "enp41s0",
                "-s",
                "10.44.0.0/16",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-forward-in",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_forward_out_rule("utun100", "enp41s0", LinuxExitNodeIpFamily::V4),
            vec![
                "FORWARD",
                "-i",
                "enp41s0",
                "-o",
                "utun100",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-forward-out",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_ipv4_mss_clamp_rule("utun100", "enp41s0", "10.44.0.0/16", 1110),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-o",
                "enp41s0",
                "-s",
                "10.44.0.0/16",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-mss",
                "-j",
                "TCPMSS",
                "--set-mss",
                "1110",
            ]
        );
    }

    #[test]
    fn legacy_exit_node_forward_rules_match_old_unscoped_rules_for_cleanup() {
        assert_eq!(
            linux_exit_node_legacy_forward_in_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit6-forward-in",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_legacy_forward_out_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD",
                "-o",
                "utun100",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit6-forward-out",
                "-j",
                "ACCEPT",
            ]
        );
    }
}
