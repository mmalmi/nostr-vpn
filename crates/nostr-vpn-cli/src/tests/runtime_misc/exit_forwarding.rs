use super::*;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn runtime_exit_node_routes_do_not_advertise_ipv6_default() {
    let mut app = AppConfig::generated();
    app.node.advertise_exit_node = true;

    assert_eq!(runtime_exit_node_default_routes(), vec!["0.0.0.0/0"]);
    assert_eq!(runtime_effective_advertised_routes(&app), vec!["0.0.0.0/0"]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_host_forwarding_does_not_advertise_free_exit_route() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;

    assert!(runtime_effective_advertised_routes(&app).is_empty());
    assert_eq!(
        runtime_local_exit_forwarding_routes(&app),
        vec!["0.0.0.0/0"]
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_forwarding_ignores_removed_legacy_ip_support_knobs() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.paid_exit.ip_support.ipv4 = false;
    app.paid_exit.ip_support.ipv6 = true;

    assert_eq!(
        runtime_local_exit_forwarding_routes(&app),
        vec!["0.0.0.0/0"]
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn paid_exit_forwarding_rejects_paid_on_paid_resale() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.set_internet_source(InternetSource::PaidAutomatic);

    assert!(runtime_local_exit_forwarding_routes(&app).is_empty());
}

#[test]
fn legacy_macos_exit_cleanup_leaves_global_ipv4_forwarding_alone() {
    let mut app = AppConfig::generated();
    app.node.advertise_exit_node = true;

    let plan = legacy_macos_exit_cleanup_plan(&runtime_effective_advertised_routes(&app));

    assert!(plan.cleanup_pf_nat);
    assert!(!plan.restore_ipv4_forwarding);
}

#[cfg(target_os = "macos")]
#[test]
fn legacy_macos_cleanup_journal_does_not_claim_ownerless_endpoint_routes() {
    let state: MacosNetworkCleanupState = serde_json::from_str(
        r#"{
            "iface": "utun42",
            "endpoint_bypass_routes": ["203.0.113.7/32"],
            "original_default_route": {
                "gateway": "192.0.2.1",
                "interface": "en0"
            }
        }"#,
    )
    .expect("deserialize pre-ownership cleanup journal");

    let actionable = crate::daemon_runtime::macos_cleanup_managed_routes(&state);

    assert!(
        actionable
            .iter()
            .all(|route| route.target != "203.0.113.7/32"),
        "an ownerless legacy endpoint route is non-actionable migration data"
    );
    assert_eq!(
        actionable,
        vec![
            MacosManagedRoute {
                target: "0.0.0.0/1".to_string(),
                gateway: None,
                interface: Some("utun42".to_string()),
            },
            MacosManagedRoute {
                target: "128.0.0.0/1".to_string(),
                gateway: None,
                interface: Some("utun42".to_string()),
            },
        ],
        "exact legacy tunnel ownership remains actionable"
    );
}

#[test]
fn macos_exit_node_pf_rules_are_scoped_to_tunnel_source_and_outbound_iface() {
    let rules = crate::macos_network::macos_exit_node_pf_rules("utun42", "en0", "10.44.0.0/16");

    assert_eq!(
        rules,
        concat!(
            "nat on en0 inet from 10.44.0.0/16 to any -> (en0)\n",
            "pass in quick on utun42 inet from 10.44.0.0/16 to any keep state\n",
            "pass out quick on en0 inet from 10.44.0.0/16 to any keep state\n",
        )
    );
    assert!(!rules.contains("net.inet.ip.forwarding"));
    assert!(!rules.contains("pass in quick on en0"));
}

#[test]
fn macos_ipv4_forwarding_state_parser_accepts_only_kernel_boolean_values() {
    assert!(!crate::parse_macos_ipv4_forwarding_state("0\n").expect("disabled state"));
    assert!(crate::parse_macos_ipv4_forwarding_state("1\n").expect("enabled state"));
    assert!(crate::parse_macos_ipv4_forwarding_state("2\n").is_err());
    assert!(crate::parse_macos_ipv4_forwarding_state("").is_err());
}

#[test]
fn macos_pf_state_parser_accepts_pfctl_status_details() {
    assert!(
        crate::parse_macos_pf_enabled("Status: Enabled for 2 days 01:02:03\n")
            .expect("enabled state")
    );
    assert!(!crate::parse_macos_pf_enabled("Status: Disabled\n").expect("disabled state"));
    assert!(crate::parse_macos_pf_enabled("Status: Unknown\n").is_err());
    assert!(crate::parse_macos_pf_enabled("").is_err());
}

#[test]
fn macos_exit_node_pf_anchor_is_scoped_per_config_owner() {
    let first = crate::macos_network::macos_exit_pf_anchor(Path::new("/etc/nvpn/one.toml"));
    let second = crate::macos_network::macos_exit_pf_anchor(Path::new("/etc/nvpn/two.toml"));
    let again = crate::macos_network::macos_exit_pf_anchor(Path::new("/etc/nvpn/one.toml"));

    assert!(first.starts_with("com.apple/nostrvpn-exit-"));
    assert_eq!(first.matches('/').count(), 1);
    assert_ne!(
        first, second,
        "two per-config daemons must flush their own anchors only"
    );
    assert_eq!(first, again, "one config keeps one anchor across restarts");
}

#[test]
fn macos_exit_node_cleanup_flushes_only_the_owner_anchor() {
    let anchor = crate::macos_network::macos_exit_pf_anchor(Path::new("/etc/nvpn/one.toml"));
    let args = crate::macos_network::macos_pf_anchor_flush_args(&anchor);
    assert_eq!(args, vec!["-a", anchor.as_str(), "-F", "all"]);
    assert_eq!(args[1].matches('/').count(), 1);
}

#[test]
fn macos_exit_claims_from_other_owners_keep_pf_enabled() {
    let owner = crate::macos_network::macos_config_identity(Path::new("/etc/nvpn/one.toml"));
    let other = crate::macos_network::macos_config_identity(Path::new("/etc/nvpn/two.toml"));

    assert!(
        crate::macos_network::macos_other_exit_claims_remain(
            &[format!("{other}.exit-claims")],
            &owner,
        ),
        "a foreign exit claim must keep the global knobs enabled"
    );
    assert!(
        !crate::macos_network::macos_other_exit_claims_remain(
            &[format!("{owner}.exit-claims")],
            &owner,
        ),
        "the owner's own claim never blocks its cleanup"
    );
    assert!(
        !crate::macos_network::macos_other_exit_claims_remain(
            &[other.to_string(), format!("{owner}.cleanup.json")],
            &owner,
        ),
        "runtime directories and journals are not exit claims"
    );
    assert!(
        !crate::macos_network::macos_other_exit_claims_remain(&[], &owner),
        "with no claims left the last owner disables the global knobs"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_exit_claim_wrapper_restores_globals_for_the_sole_owner() {
    let claims_root =
        std::env::temp_dir().join(format!("nvpn-exit-claims-{}", rand::random::<u64>()));
    std::fs::create_dir(&claims_root).unwrap();
    let owner = Path::new("/etc/nvpn/one.toml");
    let other = Path::new("/etc/nvpn/two.toml");
    let claim_file = |config: &Path| {
        claims_root.join(format!(
            "{}{}",
            crate::macos_network::macos_config_identity(config),
            crate::macos_network::MACOS_EXIT_CLAIM_SUFFIX
        ))
    };
    let remains = |config: &Path| {
        crate::macos_privileged_files::other_exit_claims_remain(&claims_root, config)
            .expect("inspect macOS exit claims")
    };

    std::fs::write(claim_file(owner), b"1\n").unwrap();
    assert!(
        !remains(owner),
        "with only its own claim on disk, the wrapper must let the last owner restore PF and IPv4 forwarding"
    );

    std::fs::write(claim_file(other), b"1\n").unwrap();
    assert!(
        remains(owner),
        "a foreign exit claim must keep the global knobs enabled"
    );

    std::fs::remove_dir_all(claims_root).unwrap();
}
