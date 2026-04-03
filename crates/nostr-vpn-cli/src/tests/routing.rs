use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::*;

use nostr_sdk::prelude::Keys;
use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::paths::PeerPathBook;

#[path = "routing_peer_paths.rs"]
mod routing_peer_paths;
#[path = "routing_relays.rs"]
mod routing_relays;

#[test]
fn utun_candidates_expand_for_default_style_names() {
    let candidates = utun_interface_candidates("utun100");
    assert_eq!(candidates.len(), 16);
    assert_eq!(candidates[0], "utun100");
    assert_eq!(candidates[1], "utun101");
    assert_eq!(candidates[15], "utun115");
}

#[test]
fn utun_candidates_keep_custom_iface_as_is() {
    let candidates = utun_interface_candidates("wg0");
    assert_eq!(candidates, vec!["wg0".to_string()]);
}

#[test]
fn uapi_addr_in_use_matcher_detects_common_errnos() {
    assert!(is_uapi_addr_in_use_error("uapi set failed: errno=48"));
    assert!(is_uapi_addr_in_use_error("uapi set failed: errno=98"));
    assert!(!is_uapi_addr_in_use_error("uapi set failed: errno=1"));
}

#[test]
fn endpoint_listen_port_rewrite_updates_socket_port() {
    assert_eq!(
        endpoint_with_listen_port("192.168.1.10:51820", 52000),
        "192.168.1.10:52000"
    );
    assert_eq!(
        endpoint_with_listen_port("[2001:db8::1]:51820", 52000),
        "[2001:db8::1]:52000"
    );
    assert_eq!(
        endpoint_with_listen_port("not-a-socket", 52000),
        "not-a-socket"
    );
}

#[test]
fn local_interface_address_for_tunnel_preserves_host_prefix() {
    assert_eq!(
        local_interface_address_for_tunnel("10.44.0.1/32"),
        "10.44.0.1/32"
    );
    assert_eq!(
        local_interface_address_for_tunnel("10.44.0.1"),
        "10.44.0.1/32"
    );
}

#[test]
fn route_targets_for_tunnel_peers_use_peer_allowed_ips() {
    let routes = route_targets_for_tunnel_peers(&[
        TunnelPeer {
            pubkey_hex: "a".repeat(64),
            endpoint: "203.0.113.10:51820".to_string(),
            allowed_ips: vec!["10.44.0.3/32".to_string()],
        },
        TunnelPeer {
            pubkey_hex: "b".repeat(64),
            endpoint: "203.0.113.11:51820".to_string(),
            allowed_ips: vec!["10.44.0.2/32".to_string(), "10.55.0.0/24".to_string()],
        },
        TunnelPeer {
            pubkey_hex: "c".repeat(64),
            endpoint: "203.0.113.12:51820".to_string(),
            allowed_ips: vec!["10.44.0.2/32".to_string()],
        },
    ]);

    assert_eq!(
        routes,
        vec![
            "10.44.0.2/32".to_string(),
            "10.44.0.3/32".to_string(),
            "10.55.0.0/24".to_string(),
        ]
    );
}

#[test]
fn macos_route_targets_add_default_route_for_selected_exit_peer() {
    let mut config = AppConfig::generated();
    let exit_participant = Keys::generate().public_key().to_hex();
    config.networks[0].participants = vec![exit_participant.clone()];
    config.exit_node = exit_participant.clone();
    config.ensure_defaults();

    let announcements = HashMap::from([(
        exit_participant.clone(),
        PeerAnnouncement {
            node_id: "exit-node".to_string(),
            public_key: generate_keypair().public_key,
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string(), "10.60.0.0/24".to_string()],
            timestamp: 1,
        },
    )]);

    let planned = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("192.0.2.10:51820"),
        10,
    )
    .expect("planned tunnel peers");

    let routes = route_targets_for_planned_tunnel_peers(&config, None, &announcements, &planned, None);

    assert_eq!(
        routes,
        vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
    );
}

#[test]
fn macos_route_targets_add_default_route_for_selected_exit_peer_after_handshake() {
    let mut config = AppConfig::generated();
    let exit_participant = Keys::generate().public_key().to_hex();
    config.networks[0].participants = vec![exit_participant.clone()];
    config.exit_node = exit_participant.clone();
    config.ensure_defaults();

    let public_key = generate_keypair().public_key;
    let public_key_hex = crate::key_b64_to_hex(&public_key).expect("peer public key hex");
    let announcements = HashMap::from([(
        exit_participant.clone(),
        PeerAnnouncement {
            node_id: "exit-node".to_string(),
            public_key,
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string(), "10.60.0.0/24".to_string()],
            timestamp: 1,
        },
    )]);

    let planned = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("192.0.2.10:51820"),
        10,
    )
    .expect("planned tunnel peers");

    let runtime_peers = HashMap::from([(
        public_key_hex,
        WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(1),
            ..Default::default()
        },
    )]);

    let routes = route_targets_for_planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &planned,
        Some(&runtime_peers),
    );

    assert_eq!(
        routes,
        vec![
            "0.0.0.0/0".to_string(),
            "10.44.0.2/32".to_string(),
            "10.60.0.0/24".to_string(),
        ]
    );
}

#[test]
fn macos_route_targets_skip_default_route_when_exit_handshake_is_on_stale_endpoint() {
    let mut config = AppConfig::generated();
    let exit_participant = Keys::generate().public_key().to_hex();
    config.networks[0].participants = vec![exit_participant.clone()];
    config.exit_node = exit_participant.clone();
    config.ensure_defaults();

    let public_key = generate_keypair().public_key;
    let public_key_hex = crate::key_b64_to_hex(&public_key).expect("peer public key hex");
    let announcements = HashMap::from([(
        exit_participant.clone(),
        PeerAnnouncement {
            node_id: "exit-node".to_string(),
            public_key,
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string(), "10.60.0.0/24".to_string()],
            timestamp: 1,
        },
    )]);

    let planned = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("192.0.2.10:51820"),
        10,
    )
    .expect("planned tunnel peers");

    let runtime_peers = HashMap::from([(
        public_key_hex,
        WireGuardPeerStatus {
            endpoint: Some("198.51.100.40:51820".to_string()),
            last_handshake_sec: Some(1),
            ..Default::default()
        },
    )]);

    let routes = route_targets_for_planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &planned,
        Some(&runtime_peers),
    );

    assert_eq!(
        routes,
        vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
    );
}

#[test]
fn route_targets_detect_when_endpoint_bypass_is_required() {
    assert!(!route_targets_require_endpoint_bypass(&[
        "10.44.0.2/32".to_string()
    ]));
    assert!(route_targets_require_endpoint_bypass(&[
        "10.55.0.0/24".to_string()
    ]));
    assert!(route_targets_require_endpoint_bypass(&[
        "0.0.0.0/0".to_string()
    ]));
}

#[test]
fn tunnel_runtime_fingerprint_changes_when_route_targets_change() {
    let base = "iface|key|51820|10.44.0.1/32|peer";
    let direct_only = vec!["10.44.0.2/32".to_string()];
    let with_exit = vec!["0.0.0.0/0".to_string(), "10.44.0.2/32".to_string()];

    assert_ne!(
        tunnel_runtime_fingerprint(base, &direct_only),
        tunnel_runtime_fingerprint(base, &with_exit)
    );
}

#[test]
fn stun_host_port_supports_default_and_explicit_ports() {
    assert_eq!(
        stun_host_port("stun:stun.iris.to"),
        Some(("stun.iris.to".to_string(), 3478))
    );
    assert_eq!(
        stun_host_port("stun://198.51.100.30:5349"),
        Some(("198.51.100.30".to_string(), 5349))
    );
    assert_eq!(stun_host_port(""), None);
}

#[test]
fn control_plane_bypass_hosts_include_nat_helpers_and_management_hosts() {
    use netdev::interface::flags::{IFF_POINTOPOINT, IFF_UP};
    use netdev::net::device::NetworkDevice;
    use std::net::IpAddr;

    let mut config = AppConfig::generated();
    config.nostr.relays = vec![
        "wss://203.0.113.10".to_string(),
        "wss://198.51.100.20:444".to_string(),
    ];
    config.nat.stun_servers = vec![
        "stun:198.51.100.30:3478".to_string(),
        "stun://203.0.113.10".to_string(),
        "not-a-stun-url".to_string(),
    ];
    config.nat.reflectors = vec!["192.0.2.40:5000".to_string(), "invalid".to_string()];

    let mut physical = NetworkInterface::dummy();
    physical.name = "en0".to_string();
    physical.flags = IFF_UP as u32;
    let mut gateway = NetworkDevice::new();
    gateway.ipv4.push(Ipv4Addr::new(192, 168, 64, 1));
    physical.gateway = Some(gateway);
    physical.dns_servers = vec![
        IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    ];

    let mut tunnel = NetworkInterface::dummy();
    tunnel.name = "utun100".to_string();
    tunnel.flags = (IFF_UP | IFF_POINTOPOINT) as u32;
    let mut tunnel_gateway = NetworkDevice::new();
    tunnel_gateway.ipv4.push(Ipv4Addr::new(100, 64, 0, 1));
    tunnel.gateway = Some(tunnel_gateway);
    tunnel.dns_servers = vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))];

    let hosts = control_plane_bypass_ipv4_hosts_from_interfaces(&config, &[physical, tunnel]);

    assert_eq!(
        hosts,
        vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(192, 0, 2, 40),
            Ipv4Addr::new(192, 168, 64, 1),
            Ipv4Addr::new(198, 51, 100, 20),
            Ipv4Addr::new(198, 51, 100, 30),
            Ipv4Addr::new(203, 0, 113, 10),
        ]
    );
}

#[test]
fn runtime_effective_advertised_routes_filter_default_exit_routes_by_platform() {
    let mut config = AppConfig::default();
    config.node.advertise_exit_node = true;
    config.node.advertised_routes = vec!["10.55.0.0/24".to_string()];

    let effective = runtime_effective_advertised_routes(&config);

    #[cfg(target_os = "linux")]
    assert_eq!(
        effective,
        vec![
            "10.55.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            "::/0".to_string(),
        ]
    );

    #[cfg(target_os = "macos")]
    assert_eq!(
        effective,
        vec!["10.55.0.0/24".to_string(), "0.0.0.0/0".to_string()]
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(effective, vec!["10.55.0.0/24".to_string()]);
}

#[test]
fn selected_exit_node_participant_tracks_supported_platforms() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];
    config.exit_node = participant.clone();

    let announcements = HashMap::from([(
        participant.clone(),
        PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: generate_keypair().public_key,
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string()],
            timestamp: 10,
        },
    )]);

    let selected = selected_exit_node_participant(&config, None, &announcements);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(selected.as_deref(), Some(participant.as_str()));

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert!(selected.is_none());
}

#[test]
fn macos_route_get_spec_parses_gateway_and_interface() {
    let output = "\
   route to: default\n\
destination: default\n\
   mask: default\n\
gateway: 10.10.243.254\n\
  interface: en0\n";
    let spec = macos_route_get_spec_from_output(output).expect("macOS route spec");
    assert_eq!(spec.gateway.as_deref(), Some("10.10.243.254"));
    assert_eq!(spec.interface, "en0");
}

#[test]
fn split_host_port_keeps_literal_host_without_port() {
    assert_eq!(
        split_host_port("relay.example.com", 443),
        Some(("relay.example.com".to_string(), 443))
    );
    assert_eq!(
        split_host_port("203.0.113.10:51820", 443),
        Some(("203.0.113.10".to_string(), 51820))
    );
}

#[test]
fn linux_ipv4_route_source_uses_tunnel_ipv4_address() {
    assert_eq!(
        linux_ipv4_route_source("10.44.93.37/32"),
        Some("10.44.93.37".to_string())
    );
    assert_eq!(linux_ipv4_route_source("fd00::1/128"), None);
}

#[test]
fn linux_route_target_is_ipv4_detects_ipv4_and_ipv6_targets() {
    assert!(linux_route_target_is_ipv4("0.0.0.0/0"));
    assert!(linux_route_target_is_ipv4("10.44.93.37/32"));
    assert!(!linux_route_target_is_ipv4("::/0"));
}

#[test]
fn linux_exit_node_default_route_families_detect_ipv4_and_ipv6_defaults() {
    let ipv6_only = linux_exit_node_default_route_families(&["::/0".to_string()]);
    assert!(!ipv6_only.ipv4);
    assert!(ipv6_only.ipv6);

    let dual_stack = linux_exit_node_default_route_families(&[
        "10.55.0.0/24".to_string(),
        "0.0.0.0/0".to_string(),
        "::/0".to_string(),
    ]);
    assert!(dual_stack.ipv4);
    assert!(dual_stack.ipv6);
}

#[test]
fn linux_exit_node_ipv6_forward_rules_use_ip6tables_shape() {
    assert_eq!(
        linux_exit_node_firewall_binary(LinuxExitNodeIpFamily::V4),
        "iptables"
    );
    assert_eq!(
        linux_exit_node_firewall_binary(LinuxExitNodeIpFamily::V6),
        "ip6tables"
    );
    assert_eq!(
        linux_exit_node_ipv4_masquerade_rule("eth0", "10.44.0.0/24"),
        vec![
            "POSTROUTING".to_string(),
            "-o".to_string(),
            "eth0".to_string(),
            "-s".to_string(),
            "10.44.0.0/24".to_string(),
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            "nvpn-exit-masq".to_string(),
            "-j".to_string(),
            "MASQUERADE".to_string(),
        ]
    );
    assert_eq!(
        linux_exit_node_forward_in_rule("utun100", LinuxExitNodeIpFamily::V6),
        vec![
            "FORWARD".to_string(),
            "-i".to_string(),
            "utun100".to_string(),
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            "nvpn-exit6-forward-in".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    );
    assert_eq!(
        linux_exit_node_forward_out_rule("utun100", LinuxExitNodeIpFamily::V6),
        vec![
            "FORWARD".to_string(),
            "-o".to_string(),
            "utun100".to_string(),
            "-m".to_string(),
            "conntrack".to_string(),
            "--ctstate".to_string(),
            "RELATED,ESTABLISHED".to_string(),
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            "nvpn-exit6-forward-out".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    );
}

#[test]
fn linux_exit_node_source_cidr_uses_full_auto_mesh_range() {
    assert_eq!(
        linux_exit_node_source_cidr("10.44.183.163/32"),
        Some("10.44.0.0/16".to_string())
    );
}

#[test]
fn linux_exit_node_source_cidr_preserves_custom_non_mesh_prefixes() {
    assert_eq!(
        linux_exit_node_source_cidr("10.55.7.9/32"),
        Some("10.55.7.0/24".to_string())
    );
}

#[test]
fn parse_exit_node_arg_normalizes_and_clears() {
    let peer = Keys::generate();
    let peer_hex = peer.public_key().to_hex();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");

    assert_eq!(
        parse_exit_node_arg(&peer_npub).expect("parse exit node"),
        Some(peer_hex)
    );
    assert_eq!(parse_exit_node_arg("off").expect("clear"), None);
    assert_eq!(parse_exit_node_arg("none").expect("clear"), None);
    assert_eq!(parse_exit_node_arg("").expect("clear"), None);
}

#[test]
fn runtime_local_signal_endpoint_prefers_detected_ipv4_for_private_configured_endpoint() {
    assert_eq!(
        runtime_local_signal_endpoint(
            "192.168.178.55:51820",
            52000,
            Some(Ipv4Addr::new(172, 20, 10, 2)),
        ),
        "172.20.10.2:52000"
    );
    assert_eq!(
        runtime_local_signal_endpoint(
            "127.0.0.1:51820",
            52000,
            Some(Ipv4Addr::new(172, 20, 10, 2)),
        ),
        "172.20.10.2:52000"
    );
}

#[test]
fn runtime_local_signal_endpoint_prefers_detected_ipv4_for_cgnat_configured_endpoint() {
    assert_eq!(
        runtime_local_signal_endpoint(
            "100.110.224.101:51820",
            52000,
            Some(Ipv4Addr::new(192, 168, 178, 80)),
        ),
        "192.168.178.80:52000"
    );
}

#[test]
fn runtime_local_signal_endpoint_keeps_public_configured_endpoint() {
    assert_eq!(
        runtime_local_signal_endpoint(
            "93.184.216.34:51820",
            52000,
            Some(Ipv4Addr::new(172, 20, 10, 2)),
        ),
        "93.184.216.34:52000"
    );
}

#[test]
fn runtime_signal_ipv4_ignores_tunnel_address() {
    assert_eq!(
        runtime_signal_ipv4(Some(Ipv4Addr::new(10, 44, 110, 128)), "10.44.110.128/32"),
        None
    );
    assert_eq!(
        runtime_signal_ipv4(Some(Ipv4Addr::new(192, 168, 178, 80)), "10.44.110.128/32"),
        Some(Ipv4Addr::new(192, 168, 178, 80))
    );
}

#[test]
fn public_endpoint_for_listen_port_requires_matching_discovery_port() {
    let endpoint = DiscoveredPublicSignalEndpoint {
        listen_port: 51820,
        endpoint: "198.51.100.20:43127".to_string(),
    };

    assert_eq!(
        public_endpoint_for_listen_port(Some(&endpoint), 51820),
        Some("198.51.100.20:43127".to_string())
    );
    assert_eq!(
        public_endpoint_for_listen_port(Some(&endpoint), 51821),
        None
    );
}

#[test]
fn mapped_public_signal_endpoint_rejects_cgnat_address() {
    assert_eq!(
        public_signal_endpoint_from_mapping(51820, "100.99.218.131:51821".to_string()),
        None
    );
}

#[test]
fn mapped_public_signal_endpoint_accepts_public_address() {
    assert_eq!(
        public_signal_endpoint_from_mapping(51820, "198.51.100.20:51821".to_string()),
        Some(DiscoveredPublicSignalEndpoint {
            listen_port: 51820,
            endpoint: "198.51.100.20:51821".to_string(),
        })
    );
}

#[test]
fn peer_announcement_includes_effective_advertised_routes() {
    let mut config = AppConfig::generated();
    config.node.advertise_exit_node = true;
    config.node.advertised_routes = vec!["10.0.0.0/24".to_string()];
    config.ensure_defaults();

    let announcement = build_peer_announcement(&config, 51820, None);

    #[cfg(target_os = "macos")]
    assert_eq!(
        announcement.advertised_routes,
        vec!["10.0.0.0/24".to_string(), "0.0.0.0/0".to_string()]
    );

    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        announcement.advertised_routes,
        vec![
            "10.0.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            "::/0".to_string(),
        ]
    );
}

#[test]
fn announcement_fingerprint_changes_when_routes_change() {
    let mut config = AppConfig::generated();
    let initial = build_peer_announcement(&config, 51820, None);
    let initial_fingerprint = announcement_fingerprint(&initial);

    config.node.advertise_exit_node = true;
    let updated = build_peer_announcement(&config, 51820, None);

    assert_ne!(initial_fingerprint, announcement_fingerprint(&updated));
}

#[test]
fn planned_tunnel_peers_assign_selected_exit_node_default_route() {
    let mut config = AppConfig::generated();
    let exit_participant = Keys::generate().public_key().to_hex();
    let routed_participant = Keys::generate().public_key().to_hex();
    config.networks[0].participants = vec![exit_participant.clone(), routed_participant.clone()];
    config.exit_node = exit_participant.clone();
    config.ensure_defaults();

    let announcements = HashMap::from([
        (
            exit_participant.clone(),
            PeerAnnouncement {
                node_id: "exit-node".to_string(),
                public_key: generate_keypair().public_key,
                endpoint: "203.0.113.20:51820".to_string(),
                local_endpoint: None,
                public_endpoint: Some("203.0.113.20:51820".to_string()),
                relay_endpoint: None,
                relay_pubkey: None,
                relay_expires_at: None,
                tunnel_ip: "10.44.0.2/32".to_string(),
                advertised_routes: vec![
                    "10.60.0.0/24".to_string(),
                    "0.0.0.0/0".to_string(),
                    "::/0".to_string(),
                ],
                timestamp: 1,
            },
        ),
        (
            routed_participant.clone(),
            PeerAnnouncement {
                node_id: "routed-node".to_string(),
                public_key: generate_keypair().public_key,
                endpoint: "203.0.113.21:51820".to_string(),
                local_endpoint: None,
                public_endpoint: Some("203.0.113.21:51820".to_string()),
                relay_endpoint: None,
                relay_pubkey: None,
                relay_expires_at: None,
                tunnel_ip: "10.44.0.3/32".to_string(),
                advertised_routes: vec!["10.70.0.0/24".to_string()],
                timestamp: 1,
            },
        ),
    ]);

    let planned = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("192.0.2.10:51820"),
        10,
    )
    .expect("planned tunnel peers");

    let exit_peer = planned
        .iter()
        .find(|planned| planned.participant == exit_participant)
        .expect("exit peer");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(
        exit_peer.peer.allowed_ips,
        vec![
            "10.44.0.2/32".to_string(),
            "0.0.0.0/0".to_string(),
            "10.60.0.0/24".to_string(),
        ]
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(
        exit_peer.peer.allowed_ips,
        vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
    );

    let routed_peer = planned
        .iter()
        .find(|planned| planned.participant == routed_participant)
        .expect("routed peer");
    assert_eq!(
        routed_peer.peer.allowed_ips,
        vec!["10.44.0.3/32".to_string(), "10.70.0.0/24".to_string()]
    );
}

#[test]
fn planned_tunnel_peers_ignore_default_route_without_selected_exit_node() {
    let mut config = AppConfig::generated();
    let exit_participant = Keys::generate().public_key().to_hex();
    config.networks[0].participants = vec![exit_participant.clone()];
    config.ensure_defaults();

    let announcements = HashMap::from([(
        exit_participant.clone(),
        PeerAnnouncement {
            node_id: "exit-node".to_string(),
            public_key: generate_keypair().public_key,
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string(), "10.60.0.0/24".to_string()],
            timestamp: 1,
        },
    )]);

    let planned = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("192.0.2.10:51820"),
        10,
    )
    .expect("planned tunnel peers");

    assert_eq!(
        planned[0].peer.allowed_ips,
        vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
    );
}

#[test]
fn linux_default_route_device_parser_extracts_interface() {
    assert_eq!(
        linux_default_route_device_from_output("default via 198.19.242.2 dev eth0 proto static\n"),
        Some("eth0".to_string())
    );
}

#[test]
fn linux_route_get_parser_extracts_gateway_interface_and_source() {
    let spec = linux_route_get_spec_from_output(
        "10.254.241.10 via 198.19.242.2 dev eth0 src 198.19.242.3 uid 0\n    cache\n",
    )
    .expect("linux route get spec");

    assert_eq!(spec.gateway.as_deref(), Some("198.19.242.2"));
    assert_eq!(spec.dev, "eth0");
    assert_eq!(spec.src.as_deref(), Some("198.19.242.3"));
}

#[test]
fn reuses_running_listen_port_without_rebind() {
    assert!(can_reuse_active_listen_port(true, true, Some(51820), 51820));
    assert!(!can_reuse_active_listen_port(
        true,
        true,
        Some(51820),
        51821
    ));
    assert!(!can_reuse_active_listen_port(
        false,
        true,
        Some(51820),
        51820
    ));
    assert!(!can_reuse_active_listen_port(
        true,
        false,
        Some(51820),
        51820
    ));
    assert!(!can_reuse_active_listen_port(true, true, None, 51820));
}

#[test]
fn tunnel_heartbeat_targets_only_include_peers_without_handshake() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: None,
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);

    let pending = pending_tunnel_heartbeat_ips(&config, None, &announcements, None);
    assert_eq!(pending, vec![Ipv4Addr::new(10, 44, 0, 2)]);

    let runtime_peers = HashMap::from([(
        key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
        WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(1),
            last_handshake_nsec: Some(0),
            ..WireGuardPeerStatus::default()
        },
    )]);
    let pending = pending_tunnel_heartbeat_ips(&config, None, &announcements, Some(&runtime_peers));
    assert!(pending.is_empty(), "handshaken peer should not be probed");
}

#[test]
fn tunnel_heartbeat_targets_include_peers_with_stale_handshakes() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: None,
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);
    let runtime_peers = HashMap::from([(
        key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
        WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(PEER_ONLINE_GRACE_SECS + 1),
            last_handshake_nsec: Some(0),
            ..WireGuardPeerStatus::default()
        },
    )]);

    let pending = pending_tunnel_heartbeat_ips(&config, None, &announcements, Some(&runtime_peers));
    assert_eq!(
        pending,
        vec![Ipv4Addr::new(10, 44, 0, 2)],
        "stale peers should still get tunnel heartbeats"
    );
}

#[test]
fn relay_connection_action_reconnects_only_when_disconnected() {
    assert_eq!(
        relay_connection_action(true),
        crate::RelayConnectionAction::KeepConnected
    );
    assert_eq!(
        relay_connection_action(false),
        crate::RelayConnectionAction::ReconnectWhenDue
    );
}

#[test]
fn runtime_magic_dns_records_prefer_live_announcement_tunnel_ip() {
    let mut config = AppConfig::generated();
    config.magic_dns_suffix = "nvpn".to_string();
    config.networks[0].participants =
        vec!["3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string()];
    config.ensure_defaults();
    config
        .set_peer_alias(
            "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645",
            "pig",
        )
        .expect("set alias");

    let mut announcements = HashMap::new();
    announcements.insert(
        "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
        PeerAnnouncement {
            node_id: "peer-node".to_string(),
            public_key: "pubkey".to_string(),
            endpoint: "192.168.1.55:51820".to_string(),
            local_endpoint: None,
            public_endpoint: None,
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.113/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 1,
        },
    );

    let records = build_runtime_magic_dns_records(&config, &announcements);
    assert_eq!(
        records.get("pig.nvpn").map(|ip| ip.to_string()),
        Some("10.44.0.113".to_string())
    );
    assert_eq!(
        records.get("pig").map(|ip| ip.to_string()),
        Some("10.44.0.113".to_string())
    );
}

#[test]
fn runtime_magic_dns_records_follow_latest_announcement_ip() {
    let mut config = AppConfig::generated();
    config.magic_dns_suffix = "nvpn".to_string();
    config.networks[0].participants =
        vec!["3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string()];
    config.ensure_defaults();
    config
        .set_peer_alias(
            "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645",
            "pig",
        )
        .expect("set alias");

    let mut announcements = HashMap::new();
    announcements.insert(
        "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
        PeerAnnouncement {
            node_id: "peer-node".to_string(),
            public_key: "pubkey".to_string(),
            endpoint: "192.168.1.55:51820".to_string(),
            local_endpoint: None,
            public_endpoint: None,
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.113/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 1,
        },
    );
    let first = build_runtime_magic_dns_records(&config, &announcements);
    assert_eq!(
        first.get("pig.nvpn").map(|ip| ip.to_string()),
        Some("10.44.0.113".to_string())
    );

    announcements.insert(
        "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
        PeerAnnouncement {
            node_id: "peer-node".to_string(),
            public_key: "pubkey".to_string(),
            endpoint: "192.168.1.55:51820".to_string(),
            local_endpoint: None,
            public_endpoint: None,
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.114/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 2,
        },
    );
    let second = build_runtime_magic_dns_records(&config, &announcements);
    assert_eq!(
        second.get("pig.nvpn").map(|ip| ip.to_string()),
        Some("10.44.0.114".to_string())
    );
}
