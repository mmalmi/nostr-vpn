use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::*;

use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::paths::PeerPathBook;

use super::super::local_endpoints;

#[test]
fn runtime_handshake_updates_path_cache() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement.clone())]);
    let mut paths = PeerPathBook::default();
    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut paths,
        Some("192.168.1.33:51820"),
        10,
    )
    .expect("initial tunnel peers");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "192.168.1.20:51820");
    paths.note_selected(&participant, &selected[0].endpoint, 10);

    let runtime_peers = HashMap::from([(
        key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
        WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(1),
            last_handshake_nsec: Some(0),
            ..WireGuardPeerStatus::default()
        },
    )]);
    assert!(record_successful_runtime_paths(
        &announcements,
        Some(&runtime_peers),
        &mut paths,
        &["192.168.1.33:51820".to_string()],
        16,
    ));

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut paths,
        Some("192.168.1.33:51820"),
        16,
    )
    .expect("tunnel peers after handshake");
    assert_eq!(selected[0].endpoint, "203.0.113.20:51820");
}

#[test]
fn successful_local_path_rotates_to_public_after_network_change() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.networks[0].participants = vec![participant.clone()];

    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);
    let mut paths = PeerPathBook::default();

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut paths,
        Some("192.168.1.33:51820"),
        10,
    )
    .expect("initial tunnel peers");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "192.168.1.20:51820");
    paths.note_selected(&participant, &selected[0].endpoint, 10);
    assert!(paths.note_success(participant.clone(), &selected[0].endpoint, 11));

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut paths,
        Some("172.20.10.7:51820"),
        12,
    )
    .expect("tunnel peers after network change");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "203.0.113.20:51820");
}

#[test]
fn runtime_endpoint_refresh_requires_cross_subnet_local_drift() {
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "10.254.241.10:51820".to_string(),
        local_endpoint: Some("198.19.241.3:51820".to_string()),
        public_endpoint: Some("10.254.241.10:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: vec!["0.0.0.0/0".to_string()],
        timestamp: 10,
    };

    assert!(runtime_endpoint_requires_refresh(
        "198.19.241.3:51820",
        "10.254.241.10:51820",
        &announcement,
        &["198.19.242.3:51820".to_string()],
    ));
    assert!(!runtime_endpoint_requires_refresh(
        "198.19.241.3:51820",
        "10.254.241.10:51820",
        &announcement,
        &["198.19.241.4:51820".to_string()],
    ));
    assert!(runtime_endpoint_requires_refresh(
        "198.19.242.1:6861",
        "10.254.241.10:51820",
        &announcement,
        &["198.19.242.3:51820".to_string()],
    ));
    assert!(!runtime_endpoint_requires_refresh(
        "203.0.113.20:51820",
        "10.254.241.10:51820",
        &announcement,
        &["198.19.242.3:51820".to_string()],
    ));
}

#[test]
fn runtime_endpoint_refresh_skips_same_subnet_gateway_translation_for_public_peer() {
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "89.27.103.157:51820".to_string(),
        local_endpoint: Some("192.168.178.80:51820".to_string()),
        public_endpoint: Some("89.27.103.157:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: vec!["0.0.0.0/0".to_string()],
        timestamp: 10,
    };

    assert!(!runtime_endpoint_requires_refresh(
        "192.168.64.1:51820",
        "89.27.103.157:51820",
        &announcement,
        &["192.168.64.2:51820".to_string()],
    ));
    assert!(runtime_endpoint_requires_refresh(
        "192.168.64.1:6861",
        "89.27.103.157:51820",
        &announcement,
        &["192.168.64.2:51820".to_string()],
    ));
}

#[test]
fn record_successful_runtime_paths_ignores_cross_subnet_local_runtime_endpoint() {
    let participant = "11".repeat(32);
    let peer_keys = generate_keypair();
    let announcements = HashMap::from([(
        participant,
        PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "10.254.241.10:51820".to_string(),
            local_endpoint: Some("198.19.241.3:51820".to_string()),
            public_endpoint: Some("10.254.241.10:51820".to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: vec!["0.0.0.0/0".to_string()],
            timestamp: 10,
        },
    )]);
    let runtime_peers = HashMap::from([(
        key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
        WireGuardPeerStatus {
            endpoint: Some("198.19.241.3:51820".to_string()),
            last_handshake_sec: Some(1),
            last_handshake_nsec: Some(0),
            ..WireGuardPeerStatus::default()
        },
    )]);
    let mut paths = PeerPathBook::default();

    assert!(!record_successful_runtime_paths(
        &announcements,
        Some(&runtime_peers),
        &mut paths,
        &["198.19.242.3:51820".to_string()],
        12,
    ));
}

#[test]
fn runtime_peer_endpoint_refresh_waits_for_handshake() {
    let participant = "11".repeat(32);
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "10.254.241.10:51820".to_string(),
        local_endpoint: Some("198.19.241.3:51820".to_string()),
        public_endpoint: Some("10.254.241.10:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: vec!["0.0.0.0/0".to_string()],
        timestamp: 10,
    };
    let planned = vec![PlannedTunnelPeer {
        participant: participant.clone(),
        endpoint: "10.254.241.10:51820".to_string(),
        peer: TunnelPeer {
            pubkey_hex: key_b64_to_hex(&announcement.public_key).expect("peer pubkey hex"),
            endpoint: "10.254.241.10:51820".to_string(),
            allowed_ips: vec!["10.44.0.2/32".to_string()],
        },
    }];
    let announcements = HashMap::from([(participant, announcement)]);
    let runtime_peers = HashMap::from([(
        planned[0].peer.pubkey_hex.clone(),
        WireGuardPeerStatus {
            endpoint: Some("198.19.241.3:51820".to_string()),
            last_handshake_sec: None,
            last_handshake_nsec: None,
            ..WireGuardPeerStatus::default()
        },
    )]);

    assert!(!runtime_peer_endpoints_require_refresh(
        &planned,
        &announcements,
        Some(&runtime_peers),
        &["198.19.242.3:51820".to_string()],
    ));
}

#[test]
fn cached_successful_endpoint_survives_announcement_flap_until_path_cache_expires() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.nat.enabled = false;
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let original = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let flapped = PeerAnnouncement {
        public_endpoint: None,
        endpoint: "192.168.1.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        timestamp: 20,
        ..original.clone()
    };

    let mut paths = PeerPathBook::default();
    let original_announcements = HashMap::from([(participant.clone(), original)]);
    let runtime_peers = HashMap::from([(
        key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
        WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(1),
            last_handshake_nsec: Some(0),
            ..WireGuardPeerStatus::default()
        },
    )]);
    assert!(record_successful_runtime_paths(
        &original_announcements,
        Some(&runtime_peers),
        &mut paths,
        &["10.0.0.33:51820".to_string()],
        12,
    ));

    let flapped_announcements = HashMap::from([(participant.clone(), flapped.clone())]);
    let selected = planned_tunnel_peers(
        &config,
        None,
        &flapped_announcements,
        &mut paths,
        Some("10.0.0.33:51820"),
        21,
    )
    .expect("cached tunnel peers");
    assert_eq!(selected[0].endpoint, "203.0.113.20:51820");

    paths.prune_stale(200, peer_path_cache_timeout_secs(5));

    let selected = planned_tunnel_peers(
        &config,
        None,
        &flapped_announcements,
        &mut paths,
        Some("10.0.0.33:51820"),
        200,
    )
    .expect("fallback tunnel peers");
    assert_eq!(selected[0].endpoint, "192.168.1.20:51820");
}

#[test]
fn nat_remote_peer_waits_for_public_endpoint_before_runtime_apply() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.nat.enabled = true;
    config.node.endpoint = "198.19.241.3:51820".to_string();
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "198.19.242.3:51820".to_string(),
        local_endpoint: Some("198.19.242.3:51820".to_string()),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("198.19.241.3:51820"),
        10,
    )
    .expect("planned tunnel peers");
    assert!(selected.is_empty());
    assert!(nat_punch_targets(&config, None, &announcements, 51820).is_empty());
}

#[test]
fn nat_same_subnet_peer_can_use_local_endpoint_without_public_signal() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.nat.enabled = true;
    config.node.endpoint = "198.19.241.3:51820".to_string();
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "198.19.241.11:51820".to_string(),
        local_endpoint: Some("198.19.241.11:51820".to_string()),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some("198.19.241.3:51820"),
        10,
    )
    .expect("planned tunnel peers");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "198.19.241.11:51820");
    assert!(
        nat_punch_targets_for_local_endpoint(&config, None, &announcements, "198.19.241.3:51820")
            .is_empty(),
        "same-subnet peer should not trigger nat punch"
    );
}

#[test]
fn nat_punch_targets_keep_stale_exit_peer_even_when_another_peer_is_online() {
    let mut config = AppConfig::generated();
    let online = "11".repeat(32);
    let stale = "22".repeat(32);
    config.nat.enabled = true;
    config.node.endpoint = "198.19.241.3:51820".to_string();
    config.networks[0].participants = vec![online.clone(), stale.clone()];

    let online_keys = generate_keypair();
    let stale_keys = generate_keypair();
    let announcements = HashMap::from([
        (
            online.clone(),
            PeerAnnouncement {
                node_id: "peer-online".to_string(),
                public_key: online_keys.public_key.clone(),
                endpoint: "203.0.113.20:51820".to_string(),
                local_endpoint: None,
                public_endpoint: Some("203.0.113.20:51820".to_string()),
                relay_endpoint: None,
                relay_pubkey: None,
                relay_expires_at: None,
                tunnel_ip: "10.44.0.2/32".to_string(),
                advertised_routes: Vec::new(),
                timestamp: 10,
            },
        ),
        (
            stale.clone(),
            PeerAnnouncement {
                node_id: "peer-stale".to_string(),
                public_key: stale_keys.public_key.clone(),
                endpoint: "203.0.113.21:51820".to_string(),
                local_endpoint: None,
                public_endpoint: Some("203.0.113.21:51820".to_string()),
                relay_endpoint: None,
                relay_pubkey: None,
                relay_expires_at: None,
                tunnel_ip: "10.44.0.3/32".to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                timestamp: 10,
            },
        ),
    ]);
    let runtime_peers = HashMap::from([
        (
            key_b64_to_hex(&online_keys.public_key).expect("online peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.20:51820".to_string()),
                last_handshake_sec: Some(1),
                last_handshake_nsec: Some(0),
                ..WireGuardPeerStatus::default()
            },
        ),
        (
            key_b64_to_hex(&stale_keys.public_key).expect("stale peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.21:51820".to_string()),
                last_handshake_sec: Some(PEER_ONLINE_GRACE_SECS + 1),
                last_handshake_nsec: Some(0),
                ..WireGuardPeerStatus::default()
            },
        ),
    ]);

    assert_eq!(
        pending_nat_punch_targets_for_local_endpoint(
            &config,
            None,
            &announcements,
            Some(&runtime_peers),
            "198.19.241.3:51820",
        ),
        vec!["203.0.113.21:51820".parse().expect("socket addr")],
        "a reachable peer should not suppress NAT punching for a stale exit peer"
    );
}

#[test]
fn cgnat_configured_host_endpoint_still_plans_same_lan_peer() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.nat.enabled = true;
    config.node.endpoint = "100.110.224.101:51820".to_string();
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "192.168.178.44:51820".to_string(),
        local_endpoint: Some("192.168.178.44:51820".to_string()),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.1.158/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);
    let own_local_endpoint = runtime_local_signal_endpoint(
        &config.node.endpoint,
        51820,
        Some(Ipv4Addr::new(192, 168, 178, 80)),
    );

    let selected = planned_tunnel_peers(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        Some(&own_local_endpoint),
        10,
    )
    .expect("planned tunnel peers");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "192.168.178.44:51820");
    assert!(
        nat_punch_targets_for_local_endpoint(&config, None, &announcements, &own_local_endpoint)
            .is_empty(),
        "same-lan peer should not trigger nat punch when local endpoint is known"
    );
}

#[test]
fn secondary_local_subnet_peer_is_planned_without_public_signal() {
    let mut config = AppConfig::generated();
    let participant = "11".repeat(32);
    config.nat.enabled = true;
    config.node.endpoint = "192.168.178.80:51820".to_string();
    config.networks[0].participants = vec![participant.clone()];

    let peer_keys = generate_keypair();
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: peer_keys.public_key.clone(),
        endpoint: "10.211.55.3:51820".to_string(),
        local_endpoint: Some("10.211.55.3:51820".to_string()),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.199.77/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let announcements = HashMap::from([(participant.clone(), announcement)]);
    let own_local_endpoints = local_endpoints(&["192.168.178.80:51820", "10.211.55.2:51820"]);

    let selected = planned_tunnel_peers_for_local_endpoints(
        &config,
        None,
        &announcements,
        &mut PeerPathBook::default(),
        &own_local_endpoints,
        10,
    )
    .expect("planned tunnel peers");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].endpoint, "10.211.55.3:51820");
    assert!(
        nat_punch_targets_for_local_endpoints(&config, None, &announcements, &own_local_endpoints)
            .is_empty(),
        "peer reachable on a secondary local subnet should not require nat punch"
    );
}

#[test]
fn explicit_announcement_keeps_local_endpoint_for_private_override() {
    let announcement = crate::build_explicit_peer_announcement(
        "peer-a".to_string(),
        generate_keypair().public_key,
        "10.211.55.3:51820".to_string(),
        "10.211.55.3:51820".to_string(),
        "10.44.199.77/32".to_string(),
        Vec::new(),
    );

    assert_eq!(announcement.endpoint, "10.211.55.3:51820");
    assert_eq!(
        announcement.local_endpoint.as_deref(),
        Some("10.211.55.3:51820")
    );
    assert!(announcement.public_endpoint.is_none());
}

#[test]
fn explicit_announcement_keeps_public_and_local_endpoints_separate() {
    let announcement = crate::build_explicit_peer_announcement(
        "peer-a".to_string(),
        generate_keypair().public_key,
        "203.0.113.20:51820".to_string(),
        "192.168.178.80:51820".to_string(),
        "10.44.0.239/32".to_string(),
        Vec::new(),
    );

    assert_eq!(announcement.endpoint, "203.0.113.20:51820");
    assert_eq!(
        announcement.local_endpoint.as_deref(),
        Some("192.168.178.80:51820")
    );
    assert_eq!(
        announcement.public_endpoint.as_deref(),
        Some("203.0.113.20:51820")
    );
}

#[test]
fn explicit_announcement_preserves_reflected_private_endpoint_from_distinct_subnet() {
    let announcement = crate::build_explicit_peer_announcement(
        "peer-a".to_string(),
        generate_keypair().public_key,
        "10.254.241.10:51820".to_string(),
        "198.19.241.3:51820".to_string(),
        "10.44.0.239/32".to_string(),
        Vec::new(),
    );

    assert_eq!(announcement.endpoint, "10.254.241.10:51820");
    assert_eq!(
        announcement.local_endpoint.as_deref(),
        Some("198.19.241.3:51820")
    );
    assert_eq!(
        announcement.public_endpoint.as_deref(),
        Some("10.254.241.10:51820")
    );
}

#[test]
fn matching_peer_subnet_selects_secondary_local_signal_endpoint() {
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: generate_keypair().public_key,
        endpoint: "10.211.55.3:51820".to_string(),
        local_endpoint: Some("10.211.55.3:51820".to_string()),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.199.77/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 10,
    };
    let own_local_endpoints = local_endpoints(&[
        "192.168.178.80:51820",
        "10.211.55.2:51820",
        "10.37.129.2:51820",
    ]);

    assert_eq!(
        crate::select_local_signal_endpoint_for_peer(&announcement, &own_local_endpoints)
            .as_deref(),
        Some("10.211.55.2:51820")
    );
}
