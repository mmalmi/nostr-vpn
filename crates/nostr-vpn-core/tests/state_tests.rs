use nostr_vpn_core::control::{PeerAnnouncement, PeerDirectory, select_peer_endpoint};

#[test]
fn newest_peer_announcement_wins() {
    let mut peers = PeerDirectory::default();

    peers.apply(PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    });

    peers.apply(PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "9.9.9.9:51820".to_string(),
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 3,
    });

    peers.apply(PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "4.4.4.4:51820".to_string(),
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 2,
    });

    let peer = peers.get("peer-a").expect("peer should exist");
    assert_eq!(peer.endpoint, "9.9.9.9:51820");
}

#[test]
fn peer_can_be_removed() {
    let mut peers = PeerDirectory::default();

    peers.apply(PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    });

    let removed = peers.remove("peer-a");
    assert!(removed.is_some());
    assert!(peers.get("peer-a").is_none());
}

#[test]
fn peer_endpoint_prefers_public_for_remote_peers() {
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    };

    assert_eq!(
        select_peer_endpoint(&announcement, Some("192.168.88.15:51820")),
        "203.0.113.20:51820"
    );
}

#[test]
fn peer_endpoint_prefers_local_for_same_lan_peers() {
    let announcement = PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    };

    assert_eq!(
        select_peer_endpoint(&announcement, Some("192.168.1.33:51820")),
        "192.168.1.20:51820"
    );
}
