use nostr_vpn_core::control::PeerAnnouncement;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::SignalPayload;

fn announcement(node_id: &str, endpoint: &str, timestamp: u64) -> PeerAnnouncement {
    PeerAnnouncement {
        node_id: node_id.to_string(),
        public_key: "pk1".to_string(),
        endpoint: endpoint.to_string(),
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        timestamp,
    }
}

#[test]
fn newer_announce_replaces_active_peer_state() {
    let mut presence = PeerPresenceBook::default();

    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "1.2.3.4:51820", 1)),
        10,
    ));
    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "9.9.9.9:51820", 3)),
        20,
    ));

    let active = presence.active();
    let peer = active.get("peer-a").expect("peer should be active");
    assert_eq!(peer.endpoint, "9.9.9.9:51820");
    assert_eq!(presence.last_seen_at("peer-a"), Some(20));
}

#[test]
fn older_announce_keeps_existing_state_but_refreshes_liveness() {
    let mut presence = PeerPresenceBook::default();

    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "9.9.9.9:51820", 3)),
        10,
    ));
    assert!(!presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "1.2.3.4:51820", 1)),
        20,
    ));

    let active = presence.active();
    let peer = active.get("peer-a").expect("peer should be active");
    assert_eq!(peer.endpoint, "9.9.9.9:51820");
    assert_eq!(presence.last_seen_at("peer-a"), Some(20));
}

#[test]
fn disconnect_removes_active_peer_but_preserves_last_seen() {
    let mut presence = PeerPresenceBook::default();

    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "9.9.9.9:51820", 3)),
        10,
    ));
    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Disconnect {
            node_id: "node-a".to_string(),
        },
        15,
    ));

    assert!(presence.active().get("peer-a").is_none());
    assert_eq!(presence.last_seen_at("peer-a"), Some(15));
}

#[test]
fn hello_refreshes_liveness_without_replacing_active_peer_state() {
    let mut presence = PeerPresenceBook::default();

    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "9.9.9.9:51820", 3)),
        10,
    ));
    assert!(!presence.apply_signal("peer-a", SignalPayload::Hello, 25));

    let active = presence.active();
    let peer = active.get("peer-a").expect("peer should remain active");
    assert_eq!(peer.endpoint, "9.9.9.9:51820");
    assert_eq!(presence.last_seen_at("peer-a"), Some(25));
}

#[test]
fn stale_peers_are_pruned_from_active_presence() {
    let mut presence = PeerPresenceBook::default();

    assert!(presence.apply_signal(
        "peer-a",
        SignalPayload::Announce(announcement("node-a", "9.9.9.9:51820", 3)),
        10,
    ));
    assert!(presence.apply_signal(
        "peer-b",
        SignalPayload::Announce(announcement("node-b", "8.8.8.8:51820", 4)),
        30,
    ));

    let removed = presence.prune_stale(41, 15);
    assert_eq!(removed, vec!["peer-a".to_string()]);
    assert!(presence.active().get("peer-a").is_none());
    assert!(presence.active().get("peer-b").is_some());
    assert_eq!(presence.last_seen_at("peer-a"), Some(10));
    assert_eq!(presence.last_seen_at("peer-b"), Some(30));
}
