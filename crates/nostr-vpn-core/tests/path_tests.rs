use nostr_vpn_core::control::PeerAnnouncement;
use nostr_vpn_core::paths::PeerPathBook;

fn announcement(
    endpoint: &str,
    local_endpoint: Option<&str>,
    public_endpoint: Option<&str>,
    timestamp: u64,
) -> PeerAnnouncement {
    PeerAnnouncement {
        node_id: "node-a".to_string(),
        public_key: "pk1".to_string(),
        endpoint: endpoint.to_string(),
        local_endpoint: local_endpoint.map(str::to_string),
        public_endpoint: public_endpoint.map(str::to_string),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp,
    }
}

#[test]
fn prefers_same_subnet_local_path_initially() {
    let mut paths = PeerPathBook::default();
    let announcement = announcement(
        "203.0.113.20:51820",
        Some("192.168.1.20:51820"),
        Some("203.0.113.20:51820"),
        10,
    );

    paths.refresh_from_announcement("peer-a", &announcement, 10);

    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 10, 5)
        .expect("path should be selected");

    assert_eq!(selected, "192.168.1.20:51820");
}

#[test]
fn rotates_to_successful_public_path_after_local_retry_window() {
    let mut paths = PeerPathBook::default();
    let announcement = announcement(
        "203.0.113.20:51820",
        Some("192.168.1.20:51820"),
        Some("203.0.113.20:51820"),
        10,
    );

    paths.refresh_from_announcement("peer-a", &announcement, 10);
    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 10, 5)
        .expect("initial path");
    assert_eq!(selected, "192.168.1.20:51820");
    paths.note_selected("peer-a", &selected, 10);

    paths.note_success("peer-a", "203.0.113.20:51820", 12);

    let before_retry = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 13, 5)
        .expect("path before retry window");
    assert_eq!(before_retry, "192.168.1.20:51820");

    let after_retry = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 16, 5)
        .expect("path after retry window");
    assert_eq!(after_retry, "203.0.113.20:51820");
}

#[test]
fn keeps_current_path_when_it_has_recent_success() {
    let mut paths = PeerPathBook::default();
    let announcement = announcement(
        "203.0.113.20:51820",
        Some("192.168.1.20:51820"),
        Some("203.0.113.20:51820"),
        10,
    );

    paths.refresh_from_announcement("peer-a", &announcement, 10);
    paths.note_selected("peer-a", "203.0.113.20:51820", 10);
    paths.note_success("peer-a", "203.0.113.20:51820", 15);

    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 20, 5)
        .expect("sticky successful path");

    assert_eq!(selected, "203.0.113.20:51820");
}

#[test]
fn successful_local_path_stops_sticking_after_subnet_change() {
    let mut paths = PeerPathBook::default();
    let announcement = announcement(
        "203.0.113.20:51820",
        Some("192.168.1.20:51820"),
        Some("203.0.113.20:51820"),
        10,
    );

    paths.refresh_from_announcement("peer-a", &announcement, 10);
    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("192.168.1.33:51820"), 10, 5)
        .expect("initial same-subnet local path");
    assert_eq!(selected, "192.168.1.20:51820");
    paths.note_selected("peer-a", &selected, 10);
    paths.note_success("peer-a", &selected, 11);

    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("172.20.10.7:51820"), 12, 5)
        .expect("public path after local subnet change");

    assert_eq!(selected, "203.0.113.20:51820");
}

#[test]
fn benchmark_net_local_path_stops_sticking_after_public_reflector_path_appears() {
    let mut paths = PeerPathBook::default();
    let announcement = announcement(
        "10.254.241.10:51820",
        Some("198.19.241.3:51820"),
        Some("10.254.241.10:51820"),
        10,
    );

    paths.refresh_from_announcement("peer-a", &announcement, 10);
    paths.note_selected("peer-a", "198.19.241.3:51820", 10);
    paths.note_success("peer-a", "198.19.241.3:51820", 11);

    let selected = paths
        .select_endpoint("peer-a", &announcement, Some("10.44.202.86:51820"), 12, 5)
        .expect("public reflector path after local-only route change");

    assert_eq!(selected, "10.254.241.10:51820");
}

#[test]
fn cached_endpoint_survives_flap_until_pruned() {
    let mut paths = PeerPathBook::default();
    let original = announcement(
        "203.0.113.20:51820",
        Some("192.168.1.20:51820"),
        Some("203.0.113.20:51820"),
        10,
    );
    paths.refresh_from_announcement("peer-a", &original, 10);
    paths.note_success("peer-a", "203.0.113.20:51820", 10);

    let flapped = announcement("192.168.1.20:51820", Some("192.168.1.20:51820"), None, 20);
    paths.refresh_from_announcement("peer-a", &flapped, 20);

    let cached = paths
        .select_endpoint("peer-a", &flapped, Some("10.0.0.33:51820"), 21, 5)
        .expect("cached public endpoint");
    assert_eq!(cached, "203.0.113.20:51820");

    paths.prune_stale(200, 30);

    let fallback = paths
        .select_endpoint("peer-a", &flapped, Some("10.0.0.33:51820"), 200, 5)
        .expect("fallback endpoint after prune");
    assert_eq!(fallback, "192.168.1.20:51820");
}

#[test]
fn fresh_public_signal_replaces_observed_same_host_different_port() {
    let mut paths = PeerPathBook::default();
    let original = announcement("203.0.113.20:51820", None, Some("203.0.113.20:51820"), 10);
    paths.refresh_from_announcement("peer-a", &original, 10);
    paths.note_selected("peer-a", "203.0.113.20:40001", 10);
    paths.note_success("peer-a", "203.0.113.20:40001", 11);

    let updated = announcement("203.0.113.20:51820", None, Some("203.0.113.20:51820"), 20);
    paths.refresh_from_announcement("peer-a", &updated, 20);

    let selected = paths
        .select_endpoint("peer-a", &updated, Some("10.0.0.33:51820"), 21, 5)
        .expect("updated public endpoint");
    assert_eq!(selected, "203.0.113.20:51820");
}
