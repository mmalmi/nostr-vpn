use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use crate::*;

pub(crate) fn sample_peer_announcement(public_key: String) -> PeerAnnouncement {
    PeerAnnouncement {
        node_id: "peer-a".to_string(),
        public_key,
        endpoint: "203.0.113.20:51820".to_string(),
        local_endpoint: Some("192.168.1.20:51820".to_string()),
        public_endpoint: Some("203.0.113.20:51820".to_string()),
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: "10.44.0.2/32".to_string(),
        advertised_routes: Vec::new(),
        timestamp: 1,
    }
}

pub(crate) fn local_endpoints(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

pub(crate) fn control_daemon_request_for_test(config: &Path, request: crate::DaemonControlRequest) {
    crate::write_daemon_control_request(config, request).expect("write control request");
}

pub(crate) fn build_peer_announcement(
    app: &AppConfig,
    listen_port: u16,
    public_endpoint: Option<&str>,
) -> PeerAnnouncement {
    let local_endpoint = crate::local_signal_endpoint(app, listen_port);
    let public_endpoint = public_endpoint
        .map(str::to_string)
        .filter(|value| value != &local_endpoint);
    let endpoint = public_endpoint
        .clone()
        .unwrap_or_else(|| local_endpoint.clone());

    PeerAnnouncement {
        node_id: app.node.id.clone(),
        public_key: app.node.public_key.clone(),
        endpoint,
        local_endpoint: Some(local_endpoint),
        public_endpoint,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: app.node.tunnel_ip.clone(),
        advertised_routes: crate::runtime_effective_advertised_routes(app),
        timestamp: crate::unix_timestamp(),
    }
}

pub(crate) fn planned_tunnel_peers(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    own_local_endpoint: Option<&str>,
    now: u64,
) -> Result<Vec<PlannedTunnelPeer>> {
    let own_local_endpoints = own_local_endpoint
        .map(|value| vec![value.to_string()])
        .unwrap_or_default();
    crate::planned_tunnel_peers_for_local_endpoints(
        app,
        own_pubkey,
        peer_announcements,
        path_book,
        &own_local_endpoints,
        now,
    )
}

pub(crate) fn nat_punch_targets(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    listen_port: u16,
) -> Vec<SocketAddr> {
    let own_local_endpoints = crate::runtime_local_signal_endpoints(app, listen_port);
    nat_punch_targets_for_local_endpoints(app, own_pubkey, peer_announcements, &own_local_endpoints)
}

pub(crate) fn nat_punch_targets_for_local_endpoint(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    own_local_endpoint: &str,
) -> Vec<SocketAddr> {
    nat_punch_targets_for_local_endpoints(
        app,
        own_pubkey,
        peer_announcements,
        &[own_local_endpoint.to_string()],
    )
}

pub(crate) fn pending_nat_punch_targets_for_local_endpoint(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    own_local_endpoint: &str,
) -> Vec<SocketAddr> {
    pending_nat_punch_targets_for_local_endpoint_with_paths(
        app,
        own_pubkey,
        peer_announcements,
        &PeerPathBook::default(),
        runtime_peers,
        own_local_endpoint,
    )
}

pub(crate) fn pending_nat_punch_targets_for_local_endpoint_with_paths(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &PeerPathBook,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    own_local_endpoint: &str,
) -> Vec<SocketAddr> {
    pending_nat_punch_targets_for_local_endpoints(
        app,
        own_pubkey,
        peer_announcements,
        path_book,
        runtime_peers,
        &[own_local_endpoint.to_string()],
    )
}

pub(crate) fn nat_punch_targets_for_local_endpoints(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    own_local_endpoints: &[String],
) -> Vec<SocketAddr> {
    let mut targets = app
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| peer_announcements.get(participant))
        .filter_map(|announcement| {
            let selected_endpoint =
                crate::select_peer_endpoint_from_local_endpoints(announcement, own_local_endpoints);
            if crate::peer_endpoint_requires_public_signal(
                app,
                announcement,
                &selected_endpoint,
                own_local_endpoints,
            ) {
                return None;
            }

            if own_local_endpoints.iter().any(|own_local_endpoint| {
                crate::endpoints_share_local_only_ipv4_subnet(
                    &selected_endpoint,
                    own_local_endpoint,
                )
            }) {
                return None;
            }

            selected_endpoint.parse::<SocketAddr>().ok()
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
}

pub(crate) fn pending_nat_punch_targets_for_local_endpoints(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &PeerPathBook,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    own_local_endpoints: &[String],
) -> Vec<SocketAddr> {
    let now = crate::unix_timestamp();
    let selected_exit_node =
        crate::selected_exit_node_participant(app, own_pubkey, peer_announcements);
    let mesh_has_recent_handshake_peer =
        crate::mesh_has_recent_handshake_peer(app, own_pubkey, peer_announcements, runtime_peers);
    let mut targets = app
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| {
            let announcement = peer_announcements.get(participant)?;
            let effective_announcement = announcement.without_expired_relay(now);
            if crate::peer_runtime_lookup(announcement, runtime_peers)
                .is_some_and(crate::peer_has_recent_handshake)
            {
                return None;
            }

            if mesh_has_recent_handshake_peer
                && !crate::stale_peer_requires_disruptive_nat_punch(
                    participant,
                    selected_exit_node.as_deref(),
                )
            {
                return None;
            }

            let selected_endpoint = path_book
                .select_endpoint_for_local_endpoints(
                    participant,
                    &effective_announcement,
                    own_local_endpoints,
                    now,
                    crate::PEER_PATH_RETRY_AFTER_SECS,
                )
                .unwrap_or_else(|| {
                    crate::select_peer_endpoint_from_local_endpoints(
                        &effective_announcement,
                        own_local_endpoints,
                    )
                });
            if crate::peer_endpoint_requires_public_signal(
                app,
                &effective_announcement,
                &selected_endpoint,
                own_local_endpoints,
            ) {
                return None;
            }

            if own_local_endpoints.iter().any(|own_local_endpoint| {
                crate::endpoints_share_local_only_ipv4_subnet(
                    &selected_endpoint,
                    own_local_endpoint,
                )
            }) {
                return None;
            }

            selected_endpoint.parse::<SocketAddr>().ok()
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
}

pub(crate) fn macos_route_get_spec_from_output(output: &str) -> Option<crate::MacosRouteSpec> {
    crate::macos_network::macos_route_get_spec_from_output(output)
}

pub(crate) fn macos_default_routes_from_netstat(output: &str) -> Vec<crate::MacosRouteSpec> {
    crate::macos_network::macos_default_routes_from_netstat(output)
}

pub(crate) fn macos_ifconfig_has_ipv4(output: &str, needle: Ipv4Addr) -> bool {
    crate::macos_network::macos_ifconfig_has_ipv4(output, needle)
}
