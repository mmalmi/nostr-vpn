use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};
use nostr_vpn_core::config::{AppConfig, DEFAULT_RELAYS, normalize_advertised_route};
use nostr_vpn_core::control::{PeerAnnouncement, select_peer_endpoint};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload, SignalingNetwork};

use crate::PEER_ONLINE_GRACE_SECS;
use crate::android_session_runtime::{strip_cidr, unix_timestamp};

use super::{
    ANDROID_PUBLISH_TIMEOUT_SECS, ANDROID_SIGNAL_STALE_AFTER_SECS, ActiveTunnelTask,
    PlannedTunnelPeer, TunnelPeer,
};

pub(super) fn signaling_networks_for_app(app: &AppConfig) -> Vec<SignalingNetwork> {
    let networks = app
        .enabled_network_meshes()
        .into_iter()
        .map(|network| SignalingNetwork {
            network_id: network.network_id,
            participants: network.participants,
        })
        .collect::<Vec<_>>();

    if networks.is_empty() {
        return vec![SignalingNetwork {
            network_id: app.effective_network_id(),
            participants: app.participant_pubkeys_hex(),
        }];
    }

    networks
}

pub(super) fn expected_peer_count(config: &AppConfig) -> usize {
    let participants = config.participant_pubkeys_hex();
    if participants.is_empty() {
        return 0;
    }

    let mut expected = participants.len();
    if let Ok(own_pubkey) = config.own_nostr_pubkey_hex() {
        if participants
            .iter()
            .any(|participant| participant == &own_pubkey)
        {
            expected = expected.saturating_sub(1);
        }
    }

    expected
}

pub(super) fn resolve_relays(config: &AppConfig) -> Vec<String> {
    if !config.nostr.relays.is_empty() {
        return config.nostr.relays.clone();
    }

    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

pub(super) fn configured_recipients(config: &AppConfig, own_pubkey: Option<&str>) -> Vec<String> {
    config
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .collect()
}

pub(super) async fn publish_private_announce_to_all(
    client: &NostrSignalingClient,
    config: &AppConfig,
    listen_port: u16,
    recipients: &[String],
) -> Result<()> {
    if recipients.is_empty() {
        return Ok(());
    }

    client
        .publish_to(
            SignalPayload::Announce(build_peer_announcement(config, listen_port)),
            recipients,
        )
        .await
        .context("failed to publish mobile private announce")?;
    Ok(())
}

pub(super) async fn publish_private_announce_best_effort(
    client: &NostrSignalingClient,
    config: &AppConfig,
    listen_port: u16,
    recipients: &[String],
) {
    match tokio::time::timeout(
        Duration::from_secs(ANDROID_PUBLISH_TIMEOUT_SECS),
        publish_private_announce_to_all(client, config, listen_port, recipients),
    )
    .await
    {
        Ok(Ok(())) => eprintln!(
            "android-session: private announce published to {} recipient(s)",
            recipients.len()
        ),
        Ok(Err(error)) => eprintln!("android-session: private announce failed: {error:#}"),
        Err(_) => eprintln!(
            "android-session: private announce timed out after {}s",
            ANDROID_PUBLISH_TIMEOUT_SECS
        ),
    }
}

pub(super) async fn publish_hello_best_effort(client: &NostrSignalingClient) {
    match tokio::time::timeout(
        Duration::from_secs(ANDROID_PUBLISH_TIMEOUT_SECS),
        client.publish(SignalPayload::Hello),
    )
    .await
    {
        Ok(Ok(())) => eprintln!("android-session: hello published"),
        Ok(Err(error)) => eprintln!("android-session: hello publish failed: {error:#}"),
        Err(_) => eprintln!(
            "android-session: hello publish timed out after {}s",
            ANDROID_PUBLISH_TIMEOUT_SECS
        ),
    }
}

pub(super) fn build_peer_announcement(config: &AppConfig, listen_port: u16) -> PeerAnnouncement {
    let endpoint = local_signal_endpoint(config, listen_port);
    PeerAnnouncement {
        node_id: config.node.id.clone(),
        public_key: config.node.public_key.clone(),
        endpoint: endpoint.clone(),
        local_endpoint: Some(endpoint),
        public_endpoint: None,
        relay_endpoint: None,
        relay_pubkey: None,
        relay_expires_at: None,
        tunnel_ip: config.node.tunnel_ip.clone(),
        advertised_routes: config.effective_advertised_routes(),
        timestamp: unix_timestamp(),
    }
}

pub(super) fn planned_tunnel_peers(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    own_local_endpoint: Option<&str>,
    now: u64,
) -> Result<Vec<PlannedTunnelPeer>> {
    let configured_participants = config.participant_pubkeys_hex();
    let route_assignments = advertised_route_assignments(config, own_pubkey, peer_announcements);
    let configured_set = configured_participants
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .cloned()
        .collect::<HashSet<_>>();
    path_book.retain_participants(&configured_set);

    let mut peers = Vec::new();
    for participant in configured_participants
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
    {
        let Some(announcement) = peer_announcements.get(participant) else {
            continue;
        };
        path_book.refresh_from_announcement(participant.clone(), announcement, now);
        let selected_endpoint = path_book
            .select_endpoint(
                participant,
                announcement,
                own_local_endpoint,
                now,
                ANDROID_SIGNAL_STALE_AFTER_SECS,
            )
            .unwrap_or_else(|| select_peer_endpoint(announcement, own_local_endpoint));
        let endpoint: SocketAddr = selected_endpoint
            .parse()
            .with_context(|| format!("invalid peer endpoint {}", selected_endpoint))?;

        let mut allowed_ips = vec![format!("{}/32", strip_cidr(&announcement.tunnel_ip))];
        for route in route_assignments
            .get(participant)
            .into_iter()
            .flatten()
            .cloned()
        {
            if !allowed_ips.iter().any(|existing| existing == &route) {
                allowed_ips.push(route);
            }
        }

        peers.push(PlannedTunnelPeer {
            participant: participant.clone(),
            endpoint: selected_endpoint,
            peer: TunnelPeer {
                participant: participant.clone(),
                pubkey_b64: announcement.public_key.clone(),
                endpoint,
                allowed_ips,
            },
        });
    }

    peers.sort_by(|left, right| left.participant.cmp(&right.participant));
    Ok(peers)
}

fn advertised_route_assignments(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> HashMap<String, Vec<String>> {
    let selected_exit_node = selected_exit_node_participant(config, own_pubkey, peer_announcements);
    let mut route_owner = HashMap::<String, String>::new();

    for participant in config
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
    {
        let Some(announcement) = peer_announcements.get(participant) else {
            continue;
        };

        for route in normalized_peer_ipv4_routes(announcement) {
            if is_exit_node_route(&route)
                && selected_exit_node.as_deref() != Some(participant.as_str())
            {
                continue;
            }
            route_owner
                .entry(route)
                .or_insert_with(|| participant.clone());
        }
    }

    let mut assignments = HashMap::<String, Vec<String>>::new();
    for (route, participant) in route_owner {
        assignments.entry(participant).or_default().push(route);
    }

    for routes in assignments.values_mut() {
        routes.sort();
        routes.dedup();
    }

    assignments
}

fn normalized_peer_ipv4_routes(announcement: &PeerAnnouncement) -> Vec<String> {
    let mut routes = Vec::new();
    let mut seen = HashSet::new();

    for route in &announcement.advertised_routes {
        let Some(route) = normalize_advertised_route(route) else {
            continue;
        };
        if strip_cidr(&route).parse::<Ipv4Addr>().is_err() {
            continue;
        }
        if seen.insert(route.clone()) {
            routes.push(route);
        }
    }

    routes
}

fn selected_exit_node_participant(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> Option<String> {
    if config.exit_node.is_empty() || Some(config.exit_node.as_str()) == own_pubkey {
        return None;
    }

    let announcement = peer_announcements.get(&config.exit_node)?;
    normalized_peer_ipv4_routes(announcement)
        .iter()
        .any(|route| route == "0.0.0.0/0")
        .then(|| config.exit_node.clone())
}

fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

pub(super) fn route_targets_for_tunnel_peers(peers: &[PlannedTunnelPeer]) -> Vec<String> {
    let mut route_targets = peers
        .iter()
        .flat_map(|peer| peer.peer.allowed_ips.iter().cloned())
        .collect::<Vec<_>>();
    route_targets.sort();
    route_targets.dedup();
    route_targets
}

pub(super) fn tunnel_fingerprint(
    config: &AppConfig,
    listen_port: u16,
    peers: &[PlannedTunnelPeer],
) -> String {
    let local_address = local_interface_address_for_tunnel(&config.node.tunnel_ip);
    let mut peer_entries = peers
        .iter()
        .map(|peer| {
            format!(
                "{}|{}|{}|{}",
                peer.peer.participant,
                peer.peer.pubkey_b64,
                peer.peer.endpoint,
                peer.peer.allowed_ips.join(",")
            )
        })
        .collect::<Vec<_>>();
    peer_entries.sort();

    format!(
        "{}|{}|{}|{}|{}",
        config.node.private_key,
        config.node.tunnel_ip,
        listen_port,
        local_address,
        peer_entries.join(";")
    )
}

pub(super) fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

pub(super) fn local_signal_endpoint(config: &AppConfig, listen_port: u16) -> String {
    runtime_local_signal_endpoint(&config.node.endpoint, listen_port)
}

pub(super) fn runtime_local_signal_endpoint(endpoint: &str, listen_port: u16) -> String {
    let value = endpoint.trim();
    if value.is_empty() || matches!(value, "127.0.0.1:51820" | "127.0.0.1" | "0.0.0.0") {
        if let Some(ip) = detect_runtime_primary_ipv4() {
            return format!("{ip}:{listen_port}");
        }
    }

    endpoint
        .parse::<SocketAddr>()
        .map(|mut parsed| {
            parsed.set_port(listen_port);
            parsed.to_string()
        })
        .unwrap_or_else(|_| endpoint.to_string())
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

pub(super) fn note_successful_runtime_paths(
    current_tunnel: Option<&ActiveTunnelTask>,
    presence: &PeerPresenceBook,
    path_book: &mut PeerPathBook,
    now: u64,
) {
    let Some(current_tunnel) = current_tunnel else {
        return;
    };
    let Ok(state) = current_tunnel.state.lock() else {
        return;
    };

    for status in &state.peer_statuses {
        let Some(handshake_age) = status.last_handshake_age else {
            continue;
        };
        if handshake_age > Duration::from_secs(PEER_ONLINE_GRACE_SECS) {
            continue;
        }
        let handshake_age: Duration = handshake_age;
        let success_at = now.saturating_sub(handshake_age.as_secs());
        path_book.note_success(
            status.participant_pubkey.clone(),
            &status.endpoint.to_string(),
            success_at,
        );
        let _ = presence.announcement_for(&status.participant_pubkey);
    }
}
