use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, maybe_autoconfigure_node, normalize_advertised_route,
};
use nostr_vpn_core::control::{PeerAnnouncement, select_peer_endpoint};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload, SignalingNetwork};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{
    DaemonPeerState, DaemonRuntimeState, PEER_ONLINE_GRACE_SECS, android_vpn::AndroidVpnExt,
    android_vpn::StartVpnArgs, mobile_wg::MobileWireGuardRuntime, mobile_wg::PeerRuntimeStatus,
    mobile_wg::WireGuardPeerConfig,
};

const ANDROID_TUN_MTU: u16 = 1_280;
const ANDROID_SESSION_STATUS_WAITING: &str = "Waiting for participants";
const ANDROID_ANNOUNCE_INTERVAL_SECS: u64 = 5;
const ANDROID_PUBLISH_TIMEOUT_SECS: u64 = 3;
const ANDROID_SIGNAL_STALE_AFTER_SECS: u64 = 45;

#[derive(Default)]
pub(crate) struct AndroidSessionSnapshot {
    pub(crate) running: bool,
    pub(crate) state: Option<DaemonRuntimeState>,
}

pub(crate) struct ActiveTunnelTask {
    pub(crate) listen_port: u16,
    pub(crate) state: std::sync::Arc<std::sync::Mutex<TunnelTaskState>>,
    pub(crate) stop_tx: watch::Sender<bool>,
    pub(crate) join: JoinHandle<()>,
}

pub(crate) struct MobileTunIo {
    pub(crate) reader: tokio::fs::File,
    pub(crate) writer: tokio::fs::File,
}

#[derive(Default)]
pub(crate) struct TunnelTaskState {
    pub(crate) peer_statuses: Vec<PeerRuntimeStatus>,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TunnelPeer {
    pub(crate) participant: String,
    pub(crate) pubkey_b64: String,
    pub(crate) endpoint: SocketAddr,
    pub(crate) allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedTunnelPeer {
    pub(crate) participant: String,
    pub(crate) endpoint: String,
    pub(crate) peer: TunnelPeer,
}

pub(crate) struct ReconcileSession<'a> {
    pub(crate) own_pubkey: Option<&'a str>,
    pub(crate) recipients: &'a [String],
}

pub(crate) struct ReconcileTunnelState<'a> {
    pub(crate) current_tunnel: &'a mut Option<ActiveTunnelTask>,
    pub(crate) current_listen_port: &'a mut u16,
    pub(crate) current_fingerprint: &'a mut Option<String>,
}

pub(crate) fn signaling_networks_for_app(app: &AppConfig) -> Vec<SignalingNetwork> {
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

pub(crate) fn expected_peer_count(config: &AppConfig) -> usize {
    let participants = config.participant_pubkeys_hex();
    if participants.is_empty() {
        return 0;
    }

    let mut expected = participants.len();
    if let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && participants
            .iter()
            .any(|participant| participant == &own_pubkey)
    {
        expected = expected.saturating_sub(1);
    }

    expected
}

pub(crate) fn resolve_relays(config: &AppConfig) -> Vec<String> {
    if !config.nostr.relays.is_empty() {
        return config.nostr.relays.clone();
    }

    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

pub(crate) fn configured_recipients(config: &AppConfig, own_pubkey: Option<&str>) -> Vec<String> {
    config
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .collect()
}

pub(crate) async fn publish_private_announce_to_all(
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

pub(crate) async fn publish_private_announce_best_effort(
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

pub(crate) async fn publish_hello_best_effort(client: &NostrSignalingClient) {
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

pub(crate) fn build_peer_announcement(config: &AppConfig, listen_port: u16) -> PeerAnnouncement {
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

pub(crate) fn planned_tunnel_peers(
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

pub(crate) fn advertised_route_assignments(
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

pub(crate) fn normalized_peer_ipv4_routes(announcement: &PeerAnnouncement) -> Vec<String> {
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

pub(crate) fn selected_exit_node_participant(
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

pub(crate) fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

pub(crate) fn route_targets_for_tunnel_peers(peers: &[PlannedTunnelPeer]) -> Vec<String> {
    let mut route_targets = peers
        .iter()
        .flat_map(|peer| peer.peer.allowed_ips.iter().cloned())
        .collect::<Vec<_>>();
    route_targets.sort();
    route_targets.dedup();
    route_targets
}

pub(crate) fn tunnel_fingerprint(
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

pub(crate) fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

pub(crate) fn local_signal_endpoint(config: &AppConfig, listen_port: u16) -> String {
    runtime_local_signal_endpoint(&config.node.endpoint, listen_port)
}

pub(crate) fn runtime_local_signal_endpoint(endpoint: &str, listen_port: u16) -> String {
    let value = endpoint.trim();
    if (value.is_empty() || matches!(value, "127.0.0.1:51820" | "127.0.0.1" | "0.0.0.0"))
        && let Some(ip) = detect_runtime_primary_ipv4()
    {
        return format!("{ip}:{listen_port}");
    }

    endpoint
        .parse::<SocketAddr>()
        .map(|mut parsed| {
            parsed.set_port(listen_port);
            parsed.to_string()
        })
        .unwrap_or_else(|_| endpoint.to_string())
}

pub(crate) fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

pub(crate) fn note_successful_runtime_paths(
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
        let success_at = now.saturating_sub(handshake_age.as_secs());
        path_book.note_success(
            status.participant_pubkey.clone(),
            &status.endpoint.to_string(),
            success_at,
        );
        let _ = presence.announcement_for(&status.participant_pubkey);
    }
}

pub(crate) fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

pub(crate) fn open_mobile_tun_io(tun_fd: RawFd) -> Result<MobileTunIo> {
    configure_tun_fd(tun_fd).context("failed to configure android tun fd")?;

    let writer = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let reader = writer
        .try_clone()
        .context("failed to duplicate android tun fd")?;

    Ok(MobileTunIo {
        reader: tokio::fs::File::from_std(reader),
        writer: tokio::fs::File::from_std(writer),
    })
}

pub(crate) fn configure_tun_fd(tun_fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(tun_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(anyhow!(
            "failed to read tun fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    if flags & libc::O_NONBLOCK == 0 {
        return Ok(());
    }

    let updated_flags = flags & !libc::O_NONBLOCK;
    let result = unsafe { libc::fcntl(tun_fd, libc::F_SETFL, updated_flags) };
    if result < 0 {
        return Err(anyhow!(
            "failed to clear O_NONBLOCK on tun fd: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

pub(crate) fn should_retry_tun_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

pub(crate) fn signal_payload_kind(payload: &SignalPayload) -> &'static str {
    match payload {
        SignalPayload::Hello => "hello",
        SignalPayload::Announce(_) => "announce",
        SignalPayload::Roster(_) => "roster",
        SignalPayload::Disconnect { .. } => "disconnect",
        SignalPayload::JoinRequest { .. } => "join-request",
    }
}

pub(crate) fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{planned_tunnel_peers, runtime_local_signal_endpoint};
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::config::AppConfig;
    use nostr_vpn_core::control::PeerAnnouncement;
    use nostr_vpn_core::paths::PeerPathBook;
    use std::collections::HashMap;
    use std::time::Duration;

    fn participant() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn peer_announcement(endpoint: &str, tunnel_ip: &str, routes: &[&str]) -> PeerAnnouncement {
        PeerAnnouncement {
            node_id: format!("node-{endpoint}"),
            public_key: "dummy-public-key".to_string(),
            endpoint: endpoint.to_string(),
            local_endpoint: None,
            public_endpoint: Some(endpoint.to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: tunnel_ip.to_string(),
            advertised_routes: routes.iter().map(|route| (*route).to_string()).collect(),
            timestamp: 1,
        }
    }

    #[test]
    fn planned_tunnel_peers_assigns_exit_node_route_only_to_selected_exit() {
        let own = participant();
        let exit = participant();
        let other = participant();

        let mut config = AppConfig::generated();
        config.networks[0].participants = vec![own.clone(), exit.clone(), other.clone()];
        config.node.public_key = own.clone();
        config.exit_node = exit.clone();

        let mut peers = HashMap::new();
        peers.insert(
            exit.clone(),
            peer_announcement("198.51.100.20:51820", "10.44.0.2/32", &["0.0.0.0/0"]),
        );
        peers.insert(
            other.clone(),
            peer_announcement("198.51.100.21:51820", "10.44.0.3/32", &["10.0.0.0/24"]),
        );

        let mut path_book = PeerPathBook::default();
        let planned = planned_tunnel_peers(
            &config,
            Some(&own),
            &peers,
            &mut path_book,
            Some("192.168.64.2:51820"),
            1,
        )
        .expect("planned peers");

        let exit_peer = planned
            .iter()
            .find(|planned| planned.participant == exit)
            .expect("exit peer");
        assert!(
            exit_peer
                .peer
                .allowed_ips
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
        let other_peer = planned
            .iter()
            .find(|planned| planned.participant == other)
            .expect("other peer");
        assert!(
            !other_peer
                .peer
                .allowed_ips
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
    }

    #[test]
    fn runtime_local_signal_endpoint_preserves_non_loopback_host_with_new_port() {
        assert_eq!(
            runtime_local_signal_endpoint("198.51.100.10:6000", 51820),
            "198.51.100.10:51820"
        );
    }

    #[test]
    fn tunnel_fingerprint_changes_when_peer_public_key_changes() {
        let mut config = AppConfig::generated();
        config.node.private_key = "private-key".to_string();
        config.node.tunnel_ip = "10.44.0.1/32".to_string();

        let peer = |pubkey: &str| PlannedTunnelPeer {
            participant: "participant".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            peer: TunnelPeer {
                participant: "participant".to_string(),
                pubkey_b64: pubkey.to_string(),
                endpoint: "198.51.100.20:51820".parse().expect("valid endpoint"),
                allowed_ips: vec!["10.44.0.2/32".to_string()],
            },
        };

        let first = super::tunnel_fingerprint(&config, 51820, &[peer("peer-key-a")]);
        let second = super::tunnel_fingerprint(&config, 51820, &[peer("peer-key-b")]);

        assert_ne!(first, second);
    }

    #[test]
    fn should_retry_tun_io_uses_transient_error_kinds() {
        assert!(super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(!super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }
}
