use std::collections::HashMap;
use std::time::Duration;

use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::presence::PeerPresenceBook;

use crate::mobile_wg::PeerRuntimeStatus;
use crate::{DaemonPeerState, DaemonRuntimeState, PEER_ONLINE_GRACE_SECS};

pub(crate) fn build_mobile_runtime_state(
    config: &AppConfig,
    expected_peers: usize,
    relay_connected: bool,
    runtime_peer_map: HashMap<String, PeerRuntimeStatus>,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    waiting_status: &str,
) -> DaemonRuntimeState {
    let peers = config
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| {
            let announcement = presence.announcement_for(&participant)?;
            let runtime_status = runtime_peer_map.get(&participant);
            let last_handshake_at = runtime_status.and_then(|status| {
                status
                    .last_handshake_age
                    .and_then(|age| crate::unix_timestamp().checked_sub(age.as_secs()))
            });
            let reachable = runtime_status
                .and_then(|status| status.last_handshake_age)
                .is_some_and(|age| age <= Duration::from_secs(PEER_ONLINE_GRACE_SECS));
            Some(DaemonPeerState {
                participant_pubkey: participant,
                node_id: announcement.node_id.clone(),
                tunnel_ip: announcement.tunnel_ip.clone(),
                endpoint: runtime_status
                    .map(|status| status.endpoint.to_string())
                    .unwrap_or_else(|| announcement.endpoint.clone()),
                runtime_endpoint: runtime_status.map(|status| status.endpoint.to_string()),
                tx_bytes: 0,
                rx_bytes: 0,
                public_key: announcement.public_key.clone(),
                advertised_routes: announcement.advertised_routes.clone(),
                presence_timestamp: announcement.timestamp,
                last_signal_seen_at: presence.last_seen_at(&announcement.node_id),
                reachable,
                last_handshake_at,
                error: if reachable {
                    None
                } else if runtime_status.is_some() {
                    Some("awaiting handshake".to_string())
                } else {
                    Some("no signal yet".to_string())
                },
            })
        })
        .collect::<Vec<_>>();

    let connected_peer_count = peers.iter().filter(|peer| peer.reachable).count();
    let mesh_ready = expected_peers > 0 && connected_peer_count >= expected_peers;

    DaemonRuntimeState {
        updated_at: crate::unix_timestamp(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        local_endpoint: config.node.endpoint.clone(),
        advertised_endpoint: config.node.endpoint.clone(),
        listen_port: config.node.listen_port,
        session_active: true,
        relay_connected,
        session_status: if expected_peers == 0 {
            waiting_status.to_string()
        } else if mesh_ready {
            "Connected".to_string()
        } else {
            format!("Connecting mesh ({connected_peer_count}/{expected_peers})")
        },
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        health: Vec::new(),
        network: Default::default(),
        port_mapping: Default::default(),
        relay_operator_running: false,
        relay_operator_status: "Relay operator disabled".to_string(),
        nat_assist_running: false,
        nat_assist_status: "NAT assist disabled".to_string(),
        peers,
    }
}
