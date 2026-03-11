use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_endpoint: Option<String>,
    pub tunnel_ip: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised_routes: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PeerDirectory {
    peers: HashMap<String, PeerAnnouncement>,
}

impl PeerDirectory {
    pub fn apply(&mut self, announcement: PeerAnnouncement) {
        match self.peers.get(&announcement.node_id) {
            Some(existing) if existing.timestamp > announcement.timestamp => {}
            _ => {
                self.peers
                    .insert(announcement.node_id.clone(), announcement);
            }
        }
    }

    pub fn get(&self, node_id: &str) -> Option<&PeerAnnouncement> {
        self.peers.get(node_id)
    }

    pub fn remove(&mut self, node_id: &str) -> Option<PeerAnnouncement> {
        self.peers.remove(node_id)
    }

    pub fn all(&self) -> Vec<PeerAnnouncement> {
        let mut peers: Vec<PeerAnnouncement> = self.peers.values().cloned().collect();
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        peers
    }
}

pub fn select_peer_endpoint(
    announcement: &PeerAnnouncement,
    own_local_endpoint: Option<&str>,
) -> String {
    if let (Some(peer_local), Some(own_local)) =
        (announcement.local_endpoint.as_deref(), own_local_endpoint)
        && endpoints_share_private_ipv4_subnet(peer_local, own_local)
    {
        return peer_local.to_string();
    }

    announcement
        .public_endpoint
        .as_deref()
        .filter(|endpoint| !endpoint.trim().is_empty())
        .unwrap_or(&announcement.endpoint)
        .to_string()
}

fn endpoints_share_private_ipv4_subnet(left: &str, right: &str) -> bool {
    let Ok(left_addr) = left.parse::<SocketAddr>() else {
        return false;
    };
    let Ok(right_addr) = right.parse::<SocketAddr>() else {
        return false;
    };

    let (SocketAddr::V4(left_v4), SocketAddr::V4(right_v4)) = (left_addr, right_addr) else {
        return false;
    };
    let left_ip = *left_v4.ip();
    let right_ip = *right_v4.ip();

    is_private_ipv4(left_ip)
        && is_private_ipv4(right_ip)
        && left_ip.octets()[0..3] == right_ip.octets()[0..3]
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}
