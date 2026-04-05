use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::control::{
    PeerAnnouncement, endpoint_shares_private_ipv4_subnet,
    select_peer_endpoint_from_local_endpoints,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum PeerPathSource {
    Local,
    Public,
    Relay,
    Legacy,
    Observed,
}

impl PeerPathSource {
    fn merge(self, other: Self) -> Self {
        self.max(other)
    }

    fn rank(self, same_subnet_local: bool) -> u8 {
        if matches!(self, Self::Relay) {
            return 5;
        }

        if same_subnet_local {
            return 4;
        }

        match self {
            Self::Public | Self::Observed => 2,
            Self::Legacy => 1,
            Self::Local => 0,
            Self::Relay => 5,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PeerPathState {
    current_endpoint: Option<String>,
    endpoints: HashMap<String, TrackedPeerPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrackedPeerPath {
    source: PeerPathSource,
    announced_at: u64,
    last_selected_at: Option<u64>,
    last_success_at: Option<u64>,
}

impl TrackedPeerPath {
    fn new(source: PeerPathSource, announced_at: u64) -> Self {
        Self {
            source,
            announced_at,
            last_selected_at: None,
            last_success_at: None,
        }
    }

    fn freshness_at(&self) -> u64 {
        self.announced_at
            .max(self.last_selected_at.unwrap_or(0))
            .max(self.last_success_at.unwrap_or(0))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerPathBook {
    peers: HashMap<String, PeerPathState>,
}

impl PeerPathBook {
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    pub fn refresh_from_announcement(
        &mut self,
        participant: impl Into<String>,
        announcement: &PeerAnnouncement,
        seen_at: u64,
    ) -> bool {
        let participant = participant.into();
        let state = self.peers.entry(participant).or_default();
        let mut changed = false;
        let announced_endpoints = announcement_endpoints(announcement);
        let announced_relay_endpoints = announced_endpoints
            .iter()
            .filter(|(_, source)| matches!(source, PeerPathSource::Relay))
            .map(|(endpoint, _)| endpoint.clone())
            .collect::<HashSet<_>>();

        let before = state.endpoints.len();
        state.endpoints.retain(|endpoint, tracked| {
            (tracked.source != PeerPathSource::Relay || announced_relay_endpoints.contains(endpoint))
                && !observed_endpoint_superseded_by_announcement(
                    endpoint,
                    tracked,
                    &announced_endpoints,
                )
        });
        if state.endpoints.len() != before {
            changed = true;
        }
        if let Some(current_endpoint) = state.current_endpoint.as_deref()
            && !state.endpoints.contains_key(current_endpoint)
        {
            state.current_endpoint = None;
            changed = true;
        }

        for (endpoint, source) in announced_endpoints {
            let entry = state
                .endpoints
                .entry(endpoint)
                .or_insert_with(|| TrackedPeerPath::new(source, seen_at));

            let merged_source = entry.source.merge(source);
            if entry.source != merged_source {
                entry.source = merged_source;
                changed = true;
            }
            if entry.announced_at < seen_at {
                entry.announced_at = seen_at;
                changed = true;
            }
        }

        changed
    }

    pub fn note_selected(
        &mut self,
        participant: impl Into<String>,
        endpoint: &str,
        selected_at: u64,
    ) -> bool {
        let participant = participant.into();
        let state = self.peers.entry(participant).or_default();
        let entry = state
            .endpoints
            .entry(endpoint.to_string())
            .or_insert_with(|| TrackedPeerPath::new(PeerPathSource::Observed, selected_at));

        let mut changed = false;
        if entry.last_selected_at != Some(selected_at) {
            entry.last_selected_at = Some(selected_at);
            changed = true;
        }
        if state.current_endpoint.as_deref() != Some(endpoint) {
            state.current_endpoint = Some(endpoint.to_string());
            changed = true;
        }

        changed
    }

    pub fn note_success(
        &mut self,
        participant: impl Into<String>,
        endpoint: &str,
        success_at: u64,
    ) -> bool {
        let participant = participant.into();
        let state = self.peers.entry(participant).or_default();
        let entry = state
            .endpoints
            .entry(endpoint.to_string())
            .or_insert_with(|| TrackedPeerPath::new(PeerPathSource::Observed, success_at));

        if entry.last_success_at.unwrap_or(0) >= success_at {
            return false;
        }

        entry.last_success_at = Some(success_at);
        true
    }

    pub fn prune_stale(&mut self, now: u64, stale_after_secs: u64) -> bool {
        if stale_after_secs == 0 {
            return false;
        }

        let cutoff = now.saturating_sub(stale_after_secs);
        let mut changed = false;
        self.peers.retain(|_, state| {
            let before = state.endpoints.len();
            state
                .endpoints
                .retain(|_, endpoint| endpoint.freshness_at() > cutoff);
            if state.endpoints.len() != before {
                changed = true;
            }
            if let Some(current) = state.current_endpoint.as_deref()
                && !state.endpoints.contains_key(current)
            {
                state.current_endpoint = None;
                changed = true;
            }
            let keep = !state.endpoints.is_empty();
            if !keep {
                changed = true;
            }
            keep
        });
        changed
    }

    pub fn retain_participants(&mut self, participants: &HashSet<String>) {
        self.peers
            .retain(|participant, _| participants.contains(participant));
    }

    pub fn remove_relay_paths_for_participant(&mut self, participant: &str) -> bool {
        let Some(state) = self.peers.get_mut(participant) else {
            return false;
        };

        let before = state.endpoints.len();
        state
            .endpoints
            .retain(|_, tracked| tracked.source != PeerPathSource::Relay);
        let mut changed = state.endpoints.len() != before;

        if let Some(current_endpoint) = state.current_endpoint.as_deref()
            && !state.endpoints.contains_key(current_endpoint)
        {
            state.current_endpoint = None;
            changed = true;
        }

        if state.endpoints.is_empty() {
            self.peers.remove(participant);
            changed = true;
        }

        changed
    }

    pub fn endpoint_has_recent_success_for_local_endpoints(
        &self,
        participant: &str,
        endpoint: &str,
        own_local_endpoints: &[String],
        now: u64,
        stale_after_secs: u64,
    ) -> bool {
        if stale_after_secs == 0 {
            return false;
        }

        let Some(tracked) = self
            .peers
            .get(participant)
            .and_then(|state| state.endpoints.get(endpoint))
        else {
            return false;
        };

        let same_subnet_local = endpoint_shares_private_ipv4_subnet(endpoint, own_local_endpoints);
        if !path_success_still_applies(endpoint, tracked, same_subnet_local) {
            return false;
        }

        tracked
            .last_success_at
            .is_some_and(|success_at| now.saturating_sub(success_at) <= stale_after_secs)
    }

    pub fn select_endpoint(
        &self,
        participant: &str,
        announcement: &PeerAnnouncement,
        own_local_endpoint: Option<&str>,
        now: u64,
        retry_after_secs: u64,
    ) -> Option<String> {
        let own_local_endpoints = own_local_endpoint
            .map(|value| vec![value.to_string()])
            .unwrap_or_default();
        self.select_endpoint_for_local_endpoints(
            participant,
            announcement,
            &own_local_endpoints,
            now,
            retry_after_secs,
        )
    }

    pub fn select_endpoint_for_local_endpoints(
        &self,
        participant: &str,
        announcement: &PeerAnnouncement,
        own_local_endpoints: &[String],
        now: u64,
        retry_after_secs: u64,
    ) -> Option<String> {
        let default_endpoint =
            select_peer_endpoint_from_local_endpoints(announcement, own_local_endpoints);
        let state = self.peers.get(participant);
        let Some(state) = state else {
            return Some(default_endpoint);
        };
        if state.endpoints.is_empty() {
            return Some(default_endpoint);
        }

        let preferred = state
            .endpoints
            .iter()
            .max_by_key(|(endpoint, tracked)| {
                candidate_rank(endpoint, tracked, own_local_endpoints, &default_endpoint)
            })
            .map(|(endpoint, _)| endpoint.clone())?;

        let Some(current_endpoint) = state
            .current_endpoint
            .as_ref()
            .filter(|endpoint| state.endpoints.contains_key(*endpoint))
        else {
            return Some(preferred);
        };

        let current = state
            .endpoints
            .get(current_endpoint)
            .expect("current endpoint should exist");
        let preferred_state = state
            .endpoints
            .get(&preferred)
            .expect("preferred endpoint should exist");
        let current_same_subnet_local =
            endpoint_shares_private_ipv4_subnet(current_endpoint, own_local_endpoints);
        let preferred_same_subnet_local =
            endpoint_shares_private_ipv4_subnet(&preferred, own_local_endpoints);

        if current_endpoint == &preferred {
            return Some(preferred);
        }

        if endpoint_is_local_only(current_endpoint) && !current_same_subnet_local {
            return Some(preferred);
        }

        let current_success_at =
            if path_success_still_applies(current_endpoint, current, current_same_subnet_local) {
                current.last_success_at.unwrap_or(0)
            } else {
                0
            };
        let preferred_success_at =
            if path_success_still_applies(&preferred, preferred_state, preferred_same_subnet_local)
            {
                preferred_state.last_success_at.unwrap_or(0)
            } else {
                0
            };

        if current_success_at > 0 {
            if preferred_success_at > current_success_at {
                return Some(preferred);
            }
            return Some(current_endpoint.clone());
        }

        let can_rotate = current
            .last_selected_at
            .map(|selected_at| now.saturating_sub(selected_at) >= retry_after_secs)
            .unwrap_or(true);

        if can_rotate {
            Some(preferred)
        } else {
            Some(current_endpoint.clone())
        }
    }
}

fn announcement_endpoints(announcement: &PeerAnnouncement) -> Vec<(String, PeerPathSource)> {
    let mut seen = HashSet::new();
    let mut endpoints = Vec::new();

    if let Some(local_endpoint) = announcement.local_endpoint.as_deref()
        && !local_endpoint.trim().is_empty()
        && seen.insert(local_endpoint.to_string())
    {
        endpoints.push((local_endpoint.to_string(), PeerPathSource::Local));
    }

    if let Some(public_endpoint) = announcement.public_endpoint.as_deref()
        && !public_endpoint.trim().is_empty()
        && seen.insert(public_endpoint.to_string())
    {
        endpoints.push((public_endpoint.to_string(), PeerPathSource::Public));
    }

    if let Some(relay_endpoint) = announcement.relay_endpoint.as_deref()
        && !relay_endpoint.trim().is_empty()
        && seen.insert(relay_endpoint.to_string())
    {
        endpoints.push((relay_endpoint.to_string(), PeerPathSource::Relay));
    }

    if !announcement.endpoint.trim().is_empty() && seen.insert(announcement.endpoint.clone()) {
        endpoints.push((announcement.endpoint.clone(), PeerPathSource::Legacy));
    }

    endpoints
}

fn observed_endpoint_superseded_by_announcement(
    endpoint: &str,
    tracked: &TrackedPeerPath,
    announced_endpoints: &[(String, PeerPathSource)],
) -> bool {
    if tracked.source != PeerPathSource::Observed || endpoint_is_local_only(endpoint) {
        return false;
    }

    // Keep previously selected/successful observed public ports alongside
    // later announcements from the same host. Endpoint-dependent NATs can map
    // different destinations to different public ports, so replacing a known
    // working observed port with the newly announced port can break reconnects.
    if tracked.last_selected_at.is_some() || tracked.last_success_at.is_some() {
        return false;
    }

    let Some(observed_host) = endpoint_host(endpoint) else {
        return false;
    };

    announced_endpoints.iter().any(|(announced_endpoint, announced_source)| {
        !matches!(announced_source, PeerPathSource::Observed)
            && !endpoint_is_local_only(announced_endpoint)
            && endpoint != announced_endpoint
            && endpoint_host(announced_endpoint).as_deref() == Some(observed_host.as_str())
    })
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    endpoint
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| addr.ip().to_string())
}

fn candidate_rank(
    endpoint: &str,
    tracked: &TrackedPeerPath,
    own_local_endpoints: &[String],
    default_endpoint: &str,
) -> (u64, u8, u8, u64) {
    let same_subnet_local = endpoint_shares_private_ipv4_subnet(endpoint, own_local_endpoints);
    let default_match = endpoint == default_endpoint;
    let last_success_at = if path_success_still_applies(endpoint, tracked, same_subnet_local) {
        tracked.last_success_at.unwrap_or(0)
    } else {
        0
    };

    (
        last_success_at,
        tracked.source.rank(same_subnet_local),
        u8::from(default_match),
        tracked.announced_at,
    )
}

fn path_success_still_applies(
    endpoint: &str,
    tracked: &TrackedPeerPath,
    same_subnet_local: bool,
) -> bool {
    if tracked.last_success_at.is_none() {
        return false;
    }

    if !endpoint_is_local_only(endpoint) {
        return true;
    }

    same_subnet_local
}

fn endpoint_is_local_only(endpoint: &str) -> bool {
    let host = endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(host, _)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_link_local()
                || ip.is_loopback()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unicast_link_local() || ip.is_unique_local()
        }
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

#[cfg(test)]
mod tests {
    use super::PeerPathBook;
    use crate::control::PeerAnnouncement;

    fn sample_peer_announcement(relay_endpoint: Option<&str>) -> PeerAnnouncement {
        PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: "peer-public-key".to_string(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: Some("192.168.1.20:51820".to_string()),
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            relay_endpoint: relay_endpoint.map(str::to_string),
            relay_pubkey: relay_endpoint.map(|_| "relay-pubkey".to_string()),
            relay_expires_at: relay_endpoint.map(|_| 500),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 100,
        }
    }

    #[test]
    fn refresh_from_announcement_drops_relay_paths_that_are_no_longer_advertised() {
        let participant = "11".repeat(32);
        let mut paths = PeerPathBook::default();
        let relay_announcement = sample_peer_announcement(Some("198.51.100.30:40001"));
        paths.refresh_from_announcement(participant.clone(), &relay_announcement, 100);
        paths.note_selected(participant.clone(), "198.51.100.30:40001", 100);

        let direct_only = sample_peer_announcement(None);
        paths.refresh_from_announcement(participant.clone(), &direct_only, 101);

        let selected = paths
            .select_endpoint_for_local_endpoints(&participant, &direct_only, &[], 101, 5)
            .expect("selected endpoint");

        assert_eq!(selected, "203.0.113.20:51820");
    }

    #[test]
    fn refresh_from_announcement_replaces_stale_relay_path_with_new_endpoint() {
        let participant = "11".repeat(32);
        let mut paths = PeerPathBook::default();
        let relay_a = sample_peer_announcement(Some("198.51.100.30:40001"));
        paths.refresh_from_announcement(participant.clone(), &relay_a, 100);
        paths.note_selected(participant.clone(), "198.51.100.30:40001", 100);

        let relay_b = sample_peer_announcement(Some("198.51.100.30:40002"));
        paths.refresh_from_announcement(participant.clone(), &relay_b, 101);

        let selected = paths
            .select_endpoint_for_local_endpoints(&participant, &relay_b, &[], 101, 5)
            .expect("selected endpoint");

        assert_eq!(selected, "198.51.100.30:40002");
    }

    #[test]
    fn refresh_from_announcement_keeps_observed_public_port_with_recent_success() {
        let participant = "11".repeat(32);
        let mut paths = PeerPathBook::default();
        let announcement = sample_peer_announcement(None);

        paths.refresh_from_announcement(participant.clone(), &announcement, 100);
        paths.note_success(participant.clone(), "203.0.113.20:33063", 100);
        paths.note_selected(participant.clone(), "203.0.113.20:33063", 100);

        let refreshed = sample_peer_announcement(None);
        paths.refresh_from_announcement(participant.clone(), &refreshed, 101);

        let selected = paths
            .select_endpoint_for_local_endpoints(&participant, &refreshed, &[], 101, 5)
            .expect("selected endpoint");

        assert_eq!(selected, "203.0.113.20:33063");
    }
}
