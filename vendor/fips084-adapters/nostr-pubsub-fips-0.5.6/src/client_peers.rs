use super::{ConnectedPeerLink, PeerIdentity, Result, invalid_option, poisoned, storage_error};
use crate::client_inner::ClientInner;
use nostr_pubsub::{MeshPeerPolicy, select_mesh_peers};

pub(super) fn select_policy_peers(
    policy: &dyn MeshPeerPolicy,
    ids: impl IntoIterator<Item = String>,
    capacity: usize,
    unknown_reserve: usize,
) -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    for id in ids {
        if let Some(mut candidate) = policy.select_mesh_peer(&id)? {
            // A policy scores an authenticated identity; it cannot replace it.
            candidate.id = id;
            candidates.push(candidate);
        }
    }
    Ok(
        select_mesh_peers(&candidates, None, capacity, unknown_reserve)
            .into_iter()
            .map(|peer| peer.id)
            .collect(),
    )
}

pub(super) fn select_links(
    policy: Option<&dyn MeshPeerPolicy>,
    links: Vec<ConnectedPeerLink>,
    capacity: usize,
    unknown_reserve: usize,
) -> Result<Vec<ConnectedPeerLink>> {
    let Some(policy) = policy else {
        return Ok(links.into_iter().take(capacity).collect());
    };
    let selected = select_policy_peers(
        policy,
        links.iter().map(|link| link.npub.clone()),
        capacity,
        unknown_reserve,
    )?;
    let by_identity = links
        .iter()
        .map(|link| (link.npub.as_str(), link.link_id))
        .collect::<std::collections::HashMap<_, _>>();
    Ok(selected
        .into_iter()
        .filter_map(|npub| {
            let link_id = *by_identity.get(npub.as_str())?;
            Some(ConnectedPeerLink { npub, link_id })
        })
        .collect())
}

pub(super) fn validate_routed_peers(
    mut peers: Vec<String>,
    capacity: usize,
    local_npub: &str,
    transport_restricted: bool,
) -> Result<Vec<String>> {
    if transport_restricted && !peers.is_empty() {
        return Err(invalid_option(
            "routed_peers require an unrestricted FIPS client",
        ));
    }
    if peers.len() > capacity {
        return Err(invalid_option(
            "routed_peers cannot exceed max_connected_peers",
        ));
    }
    for npub in &mut peers {
        *npub = PeerIdentity::from_npub(npub)
            .map(|peer| peer.npub())
            .map_err(|error| invalid_option(format!("invalid routed peer: {error}")))?;
    }
    peers.retain(|npub| npub != local_npub);
    peers.sort_unstable();
    peers.dedup();
    Ok(peers)
}

impl ClientInner {
    pub(super) async fn connected_peer_links(&self) -> Result<Vec<ConnectedPeerLink>> {
        let snapshot = self
            .endpoint
            .peers()
            .await
            .map_err(|error| storage_error("snapshot FIPS peers", error))?;
        let routed = self
            .routed_peers
            .lock()
            .map_err(|_| poisoned("FIPS routed peers"))?;
        let mut peers = routed
            .iter()
            .map(|npub| ConnectedPeerLink {
                npub: npub.clone(),
                // A routed service session belongs to the destination identity,
                // independent of changes to its intermediate physical links.
                link_id: 0,
            })
            .collect::<Vec<_>>();
        let mut direct = snapshot
            .into_iter()
            .filter(|peer| {
                peer.connected
                    && self
                        .peer_transport
                        .is_none_or(|transport| peer.transport_type.as_deref() == Some(transport))
                    && peer
                        .transport_type
                        .as_deref()
                        .is_none_or(|transport| !self.excluded_peer_transports.contains(transport))
                    && routed.binary_search(&peer.npub).is_err()
            })
            .map(|peer| ConnectedPeerLink {
                npub: peer.npub,
                link_id: peer.link_id,
            })
            .collect::<Vec<_>>();
        direct.sort_unstable_by(|left, right| left.npub.cmp(&right.npub));
        direct.dedup_by(|left, right| left.npub == right.npub);
        drop(routed);
        // Never change application-owned endpoint links to enforce pubsub bounds.
        peers = select_links(
            self.peer_policy.as_deref(),
            peers,
            self.options.max_connected_peers,
            0,
        )?;
        peers.extend(select_links(
            self.peer_policy.as_deref(),
            direct,
            self.options.max_connected_peers.saturating_sub(peers.len()),
            self.unknown_peer_reserve,
        )?);
        Ok(peers)
    }
}
