#[derive(Default)]
struct FipsLinkSnapshot {
    observed_at: Option<u64>,
    roster: HashMap<String, FipsEndpointPeer>,
    other: HashMap<String, FipsEndpointPeer>,
}

/// A configured public seed observation from one successful endpoint snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct FipsPublicSeedLinkStatus {
    /// Unix seconds at the start of the successful endpoint snapshot request.
    pub(crate) observed_at: u64,
    pub(crate) connected: bool,
    pub(crate) transport_addr: Option<String>,
    pub(crate) transport_type: Option<String>,
    pub(crate) link_id: u64,
    /// Peer-wide authenticated FMP receive bookkeeping, not UDP-only/socket counters.
    pub(crate) packets_recv: u64,
    pub(crate) bytes_recv: u64,
}

impl FipsLinkSnapshot {
    fn configured_public_seed_statuses(
        &self,
        npubs: &[&str],
    ) -> HashMap<String, FipsPublicSeedLinkStatus> {
        let Some(observed_at) = self.observed_at else {
            return HashMap::new();
        };
        // A configured endpoint can also be a private/customer peer. Only
        // established public seed identities may expose these observations.
        self.roster
            .values()
            .chain(self.other.values())
            .filter(|peer| {
                npubs.contains(&peer.npub.as_str()) && is_public_native_bootstrap_peer(&peer.npub)
            })
            .map(|peer| {
                (
                    peer.npub.clone(),
                    FipsPublicSeedLinkStatus {
                        observed_at,
                        connected: peer.connected,
                        transport_addr: peer.transport_addr.clone(),
                        transport_type: peer.transport_type.clone(),
                        link_id: peer.link_id,
                        packets_recv: peer.packets_recv,
                        bytes_recv: peer.bytes_recv,
                    },
                )
            })
            .collect()
    }
}

fn endpoint_link_refreshable_after_stale_participant(peer_link: &FipsEndpointPeer) -> bool {
    peer_link.direct_probe_pending
}

fn endpoint_path_refresh_due(
    peer_link: &FipsEndpointPeer,
    last_path_data_seen_at: Option<u64>,
    now: u64,
) -> bool {
    endpoint_link_refreshable_after_stale_participant(peer_link)
        && fips_peer_presence_stale(last_path_data_seen_at, now)
}

fn fips_ping_participants(
    mut participants: Vec<String>,
    other_link_status: &HashMap<String, FipsEndpointPeer>,
) -> Vec<String> {
    participants.extend(
        other_link_status
            .iter()
            .filter(|(_, peer)| peer.direct_probe_auto_reconnect)
            .map(|(participant, _)| participant.clone()),
    );
    participants.sort();
    participants.dedup();
    participants
}

impl FipsPrivateMeshRuntime {
    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        let now = unix_timestamp();
        let presence = self.presence.read().ok();
        let peer_activity = self.peer_activity.load();
        let snapshot = self.link_status.read().ok();
        let link_status = snapshot.as_ref().map(|snapshot| &snapshot.roster);
        let other_link_status = snapshot.as_ref().map(|snapshot| &snapshot.other);
        let mut statuses = self.mesh.load().peer_statuses();
        for status in &mut statuses {
            let participant_key = participant_pubkey_bytes(&status.pubkey);
            let peer_presence = presence
                .as_ref()
                .and_then(|presence| presence.get(&status.pubkey));
            let activity = participant_key
                .as_ref()
                .and_then(|participant| peer_activity.get(participant))
                .map(|activity| activity.snapshot());
            let peer_link = link_status
                .as_ref()
                .and_then(|link_status| link_status.get(&status.pubkey));
            status.last_seen_at = activity
                .and_then(|value| value.last_seen_at)
                .or_else(|| peer_presence.and_then(|value| value.last_seen_at));
            status.last_control_seen_at = activity
                .and_then(|value| value.last_control_seen_at)
                .or_else(|| peer_presence.and_then(|value| value.last_control_seen_at));
            status.last_data_seen_at = activity
                .and_then(|value| value.last_data_seen_at)
                .or_else(|| peer_presence.and_then(|value| value.last_data_seen_at));
            status.tx_bytes = activity
                .map(|value| value.tx_bytes)
                .or_else(|| peer_presence.map(|value| value.tx_bytes))
                .unwrap_or(0);
            status.rx_bytes = activity
                .map(|value| value.rx_bytes)
                .or_else(|| peer_presence.map(|value| value.rx_bytes))
                .unwrap_or(0);
            if let Some(peer_link) = peer_link {
                status.endpoint_npub = peer_link.npub.clone();
                status.transport_addr = peer_link.transport_addr.clone();
                status.transport_type = peer_link.transport_type.clone();
                status.srtt_ms = peer_link.srtt_ms;
                status.srtt_age_ms = peer_link.srtt_age_ms;
                status.link_packets_sent = peer_link.packets_sent;
                status.link_packets_recv = peer_link.packets_recv;
                status.link_bytes_sent = peer_link.bytes_sent;
                status.link_bytes_recv = peer_link.bytes_recv;
                status.rekey_in_progress = peer_link.rekey_in_progress;
                status.rekey_draining = peer_link.rekey_draining;
                status.current_k_bit = peer_link.current_k_bit;
                status.last_outbound_route = peer_link.last_outbound_route.clone();
                status.direct_probe_pending = peer_link.direct_probe_pending;
                status.direct_probe_after_ms = peer_link.direct_probe_after_ms;
                status.direct_probe_retry_count = peer_link.direct_probe_retry_count;
                status.direct_probe_auto_reconnect = peer_link.direct_probe_auto_reconnect;
                status.direct_probe_expires_at_ms = peer_link.direct_probe_expires_at_ms;
                status.nostr_traversal_consecutive_failures =
                    peer_link.nostr_traversal_consecutive_failures;
                status.nostr_traversal_in_cooldown = peer_link.nostr_traversal_in_cooldown;
                status.nostr_traversal_cooldown_until_ms =
                    peer_link.nostr_traversal_cooldown_until_ms;
                status.nostr_traversal_last_observed_skew_ms =
                    peer_link.nostr_traversal_last_observed_skew_ms;
            }
            if status.srtt_ms.is_none() {
                status.srtt_ms = peer_presence.and_then(|value| value.rtt_ms);
            }
            let link_connected = peer_link.is_some_and(|peer_link| peer_link.connected);
            let (connected, error) = fips_peer_liveness(
                status.last_seen_at,
                link_connected,
                peer_presence.and_then(|value| value.error.clone()),
                now,
            );
            status.connected = connected;
            status.error = error;
        }
        if let Some(other_link_status) = other_link_status {
            statuses.extend(other_endpoint_peer_statuses(other_link_status, now));
        }
        statuses.sort_by(|left, right| left.pubkey.cmp(&right.pubkey));
        statuses.dedup_by(|left, right| left.pubkey == right.pubkey);
        statuses
    }

    pub(crate) fn stale_participants_needing_path_refresh(&self, now: u64) -> Vec<String> {
        let Some(presence) = self.presence.read().ok() else {
            return Vec::new();
        };
        let peer_activity = self.peer_activity.load();
        let Some(snapshot) = self.link_status.read().ok() else {
            return Vec::new();
        };
        let link_status = &snapshot.roster;
        let mut participants = self
            .mesh
            .load()
            .peer_pubkeys()
            .into_iter()
            .filter(|participant| {
                let Some(peer_link) = link_status.get(participant) else {
                    return false;
                };
                let participant_key = participant_pubkey_bytes(participant);
                let activity = participant_key
                    .as_ref()
                    .and_then(|participant| peer_activity.get(participant))
                    .map(|activity| activity.snapshot());
                let peer_presence = presence.get(participant);
                let last_seen_at = activity
                    .as_ref()
                    .and_then(|activity| activity.last_seen_at)
                    .or_else(|| peer_presence.and_then(|presence| presence.last_seen_at));
                let last_data_seen_at = activity
                    .as_ref()
                    .and_then(|activity| activity.last_data_seen_at)
                    .or_else(|| peer_presence.and_then(|presence| presence.last_data_seen_at));
                endpoint_path_refresh_due(peer_link, last_data_seen_at.or(last_seen_at), now)
            })
            .collect::<Vec<_>>();
        participants.sort();
        participants
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        // Keep the capture time with the maps. Failed refreshes must not make
        // an old snapshot appear fresh when daemon state is written again.
        let observed_at = unix_timestamp();
        let endpoint_peers = self
            .endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")?;
        let mesh = self.mesh.load();
        let mut link_status = HashMap::new();
        let mut other_link_status = HashMap::new();
        for peer in endpoint_peers {
            if let Some(participant) =
                mesh.participant_for_endpoint_node_addr(peer.node_addr.as_bytes())
            {
                link_status.insert(participant, peer);
            } else if let Some(pubkey) = endpoint_peer_status_pubkey(&peer) {
                other_link_status.insert(pubkey, peer);
            }
        }
        *self
            .link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))? = FipsLinkSnapshot {
                observed_at: Some(observed_at),
                roster: link_status,
                other: other_link_status,
            };
        Ok(())
    }

    pub(crate) fn configured_public_seed_link_statuses(
        &self,
        npubs: &[&str],
    ) -> HashMap<String, FipsPublicSeedLinkStatus> {
        self.link_status
            .read()
            .map(|snapshot| snapshot.configured_public_seed_statuses(npubs))
            .unwrap_or_default()
    }

    pub(crate) async fn local_advertised_endpoints(&self) -> Result<Vec<OverlayEndpointAdvert>> {
        self.endpoint
            .local_advertised_endpoints()
            .await
            .context("failed to snapshot FIPS local advertised endpoints")
    }

    async fn confirmed_udp_listen_port(
        &self,
        configured: u16,
        required_ipv6: Option<bool>,
    ) -> Result<Option<u16>> {
        let addrs = self
            .endpoint
            .bound_udp_listen_addrs()
            .await
            .context("failed to snapshot FIPS bound UDP listeners")?;
        Ok((configured != 0
            && addrs.iter().any(|addr| {
                addr.port() == configured
                    && required_ipv6.is_none_or(|ipv6| addr.is_ipv6() == ipv6)
            }))
        .then_some(configured))
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        self.mesh.load().peer_pubkeys()
    }

    fn ping_due_participants(&self, now: u64) -> Result<Vec<String>> {
        let participants = self.mesh.load().peer_pubkeys();
        let peer_activity = self.peer_activity.load();
        let presence = self
            .presence
            .read()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        let snapshot = self
            .link_status
            .read()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?;
        let link_status = &snapshot.roster;
        let other_link_status = &snapshot.other;
        let participants = fips_ping_participants(participants, other_link_status);
        let mut due = participants
            .into_iter()
            .filter_map(|participant| {
                let participant_key = participant_pubkey_bytes(&participant);
                let peer_presence = presence.get(&participant);
                let link_connected = link_status
                    .get(&participant)
                    .or_else(|| other_link_status.get(&participant))
                    .is_some_and(|peer| peer.connected);
                let last_seen_at = participant_key
                    .as_ref()
                    .and_then(|participant| peer_activity.get(participant))
                    .and_then(|activity| activity.last_seen_at())
                    .or_else(|| peer_presence.and_then(|value| value.last_seen_at));
                fips_peer_ping_due(
                    last_seen_at,
                    peer_presence.and_then(|value| value.last_ping_sent_at),
                    link_connected,
                    now,
                )
                .then(|| {
                    (
                        participant,
                        peer_presence.and_then(|value| value.last_ping_sent_at),
                    )
                })
            })
            .collect::<Vec<_>>();
        prioritize_fips_peer_pings(&mut due);
        Ok(due
            .into_iter()
            .map(|(participant, _)| participant)
            .collect())
    }

    /// Snapshot authenticated FIPS peer state for the recent-route cache.
    /// The shared cache model decides whether a peer exposes a reusable UDP
    /// restart address; transport source addresses are not reinterpreted here.
    pub(crate) async fn authenticated_endpoint_peers(&self) -> Result<Vec<FipsEndpointPeer>> {
        self.endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn peer_transport_ipv4_hosts(&self) -> Result<Vec<Ipv4Addr>> {
        let mut hosts = self
            .endpoint
            .peers()
            .await
            .context("failed to snapshot FIPS endpoint peers")?
            .into_iter()
            .filter_map(|peer| peer.transport_addr)
            .filter_map(|addr| endpoint_transport_ipv4_host(&addr))
            .collect::<Vec<_>>();
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }

    pub(crate) fn replace_peers(
        &self,
        peers: Vec<FipsMeshPeerConfig>,
        local_allowed_ips: Vec<String>,
        paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    ) -> Result<()> {
        let peer_identities = peer_identity_map(&peers);
        let previous_mesh = self.mesh.load_full();
        let mut mesh = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            peers,
            local_allowed_ips,
            paid_route_admissions,
        );
        mesh.inherit_exit_flows(&previous_mesh);
        let configured = mesh.peer_pubkeys();
        let previous_activity = self.peer_activity.load();
        let peer_activity = peer_activity_map(&configured, Some(&**previous_activity));
        let mesh = Arc::new(mesh);
        let next_generation = loop {
            let generation = self.mesh_generation.load(Ordering::Acquire);
            if generation & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let updating_generation = generation.wrapping_add(1);
            match self.mesh_generation.compare_exchange(
                generation,
                updating_generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break updating_generation.wrapping_add(1),
                Err(_) => std::hint::spin_loop(),
            }
        };
        self.mesh.store(mesh);
        self.mesh_generation
            .store(next_generation, Ordering::Release);
        self.peer_activity.store(Arc::new(peer_activity));
        self.peer_identities.store(Arc::new(peer_identities));
        self.presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        {
            let mut snapshot = self
                .link_status
                .write()
                .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?;
            snapshot
                .roster
                .retain(|participant, _| configured.iter().any(|value| value == participant));
            snapshot.other.clear();
            snapshot.observed_at = None;
        }
        self.peer_capabilities
            .write()
            .map_err(|_| anyhow!("FIPS mesh peer capabilities lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn stable_mesh_snapshot(&self) -> (u64, Arc<FipsMeshRuntime>) {
        loop {
            let generation = self.mesh_generation.load(Ordering::Acquire);
            if generation & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let mesh = self.mesh.load_full();
            let observed_generation = self.mesh_generation.load(Ordering::Acquire);
            if generation == observed_generation {
                return (generation, mesh);
            }
            std::hint::spin_loop();
        }
    }

    pub(crate) fn peer_advertised_routes(&self, participant: &str) -> Vec<String> {
        let normalized = match normalize_nostr_pubkey(participant) {
            Ok(value) => value,
            Err(_) => return Vec::new(),
        };
        let now = unix_timestamp();
        let caps = match self.peer_capabilities.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        caps.get(&normalized)
            .filter(|entry| {
                fips_timestamp_within_grace(now, entry.received_at, FIPS_PEER_CAPS_GRACE_SECS)
            })
            .map(|entry| entry.capabilities.advertised_routes.clone())
            .unwrap_or_default()
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        let now = unix_timestamp();
        let caps = match self.peer_capabilities.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let mut out = caps
            .iter()
            .filter(|(_, entry)| {
                fips_timestamp_within_grace(now, entry.received_at, FIPS_PEER_CAPS_GRACE_SECS)
            })
            .filter_map(|(participant, entry)| {
                let mut addresses = entry
                    .capabilities
                    .endpoint_hints
                    .iter()
                    .filter_map(peer_endpoint_hint_addr)
                    .map(|addr| (addr, entry.received_at.saturating_mul(1000)))
                    .collect::<Vec<_>>();
                addresses.sort_by(|left, right| left.0.cmp(&right.0));
                addresses.dedup_by(|left, right| left.0 == right.0);
                (!addresses.is_empty()).then_some((participant.clone(), addresses))
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.0.cmp(&right.0));
        out
    }

    fn record_peer_capabilities(
        &self,
        participant: &str,
        capabilities: &PeerCapabilities,
        now: u64,
    ) -> Result<bool> {
        let normalized = normalize_nostr_pubkey(participant)?;
        let mut caps = self
            .peer_capabilities
            .write()
            .map_err(|_| anyhow!("FIPS mesh peer capabilities lock poisoned"))?;
        match caps.get(&normalized) {
            Some(existing) if existing.capabilities.signed_at > capabilities.signed_at => {
                return Ok(false);
            }
            _ => {}
        }
        let first_received = caps
            .insert(
                normalized,
                PeerCapabilitiesEntry {
                    capabilities: capabilities.clone(),
                    received_at: now,
                },
            )
            .is_none();
        Ok(first_received)
    }

}

fn prioritize_fips_peer_pings(due: &mut [(String, Option<u64>)]) {
    due.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
}
