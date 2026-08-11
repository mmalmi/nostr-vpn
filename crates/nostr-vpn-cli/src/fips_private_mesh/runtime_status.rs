fn endpoint_link_refreshable_after_stale_participant(peer_link: &FipsEndpointPeer) -> bool {
    peer_link.direct_probe_pending && !peer_link.connected
}

fn endpoint_path_refresh_due(
    peer_link: &FipsEndpointPeer,
    last_path_data_seen_at: Option<u64>,
    now: u64,
) -> bool {
    endpoint_link_refreshable_after_stale_participant(peer_link)
        && fips_peer_presence_stale(last_path_data_seen_at, now)
}

impl FipsPrivateMeshRuntime {
    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        let now = unix_timestamp();
        let presence = self.presence.read().ok();
        let peer_activity = self.peer_activity.load();
        let link_status = self.link_status.read().ok();
        let other_link_status = self.other_link_status.read().ok();
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
            statuses.extend(other_endpoint_peer_statuses(&other_link_status, now));
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
        let Some(link_status) = self.link_status.read().ok() else {
            return Vec::new();
        };
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
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))? = link_status;
        *self
            .other_link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh other link status lock poisoned"))? = other_link_status;
        Ok(())
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        self.endpoint
            .relay_statuses()
            .await
            .context("failed to snapshot FIPS endpoint relays")
            .map(|relays| {
                relays
                    .into_iter()
                    .map(|relay| FipsRelayStatus {
                        url: relay.url,
                        status: relay.status,
                    })
                    .collect()
            })
    }

    pub(crate) async fn local_advertised_endpoints(&self) -> Result<Vec<OverlayEndpointAdvert>> {
        self.endpoint
            .local_advertised_endpoints()
            .await
            .context("failed to snapshot FIPS local advertised endpoints")
    }

    pub(crate) async fn update_relays(&self, relays: &[String]) -> Result<()> {
        self.endpoint
            .update_relays(relays.to_vec())
            .await
            .context("failed to update FIPS endpoint relays")
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
        let link_status = self
            .link_status
            .read()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?;
        let mut due = participants
            .into_iter()
            .filter_map(|participant| {
                let participant_key = participant_pubkey_bytes(&participant);
                let peer_presence = presence.get(&participant);
                let link_connected = link_status
                    .get(&participant)
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
        self.link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh link status lock poisoned"))?
            .retain(|participant, _| configured.iter().any(|value| value == participant));
        self.other_link_status
            .write()
            .map_err(|_| anyhow!("FIPS mesh other link status lock poisoned"))?
            .clear();
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
    ) -> Result<()> {
        let normalized = normalize_nostr_pubkey(participant)?;
        let mut caps = self
            .peer_capabilities
            .write()
            .map_err(|_| anyhow!("FIPS mesh peer capabilities lock poisoned"))?;
        match caps.get(&normalized) {
            Some(existing) if existing.capabilities.signed_at > capabilities.signed_at => {
                return Ok(());
            }
            _ => {}
        }
        caps.insert(
            normalized,
            PeerCapabilitiesEntry {
                capabilities: capabilities.clone(),
                received_at: now,
            },
        );
        Ok(())
    }

}

fn prioritize_fips_peer_pings(due: &mut [(String, Option<u64>)]) {
    due.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
}
