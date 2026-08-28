// After a roster reload replaces the runtime, give the fresh authenticated
// carrier enough time to finish instead of repeatedly aborting and restarting
// its connection inside the 15-second public-UI join deadline.
pub(crate) const JOIN_ROSTER_DELIVERY_TIMEOUT: Duration = Duration::from_secs(12);

impl FipsPrivateMeshRuntime {
    pub(crate) async fn ping_peers(&self, network_id: &str, now: u64) -> Result<usize> {
        let frame = FipsControlFrame::Ping {
            network_id: network_id.to_string(),
            sent_at: now,
        };
        let participants = self.ping_due_participants(now)?;
        let mut sent = 0usize;
        for participant in participants {
            self.note_ping_attempt(&participant, now)?;
            if self.send_probe_frame(&participant, &frame).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub(crate) async fn send_join_request(
        &self,
        control: &FipsControlTcpRuntime,
        participant: &str,
        requested_at: u64,
        request: MeshJoinRequest,
    ) -> Result<()> {
        self.send_stateful_control_frame(
            control,
            participant,
            &FipsControlFrame::JoinRequest {
                requested_at,
                request,
            },
        )
        .await
    }

    pub(crate) fn enqueue_roster(
        &self,
        control: &FipsControlTcpSender,
        participant: &str,
        signed_roster: SignedRoster,
    ) -> Result<()> {
        let network_id = signed_roster.network_id()?;
        let roster = signed_roster.roster()?;
        self.enqueue_stateful_control_frame(
            control,
            participant,
            &FipsControlFrame::Roster {
                network_id,
                roster,
                signed_roster: Some(Box::new(signed_roster)),
            },
        )
    }

    pub(crate) fn join_roster_delivery(
        self: &Arc<Self>,
        control: FipsControlTcpSender,
        participant: String,
        join_roster: JoinRosterControl,
    ) -> Result<FipsJoinRosterDelivery> {
        let participant_key = participant_pubkey_bytes(&participant);
        let destination = {
            let mesh = self.mesh.load();
            let peer_identities = self.peer_identities.load();
            control_frame_destination_peer(&mesh, &peer_identities, &participant)?
        };
        let runtime = Arc::clone(self);
        Ok(Box::pin(async move {
            let sent_len = send_join_roster_with_receipt(
                &control,
                destination,
                &join_roster,
                JOIN_ROSTER_DELIVERY_TIMEOUT,
            )
            .await
            .with_context(|| {
                format!("failed to deliver and apply FIPS-TCP join roster to {participant}")
            })?;
            runtime.note_tx(Some(&participant), participant_key.as_ref(), sent_len)
        }))
    }

    pub(crate) async fn send_join_roster_ack(
        &self,
        control: &FipsControlTcpRuntime,
        participant: &str,
        roster_event_id: String,
    ) -> Result<()> {
        self.send_stateful_control_frame(
            control,
            participant,
            &FipsControlFrame::JoinRosterAck { roster_event_id },
        )
        .await
    }

    pub(crate) fn enqueue_capabilities(
        &self,
        control: &FipsControlTcpSender,
        participant: &str,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<()> {
        self.enqueue_stateful_control_frame(
            control,
            participant,
            &FipsControlFrame::Capabilities {
                network_id: network_id.to_string(),
                capabilities,
            },
        )
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open(
        &self,
        control: &FipsControlTcpRuntime,
        seller: &str,
        open: PaidRouteSessionOpen,
    ) -> Result<()> {
        self.send_stateful_control_frame(
            control,
            seller,
            &FipsControlFrame::PaidRouteSessionOpen { open },
        )
        .await
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open_ack(
        &self,
        control: &FipsControlTcpRuntime,
        buyer: &str,
        lease_id: String,
    ) -> Result<()> {
        self.send_stateful_control_frame(
            control,
            buyer,
            &FipsControlFrame::PaidRouteSessionOpenAck { lease_id },
        )
        .await
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn enqueue_paid_route_payment(
        &self,
        control: &FipsControlTcpSender,
        seller: &str,
        id: String,
        envelope: StreamingRoutePaymentEnvelope,
    ) -> Result<()> {
        self.enqueue_stateful_control_frame(
            control,
            seller,
            &FipsControlFrame::PaidRoutePayment { id, envelope },
        )
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_payment_ack(
        &self,
        control: &FipsControlTcpRuntime,
        buyer: &str,
        id: String,
    ) -> Result<()> {
        self.send_stateful_control_frame(
            control,
            buyer,
            &FipsControlFrame::PaidRoutePaymentAck { id },
        )
        .await
    }

    async fn send_stateful_control_frame(
        &self,
        control: &FipsControlTcpRuntime,
        participant: &str,
        frame: &FipsControlFrame,
    ) -> Result<()> {
        let participant_key = participant_pubkey_bytes(participant);
        let destination = {
            let mesh = self.mesh.load();
            let peer_identities = self.peer_identities.load();
            control_frame_destination_peer(&mesh, &peer_identities, participant)?
        };
        let sent_len = control
            .send(destination, frame)
            .await
            .with_context(|| format!("failed to send FIPS-TCP control frame to {participant}"))?;
        self.note_tx(Some(participant), participant_key.as_ref(), sent_len)?;
        Ok(())
    }

    fn enqueue_stateful_control_frame(
        &self,
        control: &FipsControlTcpSender,
        participant: &str,
        frame: &FipsControlFrame,
    ) -> Result<()> {
        let participant_key = participant_pubkey_bytes(participant);
        let destination = {
            let mesh = self.mesh.load();
            let peer_identities = self.peer_identities.load();
            control_frame_destination_peer(&mesh, &peer_identities, participant)?
        };
        let queued_len = control
            .enqueue(destination, frame)
            .with_context(|| format!("failed to queue FIPS-TCP control frame to {participant}"))?;
        self.note_tx(Some(participant), participant_key.as_ref(), queued_len)
    }

    async fn send_probe_frame(&self, participant: &str, frame: &FipsControlFrame) -> Result<()> {
        if !matches!(frame, FipsControlFrame::Ping { .. } | FipsControlFrame::Pong { .. }) {
            return Err(anyhow!("stateful control frames require FIPS-TCP"));
        }
        let participant_key = participant_pubkey_bytes(participant);
        let destination = {
            let mesh = self.mesh.load();
            let peer_identities = self.peer_identities.load();
            control_frame_destination_peer(&mesh, &peer_identities, participant)?
        };
        let encoded = encode_fips_control_frame(frame)?;
        let sent_len = encoded.len();
        self.endpoint
            .send_batch_to_peer(destination, vec![encoded])
            .await
            .with_context(|| format!("failed to send FIPS probe to {participant}"))?;
        self.note_tx(Some(participant), participant_key.as_ref(), sent_len)
    }

    fn note_tx(
        &self,
        participant: Option<&str>,
        participant_key: Option<&ParticipantPubkeyBytes>,
        len: usize,
    ) -> Result<()> {
        // Hot path. Dataplane callers pass the already-parsed participant key
        // from FipsMeshRuntime, avoiding per-packet pubkey parsing or
        // string-key hashing for configured peers.
        let parsed_participant_key = participant_key
            .is_none()
            .then(|| participant.and_then(participant_pubkey_bytes))
            .flatten();
        let participant_key = participant_key.or(parsed_participant_key.as_ref());
        let peer_activity = self.peer_activity.load();
        if let Some(activity) = participant_key.and_then(|key| peer_activity.get(key)) {
            activity.note_tx(len);
            return Ok(());
        }
        drop(peer_activity);
        let participant = participant
            .map(str::to_owned)
            .or_else(|| participant_key.map(hex::encode))
            .ok_or_else(|| anyhow!("missing FIPS participant identity for tx accounting"))?;
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(&participant) {
            entry.tx_bytes = entry.tx_bytes.saturating_add(len as u64);
        } else {
            let entry = FipsPeerPresence {
                tx_bytes: len as u64,
                ..Default::default()
            };
            presence.insert(participant, entry);
        }
        Ok(())
    }

    fn note_ping_attempt(&self, participant: &str, now: u64) -> Result<()> {
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(participant) {
            entry.last_ping_sent_at = Some(now);
            entry.last_ping_started_at = Some(Instant::now());
        } else {
            let entry = FipsPeerPresence {
                last_ping_sent_at: Some(now),
                last_ping_started_at: Some(Instant::now()),
                ..Default::default()
            };
            presence.insert(participant.to_string(), entry);
        }
        Ok(())
    }

    fn note_pong(&self, participant: &str, sent_at: u64) -> Result<()> {
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        let Some(entry) = presence.get_mut(participant) else {
            return Ok(());
        };
        if entry.last_ping_sent_at == Some(sent_at)
            && let Some(started_at) = entry.last_ping_started_at.take()
        {
            let elapsed_ms = started_at.elapsed().as_millis();
            if elapsed_ms <= FIPS_CONTROL_RTT_MAX_ACCEPT_MS {
                entry.rtt_ms = Some(elapsed_ms.min(u128::from(u64::MAX)) as u64);
            } else {
                entry.last_ping_sent_at = None;
            }
        }
        Ok(())
    }

    fn note_control_rx(&self, participant: &str, len: usize, now: u64) -> Result<()> {
        self.note_rx(participant, None, len, now, FipsPeerRxKind::Control)
    }

    fn note_data_rx(
        &self,
        participant: &str,
        participant_key: Option<&ParticipantPubkeyBytes>,
        len: usize,
        now: u64,
    ) -> Result<()> {
        self.note_rx(participant, participant_key, len, now, FipsPeerRxKind::Data)
    }

    fn note_rx(
        &self,
        participant: &str,
        participant_key: Option<&ParticipantPubkeyBytes>,
        len: usize,
        now: u64,
        kind: FipsPeerRxKind,
    ) -> Result<()> {
        let parsed_participant_key = participant_key
            .is_none()
            .then(|| participant_pubkey_bytes(participant))
            .flatten();
        let participant_key = participant_key.or(parsed_participant_key.as_ref());
        let peer_activity = self.peer_activity.load();
        if let Some(activity) = participant_key.and_then(|key| peer_activity.get(key)) {
            activity.note_rx(len, now, kind);
            return Ok(());
        }
        drop(peer_activity);
        let mut presence = self
            .presence
            .write()
            .map_err(|_| anyhow!("FIPS mesh presence lock poisoned"))?;
        if let Some(entry) = presence.get_mut(participant) {
            entry.last_seen_at = Some(now);
            match kind {
                FipsPeerRxKind::Control => entry.last_control_seen_at = Some(now),
                FipsPeerRxKind::Data => entry.last_data_seen_at = Some(now),
            }
            entry.rx_bytes = entry.rx_bytes.saturating_add(len as u64);
            entry.error = None;
        } else {
            let mut entry = FipsPeerPresence {
                last_seen_at: Some(now),
                rx_bytes: len as u64,
                error: None,
                ..Default::default()
            };
            match kind {
                FipsPeerRxKind::Control => entry.last_control_seen_at = Some(now),
                FipsPeerRxKind::Data => entry.last_data_seen_at = Some(now),
            }
            presence.insert(participant.to_string(), entry);
        }
        Ok(())
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn set_paid_route_accounting_peers(
        &self,
        participants: Vec<FipsPaidRouteAccountingPeer>,
    ) -> Result<()> {
        let mut accounting = self
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("FIPS paid route accounting lock poisoned"))?;
        accounting.replace_peers(participants);
        Ok(())
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn drain_paid_route_usage(&self, participant: &str) -> Result<PaidRouteUsage> {
        let mut accounting = self
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("FIPS paid route accounting lock poisoned"))?;
        Ok(accounting.drain(participant))
    }

    #[cfg(feature = "paid-exit")]
    fn note_paid_route_outbound_packet(
        &self,
        participant: Option<&str>,
        participant_key: Option<&ParticipantPubkeyBytes>,
        packet: &[u8],
    ) -> Result<()> {
        let mut accounting = self
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("FIPS paid route accounting lock poisoned"))?;
        accounting.record_outbound(participant, participant_key, packet);
        Ok(())
    }

    #[cfg(feature = "paid-exit")]
    fn note_paid_route_inbound_packet(
        &self,
        participant: Option<&str>,
        participant_key: Option<&ParticipantPubkeyBytes>,
        packet: &[u8],
    ) -> Result<()> {
        let mut accounting = self
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("FIPS paid route accounting lock poisoned"))?;
        accounting.record_inbound(participant, participant_key, packet);
        Ok(())
    }

    #[cfg(all(
        feature = "paid-exit",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    fn note_paid_route_inbound_batch(
        &self,
        mesh: &FipsMeshRuntime,
        packets: &DirectTunWriteBatch,
    ) -> Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        let mut accounting = self
            .paid_route_accounting
            .lock()
            .map_err(|_| anyhow!("FIPS paid route accounting lock poisoned"))?;
        for run in &packets.runs {
            let admitter = direct_run_admitter(mesh, run)?;
            for packet in run.packet_slices() {
                accounting.record_inbound(None, admitter.source_pubkey_bytes(), packet);
            }
        }
        Ok(())
    }

    /// Hand the latest peer roster to fips without restarting the endpoint.
    ///
    /// The wrapper translates nvpn's intermediate hint shape
    /// ([`FipsEndpointPeerTransportConfig`]) into `fips_endpoint::PeerConfig`
    /// (carrying `seen_at_ms` per address) and calls
    /// [`fips_endpoint::FipsEndpoint::update_peers`]. fips diffs new vs old,
    /// initiates connections for fresh npubs, drops retry entries for
    /// removed ones, and refreshes address hints in place for the rest.
    pub(crate) async fn update_peers(
        &self,
        endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        let peers: Vec<FipsPeerConfig> = endpoint_peers
            .iter()
            .map(|peer| FipsPeerConfig {
                npub: peer.npub.clone(),
                alias: None,
                addresses: peer
                    .addresses
                    .iter()
                    .flat_map(fips_peer_addresses_from_hint)
                    .collect(),
                connect_policy: if peer.connect_on_start {
                    ConnectPolicy::AutoConnect
                } else {
                    ConnectPolicy::Manual
                },
                auto_reconnect: peer.auto_reconnect,
                discovery_fallback_transit: peer.discovery_fallback_transit,
            })
            .collect();
        self.endpoint
            .update_peers(peers)
            .await
            .context("fips: update_peers rejected by endpoint")
    }

    pub(crate) async fn refresh_peer_paths(
        &self,
        endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<usize> {
        let peers = endpoint_peers
            .iter()
            .map(|peer| {
                PeerIdentity::from_npub(&peer.npub)
                    .with_context(|| format!("invalid FIPS endpoint peer npub {}", peer.npub))
            })
            .collect::<Result<Vec<_>>>()?;
        self.endpoint
            .refresh_peer_paths(peers)
            .await
            .context("fips: refresh_peer_paths rejected by endpoint")
    }

    pub(crate) async fn rebind_network_transports(
        &self,
        bind_interface: Option<String>,
    ) -> Result<usize> {
        self.endpoint
            .rebind_network_transports(bind_interface)
            .await
            .context("fips: network transport rebind rejected by endpoint")
    }
}
