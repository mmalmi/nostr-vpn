#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FipsPeerAddressHint {
    addr: String,
    seen_at_ms: Option<u64>,
    #[serde(default = "default_fips_peer_address_priority")]
    priority: u8,
}

const FIPS_STATIC_PEER_ENDPOINT_PRIORITY: u8 = 10;
const FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY: u8 = 100;
const FIPS_PRIVATE_DYNAMIC_PEER_ENDPOINT_PRIORITY: u8 = 200;
// Mobile probes offline roster peers on its own bounded cadence. Let FIPS
// exhaust each connection attempt so dormant devices cannot keep the packet
// tunnel awake in a permanent fast-reconnect loop.
const FIPS_MOBILE_AUTO_RECONNECT: bool = false;

fn default_fips_peer_address_priority() -> u8 {
    FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY
}

#[derive(Debug, Clone, Default)]
struct MobilePeerPresence {
    last_seen_at: Option<u64>,
    last_control_seen_at: Option<u64>,
    last_data_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    last_ping_started_at: Option<Instant>,
    rtt_ms: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
enum MobilePeerRxKind {
    Control,
    Data,
}

struct MobileEndpointReceiveContext<'a> {
    endpoint: &'a FipsEndpoint,
    mesh: &'a MobileMesh,
    mesh_peers: &'a Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    peer_identities: &'a Arc<RwLock<MobilePeerIdentityMap>>,
    peer_hints: &'a Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
    presence: &'a Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config_state: &'a Arc<RwLock<MobileTunnelConfig>>,
    app_config: &'a Arc<RwLock<AppConfig>>,
    app_config_dirty: &'a AtomicBool,
    pending_join_roster_receipts: &'a PendingJoinRosterReceipts,
    config_path: Option<&'a Path>,
    join_request_active: &'a AtomicBool,
    #[cfg_attr(not(feature = "paid-exit"), allow(dead_code))]
    state_control: &'a FipsControlTcpSender,
}

fn mobile_timestamp_within_grace(now: u64, timestamp: u64, grace_secs: u64) -> bool {
    if timestamp > now {
        return timestamp - now <= MOBILE_PEER_MAX_FUTURE_SKEW_SECS;
    }
    now - timestamp <= grace_secs
}

fn credible_mobile_timestamp(now: u64, timestamp: Option<u64>) -> Option<u64> {
    let timestamp = timestamp?;
    if timestamp > now && timestamp - now > MOBILE_PEER_MAX_FUTURE_SKEW_SECS {
        return None;
    }
    Some(timestamp)
}

fn mobile_elapsed_at_least(now: u64, timestamp: u64, interval_secs: u64) -> bool {
    if timestamp > now {
        return timestamp - now > MOBILE_PEER_MAX_FUTURE_SKEW_SECS;
    }
    now - timestamp >= interval_secs
}

async fn handle_mobile_endpoint_message(
    control: &MobileEndpointReceiveContext<'_>,
    inbound_packets: &mut Vec<Vec<u8>>,
    message: FipsEndpointMessage,
) -> Result<bool> {
    if handle_mobile_probe_datagram(control, &message).await? {
        return Ok(true);
    }

    let source_peer = message.source_peer;
    let source_node_addr = *source_peer.node_addr();
    let message_len = message.data.len();
    let packet = control.mesh.read().ok().and_then(|mesh| {
        mesh.receive_endpoint_data_owned_with_source_node_addr(
            source_node_addr.as_bytes(),
            message.data.into_vec(),
        )
        .map(|packet| (packet.source_pubkey.to_string(), packet.bytes))
    });
    if let Some((source_pubkey, mut bytes)) = packet {
        note_mobile_peer_rx(
            control.presence,
            &source_pubkey,
            message_len,
            MobilePeerRxKind::Data,
        );
        let local_address = control
            .config_state
            .read()
            .ok()
            .and_then(|config| parse_ipv4(&config.local_address));
        if let Some(reply) = local_address.and_then(|local_address| {
            nostr_vpn_core::packet_checksums::ipv4_icmp_echo_reply(&bytes, local_address)
        }) {
            control
                .endpoint
                .send_batch_to_peer(source_peer, vec![reply])
                .await
                .context("failed to send mobile ICMP echo reply")?;
            return Ok(true);
        }
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut bytes);
        inbound_packets.push(bytes);
    }
    Ok(true)
}

async fn handle_mobile_probe_datagram(
    control: &MobileEndpointReceiveContext<'_>,
    message: &FipsEndpointMessage,
) -> Result<bool> {
    let Some(frame) = decode_fips_control_frame(message.data.as_slice())? else {
        return Ok(false);
    };
    if !matches!(frame, FipsControlFrame::Ping { .. } | FipsControlFrame::Pong { .. }) {
        return Ok(true);
    }
    handle_mobile_control_frame(control, message.source_peer, message.data.len(), frame).await?;
    Ok(true)
}

async fn handle_mobile_state_control_frame(
    control: &MobileEndpointReceiveContext<'_>,
    received: ReceivedFipsControlFrame,
) -> Result<()> {
    let encoded_len = encode_fips_control_frame(&received.frame)?.len();
    handle_mobile_control_frame(
        control,
        received.source_peer,
        encoded_len,
        received.frame,
    )
    .await
}

async fn handle_mobile_control_frame(
    control: &MobileEndpointReceiveContext<'_>,
    source_peer: PeerIdentity,
    encoded_len: usize,
    frame: FipsControlFrame,
) -> Result<()> {
    let network_matches = {
        let config = control
            .config_state
            .read()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
        control_frame_network_matches(&config.network_id, &frame)
    };
    if !network_matches {
        return Ok(());
    }
    let Some(source_pubkey) = mobile_control_source_pubkey(control.mesh, source_peer, &frame)? else {
        return Ok(());
    };
    note_mobile_peer_rx(
        control.presence,
        &source_pubkey,
        encoded_len,
        MobilePeerRxKind::Control,
    );

    match frame {
        FipsControlFrame::JoinRoster { control: join_roster } => {
            apply_mobile_join_roster_frame(control, source_peer, join_roster.as_ref()).await?;
        }
        FipsControlFrame::JoinRosterAck { .. } => {}
        FipsControlFrame::Roster { signed_roster, .. } => {
            apply_mobile_roster_frame(control, signed_roster.as_deref()).await?;
        }
        FipsControlFrame::Capabilities { capabilities, .. } => {
            if update_mobile_peer_hints(control.peer_hints, &source_pubkey, &capabilities)? {
                sync_mobile_config_peer_hints(control.config_state, control.peer_hints)?;
                persist_mobile_peer_hints(
                    control.app_config,
                    control.app_config_dirty,
                    control.config_path,
                    &source_pubkey,
                    &capabilities,
                )?;
                refresh_mobile_endpoint_peers(
                    control.endpoint,
                    control.config_state,
                )
                .await?;
            }
        }
        FipsControlFrame::Ping {
            network_id,
            sent_at,
        } => {
            reply_mobile_ping(control.endpoint, source_peer, network_id, sent_at).await?;
        }
        FipsControlFrame::JoinRequest {
            requested_at,
            request,
        } => {
            record_mobile_join_request(
                control.app_config,
                control.app_config_dirty,
                control.config_path,
                &source_pubkey,
                requested_at,
                &request,
            )?;
        }
        FipsControlFrame::Pong { sent_at, .. } => {
            note_mobile_peer_pong(control.presence, &source_pubkey, sent_at);
        }
        #[cfg(feature = "paid-exit")]
        FipsControlFrame::PaidRouteSessionOpen { .. } => {
            // Mobile clients can buy paid exits, but do not advertise or host
            // public paid-exit service sessions.
        }
        #[cfg(feature = "paid-exit")]
        FipsControlFrame::PaidRouteSessionOpenAck { .. } => {}
        #[cfg(feature = "paid-exit")]
        payment @ FipsControlFrame::PaidRoutePayment { .. } => {
            handle_mobile_paid_route_payment(control, source_peer, &source_pubkey, payment)
                .await?;
        }
        #[cfg(feature = "paid-exit")]
        FipsControlFrame::PaidRoutePaymentAck { id } => {
            handle_mobile_paid_route_payment_ack(control, &source_pubkey, &id)?;
        }
    }
    Ok(())
}

#[cfg(feature = "paid-exit")]
async fn handle_mobile_paid_route_payment(
    control: &MobileEndpointReceiveContext<'_>,
    source_peer: PeerIdentity,
    source_pubkey: &str,
    frame: FipsControlFrame,
) -> Result<()> {
    let FipsControlFrame::PaidRoutePayment { id, envelope } = frame else {
        return Err(anyhow!("mobile paid route payment frame unavailable"));
    };
    if nostr_vpn_core::paid_route_store::paid_route_payment_id(&envelope)? != id {
        return Err(anyhow!("paid route payment id does not match envelope"));
    }
    let buyer_pubkey =
        normalize_nostr_pubkey(&envelope.buyer).context("invalid paid route payment buyer")?;
    if buyer_pubkey != source_pubkey {
        return Err(anyhow!(
            "paid route payment buyer does not match authenticated FIPS source"
        ));
    }
    let config_path = control
        .config_path
        .ok_or_else(|| anyhow!("mobile paid route config path unavailable"))?;
    let paid_exit = {
        let app = control
            .app_config
            .read()
            .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
        if !app.paid_exit.enabled {
            return Err(anyhow!("paid exit selling is disabled"));
        }
        app.paid_exit.clone()
    };
    let store_path = nostr_vpn_core::paid_route_store::paid_route_store_file_path(config_path);
    nostr_vpn_core::paid_route_store::apply_paid_route_seller_payment_file(
        &store_path,
        nostr_vpn_core::paid_route_store::ApplyPaidRouteSellerPaymentRequest {
            envelope,
            seller_npub: control.endpoint.npub().to_string(),
            config: paid_exit,
            now_unix: unix_timestamp(),
        },
    )?;
    let ack = FipsControlFrame::PaidRoutePaymentAck { id };
    control
        .state_control
        .send(source_peer, &ack)
        .await
        .map(|_| ())
        .context("failed to acknowledge mobile paid route payment")
}

#[cfg(feature = "paid-exit")]
fn handle_mobile_paid_route_payment_ack(
    control: &MobileEndpointReceiveContext<'_>,
    source_pubkey: &str,
    id: &str,
) -> Result<()> {
    let config_path = control
        .config_path
        .ok_or_else(|| anyhow!("mobile paid route config path unavailable"))?;
    nostr_vpn_core::paid_route_store::acknowledge_paid_route_payment_outbox(
        config_path,
        source_pubkey,
        id,
    )?;
    Ok(())
}

async fn apply_mobile_roster_frame(
    control: &MobileEndpointReceiveContext<'_>,
    signed_roster: Option<&SignedRoster>,
) -> Result<()> {
    let Some(updated) = apply_mobile_roster(
        control.app_config,
        control.app_config_dirty,
        control.config_path,
        signed_roster,
    )?
    else {
        return Ok(());
    };
    apply_mobile_roster_runtime_update(control, updated).await
}

async fn apply_mobile_roster_runtime_update(
    control: &MobileEndpointReceiveContext<'_>,
    updated: MobileTunnelConfig,
) -> Result<()> {
    let discovery_scope_changed = {
        let current = control
            .config_state
            .read()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
        normalize_runtime_network_id(&current.network_id)
            != normalize_runtime_network_id(&updated.network_id)
    };
    let local_routes = vec![updated.local_address.clone()];
    let updated_peers = updated.peers.clone();
    let updated_peer_identities = mobile_peer_identity_map(&updated_peers);
    let updated_hints = updated.peer_hints.clone();
    replace_mobile_mesh(
        control.mesh,
        FipsMeshRuntime::with_local_routes(updated_peers.clone(), local_routes),
    )?;
    {
        let mut peers = control
            .mesh_peers
            .write()
            .map_err(|_| anyhow!("mobile FIPS peer lock poisoned"))?;
        *peers = updated_peers;
    }
    {
        let mut identities = control
            .peer_identities
            .write()
            .map_err(|_| anyhow!("mobile FIPS peer identity lock poisoned"))?;
        *identities = updated_peer_identities;
    }
    {
        let mut hints = control
            .peer_hints
            .write()
            .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?;
        *hints = updated_hints;
    }
    {
        let mut config = control
            .config_state
            .write()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
        *config = updated.clone();
    }
    if updated.pending_join_request_recipient.trim().is_empty() {
        control.join_request_active.store(false, Ordering::Relaxed);
    }
    if discovery_scope_changed {
        // The FIPS discovery scope is fixed when the endpoint binds. Keep the
        // authenticated onboarding route alive until the mobile host consumes
        // the joined config and restarts the packet tunnel in its new scope.
        // Replacing peers here would drop that only working route first.
        return Ok(());
    }
    refresh_mobile_endpoint_peers(
        control.endpoint,
        control.config_state,
    )
    .await
}

async fn apply_mobile_join_roster_frame(
    control: &MobileEndpointReceiveContext<'_>,
    source_peer: PeerIdentity,
    join_roster: &JoinRosterControl,
) -> Result<()> {
    let updated = apply_mobile_join_roster(
        control.app_config,
        control.app_config_dirty,
        control.config_path,
        join_roster,
    )?;
    let applied = updated.is_some()
        || mobile_join_roster_is_durably_persisted(
            control.app_config,
            control.config_path,
            join_roster,
        )?;
    if !applied {
        return Ok(());
    }
    let roster_event_id = join_roster.signed_roster.artifact_hash();
    let committed =
        control.config_path.is_some() || !control.app_config_dirty.load(Ordering::Acquire);
    control
        .pending_join_roster_receipts
        .enqueue(roster_event_id, source_peer, committed)?;
    if let Some(updated) = updated {
        apply_mobile_roster_runtime_update(control, updated).await?;
    }
    Ok(())
}

async fn reply_mobile_ping(
    endpoint: &FipsEndpoint,
    source_peer: PeerIdentity,
    network_id: String,
    sent_at: u64,
) -> Result<()> {
    let reply = FipsControlFrame::Pong {
        network_id,
        sent_at,
        replied_at: unix_timestamp(),
    };
    let encoded = encode_fips_control_frame(&reply)?;
    if let Err(error) = endpoint
        .send_batch_to_peer(source_peer, vec![encoded])
        .await
    {
        tracing::warn!(?error, "mobile: failed to reply to FIPS peer ping");
    }
    Ok(())
}

fn mobile_control_source_pubkey(
    mesh: &MobileMesh,
    source_peer: PeerIdentity,
    frame: &FipsControlFrame,
) -> Result<Option<String>> {
    let mesh = mobile_mesh_snapshot(mesh)?;
    Ok(control_frame_source_pubkey(&mesh, source_peer, frame))
}

fn control_frame_network_matches(expected_network_id: &str, frame: &FipsControlFrame) -> bool {
    let frame_network_id = match frame {
        FipsControlFrame::Ping { network_id, .. }
        | FipsControlFrame::Pong { network_id, .. }
        | FipsControlFrame::Roster { network_id, .. }
        | FipsControlFrame::Capabilities { network_id, .. } => network_id,
        FipsControlFrame::JoinRoster { .. } | FipsControlFrame::JoinRosterAck { .. } => return true,
        FipsControlFrame::JoinRequest { request, .. } => &request.network_id,
        #[cfg(feature = "paid-exit")]
        FipsControlFrame::PaidRouteSessionOpen { .. }
        | FipsControlFrame::PaidRouteSessionOpenAck { .. }
        | FipsControlFrame::PaidRoutePayment { .. }
        | FipsControlFrame::PaidRoutePaymentAck { .. } => return true,
    };
    normalize_runtime_network_id(expected_network_id)
        == normalize_runtime_network_id(frame_network_id)
}

fn control_frame_source_pubkey(
    mesh: &FipsMeshRuntime,
    source_peer: PeerIdentity,
    frame: &FipsControlFrame,
) -> Option<String> {
    mesh.participant_for_endpoint_node_addr(source_peer.node_addr().as_bytes())
        .or_else(|| {
            let allow_unknown = matches!(
                frame,
                FipsControlFrame::JoinRequest { .. }
                    | FipsControlFrame::JoinRoster { .. }
                    | FipsControlFrame::JoinRosterAck { .. }
            );
            #[cfg(feature = "paid-exit")]
            let allow_unknown =
                allow_unknown
                    || matches!(
                        frame,
                        FipsControlFrame::PaidRouteSessionOpen { .. }
                            | FipsControlFrame::PaidRoutePayment { .. }
                    );
            allow_unknown.then(|| source_peer.pubkey().to_string())
        })
}

#[derive(Debug, Clone, Default)]
struct MobilePeerIdentityMap {
    by_participant: HashMap<MobileParticipantPubkeyBytes, PeerIdentity>,
    by_endpoint_node_addr: HashMap<[u8; 16], PeerIdentity>,
}

type MobileParticipantPubkeyBytes = [u8; 32];

impl MobilePeerIdentityMap {
    fn identity_for_send(
        &self,
        participant: Option<&MobileParticipantPubkeyBytes>,
        endpoint_node_addr: &[u8; 16],
    ) -> Option<PeerIdentity> {
        self.by_endpoint_node_addr
            .get(endpoint_node_addr)
            .or_else(|| participant.and_then(|pubkey| self.by_participant.get(pubkey)))
            .copied()
    }

    fn identity_for_participant(&self, participant: &str) -> Option<PeerIdentity> {
        let participant = mobile_participant_pubkey_bytes(participant)?;
        self.identity_for_participant_bytes(&participant)
    }

    fn identity_for_participant_bytes(
        &self,
        participant: &MobileParticipantPubkeyBytes,
    ) -> Option<PeerIdentity> {
        self.by_participant.get(participant).copied()
    }
}

fn mobile_peer_identity_map(peers: &[FipsMeshPeerConfig]) -> MobilePeerIdentityMap {
    let mut identities = MobilePeerIdentityMap::default();
    for peer in peers {
        let endpoint_npub = normalize_mobile_endpoint_npub(&peer.endpoint_npub);
        let Ok(identity) = PeerIdentity::from_npub(&endpoint_npub) else {
            continue;
        };

        if let Some(participant) = mobile_participant_pubkey_bytes(&peer.participant_pubkey) {
            identities.by_participant.insert(participant, identity);
        }
        identities
            .by_endpoint_node_addr
            .insert(*identity.node_addr().as_bytes(), identity);
    }
    identities
}

fn mobile_identity_for_send(
    identities: &MobilePeerIdentityMap,
    participant: Option<&MobileParticipantPubkeyBytes>,
    endpoint_node_addr: &[u8; 16],
) -> Option<PeerIdentity> {
    identities.identity_for_send(participant, endpoint_node_addr)
}

fn mobile_participant_pubkey_bytes(value: &str) -> Option<MobileParticipantPubkeyBytes> {
    PublicKey::parse(value.trim())
        .ok()
        .map(|pubkey| *pubkey.as_bytes())
}

fn normalize_mobile_endpoint_npub(value: &str) -> String {
    let trimmed = value.trim();
    normalize_nostr_pubkey(trimmed).ok().map_or_else(
        || trimmed.to_string(),
        |pubkey| nostr_vpn_core::config::npub_for_pubkey_hex(&pubkey),
    )
}

struct MobileEndpointSendRun {
    participant_fallback: Option<String>,
    participant_key: Option<MobileParticipantPubkeyBytes>,
    endpoint_node_addr: [u8; 16],
    identity: PeerIdentity,
    payloads: Vec<Vec<u8>>,
    packet_count: usize,
}

impl MobileEndpointSendRun {
    fn new(
        participant_fallback: Option<String>,
        participant_key: Option<MobileParticipantPubkeyBytes>,
        endpoint_node_addr: [u8; 16],
        identity: PeerIdentity,
        payload: Vec<u8>,
    ) -> Self {
        let mut run = Self {
            participant_fallback,
            participant_key,
            endpoint_node_addr,
            identity,
            payloads: Vec::new(),
            packet_count: 0,
        };
        run.push_payload(payload);
        run
    }

    fn matches(
        &self,
        participant_key: Option<MobileParticipantPubkeyBytes>,
        participant_fallback: Option<&str>,
        endpoint_node_addr: &[u8; 16],
    ) -> bool {
        if self.endpoint_node_addr != *endpoint_node_addr {
            return false;
        }
        match (self.participant_key, participant_key) {
            (Some(left), Some(right)) => left == right,
            (None, None) => self.participant_fallback.as_deref() == participant_fallback,
            _ => false,
        }
    }

    fn push_payload(&mut self, payload: Vec<u8>) {
        self.payloads.push(payload);
        self.packet_count = self.packet_count.saturating_add(1);
    }

    fn into_send_parts(self) -> (PeerIdentity, Vec<Vec<u8>>, usize) {
        (self.identity, self.payloads, self.packet_count)
    }
}

struct MobileSecureDnsDispatch {
    resolver: Arc<dyn SecureDnsLookup>,
    tasks: tokio::task::JoinSet<()>,
}

impl MobileSecureDnsDispatch {
    fn new(resolver: impl SecureDnsLookup + 'static) -> Self {
        Self {
            resolver: Arc::new(resolver),
            tasks: tokio::task::JoinSet::new(),
        }
    }

    fn try_spawn_response(
        &mut self,
        packet: Vec<u8>,
        app_config: Arc<RwLock<AppConfig>>,
        magic_dns_server: Ipv4Addr,
        inbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
    ) -> bool {
        while self.tasks.try_join_next().is_some() {}
        if self.tasks.len() >= MOBILE_SECURE_DNS_MAX_IN_FLIGHT {
            return false;
        }
        let resolver = Arc::clone(&self.resolver);
        self.tasks.spawn(async move {
            if let Some(MobileDnsPacketAction::Respond(response)) = mobile_dns_packet_action(
                &packet,
                &app_config,
                Some(resolver.as_ref()),
                magic_dns_server,
                false,
            )
            .await
            {
                let _ = inbound_tx.send(vec![response]).await;
            }
        });
        true
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_mobile_outbound_packets(
    endpoint: &FipsEndpoint,
    mesh: &MobileMesh,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    wg_send_tx: Option<&tokio_mpsc::Sender<Vec<Vec<u8>>>>,
    wg_addr: Option<Ipv4Addr>,
    mesh_addr: Option<Ipv4Addr>,
    inbound_tx_for_dns: &tokio_mpsc::Sender<Vec<Vec<u8>>>,
    app_config_for_dns: &Arc<RwLock<AppConfig>>,
    secure_dns: &mut Option<MobileSecureDnsDispatch>,
    magic_dns_server: Option<Ipv4Addr>,
    exit_dns_nat: Option<&MobileExitDnsNat>,
    packets: Vec<Vec<u8>>,
) -> bool {
    let mut pending_run = None;
    let mut pending_dns_responses = Vec::new();
    let mut pending_wg_packets = Vec::new();
    let mesh = mesh.read().ok().map(|mesh| Arc::clone(&*mesh));
    for mut packet in packets {
        // With the Android app UID captured, reqwest's DoH connection returns
        // through this same TUN. Resolve off-loop so its TCP packets can reach
        // WG. The tunnel-owned JoinSet bounds work, aborts it on tunnel stop,
        // and lets saturation fall through to the SERVFAIL path below.
        if let (Some(secure_dns), Some(magic_dns_server)) =
            (secure_dns.as_mut(), magic_dns_server)
            && exit_dns_nat.is_none()
            && parse_mobile_magic_dns_query(&packet, magic_dns_server).is_some()
            && secure_dns.try_spawn_response(
                packet.clone(),
                Arc::clone(app_config_for_dns),
                magic_dns_server,
                inbound_tx_for_dns.clone(),
            )
        {
            continue;
        }

        // Local MagicDNS responder. The well-known DNS address is owned by this
        // tunnel instance, so answer before mesh/WG routing and never treat it
        // as a remote nvpn node.
        if let Some(magic_dns_server) = magic_dns_server
            && let Some(action) = mobile_dns_packet_action(
                &packet,
                app_config_for_dns,
                None,
                magic_dns_server,
                exit_dns_nat.is_some(),
            )
            .await
        {
            match action {
                MobileDnsPacketAction::Respond(response) => {
                    if !flush_mobile_endpoint_send_run(endpoint, &mut pending_run).await {
                        return false;
                    }
                    if !flush_mobile_wg_packets(wg_send_tx, &mut pending_wg_packets).await {
                        return false;
                    }
                    pending_dns_responses.push(response);
                    continue;
                }
                MobileDnsPacketAction::ForwardViaExit => {}
            }
        }

        if !flush_mobile_inbound_packets(inbound_tx_for_dns, &mut pending_dns_responses).await {
            return false;
        }

        if let Some(exit_dns_nat) = exit_dns_nat {
            exit_dns_nat.rewrite_query(&mut packet);
        }

        let outgoing_peer = mesh.as_ref().and_then(|mesh| {
            mesh.route_outbound_packet_peer(&packet).map(|peer| {
                (
                    peer.participant_pubkey_bytes
                        .is_none()
                        .then(|| peer.participant_pubkey.to_string()),
                    peer.participant_pubkey_bytes.copied(),
                    *peer.endpoint_node_addr,
                )
            })
        });
        if let Some((participant_fallback, participant_key, endpoint_node_addr)) = outgoing_peer {
            if !flush_mobile_wg_packets(wg_send_tx, &mut pending_wg_packets).await {
                return false;
            }
            if let Some(run) = push_mobile_endpoint_send_run(
                &mut pending_run,
                peer_identities,
                participant_fallback,
                participant_key,
                endpoint_node_addr,
                packet,
            ) && !send_mobile_endpoint_run(endpoint, run).await
            {
                return false;
            }
            continue;
        }

        if !flush_mobile_endpoint_send_run(endpoint, &mut pending_run).await {
            return false;
        }
        if wg_send_tx.is_some() {
            push_mobile_wg_packet(&mut pending_wg_packets, packet, wg_addr, mesh_addr);
        }
    }
    if !flush_mobile_inbound_packets(inbound_tx_for_dns, &mut pending_dns_responses).await {
        return false;
    }
    if !flush_mobile_wg_packets(wg_send_tx, &mut pending_wg_packets).await {
        return false;
    }
    flush_mobile_endpoint_send_run(endpoint, &mut pending_run).await
}

async fn flush_mobile_inbound_packets(
    inbound_tx: &tokio_mpsc::Sender<Vec<Vec<u8>>>,
    packets: &mut Vec<Vec<u8>>,
) -> bool {
    if packets.is_empty() {
        return true;
    }
    let batch = std::mem::replace(packets, Vec::with_capacity(MOBILE_FIPS_RECV_BATCH));
    inbound_tx.send(batch).await.is_ok()
}

async fn flush_mobile_wg_packets(
    wg_tx: Option<&tokio_mpsc::Sender<Vec<Vec<u8>>>>,
    packets: &mut Vec<Vec<u8>>,
) -> bool {
    if packets.is_empty() {
        return true;
    }
    let Some(wg_tx) = wg_tx else {
        packets.clear();
        return true;
    };
    let batch = std::mem::replace(packets, Vec::with_capacity(MOBILE_FIPS_SEND_BATCH));
    wg_tx.send(batch).await.is_ok()
}

fn push_mobile_endpoint_send_run(
    run: &mut Option<MobileEndpointSendRun>,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    participant_fallback: Option<String>,
    participant_key: Option<MobileParticipantPubkeyBytes>,
    endpoint_node_addr: [u8; 16],
    packet: Vec<u8>,
) -> Option<MobileEndpointSendRun> {
    if let Some(current) = run.as_mut()
        && current.matches(
            participant_key,
            participant_fallback.as_deref(),
            &endpoint_node_addr,
        )
    {
        current.push_payload(packet);
        return None;
    }

    let identity = peer_identities.read().ok().and_then(|identities| {
        mobile_identity_for_send(&identities, participant_key.as_ref(), &endpoint_node_addr)
    });
    let Some(identity) = identity else {
        return run.take();
    };

    let previous = run.take();
    *run = Some(MobileEndpointSendRun::new(
        participant_fallback,
        participant_key,
        endpoint_node_addr,
        identity,
        packet,
    ));
    previous
}

async fn flush_mobile_endpoint_send_run(
    endpoint: &FipsEndpoint,
    run: &mut Option<MobileEndpointSendRun>,
) -> bool {
    if let Some(run) = run.take() {
        send_mobile_endpoint_run(endpoint, run).await
    } else {
        true
    }
}

async fn send_mobile_endpoint_run(endpoint: &FipsEndpoint, run: MobileEndpointSendRun) -> bool {
    let (identity, payloads, packet_count) = run.into_send_parts();
    if packet_count == 0 {
        return true;
    }
    match endpoint.send_batch_to_peer(identity, payloads).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                ?error,
                packet_count,
                "mobile: failed to send FIPS endpoint data batch"
            );
            false
        }
    }
}

fn push_mobile_wg_packet(
    packets: &mut Vec<Vec<u8>>,
    mut packet: Vec<u8>,
    wg_addr: Option<Ipv4Addr>,
    mesh_addr: Option<Ipv4Addr>,
) {
    // No matching mesh peer route: hand the plaintext off to the WG runtime,
    // which will boringtun-encapsulate and send out via the upstream UDP
    // socket. SNAT first so the inner source IP matches the WG peer's
    // configured address; Mullvad/Proton silently drop other source IPs.
    if let (Some(wg), Some(mesh)) = (wg_addr, mesh_addr) {
        rewrite_ipv4_source(&mut packet, mesh, wg);
        nostr_vpn_core::packet_checksums::finalize_ipv4_transport_checksum(&mut packet);
    }
    packets.push(packet);
}

async fn send_mobile_endpoint_data(
    endpoint: &FipsEndpoint,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    participant: &str,
    data: Vec<u8>,
) -> Result<()> {
    let participant_key = mobile_participant_pubkey_bytes(participant);
    let identity =
        peer_identities
            .read()
            .ok()
            .and_then(|identities| match participant_key.as_ref() {
                Some(participant) => identities.identity_for_participant_bytes(participant),
                None => identities.identity_for_participant(participant),
            });
    let identity = identity.ok_or_else(|| {
        anyhow!("missing mobile FIPS endpoint identity for participant {participant}")
    })?;
    endpoint
        .send_batch_to_peer(identity, vec![data])
        .await
        .context("failed to send mobile FIPS endpoint data")
}

async fn send_mobile_state_control(
    state_control: &FipsControlTcpSender,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    participant: &str,
    frame: &FipsControlFrame,
) -> Result<usize> {
    let participant_key = mobile_participant_pubkey_bytes(participant);
    let identity = peer_identities.read().ok().and_then(|identities| {
        participant_key
            .as_ref()
            .and_then(|participant| identities.identity_for_participant_bytes(participant))
            .or_else(|| identities.identity_for_participant(participant))
    });
    let identity = identity.ok_or_else(|| {
        anyhow!("missing mobile FIPS endpoint identity for participant {participant}")
    })?;
    state_control
        .send(identity, frame)
        .await
        .with_context(|| format!("failed to send mobile FIPS-TCP control to {participant}"))
}
