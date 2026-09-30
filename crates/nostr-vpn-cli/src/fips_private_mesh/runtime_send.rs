impl FipsPrivateMeshRuntime {
    pub(crate) async fn bind_with_config_scoped(
        identity_nsec: impl Into<String>,
        scope: Option<String>,
        peers: Vec<FipsMeshPeerConfig>,
        config: Config,
        local_allowed_ips: Vec<String>,
        local_tunnel_ips: Vec<IpAddr>,
        paid_route_admissions: Vec<FipsPaidRouteAdmission>,
    ) -> Result<Self> {
        let mut endpoint_builder = FipsEndpoint::builder()
            .config(config)
            .identity_nsec(identity_nsec)
            .local_rendezvous()
            .without_system_tun();
        if let Some(scope) = scope.map(|scope| scope.trim().to_string()).filter(|s| !s.is_empty())
        {
            endpoint_builder = endpoint_builder.discovery_scope(scope);
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        let (endpoint, direct_endpoint_rx) = endpoint_builder
            .bind_with_direct_receiver()
            .await
            .context("failed to bind embedded FIPS endpoint")?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        let endpoint = Arc::new(endpoint);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let endpoint = Arc::new(endpoint_builder
            .bind()
            .await
            .context("failed to bind embedded FIPS endpoint")?);
        let peer_identities = peer_identity_map(&peers);
        let mesh = FipsMeshRuntime::with_local_routes_and_paid_route_admissions(
            peers,
            local_allowed_ips,
            paid_route_admissions,
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let local_tunnel_ips = local_tunnel_ips.into_iter().collect();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = local_tunnel_ips;
        let peer_activity = peer_activity_map(&mesh.peer_pubkeys(), None);

        Ok(Self {
            endpoint,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            direct_endpoint_rx,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            local_tunnel_ips,
            mesh: ArcSwap::from_pointee(mesh),
            mesh_generation: AtomicU64::new(0),
            peer_activity: ArcSwap::from_pointee(peer_activity),
            peer_identities: ArcSwap::from_pointee(peer_identities),
            presence: RwLock::new(HashMap::new()),
            link_status: RwLock::new(HashMap::new()),
            other_link_status: RwLock::new(HashMap::new()),
            peer_capabilities: RwLock::new(HashMap::new()),
            #[cfg(feature = "paid-exit")]
            paid_route_accounting: Mutex::new(FipsPaidRouteAccounting::default()),
        })
    }

    #[cfg(target_os = "windows")]
    fn blocking_send_tunnel_packet_batch_owned_with_capacity(
        &self,
        packets: Vec<Vec<u8>>,
        turn_capacity: usize,
        runs: &mut Vec<FipsEndpointIdentitySendRun>,
    ) -> Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let input_packets = packets.len();
        let mesh = self.mesh.load();
        let peer_identities = self.peer_identities.load();
        let mut routed_packets = 0usize;

        runs.clear();
        {
            let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshRoute);
            for packet in packets {
                let Some(outgoing) = mesh.route_outbound_packet_owned_with_peer(packet) else {
                    continue;
                };
                routed_packets += 1;
                let participant_key = outgoing.participant_pubkey_bytes.copied();
                #[cfg(feature = "paid-exit")]
                self.note_paid_route_outbound_packet(
                    Some(outgoing.participant_pubkey),
                    outgoing.participant_pubkey_bytes,
                    &outgoing.bytes,
                )?;
                Self::push_endpoint_send_run(
                    runs,
                    &peer_identities,
                    outgoing.participant_pubkey,
                    participant_key,
                    outgoing.endpoint_node_addr,
                    outgoing.bytes,
                );
            }
        }
        drop(peer_identities);
        drop(mesh);

        crate::pipeline_profile::record_mesh_send_batch(
            input_packets,
            routed_packets,
            runs.len(),
            turn_capacity,
        );

        let _t =
            crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshEndpointSend);
        self.blocking_send_endpoint_send_runs(runs.drain(..))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn blocking_send_tun_pipeline_packet_turn<I>(
        &self,
        packets: I,
        turn_capacity: usize,
        runs: &mut Vec<FipsEndpointIdentitySendRun>,
    ) -> Result<usize>
    where
        I: IntoIterator<Item = TunPipelinePacket>,
    {
        self.build_tun_pipeline_send_runs(packets, turn_capacity, runs)?;
        let _t =
            crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshEndpointSend);
        self.blocking_send_endpoint_send_runs(runs.drain(..))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn build_tun_pipeline_send_runs<I>(
        &self,
        packets: I,
        turn_capacity: usize,
        runs: &mut Vec<FipsEndpointIdentitySendRun>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = TunPipelinePacket>,
    {
        let mut packets = packets.into_iter();
        let Some(first_packet) = packets.next() else {
            return Ok(());
        };

        debug_assert!(runs.is_empty());
        let mesh = self.mesh.load();
        let peer_identities = self.peer_identities.load();
        let mut input_packets = 0usize;
        let mut routed_packets = 0usize;
        let mut cached_destination_peer = None;

        {
            let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshRoute);
            for packet in std::iter::once(first_packet).chain(packets) {
                input_packets = input_packets.saturating_add(1);
                let destination = packet.destination;
                let packet_debug = fips_unix_packet_debug_enabled();
                let debug_description = packet_debug.then(|| describe_ip_packet(&packet.bytes));
                let routed = match destination {
                    Some(destination) => cached_tun_destination_route(
                        &mesh,
                        &mut cached_destination_peer,
                        destination,
                        packet.bytes,
                    ),
                    None => mesh
                        .route_outbound_packet_owned_with_peer(packet.bytes)
                        .map(RoutedTunPipelinePacket::from),
                };
                let Some(routed) = routed else {
                    if let Some(description) = debug_description {
                        eprintln!("fips: TUN packet had no FIPS route {description}");
                    }
                    continue;
                };
                routed_packets += 1;
                if packet_debug {
                    eprintln!(
                        "fips: TUN packet routed to {} {}",
                        routed.participant_pubkey,
                        describe_ip_packet(&routed.bytes)
                    );
                }
                let participant_key = routed.participant_pubkey_bytes;
                #[cfg(feature = "paid-exit")]
                self.note_paid_route_outbound_packet(
                    Some(routed.participant_pubkey),
                    routed.participant_pubkey_bytes.as_ref(),
                    &routed.bytes,
                )?;
                Self::push_endpoint_send_run(
                    runs,
                    &peer_identities,
                    routed.participant_pubkey,
                    participant_key,
                    &routed.endpoint_node_addr,
                    routed.bytes,
                );
            }
        }
        drop(peer_identities);
        drop(mesh);

        let run_count = runs.len();
        crate::pipeline_profile::record_mesh_send_batch(
            input_packets,
            routed_packets,
            run_count,
            turn_capacity,
        );
        Ok(())
    }

    fn push_endpoint_send_run(
        runs: &mut Vec<FipsEndpointIdentitySendRun>,
        peer_identities: &FipsPeerIdentityMap,
        participant_pubkey: &str,
        participant_key: Option<ParticipantPubkeyBytes>,
        endpoint_node_addr: &[u8; 16],
        payload: Vec<u8>,
    ) {
        if let Some(run) = runs.last_mut()
            && run.matches_endpoint(endpoint_node_addr, participant_key, participant_pubkey)
        {
            run.push_payload(payload);
            return;
        }

        if let Some(identity) = endpoint_identity_for_send(
            peer_identities,
            participant_key.as_ref(),
            endpoint_node_addr,
        ) {
            if let Some(run) = runs.last_mut()
                && run.matches(identity, participant_key, participant_pubkey)
            {
                run.push_payload(payload);
                return;
            }

            let run = FipsEndpointIdentitySendRun::new(
                participant_key
                    .is_none()
                    .then(|| participant_pubkey.to_string()),
                participant_key,
                identity,
                payload,
            );
            runs.push(run);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn blocking_send_endpoint_send_runs<I>(&self, runs: I) -> Result<usize>
    where
        I: IntoIterator<Item = FipsEndpointIdentitySendRun>,
    {
        let mut sent = 0usize;
        for run in runs {
            let packet_count = run.payloads.len();
            self.endpoint
                .blocking_send_batch_to_peer(run.identity, run.payloads)
                .with_context(|| {
                    format!(
                        "failed to send {packet_count} private packets over FIPS endpoint data"
                    )
                })?;
            self.note_tx(
                run.participant_fallback.as_deref(),
                run.participant_key.as_ref(),
                run.bytes_len,
            )?;
            sent += packet_count;
        }

        Ok(sent)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RoutedTunPipelinePacket<'a> {
    participant_pubkey: &'a str,
    participant_pubkey_bytes: Option<ParticipantPubkeyBytes>,
    endpoint_node_addr: [u8; 16],
    bytes: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'a> From<nostr_vpn_core::fips_mesh::RoutedFipsPacket<'a>>
    for RoutedTunPipelinePacket<'a>
{
    fn from(value: nostr_vpn_core::fips_mesh::RoutedFipsPacket<'a>) -> Self {
        Self {
            participant_pubkey: value.participant_pubkey,
            participant_pubkey_bytes: value.participant_pubkey_bytes.copied(),
            endpoint_node_addr: *value.endpoint_node_addr,
            bytes: value.bytes,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cached_tun_destination_route<'a>(
    mesh: &'a FipsMeshRuntime,
    cached: &mut Option<(IpAddr, RoutedFipsPeer<'a>)>,
    destination: IpAddr,
    bytes: Vec<u8>,
) -> Option<RoutedTunPipelinePacket<'a>> {
    let peer = if let Some((cached_destination, peer)) = cached.as_ref()
        && *cached_destination == destination
    {
        *peer
    } else {
        let peer = mesh.route_outbound_destination_peer(destination)?;
        *cached = Some((destination, peer));
        peer
    };
    if peer.via_default_route {
        mesh.note_cached_exit_outbound(*peer.endpoint_node_addr, &bytes);
    }

    Some(RoutedTunPipelinePacket {
        participant_pubkey: peer.participant_pubkey,
        participant_pubkey_bytes: peer.participant_pubkey_bytes.copied(),
        endpoint_node_addr: *peer.endpoint_node_addr,
        bytes,
    })
}
