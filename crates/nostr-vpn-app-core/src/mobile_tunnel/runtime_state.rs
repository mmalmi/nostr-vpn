fn apply_mobile_roster(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    signed_roster: Option<&SignedRoster>,
) -> Result<Option<MobileTunnelConfig>> {
    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    app.ensure_defaults();
    let signed_roster =
        signed_roster.ok_or_else(|| anyhow!("FIPS roster frame is missing signed roster event"))?;
    let changed = app.apply_verified_admin_signed_shared_roster(signed_roster)?;
    let apply_network_id = signed_roster.network_id()?;
    if let Some(config_path) = config_path
        && mobile_signed_roster_is_current_for_app(&app, &apply_network_id, signed_roster)
        && let Err(error) = upsert_signed_roster(
            &signed_rosters_file_path(config_path),
            signed_roster.clone(),
        )
    {
        mobile_debug_log(format!(
            "mobile: signed roster saved in config but artifact save failed: {error:#}"
        ));
        tracing::warn!(?error, "mobile: signed roster artifact save failed");
    }
    if !changed {
        return Ok(None);
    }
    maybe_autoconfigure_node(&mut app);
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: roster applied in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: roster applied in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    let config_path = config_path.unwrap_or_else(|| Path::new(""));
    MobileTunnelConfig::from_app_with_config_path(&app, config_path).map(Some)
}

fn apply_mobile_join_roster(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    join_roster: &JoinRosterControl,
) -> Result<Option<MobileTunnelConfig>> {
    if mobile_join_roster_is_durably_persisted(app_config, config_path, join_roster)? {
        return Ok(None);
    }
    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    app.ensure_defaults();
    let applied = if let Some(config_path) = config_path {
        apply_join_roster_durably(&mut app, config_path, join_roster, unix_timestamp())?
    } else {
        let applied = apply_join_roster(&mut app, join_roster, unix_timestamp())?;
        if applied.is_some() {
            maybe_autoconfigure_node(&mut app);
        }
        applied
    };
    let Some(_applied_network_id) = applied else {
        return Ok(None);
    };
    app_config_dirty.store(true, Ordering::Relaxed);
    let config_path = config_path.unwrap_or_else(|| Path::new(""));
    MobileTunnelConfig::from_app_with_config_path(&app, config_path).map(Some)
}

fn mobile_join_roster_is_durably_persisted(
    app_config: &Arc<RwLock<AppConfig>>,
    config_path: Option<&Path>,
    join_roster: &JoinRosterControl,
) -> Result<bool> {
    let network_id = join_roster.signed_roster.network_id()?;
    if let Some(config_path) = config_path {
        return join_roster_is_durably_persisted(config_path, join_roster);
    }

    let app = app_config
        .read()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    let original_request_is_pending = app
        .pending_nostr_join_request
        .as_ref()
        .is_some_and(|pending| pending.request.request_secret == join_roster.request_secret);
    Ok(!original_request_is_pending
        && mobile_signed_roster_is_current_for_app(
            &app,
            &network_id,
            &join_roster.signed_roster,
        ))
}

fn mobile_signed_roster_is_current_for_app(
    app: &AppConfig,
    network_id: &str,
    signed_roster: &SignedRoster,
) -> bool {
    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    app.networks.iter().any(|network| {
        normalize_runtime_network_id(&network.network_id)
            == normalize_runtime_network_id(network_id)
            && network.shared_roster_updated_at == signed_roster.signed_at()
            && normalize_nostr_pubkey(&network.shared_roster_signed_by)
                .is_ok_and(|value| value == signed_by)
    })
}

fn record_mobile_join_request(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    sender_pubkey: &str,
    requested_at: u64,
    request: &MeshJoinRequest,
) -> Result<bool> {
    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    app.ensure_defaults();
    let changed = match app.record_inbound_join_request(
        &request.network_id,
        &request.join_secret,
        sender_pubkey,
        &request.requester_node_name,
        requested_at,
    ) {
        Ok(Some(_network_name)) => true,
        Ok(None) => false,
        Err(error) => {
            mobile_debug_log(format!(
                "mobile: ignoring invalid join request from {sender_pubkey}: {error:#}"
            ));
            tracing::warn!(
                ?error,
                %sender_pubkey,
                "mobile: ignoring invalid FIPS join request"
            );
            false
        }
    };
    if !changed {
        return Ok(false);
    }
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: join request recorded in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: join request recorded in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    Ok(true)
}

fn mobile_runtime_state_path(config_path: &Path) -> Option<PathBuf> {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(MOBILE_RUNTIME_STATE_FILE))
}

struct MobileRuntimeDiagnostics<'a> {
    secure_dns: Option<&'a SecureDnsResolver>,
    wireguard_handshake:
        Option<&'a nostr_vpn_core::wg_upstream::WgUpstreamHandshakeObserver>,
}

async fn persist_mobile_runtime_state(
    path: &Path,
    endpoint: &FipsEndpoint,
    mesh: &MobileMesh,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config: &Arc<RwLock<MobileTunnelConfig>>,
    tun_counters: &MobileTunAtomicCounters,
    diagnostics: MobileRuntimeDiagnostics<'_>,
) -> Result<()> {
    let endpoint_peers = endpoint
        .peers()
        .await
        .context("mobile FIPS peer snapshot")?;
    let relay_statuses = endpoint
        .relay_statuses()
        .await
        .context("mobile FIPS relay snapshot")?;
    let config = config
        .read()
        .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
        .clone();
    let mut state = {
        let mesh = mobile_mesh_snapshot(mesh)?;
        let presence = presence
            .read()
            .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
        mobile_runtime_state_with_tun_counters(
            &config,
            &mesh,
            &presence,
            endpoint_peers,
            relay_statuses,
            tun_counters.snapshot(),
            unix_timestamp(),
        )
    };
    if let Some(counters) = diagnostics.secure_dns.map(SecureDnsResolver::counters) {
        state.secure_dns_queries = counters.queries;
        state.secure_dns_successes = counters.successes;
        state.secure_dns_failures = counters.failures;
    }
    state.wireguard_exit_ready = diagnostics.wireguard_handshake.is_some_and(
        nostr_vpn_core::wg_upstream::WgUpstreamHandshakeObserver::has_completed_handshake,
    );
    write_mobile_runtime_state(path, &state)
}

#[allow(clippy::too_many_lines)]
fn mobile_runtime_state_with_tun_counters(
    config: &MobileTunnelConfig,
    mesh: &FipsMeshRuntime,
    presence: &HashMap<String, MobilePeerPresence>,
    endpoint_peers: Vec<FipsEndpointPeer>,
    relay_statuses: Vec<FipsEndpointRelayStatus>,
    tun_counters: MobileTunCounters,
    now: u64,
) -> DaemonRuntimeState {
    let fips_direct_roster_peer_count = endpoint_peers
        .iter()
        .filter(|peer| {
            peer.connected
                && mesh
                    .participant_for_endpoint_node_addr(peer.node_addr.as_bytes())
                    .is_some()
        })
        .count();
    let fips_other_peer_count = endpoint_peers
        .iter()
        .filter(|peer| {
            peer.connected
                && mesh
                    .participant_for_endpoint_node_addr(peer.node_addr.as_bytes())
                    .is_none()
        })
        .count();
    let link_by_participant = endpoint_peers
        .into_iter()
        .filter_map(|peer| {
            let participant = mesh.participant_for_endpoint_node_addr(peer.node_addr.as_bytes())?;
            Some((participant, peer))
        })
        .collect::<HashMap<_, _>>();
    let peer_config_by_participant = config
        .peers
        .iter()
        .map(|peer| (peer.participant_pubkey.clone(), peer))
        .collect::<HashMap<_, _>>();

    let peers = mesh
        .peer_statuses()
        .into_iter()
        .map(|status| {
            let peer_config = peer_config_by_participant.get(&status.pubkey);
            let link = link_by_participant.get(&status.pubkey);
            let peer_presence = presence.get(&status.pubkey);
            let last_seen_at = peer_presence.and_then(|presence| presence.last_seen_at);
            let credible_last_seen_at = credible_mobile_timestamp(now, last_seen_at);
            let credible_last_control_seen_at = peer_presence
                .and_then(|presence| credible_mobile_timestamp(now, presence.last_control_seen_at));
            let credible_last_data_seen_at = peer_presence
                .and_then(|presence| credible_mobile_timestamp(now, presence.last_data_seen_at));
            let presence_connected = credible_last_seen_at.is_some_and(|last_seen_at| {
                mobile_timestamp_within_grace(now, last_seen_at, MOBILE_PEER_ONLINE_GRACE_SECS)
            });
            let link_connected = link.is_some_and(|peer| peer.connected);
            let reachable = presence_connected || link_connected;
            let advertised_routes = peer_config
                .map(|peer| peer.allowed_ips.clone())
                .unwrap_or_default();
            let tunnel_ip = advertised_routes
                .first()
                .map(|route| strip_cidr(route).to_string())
                .or_else(|| derive_mesh_tunnel_ip(&config.network_id, &status.pubkey))
                .unwrap_or_default();

            DaemonPeerState {
                participant_pubkey: status.pubkey.clone(),
                node_id: String::new(),
                tunnel_ip,
                endpoint: String::new(),
                runtime_endpoint: link.and_then(|peer| peer.transport_addr.clone()),
                fips_endpoint_npub: link
                    .map_or_else(|| status.endpoint_npub.clone(), |peer| peer.npub.clone()),
                fips_transport_addr: link
                    .and_then(|peer| peer.transport_addr.clone())
                    .unwrap_or_default(),
                fips_transport_type: link
                    .and_then(|peer| peer.transport_type.clone())
                    .unwrap_or_default(),
                fips_srtt_ms: link
                    .and_then(|peer| peer.srtt_ms)
                    .or_else(|| peer_presence.and_then(|presence| presence.rtt_ms)),
                fips_srtt_age_ms: link.and_then(|peer| peer.srtt_age_ms),
                fips_packets_sent: link.map_or(0, |peer| peer.packets_sent),
                fips_packets_recv: link.map_or(0, |peer| peer.packets_recv),
                fips_bytes_sent: link.map_or(0, |peer| peer.bytes_sent),
                fips_bytes_recv: link.map_or(0, |peer| peer.bytes_recv),
                direct_probe_pending: link.is_some_and(|peer| peer.direct_probe_pending),
                direct_probe_after_ms: link.and_then(|peer| peer.direct_probe_after_ms),
                direct_probe_retry_count: link.map_or(0, |peer| peer.direct_probe_retry_count),
                direct_probe_auto_reconnect: link
                    .is_some_and(|peer| peer.direct_probe_auto_reconnect),
                direct_probe_expires_at_ms: link.and_then(|peer| peer.direct_probe_expires_at_ms),
                fips_nostr_traversal_failures: link
                    .map_or(0, |peer| peer.nostr_traversal_consecutive_failures),
                fips_nostr_traversal_in_cooldown: link
                    .is_some_and(|peer| peer.nostr_traversal_in_cooldown),
                fips_nostr_traversal_cooldown_until_ms: link
                    .and_then(|peer| peer.nostr_traversal_cooldown_until_ms),
                fips_nostr_traversal_last_observed_skew_ms: link
                    .and_then(|peer| peer.nostr_traversal_last_observed_skew_ms),
                tx_bytes: peer_presence.map_or(0, |presence| presence.tx_bytes),
                rx_bytes: peer_presence.map_or(0, |presence| presence.rx_bytes),
                public_key: status.pubkey,
                advertised_routes,
                last_mesh_seen_at: credible_last_seen_at.unwrap_or(if link_connected {
                    now
                } else {
                    0
                }),
                last_fips_seen_at: credible_last_seen_at.or_else(|| link_connected.then_some(now)),
                last_fips_control_seen_at: credible_last_control_seen_at,
                last_fips_data_seen_at: credible_last_data_seen_at,
                reachable,
                last_handshake_at: credible_last_seen_at.or_else(|| link_connected.then_some(now)),
                error: if reachable {
                    None
                } else {
                    Some("fips link pending".to_string())
                },
            }
        })
        .collect::<Vec<_>>();
    let connected_peer_count = peers.iter().filter(|peer| peer.reachable).count();
    let expected_peer_count = peers.len();

    DaemonRuntimeState {
        updated_at: now,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        local_endpoint: config.advertised_endpoint.clone(),
        advertised_endpoint: config.advertised_endpoint.clone(),
        listen_port: config.listen_port,
        vpn_enabled: true,
        vpn_active: true,
        vpn_status: if expected_peer_count == 0 {
            "VPN on".to_string()
        } else {
            format!("VPN on ({connected_peer_count}/{expected_peer_count} peers)")
        },
        expected_peer_count,
        connected_peer_count,
        fips_direct_roster_peer_count,
        fips_other_peer_count,
        mesh_ready: connected_peer_count == expected_peer_count,
        relays: relay_statuses
            .into_iter()
            .map(|relay| crate::state::RelayView {
                url: relay.url,
                status: relay.status,
                enabled: true,
            })
            .collect(),
        tun_packets_read: tun_counters.packets_read,
        tun_bytes_read: tun_counters.bytes_read,
        tun_packets_written: tun_counters.packets_written,
        tun_bytes_written: tun_counters.bytes_written,
        tun_packets_dropped: tun_counters.packets_dropped,
        peers,
        ..DaemonRuntimeState::default()
    }
}

fn note_mobile_peer_rx(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    len: usize,
    kind: MobilePeerRxKind,
) {
    let now = unix_timestamp();
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.last_seen_at = Some(now);
    match kind {
        MobilePeerRxKind::Control => entry.last_control_seen_at = Some(now),
        MobilePeerRxKind::Data => entry.last_data_seen_at = Some(now),
    }
    entry.rx_bytes = entry.rx_bytes.saturating_add(len as u64);
}

fn note_mobile_peer_tx(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    len: usize,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.tx_bytes = entry.tx_bytes.saturating_add(len as u64);
}

fn note_mobile_peer_ping_attempt(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    now: u64,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.last_ping_sent_at = Some(now);
    entry.last_ping_started_at = Some(Instant::now());
}

fn note_mobile_peer_pong(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    sent_at: u64,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let Some(entry) = presence.get_mut(participant) else {
        return;
    };
    if entry.last_ping_sent_at == Some(sent_at)
        && let Some(started_at) = entry.last_ping_started_at.take()
    {
        let elapsed_ms = started_at.elapsed().as_millis();
        if elapsed_ms <= MOBILE_CONTROL_RTT_MAX_ACCEPT_MS {
            let Ok(elapsed_ms) = u64::try_from(elapsed_ms) else {
                return;
            };
            entry.rtt_ms = Some(elapsed_ms);
        } else {
            entry.last_ping_sent_at = None;
        }
    }
}

fn mobile_peer_ping_due(
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    configured_transit: bool,
    now: u64,
) -> bool {
    let interval = if configured_transit {
        MOBILE_CONFIGURED_TRANSIT_PING_INTERVAL_SECS
    } else if last_seen_at.is_some_and(|last_seen_at| {
        mobile_timestamp_within_grace(now, last_seen_at, MOBILE_PEER_ONLINE_GRACE_SECS)
    }) {
        MOBILE_PEER_ACTIVE_PING_INTERVAL_SECS
    } else {
        MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS
    };
    last_ping_sent_at.is_none_or(|sent_at| mobile_elapsed_at_least(now, sent_at, interval))
}

fn mobile_ping_participants(
    mut participants: Vec<String>,
    bootstrap_peers: &HashMap<String, Vec<FipsPeerAddressHint>>,
) -> Vec<(String, bool)> {
    let configured_transit = bootstrap_peers
        .iter()
        .filter(|(_, hints)| !hints.is_empty())
        .filter_map(|(participant, _)| normalize_nostr_pubkey(participant).ok())
        .collect::<HashSet<_>>();
    participants.extend(configured_transit.iter().cloned());
    participants.sort();
    participants.dedup();
    participants
        .into_iter()
        .map(|participant| {
            let is_configured_transit = configured_transit.contains(&participant);
            (participant, is_configured_transit)
        })
        .collect()
}

async fn mobile_ping_peers(
    endpoint: &FipsEndpoint,
    mesh: &MobileMesh,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    network_id: &str,
    bootstrap_peers: &HashMap<String, Vec<FipsPeerAddressHint>>,
) -> Result<usize> {
    let now = unix_timestamp();
    let peers = {
        let mesh = mobile_mesh_snapshot(mesh)?;
        mesh.peer_pubkeys()
    };
    let peers = mobile_ping_participants(peers, bootstrap_peers);
    let participants = {
        let presence = presence
            .read()
            .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
        peers
            .into_iter()
            .filter(|(participant, configured_transit)| {
                let peer_presence = presence.get(participant);
                mobile_peer_ping_due(
                    peer_presence.and_then(|value| value.last_seen_at),
                    peer_presence.and_then(|value| value.last_ping_sent_at),
                    *configured_transit,
                    now,
                )
            })
            .map(|(participant, _)| participant)
            .collect::<Vec<_>>()
    };
    if participants.is_empty() {
        return Ok(0);
    }
    let frame = FipsControlFrame::Ping {
        network_id: network_id.to_string(),
        sent_at: now,
    };
    let encoded = encode_fips_control_frame(&frame)?;
    let mut sent = 0usize;
    for participant in participants {
        note_mobile_peer_ping_attempt(presence, &participant, now);
        if send_mobile_endpoint_data(endpoint, peer_identities, &participant, encoded.clone())
            .await
            .is_ok()
        {
            note_mobile_peer_tx(presence, &participant, encoded.len());
            sent += 1;
        }
    }
    Ok(sent)
}

fn write_mobile_runtime_state(path: &Path, state: &DaemonRuntimeState) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(state)?;
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(MOBILE_RUNTIME_STATE_FILE)
    ));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path).or_else(|_| {
        let _ = fs::remove_file(path);
        fs::rename(&tmp, path)
    })?;
    Ok(())
}

fn update_mobile_peer_hints(
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
    source_pubkey: &str,
    capabilities: &PeerCapabilities,
) -> Result<bool> {
    let seen_at = if capabilities.signed_at == 0 {
        unix_timestamp()
    } else {
        capabilities.signed_at
    };
    let seen_at_ms = seen_at.saturating_mul(1000);
    let mut hints = capabilities
        .endpoint_hints
        .iter()
        .filter_map(peer_endpoint_hint_addr)
        .map(|addr| FipsPeerAddressHint {
            priority: mobile_fips_endpoint_hint_priority(&addr, FIPS_DYNAMIC_PEER_ENDPOINT_PRIORITY),
            addr,
            seen_at_ms: Some(seen_at_ms),
        })
        .collect::<Vec<_>>();
    hints.sort_by(|left, right| left.addr.cmp(&right.addr));
    hints.dedup_by(|left, right| left.addr == right.addr);

    let mut peer_hints = peer_hints
        .write()
        .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?;
    if peer_hints.get(source_pubkey) == Some(&hints) {
        return Ok(false);
    }
    peer_hints.insert(source_pubkey.to_string(), hints);
    Ok(true)
}

fn sync_mobile_config_peer_hints(
    config_state: &Arc<RwLock<MobileTunnelConfig>>,
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
) -> Result<()> {
    let hints = peer_hints
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?
        .clone();
    let mut config = config_state
        .write()
        .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
    config.peer_hints = hints;
    Ok(())
}

fn persist_mobile_peer_hints(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    source_pubkey: &str,
    capabilities: &PeerCapabilities,
) -> Result<()> {
    let mut endpoints = capabilities
        .endpoint_hints
        .iter()
        .filter_map(peer_endpoint_hint_addr)
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        return Ok(());
    }

    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    if app.fips_peer_endpoints.get(source_pubkey) == Some(&endpoints) {
        return Ok(());
    }
    app.fips_peer_endpoints
        .insert(source_pubkey.to_string(), endpoints);
    app.ensure_defaults();
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: peer hints updated in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: peer hints updated in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    Ok(())
}

async fn refresh_mobile_endpoint_peers(
    endpoint: &FipsEndpoint,
    config_state: &Arc<RwLock<MobileTunnelConfig>>,
) -> Result<()> {
    let config = config_state
        .read()
        .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
        .clone();
    let include_non_roster_transit = config.connect_to_non_roster_fips_peers
        || config.join_requests_enabled
        || mobile_join_request_pending(&config);
    let peers = fips_peer_configs_from_mesh(
        &config.peers,
        &config.peer_hints,
        &config.bootstrap_peers,
        include_non_roster_transit,
    );
    endpoint
        .update_peers(peers)
        .await
        .context("mobile FIPS peer update failed")?;
    Ok(())
}

async fn broadcast_mobile_capabilities(
    state_control: &FipsControlTcpSender,
    mesh_peers: &Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    peer_identities: &Arc<RwLock<MobilePeerIdentityMap>>,
    network_id: &str,
    endpoint_hints: Vec<PeerEndpointHint>,
) -> Result<usize> {
    let peers = mesh_peers
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer lock poisoned"))?
        .clone();
    if peers.is_empty() {
        return Ok(0);
    }

    let frame = FipsControlFrame::Capabilities {
        network_id: network_id.to_string(),
        capabilities: PeerCapabilities {
            advertised_routes: Vec::new(),
            endpoint_hints,
            dataplane_features: local_fips_dataplane_features(),
            signed_at: unix_timestamp(),
        },
    };
    let mut sent = 0usize;
    for peer in peers {
        if send_mobile_state_control(
            state_control,
            peer_identities,
            &peer.participant_pubkey,
            &frame,
        )
        .await
        .is_ok()
        {
            sent += 1;
        }
    }
    Ok(sent)
}

struct MobileRosterSentState {
    hash: String,
    sent_at: u64,
}

#[derive(Default)]
struct MobileRosterSyncState {
    source: Option<(String, u64, String)>,
    encoded: Option<(String, FipsControlFrame)>,
    sent_by_peer: HashMap<String, MobileRosterSentState>,
}

struct MobileRosterSyncContext {
    state_control: FipsControlTcpSender,
    mesh: MobileMesh,
    peer_identities: Arc<RwLock<MobilePeerIdentityMap>>,
    presence: Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    app_config: Arc<RwLock<AppConfig>>,
    config_path: Option<PathBuf>,
    launch_signed_roster: Option<SignedRoster>,
}

async fn sync_mobile_signed_roster_with_connected_peers(
    context: &MobileRosterSyncContext,
    state: &mut MobileRosterSyncState,
) -> Result<usize> {
    let source = {
        let app = context
            .app_config
            .read()
            .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
        app.active_network_opt().map(|network| {
            (
                normalize_runtime_network_id(&network.network_id),
                network.shared_roster_updated_at,
                network.shared_roster_signed_by.clone(),
            )
        })
    };
    if state.source != source {
        state.encoded = mobile_current_signed_roster(
            &context.app_config,
            context.config_path.as_deref(),
            context.launch_signed_roster.as_ref(),
        )?
            .map(|signed_roster| {
                let roster_hash = signed_roster.content_hash();
                let frame = FipsControlFrame::Roster {
                    network_id: signed_roster.network_id()?,
                    roster: signed_roster.roster()?,
                    signed_roster: Some(Box::new(signed_roster)),
                };
                Ok::<_, anyhow::Error>((roster_hash, frame))
            })
            .transpose()?;
        state.source = state.encoded.as_ref().map(|_| source).unwrap_or_default();
    }
    let Some((roster_hash, frame)) = state.encoded.as_ref() else {
        state.sent_by_peer.clear();
        return Ok(0);
    };
    let now = unix_timestamp();
    let connected = mobile_connected_roster_peers(&context.mesh, &context.presence)?;
    state
        .sent_by_peer
        .retain(|peer, _| connected.contains(peer));

    let mut sent = 0usize;
    for participant in connected {
        if state.sent_by_peer.get(&participant).is_some_and(|sent| {
            sent.hash == *roster_hash
                && !mobile_elapsed_at_least(now, sent.sent_at, MOBILE_ROSTER_RESEND_SECS)
        }) {
            continue;
        }
        if send_mobile_state_control(
            &context.state_control,
            &context.peer_identities,
            &participant,
            frame,
        )
            .await
            .is_ok()
        {
            state.sent_by_peer.insert(
                participant,
                MobileRosterSentState {
                    hash: roster_hash.clone(),
                    sent_at: now,
                },
            );
            sent += 1;
        }
    }
    Ok(sent)
}

fn mobile_current_signed_roster(
    app_config: &Arc<RwLock<AppConfig>>,
    config_path: Option<&Path>,
    launch_signed_roster: Option<&SignedRoster>,
) -> Result<Option<SignedRoster>> {
    let app = app_config
        .read()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    let Some(network) = app.active_network_opt() else {
        return Ok(None);
    };
    let network_id = normalize_runtime_network_id(&network.network_id);
    let signed_by = normalize_nostr_pubkey(&network.shared_roster_signed_by).unwrap_or_default();
    if network_id.is_empty() || signed_by.is_empty() || network.shared_roster_updated_at == 0 {
        return Ok(None);
    }
    if let Some(signed_roster) = launch_signed_roster
        && signed_roster.verify().is_ok()
        && signed_roster.network_id()? == network_id
        && signed_roster.signed_at() == network.shared_roster_updated_at
        && signed_roster.signer_pubkey_hex()? == signed_by
    {
        return Ok(Some(signed_roster.clone()));
    }
    let Some(config_path) = config_path else {
        return Ok(None);
    };
    let store = nostr_vpn_core::signed_rosters::load_signed_rosters(&signed_rosters_file_path(
        config_path,
    ))?;
    let Some(signed_roster) = store.latest_for(&network_id).cloned() else {
        return Ok(None);
    };
    if signed_roster.signed_at() != network.shared_roster_updated_at {
        return Ok(None);
    }
    if signed_roster.signer_pubkey_hex()? != signed_by {
        return Ok(None);
    }
    Ok(Some(signed_roster))
}

fn mobile_connected_roster_peers(
    mesh: &MobileMesh,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
) -> Result<HashSet<String>> {
    let now = unix_timestamp();
    let peers = mobile_mesh_snapshot(mesh)?.peer_pubkeys();
    let presence = presence
        .read()
        .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
    Ok(peers
        .into_iter()
        .filter(|participant| {
            presence
                .get(participant)
                .and_then(|entry| entry.last_seen_at)
                .is_some_and(|last_seen_at| {
                    mobile_timestamp_within_grace(now, last_seen_at, MOBILE_PEER_ONLINE_GRACE_SECS)
                })
        })
        .collect())
}

fn pending_mobile_join_request_frame(
    config: &MobileTunnelConfig,
) -> Result<Option<(String, FipsControlFrame)>> {
    if config.pending_join_request_recipient.trim().is_empty()
        || config.pending_join_requested_at == 0
        || config.network_id.trim().is_empty()
    {
        return Ok(None);
    }
    let recipient = FipsMeshPeerConfig::from_participant_pubkey(
        &config.pending_join_request_recipient,
        Vec::new(),
    )?;
    let frame = FipsControlFrame::JoinRequest {
        requested_at: config.pending_join_requested_at,
        request: MeshJoinRequest {
            network_id: normalize_runtime_network_id(&config.network_id),
            join_secret: config.pending_join_secret.trim().to_string(),
            requester_node_name: config.node_name.trim().to_string(),
        },
    };
    Ok(Some((recipient.endpoint_npub, frame)))
}
