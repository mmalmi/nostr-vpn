use super::*;

#[cfg(any(target_os = "macos", test))]
pub(crate) fn reset_tunnel_runtime_after_macos_underlay_repair(
    tunnel_runtime: &mut CliTunnelRuntime,
) {
    tunnel_runtime.stop();
}

#[cfg(not(any(target_os = "macos", test)))]
pub(crate) fn reset_tunnel_runtime_after_macos_underlay_repair(
    _tunnel_runtime: &mut CliTunnelRuntime,
) {
}

pub(crate) async fn connect_session(args: ConnectArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.unwrap_or_else(default_config_path);
    #[cfg(target_os = "macos")]
    if let Err(error) = repair_saved_network_state(&config_path) {
        eprintln!("connect: failed to repair saved macOS network state: {error}");
    }
    #[cfg(target_os = "macos")]
    match crate::macos_network::ensure_macos_underlay_default_route() {
        Ok(true) => eprintln!("connect: restored missing macOS underlay default route"),
        Ok(false) => {}
        Err(error) => eprintln!("connect: failed to ensure macOS underlay default route: {error}"),
    }
    let (app, network_id) =
        load_config_with_overrides(&config_path, args.network_id, args.participants)?;
    let configured_participants = app.participant_pubkeys_hex();
    if configured_participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running connect"
        ));
    }

    let relays = resolve_relays(&args.relay, &app);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let expected_peers = expected_peer_count(&app);
    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut outbound_announces = OutboundAnnounceBook::default();
    let mut relay_sessions: HashMap<String, ActiveRelaySession> = HashMap::new();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut network_snapshot = capture_network_snapshot();
    let timeout = network_probe_timeout(&app);
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let mut public_signal_endpoint = restored_public_signal_endpoint_from_state(
        read_daemon_state(&daemon_state_file_path(&config_path))
            .ok()
            .flatten()
            .as_ref(),
        app.node.listen_port,
    );

    let mut client = NostrSignalingClient::from_secret_key_with_networks(
        &app.nostr.secret_key,
        signaling_networks_for_app(&app),
    )?;
    client.connect(&relays).await?;
    if let Err(error) = publish_active_network_roster(&client, &app, None).await {
        eprintln!("signal: initial roster publish failed: {error}");
    }
    let mut relay_connected = true;

    refresh_public_signal_endpoint_with_port_mapping(
        &app,
        &network_snapshot,
        app.node.listen_port,
        &mut port_mapping_runtime,
        &mut public_signal_endpoint,
    )
    .await;
    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &relay_sessions,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    let _ = client.publish(SignalPayload::Hello).await;

    println!(
        "connect: network {} on {} relays; waiting for {expected_peers} configured peer(s)",
        network_id,
        relays.len()
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.announce_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
    reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut network_interval = tokio::time::interval(Duration::from_secs(5));
    network_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = reconnect_interval.tick() => {
                if relay_connected || Instant::now() < reconnect_due {
                    continue;
                }

                if matches!(
                    relay_connection_action(relay_connected),
                    RelayConnectionAction::KeepConnected
                ) {
                    continue;
                }

                client.disconnect().await;
                client = NostrSignalingClient::from_secret_key_with_networks(
                    &app.nostr.secret_key,
                    signaling_networks_for_app(&app),
                )?;
                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        outbound_announces.clear();
                        if let Err(error) = publish_active_network_roster(&client, &app, None).await
                        {
                            eprintln!("signal: roster publish failed after reconnect: {error}");
                        }
                        if let Err(error) = publish_private_announce_to_known_peers(
                            &client,
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                        )
                        .await
                        {
                            eprintln!("signal: known peer announce refresh failed after reconnect: {error}");
                        }
                        if let Err(error) = client.publish(SignalPayload::Hello).await {
                            let error_text = error.to_string();
                            reconnect_attempt = reconnect_attempt.saturating_add(1);
                            let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                            reconnect_due = Instant::now() + delay;
                            relay_connected = false;
                            eprintln!(
                                "signal: hello publish failed after reconnect (retry in {}s): {error_text}",
                                delay.as_secs()
                            );
                        }
                    }
                    Err(error) => {
                        let error_text = error.to_string();
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        eprintln!(
                            "signal: relay reconnect failed (retry in {}s): {error_text}",
                            delay.as_secs()
                        );
                    }
                }
            }
            _ = tunnel_heartbeat_interval.tick() => {
                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if !relay_connected
                    && let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        peer_announcements,
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    )
                {
                    eprintln!("nat: cached peer hole-punch failed: {error}");
                }
                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    eprintln!("connect: tunnel heartbeat refresh failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed: {error}");
                }
            }
            _ = network_interval.tick() => {
                #[cfg(target_os = "macos")]
                let underlay_repaired =
                    match crate::macos_network::ensure_macos_underlay_default_route() {
                        Ok(true) => {
                            eprintln!("connect: restored missing macOS underlay default route");
                            true
                        }
                        Ok(false) => false,
                        Err(error) => {
                            eprintln!(
                                "connect: failed to ensure macOS underlay default route: {error}"
                            );
                            false
                        }
                    };
                #[cfg(not(target_os = "macos"))]
                let underlay_repaired = false;
                let latest_snapshot = crate::diagnostics::prefer_nonempty_network_snapshot(
                    &network_snapshot,
                    capture_network_snapshot(),
                );
                let runtime_listen_port =
                    tunnel_runtime.active_listen_port.unwrap_or(app.node.listen_port);
                let network_changed = latest_snapshot.changed_since(&network_snapshot);
                let endpoint_changed = if network_changed {
                    network_snapshot = latest_snapshot.clone();
                    println!("connect: network change detected; refreshing paths");
                    refresh_public_signal_endpoint_with_port_mapping(
                        &app,
                        &network_snapshot,
                        runtime_listen_port,
                        &mut port_mapping_runtime,
                        &mut public_signal_endpoint,
                    )
                    .await;
                    public_signal_endpoint
                        .as_ref()
                        .is_some_and(|endpoint| endpoint.listen_port == runtime_listen_port)
                } else {
                    match port_mapping_runtime
                        .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                        .await
                    {
                        Ok(changed) => {
                            if changed {
                                sync_public_signal_endpoint_from_mapping_or_stun(
                                    &app,
                                    runtime_listen_port,
                                    &port_mapping_runtime,
                                    &mut public_signal_endpoint,
                                );
                            }
                            changed
                        }
                        Err(error) => {
                            eprintln!("nat: port mapping renew failed: {error}");
                            false
                        }
                    }
                };

                if !network_changed && !endpoint_changed && !underlay_repaired {
                    continue;
                }

                if network_changed || underlay_repaired {
                    network_snapshot = latest_snapshot;
                    if network_changed {
                        println!("connect: network change detected; refreshing paths");
                    }
                    if underlay_repaired {
                        reset_tunnel_runtime_after_macos_underlay_repair(&mut tunnel_runtime);
                    }
                    last_nat_punch_attempt = None;
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        unix_timestamp(),
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        eprintln!("connect: tunnel refresh after network change failed: {error}");
                    }
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after network refresh failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after network refresh: {error}");
                }
                if relay_connected
                    && let Err(error) = publish_private_announce_to_known_peers(
                        &client,
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                    )
                    .await
                {
                    eprintln!("signal: known peer announce refresh failed after network change: {error}");
                }
                if relay_connected
                    && let Err(error) = client.publish(SignalPayload::Hello).await
                {
                    eprintln!("signal: hello publish failed after network change: {error}");
                }
            }
            _ = announce_interval.tick() => {
                let now = unix_timestamp();
                if prune_active_relay_sessions(&mut relay_sessions, now) {
                    outbound_announces.clear();
                    last_nat_punch_attempt = None;
                    apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    )
                    .context("failed to apply tunnel update after relay expiry")?;
                }
                let removed =
                    presence.prune_stale(now, peer_signal_timeout_secs(args.announce_interval_secs));
                for participant in &removed {
                    outbound_announces.forget(participant);
                }
                let paths_pruned =
                    path_book.prune_stale(now, peer_path_cache_timeout_secs(args.announce_interval_secs));
                let recent = recently_seen_participants(
                    &presence,
                    now,
                    peer_signal_timeout_secs(args.announce_interval_secs),
                );
                outbound_announces.retain_participants(&recent);
                if !removed.is_empty() || paths_pruned {
                    last_nat_punch_attempt = None;
                    apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    )
                    .context("failed to apply tunnel update after stale peer expiry")?;
                    maybe_log_presence_mesh_count(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        expected_peers,
                        &mut last_mesh_count,
                    );
                }
                if !relay_connected {
                    continue;
                }

                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: periodic hole-punch failed: {error}");
                }
                if let Err(error) = publish_private_announce_to_active_peers(
                    &client,
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &relay_sessions,
                    &mut outbound_announces,
                )
                .await
                {
                    eprintln!("signal: active peer announce refresh failed: {error}");
                }
                if let Err(error) = client.publish(SignalPayload::Hello).await {
                    let error_text = error.to_string();
                    if publish_error_requires_reconnect(&error_text) {
                        relay_connected = false;
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        eprintln!(
                            "signal: hello publish indicates disconnected relays (retry in {}s): {error_text}",
                            delay.as_secs()
                        );
                    } else {
                        eprintln!("signal: hello publish failed: {error_text}");
                    }
                }
            }
            message = async {
                if relay_connected {
                    client.recv().await
                } else {
                    std::future::pending::<Option<SignalEnvelope>>().await
                }
            } => {
                let Some(message) = message else {
                    relay_connected = false;
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                    reconnect_due = Instant::now() + delay;
                    eprintln!("signal: relay stream closed (retry in {}s)", delay.as_secs());
                    continue;
                };

                let sender_pubkey = message.sender_pubkey;
                let payload = message.payload.clone();
                let changed =
                    presence.apply_signal(sender_pubkey.clone(), message.payload, unix_timestamp());
                if matches!(&payload, SignalPayload::Disconnect { .. }) {
                    outbound_announces.forget(&sender_pubkey);
                }
                if !changed {
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_active_network_roster(
                            &client,
                            &app,
                            Some(std::slice::from_ref(&sender_pubkey)),
                        )
                        .await
                    {
                        eprintln!("signal: targeted roster publish failed: {error}");
                    }
                    maybe_reset_targeted_announce_cache_for_hello(
                        &mut outbound_announces,
                        &sender_pubkey,
                        &payload,
                    );
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    continue;
                }

                apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                )
                .context("failed to apply tunnel update")?;
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after peer signal failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after peer signal: {error}");
                }
                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_active_network_roster(
                        &client,
                        &app,
                        Some(std::slice::from_ref(&sender_pubkey)),
                    )
                    .await
                {
                    eprintln!("signal: targeted roster publish failed: {error}");
                }
                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_private_announce_to_participants(
                        &client,
                        &app,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                        std::slice::from_ref(&sender_pubkey),
                        Some(presence.known()),
                    )
                    .await
                {
                    eprintln!("signal: targeted private announce failed: {error}");
                }

                maybe_log_presence_mesh_count(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    expected_peers,
                    &mut last_mesh_count,
                );
            }
        }
    }

    if relay_connected {
        let _ = client
            .publish(SignalPayload::Disconnect {
                node_id: app.node.id.clone(),
            })
            .await;
    }
    client.disconnect().await;
    port_mapping_runtime.stop().await;
    tunnel_runtime.stop();
    println!("connect: disconnected");

    Ok(())
}

pub(crate) async fn daemon_session(args: DaemonArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    ensure_no_other_daemon_processes_for_config(&config_path, std::process::id())?;
    #[cfg(target_os = "macos")]
    if let Err(error) = repair_saved_network_state(&config_path) {
        eprintln!("daemon: failed to repair saved macOS network state: {error}");
    }
    #[cfg(target_os = "macos")]
    match crate::macos_network::ensure_macos_underlay_default_route() {
        Ok(true) => eprintln!("daemon: restored missing macOS underlay default route"),
        Ok(false) => {}
        Err(error) => eprintln!("daemon: failed to ensure macOS underlay default route: {error}"),
    }
    let network_override = args.network_id.clone();
    let participants_override = args.participants.clone();
    let (mut app, mut network_id) = load_config_with_overrides(
        &config_path,
        network_override.clone(),
        participants_override.clone(),
    )?;
    let mut relays = resolve_relays(&args.relay, &app);
    let mut own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut expected_peers = expected_peer_count(&app);
    let state_file = daemon_state_file_path(&config_path);
    let peer_cache_file = daemon_peer_cache_file_path(&config_path);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut outbound_announces = OutboundAnnounceBook::default();
    let mut relay_sessions: HashMap<String, ActiveRelaySession> = HashMap::new();
    let mut standby_relay_sessions: HashMap<String, Vec<ActiveRelaySession>> = HashMap::new();
    let mut relay_failures: RelayFailureCooldowns = HashMap::new();
    let mut relay_provider_verifications: RelayProviderVerificationBook = HashMap::new();
    let mut pending_relay_requests: HashMap<String, PendingRelayRequest> = HashMap::new();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut network_snapshot = capture_network_snapshot();
    let mut network_changed_at = Some(unix_timestamp());
    let timeout = network_probe_timeout(&app);
    let mut captive_portal = detect_captive_portal(timeout).await;
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let mut public_signal_endpoint = restored_public_signal_endpoint_from_state(
        read_daemon_state(&state_file).ok().flatten().as_ref(),
        app.node.listen_port,
    );
    let mut last_written_peer_cache = None;
    let mut relay_operator_runtime = LocalRelayOperatorRuntime {
        status: if app.relay_for_others {
            "Waiting for relay operator startup".to_string()
        } else {
            "Relay operator disabled".to_string()
        },
        nat_assist_status: if app.provide_nat_assist {
            "Waiting for NAT assist startup".to_string()
        } else {
            "NAT assist disabled".to_string()
        },
        ..LocalRelayOperatorRuntime::default()
    };
    let mut relay_operator_process = None;

    let mut client = NostrSignalingClient::from_secret_key_with_networks(
        &app.nostr.secret_key,
        signaling_networks_for_app(&app),
    )?;
    let mut service_client = RelayServiceClient::from_secret_key(&app.nostr.secret_key)?;
    let mut relay_service_connected = false;

    if daemon_session_active(true, expected_peers) {
        refresh_public_signal_endpoint_with_port_mapping(
            &app,
            &network_snapshot,
            app.node.listen_port,
            &mut port_mapping_runtime,
            &mut public_signal_endpoint,
        )
        .await;
    }
    let restored_peer_cache = if daemon_session_active(true, expected_peers) {
        match restore_daemon_peer_cache(
            DaemonPeerCacheRestore {
                path: &peer_cache_file,
                app: &app,
                network_id: &network_id,
                own_pubkey: own_pubkey.as_deref(),
                now: unix_timestamp(),
                announce_interval_secs: args.announce_interval_secs,
            },
            &mut presence,
            &mut path_book,
        ) {
            Ok(restored) => restored,
            Err(error) => {
                eprintln!("daemon: failed to restore peer cache: {error}");
                false
            }
        }
    } else {
        false
    };

    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &relay_sessions,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    sync_local_relay_operator(
        &config_path,
        &app,
        &relays,
        public_signal_endpoint.as_ref(),
        &mut relay_operator_process,
        &mut relay_operator_runtime,
    )?;
    if restored_peer_cache && daemon_session_active(true, expected_peers) {
        let mut bootstrap_nat_attempt = None;
        if let Err(error) = maybe_run_nat_punch(
            &app,
            own_pubkey.as_deref(),
            direct_peer_announcements(&presence, false),
            &mut path_book,
            &mut tunnel_runtime,
            &mut public_signal_endpoint,
            &mut bootstrap_nat_attempt,
        ) {
            eprintln!("daemon: cached peer nat bootstrap failed: {error}");
        }
        if let Err(error) = heartbeat_pending_tunnel_peers(
            &app,
            own_pubkey.as_deref(),
            direct_peer_announcements(&presence, false),
            &tunnel_runtime,
        ) {
            eprintln!("daemon: cached peer heartbeat bootstrap failed: {error}");
        }
    }
    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.announce_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state_interval = tokio::time::interval(Duration::from_secs(1));
    state_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
    reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut network_interval = tokio::time::interval(Duration::from_secs(5));
    network_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    #[cfg(unix)]
    let mut terminate_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
    #[cfg(unix)]
    let terminate_wait = async move {
        let _ = terminate_signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate_wait = std::future::pending::<()>();
    tokio::pin!(terminate_wait);

    let mut session_enabled = true;
    let mut session_status = if !daemon_session_active(session_enabled, expected_peers) {
        daemon_session_idle_status(session_enabled, expected_peers, app.join_requests_enabled())
            .to_string()
    } else {
        "Connecting to relays".to_string()
    };
    let mut relay_connected = false;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now();
    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    write_daemon_state(
        &state_file,
        &build_daemon_runtime_state(
            &app,
            daemon_session_active(session_enabled, expected_peers),
            expected_peers,
            &presence,
            &tunnel_runtime,
            public_signal_endpoint.as_ref(),
            &session_status,
            relay_connected,
            &network_snapshot.summary(network_changed_at, captive_portal),
            &port_mapping_runtime.status(),
            &relay_operator_runtime,
        ),
    )?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let supervised_service_executable = if args.service {
        Some(current_executable_fingerprint()?)
    } else {
        None
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let supervised_service_executable: Option<(PathBuf, ExecutableFingerprint)> = None;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = &mut terminate_wait => {
                break;
            }
            _ = reconnect_interval.tick() => {
                let join_requests_active = app.join_requests_enabled();
                let session_active = daemon_session_active(session_enabled, expected_peers);
                if !relay_session_active(session_enabled, expected_peers, join_requests_active)
                    || relay_connected
                    || Instant::now() < reconnect_due
                {
                    continue;
                }

                if matches!(
                    relay_connection_action(relay_connected),
                    RelayConnectionAction::KeepConnected
                ) {
                    continue;
                }

                client.disconnect().await;
                service_client.disconnect().await;
                relay_service_connected = false;
                client = NostrSignalingClient::from_secret_key_with_networks(
                    &app.nostr.secret_key,
                    signaling_networks_for_app(&app),
                )?;
                service_client = RelayServiceClient::from_secret_key(&app.nostr.secret_key)?;

                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        relay_service_connected = match service_client.connect(&relays).await {
                            Ok(()) => true,
                            Err(error) => {
                                eprintln!("daemon: relay service connect failed: {error}");
                                false
                            }
                        };
                        if let Err(error) = publish_active_network_roster(&client, &app, None).await
                        {
                            eprintln!("daemon: roster publish failed after reconnect: {error}");
                        }
                        session_status = if session_active {
                            "Connected".to_string()
                        } else {
                            daemon_session_idle_status(
                                session_enabled,
                                expected_peers,
                                join_requests_active,
                            )
                            .to_string()
                        };
                        if session_active {
                            outbound_announces.clear();
                            if let Err(error) = publish_private_announce_to_known_peers(
                                &client,
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &tunnel_runtime,
                                public_signal_endpoint.as_ref(),
                                &relay_sessions,
                                &mut outbound_announces,
                            )
                            .await
                            {
                                let error_text = error.to_string();
                                session_status =
                                    format!("Connected; private announce failed ({error_text})");
                                eprintln!("daemon: private announce failed after reconnect: {error_text}");
                            }
                            if let Err(error) = client.publish(SignalPayload::Hello).await {
                                let error_text = error.to_string();
                                session_status =
                                    format!("Connected; hello publish failed ({error_text})");
                                eprintln!("daemon: initial hello publish failed after reconnect: {error_text}");
                            }
                        }
                    }
                    Err(error) => {
                        let error_text = error.to_string();
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        session_status = format!(
                            "Relay connect failed; retry in {}s ({error_text})",
                            delay.as_secs(),
                        );
                        eprintln!("daemon: relay connect failed (retry in {}s): {error_text}", delay.as_secs());
                    }
                }
            }
            _ = announce_interval.tick() => {
                if !daemon_session_active(session_enabled, expected_peers) || !relay_connected {
                    continue;
                }
                let now = unix_timestamp();
                let relay_sessions_changed =
                    prune_active_relay_sessions(&mut relay_sessions, now)
                    | prune_standby_relay_sessions(&mut standby_relay_sessions, now)
                    | prune_relay_failure_cooldowns(&mut relay_failures, now)
                    | prune_relay_provider_verifications(&mut relay_provider_verifications, now);
                if relay_sessions_changed {
                    outbound_announces.clear();
                    last_nat_punch_attempt = None;
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        session_status = format!("Relay expiry update failed ({error})");
                    }
                }

                            if let Err(error) = maybe_run_nat_punch(
                                &app,
                                own_pubkey.as_deref(),
                                presence.active(),
                                &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: periodic hole-punch failed: {error}");
                        }
                        let _ = prune_pending_relay_requests(&mut pending_relay_requests, now);
                        if app.use_public_relay_fallback
                            && relay_service_connected
                            && let Err(error) = maybe_request_public_relay_fallback(
                                &service_client,
                                &relays,
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &tunnel_runtime,
                                &relay_sessions,
                                &relay_failures,
                                &mut relay_provider_verifications,
                                &mut pending_relay_requests,
                                now,
                            )
                            .await
                        {
                            eprintln!("relay: allocation request failed: {error}");
                        }
                        if let Err(error) = publish_private_announce_to_active_peers(
                            &client,
                            &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &relay_sessions,
                    &mut outbound_announces,
                )
                .await
                {
                    let error_text = error.to_string();
                    session_status = format!("Private announce failed ({error_text})");
                }
                if let Err(error) = client.publish(SignalPayload::Hello).await {
                    let error_text = error.to_string();
                    if publish_error_requires_reconnect(&error_text) {
                        relay_connected = false;
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        session_status = format!(
                            "Relay disconnected; retry in {}s ({error_text})",
                            delay.as_secs(),
                        );
                        eprintln!("daemon: hello publish indicates disconnected relays (retry in {}s): {error_text}", delay.as_secs());
                    } else {
                        session_status = format!("Hello publish failed ({error_text})");
                    }
                }
            }
            _ = tunnel_heartbeat_interval.tick() => {
                if !daemon_session_active(session_enabled, expected_peers) {
                    continue;
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if !relay_connected
                    && let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        peer_announcements,
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    )
                {
                    eprintln!("nat: cached peer hole-punch failed: {error}");
                }
                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    session_status = format!("Tunnel heartbeat refresh failed ({error})");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed: {error}");
                }
            }
            _ = network_interval.tick() => {
                #[cfg(target_os = "macos")]
                let underlay_repaired =
                    match crate::macos_network::ensure_macos_underlay_default_route() {
                        Ok(true) => {
                            eprintln!("daemon: restored missing macOS underlay default route");
                            true
                        }
                        Ok(false) => false,
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to ensure macOS underlay default route: {error}"
                            );
                            false
                        }
                    };
                #[cfg(not(target_os = "macos"))]
                let underlay_repaired = false;
                let latest_snapshot = crate::diagnostics::prefer_nonempty_network_snapshot(
                    &network_snapshot,
                    capture_network_snapshot(),
                );
                let runtime_listen_port =
                    tunnel_runtime.active_listen_port.unwrap_or(app.node.listen_port);
                let session_active = daemon_session_active(session_enabled, expected_peers);
                let network_changed = latest_snapshot.changed_since(&network_snapshot);
                let endpoint_changed = if network_changed {
                    network_snapshot = latest_snapshot.clone();
                    network_changed_at = Some(unix_timestamp());
                    captive_portal = detect_captive_portal(timeout).await;
                    if session_active {
                        refresh_public_signal_endpoint_with_port_mapping(
                            &app,
                            &network_snapshot,
                            runtime_listen_port,
                            &mut port_mapping_runtime,
                            &mut public_signal_endpoint,
                        )
                        .await;
                        true
                    } else {
                        port_mapping_runtime.stop().await;
                        public_signal_endpoint = None;
                        false
                    }
                } else if session_active {
                    match port_mapping_runtime
                        .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                        .await
                    {
                        Ok(changed) => {
                            if changed {
                                sync_public_signal_endpoint_from_mapping_or_stun(
                                    &app,
                                    runtime_listen_port,
                                    &port_mapping_runtime,
                                    &mut public_signal_endpoint,
                                );
                            }
                            changed
                        }
                        Err(error) => {
                            eprintln!("daemon: port mapping renew failed: {error}");
                            false
                        }
                    }
                } else {
                    false
                };

                if !network_changed && !endpoint_changed && !underlay_repaired {
                    continue;
                }

                if network_changed || underlay_repaired {
                    if network_changed {
                        network_snapshot = latest_snapshot;
                        network_changed_at = Some(unix_timestamp());
                        eprintln!("daemon: network change detected; refreshing peer paths");
                    } else {
                        network_snapshot = latest_snapshot;
                        eprintln!("daemon: refreshing tunnel after macOS underlay repair");
                    }
                    if underlay_repaired {
                        reset_tunnel_runtime_after_macos_underlay_repair(&mut tunnel_runtime);
                    }
                    last_nat_punch_attempt = None;
                    match apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        unix_timestamp(),
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        Ok(()) => {
                            session_status = if daemon_session_active(session_enabled, expected_peers)
                            {
                                "Connected (network refresh)".to_string()
                            } else {
                                daemon_session_idle_status(
                                    session_enabled,
                                    expected_peers,
                                    app.join_requests_enabled(),
                                )
                                .to_string()
                            };
                        }
                        Err(error) => {
                            session_status =
                                format!("Network change refresh failed ({error})");
                        }
                    }
                }

                if !daemon_session_active(session_enabled, expected_peers) {
                    continue;
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after network refresh failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after network refresh: {error}");
                }
                if relay_connected
                    && let Err(error) = publish_private_announce_to_known_peers(
                        &client,
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                    )
                    .await
                {
                    eprintln!("signal: known peer announce refresh failed after network change: {error}");
                }
                if relay_connected
                    && let Err(error) = client.publish(SignalPayload::Hello).await
                {
                    eprintln!("signal: hello publish failed after network change: {error}");
                }
            }
            _ = state_interval.tick() => {
                let now = unix_timestamp();
                let changed_relay_participants = reconcile_active_relay_sessions(
                    &presence,
                    tunnel_runtime.peer_status().ok().as_ref(),
                    &mut relay_sessions,
                    &mut standby_relay_sessions,
                    &mut relay_failures,
                    &mut relay_provider_verifications,
                    &mut pending_relay_requests,
                    now,
                );
                if !changed_relay_participants.is_empty() {
                    last_nat_punch_attempt = None;
                    for participant in &changed_relay_participants {
                        outbound_announces.forget(participant);
                    }
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        session_status = format!("Relay failover update failed ({error})");
                    } else if relay_connected
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            &changed_relay_participants,
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("relay: failover announce failed: {error}");
                    }
                }

                if let Some(request) = take_daemon_control_request(&config_path) {
                    let control_result = match request {
                        DaemonControlRequest::Stop => break,
                        DaemonControlRequest::Pause => {
                            let was_session_active =
                                daemon_session_active(session_enabled, expected_peers);
                            if relay_connected && was_session_active {
                                let _ = client
                                    .publish(SignalPayload::Disconnect {
                                        node_id: app.node.id.clone(),
                                    })
                                    .await;
                            }
                            session_enabled = false;
                            let join_requests_active = app.join_requests_enabled();
                            if !join_requests_active {
                                client.disconnect().await;
                                relay_connected = false;
                            }
                            reconnect_attempt = 0;
                            reconnect_due = Instant::now();
                            port_mapping_runtime.stop().await;
                            public_signal_endpoint = None;
                            presence = PeerPresenceBook::default();
                            path_book.clear();
                            relay_sessions.clear();
                            standby_relay_sessions.clear();
                            relay_failures.clear();
                            relay_provider_verifications.clear();
                            pending_relay_requests.clear();
                            outbound_announces.clear();
                            last_nat_punch_attempt = None;
                            if let Err(error) = apply_presence_runtime_update(
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &relay_sessions,
                                &mut path_book,
                                unix_timestamp(),
                                &mut tunnel_runtime,
                                magic_dns_runtime.as_ref(),
                            ) {
                                session_status = format!("Pause failed ({error})");
                            } else {
                                session_status = daemon_session_idle_status(
                                    session_enabled,
                                    expected_peers,
                                    join_requests_active,
                                )
                                .to_string();
                            }
                            Ok(())
                        }
                        DaemonControlRequest::Resume => {
                            if !session_enabled {
                                session_enabled = true;
                                relay_connected = false;
                                reconnect_attempt = 0;
                                reconnect_due = Instant::now();
                                let _restored_peer_cache = if daemon_session_active(
                                    session_enabled,
                                    expected_peers,
                                ) {
                                    match restore_daemon_peer_cache(
                                        DaemonPeerCacheRestore {
                                            path: &peer_cache_file,
                                            app: &app,
                                            network_id: &network_id,
                                            own_pubkey: own_pubkey.as_deref(),
                                            now: unix_timestamp(),
                                            announce_interval_secs: args.announce_interval_secs,
                                        },
                                        &mut presence,
                                        &mut path_book,
                                    ) {
                                        Ok(restored) => restored,
                                        Err(error) => {
                                            eprintln!("daemon: failed to restore peer cache on resume: {error}");
                                            false
                                        }
                                    }
                                } else {
                                    false
                                };
                                if let Err(error) = apply_presence_runtime_update(
                                    &app,
                                    own_pubkey.as_deref(),
                                    &presence,
                                    &relay_sessions,
                                    &mut path_book,
                                    unix_timestamp(),
                                    &mut tunnel_runtime,
                                    magic_dns_runtime.as_ref(),
                                ) {
                                    session_status = format!("Resume failed ({error})");
                                } else if daemon_session_active(session_enabled, expected_peers) {
                                    let runtime_listen_port = tunnel_runtime
                                        .active_listen_port
                                        .unwrap_or(app.node.listen_port);
                                    refresh_public_signal_endpoint_with_port_mapping(
                                        &app,
                                        &network_snapshot,
                                        runtime_listen_port,
                                        &mut port_mapping_runtime,
                                        &mut public_signal_endpoint,
                                    )
                                    .await;
                                    session_status = "Resuming".to_string();
                                } else {
                                    port_mapping_runtime.stop().await;
                                    public_signal_endpoint = None;
                                    session_status = daemon_session_idle_status(
                                        session_enabled,
                                        expected_peers,
                                        app.join_requests_enabled(),
                                    )
                                    .to_string();
                                }
                            }
                            Ok(())
                        }
                        DaemonControlRequest::Reload => {
                            match update_daemon_config_from_staged_request(&config_path) {
                                Ok(staged_config_applied) => {
                            match load_config_with_overrides(
                                &config_path,
                                network_override.clone(),
                                participants_override.clone(),
                            ) {
                                Ok((reloaded_app, reloaded_network_id)) => {
                                    let reload = build_daemon_reload_config(
                                        reloaded_app,
                                        reloaded_network_id,
                                        &args.relay,
                                    );
                                    let configured_set = reload
                                        .configured_participants
                                        .iter()
                                        .cloned()
                                        .collect::<HashSet<_>>();
                                    app = reload.app;
                                    network_id = reload.network_id;
                                    expected_peers = reload.expected_peers;
                                    own_pubkey = reload.own_pubkey;
                                    relays = reload.relays;

                                    presence.retain_participants(&configured_set);
                                    path_book.retain_participants(&configured_set);
                                    outbound_announces.retain_participants(&configured_set);
                                    outbound_announces.clear();
                                    last_nat_punch_attempt = None;
                                    client.disconnect().await;
                                    match NostrSignalingClient::from_secret_key_with_networks(
                                        &app.nostr.secret_key,
                                        signaling_networks_for_app(&app),
                                    ) {
                                        Ok(new_client) => {
                                            client = new_client;
                                            let join_requests_active = app.join_requests_enabled();
                                            let session_active =
                                                daemon_session_active(session_enabled, expected_peers);
                                            if relay_session_active(
                                                session_enabled,
                                                expected_peers,
                                                join_requests_active,
                                            ) {
                                                match client.connect(&relays).await {
                                                    Ok(()) => {
                                                        relay_connected = true;
                                                        reconnect_attempt = 0;
                                                        reconnect_due = Instant::now();
                                                        if let Err(error) =
                                                            publish_active_network_roster(
                                                                &client,
                                                                &app,
                                                                None,
                                                            )
                                                            .await
                                                        {
                                                            eprintln!(
                                                                "daemon: roster publish failed after config reload: {error}"
                                                            );
                                                        }
                                                        session_status = if session_active {
                                                            "Config reloaded".to_string()
                                                        } else {
                                                            daemon_session_idle_status(
                                                                session_enabled,
                                                                expected_peers,
                                                                join_requests_active,
                                                            )
                                                            .to_string()
                                                        };
                                                        if session_active {
                                                            if let Err(error) = publish_private_announce_to_known_peers(
                                                                &client,
                                                                &app,
                                                                own_pubkey.as_deref(),
                                                                &presence,
                                                                &tunnel_runtime,
                                                                public_signal_endpoint.as_ref(),
                                                                &relay_sessions,
                                                                &mut outbound_announces,
                                                            ).await {
                                                                session_status = format!(
                                                                    "Config reloaded; private announce failed ({})",
                                                                    error
                                                                );
                                                            }
                                                            if let Err(error) = client.publish(SignalPayload::Hello).await {
                                                                session_status = format!(
                                                                    "Config reloaded; hello publish failed ({})",
                                                                    error
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(error) => {
                                                        relay_connected = false;
                                                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                                                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                                                        reconnect_due = Instant::now() + delay;
                                                        session_status = format!(
                                                            "Config reloaded; relay reconnect failed (retry in {}s: {})",
                                                            delay.as_secs(),
                                                            error
                                                        );
                                                    }
                                                }
                                            } else {
                                                relay_connected = false;
                                                reconnect_attempt = 0;
                                                reconnect_due = Instant::now();
                                                port_mapping_runtime.stop().await;
                                                public_signal_endpoint = None;
                                                session_status = if session_enabled {
                                                    daemon_session_idle_status(
                                                        session_enabled,
                                                        expected_peers,
                                                        join_requests_active,
                                                    )
                                                    .to_string()
                                                } else {
                                                    "Config reloaded (paused)".to_string()
                                                };
                                            }
                                        }
                                        Err(error) => {
                                            session_status = format!(
                                                "Config reload failed (signal client init): {}",
                                                error
                                            );
                                        }
                                    }

                                    if let Err(error) = apply_presence_runtime_update(
                                        &app,
                                        own_pubkey.as_deref(),
                                        &presence,
                                        &relay_sessions,
                                        &mut path_book,
                                        unix_timestamp(),
                                        &mut tunnel_runtime,
                                        magic_dns_runtime.as_ref(),
                                    ) {
                                        session_status = format!(
                                            "Config reloaded; tunnel update failed ({})",
                                            error
                                        );
                                    } else if daemon_session_active(session_enabled, expected_peers) {
                                        let runtime_listen_port = tunnel_runtime
                                            .active_listen_port
                                            .unwrap_or(app.node.listen_port);
                                        refresh_public_signal_endpoint_with_port_mapping(
                                            &app,
                                            &network_snapshot,
                                            runtime_listen_port,
                                            &mut port_mapping_runtime,
                                            &mut public_signal_endpoint,
                                        )
                                        .await;
                                    }
                                    Ok(())
                                }
                                Err(error) => {
                                    session_status = if staged_config_applied {
                                        format!("Config apply failed (reload: {error})")
                                    } else {
                                        format!("Config reload failed ({error})")
                                    };
                                    Err(error)
                                }
                            }
                                }
                                Err(error) => {
                                    session_status = format!("Config apply failed ({error})");
                                    Err(error)
                                }
                            }
                        }
                    };
                    let _ = write_daemon_control_result(&config_path, request, control_result);
                    if let Err(error) = sync_local_relay_operator(
                        &config_path,
                        &app,
                        &relays,
                        public_signal_endpoint.as_ref(),
                        &mut relay_operator_process,
                        &mut relay_operator_runtime,
                    ) {
                        eprintln!("relay operator: sync failed after control request: {error}");
                    }
                    let _ = persist_daemon_runtime_state(
                        &state_file,
                        &app,
                        session_enabled,
                        expected_peers,
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &session_status,
                        relay_connected,
                        &network_snapshot.summary(network_changed_at, captive_portal),
                        &port_mapping_runtime.status(),
                        &relay_operator_runtime,
                    );
                    if let Err(error) =
                        persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                    {
                        eprintln!("daemon: failed to persist network cleanup state: {error}");
                    }
                }
                if let Some((executable, launched_fingerprint)) =
                    supervised_service_executable.as_ref()
                {
                    match service_supervisor_restart_due(executable, launched_fingerprint) {
                        Ok(true) => {
                            eprintln!(
                                "daemon: service executable changed on disk; exiting so the supervisor restarts the updated binary"
                            );
                            break;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to check service executable fingerprint: {error}"
                            );
                        }
                    }
                }
                if daemon_session_active(session_enabled, expected_peers) {
                    let now = unix_timestamp();
                    let removed = presence.prune_stale(
                        now,
                        peer_signal_timeout_secs(args.announce_interval_secs),
                    );
                    for participant in &removed {
                        outbound_announces.forget(participant);
                    }
                    let paths_pruned =
                        path_book.prune_stale(now, peer_path_cache_timeout_secs(args.announce_interval_secs));
                    let recent = recently_seen_participants(
                        &presence,
                        now,
                        peer_signal_timeout_secs(args.announce_interval_secs),
                    );
                    outbound_announces.retain_participants(&recent);
                    if !removed.is_empty() || paths_pruned {
                        last_nat_punch_attempt = None;
                        if let Err(error) = apply_presence_runtime_update(
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &relay_sessions,
                            &mut path_book,
                            now,
                            &mut tunnel_runtime,
                            magic_dns_runtime.as_ref(),
                        ) {
                            session_status = format!("Stale peer expiry update failed ({error})");
                        } else {
                            maybe_log_presence_mesh_count(
                                &app,
                                own_pubkey.as_deref(),
                                presence.active(),
                                expected_peers,
                                &mut last_mesh_count,
                            );
                        }
                    }
                }
                if let Err(error) = write_daemon_peer_cache_if_changed(
                    DaemonPeerCacheWrite {
                        path: &peer_cache_file,
                        network_id: &network_id,
                        own_pubkey: own_pubkey.as_deref(),
                        presence: &presence,
                        path_book: &path_book,
                        tunnel_runtime: &tunnel_runtime,
                        now: unix_timestamp(),
                    },
                    &mut last_written_peer_cache,
                ) {
                    eprintln!("daemon: failed to persist peer cache: {error}");
                }
                if let Err(error) = sync_local_relay_operator(
                    &config_path,
                    &app,
                    &relays,
                    public_signal_endpoint.as_ref(),
                    &mut relay_operator_process,
                    &mut relay_operator_runtime,
                ) {
                    eprintln!("relay operator: sync failed: {error}");
                }
                let _ = persist_daemon_runtime_state(
                    &state_file,
                    &app,
                    session_enabled,
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &session_status,
                    relay_connected,
                    &network_snapshot.summary(network_changed_at, captive_portal),
                    &port_mapping_runtime.status(),
                    &relay_operator_runtime,
                );
                if let Err(error) =
                    persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                {
                    eprintln!("daemon: failed to persist network cleanup state: {error}");
                }
            }
            message = async {
                if relay_session_active(
                    session_enabled,
                    expected_peers,
                    app.join_requests_enabled(),
                ) && relay_connected
                {
                    client.recv().await
                } else {
                    std::future::pending::<Option<SignalEnvelope>>().await
                }
            } => {
                let Some(message) = message else {
                    relay_connected = false;
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                    reconnect_due = Instant::now() + delay;
                    session_status = format!("Signal stream closed; retry in {}s", delay.as_secs());
                    eprintln!("daemon: signal stream closed (retry in {}s)", delay.as_secs());
                    continue;
                };

                let sender_pubkey = message.sender_pubkey;
                let payload = message.payload.clone();
                let session_active = daemon_session_active(session_enabled, expected_peers);
                if let SignalPayload::JoinRequest {
                    requested_at,
                    request,
                } = &payload
                {
                    persist_inbound_join_request(
                        &mut app,
                        &config_path,
                        &sender_pubkey,
                        *requested_at,
                        &request.network_id,
                        &request.requester_node_name,
                        &mut session_status,
                    );
                    continue;
                }

                if let SignalPayload::Roster(roster) = &payload {
                    match persist_shared_network_roster(
                        &mut app,
                        &config_path,
                        &sender_pubkey,
                        &message.network_id,
                        roster,
                        &mut session_status,
                    ) {
                        Ok(Some(_)) => {
                            let reload = build_daemon_reload_config(
                                app.clone(),
                                app.effective_network_id(),
                                &args.relay,
                            );
                            let configured_set = reload
                                .configured_participants
                                .iter()
                                .cloned()
                                .collect::<HashSet<_>>();
                            app = reload.app;
                            network_id = reload.network_id;
                            expected_peers = reload.expected_peers;
                            own_pubkey = reload.own_pubkey;
                            relays = reload.relays;

                            presence.retain_participants(&configured_set);
                            path_book.retain_participants(&configured_set);
                            outbound_announces.retain_participants(&configured_set);
                            outbound_announces.clear();
                            last_nat_punch_attempt = None;
                            client.disconnect().await;
                            match NostrSignalingClient::from_secret_key_with_networks(
                                &app.nostr.secret_key,
                                signaling_networks_for_app(&app),
                            ) {
                                Ok(new_client) => {
                                    client = new_client;
                                    let join_requests_active = app.join_requests_enabled();
                                    if relay_session_active(
                                        session_enabled,
                                        expected_peers,
                                        join_requests_active,
                                    ) {
                                        match client.connect(&relays).await {
                                            Ok(()) => {
                                                relay_connected = true;
                                                reconnect_attempt = 0;
                                                reconnect_due = Instant::now();
                                                if let Err(error) = apply_presence_runtime_update(
                                                    &app,
                                                    own_pubkey.as_deref(),
                                                    &presence,
                                                    &relay_sessions,
                                                    &mut path_book,
                                                    unix_timestamp(),
                                                    &mut tunnel_runtime,
                                                    magic_dns_runtime.as_ref(),
                                                ) {
                                                    session_status = format!(
                                                        "Roster applied, but tunnel reload failed ({error})"
                                                    );
                                                }
                                                if let Err(error) =
                                                    publish_active_network_roster(
                                                        &client,
                                                        &app,
                                                        None,
                                                    )
                                                    .await
                                                {
                                                    eprintln!(
                                                        "daemon: roster publish failed after roster apply: {error}"
                                                    );
                                                }
                                                if daemon_session_active(session_enabled, expected_peers)
                                                    && let Err(error) = client.publish(SignalPayload::Hello).await
                                                {
                                                    eprintln!(
                                                        "daemon: hello publish failed after roster apply: {error}"
                                                    );
                                                }
                                            }
                                            Err(error) => {
                                                relay_connected = false;
                                                reconnect_attempt =
                                                    reconnect_attempt.saturating_add(1);
                                                let delay =
                                                    daemon_reconnect_backoff_delay(reconnect_attempt);
                                                reconnect_due = Instant::now() + delay;
                                                session_status = format!(
                                                    "Roster applied; relay reconnect failed (retry in {}s: {error})",
                                                    delay.as_secs(),
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    relay_connected = false;
                                    session_status =
                                        format!("Roster applied, but signaling reload failed ({error})");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!(
                                "daemon: ignoring invalid shared roster from {sender_pubkey}: {error}"
                            );
                        }
                    }
                    continue;
                }

                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_active_network_roster(
                        &client,
                        &app,
                        Some(std::slice::from_ref(&sender_pubkey)),
                    )
                    .await
                {
                    eprintln!("daemon: targeted roster publish failed: {error}");
                }

                if !session_active {
                    continue;
                }

                let changed =
                    presence.apply_signal(sender_pubkey.clone(), message.payload, unix_timestamp());
                if matches!(&payload, SignalPayload::Disconnect { .. }) {
                    outbound_announces.forget(&sender_pubkey);
                }
                if !changed {
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    continue;
                }

                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    let error_text = error.to_string();
                    session_status = format!("Tunnel update failed ({error_text})");
                } else {
                    if let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    ) {
                        eprintln!("nat: hole-punch after peer signal failed: {error}");
                    }
                    if let Err(error) = heartbeat_pending_tunnel_peers(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        &tunnel_runtime,
                    ) {
                        eprintln!("tunnel: peer heartbeat failed after peer signal: {error}");
                    }
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && {
                            maybe_reset_targeted_announce_cache_for_hello(
                                &mut outbound_announces,
                                &sender_pubkey,
                                &payload,
                            );
                            true
                        }
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    session_status = if daemon_session_active(session_enabled, expected_peers) {
                        "Connected".to_string()
                    } else {
                        daemon_session_idle_status(
                            session_enabled,
                            expected_peers,
                            app.join_requests_enabled(),
                        )
                        .to_string()
                    };
                }

                maybe_log_presence_mesh_count(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    expected_peers,
                    &mut last_mesh_count,
                );
            }
            service_message = async {
                if relay_session_active(
                    session_enabled,
                    expected_peers,
                    app.join_requests_enabled(),
                ) && relay_connected && relay_service_connected
                {
                    service_client.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let Some(service_message) = service_message else {
                    relay_service_connected = false;
                    continue;
                };
                let now = unix_timestamp();
                match service_message.payload {
                    ServicePayload::RelayAllocationGranted(granted) => {
                        match accept_relay_allocation_grant(
                            granted,
                            &mut pending_relay_requests,
                            &mut relay_sessions,
                            &mut standby_relay_sessions,
                            &relay_failures,
                            now,
                        ) {
                            RelayGrantAction::Activated(participant) => {
                                outbound_announces.forget(&participant);
                                if let Err(error) = apply_presence_runtime_update(
                                    &app,
                                    own_pubkey.as_deref(),
                                    &presence,
                                    &relay_sessions,
                                    &mut path_book,
                                    now,
                                    &mut tunnel_runtime,
                                    magic_dns_runtime.as_ref(),
                                ) {
                                    session_status = format!("Relay fallback update failed ({error})");
                                } else if let Err(error) = publish_private_announce_to_participants(
                                    &client,
                                    &app,
                                    &tunnel_runtime,
                                    public_signal_endpoint.as_ref(),
                                    &relay_sessions,
                                    &mut outbound_announces,
                                    std::slice::from_ref(&participant),
                                    Some(presence.known()),
                                )
                                .await
                                {
                                    eprintln!("relay: targeted relay announce failed: {error}");
                                }
                            }
                            RelayGrantAction::QueuedStandby(_) | RelayGrantAction::Ignored => {}
                        }
                    }
                    ServicePayload::RelayAllocationRejected(rejected) => {
                        if let Some(participant) = accept_relay_allocation_rejection(
                            rejected,
                            &mut pending_relay_requests,
                            &mut relay_failures,
                            &mut relay_provider_verifications,
                            now,
                        ) {
                            outbound_announces.forget(&participant);
                        }
                    }
                    ServicePayload::RelayAllocationRequest(_)
                    | ServicePayload::RelayProbeRequest(_)
                    | ServicePayload::RelayProbeGranted(_)
                    | ServicePayload::RelayProbeRejected(_) => {}
                }
            }
        }
    }

    if relay_connected && daemon_session_active(session_enabled, expected_peers) {
        let _ = client
            .publish(SignalPayload::Disconnect {
                node_id: app.node.id.clone(),
            })
            .await;
    }
    client.disconnect().await;
    service_client.disconnect().await;
    stop_local_relay_operator(
        &mut relay_operator_process,
        &mut relay_operator_runtime,
        "Relay operator stopped",
        "NAT assist stopped",
    );
    port_mapping_runtime.stop().await;
    tunnel_runtime.stop();
    if let Err(error) = persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime) {
        eprintln!("daemon: failed to clear network cleanup state: {error}");
    }

    let final_state = DaemonRuntimeState {
        updated_at: unix_timestamp(),
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        session_active: false,
        relay_connected: false,
        session_status: "Disconnected".to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count: 0,
        mesh_ready: false,
        health: Vec::new(),
        network: network_snapshot.summary(network_changed_at, captive_portal),
        port_mapping: PortMappingStatus::default(),
        peers: Vec::new(),
        relay_operator_running: false,
        relay_operator_pid: None,
        relay_operator_status: relay_operator_runtime.status.clone(),
        nat_assist_running: false,
        nat_assist_status: relay_operator_runtime.nat_assist_status.clone(),
    };
    let _ = write_daemon_state(&state_file, &final_state);

    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_service_dispatcher(args: DaemonArgs) -> Result<()> {
    WINDOWS_SERVICE_DAEMON_ARGS
        .set(args)
        .map_err(|_| anyhow!("windows service daemon arguments already initialized"))?;
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_windows_service_main)
        .context("failed to start Windows service dispatcher")
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service() {
        eprintln!("windows service failed: {error:?}");
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_service() -> Result<()> {
    let args = WINDOWS_SERVICE_DAEMON_ARGS
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("windows service launched without daemon arguments"))?;
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, {
        let config_path = config_path.clone();
        move |control_event| match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = request_daemon_stop(&config_path);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .context("failed to register Windows service control handler")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        Duration::from_secs(10),
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for Windows service")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        Duration::default(),
    )?;

    let result = runtime.block_on(daemon_session(args));
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    set_windows_service_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::default(),
    )?;
    result
}

#[cfg(target_os = "windows")]
pub(crate) fn set_windows_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> Result<()> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
        .with_context(|| format!("failed to update Windows service status to {state:?}"))
}

pub(crate) fn daemon_reconnect_backoff_delay(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        3 => Duration::from_secs(4),
        4 => Duration::from_secs(8),
        5 => Duration::from_secs(16),
        _ => Duration::from_secs(30),
    }
}

pub(crate) fn publish_error_requires_reconnect(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("client not connected")
        || lower.contains("relay pool shutdown")
        || lower.contains("relay not connected")
        || lower.contains("status changed")
        || lower.contains("recv message response timeout")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_daemon_runtime_state(
    app: &AppConfig,
    session_active: bool,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    session_status: &str,
    relay_connected: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    relay_operator: &LocalRelayOperatorRuntime,
) -> DaemonRuntimeState {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let now = unix_timestamp();
    let listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    let local_endpoint = local_signal_endpoint(app, listen_port);
    let advertised_endpoint = public_endpoint_for_listen_port(public_signal_endpoint, listen_port)
        .unwrap_or_else(|| local_endpoint.clone());
    let mut peers = Vec::new();

    for participant in &app.participant_pubkeys_hex() {
        if Some(participant.as_str()) == own_pubkey.as_deref() {
            continue;
        }

        let Some(announcement) = presence.announcement_for(participant) else {
            let transport = daemon_peer_transport_state(None, false, None, now);
            peers.push(DaemonPeerState {
                participant_pubkey: participant.clone(),
                node_id: String::new(),
                tunnel_ip: String::new(),
                endpoint: String::new(),
                runtime_endpoint: None,
                tx_bytes: 0,
                rx_bytes: 0,
                public_key: String::new(),
                advertised_routes: Vec::new(),
                presence_timestamp: 0,
                last_signal_seen_at: None,
                reachable: transport.reachable,
                last_handshake_at: transport.last_handshake_at,
                error: transport.error,
            });
            continue;
        };

        let signal_active = presence.active().contains_key(participant);
        let runtime_peer = peer_runtime_lookup(announcement, runtime_peers.as_ref());
        let transport =
            daemon_peer_transport_state(Some(announcement), signal_active, runtime_peer, now);

        peers.push(DaemonPeerState {
            participant_pubkey: participant.clone(),
            node_id: announcement.node_id.clone(),
            tunnel_ip: announcement.tunnel_ip.clone(),
            endpoint: announcement.endpoint.clone(),
            runtime_endpoint: runtime_peer.and_then(|peer| peer.endpoint.clone()),
            tx_bytes: runtime_peer.map(|peer| peer.tx_bytes).unwrap_or(0),
            rx_bytes: runtime_peer.map(|peer| peer.rx_bytes).unwrap_or(0),
            public_key: announcement.public_key.clone(),
            advertised_routes: announcement.advertised_routes.clone(),
            presence_timestamp: announcement.timestamp,
            last_signal_seen_at: presence.last_seen_at(participant),
            reachable: transport.reachable,
            last_handshake_at: transport.last_handshake_at,
            error: transport.error,
        });
    }

    let connected_peer_count = connected_peer_count_for_runtime(
        app,
        own_pubkey.as_deref(),
        presence,
        runtime_peers.as_ref(),
        now,
    );
    let mesh_ready = expected_peers > 0 && connected_peer_count >= expected_peers;
    let health = build_health_issues(
        app,
        session_active,
        relay_connected,
        mesh_ready,
        network,
        port_mapping,
        &peers,
    );
    DaemonRuntimeState {
        updated_at: now,
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint,
        advertised_endpoint,
        listen_port,
        session_active,
        relay_connected,
        session_status: session_status.to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        health,
        network: network.clone(),
        port_mapping: port_mapping.clone(),
        peers,
        relay_operator_running: relay_operator.running,
        relay_operator_pid: relay_operator.pid,
        relay_operator_status: relay_operator.status.clone(),
        nat_assist_running: relay_operator.nat_assist_running,
        nat_assist_status: relay_operator.nat_assist_status.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_daemon_runtime_state(
    path: &Path,
    app: &AppConfig,
    session_enabled: bool,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    session_status: &str,
    relay_connected: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    relay_operator: &LocalRelayOperatorRuntime,
) -> Result<()> {
    write_daemon_state(
        path,
        &build_daemon_runtime_state(
            app,
            daemon_session_active(session_enabled, expected_peers),
            expected_peers,
            presence,
            tunnel_runtime,
            public_signal_endpoint,
            session_status,
            relay_connected,
            network,
            port_mapping,
            relay_operator,
        ),
    )
}
