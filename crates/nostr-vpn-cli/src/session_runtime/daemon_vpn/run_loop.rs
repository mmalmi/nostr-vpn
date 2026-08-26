loop {
    tunnel_runtime.sync_fips_state(fips_tunnel_runtime.as_ref());
    let control_request_waiting = daemon_control_file_path(&config_path).exists();
    let background_ready = daemon_state_background_maintenance_enabled(
        &intervals.network_deadline,
        control_request_waiting,
    );
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            break;
        }
        _ = &mut terminate_wait => {
            break;
        }
        platform_network_change = recv_platform_network_change(&mut platform_network_change_rx),
            if platform_network_event_receive_enabled(
                network_event_pending,
                network_settle_rechecks,
                &intervals.network_deadline,
            ) && !control_request_waiting => {
            if platform_network_change.is_none() {
                platform_network_change_rx = None;
                continue;
            }
            drain_platform_network_changes(&mut platform_network_change_rx);
            network_event_pending = true;
            last_network_sample_diagnostic.clear();
            eprintln!(
                "daemon: platform network change event; sampling physical route; received_unix_ms={}",
                daemon_wall_clock_unix_milliseconds()
            );
            schedule_platform_network_event_sampling(
                &mut intervals.network_deadline,
                &mut network_settle_rechecks,
            );
        }
        Some(request) = join_request_ipc_rx.recv(), if !control_request_waiting => {
            respond_to_join_request(&mut app, request);
        }
        _ = announce_interval.tick(), if background_ready => {
            if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                if let Err(error) = publish_fips_active_network_roster(
                    runtime,
                    &app,
                    &config_path,
                    &mut pending_fips_roster_recipients,
                ) {
                    eprintln!("fips: roster publish failed: {error}");
                }
                if let Err(error) = broadcast_local_fips_capabilities(runtime, &app).await {
                    eprintln!("fips: capabilities broadcast failed: {error}");
                }
            }
        }
        _ = paid_exit_offer_refresh_interval.tick(), if background_ready => {
            #[cfg(feature = "paid-exit")]
            log_paid_exit_offer_publication(paid_exit_offer_publisher.reconcile(
                &app,
                &config_path,
                unix_timestamp(),
                fips_tunnel_runtime.as_ref().is_some_and(
                    crate::fips_private_mesh::FipsPrivateTunnelRuntime::paid_exit_seller_ready,
                ),
                true,
            ));
        }
        _ = recent_peer_refresh_interval.tick(), if background_ready => {
            if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                update_recent_peers_from_runtime(
                    runtime,
                    &app,
                    &network_id,
                    own_pubkey.as_deref(),
                    RecentPeerRefresh {
                        recent_peers: &mut recent_peers,
                        recent_peers_path: &recent_peers_path,
                        last_endpoint_peer_signature: &mut last_fips_endpoint_peer_signature,
                        last_refresh_signature: &mut last_recent_peer_refresh_signature,
                        last_cache_persisted_at: &mut last_recent_peer_cache_persisted_at,
                        force_rebuild: false,
                    },
                    unix_timestamp(),
                )
                .await;
            }
        }
        _ = intervals.tunnel_heartbeat.tick(), if background_ready => {
            if observe_wall_time_jump(
                &mut last_runtime_heartbeat_at,
                unix_timestamp(),
                MAJOR_LINK_CHANGE_TIME_JUMP_SECS,
            ) {
                intervals.runtime_resume_pending = true;
                intervals.network.reset_immediately();
            }
            let vpn_active = daemon_vpn_active(vpn_enabled, expected_peers);
            let maintain_fips = if vpn_active {
                fips_tunnel_runtime.is_some()
            } else {
                fips_private_runtime_active_for_config(
                    &app,
                    &config_path,
                    vpn_enabled,
                    expected_peers,
                )?
            };
            if maintain_fips {
                maintain_fips_heartbeat(FipsHeartbeatContext {
                    runtime: &mut fips_tunnel_runtime,
                    app: &app,
                    config_path: &config_path,
                    network_id: &network_id,
                    fallback_iface: &iface,
                    underlay_interface: network_snapshot.default_interface.as_deref(),
                    underlay_interface_mtu: network_snapshot.default_interface_mtu,
                    own_pubkey: own_pubkey.as_deref(),
                    recent_peers: &recent_peers,
                    ethernet_underlay: ethernet_underlay.as_ref(),
                    expected_peers,
                    last_endpoint_peer_signature: &mut last_fips_endpoint_peer_signature,
                    last_stale_participant_restart_at:
                        &mut last_fips_stale_participant_restart_at,
                    pending_roster_restart_state: &mut fips_pending_roster_restart_state,
                    roster_sync_state: &mut fips_roster_sync_state,
                    pending_roster_recipients: &mut pending_fips_roster_recipients,
                    join_request_sends: &mut fips_join_request_sends,
                })
                .await;
                if let Some(runtime) = fips_tunnel_runtime.as_ref() {
                    start_queued_join_roster_deliveries(runtime, &config_path);
                }
            }
            if !vpn_active {
                continue;
            }
        }
        network_trigger = next_daemon_network_trigger(
            &mut intervals.network_deadline,
            &mut intervals.network,
        ), if !control_request_waiting => {
            let event_driven_sample = daemon_network_trigger_is_event_driven(
                network_trigger,
                intervals.runtime_resume_pending,
            );
            drain_platform_network_changes_for_sample(
                &mut platform_network_change_rx,
                event_driven_sample,
            );
            let now = unix_timestamp();
            let resumed_after_sleep = std::mem::take(&mut intervals.runtime_resume_pending);
            if resumed_after_sleep {
                eprintln!("daemon: sleep/wake detected; refreshing FIPS endpoint state");
            }
            let wireguard_exit_interface =
                (app.wireguard_exit.enabled && app.wireguard_exit.configured())
                    .then_some(app.wireguard_exit.interface.trim());
            #[cfg(target_os = "linux")]
            let default_route_hints = fips_tunnel_runtime
                .as_ref()
                .map_or_else(Vec::new, |runtime| {
                    runtime.linux_underlay_default_route_hints()
                });
            #[cfg(not(target_os = "linux"))]
            let default_route_hints = Vec::new();
            let sampled_network = capture_network_snapshot_for_daemon(
                &iface,
                wireguard_exit_interface,
                default_route_hints,
            )
            .await;
            let sampled_physical_network = sampled_network.snapshot.clone();
            log_event_driven_network_sample(
                event_driven_sample,
                &sampled_network,
                &mut last_network_sample_diagnostic,
            );
            let wireguard_network_state_drift =
                app.wireguard_exit.enabled
                    && app.wireguard_exit.configured()
                    && sampled_network.live_unmanaged_ipv4_default_present;
            let latest_snapshot = prefer_nonself_tunnel_snapshot(
                &tunnel_runtime,
                wireguard_exit_interface,
                (app.wireguard_exit.enabled && app.wireguard_exit.configured())
                    .then(|| {
                        strip_cidr(&app.wireguard_exit.address)
                            .parse::<Ipv4Addr>()
                            .ok()
                })
                    .flatten(),
                &network_snapshot,
                sampled_network.snapshot,
            );
            if network_refresh_attempt.as_ref().is_some_and(|attempt| {
                attempt.is_superseded_by(
                    &latest_snapshot,
                    resumed_after_sleep,
                    wireguard_network_state_drift,
                )
            }) {
                eprintln!("daemon: physical route changed during staged refresh");
                network_refresh_attempt = None;
            }
            let network_changed = latest_snapshot.changed_since(&network_snapshot);
            let platform_network_event = network_event_pending;
            network_event_pending = false;
            let vpn_active = daemon_vpn_active(vpn_enabled, expected_peers);
            let endpoint_changed = if network_refresh_attempt.is_some() {
                false
            } else if network_changed || resumed_after_sleep {
                vpn_active
            } else if vpn_active
                && let Some(runtime_listen_port) = tunnel_runtime.active_listen_port
            {
                match port_mapping_runtime
                    .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                    .await
                {
                    Ok(changed) => changed,
                    Err(error) => {
                        eprintln!("daemon: port mapping renew failed: {error}");
                        false
                    }
                }
            } else {
                false
            };
            if network_refresh_attempt.is_none()
                && !platform_network_event
                && !network_changed
                && !wireguard_network_state_drift
                && !endpoint_changed
                && !resumed_after_sleep
            {
                schedule_platform_network_settle_recheck(
                    &mut intervals.network_deadline,
                    &mut network_settle_rechecks,
                );
                continue;
            }
            if network_refresh_attempt.is_none() {
                let Some(attempt) = begin_platform_network_refresh_attempt(
                    latest_snapshot,
                    platform_network_event,
                    network_changed,
                    wireguard_network_state_drift,
                    endpoint_changed,
                    resumed_after_sleep,
                ) else {
                    schedule_platform_network_settle_recheck(
                        &mut intervals.network_deadline,
                        &mut network_settle_rechecks,
                    );
                    continue;
                };
                network_settle_rechecks = 0;
                network_refresh_attempt = Some(attempt);
            }
            if platform_network_refresh_waits_for_underlay(
                network_refresh_attempt.as_ref(),
                &sampled_physical_network,
            ) {
                if network_settle_rechecks == 0 {
                    begin_platform_network_settle_rechecks(&mut network_settle_rechecks);
                    eprintln!(
                        "daemon: physical underlay not ready; keeping FIPS endpoint restart staged"
                    );
                }
                schedule_platform_network_settle_recheck(
                    &mut intervals.network_deadline,
                    &mut network_settle_rechecks,
                );
                continue;
            }
            let (fips_refresh, refresh_reason, target_snapshot, needs_carrier_rebind) =
                network_refresh_attempt
                    .as_ref()
                    .expect("network refresh attempt created above")
                    .parameters(fips_tunnel_runtime.is_some());
            if needs_carrier_rebind {
                let rebind_result = rebind_fips_tunnel_runtime_underlay_after_link_event(
                    &fips_tunnel_runtime,
                    target_snapshot.default_interface.as_deref(),
                    refresh_reason,
                )
                .await;
                if let Err(error) = rebind_result {
                    if !stage_platform_network_refresh_failure(
                        &mut vpn_status,
                        &mut network_refresh_terminal_error,
                        &mut network_refresh_attempt,
                        &mut intervals.network_deadline,
                        error,
                        "FIPS underlay carrier rebind failed",
                        "FIPS carrier rebind retry budget exhausted",
                    ) {
                        break;
                    }
                    continue;
                }
                network_refresh_attempt
                    .as_mut()
                    .expect("active carrier rebind attempt")
                    .mark_carrier_rebound();
            }
            if target_snapshot != network_snapshot
                || matches!(fips_refresh, FipsLinkEventRefresh::RestartEndpoint)
            {
                network_snapshot = target_snapshot;
                network_changed_at = Some(unix_timestamp());
            }
            let fips_result = if fips_tunnel_runtime.is_some()
                || fips_private_runtime_active_for_config(
                    &app,
                    &config_path,
                    vpn_enabled,
                    expected_peers,
                )?
            {
                refresh_fips_tunnel_runtime_after_link_event(
                    &mut fips_tunnel_runtime,
                    FipsRestartContext {
                        app: &app,
                        config_path: &config_path,
                        network_id: &network_id,
                        fallback_iface: &iface,
                        underlay_interface: network_snapshot.default_interface.as_deref(),
                        underlay_interface_mtu: network_snapshot.default_interface_mtu,
                        own_pubkey: own_pubkey.as_deref(),
                        recent_peers: Some(&recent_peers),
                        ethernet_underlay: ethernet_underlay.as_ref(),
                        client_dataplane_enabled: vpn_enabled,
                        last_endpoint_peer_signature: &mut last_fips_endpoint_peer_signature,
                    },
                    refresh_reason,
                    fips_refresh,
                )
                .await
            } else {
                Ok(())
            };
            if let Err(error) = fips_result {
                if !stage_platform_network_refresh_failure(
                    &mut vpn_status,
                    &mut network_refresh_terminal_error,
                    &mut network_refresh_attempt,
                    &mut intervals.network_deadline,
                    error,
                    "network route refresh failed",
                    "FIPS route refresh retry budget exhausted",
                ) {
                    break;
                }
                continue;
            }
            network_refresh_attempt = None;
            vpn_status = complete_fips_link_event_refresh(FipsLinkRefreshCompletion {
                runtime: fips_tunnel_runtime.as_ref(),
                app: &app,
                network_id: &network_id,
                own_pubkey: own_pubkey.as_deref(),
                recent_peers: &mut recent_peers,
                recent_peers_path: &recent_peers_path,
                last_endpoint_peer_signature: &mut last_fips_endpoint_peer_signature,
                last_refresh_signature: &mut last_recent_peer_refresh_signature,
                last_cache_persisted_at: &mut last_recent_peer_cache_persisted_at,
                vpn_enabled,
                expected_peers,
                now,
            })
            .await;
            if matches!(
                fips_refresh,
                FipsLinkEventRefresh::RestartEndpoint
                    | FipsLinkEventRefresh::RebindUnderlayAndRefreshPaths
            ) {
                tunnel_runtime.active_listen_port = fips_tunnel_runtime.as_ref().and_then(
                    crate::fips_private_mesh::FipsPrivateTunnelRuntime::active_listen_port,
                );
                if vpn_active
                    && let Some(runtime_listen_port) = tunnel_runtime.active_listen_port
                {
                    refresh_port_mapping(
                        &app,
                        &network_snapshot,
                        runtime_listen_port,
                        &mut port_mapping_runtime,
                    )
                    .await;
                } else {
                    port_mapping_runtime.stop().await;
                }
                captive_portal = detect_captive_portal(timeout).await;
            }
        }
        _ = intervals.state.tick() => {
            #[cfg(feature = "paid-exit")]
            let pending_control_request =
                paid_exit_buyer_refunds.before_tick(&config_path, background_ready);
            #[cfg(not(feature = "paid-exit"))]
            let pending_control_request = take_daemon_control_request(&config_path);
            let state_background_ready =
                background_ready && pending_control_request.is_none();
            if state_background_ready {
                if let Err(error) = app.ensure_pending_nostr_join_request(unix_timestamp()) {
                    eprintln!("daemon: failed to rotate expired join request: {error}");
                }
                if daemon_log_compact_check_due(&mut last_log_compact_check)
                    && let Err(error) = compact_daemon_log_if_needed(&config_path)
                {
                    eprintln!("daemon: failed to compact service log: {error}");
                }
                #[cfg(feature = "paid-exit")]
                match reconcile_automatic_paid_exit_selection(
                    &mut automatic_paid_exit,
                    &mut app,
                    &config_path,
                    unix_timestamp(),
                ) {
                Ok(true) => {
                    if let Err(error) = sync_fips_private_runtime(
                        &mut fips_tunnel_runtime,
                        SyncFipsPrivateRuntimeContext {
                            app: &app,
                            config_path: &config_path,
                            network_id: &network_id,
                            iface: &iface,
                            underlay_interface: network_snapshot
                                .default_interface
                                .as_deref(),
                            underlay_interface_mtu: network_snapshot.default_interface_mtu,
                            own_pubkey: own_pubkey.as_deref(),
                            recent_peers: Some(&recent_peers),
                            ethernet_underlay: ethernet_underlay.as_ref(),
                            vpn_enabled,
                            expected_peers,
                        },
                    )
                    .await
                    {
                        vpn_status = format!("automatic paid-exit FIPS selection failed ({error})");
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    eprintln!("paid-exit: automatic selection failed: {error}");
                }
            }
            #[cfg(feature = "paid-exit")]
            let mut automatic_paid_exit_route_changed = false;
            #[cfg(feature = "paid-exit")]
            let mut manual_paid_exit_route_changed = false;
            #[cfg(feature = "paid-exit")]
            let mut paid_exit_payment_outbox_changed = false;
            if let Some(runtime) = fips_tunnel_runtime.as_mut() {
                #[cfg(feature = "paid-exit")]
                if last_paid_exit_session_open_at.elapsed()
                    >= Duration::from_secs(PAID_EXIT_SESSION_OPEN_RETRY_SECS)
                {
                    last_paid_exit_session_open_at = Instant::now();
                    match send_selected_paid_exit_session_open(
                        runtime,
                        &mut app,
                        &config_path,
                        unix_timestamp(),
                    )
                    .await
                    {
                        Ok(PaidExitSessionOpenResult::FellBackDirect) => {
                            if let Err(error) = refresh_fips_tunnel_config(
                                runtime,
                                &app,
                                &config_path,
                                &network_id,
                                network_snapshot.default_interface.as_deref(),
                                network_snapshot.default_interface_mtu,
                                own_pubkey.as_deref(),
                            )
                            .await
                            {
                                vpn_status = format!(
                                    "paid-exit direct fallback refresh failed ({error})"
                                );
                            }
                            // The paid route used the secure-DNS runtime. Once that
                            // runtime is removed, restore direct-mode split MagicDNS
                            // so private peers such as mini.nvpn remain resolvable.
                            refresh_or_start_split_magic_dns(&mut magic_dns_runtime, &app);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            eprintln!("paid-exit: free-probe session open send failed: {error}")
                        }
                    }
                }
                match drain_fips_mesh_events(
                    runtime,
                    &mut app,
                    &config_path,
                    &mut vpn_status,
                )
                .await
                {
                    Ok(drained) => {
                        #[cfg(feature = "paid-exit")]
                        let mut drained = drained;
                        if drained.roster_changed {
                            let reload = build_daemon_reload_config(
                                app.clone(),
                                app.effective_network_id(),
                            );
                            app = reload.app;
                            network_id = reload.network_id;
                            expected_peers = reload.expected_peers;
                            own_pubkey = reload.own_pubkey;
                            fips_join_request_sends.clear();
                            if let Err(error) = refresh_fips_tunnel_config(
                                runtime,
                                &app,
                                &config_path,
                                &network_id,
                                network_snapshot.default_interface.as_deref(),
                                network_snapshot.default_interface_mtu,
                                own_pubkey.as_deref(),
                            )
                            .await
                            {
                                vpn_status =
                                    format!("Roster applied, but FIPS reload failed ({error})");
                            }
                            refresh_or_start_split_magic_dns(&mut magic_dns_runtime, &app);
                        }
                        if !drained.endpoint_hint_participants.is_empty()
                            && let Err(error) =
                                refresh_fips_tunnel_runtime_peer_paths_in_place(
                                    runtime,
                                    FipsRestartContext {
                                        app: &app,
                                        config_path: &config_path,
                                        network_id: &network_id,
                                        fallback_iface: &iface,
                                        underlay_interface: network_snapshot
                                            .default_interface
                                            .as_deref(),
                                        underlay_interface_mtu: network_snapshot
                                            .default_interface_mtu,
                                        own_pubkey: own_pubkey.as_deref(),
                                        recent_peers: Some(&recent_peers),
                                        ethernet_underlay: ethernet_underlay.as_ref(),
                                        client_dataplane_enabled: vpn_enabled,
                                        last_endpoint_peer_signature:
                                            &mut last_fips_endpoint_peer_signature,
                                    },
                                    &drained.endpoint_hint_participants,
                                    "fresh endpoint capability",
                                )
                                .await
                        {
                            vpn_status =
                                format!("FIPS endpoint hint refresh failed ({error})");
                        }
                        #[cfg(feature = "paid-exit")]
                        {
                            paid_exit_payment_outbox_changed |= handle_paid_exit_mesh_events(
                                PaidExitMeshEventContext {
                                    runtime,
                                    app: &app,
                                    config_path: &config_path,
                                    network_id: &network_id,
                                    underlay_interface: network_snapshot
                                        .default_interface
                                        .as_deref(),
                                    underlay_interface_mtu: network_snapshot.default_interface_mtu,
                                    own_pubkey: own_pubkey.as_deref(),
                                    vpn_status: &mut vpn_status,
                                    spilman_receiver: paid_exit_spilman_receiver.as_ref(),
                                    spilman_receiver_error: paid_exit_spilman_receiver_error
                                        .as_deref(),
                                },
                                &mut drained,
                            )
                            .await;
                        }
                    }
                    Err(error) => {
                        vpn_status = format!("FIPS event handling failed ({error})");
                    }
                }
                if let Err(error) = runtime.refresh_peer_dependent_routes().await {
                    vpn_status = format!("FIPS route refresh failed ({error})");
                }
                #[cfg(feature = "paid-exit")]
                {
                    let observed_at = Instant::now();
                    let active_millis_delta = u64::try_from(
                        observed_at
                            .saturating_duration_since(last_paid_exit_usage_flush_at)
                            .as_millis(),
                    )
                    .unwrap_or(u64::MAX);
                    last_paid_exit_usage_flush_at = observed_at;
                    match flush_fips_paid_route_usage(
                        runtime,
                        &app,
                        &config_path,
                        unix_timestamp(),
                        active_millis_delta,
                    ) {
                        Ok(flush) => {
                            if flush.seller_admission_changed
                                && let Err(error) = refresh_fips_tunnel_config(
                                    runtime,
                                    &app,
                                    &config_path,
                                    &network_id,
                                    network_snapshot.default_interface.as_deref(),
                                    network_snapshot.default_interface_mtu,
                                    own_pubkey.as_deref(),
                                )
                                .await
                            {
                                vpn_status =
                                    format!("paid-exit admission refresh failed ({error})");
                            }
                            match update_automatic_paid_exit(
                                &mut automatic_paid_exit,
                                runtime,
                                &mut app,
                                &config_path,
                                &flush.buyer_delta,
                                unix_timestamp(),
                            )
                            .await
                            {
                                Ok(changed) => automatic_paid_exit_route_changed |= changed,
                                Err(error) => eprintln!(
                                    "paid-exit: automatic buyer update failed: {error}"
                                ),
                            }
                            match update_manual_paid_exit(
                                &mut manual_paid_exit,
                                runtime,
                                &mut app,
                                &config_path,
                                unix_timestamp(),
                            )
                            .await
                            {
                                Ok(changed) => manual_paid_exit_route_changed |= changed,
                                Err(error) => eprintln!(
                                    "paid-exit: manual buyer health update failed: {error}"
                                ),
                            }
                        }
                        Err(error) => {
                            eprintln!("paid-exit: failed to record FIPS usage: {error}");
                        }
                    }
                    if app.public_paid_exit_node_pubkey_hex().is_some()
                        && automatic_paid_exit.payments_allowed(&app, unix_timestamp())
                    {
                            match paid_exit_stream_due_payments_for_daemon(
                                &app,
                                &config_path,
                                PAID_EXIT_DAEMON_STREAM_PAYMENT_MIN_INCREMENT_MSAT,
                                PAID_EXIT_DAEMON_STREAM_PAYMENT_LIMIT,
                            ) {
                                Ok(result)
                                    if result.signed_count > 0 || result.error_count > 0 =>
                                {
                                    eprintln!(
                                        "paid-exit: streamed buyer payments signed={} persisted={} errors={} due={} processed={} changed={}",
                                        result.signed_count,
                                        result.persisted_count,
                                        result.error_count,
                                        result.total_due_count,
                                        result.processed_due_count,
                                        result.changed
                                    );
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    eprintln!(
                                        "paid-exit: failed to stream buyer payment update: {error}"
                                    );
                                }
                            }
                    }
                    let flushed = flush_paid_exit_payment_outbox(runtime, &config_path).await;
                    if flushed.queued > 0 || flushed.errors > 0 {
                        eprintln!(
                            "paid-exit: direct FIPS payment outbox queued={} errors={}",
                            flushed.queued, flushed.errors
                        );
                    }
                }
            }
                #[cfg(feature = "paid-exit")]
                {
                    let paid_exit_route_changed = automatic_paid_exit_route_changed
                        || manual_paid_exit_route_changed;
                    if paid_exit_route_changed || paid_exit_payment_outbox_changed {
                        match sync_fips_private_runtime(
                        &mut fips_tunnel_runtime,
                        SyncFipsPrivateRuntimeContext {
                            app: &app,
                            config_path: &config_path,
                            network_id: &network_id,
                            iface: &iface,
                            underlay_interface: network_snapshot.default_interface.as_deref(),
                            underlay_interface_mtu: network_snapshot.default_interface_mtu,
                            own_pubkey: own_pubkey.as_deref(),
                            recent_peers: Some(&recent_peers),
                            ethernet_underlay: ethernet_underlay.as_ref(),
                            vpn_enabled,
                            expected_peers,
                        },
                    )
                    .await
                        {
                            Ok(()) => {
                                // The FIPS reconciliation owns secure exit DNS teardown.
                                // Start split MagicDNS only after that port has been released.
                                if paid_exit_route_changed {
                                    refresh_or_start_split_magic_dns(
                                        &mut magic_dns_runtime,
                                        &app,
                                    );
                                }
                            }
                            Err(error) => {
                                vpn_status =
                                    format!("paid-exit runtime reconciliation failed ({error})");
                            }
                        }
                    }
                }
            }
            if let Some(request) = pending_control_request {
                let publish_fips_roster_after_control =
                    matches!(request, DaemonControlRequest::Reload | DaemonControlRequest::Resume);
                let mut control_result = match request {
                    DaemonControlRequest::Stop => break,
                    DaemonControlRequest::Pause => {
                        vpn_enabled = false;
                        let persist_result =
                            persist_desired_daemon_vpn_enabled_in_config(
                                &mut app,
                                &config_path,
                                vpn_enabled,
                            );
                        let join_requests_active = app.join_requests_enabled();
                        port_mapping_runtime.stop().await;
                        vpn_status = daemon_vpn_idle_status(
                            vpn_enabled,
                            expected_peers,
                            join_requests_active,
                        )
                        .to_string();
                        persist_result.map(|_| ())
                    }
                    DaemonControlRequest::Resume => {
                        vpn_enabled = true;
                        let persist_result =
                            persist_desired_daemon_vpn_enabled_in_config(
                                &mut app,
                                &config_path,
                                vpn_enabled,
                            );
                        if daemon_vpn_active(vpn_enabled, expected_peers)
                            && let Some(runtime_listen_port) = tunnel_runtime.active_listen_port
                        {
                            refresh_port_mapping(
                                &app,
                                &network_snapshot,
                                runtime_listen_port,
                                &mut port_mapping_runtime,
                            )
                            .await;
                            vpn_status = "VPN on".to_string();
                        } else {
                            port_mapping_runtime.stop().await;
                            vpn_status = daemon_vpn_idle_status(
                                vpn_enabled,
                                expected_peers,
                                app.join_requests_enabled(),
                            )
                            .to_string();
                        }
                        persist_result.map(|_| ())
                    }
                    DaemonControlRequest::Reload => {
                        match update_daemon_config_from_staged_request(&config_path) {
                            Ok(staged_config_applied) => {
                                match load_config_with_overrides(
                                    &config_path,
                                    network_override.clone(),
                                    participants_override.clone(),
                                    ConfigLoadMode::Persist,
                                ) {
                                    Ok((mut reloaded_app, reloaded_network_id)) => {
                                        reloaded_app.pending_nostr_join_request =
                                            app.pending_nostr_join_request.clone();
                                        if let Err(error) = reloaded_app
                                            .ensure_pending_nostr_join_request(unix_timestamp())
                                        {
                                            let _ = write_daemon_control_result(
                                                &config_path,
                                                request,
                                                Err(error.context(
                                                    "failed to preserve daemon join request",
                                                )),
                                            );
                                            continue;
                                        }
                                        let reload = build_daemon_reload_config(
                                            reloaded_app,
                                            reloaded_network_id,
                                        );
                                        #[cfg(feature = "paid-exit")]
                                        if PaidExitAutomaticBuyer::enabled(&app)
                                            && !PaidExitAutomaticBuyer::enabled(&reload.app)
                                        {
                                            if let Some(runtime) = fips_tunnel_runtime.as_ref()
                                                && let Err(error) = finalize_automatic_paid_exit(
                                                    &automatic_paid_exit,
                                                    runtime,
                                                    &app,
                                                    &config_path,
                                                    unix_timestamp(),
                                                )
                                                .await
                                            {
                                                eprintln!(
                                                    "paid-exit: automatic mode-exit finalization failed: {error}"
                                                );
                                            }
                                            automatic_paid_exit.cancel_if_disabled(&reload.app);
                                        }
                                        app = reload.app;
                                        #[cfg(feature = "paid-exit")]
                                        {
                                            paid_exit_offer_refresh_interval.reset_immediately();
                                            (
                                                paid_exit_spilman_receiver,
                                                paid_exit_spilman_receiver_error,
                                            ) = try_load_paid_exit_spilman_receiver(
                                                &config_path,
                                                &app.paid_exit,
                                            )
                                            .await;
                                        }
                                        network_id = reload.network_id;
                                        expected_peers = reload.expected_peers;
                                        own_pubkey = reload.own_pubkey;
                                        if secure_exit_dns_required(&app) {
                                            magic_dns_runtime.take();
                                        }
                                        if let Some(rt) = magic_dns_runtime.as_ref() {
                                            rt.refresh_records(&app);
                                        }
                                        let join_requests_active = app.join_requests_enabled();
                                        let vpn_active =
                                            daemon_vpn_active(vpn_enabled, expected_peers);
                                        vpn_status = if vpn_active {
                                            "Config reloaded".to_string()
                                        } else if vpn_enabled {
                                            daemon_vpn_idle_status(
                                                vpn_enabled,
                                                expected_peers,
                                                join_requests_active,
                                            )
                                            .to_string()
                                        } else {
                                            "Config reloaded (paused)".to_string()
                                        };
                                        if vpn_active
                                            && let Some(runtime_listen_port) =
                                                tunnel_runtime.active_listen_port
                                        {
                                            refresh_port_mapping(
                                                &app,
                                                &network_snapshot,
                                                runtime_listen_port,
                                                &mut port_mapping_runtime,
                                            )
                                            .await;
                                        }
                                        Ok(())
                                    }
                                    Err(error) => {
                                        vpn_status = if staged_config_applied {
                                            format!("Config apply failed (reload: {error})")
                                        } else {
                                            format!("Config reload failed ({error})")
                                        };
                                        Err(error)
                                    }
                                }
                            }
                            Err(error) => {
                                vpn_status = format!("Config apply failed ({error})");
                                Err(error)
                            }
                        }
                    }
                };
                let pre_sync_fips_roster_recipients = if publish_fips_roster_after_control {
                    fips_tunnel_runtime
                        .as_ref()
                        .map(|runtime| runtime.peer_pubkeys())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                if publish_fips_roster_after_control
                    && let Some(runtime) = fips_tunnel_runtime.as_ref()
                    && let Err(error) = publish_fips_active_network_roster_to(
                        runtime,
                        &app,
                        &config_path,
                        &pre_sync_fips_roster_recipients,
                        &mut pending_fips_roster_recipients,
                    )
                {
                    eprintln!(
                        "fips: roster publish failed before peer-set refresh: {error}"
                    );
                }
                // The approval outbox and authoritative roster are durable before
                // Reload reaches the daemon. Start the receipt-backed delivery on
                // the existing FIPS runtime now: the recipient's npub is enough to
                // route it, and waiting for the full peer-set sync consumed most of
                // the mobile coordination deadline on Windows. The post-sync call
                // below remains as an idempotent retry for runtimes created by sync.
                if publish_fips_roster_after_control
                    && let Some(runtime) = fips_tunnel_runtime.as_ref()
                {
                    start_queued_join_roster_deliveries(runtime, &config_path);
                }
                let fips_sync_succeeded = match sync_fips_private_runtime(
                    &mut fips_tunnel_runtime,
                    SyncFipsPrivateRuntimeContext {
                        app: &app,
                        config_path: &config_path,
                        network_id: &network_id,
                        iface: &iface,
                        underlay_interface: network_snapshot.default_interface.as_deref(),
                        underlay_interface_mtu: network_snapshot.default_interface_mtu,
                        own_pubkey: own_pubkey.as_deref(),
                        recent_peers: Some(&recent_peers),
                        ethernet_underlay: ethernet_underlay.as_ref(),
                        vpn_enabled,
                        expected_peers,
                    },
                )
                .await
                {
                    Ok(()) => true,
                    Err(error) => {
                        vpn_status = format!("FIPS private mesh update failed ({error})");
                        if control_result.is_ok() {
                            control_result =
                                Err(error.context("apply FIPS tunnel, routes, and DNS"));
                        }
                        false
                    }
                };
                refresh_or_start_split_magic_dns(&mut magic_dns_runtime, &app);
                if publish_fips_roster_after_control
                    && let Some(runtime) = fips_tunnel_runtime.as_ref()
                {
                    publish_fips_control_updates(
                        runtime,
                        &app,
                        &config_path,
                        &mut pending_fips_roster_recipients,
                        fips_sync_succeeded,
                    )
                    .await;
                }
                let state_persisted =
                    persist_current_daemon_state(DaemonStatePersistContext {
                    state_file: &state_file,
                    config_path: &config_path,
                    app: &app,
                    vpn_enabled,
                    expected_peers,
                    tunnel_runtime: &tunnel_runtime,
                    fips_tunnel_runtime: &fips_tunnel_runtime,
                    endpoint_peer_signature: &last_fips_endpoint_peer_signature,
                    vpn_status: &vpn_status,
                    network_snapshot: &network_snapshot,
                    network_changed_at,
                    captive_portal,
                    port_mapping_runtime: &port_mapping_runtime,
                })
                .await;
                if state_persisted {
                    last_state_persisted_at = Instant::now();
                } else if control_result.is_ok() {
                    control_result = Err(anyhow!(
                        "failed to persist daemon state after applying control request"
                    ));
                }
                let _ = write_daemon_control_result(&config_path, request, control_result);
            }
            if !state_background_ready {
                continue;
            }
            #[cfg(feature = "paid-exit")]
            log_paid_exit_offer_publication(paid_exit_offer_publisher.reconcile(
                &app,
                &config_path,
                unix_timestamp(),
                fips_tunnel_runtime.as_ref().is_some_and(
                    crate::fips_private_mesh::FipsPrivateTunnelRuntime::paid_exit_seller_ready,
                ),
                false,
            ));
            let supervised_service = supervised_service_executable.as_ref();
            if daemon_service_supervisor_requests_restart(supervised_service) {
                break;
            }
            if vpn_status == "Connected (network refresh)"
                && daemon_vpn_active(vpn_enabled, expected_peers)
            {
                vpn_status = "VPN on".to_string();
            }
            if last_state_persisted_at.elapsed() >= daemon_state_persist_interval
                && persist_current_daemon_state(DaemonStatePersistContext {
                    state_file: &state_file,
                    config_path: &config_path,
                    app: &app,
                    vpn_enabled,
                    expected_peers,
                    tunnel_runtime: &tunnel_runtime,
                    fips_tunnel_runtime: &fips_tunnel_runtime,
                    endpoint_peer_signature: &last_fips_endpoint_peer_signature,
                    vpn_status: &vpn_status,
                    network_snapshot: &network_snapshot,
                    network_changed_at,
                    captive_portal,
                    port_mapping_runtime: &port_mapping_runtime,
                })
                .await
            {
                last_state_persisted_at = Instant::now();
            }
        }
    }
}
