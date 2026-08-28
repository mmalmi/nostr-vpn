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
                    drop(start_queued_join_roster_deliveries(runtime, &config_path));
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
            handle_daemon_state_tick!(background_ready);
        }
    }
}
