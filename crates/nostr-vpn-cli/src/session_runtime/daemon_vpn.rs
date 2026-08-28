fn paid_exit_offer_refresh_secs() -> u64 {
    #[cfg(feature = "paid-exit")]
    {
        PAID_EXIT_OFFER_REFRESH_SECS
    }
    #[cfg(not(feature = "paid-exit"))]
    {
        86_400
    }
}

pub(crate) async fn daemon_vpn(args: DaemonArgs) -> Result<()> {
    let startup = initialize_daemon_vpn(&args).await?;
    let mut magic_dns_runtime = start_split_magic_dns(&startup.app);
    let (mut announce_interval, mut recent_peer_refresh_interval) = daemon_refresh_intervals(&args);
    let mut intervals = daemon_vpn_intervals();
    #[cfg(feature = "paid-exit")]
    let mut last_paid_exit_usage_flush_at = Instant::now();
    let mut paid_exit_offer_refresh_interval =
        tokio::time::interval(Duration::from_secs(paid_exit_offer_refresh_secs()));
    paid_exit_offer_refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_runtime_heartbeat_at = WallTimeJumpObserver::new(unix_timestamp());
    let mut platform_network_change_rx = spawn_platform_network_change_monitor();
    let mut terminate_wait = daemon_termination_wait()?;
    let loop_state = initialize_daemon_vpn_loop(&args, &startup).await?;
    let DaemonVpnStartup {
        config_path,
        _instance_lock,
        pid_file,
        network_override,
        participants_override,
        mut app,
        mut network_id,
        mut own_pubkey,
        mut expected_peers,
        state_file,
        recent_peers_path,
        mut recent_peers,
        mut fips_join_request_sends,
        mut pending_fips_roster_recipients,
        mut fips_roster_sync_state,
        mut last_fips_stale_participant_restart_at,
        mut fips_pending_roster_restart_state,
        iface,
        ethernet_underlay,
        mut tunnel_runtime,
        mut network_snapshot,
        mut network_changed_at,
        mut captive_portal,
        timeout,
        mut port_mapping_runtime,
        mut vpn_enabled,
        mut fips_tunnel_runtime,
        mut last_fips_endpoint_peer_signature,
    } = startup;
    #[cfg(feature = "paid-exit")]
    let daemon_cashu_wallet_worker =
        crate::cashu_wallet_daemon::DaemonCashuWalletWorker::start(config_path.clone())?;
    #[cfg(feature = "paid-exit")]
    if let Some(signer) = FileSpilmanPaymentSigner::try_load(&paid_exit_wallet_data_dir(&config_path))
        .map_err(|error| anyhow!("{error}"))?
    {
        drop(signer);
    }
    write_daemon_control_ready(&config_path, std::process::id())?;
    let DaemonVpnLoopState {
        mut vpn_status,
        mut last_log_compact_check,
        mut last_state_persisted_at,
        daemon_state_persist_interval,
        platform_network_event_pending: mut network_event_pending,
        platform_network_settle_rechecks_remaining: mut network_settle_rechecks,
        supervised_service_executable,
    } = loop_state;
    let mut last_network_sample_diagnostic = String::new();
    let mut network_refresh_attempt: Option<PlatformNetworkRefreshAttempt> = None;
    let mut network_refresh_terminal_error = None;
    #[cfg(feature = "paid-exit")]
    let (mut paid_exit_spilman_receiver, mut paid_exit_spilman_receiver_error) =
        try_load_paid_exit_spilman_receiver(&config_path, &app.paid_exit).await;
    #[cfg(feature = "paid-exit")]
    let mut automatic_paid_exit = PaidExitAutomaticBuyer::default();
    #[cfg(feature = "paid-exit")]
    let mut manual_paid_exit = PaidExitManualBuyer::default();
    #[cfg(feature = "paid-exit")]
    let mut last_paid_exit_session_open_at =
        Instant::now() - Duration::from_secs(PAID_EXIT_SESSION_OPEN_RETRY_SECS);
    #[cfg(feature = "paid-exit")]
    let mut paid_exit_payment_outbox_retry = PaidExitPaymentOutboxRetry::new(Instant::now());
    #[cfg(feature = "paid-exit")]
    let mut paid_exit_buyer_refunds = PaidExitBuyerRefundRuntime::new()?;
    #[cfg(feature = "paid-exit")]
    let mut paid_exit_offer_publisher =
        PaidExitOfferPublisher::load(&app, &config_path, unix_timestamp());
    let mut last_recent_peer_refresh_signature = None;
    let mut last_recent_peer_cache_persisted_at = 0;
    let (join_request_ipc_tx, mut join_request_ipc_rx) =
        tokio::sync::mpsc::unbounded_channel::<DaemonJoinRequestIpcRequest>();
    #[cfg(unix)]
    let _join_request_ipc =
        crate::join_request_ipc::JoinRequestIpcServer::spawn(&config_path, join_request_ipc_tx)?;
    #[cfg(not(unix))]
    let _join_request_ipc_keepalive = join_request_ipc_tx;
macro_rules! handle_daemon_state_tick {
    ($background_ready:expr) => {{
            #[cfg(feature = "paid-exit")]
            let pending_control_request =
                paid_exit_buyer_refunds.before_tick(&config_path, $background_ready);
            #[cfg(not(feature = "paid-exit"))]
            let pending_control_request = take_daemon_control_request(&config_path);
            let state_background_ready =
                $background_ready && pending_control_request.is_none();
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
                    let outbox_now = Instant::now();
                    if paid_exit_payment_outbox_retry.due(outbox_now) {
                        let flushed = flush_paid_exit_payment_outbox(runtime, &config_path).await;
                        if paid_exit_payment_outbox_retry.record_flush(
                            outbox_now,
                            flushed.queued,
                            flushed.errors,
                        ) {
                            eprintln!(
                                "paid-exit: direct FIPS payment outbox queued={} errors={}",
                                flushed.queued, flushed.errors
                            );
                        }
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
                            Ok(_) => {
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
                let pre_sync_join_roster_deliveries = if publish_fips_roster_after_control {
                    fips_tunnel_runtime.as_ref().map_or_else(Vec::new, |runtime| {
                        start_queued_join_roster_deliveries(runtime, &config_path)
                    })
                } else {
                    Vec::new()
                };
                let (fips_sync_succeeded, fips_runtime_replaced) =
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
                    Ok(runtime_replaced) => (true, runtime_replaced),
                    Err(error) => {
                        vpn_status = format!("FIPS private mesh update failed ({error})");
                        if control_result.is_ok() {
                            control_result =
                                Err(error.context("apply FIPS tunnel, routes, and DNS"));
                        }
                        (false, false)
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
                        pre_sync_join_roster_deliveries,
                        fips_sync_succeeded,
                        fips_runtime_replaced,
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
    }};
}
    include!("daemon_vpn/run_loop.rs");
    #[cfg(feature = "paid-exit")]
    daemon_cashu_wallet_worker.stop();
    let shutdown_result = shutdown_daemon_vpn(DaemonVpnShutdown {
        port_mapping_runtime: &mut port_mapping_runtime,
        fips_tunnel_runtime,
        tunnel_runtime: &mut tunnel_runtime,
        config_path: &config_path,
        state_file: &state_file,
        pid_file: &pid_file,
        expected_peers,
        network_snapshot: &network_snapshot,
        network_changed_at,
        captive_portal,
    })
    .await;
    finish_daemon_vpn_shutdown(network_refresh_terminal_error, shutdown_result)
}
