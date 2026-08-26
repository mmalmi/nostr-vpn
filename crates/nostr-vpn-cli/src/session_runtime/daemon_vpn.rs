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
