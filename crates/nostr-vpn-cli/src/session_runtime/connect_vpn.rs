pub(crate) async fn connect_vpn(args: ConnectArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.unwrap_or_else(default_config_path);
    let _instance_lock = acquire_daemon_instance_lock(&config_path)?;
    #[cfg(any(target_os = "macos", test))]
    crate::ensure_macos_connect_privileges(&config_path)?;
    if repair_saved_network_state(&config_path)
        .context("connect refused while saved network cleanup remains incomplete")?
    {
        transition_daemon_state_after_network_repair(&config_path)?;
    }
    let (mut app, mut network_id) = load_config_with_overrides(
        &config_path,
        args.network_id,
        args.devices,
        ConfigLoadMode::Persist,
    )?;
    let configured_participants = app.participant_pubkeys_hex();
    if configured_participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running connect"
        ));
    }
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut expected_peers = expected_peer_count(&app);
    let iface = args.iface.clone();
    let network_snapshot = capture_network_snapshot();
    let mut port_mapping_runtime = PortMappingRuntime::default();
    refresh_port_mapping(
        &app,
        &network_snapshot,
        app.node.listen_port,
        &mut port_mapping_runtime,
    )
    .await;
    let (mut fips_tunnel_runtime, mut last_fips_endpoint_peer_signature) = {
        let config = fips_tunnel_config_from_app(
            FipsTunnelConfigInput {
                app: &app,
                config_path: &config_path,
                network_id: &network_id,
                iface: iface.clone(),
                underlay_interface: network_snapshot.default_interface.as_deref(),
                underlay_interface_mtu: network_snapshot.default_interface_mtu,
                own_pubkey: own_pubkey.as_deref(),
                recent_peers: None,
                live_peer_endpoints: &[],
                ethernet_underlay: None,
            },
        )?;
        let endpoint_peer_signature = endpoint_peer_signature(&config.endpoint_peers);
        let runtime = start_fips_private_tunnel_runtime(&config_path, config).await?;
        println!("connect: FIPS private mesh on {}", runtime.iface());
        (Some(runtime), endpoint_peer_signature)
    };
    let mut magic_dns_runtime = start_split_magic_dns(&app);

    println!(
        "connect: network {network_id} using FIPS private mesh; waiting for {expected_peers} configured peer(s)"
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.mesh_refresh_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_fips_roster_recipients: HashSet<String> = HashSet::new();
    let mut fips_roster_sync_state = FipsRosterSyncState::default();
    let mut connect_status = String::new();

    let mut last_mesh_count = 0_usize;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tunnel_heartbeat_interval.tick() => {
                if let Some(runtime) = fips_tunnel_runtime.as_mut() {
                    let now = unix_timestamp();
                    let pending_manual_join = app
                        .active_network_opt()
                        .is_some_and(|network| network.local_identity_confirmation_pending);
                    let ping_result = if pending_manual_join {
                        runtime.ping_pending_join_peers(&network_id, now).await
                    } else {
                        runtime.ping_peers(&network_id, now).await
                    };
                    if let Err(error) = ping_result {
                        eprintln!("fips: peer ping failed: {error}");
                    }
                    if let Err(error) = runtime.refresh_link_statuses().await {
                        eprintln!("fips: peer link snapshot failed: {error}");
                    }
                    if let Err(error) = sync_fips_roster_with_connected_peers(
                        runtime,
                        &app,
                        &config_path,
                        &mut fips_roster_sync_state,
                    )
                    {
                        eprintln!("fips: roster peer sync failed: {error}");
                    }
                    flush_pending_fips_roster_recipients(
                        runtime,
                        &app,
                        &config_path,
                        &mut pending_fips_roster_recipients,
                    );
                    match drain_fips_mesh_events(
                        runtime,
                        &mut app,
                        &config_path,
                        &mut connect_status,
                    )
                    .await
                    {
                        Ok(drained) => {
                            let roster_changed = drained.roster_changed;
                            network_id = app.effective_network_id();
                            expected_peers = expected_peer_count(&app);
                            if roster_changed {
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
                                    eprintln!("connect: roster applied, but FIPS reload failed: {error}");
                                } else if let Err(error) =
                                    broadcast_local_fips_capabilities(runtime, &app).await
                                {
                                    eprintln!(
                                        "fips: capabilities broadcast failed after roster apply: {error}"
                                    );
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
                                            recent_peers: None,
                                            ethernet_underlay: None,
                                            client_dataplane_enabled: true,
                                            last_endpoint_peer_signature:
                                                &mut last_fips_endpoint_peer_signature,
                                        },
                                        &drained.endpoint_hint_participants,
                                        "fresh endpoint capability",
                                    )
                                    .await
                            {
                                eprintln!(
                                    "connect: FIPS endpoint hint refresh failed: {error}"
                                );
                            }
                        }
                        Err(error) => eprintln!("connect: FIPS event handling failed: {error}"),
                    }
                    if let Err(error) = runtime.refresh_peer_dependent_routes().await {
                        eprintln!("fips: peer route refresh failed: {error}");
                    }
                    maybe_log_fips_mesh_count(
                        &app,
                        own_pubkey.as_deref(),
                        &runtime.peer_statuses(),
                        expected_peers,
                        &mut last_mesh_count,
                    );
                }
            }
            _ = announce_interval.tick() => {
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
        }
    }

    port_mapping_runtime.stop().await;
    if let Some(runtime) = fips_tunnel_runtime {
        stop_fips_private_tunnel_runtime(&config_path, runtime).await?;
    }
    println!("connect: disconnected");

    Ok(())
}
