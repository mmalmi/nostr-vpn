#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MobileNetworkChangeOutcome {
    pub(crate) rebound_transports: usize,
    pub(crate) refreshed_peers: usize,
    pub(crate) wireguard_handshake_initiated: bool,
}

impl MobileTunnel {
    pub(crate) fn start(config_json: &str) -> Result<Self> {
        const MOBILE_TUNNEL_WORKER_STACK_SIZE: usize = 4 * 1024 * 1024;

        mobile_debug_log("MobileTunnel::start parse begin");
        let launch: MobileTunnelLaunchConfig =
            serde_json::from_str(config_json).context("invalid mobile tunnel config JSON")?;
        let config = launch.tunnel;
        mobile_debug_log(format!(
            "MobileTunnel::start parsed peers={} routes={} nostr_relays={} share_lan={} listen={}",
            config.peers.len(),
            config.route_targets.len(),
            config.nostr_relays.len(),
            config.share_local_candidates,
            config.listen_port
        ));
        if !config.error.trim().is_empty() {
            return Err(anyhow!(config.error));
        }
        let app_config = mobile_app_config(&config)?;
        let config = if config.app_config_toml.trim().is_empty() {
            let config_path = non_empty_path(&config.config_path)
                .ok_or_else(|| anyhow!("mobile tunnel config path unavailable"))?;
            MobileTunnelConfig::from_app_with_config_path(&app_config, &config_path)?
        } else {
            config
        };
        mobile_debug_log("MobileTunnel::start building tokio runtime");
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("nvpn-mobile-fips")
            .thread_stack_size(MOBILE_TUNNEL_WORKER_STACK_SIZE)
            .build()
            .context("failed to start mobile FIPS runtime")?;
        mobile_debug_log("MobileTunnel::start entering start_async");
        let started = runtime.block_on(async move {
            tokio::spawn(Self::start_async_with_launch_state(
                config,
                app_config,
                launch.queued_join_rosters,
                launch.signed_roster,
                non_empty_path(&launch.private_state_config_path),
            ))
                .await
                .context("mobile FIPS startup task failed")?
        })?;
        mobile_debug_log("MobileTunnel::start start_async returned");
        Ok(Self {
            runtime,
            endpoint: Some(started.endpoint),
            state_control: started.state_control,
            mesh: started.mesh,
            presence: started.presence,
            config: started.config,
            app_config: started.app_config,
            app_config_dirty: started.app_config_dirty,
            pending_join_roster_receipts: started.pending_join_roster_receipts,
            tun_counters: started.tun_counters,
            secure_dns: started.secure_dns,
            #[cfg(any(target_os = "android", target_os = "ios"))]
            outbound_tx: started.outbound_tx,
            inbound_rx: Some(started.inbound_rx),
            tasks: started.tasks,
            runtime_state_path: started.runtime_state_path,
            wg_upstream: started.wg_upstream,
            #[cfg(target_os = "android")]
            native_tun: None,
            #[cfg(target_os = "ios")]
            ios_packet_flow: None,
            #[cfg(target_os = "android")]
            wg_upstream_socket_fd: started.wg_upstream_socket_fd,
        })
    }

    #[cfg(test)]
    #[allow(clippy::large_futures, clippy::too_many_lines)]
    async fn start_async(
        config: MobileTunnelConfig,
        app_config: AppConfig,
    ) -> Result<MobileTunnelStarted> {
        Self::start_async_with_launch_state(config, app_config, Vec::new(), None, None).await
    }

    #[allow(clippy::large_futures, clippy::too_many_lines)]
    async fn start_async_with_launch_state(
        config: MobileTunnelConfig,
        app_config: AppConfig,
        queued_join_rosters: Vec<QueuedJoinRoster>,
        launch_signed_roster: Option<SignedRoster>,
        private_state_config_path: Option<PathBuf>,
    ) -> Result<MobileTunnelStarted> {
        mobile_debug_log("MobileTunnel::start_async begin");
        let scope = mobile_lan_discovery_scope(&config.network_id);
        let initial_peers = config.peers.clone();
        let config_path = non_empty_path(&config.config_path);
        let private_state_config_path =
            private_state_config_path.or_else(|| config_path.clone());
        let runtime_state_path = private_state_config_path
            .as_deref()
            .and_then(mobile_runtime_state_path);
        let local_capability_hints = mobile_endpoint_hints(&config);
        mobile_debug_log(format!(
            "MobileTunnel::start_async binding FIPS endpoint scope={} peers={} hints={}",
            scope,
            initial_peers.len(),
            local_capability_hints.len()
        ));
        let endpoint = FipsEndpoint::builder()
            .config(fips_endpoint_config(&scope, &config))
            .identity_nsec(config.identity_nsec.clone())
            .discovery_scope(scope)
            .without_system_tun()
            .bind()
            .await
            .context("failed to bind mobile FIPS endpoint")?;
        mobile_debug_log("MobileTunnel::start_async FIPS endpoint bound");
        let endpoint = Arc::new(endpoint);
        let mut state_control = FipsControlTcpRuntime::start(Arc::clone(&endpoint))
            .await
            .context("failed to start mobile FIPS-TCP state-control service")?;
        let state_control_sender = state_control.sender();
        let local_routes = vec![config.local_address.clone()];
        let mesh = new_mobile_mesh(FipsMeshRuntime::with_local_routes(
            initial_peers.clone(),
            local_routes,
        ));
        let peer_identities = Arc::new(RwLock::new(mobile_peer_identity_map(
            &initial_peers,
            &config.bootstrap_peers,
        )));
        let mesh_peers = Arc::new(RwLock::new(initial_peers));
        let peer_hints = Arc::new(RwLock::new(config.peer_hints.clone()));
        let presence = Arc::new(RwLock::new(HashMap::new()));
        let config_state = Arc::new(RwLock::new(config.clone()));
        let app_config = Arc::new(RwLock::new(app_config));
        let app_config_dirty = Arc::new(AtomicBool::new(false));
        let pending_join_roster_receipts = Arc::new(PendingJoinRosterReceiptQueue::load(
            private_state_config_path
                .as_deref()
                .map(pending_join_roster_receipts_path),
        )?);
        let tun_counters = Arc::new(MobileTunAtomicCounters::default());
        let (outbound_tx, mut outbound_rx) =
            tokio_mpsc::channel::<Vec<Vec<u8>>>(MOBILE_TUN_OUTBOUND_BATCH_CHANNEL_CAPACITY);
        #[cfg(not(any(test, target_os = "android", target_os = "ios")))]
        let _outbound_tx = outbound_tx;
        let (inbound_tx, inbound_rx) =
            tokio_mpsc::channel::<Vec<Vec<u8>>>(MOBILE_TUN_INBOUND_BATCH_CHANNEL_CAPACITY);

        // If the user has WG upstream enabled, stand up the boringtun
        // pump alongside the FIPS endpoint. The WG runtime is fed via
        // an mpsc::channel pair: `wg_send_tx` carries plaintext that
        // should be encapsulated and sent to the upstream;
        // `wg_recv_rx` carries plaintext we got back after
        // decapsulating the upstream's reply, ready to write back to
        // the OS tun.
        let mesh_ipv4 = parse_ipv4(&config.local_address);
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        #[cfg(feature = "paid-exit")]
        if let Some(store_path) = private_state_config_path
            .as_deref()
            .map(nostr_vpn_core::paid_route_store::paid_route_store_file_path)
        {
            let provider = app_config
                .read()
                .map_err(|_| anyhow!("mobile app config lock poisoned"))?
                .manual_paid_exit_provider
                .clone();
            if !provider.is_default() {
                let endpoint = Arc::clone(&endpoint);
                tasks.push(tokio::spawn(async move {
                    if let Err(error) =
                        import_mobile_manual_paid_exit_offer(endpoint, provider, store_path).await
                    {
                        tracing::warn!(?error, "mobile: manual paid exit offer import stopped");
                    }
                }));
            }
        }

        let mut wg_runtime: Option<WgUpstreamRuntime> = None;
        let mut wg_send_tx: Option<tokio_mpsc::Sender<Vec<Vec<u8>>>> = None;
        #[cfg(target_os = "android")]
        let mut wg_socket_fd: c_int = -1;
        let mut wg_address_ipv4: Option<Ipv4Addr> = None;
        {
            let state_control = state_control_sender.clone();
            let pending = Arc::clone(&pending_join_roster_receipts);
            tasks.push(tokio::spawn(async move {
                run_pending_join_roster_receipt_delivery(state_control, pending).await;
            }));
        }
        let exit_dns_resolver_config = mobile_exit_dns_resolver_config(&config)?;
        let exit_dns_nat = parse_ipv4(&config.magic_dns_server)
            .and_then(|local_dns_server| {
                active_mobile_exit_dns_servers(&config)
                    .map(|servers| MobileExitDnsNat::new(local_dns_server, servers))
                    .transpose()
            })
            .transpose()?
            .map(Arc::new);
        if let Some(wg_config) = config.wireguard_exit.as_ref() {
            wg_address_ipv4 = parse_ipv4(&wg_config.address);
            let (send_tx, send_rx) =
                tokio_mpsc::channel::<Vec<Vec<u8>>>(MOBILE_TUN_OUTBOUND_BATCH_CHANNEL_CAPACITY);
            let (recv_tx, mut recv_rx) =
                tokio_mpsc::channel::<Vec<Vec<u8>>>(MOBILE_TUN_INBOUND_BATCH_CHANNEL_CAPACITY);
            let runtime = WgUpstreamRuntime::start_with_channels(wg_config, send_rx, recv_tx)
                .await
                .context("failed to start mobile WG runtime")?;
            #[cfg(target_os = "android")]
            {
                wg_socket_fd = runtime.udp_socket_fd();
            }
            let upstream = runtime.upstream();
            let handshake = runtime.handshake_observer();
            wg_runtime = Some(runtime);
            wg_send_tx = Some(send_tx);
            // Forward decrypted WG packets back to the OS as
            // inbound traffic. DNAT: rewrite the WG-side
            // destination IP back to the mesh tun address so
            // the OS routes the reply to the local app stack.
            let inbound_tx_for_wg = inbound_tx.clone();
            let wg_addr = wg_address_ipv4;
            let mesh_addr = mesh_ipv4;
            let inbound_exit_dns_nat = exit_dns_nat.clone();
            tasks.push(tokio::spawn(async move {
                let mut packets = Vec::with_capacity(MOBILE_FIPS_RECV_BATCH);
                while let Some(batch) = recv_rx.recv().await {
                    if !push_mobile_wg_inbound_batch(
                        batch,
                        &mut packets,
                        &inbound_tx_for_wg,
                        wg_addr,
                        mesh_addr,
                        inbound_exit_dns_nat.as_deref(),
                    )
                    .await
                    {
                        return;
                    }
                    for _ in 1..MOBILE_TUN_INBOUND_BATCH_CHANNEL_CAPACITY {
                        let Ok(batch) = recv_rx.try_recv() else {
                            break;
                        };
                        if !push_mobile_wg_inbound_batch(
                            batch,
                            &mut packets,
                            &inbound_tx_for_wg,
                            wg_addr,
                            mesh_addr,
                            inbound_exit_dns_nat.as_deref(),
                        )
                        .await
                        {
                            return;
                        }
                    }

                    if !packets.is_empty()
                        && !flush_mobile_inbound_packets(&inbound_tx_for_wg, &mut packets).await
                    {
                        break;
                    }
                }
            }));
            // Watchdog: log if the handshake doesn't complete
            // promptly, but do not block mobile tunnel startup.
            // Android must receive the native handle first so it can
            // call VpnService.protect(fd) on the WG UDP socket before
            // the default VPN route traps retry traffic.
            let timeout = DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT;
            tasks.push(tokio::spawn(async move {
                if handshake.wait_for_handshake(timeout).await {
                    tracing::info!(?upstream, "wg-upstream: mobile tunnel handshake completed");
                } else {
                    tracing::warn!(
                        ?upstream,
                        "wg-upstream: no handshake within {timeout:?} on mobile tunnel; \
                         traffic will queue until upstream becomes reachable"
                    );
                }
            }));
        }

        let magic_dns_server = parse_ipv4(&config.magic_dns_server);
        let secure_dns = (magic_dns_server.is_some() && exit_dns_nat.is_none())
            .then(|| SecureDnsResolver::from_resolver_config(&exit_dns_resolver_config))
            .transpose()
            .context("failed to initialize mobile secure DNS")?;
        let secure_dns_dispatch = secure_dns
            .as_ref()
            .map(|resolver| MobileSecureDnsDispatch::new(resolver.clone()));
        let send_task = {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let peer_identities = Arc::clone(&peer_identities);
            let wg_send_tx_for_dispatch = wg_send_tx.clone();
            let wg_addr = wg_address_ipv4;
            let mesh_addr = mesh_ipv4;
            let inbound_tx_for_dns = inbound_tx.clone();
            let app_config_for_dns = Arc::clone(&app_config);
            let outbound_exit_dns_nat = exit_dns_nat.clone();
            let mut secure_dns_dispatch = secure_dns_dispatch;
            tokio::spawn(async move {
                while let Some(packets) = outbound_rx.recv().await {
                    if !dispatch_mobile_outbound_packets(
                        &endpoint,
                        &mesh,
                        &peer_identities,
                        wg_send_tx_for_dispatch.as_ref(),
                        wg_addr,
                        mesh_addr,
                        &inbound_tx_for_dns,
                        &app_config_for_dns,
                        &mut secure_dns_dispatch,
                        magic_dns_server,
                        outbound_exit_dns_nat.as_deref(),
                        packets,
                    )
                    .await
                    {
                        break;
                    }
                }
            })
        };
        tasks.push(send_task);

        let join_request_active = Arc::new(AtomicBool::new(false));
        if let Some((recipient_npub, frame)) = pending_mobile_join_request_frame(&config)? {
            let recipient_peer = PeerIdentity::from_npub(&recipient_npub).with_context(|| {
                format!("invalid mobile join request endpoint npub {recipient_npub}")
            })?;
            let state_control = state_control_sender.clone();
            let join_request_active_for_task = Arc::clone(&join_request_active);
            join_request_active.store(true, Ordering::Relaxed);
            tasks.push(tokio::spawn(async move {
                while join_request_active_for_task.load(Ordering::Relaxed) {
                    let _ = state_control.send(recipient_peer, &frame).await;
                    tokio::time::sleep(Duration::from_secs(FIPS_JOIN_REQUEST_RETRY_SECS)).await;
                }
            }));
        }

        if !queued_join_rosters.is_empty() || private_state_config_path.is_some() {
            tasks.push(tokio::spawn(watch_mobile_queued_join_rosters(
                state_control_sender.clone(),
                private_state_config_path.clone(),
                queued_join_rosters,
            )));
        }

        if !config.network_id.trim().is_empty() && !local_capability_hints.is_empty() {
            let state_control = state_control_sender.clone();
            let mesh_peers = Arc::clone(&mesh_peers);
            let peer_identities = Arc::clone(&peer_identities);
            let network_id = config.network_id.clone();
            tasks.push(tokio::spawn(async move {
                let mut startup_broadcasts_remaining = MOBILE_CAPABILITIES_STARTUP_BURST_COUNT;
                loop {
                    if let Err(error) = broadcast_mobile_capabilities(
                        &state_control,
                        &mesh_peers,
                        &peer_identities,
                        &network_id,
                        local_capability_hints.clone(),
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to broadcast capabilities");
                    }
                    let sleep_duration = if startup_broadcasts_remaining > 1 {
                        startup_broadcasts_remaining -= 1;
                        Duration::from_millis(MOBILE_CAPABILITIES_STARTUP_BURST_INTERVAL_MS)
                    } else {
                        startup_broadcasts_remaining = 0;
                        Duration::from_secs(MOBILE_CAPABILITIES_BROADCAST_SECS)
                    };
                    tokio::time::sleep(sleep_duration).await;
                }
            }));
        }

        if let Some(status_path) = runtime_state_path.clone() {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let presence = Arc::clone(&presence);
            let status_config = Arc::clone(&config_state);
            let status_tun_counters = Arc::clone(&tun_counters);
            let status_secure_dns = secure_dns.clone();
            let status_wireguard_handshake = wg_runtime
                .as_ref()
                .map(WgUpstreamRuntime::handshake_observer);
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Err(error) = persist_mobile_runtime_state(
                        &status_path,
                        &endpoint,
                        &mesh,
                        &presence,
                        &status_config,
                        &status_tun_counters,
                        MobileRuntimeDiagnostics {
                            secure_dns: status_secure_dns.as_ref(),
                            wireguard_handshake: status_wireguard_handshake.as_ref(),
                        },
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to persist runtime state");
                    }
                    tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                        .await;
                }
            }));
        }

        {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let peer_identities = Arc::clone(&peer_identities);
            let presence = Arc::clone(&presence);
            let ping_config = Arc::clone(&config_state);
            tasks.push(tokio::spawn(async move {
                loop {
                    let (network_id, bootstrap_peers) = ping_config
                        .read()
                        .map(|config| {
                            let network_id = if config.network_id.trim().is_empty() {
                                config.pending_join_network_id.clone()
                            } else {
                                config.network_id.clone()
                            };
                            (network_id, config.bootstrap_peers.clone())
                        })
                        .unwrap_or_default();
                    if network_id.trim().is_empty() {
                        tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                            .await;
                        continue;
                    }
                    if let Err(error) = mobile_ping_peers(
                        &endpoint,
                        &mesh,
                        &peer_identities,
                        &presence,
                        &network_id,
                        &bootstrap_peers,
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to ping FIPS peers");
                    }
                    tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                        .await;
                }
            }));
        }

        if config_path.is_some() || launch_signed_roster.is_some() {
            let state_control = state_control_sender.clone();
            let mesh = Arc::clone(&mesh);
            let peer_identities = Arc::clone(&peer_identities);
            let presence = Arc::clone(&presence);
            let app_config = Arc::clone(&app_config);
            let config_path = config_path.clone();
            tasks.push(tokio::spawn(async move {
                let context = MobileRosterSyncContext {
                    state_control,
                    mesh,
                    peer_identities,
                    presence,
                    app_config,
                    config_path,
                    launch_signed_roster,
                };
                let mut roster_sync = MobileRosterSyncState::default();
                loop {
                    if let Err(error) = sync_mobile_signed_roster_with_connected_peers(
                        &context,
                        &mut roster_sync,
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to sync signed roster");
                    }
                    tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                        .await;
                }
            }));
        }

        let recv_task = {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let mesh_peers = Arc::clone(&mesh_peers);
            let peer_identities = Arc::clone(&peer_identities);
            let peer_hints = Arc::clone(&peer_hints);
            let presence = Arc::clone(&presence);
            let config_state = Arc::clone(&config_state);
            let app_config = Arc::clone(&app_config);
            let app_config_dirty = Arc::clone(&app_config_dirty);
            let pending_join_roster_receipts = Arc::clone(&pending_join_roster_receipts);
            let config_path = config_path.clone();
            let join_request_active = Arc::clone(&join_request_active);
            let state_control_sender = state_control_sender.clone();
            let inbound_exit_dns_nat = exit_dns_nat.clone();
            tokio::spawn(async move {
                let control = MobileEndpointReceiveContext {
                    endpoint: endpoint.as_ref(),
                    mesh: &mesh,
                    mesh_peers: &mesh_peers,
                    peer_identities: &peer_identities,
                    peer_hints: &peer_hints,
                    presence: &presence,
                    config_state: &config_state,
                    app_config: &app_config,
                    app_config_dirty: app_config_dirty.as_ref(),
                    pending_join_roster_receipts: &pending_join_roster_receipts,
                    config_path: config_path.as_deref(),
                    join_request_active: join_request_active.as_ref(),
                    state_control: &state_control_sender,
                };
                let mut messages = Vec::with_capacity(MOBILE_FIPS_RECV_BATCH);
                let mut inbound_packets = Vec::with_capacity(MOBILE_FIPS_RECV_BATCH);
                'recv: loop {
                    tokio::select! {
                        received = state_control.recv() => {
                            let Some(received) = received else { break; };
                            if let Err(error) = handle_mobile_state_control_frame(&control, received).await {
                                tracing::warn!(?error, "mobile: failed to handle FIPS-TCP state control");
                            }
                        }
                        received = endpoint.recv_batch_into(&mut messages, MOBILE_FIPS_RECV_BATCH) => {
                            let Some(_) = received else { break; };
                            inbound_packets.clear();
                            for message in messages.drain(..) {
                                match handle_mobile_endpoint_message(
                                    &control,
                                    &mut inbound_packets,
                                    message,
                                ).await {
                                    Ok(true) => {}
                                    Ok(false) => break 'recv,
                                    Err(error) => {
                                        tracing::warn!(?error, "mobile: failed to handle FIPS datagram");
                                    }
                                }
                            }
                            if let Some(exit_dns_nat) = inbound_exit_dns_nat.as_deref() {
                                for packet in &mut inbound_packets {
                                    exit_dns_nat.rewrite_response(packet);
                                }
                            }
                            if !inbound_packets.is_empty()
                                && !flush_mobile_inbound_packets(&inbound_tx, &mut inbound_packets).await
                            {
                                break 'recv;
                            }
                        }
                    }
                }
            })
        };
        tasks.push(recv_task);

        Ok(MobileTunnelStarted {
            endpoint,
            state_control: state_control_sender,
            mesh,
            presence,
            config: config_state,
            app_config,
            app_config_dirty,
            pending_join_roster_receipts,
            tun_counters,
            secure_dns,
            #[cfg(any(test, target_os = "android", target_os = "ios"))]
            outbound_tx,
            inbound_rx,
            tasks,
            runtime_state_path,
            wg_upstream: wg_runtime,
            #[cfg(target_os = "android")]
            wg_upstream_socket_fd: wg_socket_fd,
        })
    }

    /// Raw fd of the WG upstream UDP socket, or -1 if WG upstream
    /// isn't running. On Android, the host's `VpnService` calls
    /// `protect(fd)` on this so the encrypted UDP escapes the VPN
    /// tun. iOS relies on the resolved upstream route being declared
    /// as an `excludedRoutes` entry at tunnel-establish time instead.
    #[cfg(target_os = "android")]
    pub(crate) fn wg_upstream_socket_fd(&self) -> c_int {
        self.wg_upstream_socket_fd
    }

    #[cfg(target_os = "android")]
    pub(crate) fn attach_tun_fd(&mut self, fd: c_int) -> Result<()> {
        if fd < 0 {
            return Err(anyhow!("invalid native tun fd"));
        }
        if self.native_tun.is_some() {
            reject_unattached_mobile_tun_fd(fd);
            return Err(anyhow!("native tun fd already attached"));
        }
        let Some(inbound_rx) = self.inbound_rx.take() else {
            reject_unattached_mobile_tun_fd(fd);
            return Err(anyhow!("mobile tunnel inbound packet receiver stopped"));
        };
        let mtu = match self.config.read() {
            Ok(config) => config.mtu,
            Err(_) => {
                self.inbound_rx = Some(inbound_rx);
                reject_unattached_mobile_tun_fd(fd);
                return Err(anyhow!("mobile FIPS config lock poisoned"));
            }
        };
        self.native_tun = Some(NativeTunRuntime::start(
            fd,
            self.outbound_tx.clone(),
            inbound_rx,
            native_tun_packet_capacity(mtu),
            Arc::clone(&self.tun_counters),
        )?);
        Ok(())
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn attach_packet_flow(&mut self, callbacks: IosPacketFlowCallbacks) -> Result<()> {
        if self.ios_packet_flow.is_some() {
            return Err(anyhow!("iOS packet flow already attached"));
        }
        let inbound_rx = self
            .inbound_rx
            .take()
            .ok_or_else(|| anyhow!("mobile tunnel inbound packet receiver stopped"))?;
        self.ios_packet_flow = Some(IosPacketFlowRuntime::start(
            &self.runtime,
            inbound_rx,
            callbacks,
            Arc::clone(&self.tun_counters),
        ));
        Ok(())
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn send_packet_flow_batch(
        &self,
        bytes: &[u8],
        lengths: &[usize],
    ) -> Result<()> {
        send_ios_packet_flow_batch(
            &self.outbound_tx,
            &self.tun_counters,
            bytes,
            lengths,
        )
    }

    pub(crate) fn handle_underlay_network_change(&self) -> Result<MobileNetworkChangeOutcome> {
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| anyhow!("mobile tunnel stopped"))?;
        let peers = self
            .config
            .read()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
            .peers
            .iter()
            .filter_map(|peer| {
                PeerIdentity::from_npub(&normalize_mobile_endpoint_npub(&peer.endpoint_npub)).ok()
            })
            .collect::<Vec<_>>();
        let wg_upstream = self.wg_upstream.as_ref();
        self.runtime.block_on(async move {
            let wireguard_refresh = match wg_upstream {
                Some(runtime) => Some(runtime.force_handshake().await),
                None => None,
            };
            let rebound_transports = endpoint
                .rebind_network_transports(None)
                .await
                .context("mobile FIPS network transport rebind")?;
            let refreshed_peers = endpoint
                .refresh_peer_paths(peers)
                .await
                .context("mobile FIPS peer path refresh after network change")?;
            let wireguard_handshake_initiated = match wireguard_refresh {
                Some(result) => {
                    result.context("mobile WireGuard handshake after network change")?;
                    true
                }
                None => false,
            };
            Ok(MobileNetworkChangeOutcome {
                rebound_transports,
                refreshed_peers,
                wireguard_handshake_initiated,
            })
        })
    }

    #[cfg(target_os = "android")]
    pub(crate) fn handle_wireguard_underlay_ready(&self) -> Result<()> {
        let wg_upstream = self
            .wg_upstream
            .as_ref()
            .ok_or_else(|| anyhow!("mobile WireGuard upstream stopped"))?;
        self.runtime
            .block_on(wg_upstream.force_handshake())
            .context("mobile WireGuard handshake after underlay binding")?;
        Ok(())
    }

    pub(crate) fn wg_upstream_excluded_route(&self) -> Option<String> {
        self.wg_upstream
            .as_ref()
            .and_then(|runtime| wg_upstream_excluded_route_for_addr(runtime.upstream()))
    }

    pub(crate) fn runtime_state_json(&self) -> Result<String> {
        let tun_counters = self.tun_counters.snapshot();
        let secure_dns_counters = self.secure_dns.as_ref().map(SecureDnsResolver::counters);
        let wireguard_exit_ready = self
            .wg_upstream
            .as_ref()
            .is_some_and(|runtime| runtime.handshake_observer().has_completed_handshake());

        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| anyhow!("mobile tunnel stopped"))?;
        let mesh = Arc::clone(&self.mesh);
        let presence = Arc::clone(&self.presence);
        let config = self
            .config
            .read()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
            .clone();
        self.runtime.block_on(async move {
            let endpoint_peers = endpoint
                .peers()
                .await
                .context("mobile FIPS peer snapshot")?;
            let relay_statuses = endpoint
                .relay_statuses()
                .await
                .context("mobile FIPS relay snapshot")?;
            let mut state = {
                let mesh = mobile_mesh_snapshot(&mesh)?;
                let presence = presence
                    .read()
                    .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
                mobile_runtime_state_with_tun_counters(
                    &config,
                    &mesh,
                    &presence,
                    endpoint_peers,
                    relay_statuses,
                    tun_counters,
                    unix_timestamp(),
                )
            };
            if let Some(counters) = secure_dns_counters {
                state.secure_dns_queries = counters.queries;
                state.secure_dns_successes = counters.successes;
                state.secure_dns_failures = counters.failures;
            }
            state.wireguard_exit_ready = wireguard_exit_ready;
            serde_json::to_string(&state).context("serialize mobile runtime state")
        })
    }

    pub(crate) fn take_app_config_toml(&self) -> Result<String> {
        pending_app_config_toml(&self.app_config, &self.config, &self.app_config_dirty)
    }

    pub(crate) fn acknowledge_app_config_toml(&self, expected_toml: &str) -> Result<bool> {
        acknowledge_pending_app_config_toml(
            &self.app_config,
            &self.config,
            &self.app_config_dirty,
            &self.pending_join_roster_receipts,
            expected_toml,
        )
    }

    pub(crate) fn send_join_roster(
        &self,
        recipient: &str,
        join_roster: &JoinRosterControl,
        timeout: Duration,
    ) -> Result<()> {
        let app = self
            .app_config
            .read()
            .map_err(|_| anyhow!("mobile app config lock poisoned"))?
            .clone();
        let destination = mobile_join_roster_destination(&app, recipient)?.with_context(|| {
            format!("missing FIPS endpoint identity for participant {recipient}")
        })?;
        self.runtime.block_on(send_join_roster_with_receipt(
            &self.state_control,
            destination,
            join_roster,
            timeout,
        ))?;
        Ok(())
    }
}

include!("runtime/support.rs");
