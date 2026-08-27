#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FipsPrivateTunnelRuntime {
    #[cfg(feature = "paid-exit")]
    pub(crate) fn paid_exit_dns_health_probe(
        &self,
    ) -> Result<crate::secure_dns_runtime::SecureDnsHealthProbe> {
        self.secure_dns
            .as_ref()
            .ok_or_else(|| anyhow!("secure DNS is unavailable for paid exit health"))?
            .health_probe()
    }

    fn persist_network_cleanup_ownership(&self) -> Result<()> {
        crate::daemon_runtime::persist_fips_daemon_network_cleanup_state(
            &self.cleanup_journal_config_path,
            Some(self),
        )
        .context("persist network cleanup ownership before mutation")
    }

    pub(crate) async fn start(
        config: FipsPrivateTunnelConfig,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if pending_linux_network_cleanup_state().is_some() {
            return Err(anyhow!(
                "refusing to start FIPS while prior Linux network cleanup remains pending"
            ));
        }
        let mesh = bind_fips_private_mesh(&config).await?;
        let active_listen_port = mesh
            .confirmed_udp_listen_port(
                config.listen_port,
                required_public_udp_listener_ipv6(&config),
            )
            .await?;
        Self::start_with_mesh(
            config,
            mesh,
            active_listen_port,
            cleanup_journal_config_path,
        )
        .await
    }

    async fn start_with_mesh(
        config: FipsPrivateTunnelConfig,
        mesh: Arc<FipsPrivateMeshRuntime>,
        active_listen_port: Option<u16>,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Self> {
        crate::pipeline_profile::maybe_spawn_reporter();
        #[cfg(target_os = "linux")]
        ensure_linux_tun_permissions(&config.iface)?;
        #[cfg(feature = "paid-exit")]
        mesh.set_paid_route_accounting_peers(config.paid_route_accounting_peers.clone())?;
        let control_pubsub = crate::control_pubsub_runtime::ControlPubsubFipsRuntime::start_for_peers(
            Arc::clone(mesh.endpoint()),
            config.nostr_pubsub.clone(),
            config.nostr_relays.clone(),
            Some(config.control_pubsub_store_path.clone()),
            &config
                .peers
                .iter()
                .map(|peer| peer.participant_pubkey.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        let state_control = FipsControlTcpRuntime::start(Arc::clone(mesh.endpoint())).await?;
        let tun = Arc::new(
            SystemTun::new(&config.iface)
                .with_context(|| fips_tun_create_context(&config.iface))?
                .set_non_blocking()
                .context("failed to set FIPS tunnel nonblocking")?,
        );
        let iface = tun.name().context("failed to read FIPS tunnel name")?;
        let tun_fd = BorrowedTunFd::new(tun.as_raw_fd());
        let (event_tx, event_rx) = mpsc::channel::<FipsPrivateMeshEvent>(1024);
        let exit_route_ready = fips_exit_route_ready(&config, &mesh.peer_statuses());
        let seller_egress_ready = local_exit_seller_egress_ready(
            &config,
            &connected_peer_pubkeys(&mesh.peer_statuses()),
            false,
            active_listen_port,
        );
        let mut runtime = Self {
            iface,
            mesh,
            control_pubsub,
            state_control,
            secure_dns: None,
            manages_secure_dns: true,
            config: config.clone(),
            cleanup_journal_config_path: cleanup_journal_config_path.to_path_buf(),
            _tun: tun,
            fips_host: None,
            fips_host_disabled_artifacts_cleaned: false,
            tun_send_worker: None,
            mesh_recv_worker: None,
            fips_host_recv_worker: None,
            event_rx,
            exit_route_ready,
            local_exit_seller_egress_ready: seller_egress_ready,
            active_listen_port,
            endpoint_bypass_routes: Vec::new(),
            #[cfg(target_os = "macos")]
            endpoint_bypass_underlay: None,
            #[cfg(target_os = "macos")]
            macos_underlay_refresh_pending: true,
            #[cfg(target_os = "linux")]
            original_default_route: None,
            #[cfg(target_os = "linux")]
            ethernet_underlay_default_route: None,
            #[cfg(target_os = "linux")]
            original_default_ipv6_route: None,
            #[cfg(target_os = "linux")]
            linux_network_state_initialized: false,
            #[cfg(target_os = "linux")]
            exit_node_runtime: crate::LinuxExitNodeRuntime::default(),
            #[cfg(target_os = "macos")]
            exit_node_runtime: crate::MacosExitNodeRuntime::default(),
            #[cfg(target_os = "macos")]
            wg_upstream: None,
        };
        let startup = async {
            runtime
                .prepare_secure_dns(&config, cleanup_journal_config_path)
                .await?;
            runtime.apply_interface_config(&config).await?;
            let ready = runtime.seller_egress_ready(&config);
            runtime.replace_paid_route_admissions(&config, ready)?;
            runtime.finish_secure_dns(&config).await?;
            runtime
                .reconcile_fips_host_runtime(config.fips_host.clone())
                .await?;
            runtime.start_packet_workers(tun_fd, event_tx, config.fips_host.is_some())
        }
        .await;
        if let Err(error) = startup {
            let cleanup = runtime.stop().await;
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => anyhow!(
                    "{error:#}; failed to clean partially-started FIPS runtime: {cleanup:#}"
                ),
            });
        }
        Ok(runtime)
    }

    async fn endpoint_bypass_ipv4_hosts(
        &self,
        config: &FipsPrivateTunnelConfig,
    ) -> Result<Vec<Ipv4Addr>> {
        let mut hosts = config.endpoint_hint_ipv4_hosts();
        hosts.extend(
            self.mesh
                .peer_transport_ipv4_hosts()
                .await?
                .into_iter()
                .filter(|host| !route_targets_include_ipv4_host(&config.route_targets, *host)),
        );
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }
    pub(crate) fn requires_endpoint_restart(&self, config: &FipsPrivateTunnelConfig) -> bool {
        fips_tunnel_requires_endpoint_restart(&self.config, config)
    }
    pub(crate) fn wireguard_exit_ready(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.exit_node_runtime
                .wireguard_exit
                .as_ref()
                .is_some_and(crate::LinuxWireGuardExitRuntime::has_completed_handshake)
        }
        #[cfg(target_os = "macos")]
        {
            self.wg_upstream.is_some()
        }
    }
    fn wireguard_exit_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.exit_node_runtime.wireguard_exit.is_some()
        }
        #[cfg(target_os = "macos")]
        {
            self.wg_upstream.is_some()
        }
    }
    fn seller_egress_ready(&self, config: &FipsPrivateTunnelConfig) -> bool {
        local_exit_seller_egress_ready(
            config,
            &connected_peer_pubkeys(&self.mesh.peer_statuses()),
            self.wireguard_exit_ready(),
            self.active_listen_port,
        )
    }
    fn replace_paid_route_admissions(
        &mut self,
        config: &FipsPrivateTunnelConfig,
        egress_ready: bool,
    ) -> Result<()> {
        self.mesh.replace_peers(
            config.peers.clone(),
            config.local_allowed_ips(),
            paid_route_admissions_for_egress(config, egress_ready),
        )?;
        self.local_exit_seller_egress_ready = egress_ready;
        Ok(())
    }
    pub(crate) async fn apply_config(
        &mut self,
        config: FipsPrivateTunnelConfig,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<()> {
        // A source switch must close buyer routing before any host route/NAT
        // mutation. Re-open it only after the selected egress is usable.
        self.replace_paid_route_admissions(&config, false)?;
        #[cfg(feature = "paid-exit")]
        self.mesh
            .set_paid_route_accounting_peers(config.paid_route_accounting_peers.clone())?;
        let endpoint_peers_to_refresh = endpoint_peers_with_changed_addresses(
            &self.config.endpoint_peers,
            &config.endpoint_peers,
        );
        if let Err(error) = self.mesh.update_peers(&config.endpoint_peers).await {
            eprintln!("fips: update_peers during apply_config failed: {error}");
        }
        if !endpoint_peers_to_refresh.is_empty() {
            match self.mesh.refresh_peer_paths(&endpoint_peers_to_refresh).await {
                Ok(refreshed) => eprintln!(
                    "fips: refreshed {refreshed} peer path(s) after endpoint address update"
                ),
                Err(error) => {
                    eprintln!("fips: peer path refresh after endpoint address update failed: {error}");
                }
            }
        }
        if self.config.nostr_relays != config.nostr_relays {
            self.mesh.update_relays(&config.nostr_relays).await?;
        }
        self.prepare_secure_dns(&config, cleanup_journal_config_path)
            .await?;
        self.apply_interface_config(&config).await?;
        let ready = self.seller_egress_ready(&config);
        self.replace_paid_route_admissions(&config, ready)?;
        self.finish_secure_dns(&config).await?;
        self.reconcile_fips_host_runtime(config.fips_host.clone())
            .await?;
        self.config = config;
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(runtime) = self.exit_node_runtime.wireguard_exit.as_mut()
            && let Err(error) = runtime.refresh_completed_handshake()
        {
            eprintln!("fips: failed to query WireGuard exit handshake: {error:#}");
        }
        let statuses = self.mesh.peer_statuses();
        let exit_route_ready = fips_exit_route_ready(&self.config, &statuses);
        let seller_egress_ready = local_exit_seller_egress_ready(
            &self.config,
            &connected_peer_pubkeys(&statuses),
            self.wireguard_exit_ready(),
            self.active_listen_port,
        );
        let seller_readiness_changed =
            self.local_exit_seller_egress_ready != seller_egress_ready;
        if self.local_exit_seller_egress_ready && !seller_egress_ready {
            let config = self.config.clone();
            self.replace_paid_route_admissions(&config, false)?;
        }
        if self.exit_route_ready != exit_route_ready || seller_readiness_changed {
            let config = self.config.clone();
            self.apply_interface_config(&config).await?;
            self.finish_secure_dns(&config).await?;
            self.replace_paid_route_admissions(&config, seller_egress_ready)?;
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            if !linux_route_targets_require_ip_endpoint_bypass(&self.config.route_targets) {
                return Ok(());
            }
            let config = self.config.clone();
            let mut bypass_hosts = config.control_plane_bypass_hosts.clone();
            bypass_hosts.extend(self.endpoint_bypass_ipv4_hosts(&config).await?);
            if linux_endpoint_bypass_hosts_unchanged(
                &self.endpoint_bypass_routes,
                &bypass_hosts,
            ) {
                return Ok(());
            }
            return self.apply_interface_config(&config).await;
        }
        #[cfg(target_os = "macos")]
        {
            let config = self.config.clone();
            self.reconcile_macos_endpoint_bypass_for_config(&config)
                .await?;
            Ok(())
        }
    }

    pub(crate) async fn stop(self) -> Result<()> {
        let mut runtime = self;
        #[cfg(target_os = "linux")]
        let network_cleanup = runtime.cleanup_linux_network_state();
        #[cfg(target_os = "macos")]
        let mut macos_network_failures = Vec::new();
        #[cfg(target_os = "macos")]
        if let Err(error) = runtime.cleanup_macos_network_state() {
            macos_network_failures.push(format!("remove macOS tunnel routes: {error:#}"));
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = runtime.cleanup_macos_exit_node_forwarding_checked() {
            macos_network_failures.push(format!("restore macOS exit forwarding: {error:#}"));
        }
        #[cfg(target_os = "macos")]
        if let Some(handle) = runtime.wg_upstream.as_mut() {
            if let Err(error) = handle.cleanup().await {
                macos_network_failures.push(format!("remove macOS WG upstream: {error:#}"));
            } else {
                runtime.wg_upstream.take();
            }
        }
        let dns_cleanup = if let Some(secure_dns) = runtime.secure_dns.as_mut() {
            secure_dns.stop().await
        } else {
            Ok(())
        };
        if dns_cleanup.is_ok() {
            runtime.secure_dns.take();
        }
        #[cfg(target_os = "linux")]
        let linux_owned_cleanup = if network_cleanup.is_ok() && dns_cleanup.is_ok() {
            Ok(())
        } else {
            Err(anyhow!("Linux network or secure DNS cleanup remains incomplete"))
        };
        #[cfg(target_os = "linux")]
        record_linux_stop_cleanup_ownership(
            &linux_owned_cleanup,
            LinuxNetworkCleanupState::from_runtime(&runtime),
        );
        #[cfg(target_os = "macos")]
        let network_cleanup = combined_failures(macos_network_failures);
        #[cfg(target_os = "macos")]
        let macos_owned_cleanup = if network_cleanup.is_ok() && dns_cleanup.is_ok() {
            Ok(())
        } else {
            Err(anyhow!("macOS network or secure DNS cleanup remains incomplete"))
        };
        #[cfg(target_os = "macos")]
        record_macos_stop_cleanup_ownership(
            &macos_owned_cleanup,
            runtime.macos_network_cleanup_state(),
        );
        runtime.stop_fips_host_runtime();
        if let Some(control_pubsub) = runtime.control_pubsub.take() {
            control_pubsub.stop().await;
        }
        runtime.state_control.stop().await;
        runtime.event_rx.close();
        if let Some(worker) = runtime.tun_send_worker.take() {
            stop_tun_send_worker(worker).await;
        }
        if let Some(worker) = runtime.fips_host_recv_worker.take() {
            stop_fips_host_recv_worker(worker).await;
        }
        if let Some(worker) = runtime.mesh_recv_worker.take() {
            stop_mesh_recv_worker(worker, &runtime.mesh).await;
        }
        let endpoint_cleanup = runtime
            .mesh
            .endpoint()
            .shutdown()
            .await
            .context("failed to stop FIPS endpoint");
        let mut failures = Vec::new();
        if let Err(error) = network_cleanup {
            failures.push(format!("network cleanup failed ({error:#})"));
        }
        if let Err(error) = dns_cleanup {
            failures.push(format!("secure DNS cleanup failed ({error:#})"));
        }
        if let Err(error) = endpoint_cleanup {
            failures.push(format!("endpoint shutdown failed ({error:#})"));
        }
        combined_failures(failures)
    }

    async fn prepare_secure_dns(
        &mut self,
        config: &FipsPrivateTunnelConfig,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<()> {
        // Keep an already-active WireGuard profile resolver throughout a
        // config handoff. Staging the no-exit automatic fallback here can
        // dispatch an in-flight Cloudflare query before finish_secure_dns
        // restores the profile resolver.
        let wireguard_active = self.wireguard_exit_active();
        if self.manages_secure_dns && config.secure_dns_required() && self.secure_dns.is_none() {
            crate::secure_dns_runtime::SecureDnsRuntime::start_into(
                &mut self.secure_dns,
                &self.iface,
                None,
                config.magic_dns_records.clone(),
                config.exit_dns_resolver_config(wireguard_active)?,
                config
                    .fips_host
                    .as_ref()
                    .map(|_| Arc::clone(self.mesh.endpoint())),
                |intent| {
                    crate::daemon_runtime::persist_fips_secure_dns_cleanup_intent(
                        cleanup_journal_config_path,
                        intent,
                    )
                },
            )
            .await?;
        }
        if let Some(secure_dns) = self.secure_dns.as_mut() {
            secure_dns.update_config(
                config.magic_dns_records.clone(),
                config.exit_dns_resolver_config(wireguard_active)?,
            )?;
        }
        Ok(())
    }

    async fn finish_secure_dns(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        let wireguard_active = self.wireguard_exit_active();
        if self.manages_secure_dns
            && config.secure_dns_required()
            && let Some(secure_dns) = self.secure_dns.as_mut()
        {
            let resolver_config = config.exit_dns_resolver_config(wireguard_active)?;
            secure_dns.update_records(config.magic_dns_records.clone());
            // Drop connections opened before the route handoff; pooled DoH
            // sockets keep their original path and otherwise fail until idle expiry.
            secure_dns.reset_resolver(resolver_config)?;
        }
        if (!self.manages_secure_dns || !config.secure_dns_required())
            && let Some(secure_dns) = self.secure_dns.as_mut()
        {
            secure_dns.stop().await?;
            self.secure_dns.take();
        }
        Ok(())
    }

    async fn apply_interface_config(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.apply_linux_network_state(config).await?;
        }
        #[cfg(target_os = "macos")]
        {
            let previous_exit_requested = self
                .config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
                || self.config.wireguard_exit.enabled;
            let next_exit_requested = config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
                || config.wireguard_exit.enabled;
            if macos_direct_underlay_restore_needed(
                previous_exit_requested,
                next_exit_requested,
            ) {
                crate::macos_network::restore_macos_underlay_default_route_if_missing()?;
            }
            self.cleanup_stale_macos_wg_upstream(&config.wireguard_exit)
                .await?;
            self.apply_macos_network_state(config).await?;
            self.reconcile_macos_wg_upstream(config).await?;
            self.reconcile_macos_exit_node_forwarding(
                &config.local_address,
                &config.local_exit_forwarding_routes,
                config.local_exit_seller_egress.as_ref(),
                self.seller_egress_ready(config),
            )?;
        }
        self.exit_route_ready = fips_exit_route_ready(config, &self.mesh.peer_statuses());
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn apply_macos_network_state(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        let requested_ipv4_exit = config
            .route_targets
            .iter()
            .any(|route| route == "0.0.0.0/0");
        let mut route_targets = effective_fips_route_targets(config, &self.mesh.peer_statuses());
        let pending_exit_without_peer = requested_ipv4_exit
            && !config.wireguard_exit.enabled
            && !config.peers.iter().any(|peer| {
                peer.allowed_ips
                    .iter()
                    .any(|route| crate::is_exit_node_route(route))
            });
        let original_route_targets_require_bypass =
            crate::route_targets_require_endpoint_bypass(&route_targets);
        let (has_peer_endpoint_hosts, underlay) = self
            .reconcile_macos_endpoint_bypass_for_config(config)
            .await?;
        if requested_ipv4_exit && !has_peer_endpoint_hosts && !pending_exit_without_peer {
            eprintln!(
                "fips: withholding macOS default route until the selected exit peer underlay endpoint is known"
            );
            route_targets.retain(|route| !crate::is_exit_node_route(route));
        } else if original_route_targets_require_bypass
            && underlay.is_none()
            && !pending_exit_without_peer
        {
            eprintln!(
                "fips: withholding macOS default route because no underlay default route is available"
            );
            route_targets.retain(|route| !crate::is_exit_node_route(route));
        }
        let active_ipv4_exit = route_targets.iter().any(|route| route == "0.0.0.0/0");
        if !active_ipv4_exit
            && let Err(error) = crate::delete_macos_default_route_for_interface(&self.iface)
            && !crate::daemon_runtime::macos_route_delete_error_is_absent(&error.to_string())
        {
            eprintln!(
                "fips: failed to remove stale macOS default routes on {}: {}",
                self.iface, error
            );
        }
        route_targets = config.interface_route_targets(route_targets);
        self.persist_network_cleanup_ownership()?;
        // FIPS mesh peer routes go in first. They're /32s for each peer's
        // tunnel IP, so even when we install split defaults below, mesh traffic
        // still wins on longest-prefix-match and stays inside the FIPS tunnel.
        crate::apply_local_interface_network_with_mtu_and_addresses(
            &self.iface,
            &config.interface_addresses(),
            &route_targets,
            config.interface_mtu(),
        )
        .with_context(|| format!("failed to configure FIPS tunnel interface {}", self.iface))?;
        // macOS may rewrite the route table while split defaults are added.
        // Re-read and repair the seller/relay underlay escape routes after
        // that mutation so a paid tunnel can never route its own transport
        // back into itself.
        if active_ipv4_exit
            && has_peer_endpoint_hosts
            && let Err(error) = self.reconcile_macos_endpoint_bypass_for_config(config).await
        {
            let rollback = crate::delete_macos_default_route_for_interface(&self.iface);
            return match rollback {
                Ok(()) => Err(error.context(
                    "reassert macOS endpoint bypass after default route update; paid default route rolled back",
                )),
                Err(rollback_error) => Err(error.context(format!(
                    "reassert macOS endpoint bypass after default route update; paid default route rollback failed: {rollback_error:#}"
                ))),
            };
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn reconcile_macos_endpoint_bypass_for_config(
        &mut self,
        config: &FipsPrivateTunnelConfig,
    ) -> Result<(bool, Option<crate::MacosRouteSpec>)> {
        let hosts = self.endpoint_bypass_ipv4_hosts(config).await?;
        let routes = crate::macos_network::macos_endpoint_bypass_targets_for_hosts(&hosts);
        let force_underlay_refresh = self.macos_underlay_refresh_pending
            || self.config.underlay_interface != config.underlay_interface;
        // Peer events are frequent and normally leave both bypasses and the
        // physical underlay unchanged. Only a real link/config transition
        // invalidates the populated ownership cache.
        let current_routes_present = self
            .endpoint_bypass_underlay
            .as_ref()
            .is_some_and(|underlay| {
                crate::macos_network::macos_managed_routes_present_in_system(
                    &self.endpoint_bypass_routes,
                    underlay,
                )
                .unwrap_or_else(|error| {
                    eprintln!("fips: failed to verify cached macOS endpoint bypasses: {error}");
                    false
                })
            });
        if !macos_endpoint_bypass_underlay_refresh_required(
            &self.endpoint_bypass_routes,
            self.endpoint_bypass_underlay.as_ref(),
            &routes,
            current_routes_present,
        ) && !force_underlay_refresh
        {
            return Ok((!hosts.is_empty(), self.endpoint_bypass_underlay.clone()));
        }
        let underlay = match crate::macos_network::
            macos_underlay_default_route_from_system_for_interface(
                config.underlay_interface.as_deref(),
            )
        {
            Ok(underlay) => underlay,
            Err(error) => {
                eprintln!("fips: failed to resolve macOS endpoint underlay route: {error}");
                None
            }
        };
        self.reconcile_macos_endpoint_bypass_routes(
            underlay.as_ref().map_or(&[], |_| routes.as_slice()),
            underlay.as_ref(),
            !current_routes_present,
        )?;
        self.macos_underlay_refresh_pending = false;
        Ok((!hosts.is_empty(), underlay))
    }

    #[cfg(target_os = "macos")]
    fn reconcile_macos_endpoint_bypass_routes(
        &mut self,
        routes: &[String],
        underlay: Option<&crate::MacosRouteSpec>,
        force_reapply: bool,
    ) -> Result<()> {
        // Reassert the currently owned identity before removing anything.
        // This also makes a previously successful runtime crash-repairable
        // even if an earlier post-apply journal update was interrupted.
        self.persist_network_cleanup_ownership()?;
        let mut failures = Vec::new();
        let desired = routes
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let underlay_changed = self.endpoint_bypass_underlay.as_ref() != underlay;
        let current_underlay = self.endpoint_bypass_underlay.clone();
        let current_gateway = current_underlay
            .as_ref()
            .and_then(|owner| owner.gateway.as_deref());
        let current_interface = current_underlay
            .as_ref()
            .map(|owner| owner.interface.as_str());
        let stale = self
            .endpoint_bypass_routes
            .iter()
            .filter(|route| underlay_changed || !desired.contains(*route))
            .cloned()
            .collect::<Vec<_>>();
        for route in stale {
            if let Err(error) =
                crate::delete_macos_managed_route(&route, current_gateway, current_interface)
                && !crate::daemon_runtime::macos_route_delete_error_is_absent(&error.to_string())
            {
                failures.push(format!("remove endpoint bypass route {route}: {error:#}"));
            }
        }
        if !failures.is_empty() {
            return Err(anyhow!(failures.join("; ")));
        }
        if underlay_changed {
            self.endpoint_bypass_routes.clear();
            self.endpoint_bypass_underlay = None;
        } else {
            self.endpoint_bypass_routes
                .retain(|route| desired.contains(route));
        }
        // Journal every exact desired route and underlay before the first
        // route add. Replaying this intent is safe if the crash happened
        // before an add because cleanup verifies exact route ownership and
        // treats an absent route as already clean.
        let actual_routes = std::mem::replace(&mut self.endpoint_bypass_routes, routes.to_vec());
        let actual_underlay =
            std::mem::replace(&mut self.endpoint_bypass_underlay, underlay.cloned());
        let persist_intent = self.persist_network_cleanup_ownership();
        self.endpoint_bypass_routes = actual_routes;
        self.endpoint_bypass_underlay = actual_underlay;
        persist_intent?;
        let interface = underlay.map(|owner| owner.interface.as_str());
        for (route, error) in apply_macos_endpoint_bypass_route_changes(
            &mut self.endpoint_bypass_routes,
            &mut self.endpoint_bypass_underlay,
            routes,
            underlay,
            force_reapply,
            |route, gateway| crate::apply_macos_route_spec(route, gateway, interface),
        ) {
            failures.push(format!("install endpoint bypass route {route}: {error:#}"));
        }
        combined_failures(failures)
    }

    #[cfg(target_os = "macos")]
    fn cleanup_macos_network_state(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if let Err(error) = self.reconcile_macos_endpoint_bypass_routes(&[], None, false) {
            failures.push(error.to_string());
        }
        if let Err(error) = crate::delete_macos_default_route_for_interface(&self.iface)
            && !crate::daemon_runtime::macos_route_delete_error_is_absent(&error.to_string())
        {
            failures.push(format!(
                "remove split-default routes on {}: {error:#}",
                self.iface
            ));
        }
        combined_failures(failures)
    }

    async fn reconcile_fips_host_runtime(
        &mut self,
        config: Option<FipsHostTunnelConfig>,
    ) -> Result<()> {
        let was_running = self.fips_host.is_some();
        let needs_restart = match (&self.fips_host, &config) {
            (Some(runtime), Some(config)) => runtime.requires_restart(&self.iface, config),
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        };
        if needs_restart {
            self.stop_fips_host_runtime();
        }
        match config {
            Some(config) if self.fips_host.is_none() => {
                self.fips_host_disabled_artifacts_cleaned = false;
                let runtime = crate::fips_host_tunnel::FipsHostTunnelRuntime::start(
                    &self.iface,
                    config,
                )?;
                eprintln!("fips-host: integrated .fips IPv6 resolver active on {}", self.iface);
                self.fips_host = Some(runtime);
            }
            None
                if fips_host_disabled_cleanup_due(
                    was_running,
                    self.fips_host_disabled_artifacts_cleaned,
                ) =>
            {
                crate::fips_host_tunnel::FipsHostTunnelRuntime::cleanup_disabled_artifacts();
                self.fips_host_disabled_artifacts_cleaned = true;
            }
            None => self.fips_host_disabled_artifacts_cleaned = true,
            Some(_) => {}
        }
        Ok(())
    }
    fn stop_fips_host_runtime(&mut self) {
        if let Some(runtime) = self.fips_host.take() {
            runtime.stop();
        }
    }

    #[cfg(target_os = "macos")]
    fn reconcile_macos_exit_node_forwarding(
        &mut self,
        local_address: &str,
        routes: &[String],
        seller_egress: Option<&PaidExitSellerEgress>,
        seller_egress_ready: bool,
    ) -> Result<()> {
        let route_families = crate::linux_exit_node_default_route_families(routes);
        if !route_families.ipv4 {
            return self.cleanup_macos_exit_node_forwarding_checked();
        }
        if route_families.ipv6 {
            eprintln!(
                "fips: IPv6 exit-node forwarding is disabled on macOS until nvpn has IPv6 PF source filtering"
            );
        }
        if !seller_egress_ready {
            return self.cleanup_macos_exit_node_forwarding_checked();
        }
        let tunnel_source_cidr = crate::linux_exit_node_source_cidr(local_address)
            .ok_or_else(|| anyhow!("invalid IPv4 tunnel address '{local_address}'"))?;
        let host_default_iface = if matches!(seller_egress, Some(PaidExitSellerEgress::Direct)) {
            crate::macos_underlay_default_route_from_system()?.map(|route| route.interface)
        } else {
            None
        };
        let outbound_iface = local_exit_outbound_interface(
            seller_egress,
            &self.iface,
            self.wg_upstream.as_ref().map(|upstream| upstream.iface.as_str()),
            host_default_iface.as_deref(),
        )
        .ok_or_else(|| anyhow!("selected seller internet source is not ready for exit NAT"))?;
        let already_configured = self.exit_node_runtime.outbound_iface.as_deref()
            == Some(outbound_iface.as_str())
            && self.exit_node_runtime.tunnel_source_cidr.as_deref()
                == Some(tunnel_source_cidr.as_str())
            && self.exit_node_runtime.ipv4_forward_was_enabled.is_some();
        if already_configured {
            return Ok(());
        }
        self.cleanup_macos_exit_node_forwarding_checked()?;
        let previous_forwarding = crate::read_macos_ipv4_forwarding()
            .context("read macOS IPv4 forwarding state")?;
        self.exit_node_runtime.ipv4_forward_was_enabled = Some(previous_forwarding);
        self.persist_network_cleanup_ownership()?;
        if !previous_forwarding
            && let Err(error) = crate::write_macos_ipv4_forwarding(true)
        {
            return Err(self.rollback_macos_exit_node_setup(
                error.context("enable macOS IPv4 forwarding"),
            ));
        }
        let previous_pf = match crate::macos_pf_enabled() {
            Ok(enabled) => enabled,
            Err(error) => {
                return Err(self
                    .rollback_macos_exit_node_setup(error.context("read macOS PF enabled state")));
            }
        };
        self.exit_node_runtime.pf_was_enabled = Some(previous_pf);
        self.exit_node_runtime.outbound_iface = Some(outbound_iface.clone());
        self.exit_node_runtime.tunnel_source_cidr = Some(tunnel_source_cidr.clone());
        self.persist_network_cleanup_ownership()?;
        if !previous_pf
            && let Err(error) = crate::enable_macos_pf()
        {
            return Err(
                self.rollback_macos_exit_node_setup(error.context("enable macOS PF for exit NAT"))
            );
        }
        if let Err(error) =
            crate::apply_macos_exit_node_pf_rules(&self.iface, &outbound_iface, &tunnel_source_cidr)
        {
            return Err(
                self.rollback_macos_exit_node_setup(error.context("install macOS exit PF rules"))
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn cleanup_macos_exit_node_forwarding_checked(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if self.exit_node_runtime.pf_was_enabled.is_some() {
            match crate::cleanup_macos_pf_nat() {
                Ok(()) => {
                    if self.exit_node_runtime.pf_was_enabled == Some(false) {
                        match crate::run_checked(ProcessCommand::new("pfctl").arg("-d")) {
                            Ok(()) => self.exit_node_runtime.pf_was_enabled = None,
                            Err(error) => {
                                failures.push(format!("restore PF disabled state: {error:#}"));
                            }
                        }
                    } else {
                        self.exit_node_runtime.pf_was_enabled = None;
                    }
                }
                Err(error) => failures.push(format!("remove PF exit rules: {error:#}")),
            }
        }
        match self.exit_node_runtime.ipv4_forward_was_enabled {
            Some(false) => match crate::write_macos_ipv4_forwarding(false) {
                Ok(()) => self.exit_node_runtime.ipv4_forward_was_enabled = None,
                Err(error) => {
                    failures.push(format!("restore IPv4 forwarding state: {error:#}"));
                }
            },
            Some(true) => self.exit_node_runtime.ipv4_forward_was_enabled = None,
            None => {}
        }
        if self.exit_node_runtime.pf_was_enabled.is_none() {
            self.exit_node_runtime.outbound_iface = None;
            self.exit_node_runtime.tunnel_source_cidr = None;
        }
        combined_failures(failures)
    }

    #[cfg(target_os = "macos")]
    fn rollback_macos_exit_node_setup(&mut self, setup_error: anyhow::Error) -> anyhow::Error {
        match self.cleanup_macos_exit_node_forwarding_checked() {
            Ok(()) => setup_error,
            Err(cleanup_error) => anyhow!(
                "{setup_error:#}; failed to roll back partial macOS exit-node setup: \
                 {cleanup_error:#}"
            ),
        }
    }
}
include!("macos_wg_transition.rs");
include!("tunnel_runtime_unix_core/delegates.rs");
