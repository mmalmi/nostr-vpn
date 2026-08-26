#[cfg(target_os = "windows")]
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

    pub(crate) fn wireguard_exit_ready(&self) -> bool {
        self.wg_upstream.is_some()
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn paid_exit_seller_ready(&self) -> bool {
        // Windows does not yet install seller forwarding/NAT, so listener
        // ownership alone must never make a public offer discoverable.
        false
    }

    pub(crate) async fn start(
        config: FipsPrivateTunnelConfig,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Self> {
        validate_windows_wireguard_config(&config.wireguard_exit, &config.exit_dns)?;
        crate::pipeline_profile::maybe_spawn_reporter();
        let mesh = bind_fips_private_mesh(&config).await?;
        let active_listen_port = mesh
            .confirmed_udp_listen_port(
                config.listen_port,
                required_public_udp_listener_ipv6(&config),
            )
            .await?;
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
        let (session, iface, interface_index) = start_windows_fips_wintun(&config)?;
        let peer_statuses = mesh.peer_statuses();
        let exit_route_ready = fips_exit_route_ready(&config, &peer_statuses);
        let effective_route_targets = effective_fips_route_targets(&config, &peer_statuses);
        let endpoint_bypass_targets = windows_fips_endpoint_bypass_targets(
            &config.endpoint_peers,
            &effective_route_targets,
        );
        let mut endpoint_bypass_routes =
            crate::wg_upstream_runtime::WindowsManagedEndpointRoutes::apply(
                &endpoint_bypass_targets,
                &[interface_index],
                cleanup_journal_config_path,
            )
            .context("failed to apply Windows FIPS endpoint bypass routes")?;
        let mut route_guard = match crate::wg_upstream_runtime::WindowsManagedInterfaceRoutes::apply(
            interface_index,
            &effective_route_targets,
            cleanup_journal_config_path,
        ) {
            Ok(route_guard) => route_guard,
            Err(error) => {
                let rollback = endpoint_bypass_routes
                    .as_mut()
                    .map_or(Ok(()), |routes| routes.revert());
                return Err(windows_fips_with_cleanup_error(
                    error.context("failed to apply Windows FIPS routes"),
                    "rollback endpoint bypass routes",
                    rollback,
                ));
            }
        };
        let mut secure_dns = None;
        if config.secure_dns_required()
            && let Err(error) = crate::secure_dns_runtime::SecureDnsRuntime::start_into(
                &mut secure_dns,
                &iface,
                Some(interface_index),
                config.magic_dns_records.clone(),
                config.exit_dns_resolver_config(false)?,
                None,
                |intent| {
                    crate::daemon_runtime::persist_fips_secure_dns_cleanup_intent(
                        cleanup_journal_config_path,
                        intent,
                    )
                },
            )
            .await
        {
            let mut failures = Vec::new();
            if let Some(runtime) = secure_dns.as_mut() {
                let cleanup = runtime.stop().await;
                record_windows_secure_dns_cleanup(interface_index, &cleanup);
                windows_fips_record_cleanup(
                    &mut failures,
                    "partially installed Windows secure DNS",
                    cleanup,
                );
            }
            windows_fips_record_cleanup(
                &mut failures,
                "Windows FIPS tunnel routes",
                route_guard.revert(),
            );
            if let Some(routes) = endpoint_bypass_routes.as_mut() {
                windows_fips_record_cleanup(
                    &mut failures,
                    "Windows FIPS endpoint bypass routes",
                    routes.revert(),
                );
            }
            return Err(windows_fips_with_cleanup_error(
                error.context("start Windows FIPS secure DNS"),
                "rollback Windows FIPS startup",
                windows_fips_finish_cleanup(failures),
            ));
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (event_tx, event_rx) = mpsc::channel::<FipsPrivateMeshEvent>(1024);
        let tun_read_thread =
            spawn_windows_fips_tun_read_thread(stop.clone(), session.clone(), Arc::clone(&mesh));
        let mesh_recv_task = spawn_windows_fips_mesh_recv_task(
            stop.clone(),
            Arc::clone(&mesh),
            session.clone(),
            event_tx,
        );

        let mut runtime = Self {
            iface,
            mesh,
            control_pubsub,
            state_control,
            secure_dns,
            config: config.clone(),
            cleanup_journal_config_path: cleanup_journal_config_path.to_path_buf(),
            session,
            stop,
            tun_read_thread,
            mesh_recv_task,
            event_rx,
            exit_route_ready,
            active_listen_port,
            interface_index,
            route_guard,
            endpoint_bypass_routes,
            wg_upstream: None,
        };
        // Reconcile the WG upstream against the initial config. Same
        // safe-by-construction guarantee as macOS: if the WG handshake
        // doesn't complete within the watchdog window, the routing
        // table stays untouched.
        let startup_result: Result<()> = async {
            runtime
                .reconcile_windows_wg_upstream(&config.wireguard_exit)
                .await?;
            let wireguard_interface = runtime
                .wg_upstream
                .as_ref()
                .map(|upstream| upstream.iface.clone());
            let resolver_config =
                config.exit_dns_resolver_config(wireguard_interface.is_some())?;
            let servers = resolver_config.through_exit_servers().to_vec();
            if let Some(secure_dns) = runtime.secure_dns.as_mut() {
                secure_dns.update_config(config.magic_dns_records.clone(), resolver_config)?;
                secure_dns
                    .update_windows_wireguard_dns(wireguard_interface.as_deref(), &servers)?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = startup_result {
            let cleanup = runtime.stop().await;
            return Err(windows_fips_with_cleanup_error(
                error.context("finish Windows FIPS tunnel startup"),
                "rollback Windows FIPS startup",
                cleanup,
            ));
        }
        Ok(runtime)
    }

    pub(crate) fn requires_endpoint_restart(&self, config: &FipsPrivateTunnelConfig) -> bool {
        self.config.iface != config.iface
            || self.config.local_address != config.local_address
            || fips_tunnel_requires_endpoint_restart(&self.config, config)
    }

    pub(crate) async fn apply_config(
        &mut self,
        config: FipsPrivateTunnelConfig,
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<()> {
        validate_windows_wireguard_config(&config.wireguard_exit, &config.exit_dns)?;
        let existing_wireguard_upstream_matches = config.wireguard_exit.enabled
            && config.wireguard_exit.configured()
            && self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.matches(&config.wireguard_exit));
        if existing_wireguard_upstream_matches {
            // Moving an existing endpoint bypass is independent of peer control
            // and must not wait behind its reconnect work after an underlay change.
            self.reconcile_windows_wg_upstream(&config.wireguard_exit)
                .await?;
        }
        self.mesh.replace_peers(
            config.peers.clone(),
            config.local_allowed_ips(),
            config.paid_route_admissions.clone(),
        )?;
        #[cfg(feature = "paid-exit")]
        self.mesh
            .set_paid_route_accounting_peers(config.paid_route_accounting_peers.clone())?;
        if let Err(error) = self.mesh.update_peers(&config.endpoint_peers).await {
            eprintln!("fips: update_peers during apply_config failed: {error}");
        }
        if self.config.nostr_relays != config.nostr_relays {
            self.mesh.update_relays(&config.nostr_relays).await?;
        }
        if config.secure_dns_required() && self.secure_dns.is_none() {
            crate::secure_dns_runtime::SecureDnsRuntime::start_into(
                &mut self.secure_dns,
                &self.iface,
                Some(self.interface_index),
                config.magic_dns_records.clone(),
                config.exit_dns_resolver_config(false)?,
                None,
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
            secure_dns.update_records(config.magic_dns_records.clone());
            secure_dns.update_config(
                config.magic_dns_records.clone(),
                config.exit_dns_resolver_config(false)?,
            )?;
        }
        // Verify and install the desired WireGuard upstream before changing
        // FIPS routes. A failed handshake leaves the existing route set
        // untouched while secure exit DNS remains fail-closed.
        if !existing_wireguard_upstream_matches {
            self.reconcile_windows_wg_upstream(&config.wireguard_exit)
                .await?;
        }
        self.apply_windows_route_config(&config)?;
        if !config.secure_dns_required()
            && let Some(secure_dns) = self.secure_dns.as_mut()
        {
            let interface_index = secure_dns
                .windows_cleanup_interface_index()
                .unwrap_or(self.interface_index);
            let cleanup = secure_dns.stop().await;
            record_windows_secure_dns_cleanup(interface_index, &cleanup);
            cleanup?;
            self.secure_dns.take();
        }
        let wireguard_interface = self
            .wg_upstream
            .as_ref()
            .map(|upstream| upstream.iface.clone());
        let resolver_config = config.exit_dns_resolver_config(wireguard_interface.is_some())?;
        let servers = resolver_config.through_exit_servers().to_vec();
        if let Some(secure_dns) = self.secure_dns.as_mut() {
            secure_dns.update_config(config.magic_dns_records.clone(), resolver_config)?;
            secure_dns
                .update_windows_wireguard_dns(wireguard_interface.as_deref(), &servers)?;
        }
        self.config = config;
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&mut self) -> Result<()> {
        let config = self.config.clone();
        self.apply_windows_route_config(&config)
    }

    fn apply_windows_route_config(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        let peer_statuses = self.mesh.peer_statuses();
        let exit_route_ready = fips_exit_route_ready(config, &peer_statuses);
        let effective_route_targets = effective_fips_route_targets(config, &peer_statuses);
        let desired_endpoint_routes = windows_fips_endpoint_bypass_targets(
            &config.endpoint_peers,
            &effective_route_targets,
        );
        let mut excluded_tunnel_interfaces = vec![self.interface_index];
        if let Some(upstream) = self.wg_upstream.as_ref() {
            excluded_tunnel_interfaces.push(upstream.interface_index());
        }
        match self.endpoint_bypass_routes.as_mut() {
            Some(routes) => {
                routes
                    .reconcile(&desired_endpoint_routes, &excluded_tunnel_interfaces)
                    .context("reconcile Windows FIPS endpoint bypass routes")?;
                if desired_endpoint_routes.is_empty() {
                    self.endpoint_bypass_routes = None;
                }
            }
            None if !desired_endpoint_routes.is_empty() => {
                self.endpoint_bypass_routes =
                    crate::wg_upstream_runtime::WindowsManagedEndpointRoutes::apply(
                        &desired_endpoint_routes,
                        &excluded_tunnel_interfaces,
                        &self.cleanup_journal_config_path,
                    )
                    .context("apply Windows FIPS endpoint bypass routes")?;
            }
            None => {}
        }

        self.route_guard
            .reconcile(&effective_route_targets)
            .context("reconcile Windows FIPS tunnel routes")?;
        self.exit_route_ready = exit_route_ready;
        Ok(())
    }

    /// Same shape as the macOS reconcile: a no-op if the existing
    /// tunnel already matches, teardown-then-rebuild on config change,
    /// just teardown on disable. Handshake-first, watchdog-protected:
    /// the routing table is only modified after a successful WG
    /// handshake.
    async fn reconcile_windows_wg_upstream(
        &mut self,
        wg_config: &WireGuardExitConfig,
    ) -> Result<()> {
        let want_up = wg_config.enabled && wg_config.configured();
        if want_up
            && self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.matches(wg_config))
        {
            let refreshed = self
                .wg_upstream
                .as_mut()
                .expect("matching Windows WireGuard upstream exists")
                .refresh_underlay_routes(&[self.interface_index])
                .context("refresh Windows WireGuard endpoint underlay route")?;
            if refreshed {
                eprintln!(
                    "fips: refreshed Windows WG endpoint bypass after physical underlay change"
                );
            }
            return Ok(());
        }
        if let Some(existing) = self.wg_upstream.as_mut() {
            existing
                .cleanup()
                .await
                .context("clean up previous Windows WireGuard upstream")?;
            self.wg_upstream = None;
        }
        if !want_up {
            let native_cleanup =
                crate::wg_upstream_runtime::retry_pending_windows_native_cleanup_journaled(
                    &self.cleanup_journal_config_path,
                );
            let route_cleanup =
                crate::wg_upstream_runtime::retry_pending_windows_route_cleanup_journaled(
                    &self.cleanup_journal_config_path,
                );
            return match (native_cleanup, route_cleanup) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(native), Ok(())) => {
                    Err(native.context("clean up pending native WireGuard before Direct"))
                }
                (Ok(()), Err(routes)) => {
                    Err(routes.context("clean up pending WireGuard routes before Direct"))
                }
                (Err(native), Err(routes)) => Err(anyhow!(
                    "clean up pending native WireGuard before Direct: {native:#}; \
                     clean up pending WireGuard routes before Direct: {routes:#}"
                )),
            };
        }
        let handle = crate::wg_upstream_runtime::apply_daemon_wg_upstream_for_fips(
            wg_config,
            crate::wg_upstream_runtime::DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT,
            self.interface_index,
            &self.cleanup_journal_config_path,
        )
        .await
        .context("start native Windows WireGuard upstream")?;
        eprintln!(
            "fips: WG upstream up on {} via {} (default route swapped)",
            handle.iface, handle.upstream
        );
        self.wg_upstream = Some(handle);
        Ok(())
    }

    pub(crate) async fn stop(self) -> Result<()> {
        let mut runtime = self;
        let mut failures = Vec::new();
        // Tear the WG upstream down BEFORE the FIPS bits so the route
        // revert lands while we still have a sane working tree.
        if let Some(handle) = runtime.wg_upstream.as_mut() {
            windows_fips_record_cleanup(
                &mut failures,
                "Windows WireGuard upstream",
                handle.cleanup().await,
            );
        }
        if let Some(control_pubsub) = runtime.control_pubsub.take() {
            control_pubsub.stop().await;
        }
        runtime.state_control.stop().await;
        runtime.stop.store(true, Ordering::Relaxed);
        windows_fips_record_cleanup(
            &mut failures,
            "FIPS WinTun session",
            runtime
                .session
                .shutdown()
                .context("shut down FIPS WinTun session"),
        );
        windows_fips_record_cleanup(
            &mut failures,
            "Windows FIPS tunnel routes",
            runtime.route_guard.revert(),
        );
        if let Some(routes) = runtime.endpoint_bypass_routes.as_mut() {
            windows_fips_record_cleanup(
                &mut failures,
                "Windows FIPS endpoint bypass routes",
                routes.revert(),
            );
        }
        windows_fips_record_cleanup(
            &mut failures,
            "pending Windows route obligations",
            crate::wg_upstream_runtime::retry_pending_windows_route_cleanup_journaled(
                &runtime.cleanup_journal_config_path,
            ),
        );
        let mut secure_dns_cleanup_succeeded = false;
        if let Some(secure_dns) = runtime.secure_dns.as_mut() {
            let interface_index = secure_dns
                .windows_cleanup_interface_index()
                .unwrap_or(runtime.interface_index);
            let cleanup = secure_dns.stop().await;
            record_windows_secure_dns_cleanup(interface_index, &cleanup);
            secure_dns_cleanup_succeeded = cleanup.is_ok();
            windows_fips_record_cleanup(&mut failures, "Windows secure DNS", cleanup);
        }
        if secure_dns_cleanup_succeeded {
            runtime.secure_dns.take();
        }
        runtime.event_rx.close();
        if runtime.tun_read_thread.join().is_err() {
            failures.push("FIPS WinTun reader thread panicked".to_string());
        }
        runtime.mesh_recv_task.abort();
        let _ = runtime.mesh_recv_task.await;
        windows_fips_record_cleanup(
            &mut failures,
            "FIPS endpoint",
            runtime
                .mesh
                .endpoint()
                .shutdown()
                .await
                .context("stop FIPS endpoint"),
        );
        windows_fips_finish_cleanup(failures)
    }
}

#[cfg(target_os = "windows")]
fn windows_fips_record_cleanup(
    failures: &mut Vec<String>,
    resource: &str,
    result: Result<()>,
) {
    if let Err(error) = result {
        failures.push(format!("{resource}: {error:#}"));
    }
}

#[cfg(target_os = "windows")]
fn windows_fips_finish_cleanup(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Windows FIPS cleanup incomplete: {}",
            failures.join("; ")
        ))
    }
}

#[cfg(target_os = "windows")]
fn windows_fips_with_cleanup_error(
    error: anyhow::Error,
    operation: &str,
    cleanup: Result<()>,
) -> anyhow::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => anyhow!("{error:#}; {operation}: {cleanup_error:#}"),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn validate_windows_wireguard_config(
    config: &WireGuardExitConfig,
    exit_dns: &ExitDnsConfig,
) -> Result<()> {
    if !config.enabled || !config.configured() {
        return Ok(());
    }
    match config.endpoint.parse::<SocketAddr>() {
        Ok(endpoint) if !endpoint.is_ipv4() => {
            return Err(anyhow!(
                "Windows WireGuard exit does not yet support an IPv6 endpoint"
            ));
        }
        Err(_) if exit_dns.mode == nostr_vpn_core::config::ExitDnsMode::ThroughExit => {
            return Err(anyhow!(
                "Windows WireGuard exit with DNS-through-exit requires a literal IPv4 \
                 endpoint with port; hostname DNS is fail-closed until the tunnel connects"
            ));
        }
        Ok(_) | Err(_) => {}
    }
    if config.allowed_ips.iter().any(|route| {
        route
            .split_once('/')
            .map_or(route.as_str(), |(address, _)| address)
            .trim()
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    }) {
        return Err(anyhow!(
            "Windows WireGuard exit does not yet support IPv6 AllowedIPs"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn windows_fips_endpoint_bypass_targets(
    endpoint_peers: &[FipsEndpointPeerTransportConfig],
    route_targets: &[String],
) -> Vec<String> {
    let has_broad_ipv4_route = route_targets.iter().any(|route| {
        let Some((host, bits)) = route.trim().split_once('/') else {
            return false;
        };
        host.parse::<Ipv4Addr>().is_ok()
            && bits.parse::<u8>().is_ok_and(|prefix_len| prefix_len < 32)
    });
    if !has_broad_ipv4_route {
        return Vec::new();
    }

    let mut hosts = endpoint_peers
        .iter()
        .flat_map(|peer| peer.addresses.iter())
        .filter(|hint| hint.seen_at_ms.is_none())
        .filter_map(|hint| {
            let (transport, addr) = split_peer_transport_addr(&hint.addr);
            if transport != "udp" {
                return None;
            }
            match addr.parse::<SocketAddr>().ok()?.ip() {
                IpAddr::V4(host) => Some(host),
                IpAddr::V6(_) => None,
            }
        })
        .filter(|host| {
            !route_targets.iter().any(|route| {
                let Some((target, bits)) = route.trim().split_once('/') else {
                    return false;
                };
                bits == "32" && target.parse::<Ipv4Addr>() == Ok(*host)
            })
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts.into_iter().map(|host| format!("{host}/32")).collect()
}

#[cfg(test)]
mod windows_endpoint_bypass_tests {
    use super::*;

    fn address(addr: &str) -> FipsPeerAddressHint {
        FipsPeerAddressHint {
            addr: addr.to_string(),
            seen_at_ms: None,
            priority: 0,
        }
    }

    #[test]
    fn configured_udp_endpoint_bypasses_are_deterministic() {
        let peers = vec![FipsEndpointPeerTransportConfig {
            npub: "peer".to_string(),
            addresses: vec![
                address("udp:203.0.113.7:2121"),
                address("65.109.48.91:2121"),
                address("udp:65.109.48.91:2121"),
                address("tcp:192.0.2.9:8443"),
                address("udp:[2001:db8::7]:2121"),
                FipsPeerAddressHint {
                    addr: "udp:192.0.2.10:2121".to_string(),
                    seen_at_ms: Some(1),
                    priority: 0,
                },
            ],
            connect_on_start: true,
            auto_reconnect: true,
            discovery_fallback_transit: false,
        }];

        assert_eq!(
            windows_fips_endpoint_bypass_targets(
                &peers,
                &["0.0.0.0/0".to_string(), "203.0.113.7/32".to_string()],
            ),
            vec!["65.109.48.91/32"]
        );
        assert!(
            windows_fips_endpoint_bypass_targets(&peers, &["10.44.0.2/32".to_string()]).is_empty()
        );
    }

    #[test]
    fn windows_wireguard_rejects_only_unsupported_pre_dns_configs() {
        let mut config = WireGuardExitConfig {
            enabled: true,
            address: "10.64.70.195/32".to_string(),
            private_key: "private-key".to_string(),
            peer_public_key: "peer-key".to_string(),
            endpoint: "vpn.example:51820".to_string(),
            ..WireGuardExitConfig::default()
        };
        let mut exit_dns = ExitDnsConfig {
            mode: nostr_vpn_core::config::ExitDnsMode::ThroughExit,
            ..ExitDnsConfig::default()
        };
        assert!(
            validate_windows_wireguard_config(&config, &exit_dns)
                .expect_err("hostname must fail before secure DNS")
                .to_string()
                .contains("literal IPv4 endpoint")
        );
        exit_dns.mode = nostr_vpn_core::config::ExitDnsMode::Automatic;
        validate_windows_wireguard_config(&config, &exit_dns)
            .expect("bootstrap DoH can resolve a hostname endpoint");
        config.endpoint = "[2001:db8::20]:51820".to_string();
        assert!(
            validate_windows_wireguard_config(&config, &exit_dns)
                .expect_err("IPv6 endpoint is unsupported")
                .to_string()
                .contains("does not yet support an IPv6 endpoint")
        );
        config.endpoint = "198.51.100.20:51820".to_string();
        config.allowed_ips.push("::/0".to_string());
        assert!(
            validate_windows_wireguard_config(&config, &exit_dns)
                .expect_err("IPv6 AllowedIPs are unsupported")
                .to_string()
                .contains("does not yet support IPv6 AllowedIPs")
        );
        config.allowed_ips.retain(|route| route != "::/0");
        validate_windows_wireguard_config(&config, &exit_dns).expect("literal IPv4-only config");
    }

    #[test]
    fn windows_runtime_does_not_swallow_wg_or_stop_cleanup_failures() {
        let source = include_str!("tunnel_runtime_windows.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("Windows runtime source");
        assert!(
            !production.contains("WG upstream not started:"),
            "new native WireGuard apply failure must propagate"
        );
        assert!(
            !production.contains("if let Some(existing) = self.wg_upstream.take()"),
            "cleanup must retain the owned handle until teardown succeeds"
        );
        assert!(
            production.contains("windows_fips_finish_cleanup"),
            "stop must aggregate route, service, config, session, and endpoint failures"
        );
    }

    #[test]
    fn windows_reload_verifies_wireguard_before_routes_and_direct_dns_teardown() {
        let source = include_str!("tunnel_runtime_windows.rs");
        let apply = source
            .split("pub(crate) async fn apply_config")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) async fn refresh_peer_dependent_routes").next())
            .expect("Windows apply_config source");
        let wireguard = apply
            .find("self.reconcile_windows_wg_upstream")
            .expect("WireGuard reconcile");
        let peer_update = apply
            .find("self.mesh.update_peers")
            .expect("FIPS peer update");
        let routes = apply
            .find("self.apply_windows_route_config")
            .expect("FIPS route reconcile");
        let secure_dns_stop = apply
            .find("let cleanup = secure_dns.stop().await")
            .expect("direct DNS teardown");
        assert!(
            wireguard < peer_update && peer_update < routes && routes < secure_dns_stop,
            "refresh matching WG underlay before awaited peer control; failed WG must leave routes \
             untouched, while Direct cleans WG before restoring DNS"
        );
        let reconcile = source
            .split("async fn reconcile_windows_wg_upstream")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) async fn stop").next())
            .expect("Windows WireGuard reconcile source");
        let direct_cleanup = reconcile
            .split("if !want_up")
            .nth(1)
            .expect("Direct cleanup branch");
        assert!(
            direct_cleanup.contains("retry_pending_windows_native_cleanup_journaled")
                && direct_cleanup.contains("retry_pending_windows_route_cleanup_journaled"),
            "Direct must not restore DNS while orphaned native WG or routes remain"
        );
    }
}
