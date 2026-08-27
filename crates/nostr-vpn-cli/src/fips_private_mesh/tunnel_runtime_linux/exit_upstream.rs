#[cfg(target_os = "linux")]
impl FipsPrivateTunnelRuntime {
    fn reconcile_linux_exit_node_forwarding(
        &mut self,
        config: &FipsPrivateTunnelConfig,
        seller_egress_ready: bool,
    ) -> Result<()> {
        let local_address = config.local_address.as_str();
        let seller_egress = config.local_exit_seller_egress.as_ref();
        let wireguard_exit = &config.wireguard_exit;
        let ipv4_mss_clamp = exit_node_ipv4_mss_clamp(config.mesh_mtu.tunnel);
        let mut route_families =
            crate::linux_exit_node_default_route_families(&config.local_exit_forwarding_routes);
        if route_families.ipv6 {
            eprintln!(
                "fips: IPv6 exit-node forwarding is disabled until nvpn has IPv6 mesh source filtering"
            );
            route_families.ipv6 = false;
        }
        // WG upstream as this host's own egress does not imply mesh
        // exit-node forwarding. Only advertised default routes should
        // turn on ip_forward/NAT below.
        let needs_ipv4_tunnel_source = route_families.ipv4 || wireguard_exit.enabled;
        let ipv4_tunnel_source_cidr = if needs_ipv4_tunnel_source {
            let Some(tunnel_source_cidr) = crate::linux_exit_node_source_cidr(local_address) else {
                self.reconcile_linux_exit_node_forwarding_cleanup()?;
                return Err(anyhow!(
                    "invalid IPv4 tunnel address '{local_address}' for exit forwarding"
                ));
            };
            Some(tunnel_source_cidr)
        } else {
            None
        };

        let wireguard_exit_iface = if wireguard_exit.enabled {
            let Some(source_cidr) = ipv4_tunnel_source_cidr.as_deref() else {
                self.reconcile_linux_exit_node_forwarding_cleanup()?;
                return Err(anyhow!("WireGuard exit has no IPv4 tunnel source"));
            };
            match crate::validate_linux_wireguard_exit_config(wireguard_exit) {
                Ok(iface) => {
                    if !crate::linux_wireguard_exit_ipv6_default(wireguard_exit) {
                        route_families.ipv6 = false;
                    }
                    if let Err(error) =
                        self.apply_linux_wireguard_exit_upstream(wireguard_exit, source_cidr)
                    {
                        let _ = self.cleanup_linux_exit_node_forwarding_rules();
                        self.block_linux_wireguard_exit_if_strict(config.exit_node_leak_protection);
                        return Err(error).context("failed to configure WireGuard exit upstream");
                    }
                    Some((iface, source_cidr.to_string()))
                }
                Err(error) => {
                    let _ = self.cleanup_linux_exit_node_forwarding_rules();
                    self.cleanup_linux_wireguard_exit_upstream()?;
                    self.block_linux_wireguard_exit_if_strict(
                        config.exit_node_leak_protection && wireguard_exit.enabled,
                    );
                    return Err(error).context("WireGuard exit upstream is not ready");
                }
            }
        } else {
            self.cleanup_linux_wireguard_exit_upstream()?;
            None
        };

        if !route_families.ipv4 && !route_families.ipv6 {
            self.cleanup_linux_exit_node_forwarding_rules()?;
            return Ok(());
        }

        let seller_egress_ready = match seller_egress {
            Some(PaidExitSellerEgress::WireGuard) => wireguard_exit_iface.is_some(),
            Some(PaidExitSellerEgress::Direct | PaidExitSellerEgress::PrivatePeer { .. }) => {
                seller_egress_ready
            }
            None => false,
        };
        if !seller_egress_ready {
            self.cleanup_linux_exit_node_forwarding_rules()?;
            return Ok(());
        }

        let ipv4_outbound_iface = if route_families.ipv4 {
            let host_default_iface = if matches!(seller_egress, Some(PaidExitSellerEgress::Direct))
            {
                match crate::linux_default_route() {
                    Ok(route) => Some(route.dev),
                    Err(error) => {
                        let _ = self.cleanup_linux_exit_node_forwarding_rules();
                        return Err(error).context("failed to resolve default IPv4 route device");
                    }
                }
            } else {
                None
            };
            local_exit_outbound_interface(
                seller_egress,
                &self.iface,
                wireguard_exit_iface
                    .as_ref()
                    .map(|(iface, _)| iface.as_str()),
                host_default_iface.as_deref(),
            )
        } else {
            None
        };

        let ipv6_outbound_iface = None;

        let already_configured = self.exit_node_runtime.ipv4_outbound_iface == ipv4_outbound_iface
            && self.exit_node_runtime.ipv6_outbound_iface == ipv6_outbound_iface
            && self.exit_node_runtime.ipv4_tunnel_source_cidr == ipv4_tunnel_source_cidr
            && self.exit_node_runtime.ipv4_mss_clamp == Some(ipv4_mss_clamp);
        if already_configured {
            return Ok(());
        }

        self.cleanup_linux_exit_node_forwarding_rules()?;

        self.exit_node_runtime.ipv4_outbound_iface = ipv4_outbound_iface.clone();
        self.exit_node_runtime.ipv6_outbound_iface = ipv6_outbound_iface.clone();
        self.exit_node_runtime.ipv4_tunnel_source_cidr = ipv4_tunnel_source_cidr.clone();
        self.exit_node_runtime.ipv4_mss_clamp = Some(ipv4_mss_clamp);
        self.persist_network_cleanup_ownership()?;

        if route_families.ipv4 {
            match crate::read_linux_ip_forward(crate::LinuxExitNodeIpFamily::V4) {
                Ok(previous) => {
                    self.exit_node_runtime.ipv4_forward_was_enabled = Some(previous);
                    self.persist_network_cleanup_ownership()?;
                    if !previous
                        && let Err(error) =
                            crate::write_linux_ip_forward(crate::LinuxExitNodeIpFamily::V4, true)
                    {
                        let _ = self.cleanup_linux_exit_node_forwarding_rules();
                        return Err(error).context("failed to enable IPv4 forwarding");
                    }
                }
                Err(error) => {
                    let _ = self.cleanup_linux_exit_node_forwarding_rules();
                    return Err(error).context("failed to read IPv4 forwarding state");
                }
            }
        }

        if let (Some(outbound_iface), Some(tunnel_source_cidr)) = (
            ipv4_outbound_iface.as_deref(),
            ipv4_tunnel_source_cidr.as_deref(),
        ) {
            eprintln!(
                "fips: enabling IPv4 exit forwarding on {} via {} source {}",
                self.iface, outbound_iface, tunnel_source_cidr
            );
            self.cleanup_linux_legacy_exit_node_forwarding_rules()?;
            let forward_in = crate::linux_exit_node_forward_in_rule(
                &self.iface,
                outbound_iface,
                tunnel_source_cidr,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let forward_out = crate::linux_exit_node_forward_out_rule(
                &self.iface,
                outbound_iface,
                crate::LinuxExitNodeIpFamily::V4,
            );
            let masquerade =
                crate::linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);
            let mss_clamp = crate::linux_exit_node_ipv4_mss_clamp_rule(
                &self.iface,
                outbound_iface,
                tunnel_source_cidr,
                ipv4_mss_clamp,
            );

            if let Err(error) = crate::linux_iptables_ensure_rule_at_front(
                crate::LinuxExitNodeIpFamily::V4,
                None,
                &forward_in,
            )
            .and_then(|()| {
                crate::linux_iptables_ensure_rule_at_front(
                    crate::LinuxExitNodeIpFamily::V4,
                    None,
                    &forward_out,
                )
            })
            .and_then(|()| {
                crate::linux_iptables_ensure_rule(
                    crate::LinuxExitNodeIpFamily::V4,
                    Some("nat"),
                    &masquerade,
                )
            })
            .and_then(|()| {
                crate::linux_iptables_ensure_rule_at_front(
                    crate::LinuxExitNodeIpFamily::V4,
                    Some("mangle"),
                    &mss_clamp,
                )
            }) {
                let _ = self.cleanup_linux_exit_node_forwarding_rules();
                return Err(error).context("failed to install IPv4 exit firewall rules");
            }
        }

        self.cleanup_linux_legacy_exit_node_forwarding_rules()?;
        Ok(())
    }

    fn apply_linux_wireguard_exit_upstream(
        &mut self,
        config: &WireGuardExitConfig,
        source_cidr: &str,
    ) -> Result<()> {
        self.cleanup_pending_linux_wireguard_exit_obligations()
            .context("retry incomplete prior WireGuard apply cleanup")?;
        let mut previous_runtime = self.exit_node_runtime.wireguard_exit.clone();
        if previous_runtime.as_ref().is_some_and(|runtime| {
            runtime.interface != config.interface.trim()
                || runtime.managed_address != config.address.trim()
                || runtime.source_cidr != source_cidr
        }) {
            let runtime = self
                .exit_node_runtime
                .wireguard_exit
                .take()
                .expect("checked WireGuard runtime");
            previous_runtime = None;
            if let Err(error) = self.cleanup_detached_linux_wireguard_exit_upstream(&runtime) {
                self.exit_node_runtime.wireguard_exit = Some(runtime);
                return Err(error);
            }
        }
        if let Some(runtime) = previous_runtime.as_mut()
            && let Some(refreshed_default) = crate::select_linux_wireguard_underlay_default_route(
                self.original_default_route.as_deref(),
                runtime.previous_default_route.as_deref(),
                None,
                config.interface.trim(),
            )
        {
            runtime.refresh_underlay_default_route(refreshed_default);
        }
        let original_default_route = self.original_default_route.clone();
        let mesh_iface = self.iface.clone();
        let apply_result = {
            let mut persist_cleanup_intent =
                |obligation: &crate::LinuxWireGuardExitCleanupObligation| {
                    retain_linux_wireguard_apply_cleanup(
                        &mut self.exit_node_runtime,
                        previous_runtime.as_ref(),
                        obligation,
                    );
                    self.persist_network_cleanup_ownership()
                };
            crate::apply_linux_wireguard_exit_upstream(
                config,
                source_cidr,
                &mesh_iface,
                previous_runtime.as_ref(),
                original_default_route.as_deref(),
                &mut persist_cleanup_intent,
            )
        };
        let runtime = match apply_result {
            Ok(runtime) => runtime,
            Err(failure) => {
                let (error, cleanup_obligation) = failure.into_parts();
                if let Some(obligation) = cleanup_obligation {
                    self.exit_node_runtime
                        .pending_wireguard_exit_cleanup
                        .clear();
                    self.exit_node_runtime
                        .pending_wireguard_exit_cleanup
                        .push(obligation);
                    self.exit_node_runtime.wireguard_exit = previous_runtime;
                    return match self.persist_network_cleanup_ownership() {
                        Ok(()) => Err(error),
                        Err(persist) => Err(anyhow!(
                            "{error:#}; failed to persist remaining WireGuard cleanup \
                             ownership: {persist:#}"
                        )),
                    };
                }
                self.exit_node_runtime
                    .pending_wireguard_exit_cleanup
                    .clear();
                if let Some(runtime) = previous_runtime.take() {
                    self.exit_node_runtime.wireguard_exit = None;
                    if let Err(cleanup) =
                        self.cleanup_detached_linux_wireguard_exit_upstream(&runtime)
                    {
                        self.exit_node_runtime.wireguard_exit = Some(runtime);
                        return Err(anyhow!(
                            "{error:#}; failed to clean previous WireGuard runtime: {cleanup:#}"
                        ));
                    }
                }
                return match self.persist_network_cleanup_ownership() {
                    Ok(()) => Err(error),
                    Err(persist) => Err(anyhow!(
                        "{error:#}; failed to persist completed WireGuard rollback: {persist:#}"
                    )),
                };
            }
        };
        self.exit_node_runtime
            .pending_wireguard_exit_cleanup
            .clear();
        self.exit_node_runtime.wireguard_exit = Some(runtime);
        // Persist the complete runtime before the inbound firewall mutation.
        // The conservative apply rollback remains on disk if this replacement
        // fails, so either journal can restore native internet after a crash.
        self.persist_network_cleanup_ownership()?;
        let inbound_guard = self
            .exit_node_runtime
            .wireguard_exit
            .as_ref()
            .ok_or_else(|| anyhow!("WireGuard runtime disappeared before inbound guard"))
            .and_then(|runtime| self.ensure_linux_wireguard_exit_inbound_guard(runtime));
        if let Err(error) = inbound_guard {
            let runtime = self
                .exit_node_runtime
                .wireguard_exit
                .take()
                .expect("WireGuard runtime exists for inbound-guard rollback");
            if let Err(cleanup) = self.cleanup_detached_linux_wireguard_exit_upstream(&runtime) {
                self.exit_node_runtime.wireguard_exit = Some(runtime);
                let persist = self.persist_network_cleanup_ownership().err();
                return Err(match persist {
                    Some(persist) => anyhow!(
                        "{error:#}; failed to roll back WireGuard after inbound-guard failure \
                         ({cleanup:#}); failed to persist remaining ownership ({persist:#})"
                    ),
                    None => anyhow!(
                        "{error:#}; failed to roll back WireGuard after inbound-guard failure: \
                         {cleanup:#}"
                    ),
                });
            }
            self.persist_network_cleanup_ownership()?;
            return Err(error);
        }
        self.persist_network_cleanup_ownership()?;
        Ok(())
    }

    fn ensure_linux_wireguard_exit_inbound_guard(
        &self,
        runtime: &crate::LinuxWireGuardExitRuntime,
    ) -> Result<()> {
        let drop_inbound = crate::linux_wireguard_exit_inbound_drop_rule(
            &runtime.interface,
            &self.iface,
            &runtime.source_cidr,
        );
        crate::linux_iptables_ensure_rule_at_front(
            crate::LinuxExitNodeIpFamily::V4,
            None,
            &drop_inbound,
        )
    }

    fn cleanup_linux_wireguard_exit_inbound_guard(
        &self,
        runtime: &crate::LinuxWireGuardExitRuntime,
    ) -> Result<()> {
        let drop_inbound = crate::linux_wireguard_exit_inbound_drop_rule(
            &runtime.interface,
            &self.iface,
            &runtime.source_cidr,
        );
        let mut last_error = None;
        for _ in 0..3 {
            match crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                None,
                &drop_inbound,
            ) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("bounded inbound-guard cleanup attempted"))
            .context("failed to remove WireGuard inbound guard rule after three attempts")
    }

    fn block_linux_wireguard_exit_if_strict(&mut self, enabled: bool) {
        if !enabled {
            return;
        }
        if let Err(error) = self.capture_linux_original_default_route(None, false) {
            eprintln!("fips: failed to capture WireGuard underlay default route: {error:#}");
        }
        if let Err(error) = self.persist_network_cleanup_ownership() {
            eprintln!(
                "fips: refusing to block the Linux default route without durable cleanup \
                 ownership: {error:#}"
            );
            return;
        }
        self.block_linux_original_default_route(false);
    }

    fn cleanup_linux_wireguard_exit_upstream(&mut self) -> Result<()> {
        let iface = self.iface.clone();
        cleanup_linux_wireguard_state(&iface, &mut self.exit_node_runtime)
    }

    fn cleanup_pending_linux_wireguard_exit_obligations(&mut self) -> Result<()> {
        let pending = std::mem::take(
            &mut self
                .exit_node_runtime
                .pending_wireguard_exit_cleanup,
        );
        let mut remaining = Vec::new();
        let mut failures = Vec::new();
        for mut obligation in pending {
            if let Err(error) =
                crate::cleanup_linux_wireguard_exit_obligation(&mut obligation)
            {
                failures.push(format!("{error:#}"));
                remaining.push(obligation);
            }
        }
        self.exit_node_runtime.pending_wireguard_exit_cleanup = remaining;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "retained WireGuard apply cleanup incomplete: {}",
                failures.join("; ")
            ))
        }
    }

    fn cleanup_detached_linux_wireguard_exit_upstream(
        &self,
        runtime: &crate::LinuxWireGuardExitRuntime,
    ) -> Result<()> {
        let guard = self.cleanup_linux_wireguard_exit_inbound_guard(runtime);
        let network = crate::cleanup_linux_wireguard_exit_upstream(runtime);
        match (guard, network) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(guard), Ok(())) => Err(guard),
            (Ok(()), Err(network)) => Err(network),
            (Err(guard), Err(network)) => Err(anyhow!(
                "inbound guard cleanup failed ({guard:#}); network cleanup failed ({network:#})"
            )),
        }
    }

    fn cleanup_linux_exit_node_forwarding_rules(&mut self) -> Result<()> {
        let iface = self.iface.clone();
        cleanup_linux_forwarding_state(&iface, &mut self.exit_node_runtime)
    }

    fn cleanup_linux_legacy_exit_node_forwarding_rules(&self) -> Result<()> {
        cleanup_linux_legacy_forwarding_rules(&self.iface)
    }

    fn reconcile_linux_exit_node_forwarding_cleanup(&mut self) -> Result<()> {
        let iface = self.iface.clone();
        cleanup_linux_exit_node_state(&iface, &mut self.exit_node_runtime)
    }

    fn cleanup_linux_network_state(&mut self) -> Result<()> {
        self.linux_network_state_initialized = false;
        cleanup_linux_network_state_with_actions(self)
    }
}
