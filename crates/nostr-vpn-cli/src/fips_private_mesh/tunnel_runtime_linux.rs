#[cfg(target_os = "linux")]
fn linux_route_targets_require_ip_endpoint_bypass(route_targets: &[String]) -> bool {
    crate::route_targets_require_endpoint_bypass(route_targets)
}

#[cfg(any(target_os = "linux", test))]
fn linux_withhold_default_route_for_missing_peer_endpoint(
    route_targets: &[String],
    peer_endpoint_hosts: &[Ipv4Addr],
    ethernet_underlay_configured: bool,
) -> bool {
    !ethernet_underlay_configured
        && peer_endpoint_hosts.is_empty()
        && route_targets.iter().any(|route| route == "0.0.0.0/0")
}

#[cfg(any(target_os = "linux", test))]
fn linux_reuse_cached_underlay_route(
    original_default_route: &mut Option<String>,
    cached_route: Option<&str>,
    interface: &str,
) -> bool {
    let Some(route) = cached_route else {
        return false;
    };
    let mut tokens = route.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            if tokens.next() != Some(interface) {
                return false;
            }
            *original_default_route = Some(route.to_string());
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "linux", test))]
fn linux_strict_exit_requested(route_targets: &[String], exit_node_leak_protection: bool) -> bool {
    exit_node_leak_protection
        && route_targets
            .iter()
            .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

#[cfg(any(target_os = "linux", test))]
fn linux_ipv4_underlay_capture_requested(
    route_targets: &[String],
    wireguard_exit_enabled: bool,
) -> bool {
    wireguard_exit_enabled || route_targets.iter().any(|route| route == "0.0.0.0/0")
}

#[cfg(any(target_os = "linux", test))]
fn linux_missing_ipv4_underlay_route_allowed(
    ethernet_underlay_configured: bool,
    wireguard_exit_enabled: bool,
) -> bool {
    ethernet_underlay_configured && !wireguard_exit_enabled
}

#[cfg(any(target_os = "linux", test))]
fn linux_ipv4_underlay_restore_due(
    requested_ipv4_exit: bool,
    active_mesh_ipv4_exit: bool,
    wireguard_exit_enabled: bool,
    strict_exit: bool,
) -> bool {
    requested_ipv4_exit
        && !active_mesh_ipv4_exit
        && !wireguard_exit_enabled
        && !strict_exit
}

#[cfg(any(target_os = "linux", test))]
trait LinuxEndpointBypassTarget {
    fn endpoint_bypass_target(&self) -> &str;
}

#[cfg(any(target_os = "linux", test))]
impl LinuxEndpointBypassTarget for String {
    fn endpoint_bypass_target(&self) -> &str {
        self
    }
}

#[cfg(any(target_os = "linux", test))]
impl LinuxEndpointBypassTarget for crate::LinuxManagedEndpointBypassRoute {
    fn endpoint_bypass_target(&self) -> &str {
        &self.route.target
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_endpoint_bypass_hosts_unchanged<T: LinuxEndpointBypassTarget>(
    current_routes: &[T],
    desired_hosts: &[Ipv4Addr],
) -> bool {
    let current_targets = current_routes
        .iter()
        .map(|managed| managed.endpoint_bypass_target().to_string())
        .collect::<std::collections::HashSet<_>>();
    let desired_targets = desired_hosts
        .iter()
        .map(|host| format!("{host}/32"))
        .collect::<std::collections::HashSet<_>>();
    current_targets == desired_targets
}

#[cfg(target_os = "linux")]
fn linux_control_only_network_intent(config: &FipsPrivateTunnelConfig) -> bool {
    config.route_targets.is_empty()
        && config.fips_host.is_none()
        && config.local_exit_forwarding_routes.is_empty()
        && !config.wireguard_exit.enabled
}

#[cfg(target_os = "linux")]
fn linux_exit_node_runtime_is_inactive(runtime: &crate::LinuxExitNodeRuntime) -> bool {
    runtime.ipv4_outbound_iface.is_none()
        && runtime.ipv6_outbound_iface.is_none()
        && runtime.ipv4_tunnel_source_cidr.is_none()
        && runtime.ipv4_mss_clamp.is_none()
        && runtime.ipv4_forward_was_enabled.is_none()
        && runtime.ipv6_forward_was_enabled.is_none()
        && runtime.wireguard_exit.is_none()
        && runtime.pending_wireguard_exit_cleanup.is_empty()
}

#[cfg(target_os = "linux")]
pub(crate) fn retain_linux_wireguard_apply_cleanup(
    runtime: &mut crate::LinuxExitNodeRuntime,
    previous_runtime: Option<&crate::LinuxWireGuardExitRuntime>,
    obligation: &crate::LinuxWireGuardExitCleanupObligation,
) {
    runtime.wireguard_exit = previous_runtime.cloned();
    runtime.pending_wireguard_exit_cleanup = vec![obligation.clone()];
}

#[cfg(target_os = "linux")]
impl FipsPrivateTunnelRuntime {
    async fn apply_linux_network_state(&mut self, config: &FipsPrivateTunnelConfig) -> Result<()> {
        let requested_ipv4_exit =
            linux_ipv4_underlay_capture_requested(&config.route_targets, config.wireguard_exit.enabled);
        let requested_ipv6_exit = config.route_targets.iter().any(|route| route == "::/0")
            || (config.wireguard_exit.enabled
                && crate::linux_wireguard_exit_ipv6_default(&config.wireguard_exit));
        let mut route_targets = effective_fips_route_targets(config, &self.mesh.peer_statuses());
        let strict_exit =
            linux_strict_exit_requested(&route_targets, config.exit_node_leak_protection);
        let original_route_targets_require_bypass =
            linux_route_targets_require_ip_endpoint_bypass(&route_targets);
        let mut peer_endpoint_hosts = Vec::new();
        if original_route_targets_require_bypass {
            peer_endpoint_hosts = self.endpoint_bypass_ipv4_hosts(config).await?;
            if linux_withhold_default_route_for_missing_peer_endpoint(
                &route_targets,
                &peer_endpoint_hosts,
                config.ethernet_underlay.is_some(),
            ) {
                eprintln!(
                    "fips: withholding default route until the selected exit peer underlay endpoint is known"
                );
                route_targets.retain(|route| !crate::is_exit_node_route(route));
            }
        }

        let active_ipv4_exit = route_targets.iter().any(|route| route == "0.0.0.0/0");
        let active_ipv6_exit = route_targets.iter().any(|route| route == "::/0");

        if requested_ipv4_exit {
            self.capture_linux_original_default_route(
                config.underlay_interface.as_deref(),
                linux_missing_ipv4_underlay_route_allowed(
                    config.ethernet_underlay.is_some(),
                    config.wireguard_exit.enabled,
                ),
            )?;
        } else {
            self.restore_linux_original_default_route();
        }
        if requested_ipv6_exit {
            self.capture_linux_original_default_ipv6_route(config.underlay_interface.as_deref())?;
        } else {
            self.restore_linux_original_default_ipv6_route();
        }
        if linux_ipv4_underlay_restore_due(
            requested_ipv4_exit,
            active_ipv4_exit,
            config.wireguard_exit.enabled,
            strict_exit,
        ) {
            self.restore_linux_original_default_route();
        }
        if !strict_exit
            && requested_ipv6_exit
            && !active_ipv6_exit
            && !crate::linux_wireguard_exit_ipv6_default(&config.wireguard_exit)
        {
            self.restore_linux_original_default_ipv6_route();
        }
        // The saved physical defaults are the only information that can
        // restore native internet after a hard crash. Fsync them before any
        // endpoint, interface, split-default, firewall, or forwarding
        // mutation below.
        self.persist_network_cleanup_ownership()?;

        let endpoint_bypass_specs = if original_route_targets_require_bypass || strict_exit {
            let mut bypass_hosts = config.control_plane_bypass_hosts.clone();
            bypass_hosts.extend(peer_endpoint_hosts);
            bypass_hosts.sort_unstable();
            bypass_hosts.dedup();
            crate::linux_bypass_route_specs_for_hosts(
                bypass_hosts,
                &self.iface,
                self.original_default_route.as_deref(),
            )?
        } else {
            Vec::new()
        };
        self.reconcile_linux_endpoint_bypass_routes(&endpoint_bypass_specs)?;

        let interface_route_targets = config.interface_route_targets(route_targets.clone());
        let interface_addresses = config.interface_addresses();
        // A control-only node has no managed routes or forwarding state to
        // reconcile. Audit the actual TUN state before mutating it so our own
        // idempotent-looking `ip` commands cannot create a netlink refresh loop.
        // A missing address, changed MTU/queue, or down link still falls through
        // to the normal restoration path.
        let unchanged_control_only_state = self.linux_network_state_initialized
            && linux_control_only_network_intent(&self.config)
            && linux_control_only_network_intent(config)
            && self.config.interface_addresses() == interface_addresses
            && self.config.interface_mtu() == config.interface_mtu()
            && endpoint_bypass_specs.is_empty()
            && self.endpoint_bypass_routes.is_empty()
            && self.original_default_route.is_none()
            && self.original_default_ipv6_route.is_none()
            && linux_exit_node_runtime_is_inactive(&self.exit_node_runtime)
            && linux_interface_state_matches(
                &self.iface,
                &interface_addresses,
                config.interface_mtu(),
                linux_tun_tx_queue_len(),
            );
        if unchanged_control_only_state {
            return Ok(());
        }
        // WireGuard cleanup restores its saved physical default. Delay it
        // until all awaited/fallible preparation is complete, then block that
        // default synchronously in strict mode before applying replacement
        // private-FIPS routes. No fallible preparation may be inserted here.
        if !config.wireguard_exit.enabled {
            let mut failures = Vec::new();
            if let Err(error) = self.cleanup_linux_wireguard_exit_upstream() {
                failures.push(format!("WireGuard cleanup: {error:#}"));
            }
            if strict_exit && requested_ipv4_exit
                && let Err(error) = self.block_linux_original_default_route_checked(false)
            {
                failures.push(format!("IPv4 default block: {error:#}"));
            }
            if strict_exit && requested_ipv6_exit
                && let Err(error) = self.block_linux_original_default_route_checked(true)
            {
                failures.push(format!("IPv6 default block: {error:#}"));
            }
            if !failures.is_empty() {
                return Err(anyhow!(
                    "Linux WireGuard exit handoff incomplete: {}",
                    failures.join("; ")
                ));
            }
        }
        crate::apply_local_interface_network_with_mtu_and_addresses(
            &self.iface,
            &interface_addresses,
            &interface_route_targets,
            config.interface_mtu(),
        )
        .with_context(|| format!("failed to configure FIPS tunnel interface {}", self.iface))?;
        apply_linux_tun_tx_queue_len(&self.iface)?;
        if let Err(error) = crate::flush_linux_route_cache() {
            eprintln!("fips: failed to flush linux route cache: {error}");
        }
        if strict_exit {
            if requested_ipv4_exit && !active_ipv4_exit {
                self.block_linux_original_default_route(false);
            }
            if requested_ipv6_exit && !active_ipv6_exit {
                self.block_linux_original_default_route(true);
            }
        }
        self.reconcile_linux_exit_node_forwarding(
            config,
            local_exit_seller_egress_ready(
                config,
                &connected_peer_pubkeys(&self.mesh.peer_statuses()),
                self.exit_node_runtime.wireguard_exit.is_some(),
                self.active_listen_port,
            ),
        )?;
        self.linux_network_state_initialized = true;
        Ok(())
    }

    fn capture_linux_original_default_route(
        &mut self,
        underlay_interface: Option<&str>,
        allow_missing: bool,
    ) -> Result<()> {
        if underlay_interface.is_none() {
            self.ethernet_underlay_default_route = None;
            if self.original_default_route.is_some() {
                return Ok(());
            }
            if allow_missing {
                return Ok(());
            }
        }
        let route = match underlay_interface {
            Some(interface) => {
                match crate::linux_current_default_route_for_interface(interface)
                    .with_context(|| {
                        format!("failed to inspect IPv4 underlay route on {interface}")
                    })? {
                    Some(route) => Some(route),
                    None => {
                        if linux_reuse_cached_underlay_route(
                            &mut self.original_default_route,
                            self.ethernet_underlay_default_route.as_deref(),
                            interface,
                        ) {
                            return Ok(());
                        }
                        self.exit_node_runtime
                            .wireguard_exit
                            .as_ref()
                            .and_then(|runtime| {
                                runtime.underlay_default_route_for_interface(interface)
                            })
                            .map_or_else(
                                || {
                                    if allow_missing {
                                        Ok(None)
                                    } else {
                                        Err(anyhow!(
                                            "failed to resolve IPv4 underlay route on {interface}"
                                        ))
                                    }
                                },
                                |route| Ok(Some(route)),
                            )?
                    }
                }
            }
            None => match crate::linux_default_route() {
                Ok(route) => Some(route),
                Err(error) => {
                    eprintln!("fips: failed to capture original default route: {error}");
                    return Ok(());
                }
            },
        };
        let Some(route) = route else {
            return Ok(());
        };
        crate::update_linux_underlay_default_route(
            &mut self.original_default_route,
            route,
            &self.iface,
        )
        .context("failed to update cached IPv4 underlay route")?;
        if underlay_interface.is_some() {
            self.ethernet_underlay_default_route
                .clone_from(&self.original_default_route);
        }
        Ok(())
    }

    pub(crate) fn linux_underlay_default_route_hints(&self) -> Vec<String> {
        if let Some(runtime) = self.exit_node_runtime.wireguard_exit.as_ref() {
            return runtime.underlay_default_route_hints().to_vec();
        }
        let mut routes = self
            .original_default_route
            .iter()
            .chain(self.ethernet_underlay_default_route.iter())
            .cloned()
            .collect::<Vec<_>>();
        routes.sort();
        routes.dedup();
        routes
    }

    fn capture_linux_original_default_ipv6_route(
        &mut self,
        underlay_interface: Option<&str>,
    ) -> Result<()> {
        if underlay_interface.is_none() && self.original_default_ipv6_route.is_some() {
            return Ok(());
        }
        let route = match underlay_interface {
            Some(interface) => crate::linux_default_ipv6_route_for_interface(interface)
                .with_context(|| format!("failed to refresh IPv6 underlay route on {interface}"))?,
            None => match crate::linux_default_ipv6_route() {
                Ok(route) => route,
                Err(error) => {
                    eprintln!("fips: failed to capture original IPv6 default route: {error}");
                    return Ok(());
                }
            },
        };
        crate::update_linux_underlay_default_route(
            &mut self.original_default_ipv6_route,
            route,
            &self.iface,
        )
        .context("failed to update cached IPv6 underlay route")
    }

    fn restore_linux_original_default_route(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_route, false, &owned);
    }

    fn restore_linux_original_default_ipv6_route(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_ipv6_route, true, &owned);
    }

    fn block_linux_original_default_route(&mut self, ipv6: bool) {
        if let Err(error) = self.block_linux_original_default_route_checked(ipv6) {
            let family = if ipv6 { "IPv6" } else { "IPv4" };
            eprintln!("fips: failed to block {family} default route: {error:#}");
        }
    }

    fn block_linux_original_default_route_checked(&mut self, ipv6: bool) -> Result<()> {
        let family = if ipv6 { "IPv6" } else { "IPv4" };
        let current = if ipv6 {
            crate::linux_current_default_ipv6_route()
        } else {
            crate::linux_current_default_route()
        }
        .with_context(|| format!("failed to inspect {family} default route before blocking it"))?;
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        if current.is_some_and(|route| !owned.contains(&route.dev)) {
            let deleted = if ipv6 {
                crate::delete_linux_default_ipv6_route()
            } else {
                crate::delete_linux_default_route()
            };
            deleted.with_context(|| format!("failed to delete {family} default route"))?;
        }
        Ok(())
    }

    fn reconcile_linux_endpoint_bypass_routes(
        &mut self,
        routes: &[crate::LinuxEndpointBypassRoute],
    ) -> Result<()> {
        let mut desired = routes.to_vec();
        desired.sort_by(|left, right| left.target.cmp(&right.target));
        desired.dedup_by(|left, right| left.target == right.target);
        let desired_targets = desired
            .iter()
            .map(|route| route.target.clone())
            .collect::<std::collections::HashSet<_>>();

        // Secure every fresh identity before restoring stale identities so an
        // underlay handoff never drops all transport bypasses at once.
        for route in desired {
            let current = crate::linux_endpoint_bypass_route_snapshot(&route.target)?;
            let current_is_desired = current.len() == 1
                && crate::linux_endpoint_bypass_route_matches_line(&route, &current[0]);
            if let Some(index) = self
                .endpoint_bypass_routes
                .iter()
                .position(|managed| managed.route.target == route.target)
            {
                if current_is_desired {
                    self.endpoint_bypass_routes[index].route = route;
                    continue;
                }
                let previous_managed = self.endpoint_bypass_routes[index].route.clone();
                let current_is_previous = current.len() == 1
                    && crate::linux_endpoint_bypass_route_matches_line(
                        &previous_managed,
                        &current[0],
                    );
                if !current.is_empty() && !current_is_previous {
                    return Err(anyhow!(
                        "refusing to overwrite drifted unowned endpoint route {}: {:?}",
                        route.target,
                        current
                    ));
                }
                {
                    let managed = &mut self.endpoint_bypass_routes[index];
                    if !managed.owned {
                        managed.previous_routes = current;
                        managed.owned = true;
                    }
                    managed.route = route;
                }
                self.apply_linux_endpoint_bypass_route(index)?;
                continue;
            }

            if current_is_desired {
                self.endpoint_bypass_routes
                    .push(crate::LinuxManagedEndpointBypassRoute {
                        route,
                        previous_routes: current,
                        owned: false,
                    });
                continue;
            }
            if current.len() > 1 {
                return Err(anyhow!(
                    "refusing to replace ambiguous endpoint route identity {}: {:?}",
                    route.target,
                    current
                ));
            }
            self.endpoint_bypass_routes
                .push(crate::LinuxManagedEndpointBypassRoute {
                    route,
                    previous_routes: current,
                    owned: true,
                });
            self.apply_linux_endpoint_bypass_route(self.endpoint_bypass_routes.len() - 1)?;
        }

        let mut failures = Vec::new();
        let mut index = 0;
        while index < self.endpoint_bypass_routes.len() {
            if desired_targets.contains(&self.endpoint_bypass_routes[index].route.target) {
                index += 1;
                continue;
            }
            match crate::restore_linux_managed_endpoint_bypass_route(
                &self.endpoint_bypass_routes[index],
            ) {
                Ok(()) => {
                    self.endpoint_bypass_routes.remove(index);
                }
                Err(error) => {
                    failures.push(format!(
                        "{}: {error:#}",
                        self.endpoint_bypass_routes[index].route.target
                    ));
                    index += 1;
                }
            }
        }
        self.endpoint_bypass_routes
            .sort_by(|left, right| left.route.target.cmp(&right.route.target));
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "failed to restore stale endpoint bypass routes: {}",
                failures.join("; ")
            ))
        }
    }

    fn apply_linux_endpoint_bypass_route(&self, index: usize) -> Result<()> {
        self.persist_network_cleanup_ownership()?;
        let route = &self.endpoint_bypass_routes[index].route;
        crate::apply_linux_endpoint_bypass_route(route).with_context(|| {
            format!("failed to install endpoint bypass route {}", route.target)
        })
    }

    include!("tunnel_runtime_linux/exit_upstream.rs");
}

#[cfg(target_os = "linux")]
fn apply_linux_tun_tx_queue_len(iface: &str) -> Result<()> {
    let Some(queue_len) = linux_tun_tx_queue_len() else {
        return Ok(());
    };
    let queue_len = queue_len.to_string();
    crate::run_checked(
        ProcessCommand::new("ip")
            .args(["link", "set", "dev", iface, "txqueuelen", &queue_len]),
    )
    .with_context(|| format!("failed to set Linux tunnel txqueuelen on {iface}"))?;
    eprintln!("fips: Linux tunnel txqueuelen set on {iface}; txqueuelen={queue_len}");
    Ok(())
}
