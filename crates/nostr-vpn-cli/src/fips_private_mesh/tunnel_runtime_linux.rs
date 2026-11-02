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
        use crate::linux_exit_guard::{ForwardedExit, GuardRoute};

        let route_targets = effective_fips_route_targets(config, &self.mesh.peer_statuses());
        let interface_routes = config.interface_route_targets(route_targets);
        let interface_addresses = config.interface_addresses();
        let main_routes = interface_routes
            .iter()
            .filter(|route| !crate::is_exit_node_route(route))
            .cloned()
            .collect::<Vec<_>>();
        // Physical defaults and endpoint host routes belong to the network
        // manager. Carrier sockets select them with SO_MARK; application
        // defaults live only in the owned policy table.
        let unchanged_control_only_state = self.linux_network_state_initialized
            && linux_control_only_network_intent(&self.config)
            && linux_control_only_network_intent(config)
            && self.config.interface_addresses() == interface_addresses
            && self.config.interface_mtu() == config.interface_mtu()
            && linux_exit_node_runtime_is_inactive(&self.exit_node_runtime)
            && linux_interface_state_matches(
                &self.iface,
                &interface_addresses,
                config.interface_mtu(),
                linux_tun_tx_queue_len(),
            );
        // The fd00::/8 main-table rule survives interface deletion in RPDB.
        // Only a rule this runtime created is journaled as owned; a rule that
        // already exists is borrowed and left to whoever installed it.
        let fd00_main_rule = main_routes.iter().any(|route| route == "fd00::/8")
            && interface_addresses
                .iter()
                .any(|address| crate::linux_tunnel_address_is_ipv6(address));
        if !unchanged_control_only_state {
            if self.mesh_fd00_main_rule && !fd00_main_rule {
                crate::remove_linux_fd00_main_rule()
                    .context("remove mesh fd00::/8 main-table policy rule")?;
                self.mesh_fd00_main_rule = false;
            }
            self.persist_network_cleanup_ownership()?;
            let fd00_rule_created =
                crate::apply_local_interface_network_with_mtu_and_addresses(
                    &self.iface,
                    &interface_addresses,
                    &main_routes,
                    config.interface_mtu(),
                )
                .with_context(|| {
                    format!("failed to configure FIPS tunnel interface {}", self.iface)
                })?;
            if fd00_rule_created && !self.mesh_fd00_main_rule {
                self.mesh_fd00_main_rule = true;
                self.persist_network_cleanup_ownership()?;
            }
            apply_linux_tun_tx_queue_len(&self.iface)?;
            self.reconcile_linux_exit_node_forwarding(
                config,
                local_exit_seller_egress_ready(
                    config,
                    &connected_peer_pubkeys(&self.mesh.peer_statuses()),
                    self.exit_node_runtime.wireguard_exit.is_some(),
                    self.active_listen_port,
                ),
            )
            .await?;
        }
        let mut routes = interface_routes
            .into_iter()
            .filter(|target| {
                interface_addresses.iter().any(|address| {
                    strip_cidr(address)
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_ipv6() == target.contains(':'))
                })
            })
            .map(|target| GuardRoute {
                target,
                interface: self.iface.clone(),
                gateway: None,
            })
            .collect::<Vec<_>>();
        if let Some(wireguard) = self.exit_node_runtime.wireguard_exit.as_ref() {
            routes.push(GuardRoute {
                target: "0.0.0.0/0".into(),
                interface: wireguard.interface.clone(),
                gateway: None,
            });
            if crate::linux_wireguard_exit_ipv6_default(&config.wireguard_exit) {
                routes.push(GuardRoute {
                    target: "::/0".into(),
                    interface: wireguard.interface.clone(),
                    gateway: None,
                });
            }
        }
        let forwarded = if matches!(
            config.local_exit_seller_egress.as_ref(),
            Some(PaidExitSellerEgress::PrivatePeer { .. } | PaidExitSellerEgress::WireGuard)
        ) && config
            .local_exit_forwarding_routes
            .iter()
            .any(|route| route == "0.0.0.0/0")
        {
            Some(ForwardedExit {
                interface: self.iface.clone(),
                source: crate::linux_exit_node_source_cidr(&config.local_address)
                    .ok_or_else(|| anyhow!("invalid IPv4 seller source range"))?,
            })
        } else {
            None
        };
        crate::linux_exit_intent::routes(routes, forwarded)?;
        self.linux_network_state_initialized = true;
        Ok(())
    }


}

include!("tunnel_runtime_linux/exit_upstream.rs");

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
