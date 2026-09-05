impl CliTunnelRuntime {
    fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            active_listen_port: None,
            paid_exit_seller_ready: false,
            wireguard_exit_ready: false,
        }
    }

    fn stop(&mut self) {
        self.active_listen_port = None;
        self.paid_exit_seller_ready = false;
        self.wireguard_exit_ready = false;
    }

    #[cfg(target_os = "macos")]
    fn macos_network_cleanup_state(&self) -> Option<MacosNetworkCleanupState> {
        None
    }

    fn listen_port(&self) -> Option<u16> {
        self.active_listen_port
    }

    fn sync_fips_state(
        &mut self,
        runtime: Option<&crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    ) {
        self.active_listen_port = runtime.and_then(
            crate::fips_private_mesh::FipsPrivateTunnelRuntime::active_listen_port,
        );
        self.wireguard_exit_ready = runtime.is_some_and(
            crate::fips_private_mesh::FipsPrivateTunnelRuntime::wireguard_exit_ready,
        );
        #[cfg(feature = "paid-exit")]
        {
            self.paid_exit_seller_ready = runtime.is_some_and(
                crate::fips_private_mesh::FipsPrivateTunnelRuntime::paid_exit_seller_ready,
            );
        }
    }

    pub(crate) fn owns_interface(&self, iface: &str) -> bool {
        self.iface == iface
    }
}

fn load_pending_fips_control_recipients(
    config_path: &Path,
) -> Result<Vec<(&'static str, String)>> {
    let recipients = nostr_vpn_core::join_delivery::load_join_rosters(config_path)
        .into_iter()
        .map(|(_, queued)| ("join roster", queued.recipient_npub))
        .collect::<Vec<_>>();
    #[cfg(feature = "paid-exit")]
    let recipients = {
        let mut recipients = recipients;
        recipients.extend(
            load_paid_exit_payment_outbox(config_path)
                .into_iter()
                .map(|queued| ("paid-exit", queued.envelope.seller)),
        );
        let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
        recipients.extend(
            store
                .channels
                .values()
                .filter(|channel| {
                    channel.role == PaidRouteChannelRole::Seller
                        && !matches!(
                            channel.status,
                            PaidRouteLifecycleStatus::Closed
                                | PaidRouteLifecycleStatus::Expired
                                | PaidRouteLifecycleStatus::Failed
                        )
                })
                .map(|channel| {
                    (
                        "paid-exit seller settlement",
                        channel.counterparty_npub.clone(),
                    )
                }),
        );
        recipients
    };
    Ok(recipients)
}

fn endpoint_with_listen_port(endpoint: &str, listen_port: u16) -> String {
    let trimmed = endpoint.trim();
    if let Ok(mut parsed) = trimmed.parse::<SocketAddr>() {
        parsed.set_port(listen_port);
        return parsed.to_string();
    }
    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return trimmed.to_string();
    };
    if host.is_empty() || host.contains(':') || port.trim().parse::<u16>().is_err() {
        return trimmed.to_string();
    }
    format!("{}:{listen_port}", host.trim())
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn endpoint_prefers_runtime_local_ipv4(endpoint: &str) -> bool {
    let value = endpoint.trim();
    if value.is_empty() {
        return true;
    }

    let host = value
        .rsplit_once(':')
        .map_or(value, |(host, _port)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ipv4_is_local_only(ip),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

fn runtime_local_signal_endpoint(
    endpoint: &str,
    listen_port: u16,
    detected_ipv4: Option<Ipv4Addr>,
) -> String {
    if endpoint_prefers_runtime_local_ipv4(endpoint)
        && let Some(ip) = detected_ipv4
    {
        return SocketAddrV4::new(ip, listen_port).to_string();
    }

    endpoint_with_listen_port(endpoint, listen_port)
}

fn runtime_signal_ipv4(detected_ipv4: Option<Ipv4Addr>, tunnel_ip: &str) -> Option<Ipv4Addr> {
    let tunnel_ipv4 = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok();
    detected_ipv4.filter(|ip| Some(*ip) != tunnel_ipv4)
}

fn local_signal_endpoint(app: &AppConfig, listen_port: u16) -> String {
    let detected_ipv4 = if endpoint_prefers_runtime_local_ipv4(&app.node.endpoint) {
        detect_runtime_primary_ipv4()
    } else {
        None
    };
    runtime_local_signal_endpoint(
        &app.node.endpoint,
        listen_port,
        runtime_signal_ipv4(detected_ipv4, &app.node.tunnel_ip),
    )
}

async fn refresh_port_mapping(
    app: &AppConfig,
    network_snapshot: &diagnostics::NetworkSnapshot,
    listen_port: u16,
    port_mapping_runtime: &mut PortMappingRuntime,
) {
    if !port_mapping_needed(app) {
        port_mapping_runtime.stop().await;
        return;
    }

    let timeout = Duration::from_secs(app.nat.discovery_timeout_secs.max(1));
    if let Err(error) = port_mapping_runtime
        .refresh(network_snapshot, listen_port, timeout)
        .await
    {
        eprintln!("nat: port mapping refresh failed: {error}");
    }
}

fn port_mapping_needed(app: &AppConfig) -> bool {
    app.nat.enabled && app.fips_nostr_discovery_enabled
}

fn port_mapping_parameters(
    app: &AppConfig,
    vpn_active: bool,
    listen_port: Option<u16>,
) -> Option<(u16, u64)> {
    if !vpn_active || !port_mapping_needed(app) {
        return None;
    }
    listen_port.map(|port| (port, app.nat.discovery_timeout_secs.max(1)))
}

fn network_probe_timeout(app: &AppConfig) -> Duration {
    Duration::from_secs(app.nat.discovery_timeout_secs.max(2))
}
