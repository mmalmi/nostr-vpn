fn format_health_severity(severity: HealthSeverity) -> &'static str {
    match severity {
        HealthSeverity::Info => "info",
        HealthSeverity::Warning => "warning",
        HealthSeverity::Critical => "critical",
    }
}

async fn run_doctor(args: DoctorArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let (app, network_id) = load_config_with_overrides_async(
        &config_path,
        args.network_id,
        args.devices,
        ConfigLoadMode::ReadOnly,
    ).await?;
    let daemon = daemon_status(&config_path)?;
    let netcheck = run_netcheck_report(&app, args.timeout_secs).await;

    let mut network = daemon
        .state
        .as_ref()
        .map(|state| state.network.clone())
        .unwrap_or_else(|| capture_network_snapshot().summary(None, netcheck.captive_portal));
    if network.captive_portal.is_none() {
        network.captive_portal = netcheck.captive_portal;
    }
    let port_mapping = daemon
        .state
        .as_ref()
        .map(|state| state.port_mapping.clone())
        .unwrap_or_else(|| netcheck.port_mapping.clone());
    let issues = daemon
        .state
        .as_ref()
        .map(|state| {
            if state.health.is_empty() {
                build_health_issues(
                    &app,
                    state.vpn_active,
                    state.mesh_ready,
                    &network,
                    &port_mapping,
                    &state.peers,
                )
            } else {
                state.health.clone()
            }
        })
        .unwrap_or_default();
    let log_tail = read_daemon_log_tail(&daemon.log_file, 80);
    let bundle_path = if let Some(path) = args.write_bundle.as_deref() {
        Some(
            write_doctor_bundle(
                path,
                &app,
                &network_id,
                &daemon,
                &network,
                &port_mapping,
                &issues,
                &netcheck,
                &log_tail,
            )
            .await?,
        )
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "networkId": network_id,
                "daemon": {
                    "running": daemon.running,
                    "pid": daemon.pid,
                    "logFile": daemon.log_file,
                    "stateFile": daemon.state_file,
                    "state": daemon.state,
                },
                "network": network,
                "portMapping": port_mapping,
                "health": issues,
                "netcheck": netcheck,
                "bundlePath": bundle_path,
            }))?
        );
        return Ok(());
    }

    println!("network: {network_id}");
    if daemon.running {
        println!("daemon: running (pid {})", daemon.pid.unwrap_or_default());
    } else {
        println!("daemon: stopped");
    }
    if let Some(state) = daemon.state.as_ref() {
        println!("vpn: {}", state.vpn_status);
    }
    println!(
        "netcheck: udp={} ipv4={} ipv6={} captive_portal={}",
        netcheck.udp,
        netcheck.ipv4,
        netcheck.ipv6,
        netcheck
            .captive_portal
            .map_or("unknown".to_string(), |value| value.to_string())
    );
    if let Some(interface) = network.default_interface.as_deref() {
        println!("default_interface: {interface}");
    }
    if let Some(primary_ipv4) = network.primary_ipv4.as_deref() {
        println!("primary_ipv4: {primary_ipv4}");
    }
    if let Some(primary_ipv6) = network.primary_ipv6.as_deref() {
        println!("primary_ipv6: {primary_ipv6}");
    }
    if let Some(public_ipv4) = netcheck.public_ipv4.as_deref() {
        println!("public_ipv4: {public_ipv4}");
    }
    println!(
        "port_mapping: active={} upnp={} nat_pmp={} pcp={}",
        port_mapping.active_protocol.as_deref().unwrap_or("none"),
        format_probe_state(port_mapping.upnp.state),
        format_probe_state(port_mapping.nat_pmp.state),
        format_probe_state(port_mapping.pcp.state),
    );
    if issues.is_empty() {
        println!("health: ok");
    } else {
        println!("health:");
        for issue in &issues {
            println!(
                "  [{}] {}",
                format_health_severity(issue.severity),
                issue.summary
            );
            println!("    {}", issue.detail);
        }
    }
    if let Some(path) = bundle_path {
        println!("bundle: {}", path.display());
    }

    Ok(())
}

fn print_daemon_peer_line(peer: &DaemonPeerState, now: u64) {
    let marker = if peer.reachable { '✓' } else { '✗' };
    let transport = daemon_peer_transport_label(
        peer.reachable,
        &peer.fips_transport_type,
        &peer.fips_transport_addr,
    );
    let srtt = peer
        .fips_srtt_ms
        .map(|ms| format!(" srtt={ms}ms"))
        .unwrap_or_default();
    let last = peer
        .last_fips_seen_at
        .and_then(|seen| daemon_peer_age_secs(now, seen))
        .map(|age| format!(" last={age}s"))
        .unwrap_or_default();
    let traffic = if peer.fips_bytes_sent + peer.fips_bytes_recv > 0 {
        format!(
            " io={}/{}",
            human_bytes(peer.fips_bytes_recv),
            human_bytes(peer.fips_bytes_sent),
        )
    } else {
        String::new()
    };
    let routes = if peer.advertised_routes.is_empty() {
        String::new()
    } else {
        format!(" routes={}", peer.advertised_routes.join(","))
    };
    let probe = if peer.direct_probe_pending {
        " direct_probe=pending"
    } else {
        ""
    };
    let err = peer
        .error
        .as_deref()
        .filter(|err| !err.is_empty() && !peer.reachable)
        .map(|err| format!(" ({err})"))
        .unwrap_or_default();
    let pubkey = if !peer.public_key.is_empty() {
        peer.public_key.as_str()
    } else {
        peer.participant_pubkey.as_str()
    };
    println!(
        "  {marker} {} {} {transport}{srtt}{last}{traffic}{routes}{probe}{err}",
        truncate_pubkey(pubkey),
        peer.tunnel_ip,
    );
}

fn daemon_peer_transport_label(reachable: bool, kind: &str, addr: &str) -> String {
    match (kind, addr) {
        ("", "") if reachable => "via mesh".to_string(),
        ("", "") => "pending".to_string(),
        (kind, _) if kind.eq_ignore_ascii_case("relayed") => "via mesh".to_string(),
        (kind, "") => kind.to_string(),
        (kind, addr) => format!("{kind} {addr}"),
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx + 1 < UNITS.len() {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else {
        format!("{value:.1}{}", UNITS[idx])
    }
}

fn daemon_peer_age_secs(now: u64, seen_at: u64) -> Option<u64> {
    if seen_at == 0 {
        return None;
    }
    if seen_at > now {
        return (seen_at - now <= DAEMON_PEER_STATUS_MAX_FUTURE_SKEW_SECS).then_some(0);
    }
    Some(now - seen_at)
}

fn truncate_pubkey(pubkey_hex: &str) -> String {
    if pubkey_hex.len() <= 12 {
        pubkey_hex.to_string()
    } else {
        format!("{}…", &pubkey_hex[..12])
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn parse_advertised_routes_arg(value: &str) -> Result<Vec<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut routes = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let normalized = normalize_advertised_route(raw)
            .ok_or_else(|| anyhow!("invalid advertised route '{raw}'"))?;
        if !routes.iter().any(|existing| existing == &normalized) {
            routes.push(normalized);
        }
    }

    Ok(routes)
}

fn parse_csv_arg(value: &str) -> Vec<String> {
    let mut values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn parse_tcp_ports_arg(value: &str) -> Result<Vec<u16>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let port = raw
            .parse::<u16>()
            .with_context(|| format!("invalid TCP port '{raw}'"))?;
        if port == 0 {
            return Err(anyhow!("invalid TCP port '{raw}'"));
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    Ok(ports)
}

fn parse_fips_peer_endpoint_args(values: &[String]) -> Result<HashMap<String, Vec<String>>> {
    let mut peers = HashMap::<String, Vec<String>>::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let (peer, endpoint) = value
            .split_once('=')
            .ok_or_else(|| anyhow!("expected --fips-peer-endpoint npub=host or npub=host:port"))?;
        let peer = normalize_nostr_pubkey(peer.trim())?;
        let endpoint = normalize_fips_peer_endpoint(endpoint.trim())?;
        peers.entry(peer).or_default().push(endpoint);
    }

    for endpoints in peers.values_mut() {
        endpoints.sort();
        endpoints.dedup();
    }
    Ok(peers)
}

fn normalize_fips_peer_endpoint(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("empty FIPS peer endpoint"));
    }
    normalize_fips_peer_endpoint_hint(value)
        .ok_or_else(|| anyhow!("FIPS peer endpoint must be a usable UDP host or host:port"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_checked(command: &mut ProcessCommand) -> Result<()> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "command failed: {display}\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(())
}
