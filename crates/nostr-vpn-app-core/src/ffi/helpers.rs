fn native_outbound_join_request(
    request: &PendingOutboundJoinRequest,
) -> NativeOutboundJoinRequestState {
    NativeOutboundJoinRequestState {
        recipient_npub: npub_for_pubkey_hex(&request.recipient),
        recipient_pubkey_hex: request.recipient.clone(),
        requested_at_text: join_request_age_text(request.requested_at),
    }
}

fn native_inbound_join_request(
    request: &PendingInboundJoinRequest,
) -> NativeInboundJoinRequestState {
    NativeInboundJoinRequestState {
        requester_npub: npub_for_pubkey_hex(&request.requester),
        requester_pubkey_hex: request.requester.clone(),
        requester_node_name: request.requester_node_name.clone(),
        requested_at_text: join_request_age_text(request.requested_at),
    }
}

fn remote_network_participant_count(network: &NetworkConfig, own_pubkey_hex: &str) -> usize {
    let mut participants = network.devices.clone();
    participants.extend(network.admins.iter().cloned());
    participants.sort();
    participants.dedup();
    participants
        .iter()
        .filter(|participant| participant.as_str() != own_pubkey_hex)
        .count()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FipsPeerStats {
    direct_roster_peer_count: u64,
    roster_peer_count: u64,
}

fn active_network_fips_peer_stats(
    networks: &[NativeNetworkState],
    own_pubkey_hex: &str,
) -> FipsPeerStats {
    let Some(network) = networks.iter().find(|network| network.enabled) else {
        return FipsPeerStats::default();
    };

    let mut stats = FipsPeerStats::default();
    for participant in &network.participants {
        if !own_pubkey_hex.is_empty() && participant.pubkey_hex == own_pubkey_hex {
            continue;
        }
        if participant_has_fips_signal(participant) {
            stats.roster_peer_count += 1;
            if participant_has_direct_fips_link(participant) {
                stats.direct_roster_peer_count += 1;
            }
        }
    }
    stats
}

fn participant_has_direct_fips_link(participant: &NativeParticipantState) -> bool {
    participant.reachable && !participant.fips_transport_addr.trim().is_empty()
}

fn participant_has_fips_signal(participant: &NativeParticipantState) -> bool {
    !participant.fips_endpoint_hints.is_empty()
        || !participant.fips_endpoint_npub.trim().is_empty()
        || !participant.fips_transport_addr.trim().is_empty()
        || !participant.fips_transport_type.trim().is_empty()
        || participant.fips_packets_sent > 0
        || participant.fips_packets_recv > 0
        || participant.fips_bytes_sent > 0
        || participant.fips_bytes_recv > 0
}

fn network_setup_required_for_config(config: &AppConfig) -> bool {
    config.active_network_opt().is_none()
}

fn native_health_issues(issues: &[HealthIssue]) -> Vec<NativeHealthIssue> {
    issues
        .iter()
        .map(|issue| NativeHealthIssue {
            code: issue.code.clone(),
            severity: format!("{:?}", issue.severity).to_ascii_lowercase(),
            summary: issue.summary.clone(),
            detail: issue.detail.clone(),
        })
        .collect()
}

fn native_network_summary(summary: &NetworkSummary) -> NativeNetworkSummary {
    NativeNetworkSummary {
        default_interface: summary.default_interface.clone().unwrap_or_default(),
        primary_ipv4: summary.primary_ipv4.clone().unwrap_or_default(),
        primary_ipv6: summary.primary_ipv6.clone().unwrap_or_default(),
        gateway_ipv4: summary.gateway_ipv4.clone().unwrap_or_default(),
        gateway_ipv6: summary.gateway_ipv6.clone().unwrap_or_default(),
        changed_at: summary.changed_at.unwrap_or_default(),
        captive_portal: summary
            .captive_portal
            .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
    }
}

fn native_probe_status(status: &ProbeStatus) -> NativeProbeStatus {
    NativeProbeStatus {
        state: format!("{:?}", status.state).to_ascii_lowercase(),
        detail: status.detail.clone(),
    }
}

fn native_port_mapping_status(status: &PortMappingStatus) -> NativePortMappingStatus {
    NativePortMappingStatus {
        upnp: native_probe_status(&status.upnp),
        nat_pmp: native_probe_status(&status.nat_pmp),
        pcp: native_probe_status(&status.pcp),
        active_protocol: status.active_protocol.clone().unwrap_or_default(),
        external_endpoint: status.external_endpoint.clone().unwrap_or_default(),
        gateway: status.gateway.clone().unwrap_or_default(),
        good_until: status.good_until.unwrap_or_default(),
    }
}

fn service_status_detail(status: &CliServiceStatusResponse) -> String {
    if !status.supported {
        return "Background service unsupported on this platform".to_string();
    }
    if !status.installed {
        return "Background service is not installed".to_string();
    }
    if status.disabled {
        return "Background service is installed but disabled in launchd".to_string();
    }
    if status.running {
        let label = status
            .label
            .trim()
            .strip_prefix("to.iris.")
            .unwrap_or_else(|| status.label.trim());
        let label_suffix = if label.is_empty() {
            String::new()
        } else {
            format!(" ({label})")
        };
        return status.pid.map_or_else(
            || format!("Background service running{label_suffix}"),
            |pid| format!("Background service running{label_suffix}, pid {pid}"),
        );
    }
    if status.loaded {
        return "Background service installed but not running".to_string();
    }
    if !status.plist_path.trim().is_empty() {
        return format!(
            "Background service installed but launch status is unavailable: {}",
            status.plist_path
        );
    }
    "Background service installed but launch status is unavailable".to_string()
}

fn desktop_service_supported() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))
}

fn cli_binary_installed() -> bool {
    resolve_nvpn_cli_path().is_ok()
}

fn external_daemon_mode() -> bool {
    env::var(EXTERNAL_DAEMON_ENV).is_ok_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes")
    })
}

fn peer_offers_exit_node(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

fn peer_last_fips_seen_secs(peer: &DaemonPeerState) -> Option<u64> {
    peer.last_fips_seen_at
        .or_else(|| (peer.last_mesh_seen_at > 0).then_some(peer.last_mesh_seen_at))
}

fn peer_last_fips_seen_age_secs(peer: &DaemonPeerState) -> Option<u64> {
    peer_last_fips_seen_secs(peer).and_then(presence_age_secs_since)
}

fn within_presence_grace(seen_at: u64) -> bool {
    presence_age_secs_since(seen_at).is_some_and(|age| age <= PEER_PRESENCE_GRACE_SECS)
}

fn presence_age_secs_since(epoch_secs: u64) -> Option<u64> {
    age_secs_since_with_future_skew(epoch_secs, PEER_PRESENCE_MAX_FUTURE_SKEW_SECS)
}

fn age_secs_since_with_future_skew(epoch_secs: u64, max_future_skew_secs: u64) -> Option<u64> {
    let now = unix_timestamp();
    if epoch_secs > now {
        return (epoch_secs - now <= max_future_skew_secs).then_some(0);
    }
    Some(now - epoch_secs)
}

fn age_secs_since(epoch_secs: u64) -> u64 {
    unix_timestamp().saturating_sub(epoch_secs)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn join_request_age_text(requested_at: u64) -> String {
    if requested_at == 0 {
        return "just now".to_string();
    }
    compact_age_text(age_secs_since(requested_at))
}

fn compact_age_text(age_secs: u64) -> String {
    match age_secs {
        0..=59 => format!("{age_secs}s ago"),
        60..=3_599 => format!("{}m ago", age_secs / 60),
        3_600..=86_399 => format!("{}h ago", age_secs / 3_600),
        86_400..=604_799 => format!("{}d ago", age_secs / 86_400),
        604_800..=2_591_999 => format!("{}w ago", age_secs / 604_800),
        2_592_000..=31_535_999 => format!("{}mo ago", age_secs / 2_592_000),
        _ => format!("{}y ago", age_secs / 31_536_000),
    }
}

fn shorten_middle(value: &str, prefix: usize, suffix: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= prefix + suffix + 1 {
        return value.to_string();
    }
    let start = chars.iter().take(prefix).collect::<String>();
    let end = chars
        .iter()
        .skip(chars.len().saturating_sub(suffix))
        .collect::<String>();
    format!("{start}...{end}")
}

fn peer_link_text(peer: &DaemonPeerState) -> Option<String> {
    if let Some(addr) = non_empty(&peer.fips_transport_addr) {
        let transport = non_empty(&peer.fips_transport_type).unwrap_or_else(|| "fips".to_string());
        let mut text = format!("{transport} {}", shorten_middle(&addr, 22, 10));
        if let Some(srtt_ms) = peer.fips_srtt_ms.filter(|value| *value > 0) {
            let _ = write!(text, " ({srtt_ms} ms)");
        }
        if peer.direct_probe_pending {
            text.push_str(", probing direct");
        }
        return Some(text);
    }

    let is_fips_peer = !peer.fips_endpoint_npub.trim().is_empty()
        || peer.endpoint.trim().eq_ignore_ascii_case("fips")
        || peer
            .runtime_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.trim().eq_ignore_ascii_case("fips"));
    let recently_seen =
        peer.reachable || peer_last_fips_seen_secs(peer).is_some_and(within_presence_grace);
    if is_fips_peer && recently_seen {
        let mut text = if peer.direct_probe_pending {
            "mesh, probing direct".to_string()
        } else {
            "mesh".to_string()
        };
        if let Some(srtt_ms) = peer.fips_srtt_ms.filter(|value| *value > 0) {
            let _ = write!(text, " ({srtt_ms} ms)");
        }
        return Some(text);
    }

    None
}

fn native_config_path(data_dir: &str) -> PathBuf {
    let trimmed = data_dir.trim();
    if trimmed.is_empty() {
        default_config_path()
    } else {
        PathBuf::from(trimmed).join("config.toml")
    }
}

fn default_config_path() -> PathBuf {
    dirs::config_dir().map_or_else(
        || PathBuf::from("nvpn.toml"),
        |dir| dir.join("nvpn").join("config.toml"),
    )
}

fn resolve_nvpn_cli_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        return validate_nvpn_binary(&PathBuf::from(path));
    }
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for candidate in bundled_nvpn_candidate_paths(dir) {
            if let Ok(validated) = validate_nvpn_binary(&candidate) {
                return Ok(validated);
            }
        }
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            if let Ok(validated) = validate_nvpn_binary(&dir.join(nvpn_binary_name())) {
                return Ok(validated);
            }
        }
    }
    Err(anyhow!("nvpn CLI binary not found"))
}

fn bundled_nvpn_candidate_paths(exe_dir: &Path) -> Vec<PathBuf> {
    let name = nvpn_binary_name();
    let mut paths = vec![exe_dir.join(name)];
    paths.push(exe_dir.join("binaries").join(name));
    if let Some(contents_dir) = exe_dir.parent() {
        paths.push(contents_dir.join("Resources").join("binaries").join(name));
        paths.push(contents_dir.join("Resources").join(name));
    }
    paths
}

fn nvpn_binary_name() -> &'static str {
    if cfg!(windows) { "nvpn.exe" } else { "nvpn" }
}

fn validate_nvpn_binary(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }
    Ok(canonical)
}

fn ensure_success(command_name: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure(command_name, output))
    }
}

fn command_failure(command_name: &str, output: &Output) -> anyhow::Error {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow!(
        "{command_name} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    )
}

fn extract_json_document(output: &str) -> Result<&str> {
    let start = output
        .find('{')
        .ok_or_else(|| anyhow!("command output did not contain JSON"))?;
    let end = output
        .rfind('}')
        .ok_or_else(|| anyhow!("command output did not contain complete JSON"))?;
    Ok(&output[start..=end])
}

fn parse_advertised_routes(input: &str) -> Vec<String> {
    let mut routes = input
        .split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(normalize_advertised_route)
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    routes
}

fn parse_csv_values(input: &str) -> Vec<String> {
    let mut values = input
        .split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

#[cfg(feature = "paid-exit")]
fn parse_paid_exit_mint_urls(input: &str) -> Result<Vec<String>> {
    let mut urls = parse_csv_values(input)
        .into_iter()
        .map(|url| normalize_paid_route_mint_url(&url))
        .collect::<Result<Vec<_>>>()?;
    urls.sort();
    urls.dedup();
    Ok(urls)
}

#[cfg(not(feature = "paid-exit"))]
fn parse_paid_exit_mint_urls(_input: &str) -> Result<Vec<String>> {
    Err(anyhow!("paid exit is unavailable"))
}

fn parse_optional_asn(input: &str) -> Result<Option<u32>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let trimmed = trimmed.strip_prefix("AS").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("as").unwrap_or(trimmed);
    trimmed
        .parse::<u32>()
        .map(Some)
        .with_context(|| format!("invalid paid exit ASN '{input}'"))
}

fn parse_tcp_ports(input: &str) -> Vec<u16> {
    let mut ports = input
        .split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn effective_config_relays(config: &AppConfig) -> Vec<String> {
    let disabled_relays = normalize_relay_urls(config.nostr.disabled_relays.clone())
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let fips = fips_endpoint::NostrDiscoveryConfig::default();
    let mut relays = if config.nostr.relays.is_empty() {
        normalize_relay_urls(fips.advert_relays)
    } else {
        normalize_relay_urls(config.nostr.relays.clone())
    };
    relays.retain(|relay| !disabled_relays.contains(relay));
    relays
}

fn short_pubkey(pubkey_hex: &str) -> String {
    if pubkey_hex.len() <= 12 {
        pubkey_hex.to_string()
    } else {
        format!(
            "{}...{}",
            &pubkey_hex[..8],
            &pubkey_hex[pubkey_hex.len() - 4..]
        )
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn paid_exit_provider_display_name(market: &NativePaidRouteMarketState, pubkey_hex: &str) -> String {
    let Some(offer) = market
        .offers
        .iter()
        .filter(|offer| normalize_nostr_pubkey(&offer.seller_npub).ok().as_deref() == Some(pubkey_hex))
        .max_by_key(|offer| offer.last_seen_unix)
    else {
        return "Paid provider".to_string();
    };
    let country = non_empty(&offer.country_code).unwrap_or_else(|| "Unknown country".to_string());
    match non_empty(&offer.price_text) {
        Some(price) => format!("{country} · {price}"),
        None => country,
    }
}

fn exit_node_display_name(
    config: &AppConfig,
    active_network: &NetworkConfig,
    pubkey_hex: &str,
) -> String {
    if let Some(name) = config
        .magic_dns_name_for_participant(pubkey_hex)
        .and_then(|value| non_empty(&value))
    {
        return name;
    }
    if let Some(name) = config
        .peer_alias(pubkey_hex)
        .and_then(|value| non_empty(&value))
    {
        return name;
    }
    if active_network
        .admins
        .iter()
        .any(|admin| admin == pubkey_hex)
    {
        return "admin".to_string();
    }
    short_pubkey(pubkey_hex)
}

#[cfg(target_os = "macos")]
fn privileged_outcome_to_output(outcome: PrivilegedCommandOutput) -> Output {
    use std::os::unix::process::ExitStatusExt;
    let raw = if outcome.success { 0 } else { 1 << 8 };
    Output {
        status: std::process::ExitStatus::from_raw(raw),
        stdout: outcome.stdout,
        stderr: outcome.stderr,
    }
}

#[cfg(target_os = "macos")]
fn macos_service_action_shell_command(nvpn_bin: &Path, args: &[&str]) -> String {
    std::iter::once(shell_quote(&nvpn_bin.display().to_string()))
        .chain(args.iter().map(|arg| shell_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
