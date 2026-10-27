#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxRouteGetSpec {
    pub(crate) gateway: Option<String>,
    pub(crate) dev: String,
    pub(crate) src: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxEndpointBypassRoute {
    pub(crate) target: String,
    pub(crate) gateway: Option<String>,
    pub(crate) dev: String,
    pub(crate) src: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxManagedEndpointBypassRoute {
    pub(crate) route: LinuxEndpointBypassRoute,
    pub(crate) previous_routes: Vec<String>,
    pub(crate) owned: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct LinuxDefaultRouteSpec {
    pub(crate) line: String,
    pub(crate) dev: String,
    pub(crate) gateway: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) metric: u32,
    pub(crate) on_link: bool,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_route_get_spec_from_output(output: &str) -> Option<LinuxRouteGetSpec> {
    let line = output.lines().find(|line| !line.trim().is_empty())?.trim();
    let tokens = line.split_whitespace().collect::<Vec<_>>();

    let mut gateway = None;
    let mut dev = None;
    let mut src = None;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "via" => {
                gateway = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            "dev" => {
                dev = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            "src" => {
                src = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            _ => {
                index += 1;
            }
        }
    }

    Some(LinuxRouteGetSpec {
        gateway,
        dev: dev?,
        src,
    })
}

#[cfg(target_os = "linux")]
fn linux_default_route_from_output_for_interface(
    output: &str,
    interface: Option<&str>,
) -> Option<LinuxDefaultRouteSpec> {
    linux_default_route_specs_from_output(output)
        .filter_map(|route| {
            if interface.is_some_and(|interface| interface != route.dev) {
                return None;
            }
            Some((route.metric, route))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, route)| route)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_default_route_spec_from_line(line: &str) -> Option<LinuxDefaultRouteSpec> {
    let line = line.trim();
    if line.split_whitespace().next() != Some("default") {
        return None;
    }
    let route = linux_route_get_spec_from_output(line)?;
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let metric = tokens
        .windows(2)
        .find(|window| window[0] == "metric")
        .and_then(|window| window[1].parse::<u32>().ok())
        .unwrap_or(0);
    Some(LinuxDefaultRouteSpec {
        line: line.to_string(),
        dev: route.dev,
        gateway: route.gateway,
        source: route.src,
        metric,
        on_link: tokens.contains(&"onlink"),
    })
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_default_route_specs_from_output(
    output: &str,
) -> impl Iterator<Item = LinuxDefaultRouteSpec> + '_ {
    output.lines().filter_map(linux_default_route_spec_from_line)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_ipv4_default_route_matches_interface(
    route: &LinuxDefaultRouteSpec,
    interface: &netdev::Interface,
) -> bool {
    let source = match route.source.as_deref() {
        Some(source) => match source.parse::<Ipv4Addr>() {
            Ok(source) => Some(source),
            Err(_) => return false,
        },
        None => None,
    };
    let gateway = match route.gateway.as_deref() {
        Some(gateway) => match gateway.parse::<Ipv4Addr>() {
            Ok(gateway) => Some(gateway),
            Err(_) => return false,
        },
        None => None,
    };
    linux_ipv4_route_fields_match_interface(gateway, source, route.on_link, interface)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_ipv4_route_fields_match_interface(
    gateway: Option<Ipv4Addr>,
    source: Option<Ipv4Addr>,
    on_link: bool,
    interface: &netdev::Interface,
) -> bool {
    let networks = interface
        .ipv4
        .iter()
        .filter(|network| {
            let address = network.addr();
            !address.is_loopback()
                && !address.is_link_local()
                && source.is_none_or(|source| address == source)
        })
        .collect::<Vec<_>>();
    if networks.is_empty() {
        return false;
    }
    match gateway {
        Some(gateway) => {
            on_link || networks.iter().any(|network| network.contains(&gateway))
        }
        None => true,
    }
}

#[cfg(test)]
pub(crate) fn linux_ipv4_default_route_primary_address(
    route: &LinuxDefaultRouteSpec,
    interface: &netdev::Interface,
) -> Option<Ipv4Addr> {
    let source = route
        .source
        .as_deref()
        .and_then(|source| source.parse().ok());
    let gateway = route
        .gateway
        .as_deref()
        .and_then(|gateway| gateway.parse().ok());
    linux_ipv4_route_primary_address(source, gateway, route.on_link, interface)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_ipv4_route_primary_address(
    source: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
    on_link: bool,
    interface: &netdev::Interface,
) -> Option<Ipv4Addr> {
    if let Some(source) = source.filter(|source| interface.ipv4_addrs().contains(source)) {
        return Some(source);
    }
    let usable = interface
        .ipv4
        .iter()
        .filter(|network| {
            let address = network.addr();
            !address.is_loopback() && !address.is_link_local()
        })
        .collect::<Vec<_>>();
    if let Some(gateway) = gateway
        && let Some(network) = usable.iter().find(|network| network.contains(&gateway))
    {
        return Some(network.addr());
    }
    if gateway.is_none() || (on_link && usable.len() == 1) {
        usable.first().map(|network| network.addr())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ipv4_default_route_is_usable(route: &LinuxDefaultRouteSpec) -> bool {
    get_interfaces()
        .iter()
        .find(|interface| interface.name == route.dev)
        .is_some_and(|interface| {
            interface.is_oper_up()
                && fs::read_to_string(format!("/sys/class/net/{}/carrier", interface.name))
                    .is_ok_and(|carrier| carrier.trim() == "1")
                && linux_ipv4_default_route_matches_interface(route, interface)
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_default_route_from_lines_for_interface(
    routes: &[String],
    interface: &str,
) -> Option<LinuxDefaultRouteSpec> {
    linux_default_route_from_output_for_interface(&routes.join("\n"), Some(interface))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn command_stdout_checked(command: &mut ProcessCommand) -> Result<String> {
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

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_default_route() -> Result<LinuxDefaultRouteSpec> {
    linux_default_route_for_family("-4", "IPv4", None)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_current_default_route() -> Result<Option<LinuxDefaultRouteSpec>> {
    linux_current_default_route_for_family("-4", None)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_current_default_ipv6_route() -> Result<Option<LinuxDefaultRouteSpec>> {
    linux_current_default_route_for_family("-6", None)
}

#[cfg(target_os = "linux")]
fn linux_default_route_for_family(
    family_flag: &str,
    family_label: &str,
    interface: Option<&str>,
) -> Result<LinuxDefaultRouteSpec> {
    linux_current_default_route_for_family(family_flag, interface)?.ok_or_else(|| {
        anyhow!(
            "failed to resolve default {family_label} route{}",
            interface.map_or_else(String::new, |interface| format!(" on {interface}"))
        )
    })
}

#[cfg(target_os = "linux")]
fn linux_current_default_route_for_family(
    family_flag: &str,
    interface: Option<&str>,
) -> Result<Option<LinuxDefaultRouteSpec>> {
    let output = command_stdout_checked(
        ProcessCommand::new("ip")
            .arg(family_flag)
            .arg("route")
            .arg("show")
            .arg("default"),
    )?;
    Ok(linux_default_route_from_output_for_interface(
        &output, interface,
    ))
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_saved_default_restore_required(
    saved: &str,
    current: Option<&LinuxDefaultRouteSpec>,
    owned_interfaces: &[String],
) -> bool {
    match current {
        None => true,
        Some(current) if current.line == saved => false,
        Some(current) => owned_interfaces
            .iter()
            .any(|interface| interface == &current.dev),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn restore_linux_default_route(route: &str) -> Result<()> {
    restore_linux_default_route_for_family("-4", route)
}

#[cfg(target_os = "linux")]
pub(crate) fn restore_linux_default_ipv6_route(route: &str) -> Result<()> {
    restore_linux_default_route_for_family("-6", route)
}

#[cfg(target_os = "linux")]
fn restore_linux_default_route_for_family(family_flag: &str, route: &str) -> Result<()> {
    let mut command = ProcessCommand::new("ip");
    command.arg(family_flag).arg("route").arg("replace");
    for token in linux_route_replay_args(route)? {
        command.arg(token);
    }
    run_checked(&mut command)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_route_replay_args(route: &str) -> Result<Vec<&str>> {
    let mut tokens = route
        .split_whitespace()
        .filter(|token| *token != "linkdown");
    let mut args = Vec::new();
    let Some(destination) = tokens.next() else {
        return Err(anyhow!("refusing to replay an empty saved route"));
    };
    linux_route_replay_destination(destination)?;
    args.push(destination);
    while let Some(token) = tokens.next() {
        if token.starts_with('-') {
            return Err(anyhow!("refusing route replay flag {token:?}"));
        }
        match token {
            "onlink" => args.push(token),
            "via" | "src" => {
                let value = tokens.next().ok_or_else(|| anyhow!("route replay {token} needs an address"))?;
                value.parse::<IpAddr>()
                    .map_err(|_| anyhow!("invalid route replay {token} address {value:?}"))?;
                args.push(token);
                args.push(value);
            }
            "dev" => {
                let value = tokens.next().ok_or_else(|| anyhow!("route replay dev needs an interface"))?;
                if value.starts_with('-') {
                    return Err(anyhow!("refusing route replay flag {value:?}"));
                }
                crate::linux_exit_guard::validate_interface(value).map_err(|error| {
                    anyhow!("invalid route replay interface {value:?}: {error}")
                })?;
                args.push(token);
                args.push(value);
            }
            "metric" => {
                let value = linux_route_replay_number(&mut tokens, token)?;
                args.push(token);
                args.push(value);
            }
            "mtu" => {
                args.push(token);
                let mut value = tokens.next().ok_or_else(|| anyhow!("route replay mtu needs a number"))?;
                if value == "lock" {
                    args.push(value);
                    value = tokens.next().ok_or_else(|| anyhow!("route replay mtu lock needs a number"))?;
                }
                value.parse::<u32>()
                    .map_err(|_| anyhow!("invalid route replay mtu {value:?}"))?;
                args.push(value);
            }
            "scope" | "proto" => {
                let value = tokens.next().ok_or_else(|| anyhow!("route replay {token} needs a value"))?;
                if !linux_route_replay_identifier(value) {
                    return Err(anyhow!("invalid route replay {token} {value:?}"));
                }
                args.push(token);
                args.push(value);
            }
            "expires" => {
                let value = tokens.next().ok_or_else(|| anyhow!("route replay expires needs a lifetime"))?;
                value
                    .strip_suffix("sec")
                    .and_then(|seconds| seconds.parse::<u32>().ok())
                    .ok_or_else(|| anyhow!("invalid route replay expires {value:?}"))?;
                args.push(token);
                args.push(value);
            }
            "pref" => {
                let value = tokens.next().ok_or_else(|| anyhow!("route replay pref needs a preference"))?;
                if !matches!(value, "low" | "medium" | "high") {
                    return Err(anyhow!("invalid route replay pref {value:?}"));
                }
                args.push(token);
                args.push(value);
            }
            unknown => return Err(anyhow!("refusing route replay token {unknown:?}")),
        }
    }
    Ok(args)
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_replay_destination(token: &str) -> Result<()> {
    if token == "default" {
        return Ok(());
    }
    if !token.starts_with('-')
        && (token.parse::<IpAddr>().is_ok()
            || crate::linux_exit_guard::validate_network_prefix(token).is_ok())
    {
        return Ok(());
    }
    Err(anyhow!("invalid route replay destination {token:?}"))
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_replay_number<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    keyword: &str,
) -> Result<&'a str> {
    let value = tokens
        .next()
        .ok_or_else(|| anyhow!("route replay {keyword} needs a number"))?;
    value
        .parse::<u32>()
        .map_err(|_| anyhow!("invalid route replay {keyword} {value:?}"))?;
    Ok(value)
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_replay_identifier(value: &str) -> bool {
    (1..=16).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(target_os = "linux")]
pub(crate) fn flush_linux_route_cache() -> Result<()> {
    run_checked(
        ProcessCommand::new("ip")
            .arg("-4")
            .arg("route")
            .arg("flush")
            .arg("cache"),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after_host) = rest.split_once(']')?;
        let port = after_host
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && !host.is_empty() && port.parse::<u16>().is_ok() =>
        {
            Some((host.to_string(), port.parse::<u16>().ok()?))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_endpoint_bypass_route_snapshot(target: &str) -> Result<Vec<String>> {
    let output = command_stdout_checked(
        ProcessCommand::new("ip")
            .arg("-4")
            .arg("route")
            .arg("show")
            .arg(target),
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_endpoint_bypass_route_matches_line(
    route: &LinuxEndpointBypassRoute,
    line: &str,
) -> bool {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let expected_target = route.target.strip_suffix("/32").unwrap_or(&route.target);
    let actual_target = tokens
        .first()
        .map(|target| target.strip_suffix("/32").unwrap_or(target));
    if actual_target != Some(expected_target) {
        return false;
    }
    let value_after = |name: &str| {
        tokens
            .windows(2)
            .find(|window| window[0] == name)
            .map(|window| window[1])
    };
    value_after("via") == route.gateway.as_deref()
        && value_after("dev") == Some(route.dev.as_str())
        && value_after("src") == route.src.as_deref()
}

#[cfg(target_os = "linux")]
pub(crate) fn restore_linux_managed_endpoint_bypass_route(
    managed: &LinuxManagedEndpointBypassRoute,
) -> Result<()> {
    if !managed.owned {
        return Ok(());
    }
    let current = linux_endpoint_bypass_route_snapshot(&managed.route.target)?;
    if current == managed.previous_routes {
        // A write-ahead cleanup intent can be replayed after a crash that
        // happened before the managed route was installed.
        return Ok(());
    }
    if !(current.is_empty()
        || (current.len() == 1
            && linux_endpoint_bypass_route_matches_line(&managed.route, &current[0])))
    {
        return Err(anyhow!(
            "refusing to overwrite drifted unowned route identity {}: {:?}",
            managed.route.target,
            current
        ));
    }
    let mut flush = ProcessCommand::new("ip");
    flush
        .arg("-4")
        .arg("route")
        .arg("flush")
        .arg(&managed.route.target);
    run_checked(&mut flush)?;
    for route in &managed.previous_routes {
        let mut restore = ProcessCommand::new("ip");
        restore.arg("-4").arg("route").arg("replace");
        restore.args(linux_route_replay_args(route)?);
        run_checked(&mut restore).with_context(|| {
            format!(
                "restore preexisting endpoint bypass identity {}",
                managed.route.target
            )
        })?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_default_routes() -> Result<Vec<MacosRouteSpec>> {
    crate::macos_network::macos_default_routes()
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_underlay_default_route_from_routes(
    routes: &[MacosRouteSpec],
) -> Option<MacosRouteSpec> {
    crate::macos_network::macos_underlay_default_route_from_routes(routes)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_underlay_default_route_from_system() -> Result<Option<MacosRouteSpec>> {
    crate::macos_network::macos_underlay_default_route_from_system()
}

#[cfg(target_os = "macos")]
pub(crate) fn delete_macos_managed_route(
    target: &str,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> Result<()> {
    crate::macos_network::delete_macos_managed_route(target, gateway, interface)
}

#[cfg(target_os = "macos")]
pub(crate) fn restore_macos_default_route(route: &MacosRouteSpec) -> Result<()> {
    crate::macos_network::restore_macos_default_route(route)
}

#[cfg(target_os = "macos")]
pub(crate) fn apply_macos_default_route(
    gateway: Option<&str>,
    ifscope: Option<&str>,
) -> Result<()> {
    crate::macos_network::apply_macos_default_route(gateway, ifscope)
}

#[cfg(target_os = "macos")]
pub(crate) fn delete_macos_default_route_for_interface(iface: &str) -> Result<()> {
    crate::macos_network::delete_macos_default_route_for_interface(iface)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_iface_has_ipv4_address(iface: &str, needle: Ipv4Addr) -> Result<bool> {
    crate::macos_network::macos_iface_has_ipv4_address(iface, needle)
}

#[cfg(target_os = "macos")]
pub(crate) fn apply_macos_route_spec(
    target: &str,
    gateway: Option<&str>,
    ifscope: Option<&str>,
) -> Result<()> {
    crate::macos_network::apply_macos_route_spec(target, gateway, ifscope)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_pf_enabled() -> Result<bool> {
    crate::macos_network::macos_pf_enabled()
}

#[cfg(test)]
pub(crate) fn parse_macos_ipv4_forwarding_state(output: &str) -> Result<bool> {
    crate::macos_network::parse_macos_ipv4_forwarding_state(output)
}

#[cfg(test)]
pub(crate) fn parse_macos_pf_enabled(output: &str) -> Result<bool> {
    crate::macos_network::parse_macos_pf_enabled(output)
}

#[cfg(target_os = "macos")]
pub(crate) fn read_macos_ipv4_forwarding() -> Result<bool> {
    crate::macos_network::read_macos_ipv4_forwarding()
}

#[cfg(target_os = "macos")]
pub(crate) fn write_macos_ipv4_forwarding(enabled: bool) -> Result<()> {
    crate::macos_network::write_macos_ipv4_forwarding(enabled)
}

#[cfg(target_os = "macos")]
pub(crate) fn apply_macos_exit_node_pf_rules(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Result<()> {
    crate::macos_network::apply_macos_exit_node_pf_rules(
        tunnel_iface,
        outbound_iface,
        tunnel_source_cidr,
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn enable_macos_pf() -> Result<()> {
    crate::macos_network::enable_macos_pf()
}

#[cfg(target_os = "macos")]
pub(crate) fn cleanup_macos_pf_nat() -> Result<()> {
    crate::macos_network::cleanup_macos_pf_nat()
}

#[cfg(target_os = "linux")]
pub(crate) fn read_linux_ip_forward(family: LinuxExitNodeIpFamily) -> Result<bool> {
    let path = linux_ip_forward_path(family);
    Ok(fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?
        .trim()
        == "1")
}

#[cfg(target_os = "linux")]
pub(crate) fn write_linux_ip_forward(family: LinuxExitNodeIpFamily, enabled: bool) -> Result<()> {
    let path = linux_ip_forward_path(family);
    fs::write(path, if enabled { "1" } else { "0" })
        .with_context(|| format!("failed to write {path}"))
}

#[cfg(test)]
mod linux_route_replay_tests {
    use super::*;

    #[test]
    fn replay_args_preserve_the_captured_default_route() {
        let args =
            linux_route_replay_args("default via 192.0.2.1 dev eth0 metric 100").expect("replay");
        assert_eq!(
            args,
            vec!["default", "via", "192.0.2.1", "dev", "eth0", "metric", "100"]
        );
    }

    #[test]
    fn replay_args_allow_the_route_show_vocabulary() {
        for line in [
            "default via 192.0.2.1 dev eth0 proto dhcp metric 600",
            "default via 192.0.2.1 dev eth0 onlink",
            "default dev eth0 proto static scope link src 192.0.2.5 metric 100",
            "default via 192.0.2.1 dev eth0 mtu lock 1500",
            "default via fe80::1 dev eth0 proto ra metric 1024 expires 25sec pref medium",
            "203.0.113.0/24 dev eth0 proto kernel scope link src 203.0.113.5",
            "203.0.113.7 via 203.0.113.1 dev eth0",
            "198.51.100.1 dev eth0",
        ] {
            assert!(linux_route_replay_args(line).is_ok(), "{line:?} must replay");
        }
    }

    #[test]
    fn replay_args_reject_non_route_tokens() {
        for line in [
            "default via 192.0.2.1 dev eth0 table 42",
            "default via 192.0.2.1 dev eth0 nexthop via 192.0.2.2",
            "default via 192.0.2.1 dev eth0 encap mpls 20",
            "default -batch route.file",
            "default via 192.0.2.1 dev -badiface",
            "default via not-an-address dev eth0",
            "default via 192.0.2.1 dev eth0 metric -1",
            "default via 192.0.2.1 dev eth0 proto 99999999999999999999",
            "unreachable 198.51.100.0/24",
            "",
        ] {
            assert!(
                linux_route_replay_args(line).is_err(),
                "{line:?} must be rejected"
            );
        }
    }
}
