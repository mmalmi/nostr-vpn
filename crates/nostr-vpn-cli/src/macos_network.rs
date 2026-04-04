use super::*;

pub(super) fn macos_route_get_spec_from_output(output: &str) -> Option<MacosRouteSpec> {
    let mut gateway = None;
    let mut interface = None;

    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("gateway:") {
            let value = value.trim();
            if !value.is_empty() {
                gateway = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("interface:") {
            let value = value.trim();
            if !value.is_empty() {
                interface = Some(value.to_string());
            }
        }
    }

    Some(MacosRouteSpec {
        gateway,
        interface: interface?,
    })
}

pub(super) fn macos_default_routes_from_netstat(output: &str) -> Vec<MacosRouteSpec> {
    let mut routes = Vec::new();

    for line in output.lines().map(str::trim) {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.first().copied() != Some("default") || tokens.len() < 4 {
            continue;
        }

        let iface_index = if tokens.last().copied() == Some("!") {
            tokens.len().saturating_sub(2)
        } else {
            tokens.len().saturating_sub(1)
        };
        let Some(interface) = tokens.get(iface_index) else {
            continue;
        };

        routes.push(MacosRouteSpec {
            gateway: (!tokens[1].starts_with("link#")).then(|| tokens[1].to_string()),
            interface: (*interface).to_string(),
        });
    }

    routes
}

pub(crate) fn macos_has_underlay_default_route(output: &str) -> bool {
    macos_underlay_default_route_from_routes(&macos_default_routes_from_netstat(output)).is_some()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_has_tunnel_split_default_routes(output: &str) -> bool {
    output.lines().map(str::trim).any(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 4 {
            return false;
        }

        let target = tokens[0];
        let iface_index = if tokens.last().copied() == Some("!") {
            tokens.len().saturating_sub(2)
        } else {
            tokens.len().saturating_sub(1)
        };
        let Some(interface) = tokens.get(iface_index).copied() else {
            return false;
        };

        interface.starts_with("utun")
            && matches!(target, "0/1" | "0.0.0.0/1" | "128/1" | "128.0.0.0/1")
    })
}

pub(super) fn macos_underlay_default_route_from_routes(
    routes: &[MacosRouteSpec],
) -> Option<MacosRouteSpec> {
    routes
        .iter()
        .find(|route| {
            route.gateway.is_some()
                && !route.interface.starts_with("utun")
                && !route.interface.starts_with("bridge")
                && route.interface != "lo0"
        })
        .cloned()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_interface_names_from_ifconfig_list(output: &str) -> Vec<String> {
    output
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_current_interface_names() -> Result<Vec<String>> {
    let output = command_stdout_checked(ProcessCommand::new("ifconfig").arg("-l"))?;
    Ok(macos_interface_names_from_ifconfig_list(&output))
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_ipconfig_router_from_output(output: &str) -> Option<Ipv4Addr> {
    for line in output.lines().map(str::trim) {
        let value = if let Some(value) = line.strip_prefix("router (ip):") {
            value.trim()
        } else if let Some(value) = line.strip_prefix("router (ip_mult):") {
            value.trim().trim_start_matches('{').trim_end_matches('}')
        } else {
            continue;
        };

        if let Ok(router) = value.parse::<Ipv4Addr>() {
            return Some(router);
        }
    }

    None
}

#[cfg(target_os = "macos")]
pub(super) fn macos_default_route() -> Result<MacosRouteSpec> {
    let output = command_stdout_checked(
        ProcessCommand::new("route")
            .arg("-n")
            .arg("get")
            .arg("default"),
    )?;
    macos_route_get_spec_from_output(&output)
        .ok_or_else(|| anyhow!("failed to resolve macOS default route"))
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_ipconfig_ipv4_for_interface(iface: &str) -> Result<Option<Ipv4Addr>> {
    match command_stdout_checked(ProcessCommand::new("ipconfig").arg("getifaddr").arg(iface)) {
        Ok(output) => Ok(output.trim().parse::<Ipv4Addr>().ok()),
        Err(error) => {
            if error.to_string().to_ascii_lowercase().contains("not found") {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_ipconfig_router_for_interface(iface: &str) -> Result<Option<Ipv4Addr>> {
    if let Ok(output) = command_stdout_checked(
        ProcessCommand::new("ipconfig")
            .arg("getoption")
            .arg(iface)
            .arg("router"),
    ) && let Ok(router) = output.trim().parse::<Ipv4Addr>()
    {
        return Ok(Some(router));
    }

    let output =
        command_stdout_checked(ProcessCommand::new("ipconfig").arg("getpacket").arg(iface))?;
    Ok(macos_ipconfig_router_from_output(&output))
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_underlay_default_route_from_system() -> Result<Option<MacosRouteSpec>> {
    let output = command_stdout_checked(ProcessCommand::new("ifconfig").arg("-l"))?;
    for iface in macos_interface_names_from_ifconfig_list(&output) {
        if iface.starts_with("utun")
            || iface.starts_with("bridge")
            || iface == "lo0"
            || iface == "gif0"
            || iface == "stf0"
            || iface == "anpi0"
        {
            continue;
        }

        let Some(_ipv4) = macos_ipconfig_ipv4_for_interface(&iface)? else {
            continue;
        };
        let Some(router) = macos_ipconfig_router_for_interface(&iface)? else {
            continue;
        };

        return Ok(Some(MacosRouteSpec {
            gateway: Some(router.to_string()),
            interface: iface,
        }));
    }

    Ok(None)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_tunnel_interfaces_with_ipv4(tunnel_ip: Ipv4Addr) -> Result<Vec<String>> {
    let output = command_stdout_checked(ProcessCommand::new("ifconfig").arg("-l"))?;
    let mut matches = Vec::new();
    for iface in macos_interface_names_from_ifconfig_list(&output) {
        if !iface.starts_with("utun") {
            continue;
        }
        if macos_iface_has_ipv4_address(&iface, tunnel_ip)? {
            matches.push(iface);
        }
    }
    Ok(matches)
}

#[cfg(target_os = "macos")]
pub(crate) fn renew_macos_interface_dhcp(iface: &str) -> Result<()> {
    run_checked(
        ProcessCommand::new("ipconfig")
            .arg("set")
            .arg(iface)
            .arg("DHCP"),
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_macos_underlay_default_route() -> Result<bool> {
    let output = command_stdout_checked(
        ProcessCommand::new("netstat")
            .arg("-rn")
            .arg("-f")
            .arg("inet"),
    )?;
    if macos_has_underlay_default_route(&output) || macos_has_tunnel_split_default_routes(&output) {
        return Ok(false);
    }

    let Some(underlay) = macos_underlay_default_route_from_system()? else {
        return Ok(false);
    };

    if restore_macos_default_route(&underlay).is_ok() {
        let refreshed_output = command_stdout_checked(
            ProcessCommand::new("netstat")
                .arg("-rn")
                .arg("-f")
                .arg("inet"),
        )?;
        if macos_has_underlay_default_route(&refreshed_output) {
            return Ok(true);
        }
    }

    let _ = renew_macos_interface_dhcp(&underlay.interface);
    let refreshed_output = command_stdout_checked(
        ProcessCommand::new("netstat")
            .arg("-rn")
            .arg("-f")
            .arg("inet"),
    )?;
    if macos_has_underlay_default_route(&refreshed_output)
        || macos_has_tunnel_split_default_routes(&refreshed_output)
    {
        return Ok(true);
    }

    restore_macos_default_route(&underlay)?;
    Ok(true)
}

#[cfg(target_os = "macos")]
pub(super) fn macos_default_routes() -> Result<Vec<MacosRouteSpec>> {
    let output = command_stdout_checked(
        ProcessCommand::new("netstat")
            .arg("-rn")
            .arg("-f")
            .arg("inet"),
    )?;
    Ok(macos_default_routes_from_netstat(&output))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_route_to_host(host: Ipv4Addr) -> Result<MacosRouteSpec> {
    let output = command_stdout_checked(
        ProcessCommand::new("route")
            .arg("-n")
            .arg("get")
            .arg(host.to_string()),
    )?;
    macos_route_get_spec_from_output(&output)
        .ok_or_else(|| anyhow!("failed to resolve macOS route for {host}"))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_bypass_route_specs(
    app: &AppConfig,
    peers: &[TunnelPeer],
    tunnel_iface: &str,
    original_default_route: Option<&MacosRouteSpec>,
) -> Result<Vec<MacosEndpointBypassRoute>> {
    let mut hosts = peers
        .iter()
        .filter_map(|peer| match endpoint_host_ip(&peer.endpoint) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .chain(control_plane_bypass_ipv4_hosts(app))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();

    let mut routes = Vec::with_capacity(hosts.len());
    for host in hosts {
        let spec = macos_route_to_host(host)
            .ok()
            .filter(|spec| spec.interface != tunnel_iface)
            .or_else(|| {
                original_default_route
                    .cloned()
                    .filter(|spec| spec.interface != tunnel_iface)
            })
            .ok_or_else(|| anyhow!("failed to resolve macOS bypass route for {host}"))?;
        routes.push(MacosEndpointBypassRoute {
            target: format!("{host}/32"),
            gateway: spec.gateway,
            interface: spec.interface,
        });
    }

    Ok(routes)
}

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_endpoint_bypass_route(route: &MacosEndpointBypassRoute) -> Result<()> {
    apply_macos_route_spec(
        &route.target,
        route.gateway.as_deref(),
        Some(route.interface.as_str()),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn delete_macos_managed_route(
    target: &str,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> Result<()> {
    if gateway.is_none()
        && let Some(iface) = interface
    {
        return delete_macos_route_spec(target, Some(iface));
    }

    delete_macos_route_spec(target, None)
}

#[cfg(target_os = "macos")]
pub(super) fn delete_macos_endpoint_bypass_route(route: &MacosEndpointBypassRoute) -> Result<()> {
    delete_macos_managed_route(
        &route.target,
        route.gateway.as_deref(),
        Some(route.interface.as_str()),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn restore_macos_default_route(route: &MacosRouteSpec) -> Result<()> {
    apply_macos_default_route(route.gateway.as_deref(), Some(route.interface.as_str()))
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_tunnel_default_route_targets() -> &'static [&'static str] {
    &["0.0.0.0/1", "128.0.0.0/1"]
}

#[cfg(any(target_os = "macos", test))]
fn macos_direct_route_family(target: &str) -> &'static str {
    if strip_cidr(target).contains(':') {
        "-inet6"
    } else {
        "-inet"
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_direct_route_args(action: &str, target: &str, iface: &str) -> Vec<String> {
    vec![
        "-q".to_string(),
        "-n".to_string(),
        action.to_string(),
        macos_direct_route_family(target).to_string(),
        target.to_string(),
        "-iface".to_string(),
        iface.to_string(),
    ]
}

#[cfg(any(target_os = "macos", test))]
fn macos_gateway_route_args(action: &str, target: &str, gateway: &str) -> Vec<String> {
    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let mut args = vec!["-n".to_string(), action.to_string()];
    if is_host {
        args.push("-host".to_string());
        args.push(target_ip.to_string());
    } else if target == "0.0.0.0/0" {
        args.push("default".to_string());
    } else {
        args.push("-net".to_string());
        args.push(target.to_string());
    }
    args.push(gateway.to_string());
    args
}

#[cfg(test)]
pub(crate) fn macos_gateway_route_args_for_test(
    action: &str,
    target: &str,
    gateway: &str,
) -> Vec<String> {
    macos_gateway_route_args(action, target, gateway)
}

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_default_route(
    gateway: Option<&str>,
    ifscope: Option<&str>,
) -> Result<()> {
    if let Some(ifscope) = ifscope {
        let _ = delete_macos_default_route_for_interface(ifscope);
    }

    if gateway.is_none() {
        let iface = ifscope.ok_or_else(|| anyhow!("missing interface for direct default route"))?;
        for target in macos_tunnel_default_route_targets() {
            apply_macos_route_spec(target, None, Some(iface)).with_context(|| {
                format!("failed to install macOS default route target {target} on {iface}")
            })?;
        }
        return Ok(());
    }

    let mut change = ProcessCommand::new("route");
    change.arg("-n").arg("change").arg("default");
    change.arg(gateway.expect("gateway checked above"));

    match run_checked(&mut change) {
        Ok(()) => Ok(()),
        Err(_) => {
            let mut add = ProcessCommand::new("route");
            add.arg("-n").arg("add").arg("default");
            add.arg(gateway.expect("gateway checked above"));
            run_checked(&mut add)
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn delete_macos_default_route_for_interface(iface: &str) -> Result<()> {
    let mut failures = Vec::new();
    for target in
        std::iter::once("0.0.0.0/0").chain(macos_tunnel_default_route_targets().iter().copied())
    {
        if let Err(error) = delete_macos_route_spec(target, Some(iface))
            && !crate::daemon_runtime::macos_route_delete_error_is_absent(&error.to_string())
        {
            failures.push(format!("remove {target} on {iface}: {error}"));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}

pub(super) fn macos_ifconfig_has_ipv4(output: &str, needle: Ipv4Addr) -> bool {
    output.lines().map(str::trim).any(|line| {
        line.strip_prefix("inet ")
            .and_then(|rest| rest.split_whitespace().next())
            .is_some_and(|value| value == needle.to_string())
    })
}

#[cfg(target_os = "macos")]
pub(super) fn macos_iface_has_ipv4_address(iface: &str, needle: Ipv4Addr) -> Result<bool> {
    let output = command_stdout_checked(ProcessCommand::new("ifconfig").arg(iface))?;
    Ok(macos_ifconfig_has_ipv4(&output, needle))
}

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_route_spec(
    target: &str,
    gateway: Option<&str>,
    ifscope: Option<&str>,
) -> Result<()> {
    if gateway.is_none() {
        let iface = ifscope.ok_or_else(|| anyhow!("missing interface for direct route"))?;
        let mut add = ProcessCommand::new("route");
        add.args(macos_direct_route_args("add", target, iface));
        return match run_checked(&mut add) {
            Ok(()) => Ok(()),
            Err(_) => {
                let mut change = ProcessCommand::new("route");
                change.args(macos_direct_route_args("change", target, iface));
                run_checked(&mut change)
            }
        };
    }

    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let mut add = ProcessCommand::new("route");
    if let Some(gateway) = gateway {
        add.args(macos_gateway_route_args("add", target, gateway));
    } else {
        add.arg("-n").arg("add");
        if let Some(ifscope) = ifscope {
            add.arg("-ifscope").arg(ifscope);
        }
        if is_host {
            add.arg("-host").arg(target_ip);
        } else if target == "0.0.0.0/0" {
            add.arg("default");
        } else {
            add.arg("-net").arg(target);
        }
        let iface = ifscope.ok_or_else(|| anyhow!("missing interface for direct route"))?;
        add.arg("-interface").arg(iface);
    }

    match run_checked(&mut add) {
        Ok(()) => Ok(()),
        Err(_) => {
            let mut change = ProcessCommand::new("route");
            if let Some(gateway) = gateway {
                change.args(macos_gateway_route_args("change", target, gateway));
            } else {
                change.arg("-n").arg("change");
                if let Some(ifscope) = ifscope {
                    change.arg("-ifscope").arg(ifscope);
                }
                if is_host {
                    change.arg("-host").arg(target_ip);
                } else if target == "0.0.0.0/0" {
                    change.arg("default");
                } else {
                    change.arg("-net").arg(target);
                }
                let iface = ifscope.ok_or_else(|| anyhow!("missing interface for direct route"))?;
                change.arg("-interface").arg(iface);
            }
            run_checked(&mut change)
        }
    }
}

#[cfg(target_os = "macos")]
fn delete_macos_route_spec(target: &str, ifscope: Option<&str>) -> Result<()> {
    if let Some(iface) = ifscope {
        let mut delete = ProcessCommand::new("route");
        delete.args(macos_direct_route_args("delete", target, iface));
        return run_checked(&mut delete);
    }

    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let mut delete = ProcessCommand::new("route");
    delete.arg("-n").arg("delete");
    if is_host {
        delete.arg("-host").arg(target_ip);
    } else if target == "0.0.0.0/0" {
        delete.arg("default");
    } else {
        delete.arg("-net").arg(target);
    }

    run_checked(&mut delete)
}

#[cfg(target_os = "macos")]
pub(super) fn read_macos_ip_forward() -> Result<bool> {
    Ok(command_stdout_checked(
        ProcessCommand::new("sysctl")
            .arg("-n")
            .arg("net.inet.ip.forwarding"),
    )?
    .trim()
        == "1")
}

#[cfg(target_os = "macos")]
pub(super) fn write_macos_ip_forward(enabled: bool) -> Result<()> {
    run_checked(ProcessCommand::new("sysctl").arg("-w").arg(format!(
        "net.inet.ip.forwarding={}",
        if enabled { "1" } else { "0" }
    )))
}

#[cfg(target_os = "macos")]
pub(super) fn ensure_macos_ip_forwarding(
    enabled: bool,
    runtime: &mut MacosExitNodeRuntime,
) -> Result<()> {
    let previous = read_macos_ip_forward()?;
    runtime.ipv4_forward_was_enabled = Some(previous);
    if previous != enabled {
        write_macos_ip_forward(enabled)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const MACOS_PF_EXIT_ANCHOR: &str = "com.apple/to.nostrvpn/exit";

#[cfg(target_os = "macos")]
pub(super) fn macos_pf_enabled() -> Result<bool> {
    Ok(
        command_stdout_checked(ProcessCommand::new("pfctl").arg("-s").arg("info"))?
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("status: enabled")),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn ensure_macos_pf_nat(
    outbound_iface: &str,
    runtime: &mut MacosExitNodeRuntime,
) -> Result<()> {
    let pf_enabled = macos_pf_enabled()?;
    runtime.pf_was_enabled = Some(pf_enabled);
    if !pf_enabled {
        run_checked(ProcessCommand::new("pfctl").arg("-E"))?;
    }

    let rule =
        format!("nat on {outbound_iface} inet from 10.44.0.0/16 to any -> ({outbound_iface})\n");
    let mut child = ProcessCommand::new("pfctl")
        .arg("-a")
        .arg(MACOS_PF_EXIT_ANCHOR)
        .arg("-N")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn pfctl for macOS NAT rules")?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("missing pfctl stdin"))?
        .write_all(rule.as_bytes())
        .context("failed to write PF NAT rules")?;
    let output = child
        .wait_with_output()
        .context("failed to wait for pfctl")?;
    if !output.status.success() {
        return Err(anyhow!(
            "pfctl failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn cleanup_macos_pf_nat() -> Result<()> {
    run_checked(
        ProcessCommand::new("pfctl")
            .arg("-a")
            .arg(MACOS_PF_EXIT_ANCHOR)
            .arg("-F")
            .arg("nat"),
    )
}
