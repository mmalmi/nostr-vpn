#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::ToSocketAddrs;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as ProcessCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::{Context, Result, anyhow};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use netdev::get_interfaces;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use netdev::interface::interface::Interface as NetworkInterface;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use nostr_vpn_core::config::AppConfig;

#[cfg(target_os = "macos")]
use crate::MacosExitNodeRuntime;
#[cfg(any(target_os = "macos", test))]
use crate::MacosRouteSpec;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::TunnelPeer;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::run_checked;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use crate::strip_cidr;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxRouteGetSpec {
    pub(crate) gateway: Option<String>,
    pub(crate) dev: String,
    pub(crate) src: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct LinuxEndpointBypassRoute {
    pub(crate) target: String,
    pub(crate) gateway: Option<String>,
    pub(crate) dev: String,
    pub(crate) src: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct LinuxDefaultRouteSpec {
    pub(crate) line: String,
    pub(crate) dev: String,
}

#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MacosEndpointBypassRoute {
    pub(crate) target: String,
    pub(crate) gateway: Option<String>,
    pub(crate) interface: String,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) const MACOS_TUNNEL_MTU: &str = "1380";

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_default_route_device_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens
            .windows(2)
            .find(|window| window[0] == "dev")
            .map(|window| window[1].to_string())
    })
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
fn linux_default_route_from_output(output: &str) -> Option<LinuxDefaultRouteSpec> {
    let line = output.lines().find(|line| !line.trim().is_empty())?.trim();
    Some(LinuxDefaultRouteSpec {
        line: line.to_string(),
        dev: linux_default_route_device_from_output(line)?,
    })
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
    linux_default_route_for_family("-4", "IPv4")
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_default_ipv6_route() -> Result<LinuxDefaultRouteSpec> {
    linux_default_route_for_family("-6", "IPv6")
}

#[cfg(target_os = "linux")]
fn linux_default_route_for_family(
    family_flag: &str,
    family_label: &str,
) -> Result<LinuxDefaultRouteSpec> {
    let output = command_stdout_checked(
        ProcessCommand::new("ip")
            .arg(family_flag)
            .arg("route")
            .arg("show")
            .arg("default"),
    )?;
    linux_default_route_from_output(&output)
        .ok_or_else(|| anyhow!("failed to resolve default {family_label} route"))
}

#[cfg(target_os = "linux")]
pub(crate) fn restore_linux_default_route(route: &str) -> Result<()> {
    let mut command = ProcessCommand::new("ip");
    command.arg("-4").arg("route").arg("replace");
    for token in route.split_whitespace() {
        command.arg(token);
    }
    run_checked(&mut command)
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn relay_bypass_ipv4_hosts(app: &AppConfig) -> Vec<Ipv4Addr> {
    let mut hosts = app
        .nostr
        .relays
        .iter()
        .flat_map(|relay| relay_ipv4_hosts(relay))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn relay_ipv4_hosts(relay: &str) -> Vec<Ipv4Addr> {
    let Some((host, port)) = relay_host_port(relay) else {
        return Vec::new();
    };

    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }

    if host.parse::<IpAddr>().is_ok() {
        return Vec::new();
    }

    (host.as_str(), port)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter_map(|addr| match addr.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn relay_host_port(relay: &str) -> Option<(String, u16)> {
    let relay = relay.trim();
    if relay.is_empty() {
        return None;
    }

    let (scheme, remainder) = relay
        .split_once("://")
        .map_or(("", relay), |(scheme, rest)| (scheme, rest));
    let authority = remainder.split('/').next().unwrap_or(remainder);
    let default_port = match scheme {
        "wss" | "https" => 443,
        _ => 80,
    };

    split_host_port(authority, default_port)
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn stun_host_port(server: &str) -> Option<(String, u16)> {
    let server = server.trim();
    if server.is_empty() {
        return None;
    }

    let authority = server
        .strip_prefix("stun://")
        .or_else(|| server.strip_prefix("stun:"))
        .unwrap_or(server);

    split_host_port(authority, 3478)
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn stun_ipv4_hosts(app: &AppConfig) -> Vec<Ipv4Addr> {
    let mut hosts = app
        .nat
        .stun_servers
        .iter()
        .filter_map(|server| stun_host_port(server))
        .flat_map(|(host, port)| {
            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                return vec![ip];
            }

            if host.parse::<IpAddr>().is_ok() {
                return Vec::new();
            }

            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addrs| {
                    addrs
                        .filter_map(|addr| match addr.ip() {
                            IpAddr::V4(ip) => Some(ip),
                            IpAddr::V6(_) => None,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn reflector_ipv4_hosts(app: &AppConfig) -> Vec<Ipv4Addr> {
    let mut hosts = app
        .nat
        .reflectors
        .iter()
        .filter_map(|reflector| reflector.parse::<SocketAddr>().ok())
        .filter_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn management_ipv4_hosts_from_interfaces(interfaces: &[NetworkInterface]) -> Vec<Ipv4Addr> {
    let mut hosts = interfaces
        .iter()
        .filter(|interface| interface.is_up() && !interface.is_loopback() && !interface.is_tun())
        .flat_map(|interface| {
            let gateways = interface
                .gateway
                .iter()
                .flat_map(|gateway| gateway.ipv4.iter().copied());
            let dns_servers = interface
                .dns_servers
                .iter()
                .filter_map(|server| match server {
                    IpAddr::V4(ip) => Some(*ip),
                    IpAddr::V6(_) => None,
                });
            gateways.chain(dns_servers).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn control_plane_bypass_ipv4_hosts_from_interfaces(
    app: &AppConfig,
    interfaces: &[NetworkInterface],
) -> Vec<Ipv4Addr> {
    let mut hosts = relay_bypass_ipv4_hosts(app);
    hosts.extend(stun_ipv4_hosts(app));
    hosts.extend(reflector_ipv4_hosts(app));
    hosts.extend(management_ipv4_hosts_from_interfaces(interfaces));
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn control_plane_bypass_ipv4_hosts(app: &AppConfig) -> Vec<Ipv4Addr> {
    control_plane_bypass_ipv4_hosts_from_interfaces(app, &get_interfaces())
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
pub(crate) fn linux_bypass_route_specs(
    app: &AppConfig,
    peers: &[TunnelPeer],
    tunnel_iface: &str,
    original_default_route: Option<&str>,
) -> Result<Vec<LinuxEndpointBypassRoute>> {
    let mut hosts = peers
        .iter()
        .filter_map(|peer| match crate::endpoint_host_ip(&peer.endpoint) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .chain(control_plane_bypass_ipv4_hosts(app))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();

    let mut routes = Vec::with_capacity(hosts.len());
    for host in hosts {
        let output = command_stdout_checked(
            ProcessCommand::new("ip")
                .arg("-4")
                .arg("route")
                .arg("get")
                .arg(host.to_string()),
        )?;
        let spec = linux_route_get_spec_from_output(&output)
            .and_then(|spec| {
                if spec.dev == tunnel_iface {
                    None
                } else {
                    Some(spec)
                }
            })
            .or_else(|| {
                original_default_route
                    .and_then(linux_route_get_spec_from_output)
                    .filter(|spec| spec.dev != tunnel_iface)
            })
            .ok_or_else(|| anyhow!("failed to resolve bypass route for {host}"))?;
        routes.push(LinuxEndpointBypassRoute {
            target: format!("{host}/32"),
            gateway: spec.gateway,
            dev: spec.dev,
            src: spec.src,
        });
    }

    Ok(routes)
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_linux_endpoint_bypass_route(route: &LinuxEndpointBypassRoute) -> Result<()> {
    let mut command = ProcessCommand::new("ip");
    command
        .arg("-4")
        .arg("route")
        .arg("replace")
        .arg(&route.target);
    if let Some(gateway) = route.gateway.as_deref() {
        command.arg("via").arg(gateway);
    }
    command.arg("dev").arg(&route.dev);
    if let Some(src) = route.src.as_deref() {
        command.arg("src").arg(src);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_linux_endpoint_bypass_route(target: &str) -> Result<()> {
    run_checked(
        ProcessCommand::new("ip")
            .arg("-4")
            .arg("route")
            .arg("del")
            .arg(target),
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_default_route() -> Result<MacosRouteSpec> {
    crate::macos_network::macos_default_route()
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_default_routes() -> Result<Vec<MacosRouteSpec>> {
    crate::macos_network::macos_default_routes()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_underlay_default_route_from_routes(
    routes: &[MacosRouteSpec],
) -> Option<MacosRouteSpec> {
    crate::macos_network::macos_underlay_default_route_from_routes(routes)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_bypass_route_specs(
    app: &AppConfig,
    peers: &[TunnelPeer],
    tunnel_iface: &str,
    original_default_route: Option<&MacosRouteSpec>,
) -> Result<Vec<MacosEndpointBypassRoute>> {
    crate::macos_network::macos_bypass_route_specs(app, peers, tunnel_iface, original_default_route)
}

#[cfg(target_os = "macos")]
pub(crate) fn apply_macos_endpoint_bypass_route(route: &MacosEndpointBypassRoute) -> Result<()> {
    crate::macos_network::apply_macos_endpoint_bypass_route(route)
}

#[cfg(target_os = "macos")]
pub(crate) fn delete_macos_endpoint_bypass_route(route: &MacosEndpointBypassRoute) -> Result<()> {
    crate::macos_network::delete_macos_endpoint_bypass_route(route)
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
pub(crate) fn read_macos_ip_forward() -> Result<bool> {
    crate::macos_network::read_macos_ip_forward()
}

#[cfg(target_os = "macos")]
pub(crate) fn write_macos_ip_forward(enabled: bool) -> Result<()> {
    crate::macos_network::write_macos_ip_forward(enabled)
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_macos_ip_forwarding(
    enabled: bool,
    runtime: &mut MacosExitNodeRuntime,
) -> Result<()> {
    crate::macos_network::ensure_macos_ip_forwarding(enabled, runtime)
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_macos_pf_nat(
    outbound_iface: &str,
    runtime: &mut MacosExitNodeRuntime,
) -> Result<()> {
    crate::macos_network::ensure_macos_pf_nat(outbound_iface, runtime)
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

#[cfg(target_os = "linux")]
fn linux_ip_forward_path(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "/proc/sys/net/ipv4/ip_forward",
        LinuxExitNodeIpFamily::V6 => "/proc/sys/net/ipv6/conf/all/forwarding",
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_source_cidr(tunnel_ip: &str) -> Option<String> {
    let octets = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok()?.octets();
    if octets[0] == 10 && octets[1] == 44 {
        return Some("10.44.0.0/16".to_string());
    }

    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxExitNodeIpFamily {
    V4,
    V6,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LinuxExitNodeDefaultRouteFamilies {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_exit_node_default_route_families(
    routes: &[String],
) -> LinuxExitNodeDefaultRouteFamilies {
    LinuxExitNodeDefaultRouteFamilies {
        ipv4: routes.iter().any(|route| route == "0.0.0.0/0"),
        ipv6: routes.iter().any(|route| route == "::/0"),
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_firewall_binary(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "iptables",
        LinuxExitNodeIpFamily::V6 => "ip6tables",
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_forward_in_rule(
    iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-in",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-in",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_forward_out_rule(
    iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-o".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "RELATED,ESTABLISHED".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-out",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-out",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_ipv4_masquerade_rule(
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Vec<String> {
    vec![
        "POSTROUTING".to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-exit-masq".to_string(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn linux_iptables_rule_exists(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<bool> {
    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-C");
    for arg in rule {
        command.arg(arg);
    }

    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "command failed: {display}\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_iptables_ensure_rule(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-A");
    for arg in rule {
        command.arg(arg);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_iptables_delete_rule(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if !linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-D");
    for arg in rule {
        command.arg(arg);
    }
    run_checked(&mut command)
}

#[cfg(any(test, not(target_os = "windows")))]
pub(crate) fn apply_local_interface_network(
    iface: &str,
    address: &str,
    route_targets: &[String],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let ipv4_route_source = linux_ipv4_route_source(address);
        run_checked(
            ProcessCommand::new("ip")
                .arg("address")
                .arg("replace")
                .arg(address)
                .arg("dev")
                .arg(iface),
        )?;
        run_checked(
            ProcessCommand::new("ip")
                .arg("link")
                .arg("set")
                .arg("mtu")
                .arg("1380")
                .arg("up")
                .arg("dev")
                .arg(iface),
        )?;
        for target in route_targets {
            if target == "0.0.0.0/0" {
                let _ = ProcessCommand::new("ip")
                    .arg("-4")
                    .arg("route")
                    .arg("del")
                    .arg("default")
                    .status();
            } else if target == "::/0" {
                let _ = ProcessCommand::new("ip")
                    .arg("-6")
                    .arg("route")
                    .arg("del")
                    .arg("default")
                    .status();
            }
            let mut command = ProcessCommand::new("ip");
            command
                .arg("route")
                .arg("replace")
                .arg(target)
                .arg("dev")
                .arg(iface);
            if linux_route_target_is_ipv4(target)
                && let Some(source) = ipv4_route_source.as_deref()
            {
                command.arg("src").arg(source);
            }
            run_checked(&mut command)?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let ip = strip_cidr(address).to_string();
        run_checked(
            ProcessCommand::new("ifconfig")
                .arg(iface)
                .arg("inet")
                .arg(&ip)
                .arg(&ip)
                .arg("netmask")
                .arg("255.255.255.0")
                .arg("mtu")
                .arg(MACOS_TUNNEL_MTU)
                .arg("up"),
        )?;
        eprintln!(
            "tunnel: applying macOS interface {} with routes [{}]",
            iface,
            route_targets.join(", ")
        );
        for target in route_targets {
            apply_macos_route(iface, target)?;
        }
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (iface, address, route_targets);

    #[allow(unreachable_code)]
    Err(anyhow!(
        "interface setup is not implemented for this platform"
    ))
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_ipv4_route_source(address: &str) -> Option<String> {
    strip_cidr(address)
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| ip.to_string())
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_route_target_is_ipv4(target: &str) -> bool {
    strip_cidr(target).parse::<Ipv4Addr>().is_ok()
}

#[cfg(target_os = "macos")]
fn apply_macos_route(iface: &str, target: &str) -> Result<()> {
    if target == "0.0.0.0/0" {
        eprintln!("tunnel: applying macOS default route via interface {iface}");
        return apply_macos_default_route(None, Some(iface));
    }
    apply_macos_route_spec(target, None, Some(iface))
}
