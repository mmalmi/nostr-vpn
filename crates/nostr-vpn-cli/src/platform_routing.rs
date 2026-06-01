#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::IpAddr;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::Ipv6Addr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::ToSocketAddrs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as ProcessCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use anyhow::{Result, anyhow};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use netdev::get_interfaces;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use netdev::interface::interface::Interface as NetworkInterface;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use nostr_vpn_core::config::AppConfig;

#[cfg(any(target_os = "macos", test))]
use crate::MacosRouteSpec;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::run_checked;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use crate::strip_cidr;

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub(crate) fn linux_default_route_device_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens
            .windows(2)
            .find(|window| window[0] == "dev")
            .map(|window| window[1].to_string())
    })
}

#[cfg(target_os = "linux")]
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
    for token in route.split_whitespace() {
        command.arg(token);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_linux_default_route() -> Result<()> {
    run_checked(
        ProcessCommand::new("ip")
            .arg("-4")
            .arg("route")
            .arg("del")
            .arg("default"),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_linux_default_ipv6_route() -> Result<()> {
    run_checked(
        ProcessCommand::new("ip")
            .arg("-6")
            .arg("route")
            .arg("del")
            .arg("default"),
    )
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn control_plane_bypass_ipv4_hosts_from_interfaces(
    app: &AppConfig,
    interfaces: &[NetworkInterface],
) -> Vec<Ipv4Addr> {
    let mut hosts = relay_bypass_ipv4_hosts(app);
    hosts.extend(stun_ipv4_hosts(app));
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
pub(crate) fn linux_bypass_route_specs_for_hosts(
    mut hosts: Vec<Ipv4Addr>,
    tunnel_iface: &str,
    original_default_route: Option<&str>,
) -> Result<Vec<LinuxEndpointBypassRoute>> {
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

#[cfg(target_os = "linux")]
fn linux_ip_forward_path(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "/proc/sys/net/ipv4/ip_forward",
        LinuxExitNodeIpFamily::V6 => "/proc/sys/net/ipv6/conf/all/forwarding",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
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
#[cfg_attr(all(test, target_os = "windows"), allow(dead_code))]
pub(crate) struct LinuxExitNodeDefaultRouteFamilies {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[cfg_attr(all(test, target_os = "windows"), allow(dead_code))]
pub(crate) fn linux_exit_node_default_route_families(
    routes: &[String],
) -> LinuxExitNodeDefaultRouteFamilies {
    LinuxExitNodeDefaultRouteFamilies {
        ipv4: routes.iter().any(|route| route == "0.0.0.0/0"),
        ipv6: routes.iter().any(|route| route == "::/0"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_exit_node_firewall_binary(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "iptables",
        LinuxExitNodeIpFamily::V6 => "ip6tables",
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_forward_in_rule(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        tunnel_iface.to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
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
    tunnel_iface: &str,
    outbound_iface: &str,
    family: LinuxExitNodeIpFamily,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        outbound_iface.to_string(),
        "-o".to_string(),
        tunnel_iface.to_string(),
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
pub(crate) fn linux_exit_node_legacy_forward_in_rule(
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
pub(crate) fn linux_exit_node_legacy_forward_out_rule(
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

#[cfg(target_os = "linux")]
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

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_exit_node_ipv4_mss_clamp_rule(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
    mss: u16,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        tunnel_iface.to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-exit-mss".to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--set-mss".to_string(),
        mss.to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_wireguard_exit_inbound_drop_rule(
    wireguard_iface: &str,
    tunnel_iface: &str,
    tunnel_source_cidr: &str,
) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        wireguard_iface.to_string(),
        "-o".to_string(),
        tunnel_iface.to_string(),
        "-d".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "NEW,INVALID".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-wg-upstream-inbound-drop".to_string(),
        "-j".to_string(),
        "DROP".to_string(),
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
pub(crate) fn linux_iptables_ensure_rule_at_front(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let Some((chain, args)) = rule.split_first() else {
        return Err(anyhow!("iptables rule is missing a chain"));
    };

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-I").arg(chain).arg("1");
    for arg in args {
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
#[cfg_attr(all(test, target_os = "windows"), allow(dead_code))]
#[allow(dead_code)]
pub(crate) fn apply_local_interface_network_with_mtu(
    iface: &str,
    address: &str,
    route_targets: &[String],
    mtu: u16,
) -> Result<()> {
    apply_local_interface_network_with_mtu_and_addresses(
        iface,
        &[address.to_string()],
        route_targets,
        mtu,
    )
}

#[cfg(any(test, not(target_os = "windows")))]
#[cfg_attr(all(test, target_os = "windows"), allow(dead_code))]
pub(crate) fn apply_local_interface_network_with_mtu_and_addresses(
    iface: &str,
    addresses: &[String],
    route_targets: &[String],
    mtu: u16,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mtu = mtu.to_string();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mtu = mtu.as_str();
    #[cfg(target_os = "linux")]
    {
        let ipv4_route_source = addresses
            .iter()
            .find_map(|address| linux_ipv4_route_source(address));
        let local_has_ipv4 = addresses
            .iter()
            .any(|address| linux_tunnel_address_is_ipv4(address));
        let local_has_ipv6 = addresses
            .iter()
            .any(|address| linux_tunnel_address_is_ipv6(address));
        for address in addresses {
            run_checked(
                ProcessCommand::new("ip")
                    .arg("address")
                    .arg("replace")
                    .arg(address)
                    .arg("dev")
                    .arg(iface),
            )?;
        }
        run_checked(
            ProcessCommand::new("ip")
                .arg("link")
                .arg("set")
                .arg("mtu")
                .arg(mtu)
                .arg("up")
                .arg("dev")
                .arg(iface),
        )?;
        for target in route_targets {
            if linux_route_target_is_ipv4(target) && !local_has_ipv4 {
                continue;
            }
            if linux_route_target_is_ipv6(target) && !local_has_ipv6 {
                continue;
            }
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
            command.args(linux_route_replace_args(
                target,
                iface,
                ipv4_route_source.as_deref(),
            ));
            run_checked(&mut command)?;
            if target == "fd00::/8" {
                let _ = ProcessCommand::new("ip")
                    .arg("-6")
                    .arg("rule")
                    .arg("add")
                    .arg("to")
                    .arg(target)
                    .arg("table")
                    .arg("main")
                    .arg("priority")
                    .arg("5265")
                    .status();
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let primary_address = addresses
            .iter()
            .find(|address| linux_tunnel_address_is_ipv4(address))
            .or_else(|| addresses.first())
            .ok_or_else(|| anyhow!("no tunnel interface address configured"))?;
        let ip = strip_cidr(primary_address).to_string();
        run_checked(
            ProcessCommand::new("ifconfig")
                .arg(iface)
                .arg("inet")
                .arg(&ip)
                .arg(&ip)
                .arg("netmask")
                .arg("255.255.255.0")
                .arg("mtu")
                .arg(mtu)
                .arg("up"),
        )?;
        for address in addresses {
            if !linux_tunnel_address_is_ipv6(address) {
                continue;
            }
            let (ip, prefix) = split_cidr(address, "128");
            run_checked(
                ProcessCommand::new("ifconfig")
                    .arg(iface)
                    .arg("inet6")
                    .arg(ip)
                    .arg("prefixlen")
                    .arg(prefix)
                    .arg("alias"),
            )?;
        }
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
    let _ = (iface, addresses, route_targets, mtu);

    #[allow(unreachable_code)]
    Err(anyhow!(
        "interface setup is not implemented for this platform"
    ))
}

#[cfg(target_os = "macos")]
fn split_cidr<'a>(address: &'a str, default_prefix: &'a str) -> (&'a str, &'a str) {
    address.split_once('/').unwrap_or((address, default_prefix))
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_ipv4_route_source(address: &str) -> Option<String> {
    strip_cidr(address)
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| ip.to_string())
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_replace_args(
    target: &str,
    iface: &str,
    ipv4_route_source: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if linux_route_target_is_ipv6(target) {
        args.push("-6".to_string());
    } else if linux_route_target_is_ipv4(target) {
        args.push("-4".to_string());
    }
    args.extend([
        "route".to_string(),
        "replace".to_string(),
        target.to_string(),
        "dev".to_string(),
        iface.to_string(),
    ]);
    if linux_route_target_is_ipv4(target)
        && let Some(source) = ipv4_route_source
    {
        args.push("src".to_string());
        args.push(source.to_string());
    }
    args
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_tunnel_address_is_ipv4(address: &str) -> bool {
    strip_cidr(address).parse::<Ipv4Addr>().is_ok()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_tunnel_address_is_ipv6(address: &str) -> bool {
    strip_cidr(address).parse::<Ipv6Addr>().is_ok()
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn linux_route_target_is_ipv4(target: &str) -> bool {
    strip_cidr(target).parse::<Ipv4Addr>().is_ok()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn linux_route_target_is_ipv6(target: &str) -> bool {
    strip_cidr(target).parse::<Ipv6Addr>().is_ok()
}

#[cfg(target_os = "macos")]
fn apply_macos_route(iface: &str, target: &str) -> Result<()> {
    if linux_route_target_is_ipv6(target) {
        let (target_ip, prefix) = split_cidr(target, "128");
        let _ = ProcessCommand::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("-prefixlen")
            .arg(prefix)
            .arg(target_ip)
            .arg("-interface")
            .arg(iface)
            .status();
        return run_checked(
            ProcessCommand::new("route")
                .arg("add")
                .arg("-inet6")
                .arg("-prefixlen")
                .arg(prefix)
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        );
    }
    if target == "0.0.0.0/0" {
        eprintln!("tunnel: applying macOS default route via interface {iface}");
        return apply_macos_default_route(None, Some(iface));
    }
    apply_macos_route_spec(target, None, Some(iface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_route_family_helpers_detect_ipv4_and_ipv6_cidrs() {
        assert!(linux_tunnel_address_is_ipv4("10.44.0.1/32"));
        assert!(!linux_tunnel_address_is_ipv6("10.44.0.1/32"));
        assert!(linux_tunnel_address_is_ipv6("fd00::1/128"));
        assert!(!linux_tunnel_address_is_ipv4("fd00::1/128"));
        assert!(linux_route_target_is_ipv4("0.0.0.0/0"));
        assert!(!linux_route_target_is_ipv4("::/0"));
        assert!(linux_route_target_is_ipv6("::/0"));
        assert!(!linux_route_target_is_ipv6("10.44.0.0/16"));
    }

    #[test]
    fn platform_routing_parses_relay_and_stun_host_ports() {
        assert_eq!(
            relay_host_port("wss://relay.example.com"),
            Some(("relay.example.com".to_string(), 443))
        );
        assert_eq!(
            relay_host_port("ws://relay.example.com:8080/path"),
            Some(("relay.example.com".to_string(), 8080))
        );
        assert_eq!(
            relay_host_port("relay.example.com"),
            Some(("relay.example.com".to_string(), 80))
        );
        assert_eq!(
            stun_host_port("stun:stun.example.com"),
            Some(("stun.example.com".to_string(), 3478))
        );
        assert_eq!(
            stun_host_port("[2001:db8::1]:5349"),
            Some(("2001:db8::1".to_string(), 5349))
        );
    }

    #[test]
    fn linux_route_replace_args_selects_address_family() {
        assert_eq!(
            linux_route_replace_args("fd00::/8", "utun100", Some("10.44.0.1")),
            vec!["-6", "route", "replace", "fd00::/8", "dev", "utun100"]
        );
        assert_eq!(
            linux_route_replace_args("10.44.0.2/32", "utun100", Some("10.44.0.1")),
            vec![
                "-4",
                "route",
                "replace",
                "10.44.0.2/32",
                "dev",
                "utun100",
                "src",
                "10.44.0.1"
            ]
        );
    }

    #[test]
    fn wireguard_upstream_inbound_drop_rule_blocks_new_mesh_forwards() {
        assert_eq!(
            linux_wireguard_exit_inbound_drop_rule("nvpn-wg-exit", "nvpn0", "10.44.0.0/16"),
            vec![
                "FORWARD",
                "-i",
                "nvpn-wg-exit",
                "-o",
                "nvpn0",
                "-d",
                "10.44.0.0/16",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW,INVALID",
                "-m",
                "comment",
                "--comment",
                "nvpn-wg-upstream-inbound-drop",
                "-j",
                "DROP",
            ]
        );
    }

    #[test]
    fn exit_node_forward_rules_are_scoped_to_mesh_source_and_outbound_iface() {
        assert_eq!(
            linux_exit_node_forward_in_rule(
                "utun100",
                "enp41s0",
                "10.44.0.0/16",
                LinuxExitNodeIpFamily::V4
            ),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-o",
                "enp41s0",
                "-s",
                "10.44.0.0/16",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-forward-in",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_forward_out_rule("utun100", "enp41s0", LinuxExitNodeIpFamily::V4),
            vec![
                "FORWARD",
                "-i",
                "enp41s0",
                "-o",
                "utun100",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-forward-out",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_ipv4_mss_clamp_rule("utun100", "enp41s0", "10.44.0.0/16", 1110),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-o",
                "enp41s0",
                "-s",
                "10.44.0.0/16",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit-mss",
                "-j",
                "TCPMSS",
                "--set-mss",
                "1110",
            ]
        );
    }

    #[test]
    fn legacy_exit_node_forward_rules_match_old_unscoped_rules_for_cleanup() {
        assert_eq!(
            linux_exit_node_legacy_forward_in_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD",
                "-i",
                "utun100",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit6-forward-in",
                "-j",
                "ACCEPT",
            ]
        );
        assert_eq!(
            linux_exit_node_legacy_forward_out_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD",
                "-o",
                "utun100",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                "nvpn-exit6-forward-out",
                "-j",
                "ACCEPT",
            ]
        );
    }
}
