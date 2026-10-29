#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_CHILD_COMMAND_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

#[cfg(target_os = "windows")]
pub(crate) use nostr_vpn_core::magic_dns::run_windows_command_with_timeout;

#[cfg(target_os = "windows")]
pub(crate) fn run_windows_command(
    command: &mut ProcessCommand,
    operation: &str,
) -> Result<std::process::Output> {
    run_windows_command_with_timeout(command, operation, WINDOWS_CHILD_COMMAND_TIMEOUT)
}

#[cfg(target_os = "windows")]
trait WindowsCommandTimeoutExt {
    fn bounded_output(&mut self, operation: &str) -> Result<std::process::Output>;
}

#[cfg(target_os = "windows")]
impl WindowsCommandTimeoutExt for ProcessCommand {
    fn bounded_output(&mut self, operation: &str) -> Result<std::process::Output> {
        run_windows_command(self, operation)
    }
}

#[cfg(target_os = "windows")]
fn apply_windows_endpoint_bypass_route(
    wg_iface_index: u32,
    upstream: SocketAddr,
    excluded_tunnel_interfaces: &[u32],
    manage_default_v6: bool,
    cleanup_journal_config_path: &Path,
) -> Result<WindowsFullDefaultRoute> {
    apply_windows_managed_default_routes(
        wg_iface_index,
        upstream,
        excluded_tunnel_interfaces,
        true,
        manage_default_v6,
        cleanup_journal_config_path,
    )
}

#[cfg(target_os = "windows")]
fn apply_windows_managed_default_routes(
    wg_iface_index: u32,
    upstream: SocketAddr,
    excluded_tunnel_interfaces: &[u32],
    manage_default: bool,
    manage_default_v6: bool,
    cleanup_journal_config_path: &Path,
) -> Result<WindowsFullDefaultRoute> {
    retry_pending_windows_route_cleanup_journaled(cleanup_journal_config_path)?;
    let upstream_ip = match upstream.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(anyhow!(
                "WG upstream IPv6 endpoint not yet supported on Windows"
            ));
        }
    };
    let mut excluded = excluded_tunnel_interfaces.to_vec();
    excluded.push(wg_iface_index);
    let underlay = capture_windows_default_route_excluding(&excluded)?;
    let mut runner = SystemWindowsRouteCommandRunner::journaled(cleanup_journal_config_path);
    let routes = match WindowsManagedDefaultRoutes::apply_with(
        &mut runner,
        wg_iface_index,
        upstream_ip,
        underlay,
        manage_default,
        manage_default_v6,
    ) {
        Ok(routes) => routes,
        Err(mut failure) => {
            retain_pending_windows_route_cleanup(failure.cleanup.take_cleanup_snapshot());
            return Err(failure.error);
        }
    };
    Ok(WindowsFullDefaultRoute {
        routes,
        cleanup_journal_config_path: cleanup_journal_config_path.to_path_buf(),
    })
}

#[cfg(target_os = "windows")]
pub struct WindowsFullDefaultRoute {
    routes: WindowsManagedDefaultRoutes,
    cleanup_journal_config_path: PathBuf,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsDefaultRoute {
    pub(crate) gateway: String,
    pub(crate) interface_index: u32,
    pub(crate) interface_ipv4: std::net::Ipv4Addr,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsIpv6DefaultRoute {
    pub(crate) gateway: Option<std::net::Ipv6Addr>,
    pub(crate) interface_index: u32,
    pub(crate) metric: u32,
}

#[cfg(target_os = "windows")]
impl WindowsFullDefaultRoute {
    pub fn reconcile_endpoint_and_underlay(
        &mut self,
        upstream: SocketAddr,
        excluded_tunnel_interfaces: &[u32],
    ) -> Result<bool> {
        let upstream_ip = match upstream.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                return Err(anyhow!(
                    "WG upstream IPv6 endpoint not yet supported on Windows"
                ));
            }
        };
        let mut excluded = excluded_tunnel_interfaces.to_vec();
        excluded.push(self.routes.wg_iface_index);
        let fresh_underlay = capture_windows_default_route_excluding(&excluded)?;
        let mut runner =
            SystemWindowsRouteCommandRunner::journaled(&self.cleanup_journal_config_path);
        self.routes.reconcile_with(
            &mut runner,
            upstream_ip,
            fresh_underlay,
            excluded_tunnel_interfaces,
        )
    }

    pub fn revert(&mut self) -> Result<()> {
        self.routes
            .revert_with(&mut SystemWindowsRouteCommandRunner::journaled(
                &self.cleanup_journal_config_path,
            ))
    }

    pub(crate) fn cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        self.routes.cleanup_snapshot()
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsFullDefaultRoute {
    fn drop(&mut self) {
        let mut runner =
            SystemWindowsRouteCommandRunner::journaled(&self.cleanup_journal_config_path);
        if let Err(error) = self.routes.revert_retaining_pending_with(&mut runner) {
            eprintln!(
                "wg-upstream: WARNING — Windows route revert failed: {error}. \
                 You may need to run `netsh interface ipv4 delete route 0.0.0.0/0 \
                 interface={}` manually.",
                self.routes.wg_iface_index
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn capture_windows_default_route_excluding(
    excluded_tunnel_interfaces: &[u32],
) -> Result<WindowsDefaultRoute> {
    capture_windows_default_route_for_interfaces(
        excluded_tunnel_interfaces,
        &netdev::get_interfaces(),
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn capture_windows_default_route_for_interfaces(
    excluded_tunnel_interfaces: &[u32],
    interfaces: &[netdev::Interface],
) -> Result<WindowsDefaultRoute> {
    // `route print -4 0.0.0.0` lists IPv4 default routes. Output
    // includes columns like:
    //   Network Destination | Netmask | Gateway | Interface | Metric
    //   0.0.0.0             | 0.0.0.0 | 192.168.1.1 | 192.168.1.42 | 25
    let output = ProcessCommand::new("route")
        .args(["print", "-4", "0.0.0.0"])
        .bounded_output("`route print -4 0.0.0.0`")?;
    if !output.status.success() {
        return Err(anyhow!("route print failed: {}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    select_windows_default_route_from_output(
        &stdout,
        excluded_tunnel_interfaces,
        interfaces,
    )
}

#[cfg(any(test, target_os = "windows"))]
fn select_windows_default_route_from_output(
    output: &str,
    excluded_tunnel_interfaces: &[u32],
    interfaces: &[netdev::Interface],
) -> Result<WindowsDefaultRoute> {
    select_windows_default_route_candidate(
        parse_windows_default_route_candidates(output),
        excluded_tunnel_interfaces,
        |address| {
            let address = address.parse::<std::net::Ipv4Addr>()?;
            interfaces
                .iter()
                .find(|interface| interface.ipv4.iter().any(|network| network.addr() == address))
                .map(|interface| interface.index)
                .ok_or_else(|| anyhow!("no Windows interface found with IPv4 address {address}"))
        },
    )
}

#[cfg(any(test, target_os = "windows"))]
fn select_windows_default_route_candidate(
    candidates: Vec<ParsedWindowsDefaultRoute>,
    excluded_tunnel_interfaces: &[u32],
    mut resolve_interface_index: impl FnMut(&str) -> Result<u32>,
) -> Result<WindowsDefaultRoute> {
    let mut resolution_failures = Vec::new();
    for candidate in candidates {
        let interface_index = match resolve_interface_index(&candidate.interface_ip) {
            Ok(interface_index) => interface_index,
            Err(error) => {
                resolution_failures.push(format!("{}: {error:#}", candidate.interface_ip));
                continue;
            }
        };
        if excluded_tunnel_interfaces.contains(&interface_index) {
            continue;
        }
        return Ok(WindowsDefaultRoute {
            gateway: candidate.gateway,
            interface_index,
            interface_ipv4: candidate
                .interface_ip
                .parse()
                .context("parse Windows default-route interface IPv4 address")?,
        });
    }
    Err(anyhow!(
        "no physical IPv4 default route found outside excluded tunnel interfaces \
         {excluded_tunnel_interfaces:?}; interface resolution failures: {}",
        resolution_failures.join("; ")
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn capture_windows_ipv6_default_routes() -> Result<Vec<WindowsIpv6DefaultRoute>> {
    let output = ProcessCommand::new("route")
        .args(["print", "-6", "::/0"])
        .bounded_output("`route print -6 ::/0`")?;
    if !output.status.success() {
        return Err(anyhow!("IPv6 route print failed: {}", output.status));
    }
    Ok(parse_windows_ipv6_default_route_columns(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

#[cfg(any(test, target_os = "windows"))]
struct ParsedWindowsDefaultRoute {
    gateway: String,
    interface_ip: String,
    metric: u32,
}

#[cfg(test)]
fn parse_windows_default_route_columns(output: &str) -> Option<ParsedWindowsDefaultRoute> {
    parse_windows_default_route_candidates(output)
        .into_iter()
        .next()
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_default_route_candidates(output: &str) -> Vec<ParsedWindowsDefaultRoute> {
    let mut candidates = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        if tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
            // Some columns may be "On-link" for the gateway when the
            // default goes via a /32 host route; skip those — they
            // can't be used as the bypass nexthop.
            if tokens[2].eq_ignore_ascii_case("on-link") {
                continue;
            }
            let metric = tokens[4].parse::<u32>().unwrap_or(u32::MAX);
            let candidate = ParsedWindowsDefaultRoute {
                gateway: tokens[2].to_string(),
                interface_ip: tokens[3].to_string(),
                metric,
            };
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|candidate| candidate.metric);
    candidates
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_ipv6_default_route_columns(output: &str) -> Vec<WindowsIpv6DefaultRoute> {
    let mut routes = output
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 4 || tokens[2] != "::/0" {
                return None;
            }
            let interface_index = tokens[0].parse().ok()?;
            let metric = tokens[1].parse().ok()?;
            let gateway = if tokens[3].eq_ignore_ascii_case("on-link") {
                None
            } else {
                Some(tokens[3].parse().ok()?)
            };
            Some(WindowsIpv6DefaultRoute {
                gateway,
                interface_index,
                metric,
            })
        })
        .collect::<Vec<_>>();
    routes.sort_by_key(|route| route.metric);
    routes
}

#[cfg(target_os = "windows")]
fn resolve_windows_interface_identity(interface_index: u32) -> Result<String> {
    // This is on the underlay-handoff hot path; avoid a PowerShell startup.
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    let mut row = MIB_IF_ROW2::default();
    row.InterfaceIndex = interface_index;
    let status = unsafe { GetIfEntry2(&mut row) };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32)).with_context(|| {
            format!("resolve stable Windows identity for interface {interface_index}")
        });
    }
    let guid = row.InterfaceGuid;
    Ok(format_windows_interface_guid(
        guid.data1, guid.data2, guid.data3, guid.data4,
    ))
}

#[cfg(any(test, target_os = "windows"))]
fn format_windows_interface_guid(
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
) -> String {
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        data4[0], data4[1], data4[2], data4[3], data4[4], data4[5], data4[6], data4[7]
    )
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_interface_index_for_alias(output: &str, alias: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        let Ok(idx) = tokens[0].parse::<u32>() else {
            continue;
        };
        let name = tokens[4..].join(" ");
        if name.eq_ignore_ascii_case(alias.trim()) {
            return Some(idx);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn resolve_windows_interface_index_for_alias_name(alias: &str) -> Result<u32> {
    let output = ProcessCommand::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .bounded_output("`netsh interface ipv4 show interfaces`")?;
    if !output.status.success() {
        return Err(anyhow!("netsh show interfaces failed: {}", output.status));
    }
    parse_windows_interface_index_for_alias(&String::from_utf8_lossy(&output.stdout), alias)
        .ok_or_else(|| anyhow!("no Windows interface index found for alias {alias:?}"))
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_add_args(route: &WindowsRouteSpec) -> Vec<String> {
    let mut args = vec![
        "interface".to_string(),
        windows_route_family(route).to_string(),
        "add".to_string(),
        "route".to_string(),
        route.prefix.clone(),
        format!("interface={}", route.interface_index),
    ];
    if !route.next_hop_is_on_link() {
        args.push(format!("nexthop={}", route.next_hop));
    }
    args.extend([
        format!("metric={}", route.metric),
        "store=active".to_string(),
    ]);
    args
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_set_args(route: &WindowsRouteSpec) -> Vec<String> {
    let mut args = windows_route_add_args(route);
    args[2] = "set".to_string();
    args
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_delete_args(route: &WindowsRouteSpec) -> Vec<String> {
    vec![
        "interface".to_string(),
        windows_route_family(route).to_string(),
        "delete".to_string(),
        "route".to_string(),
        route.prefix.clone(),
        format!("interface={}", route.interface_index),
        format!("nexthop={}", route.next_hop),
        "store=active".to_string(),
    ]
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_family(route: &WindowsRouteSpec) -> &'static str {
    if route
        .prefix
        .split_once('/')
        .map_or(route.prefix.as_str(), |(address, _)| address)
        .parse::<std::net::Ipv6Addr>()
        .is_ok()
    {
        "ipv6"
    } else {
        "ipv4"
    }
}

#[cfg(target_os = "windows")]
fn windows_route_exists(route: &WindowsRouteSpec, exact_attributes: bool) -> Result<bool> {
    // Reconciliation performs several ownership probes, so query IpHelper
    // directly instead of starting PowerShell for each one.
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };

    let (destination, prefix_length) = route
        .prefix
        .split_once('/')
        .ok_or_else(|| anyhow!("Windows route prefix must be CIDR: {}", route.prefix))?;
    let destination: std::net::IpAddr = destination
        .parse()
        .with_context(|| format!("invalid Windows route address {destination}"))?;
    let prefix_length = prefix_length
        .parse::<u8>()
        .with_context(|| format!("invalid Windows route prefix length {prefix_length}"))?;
    let max_prefix_length = match destination {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    if prefix_length > max_prefix_length {
        return Err(anyhow!(
            "invalid Windows route prefix length {prefix_length}"
        ));
    }
    let next_hop: std::net::IpAddr = route
        .next_hop
        .parse()
        .with_context(|| format!("invalid Windows route next hop {}", route.next_hop))?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = route.interface_index;
    row.DestinationPrefix.Prefix = windows_sockaddr_for_ip(destination);
    row.DestinationPrefix.PrefixLength = prefix_length;
    row.NextHop = windows_sockaddr_for_ip(next_hop);
    let status = unsafe { GetIpForwardEntry2(&mut row) };
    match status {
        ERROR_SUCCESS => Ok(!exact_attributes || row.Metric == route.metric),
        ERROR_NOT_FOUND => Ok(false),
        status => Err(std::io::Error::from_raw_os_error(status as i32))
            .context("query native Windows route ownership state"),
    }
}

#[cfg(target_os = "windows")]
fn windows_sockaddr_for_ip(
    address: std::net::IpAddr,
) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    };

    match address {
        std::net::IpAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        // `S_addr` stores network-order bytes in native memory.
                        S_addr: u32::from_ne_bytes(address.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        std::net::IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

#[cfg(target_os = "windows")]
fn run_windows_netsh(args: &[String]) -> Result<()> {
    let output = ProcessCommand::new("netsh")
        .args(args)
        .bounded_output(&format!("`netsh {}`", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "netsh {} failed:\n  stdout: {}\n  stderr: {}",
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "windows"))]
mod windows_command_timeout_tests {
    use super::*;

    #[test]
    fn native_queries_find_the_physical_default_route() {
        let default =
            capture_windows_default_route_excluding(&[]).expect("capture physical default route");
        let route = WindowsRouteSpec {
            prefix: "0.0.0.0/0".to_string(),
            interface_index: default.interface_index,
            next_hop: default.gateway,
            metric: u32::MAX,
            interface_identity: None,
        };
        assert!(
            windows_route_exists(&route, false).expect("query native route identity"),
            "native lookup must find the default route regardless of metric"
        );
        assert!(
            !resolve_windows_interface_identity(route.interface_index)
                .expect("resolve native interface identity")
                .is_empty()
        );
    }

    #[test]
    fn timed_out_child_is_terminated_and_reported() {
        let mut command = ProcessCommand::new("powershell");
        command.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 5",
        ]);

        let started = std::time::Instant::now();
        let error = run_windows_command_with_timeout(
            &mut command,
            "deliberately slow child",
            std::time::Duration::from_millis(100),
        )
        .expect_err("slow child must time out");

        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(
            error
                .to_string()
                .contains("deliberately slow child timed out")
        );
    }
}
