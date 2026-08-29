use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::process::Command as ProcessCommand;

#[cfg(not(target_os = "windows"))]
use netdev::get_default_interface;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use netdev::get_interfaces;

#[cfg(target_os = "macos")]
use crate::macos_network::{
    macos_default_routes, macos_ipconfig_ipv4_for_interface, macos_ipconfig_router_for_interface,
    macos_selected_default_route_from_system, macos_underlay_default_route_from_routes,
    macos_underlay_default_route_from_system,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NetworkSnapshot {
    pub default_interface: Option<String>,
    pub default_interface_mtu: Option<u32>,
    pub primary_ipv4: Option<Ipv4Addr>,
    pub primary_ipv6: Option<Ipv6Addr>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub gateway_ipv6: Option<Ipv6Addr>,
}

impl NetworkSnapshot {
    #[must_use]
    pub(crate) fn fingerprint(&self) -> String {
        [
            self.default_interface.as_deref().unwrap_or(""),
            &self
                .default_interface_mtu
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .primary_ipv4
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .primary_ipv6
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .gateway_ipv4
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .gateway_ipv6
                .map_or_else(String::new, |value| value.to_string()),
        ]
        .join("|")
    }

    #[must_use]
    pub(crate) fn changed_since(&self, previous: &Self) -> bool {
        self.fingerprint() != previous.fingerprint()
    }

    #[must_use]
    pub(crate) fn summary(
        &self,
        changed_at: Option<u64>,
        captive_portal: Option<bool>,
    ) -> NetworkSummary {
        NetworkSummary {
            default_interface: self.default_interface.clone(),
            default_interface_mtu: self.default_interface_mtu,
            primary_ipv4: self.primary_ipv4.map(|value| value.to_string()),
            primary_ipv6: self.primary_ipv6.map(|value| value.to_string()),
            gateway_ipv4: self.gateway_ipv4.map(|value| value.to_string()),
            gateway_ipv6: self.gateway_ipv6.map(|value| value.to_string()),
            changed_at,
            captive_portal,
        }
    }
}

#[must_use]
pub(crate) fn prefer_nonempty_network_snapshot(
    previous: &NetworkSnapshot,
    latest: NetworkSnapshot,
) -> NetworkSnapshot {
    let latest_is_empty = latest.default_interface.is_none()
        && latest.default_interface_mtu.is_none()
        && latest.primary_ipv4.is_none()
        && latest.primary_ipv6.is_none()
        && latest.gateway_ipv4.is_none()
        && latest.gateway_ipv6.is_none();
    let previous_has_underlay = previous.default_interface.is_some()
        || previous.default_interface_mtu.is_some()
        || previous.primary_ipv4.is_some()
        || previous.primary_ipv6.is_some()
        || previous.gateway_ipv4.is_some()
        || previous.gateway_ipv6.is_some();
    if latest_is_empty && previous_has_underlay {
        previous.clone()
    } else {
        latest
    }
}

fn network_snapshot_fingerprint_id(snapshot: &NetworkSnapshot) -> String {
    use sha2::{Digest, Sha256};

    let digest = hex::encode(Sha256::digest(snapshot.fingerprint().as_bytes()));
    digest[..12].to_string()
}

#[derive(Debug)]
pub(crate) struct NetworkSnapshotSample {
    pub(crate) snapshot: NetworkSnapshot,
    pub(crate) diagnostic: String,
    pub(crate) live_unmanaged_ipv4_default_present: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxIpv4DefaultRoute {
    interface: String,
    gateway: Ipv4Addr,
    source: Option<Ipv4Addr>,
    metric: u32,
    on_link: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxIpv6DefaultRoute {
    interface: String,
    gateway: Ipv6Addr,
    metric: u32,
}

#[cfg(any(target_os = "linux", test))]
fn select_linux_underlay_default_route<'a, Route>(
    routes: &'a [Route],
    interface_name: impl Fn(&Route) -> &str,
    metric: impl Fn(&Route) -> u32,
    excluded_interfaces: &[&str],
    mut route_is_usable: impl FnMut(&Route) -> bool,
) -> Option<&'a Route> {
    routes
        .iter()
        .filter(|route| {
            let interface = interface_name(route);
            !excluded_interfaces.contains(&interface) && route_is_usable(route)
        })
        .min_by_key(|route| metric(route))
}

#[cfg(any(target_os = "linux", test))]
fn merge_linux_ipv4_default_routes(
    live_routes: &[LinuxIpv4DefaultRoute],
    cached_routes: &[LinuxIpv4DefaultRoute],
) -> Vec<LinuxIpv4DefaultRoute> {
    let live_interfaces = live_routes
        .iter()
        .map(|route| route.interface.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut routes = cached_routes
        .iter()
        .filter(|route| !live_interfaces.contains(route.interface.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    routes.extend_from_slice(live_routes);
    routes
}

#[cfg(any(target_os = "linux", test))]
fn linux_live_unmanaged_ipv4_default_present(
    live_routes: &[LinuxIpv4DefaultRoute],
    excluded_interfaces: &[&str],
) -> bool {
    live_routes
        .iter()
        .any(|route| !excluded_interfaces.contains(&route.interface.as_str()))
}

#[cfg(any(target_os = "linux", test))]
fn linux_ipv4_default_route_from_spec(spec: crate::LinuxDefaultRouteSpec) -> LinuxIpv4DefaultRoute {
    LinuxIpv4DefaultRoute {
        interface: spec.dev,
        gateway: spec
            .gateway
            .and_then(|gateway| gateway.parse().ok())
            .unwrap_or(Ipv4Addr::UNSPECIFIED),
        source: spec.source.and_then(|source| source.parse().ok()),
        metric: spec.metric,
        on_link: spec.on_link,
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ipv4_default_route_lines(routes: &str) -> Vec<LinuxIpv4DefaultRoute> {
    crate::linux_default_route_specs_from_output(routes)
        .map(linux_ipv4_default_route_from_spec)
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ipv4_default_route_hints(routes: &[String]) -> Vec<LinuxIpv4DefaultRoute> {
    routes
        .iter()
        .filter_map(|line| crate::linux_default_route_spec_from_line(line))
        .map(linux_ipv4_default_route_from_spec)
        .collect()
}

#[cfg(target_os = "linux")]
fn capture_linux_ipv4_default_routes() -> Vec<LinuxIpv4DefaultRoute> {
    ProcessCommand::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            parse_linux_ipv4_default_route_lines(&String::from_utf8_lossy(&output.stdout))
        })
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ipv6_default_routes(route_table: &str) -> Vec<LinuxIpv6DefaultRoute> {
    route_table
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || u8::from_str_radix(fields[1], 16).ok()? != 0
                || u32::from_str_radix(fields[8], 16).ok()? & 1 == 0
            {
                return None;
            }
            let gateway = u128::from_str_radix(fields[4], 16).ok()?;
            Some(LinuxIpv6DefaultRoute {
                interface: fields[9].to_string(),
                gateway: Ipv6Addr::from(gateway),
                metric: u32::from_str_radix(fields[5], 16).ok()?,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn linux_interface_carrier_up(interface: &str) -> bool {
    fs::read_to_string(format!("/sys/class/net/{interface}/carrier"))
        .is_ok_and(|carrier| carrier.trim() == "1")
}

fn usable_ipv4(interface: &netdev::Interface) -> Option<Ipv4Addr> {
    interface
        .ipv4_addrs()
        .into_iter()
        .find(|ip| !ip.is_loopback() && !ip.is_link_local())
}

fn usable_ipv6(interface: &netdev::Interface) -> Option<Ipv6Addr> {
    interface.ipv6_addrs().into_iter().find(|ip| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_unicast_link_local()
            && !ip.is_multicast()
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_interface_state_usable(
    interface: &netdev::Interface,
    carrier_up: bool,
    require_ipv6: bool,
) -> bool {
    interface.is_up()
        && carrier_up
        && if require_ipv6 {
            usable_ipv6(interface).is_some()
        } else {
            usable_ipv4(interface).is_some()
        }
}

#[cfg(target_os = "linux")]
fn linux_interface_usable(interface: &netdev::Interface, require_ipv6: bool) -> bool {
    linux_interface_state_usable(
        interface,
        linux_interface_carrier_up(&interface.name),
        require_ipv6,
    )
}

#[cfg(target_os = "linux")]
fn capture_linux_underlay_network_snapshot_sample(
    excluded_interfaces: &[&str],
    default_route_hints: &[String],
) -> NetworkSnapshotSample {
    let ipv4_routes = capture_linux_ipv4_default_routes();
    let ipv6_routes = fs::read_to_string("/proc/net/ipv6_route")
        .map(|table| parse_linux_ipv6_default_routes(&table))
        .unwrap_or_default();
    let cached_ipv4_routes = parse_linux_ipv4_default_route_hints(default_route_hints);
    let live_unmanaged_ipv4_default_present =
        linux_live_unmanaged_ipv4_default_present(&ipv4_routes, excluded_interfaces);
    let merged_ipv4_routes = merge_linux_ipv4_default_routes(&ipv4_routes, &cached_ipv4_routes);
    let interfaces = get_interfaces();
    let ipv4_route = select_linux_underlay_default_route(
        &merged_ipv4_routes,
        |route| route.interface.as_str(),
        |route| route.metric,
        excluded_interfaces,
        |route| {
            interfaces
                .iter()
                .find(|interface| interface.name == route.interface)
                .is_some_and(|interface| {
                    linux_interface_usable(interface, false)
                        && crate::linux_ipv4_route_fields_match_interface(
                            (!route.gateway.is_unspecified()).then_some(route.gateway),
                            route.source,
                            route.on_link,
                            interface,
                        )
                })
        },
    );
    let ipv6_route = ipv4_route.is_none().then(|| {
        select_linux_underlay_default_route(
            &ipv6_routes,
            |route| route.interface.as_str(),
            |route| route.metric,
            excluded_interfaces,
            |route| {
                interfaces
                    .iter()
                    .find(|interface| interface.name == route.interface)
                    .is_some_and(|interface| linux_interface_usable(interface, true))
            },
        )
    });
    let (interface_name, metric, gateway_ipv4, gateway_ipv6, family) = if let Some(route) =
        ipv4_route
    {
        (
            route.interface.as_str(),
            route.metric,
            (!route.gateway.is_unspecified()).then_some(route.gateway),
            None,
            "ipv4",
        )
    } else if let Some(route) = ipv6_route.flatten() {
        (
            route.interface.as_str(),
            route.metric,
            None,
            (!route.gateway.is_unspecified()).then_some(route.gateway),
            "ipv6",
        )
    } else {
        let snapshot = NetworkSnapshot::default();
        return NetworkSnapshotSample {
            diagnostic: format!(
                "selected=none ipv4_routes={} cached_ipv4_routes={} ipv6_routes={} fingerprint={}",
                ipv4_routes.len(),
                cached_ipv4_routes.len(),
                ipv6_routes.len(),
                network_snapshot_fingerprint_id(&snapshot)
            ),
            snapshot,
            live_unmanaged_ipv4_default_present,
        };
    };
    let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.name == interface_name)
    else {
        unreachable!("selected route was validated against the interface snapshot");
    };
    let snapshot = NetworkSnapshot {
        default_interface: Some(interface.name.clone()),
        default_interface_mtu: interface.mtu,
        primary_ipv4: crate::linux_ipv4_route_primary_address(
            ipv4_route.and_then(|route| route.source),
            ipv4_route.and_then(|route| (!route.gateway.is_unspecified()).then_some(route.gateway)),
            ipv4_route.is_some_and(|route| route.on_link),
            interface,
        ),
        primary_ipv6: usable_ipv6(interface),
        gateway_ipv4,
        gateway_ipv6,
    };
    NetworkSnapshotSample {
        diagnostic: format!(
            "selected={} family={} metric={} ipv4_routes={} cached_ipv4_routes={} ipv6_routes={} fingerprint={}",
            interface_name,
            family,
            metric,
            ipv4_routes.len(),
            cached_ipv4_routes.len(),
            ipv6_routes.len(),
            network_snapshot_fingerprint_id(&snapshot)
        ),
        snapshot,
        live_unmanaged_ipv4_default_present,
    }
}

#[cfg(any(test, target_os = "windows"))]
fn interface_is_excluded(interface: &netdev::Interface, excluded: &[&str]) -> bool {
    excluded.iter().any(|name| {
        interface.name.eq_ignore_ascii_case(name)
            || interface
                .friendly_name
                .as_deref()
                .is_some_and(|friendly| friendly.eq_ignore_ascii_case(name))
    })
}

#[cfg(any(test, target_os = "windows"))]
fn windows_excluded_interface_indices(
    interfaces: &[netdev::Interface],
    excluded_interfaces: &[&str],
) -> Vec<u32> {
    let mut indices = interfaces
        .iter()
        .filter(|interface| interface_is_excluded(interface, excluded_interfaces))
        .map(|interface| interface.index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

#[cfg(any(test, target_os = "windows"))]
fn windows_network_snapshot_from_ipv4_route(
    route: &crate::wg_upstream_runtime::WindowsDefaultRoute,
    interfaces: &[netdev::Interface],
    excluded_interfaces: &[&str],
) -> Option<NetworkSnapshot> {
    let interface = interfaces.iter().find(|interface| {
        interface.index == route.interface_index
            && interface.ipv4_addrs().contains(&route.interface_ipv4)
            && !interface_is_excluded(interface, excluded_interfaces)
    })?;
    Some(NetworkSnapshot {
        default_interface: Some(interface.name.clone()),
        default_interface_mtu: interface.mtu,
        primary_ipv4: Some(route.interface_ipv4),
        primary_ipv6: usable_ipv6(interface),
        gateway_ipv4: route.gateway.parse().ok(),
        gateway_ipv6: None,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn windows_network_snapshot_from_ipv4_capture(
    interfaces: &[netdev::Interface],
    excluded_interfaces: &[&str],
    mut capture_route: impl FnMut(
        &[u32],
    )
        -> anyhow::Result<crate::wg_upstream_runtime::WindowsDefaultRoute>,
) -> Option<NetworkSnapshot> {
    let mut excluded_indices = windows_excluded_interface_indices(interfaces, excluded_interfaces);
    for _ in 0..=interfaces.len() {
        let route = capture_route(&excluded_indices).ok()?;
        if let Some(snapshot) =
            windows_network_snapshot_from_ipv4_route(&route, interfaces, excluded_interfaces)
        {
            return Some(snapshot);
        }
        if excluded_indices.contains(&route.interface_index) {
            return None;
        }
        excluded_indices.push(route.interface_index);
        excluded_indices.sort_unstable();
    }
    None
}

#[cfg(any(test, target_os = "windows"))]
fn windows_network_snapshot_from_ipv6_routes(
    routes: &[crate::wg_upstream_runtime::WindowsIpv6DefaultRoute],
    interfaces: &[netdev::Interface],
    excluded_interfaces: &[&str],
) -> Option<NetworkSnapshot> {
    routes.iter().find_map(|route| {
        let interface = interfaces.iter().find(|interface| {
            interface.index == route.interface_index
                && !interface_is_excluded(interface, excluded_interfaces)
                && usable_ipv6(interface).is_some()
        })?;
        Some(NetworkSnapshot {
            default_interface: Some(interface.name.clone()),
            default_interface_mtu: interface.mtu,
            primary_ipv4: usable_ipv4(interface),
            primary_ipv6: usable_ipv6(interface),
            gateway_ipv4: None,
            gateway_ipv6: route.gateway,
        })
    })
}

#[cfg(target_os = "windows")]
fn capture_windows_network_snapshot(excluded_interfaces: &[&str]) -> NetworkSnapshot {
    let interfaces = get_interfaces();
    if let Some(snapshot) = windows_network_snapshot_from_ipv4_capture(
        &interfaces,
        excluded_interfaces,
        crate::wg_upstream_runtime::capture_windows_default_route_excluding,
    ) {
        return snapshot;
    }
    crate::wg_upstream_runtime::capture_windows_ipv6_default_routes()
        .ok()
        .and_then(|routes| {
            windows_network_snapshot_from_ipv6_routes(&routes, &interfaces, excluded_interfaces)
        })
        .unwrap_or_default()
}

pub(crate) fn capture_network_snapshot_sample_excluding_interfaces(
    excluded_interfaces: &[&str],
    default_route_hints: &[String],
) -> NetworkSnapshotSample {
    #[cfg(target_os = "linux")]
    {
        capture_linux_underlay_network_snapshot_sample(excluded_interfaces, default_route_hints)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = default_route_hints;
        #[cfg(target_os = "windows")]
        let snapshot = capture_windows_network_snapshot(excluded_interfaces);
        #[cfg(not(target_os = "windows"))]
        let snapshot = {
            let _ = excluded_interfaces;
            capture_network_snapshot()
        };
        NetworkSnapshotSample {
            diagnostic: format!(
                "selected={} fingerprint={}",
                snapshot.default_interface.as_deref().unwrap_or("none"),
                network_snapshot_fingerprint_id(&snapshot)
            ),
            snapshot,
            live_unmanaged_ipv4_default_present: false,
        }
    }
}

pub(crate) fn capture_network_snapshot() -> NetworkSnapshot {
    #[cfg(target_os = "windows")]
    return capture_windows_network_snapshot(&[]);

    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(target_os = "macos")]
        {
            let snapshot = capture_macos_network_snapshot();
            if snapshot.default_interface.is_some()
                || snapshot.primary_ipv4.is_some()
                || snapshot.primary_ipv6.is_some()
            {
                return snapshot;
            }
        }
        let mut snapshot = NetworkSnapshot::default();
        let Ok(interface) = get_default_interface() else {
            return snapshot;
        };
        snapshot.default_interface = Some(interface.name.clone());
        snapshot.default_interface_mtu = interface.mtu;
        snapshot.primary_ipv4 = usable_ipv4(&interface);
        snapshot.primary_ipv6 = usable_ipv6(&interface);
        if let Some(gateway) = interface.gateway {
            snapshot.gateway_ipv4 = gateway.ipv4.first().copied();
            snapshot.gateway_ipv6 = gateway.ipv6.first().copied();
        }
        snapshot
    }
}

#[cfg(target_os = "macos")]
fn capture_macos_network_snapshot() -> NetworkSnapshot {
    let mut snapshot = NetworkSnapshot::default();
    let underlay = macos_selected_default_route_from_system()
        .ok()
        .flatten()
        .or_else(|| {
            macos_default_routes().ok().and_then(|routes| {
                macos_underlay_default_route_from_routes(&routes)
                    .or_else(|| macos_underlay_default_route_from_system().ok().flatten())
            })
        })
        .or_else(|| macos_underlay_default_route_from_system().ok().flatten());
    let Some(underlay) = underlay else {
        return snapshot;
    };
    snapshot.default_interface = Some(underlay.interface.clone());
    snapshot.default_interface_mtu = interface_mtu_by_name(&underlay.interface);
    snapshot.primary_ipv4 = macos_ipconfig_ipv4_for_interface(&underlay.interface)
        .ok()
        .flatten();
    snapshot.gateway_ipv4 = underlay
        .gateway
        .as_deref()
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            macos_ipconfig_router_for_interface(&underlay.interface)
                .ok()
                .flatten()
        });
    snapshot
}

#[cfg(target_os = "macos")]
fn interface_mtu_by_name(name: &str) -> Option<u32> {
    get_interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .and_then(|interface| interface.mtu)
}

#[cfg(test)]
#[path = "underlay_snapshot_tests.rs"]
mod tests;
