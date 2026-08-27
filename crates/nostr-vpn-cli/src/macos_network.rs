use super::*;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::{io, thread};
#[cfg(target_os = "macos")]
use tokio::sync::mpsc;

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

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_selected_default_route_from_route_get(output: &str) -> Option<MacosRouteSpec> {
    let mut gateway = None;
    let mut interface = None;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("gateway:") {
            let value = value.trim();
            if !value.is_empty() && !value.starts_with("link#") {
                gateway = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("interface:") {
            let value = value.trim();
            if !value.is_empty() {
                interface = Some(value.to_string());
            }
        }
    }

    let interface = interface?;
    if gateway.is_none()
        || interface.starts_with("utun")
        || interface.starts_with("bridge")
        || interface == "lo0"
    {
        return None;
    }

    Some(MacosRouteSpec { gateway, interface })
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_selected_default_route_from_system() -> Result<Option<MacosRouteSpec>> {
    let output = command_stdout_checked(
        ProcessCommand::new("route")
            .arg("-n")
            .arg("get")
            .arg("default"),
    )?;
    Ok(macos_selected_default_route_from_route_get(&output))
}

#[cfg(target_os = "macos")]
pub(crate) fn spawn_macos_route_change_monitor() -> Option<mpsc::Receiver<()>> {
    let fd = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        eprintln!(
            "daemon: failed to open macOS route monitor socket: {}",
            io::Error::last_os_error()
        );
        return None;
    }

    let (tx, rx) = mpsc::channel(1);
    let spawn_result = thread::Builder::new()
        .name("nvpn-macos-route-monitor".to_string())
        .spawn(move || {
            let _fd = MacosRouteMonitorFd(fd);
            let mut buf = [0_u8; 8192];
            loop {
                let read = unsafe {
                    libc::read(
                        fd,
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len() as libc::size_t,
                    )
                };
                if read < 0 {
                    eprintln!(
                        "daemon: macOS route monitor read failed: {}",
                        io::Error::last_os_error()
                    );
                    break;
                }
                if read == 0 {
                    continue;
                }
                if !macos_route_message_is_underlay_relevant(&buf[..read as usize]) {
                    continue;
                }
                match tx.try_send(()) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
                    Err(mpsc::error::TrySendError::Closed(())) => break,
                }
            }
        });

    match spawn_result {
        Ok(_) => Some(rx),
        Err(error) => {
            unsafe {
                libc::close(fd);
            }
            eprintln!("daemon: failed to spawn macOS route monitor: {error}");
            None
        }
    }
}

#[cfg(target_os = "macos")]
struct MacosRouteMonitorFd(libc::c_int);

#[cfg(target_os = "macos")]
impl Drop for MacosRouteMonitorFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_route_message_is_underlay_relevant(message: &[u8]) -> bool {
    let Some(message_type) = message.get(3).copied() else {
        return false;
    };
    // A handoff can be route-only: macOS may delete the old default route and
    // add the replacement without emitting a separate address or interface
    // notification. Include route add/delete/change so the daemon observes
    // that transition immediately. The debounced NetworkSnapshot comparison
    // below this monitor makes notifications caused by nvpn's own host-route
    // maintenance a no-op.
    matches!(message_type, 0x01 | 0x02 | 0x03 | 0x0c | 0x0d | 0x0e | 0x12)
}

pub(super) fn macos_underlay_default_route_from_routes(
    routes: &[MacosRouteSpec],
) -> Option<MacosRouteSpec> {
    macos_underlay_route_from_candidates(routes, None)
}

#[cfg(any(target_os = "macos", test))]
fn macos_underlay_route_from_candidates(
    routes: &[MacosRouteSpec],
    preferred_interface: Option<&str>,
) -> Option<MacosRouteSpec> {
    let is_physical = |route: &&MacosRouteSpec| {
        route.gateway.is_some()
            && !route.interface.starts_with("utun")
            && !route.interface.starts_with("bridge")
            && route.interface != "lo0"
    };
    preferred_interface
        .and_then(|preferred| {
            routes
                .iter()
                .filter(is_physical)
                .find(|route| route.interface == preferred)
        })
        .or_else(|| routes.iter().find(is_physical))
        .cloned()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_underlay_default_route_needs_restore(routes: &[MacosRouteSpec]) -> bool {
    macos_underlay_default_route_from_routes(routes).is_none()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_endpoint_bypass_targets_for_hosts(hosts: &[Ipv4Addr]) -> Vec<String> {
    let mut targets = hosts
        .iter()
        .map(|host| format!("{host}/32"))
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
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
    macos_underlay_default_route_from_system_for_interface(None)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_underlay_default_route_from_system_for_interface(
    preferred_interface: Option<&str>,
) -> Result<Option<MacosRouteSpec>> {
    let output = command_stdout_checked(ProcessCommand::new("ifconfig").arg("-l"))?;
    let mut candidates = Vec::new();
    for iface in macos_interface_names_from_ifconfig_list(&output) {
        if iface.starts_with("utun")
            || iface.starts_with("bridge")
            || iface == "lo0"
            || iface == "gif0"
            || iface == "stf0"
            || iface.starts_with("anpi")
            || iface.starts_with("awdl")
            || iface.starts_with("llw")
        {
            continue;
        }

        let Ok(Some(_ipv4)) = macos_ipconfig_ipv4_for_interface(&iface) else {
            continue;
        };
        let Ok(Some(router)) = macos_ipconfig_router_for_interface(&iface) else {
            continue;
        };

        candidates.push(MacosRouteSpec {
            gateway: Some(router.to_string()),
            interface: iface,
        });
    }

    Ok(macos_underlay_route_from_candidates(
        &candidates,
        preferred_interface,
    ))
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
pub(super) fn delete_macos_managed_route(
    target: &str,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> Result<()> {
    if gateway.is_none() && interface.is_none() {
        return Err(anyhow!(
            "refusing to delete macOS route {target} without recorded ownership"
        ));
    }

    let before = macos_ipv4_route_table().context("inspect managed route before cleanup")?;
    if !macos_managed_route_present(&before, target, gateway, interface) {
        return Ok(());
    }

    let deletion = if let Some(gateway) = gateway {
        delete_macos_gateway_route(target, gateway, interface)
    } else {
        delete_macos_direct_route_on_interface(target, interface.expect("owner checked above"))
    };
    let after = macos_ipv4_route_table().context("verify managed route after cleanup")?;
    if macos_managed_route_present(&after, target, gateway, interface) {
        return match deletion {
            Ok(()) => Err(anyhow!(
                "managed macOS route {target} still matches its recorded owner after deletion"
            )),
            Err(error) => Err(error.context(format!(
                "managed macOS route {target} still matches its recorded owner"
            ))),
        };
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn restore_macos_default_route(route: &MacosRouteSpec) -> Result<()> {
    apply_macos_default_route(route.gateway.as_deref(), Some(route.interface.as_str()))
}

#[cfg(any(target_os = "macos", test))]
fn macos_add_underlay_default_route_args(gateway: &str) -> Vec<String> {
    vec![
        "-n".to_string(),
        "add".to_string(),
        "default".to_string(),
        gateway.to_string(),
    ]
}

#[cfg(target_os = "macos")]
pub(crate) fn restore_macos_underlay_default_route_if_missing() -> Result<bool> {
    let routes = macos_default_routes()?;
    if !macos_underlay_default_route_needs_restore(&routes) {
        return Ok(false);
    }

    let route = macos_underlay_default_route_from_system()?
        .ok_or_else(|| anyhow!("no physical macOS underlay default route is available"))?;
    let gateway = route
        .gateway
        .as_deref()
        .ok_or_else(|| anyhow!("physical macOS underlay route has no gateway"))?;

    // A Network Extension may retain an interface-scoped default on its utun.
    // Add the physical default alongside it: changing `default` here could
    // mutate a foreign VPN route and leave that VPN in an inconsistent state.
    let mut command = ProcessCommand::new("route");
    command.args(macos_add_underlay_default_route_args(gateway));
    run_checked(&mut command).with_context(|| {
        format!(
            "failed to restore physical macOS default route via {} on {}",
            gateway, route.interface
        )
    })?;

    let restored = macos_default_routes()?;
    if macos_underlay_default_route_needs_restore(&restored) {
        return Err(anyhow!(
            "physical macOS default route via {} on {} was not installed",
            gateway,
            route.interface
        ));
    }

    eprintln!(
        "tunnel: restored missing macOS underlay default route on {}",
        route.interface
    );
    Ok(true)
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_tunnel_default_route_targets() -> &'static [&'static str] {
    &["0.0.0.0/1", "128.0.0.0/1"]
}

#[cfg(any(target_os = "macos", test))]
fn macos_split_default_route_destination_matches(destination: &str, target: &str) -> bool {
    match target {
        "0.0.0.0/1" => matches!(destination, "0/1" | "0.0/1" | "0.0.0/1" | "0.0.0.0/1"),
        "128.0.0.0/1" => matches!(
            destination,
            "128/1" | "128.0/1" | "128.0.0/1" | "128.0.0.0/1"
        ),
        _ => false,
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_split_default_route_owners_from_netstat(output: &str, target: &str) -> Vec<String> {
    let mut owners = output
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 4 || !macos_split_default_route_destination_matches(tokens[0], target)
            {
                return None;
            }
            tokens.get(3).map(|iface| (*iface).to_string())
        })
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    owners
}

#[cfg(any(target_os = "macos", test))]
fn macos_route_destination_matches(destination: &str, target: &str) -> bool {
    if matches!(target, "0.0.0.0/1" | "128.0.0.0/1") {
        return macos_split_default_route_destination_matches(destination, target);
    }
    if target.ends_with("/32") {
        return destination == strip_cidr(target);
    }
    if target == "0.0.0.0/0" {
        return destination == "default";
    }
    destination == target
}

#[cfg(any(target_os = "macos", test))]
fn macos_managed_route_present(
    output: &str,
    target: &str,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> bool {
    if gateway.is_none() && interface.is_none() {
        return false;
    }
    output.lines().map(str::trim).any(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 4 || !macos_route_destination_matches(tokens[0], target) {
            return false;
        }
        gateway.is_none_or(|expected| tokens[1] == expected)
            && interface.is_none_or(|expected| tokens.get(3).copied() == Some(expected))
    })
}

#[cfg(any(target_os = "macos", test))]
fn macos_global_managed_route_present(
    output: &str,
    target: &str,
    gateway: Option<&str>,
    interface: Option<&str>,
) -> bool {
    output.lines().map(str::trim).any(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens.len() >= 4
            && macos_route_destination_matches(tokens[0], target)
            && gateway.is_none_or(|expected| tokens[1] == expected)
            && interface.is_none_or(|expected| tokens.get(3).copied() == Some(expected))
            && !tokens[2].contains('I')
    })
}

#[cfg(any(target_os = "macos", test))]
fn macos_global_managed_routes_present(
    output: &str,
    targets: &[String],
    owner: &MacosRouteSpec,
) -> bool {
    targets.iter().all(|target| {
        macos_global_managed_route_present(
            output,
            target,
            owner.gateway.as_deref(),
            Some(owner.interface.as_str()),
        )
    })
}

#[cfg(target_os = "macos")]
fn macos_ipv4_route_table() -> Result<String> {
    command_stdout_checked(
        ProcessCommand::new("netstat")
            .arg("-rn")
            .arg("-f")
            .arg("inet"),
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_managed_routes_present_in_system(
    targets: &[String],
    owner: &MacosRouteSpec,
) -> Result<bool> {
    let routes = macos_ipv4_route_table().context("inspect managed macOS IPv4 routes")?;
    Ok(macos_global_managed_routes_present(&routes, targets, owner))
}

#[cfg(any(target_os = "macos", test))]
fn macos_gateway_route_args(
    action: &str,
    target: &str,
    gateway: &str,
    ifscope: Option<&str>,
) -> Vec<String> {
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
    if let Some(ifscope) = ifscope {
        args.push("-ifscope".to_string());
        args.push(ifscope.to_string());
    }
    args
}

include!("macos_network/global_gateway_routes.rs");

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_default_route(
    gateway: Option<&str>,
    ifscope: Option<&str>,
) -> Result<()> {
    if let Some(ifscope) = ifscope {
        let _ = delete_macos_default_route_for_interface(ifscope);
        let _ = ProcessCommand::new("route")
            .arg("-n")
            .arg("delete")
            .arg("default")
            .arg("-ifscope")
            .arg(ifscope)
            .status();
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
    let mut deletion_errors = std::collections::HashMap::new();
    let before =
        macos_ipv4_route_table().context("inspect exact macOS IPv4 routes before cleanup")?;
    for target in macos_tunnel_default_route_targets() {
        if !macos_split_default_route_owners_from_netstat(&before, target)
            .iter()
            .any(|owner| owner == iface)
        {
            continue;
        }
        if let Err(error) = delete_macos_direct_route_on_interface(target, iface) {
            deletion_errors.insert(*target, error);
        }
    }

    let after = macos_ipv4_route_table().context("verify exact macOS IPv4 routes after cleanup")?;
    for target in macos_tunnel_default_route_targets() {
        if macos_split_default_route_owners_from_netstat(&after, target)
            .iter()
            .any(|owner| owner == iface)
        {
            if let Some(error) = deletion_errors.remove(*target) {
                failures.push(format!("remove {target} on {iface}: {error:#}"));
            } else {
                failures.push(format!("{target} is still owned by {iface} after cleanup"));
            }
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
    if gateway.is_none() && ifscope.is_none() {
        return Err(anyhow!("missing owner for macOS route {target}"));
    }
    let existing = macos_ipv4_route_table().context("inspect managed route before install")?;
    let already_present = if gateway.is_some() {
        macos_global_managed_route_present(&existing, target, gateway, ifscope)
    } else {
        macos_managed_route_present(&existing, target, gateway, ifscope)
    };
    if already_present {
        return Ok(());
    }

    // Older nvpn builds installed gateway bypasses with `-ifscope`, which
    // does not protect an ordinary transport socket from a global split
    // default. Remove that exact legacy route before installing the global
    // /32 owned by the same gateway and resolved interface.
    if let (Some(gateway), Some(ifscope)) = (gateway, ifscope)
        && macos_managed_route_present(&existing, target, Some(gateway), Some(ifscope))
    {
        delete_macos_scoped_gateway_route(target, gateway, ifscope)?;
    }

    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let mut add = ProcessCommand::new("route");
    if let Some(gateway) = gateway {
        add.args(macos_global_gateway_route_args(
            "add", target, gateway, ifscope,
        ));
    } else {
        add.arg("-n").arg("add");
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

    run_checked(&mut add)?;
    let installed = macos_ipv4_route_table().context("verify managed route after install")?;
    let installed_matches = if gateway.is_some() {
        macos_global_managed_route_present(&installed, target, gateway, ifscope)
    } else {
        macos_managed_route_present(&installed, target, gateway, ifscope)
    };
    if !installed_matches {
        return Err(anyhow!(
            "macOS route {target} did not match its requested owner after install"
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn delete_macos_gateway_route(target: &str, gateway: &str, interface: Option<&str>) -> Result<()> {
    let mut global = ProcessCommand::new("route");
    global.args(macos_global_gateway_route_args(
        "delete", target, gateway, interface,
    ));
    let global_result = run_checked(&mut global);
    let Some(interface) = interface else {
        return global_result;
    };
    let scoped_result = delete_macos_scoped_gateway_route(target, gateway, interface);
    match (global_result, scoped_result) {
        (Ok(()), _) | (_, Ok(())) => Ok(()),
        (Err(global_error), Err(scoped_error)) => Err(global_error.context(format!(
            "global and interface-scoped route deletion failed; scoped: {scoped_error:#}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn delete_macos_scoped_gateway_route(target: &str, gateway: &str, interface: &str) -> Result<()> {
    let mut delete = ProcessCommand::new("route");
    delete.args(macos_gateway_route_args(
        "delete",
        target,
        gateway,
        Some(interface),
    ));
    run_checked(&mut delete)
}

#[cfg(target_os = "macos")]
fn delete_macos_direct_route_on_interface(target: &str, iface: &str) -> Result<()> {
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
    delete.arg("-interface").arg(iface);
    run_checked(&mut delete)
}

#[cfg(any(target_os = "macos", test))]
const MACOS_PF_EXIT_ANCHOR: &str = "com.apple/nostrvpn-exit";

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_exit_node_pf_rules(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> String {
    format!(
        concat!(
            "nat on {outbound_iface} inet from {tunnel_source_cidr} to any -> ({outbound_iface})\n",
            "pass in quick on {tunnel_iface} inet from {tunnel_source_cidr} to any keep state\n",
            "pass out quick on {outbound_iface} inet from {tunnel_source_cidr} to any keep state\n",
        ),
        tunnel_iface = tunnel_iface,
        outbound_iface = outbound_iface,
        tunnel_source_cidr = tunnel_source_cidr,
    )
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_macos_ipv4_forwarding_state(output: &str) -> Result<bool> {
    match output.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        value => Err(anyhow!("unexpected net.inet.ip.forwarding value '{value}'")),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn read_macos_ipv4_forwarding() -> Result<bool> {
    let output = command_stdout_checked(
        ProcessCommand::new("sysctl")
            .arg("-n")
            .arg("net.inet.ip.forwarding"),
    )?;
    parse_macos_ipv4_forwarding_state(&output)
}

#[cfg(target_os = "macos")]
pub(crate) fn write_macos_ipv4_forwarding(enabled: bool) -> Result<()> {
    run_checked(
        ProcessCommand::new("sysctl")
            .arg("-w")
            .arg(format!("net.inet.ip.forwarding={}", u8::from(enabled))),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn macos_pf_enabled() -> Result<bool> {
    let output = command_stdout_checked(ProcessCommand::new("pfctl").arg("-s").arg("info"))?;
    parse_macos_pf_enabled(&output)
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_macos_pf_enabled(output: &str) -> Result<bool> {
    let state = output.lines().map(str::trim).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("status")
            .then(|| value.split_whitespace().next())
            .flatten()
    });
    match state {
        Some(state) if state.eq_ignore_ascii_case("enabled") => Ok(true),
        Some(state) if state.eq_ignore_ascii_case("disabled") => Ok(false),
        Some(state) => Err(anyhow!("unexpected PF status '{state}'")),
        None => Err(anyhow!("PF status output did not contain a status line")),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn apply_macos_exit_node_pf_rules(
    tunnel_iface: &str,
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Result<()> {
    let rules = macos_exit_node_pf_rules(tunnel_iface, outbound_iface, tunnel_source_cidr);
    let mut command = ProcessCommand::new("pfctl")
        .arg("-a")
        .arg(MACOS_PF_EXIT_ANCHOR)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to execute pfctl")?;
    if let Some(stdin) = command.stdin.as_mut() {
        stdin
            .write_all(rules.as_bytes())
            .context("failed to write nvpn PF rules")?;
    }
    let output = command
        .wait_with_output()
        .context("failed to wait for pfctl")?;
    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "command failed: pfctl -a {MACOS_PF_EXIT_ANCHOR} -f -\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn enable_macos_pf() -> Result<()> {
    run_checked(ProcessCommand::new("pfctl").arg("-e"))
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_pf_anchor_flush_args() -> Vec<String> {
    vec![
        "-a".to_string(),
        MACOS_PF_EXIT_ANCHOR.to_string(),
        "-F".to_string(),
        "all".to_string(),
    ]
}

#[cfg(target_os = "macos")]
pub(super) fn cleanup_macos_pf_nat() -> Result<()> {
    let mut command = ProcessCommand::new("pfctl");
    command.args(macos_pf_anchor_flush_args());
    run_checked(&mut command)
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("macos_network_tests.rs");
}
