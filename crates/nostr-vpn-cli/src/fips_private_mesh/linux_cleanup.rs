#[cfg(target_os = "linux")]
use crate::{
    LinuxExitNodeRuntime, LinuxNetworkCleanupState, LinuxWireGuardExitRuntime,
};

#[cfg(any(test, target_os = "linux"))]
const LINUX_NETWORK_CLEANUP_ATTEMPTS: usize = 3;

#[cfg(target_os = "linux")]
static PENDING_LINUX_NETWORK_CLEANUP: std::sync::Mutex<Option<LinuxNetworkCleanupState>> =
    std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
pub(crate) fn pending_linux_network_cleanup_state() -> Option<LinuxNetworkCleanupState> {
    PENDING_LINUX_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(target_os = "linux")]
fn replace_pending_linux_network_cleanup_state(state: Option<LinuxNetworkCleanupState>) {
    *PENDING_LINUX_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
}

#[cfg(target_os = "linux")]
pub(crate) fn record_linux_secure_dns_cleanup(
    cleanup_state: crate::secure_dns_runtime::LinuxSecureDnsCleanupState,
    cleanup_result: &Result<()>,
) {
    let mut pending = PENDING_LINUX_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cleanup_result.is_err() {
        pending
            .get_or_insert_with(LinuxNetworkCleanupState::default)
            .secure_dns = Some(cleanup_state);
        return;
    }
    if let Some(state) = pending.as_mut()
        && state.secure_dns.as_ref() == Some(&cleanup_state)
    {
        state.secure_dns = None;
    }
    if pending
        .as_ref()
        .is_some_and(LinuxNetworkCleanupState::is_empty)
    {
        *pending = None;
    }
}

#[cfg(target_os = "linux")]
fn record_linux_stop_cleanup_ownership(
    cleanup_result: &Result<()>,
    remaining: Option<LinuxNetworkCleanupState>,
) {
    replace_pending_linux_network_cleanup_state(
        cleanup_result.is_err().then_some(remaining).flatten(),
    );
}

#[cfg(all(test, target_os = "linux"))]
fn take_pending_linux_network_cleanup_state() -> Option<LinuxNetworkCleanupState> {
    PENDING_LINUX_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

#[cfg(any(test, target_os = "linux"))]
trait LinuxNetworkCleanupActions {
    fn cleanup_endpoint_bypass_routes(&mut self) -> anyhow::Result<()>;
    fn cleanup_forwarding_and_wireguard(&mut self) -> anyhow::Result<()>;
    fn restore_original_ipv4_default(&mut self);
    fn restore_original_ipv6_default(&mut self);
    fn ipv4_default_restore_pending(&self) -> bool;
    fn ipv6_default_restore_pending(&self) -> bool;
    fn wait_before_default_restore_retry(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    fn flush_route_cache(&mut self) -> anyhow::Result<()>;
}

#[cfg(any(test, target_os = "linux"))]
fn cleanup_linux_network_state_with_actions(
    actions: &mut impl LinuxNetworkCleanupActions,
) -> anyhow::Result<()> {
    let mut failures = Vec::new();
    let mut endpoint_cleanup_error = None;
    for _ in 0..LINUX_NETWORK_CLEANUP_ATTEMPTS {
        match actions.cleanup_endpoint_bypass_routes() {
            Ok(()) => {
                endpoint_cleanup_error = None;
                break;
            }
            Err(error) => endpoint_cleanup_error = Some(error),
        }
    }
    if let Some(error) = endpoint_cleanup_error {
        failures.push(format!(
            "endpoint bypass cleanup failed after three attempts: {error:#}"
        ));
    }

    // Physical default restoration and cache invalidation are independent
    // safety obligations. Restore while overlay identities are still present
    // so exact-ownership checks can distinguish an nVPN default from a new
    // NetworkManager default after an underlay switch.
    actions.restore_original_ipv4_default();
    actions.restore_original_ipv6_default();

    let mut forwarding_cleanup_error = None;
    for _ in 0..LINUX_NETWORK_CLEANUP_ATTEMPTS {
        match actions.cleanup_forwarding_and_wireguard() {
            Ok(()) => {
                forwarding_cleanup_error = None;
                break;
            }
            Err(error) => forwarding_cleanup_error = Some(error),
        }
    }
    if let Some(error) = forwarding_cleanup_error {
        failures.push(format!(
            "forwarding/WireGuard cleanup failed after three attempts: {error:#}"
        ));
    }

    // WireGuard cleanup can restore a usable journaled underlay after the
    // saved route became invalid. Recheck against that post-cleanup state.
    for attempt in 0..LINUX_NETWORK_CLEANUP_ATTEMPTS {
        if !actions.ipv4_default_restore_pending() {
            break;
        }
        actions.restore_original_ipv4_default();
        if actions.ipv4_default_restore_pending()
            && attempt + 1 < LINUX_NETWORK_CLEANUP_ATTEMPTS
        {
            actions.wait_before_default_restore_retry();
        }
    }
    for attempt in 0..LINUX_NETWORK_CLEANUP_ATTEMPTS {
        if !actions.ipv6_default_restore_pending() {
            break;
        }
        actions.restore_original_ipv6_default();
        if actions.ipv6_default_restore_pending()
            && attempt + 1 < LINUX_NETWORK_CLEANUP_ATTEMPTS
        {
            actions.wait_before_default_restore_retry();
        }
    }
    if actions.ipv4_default_restore_pending() {
        failures.push("failed to restore original IPv4 default route".to_string());
    }
    if actions.ipv6_default_restore_pending() {
        failures.push("failed to restore original IPv6 default route".to_string());
    }

    if let Err(error) = actions.flush_route_cache() {
        failures.push(format!("failed to flush Linux route cache: {error:#}"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Linux network cleanup remains incomplete: {}",
            failures.join("; ")
        ))
    }
}

#[cfg(target_os = "linux")]
impl LinuxNetworkCleanupActions for FipsPrivateTunnelRuntime {
    fn cleanup_endpoint_bypass_routes(&mut self) -> anyhow::Result<()> {
        cleanup_linux_endpoint_bypass_routes(&mut self.endpoint_bypass_routes)
    }

    fn cleanup_forwarding_and_wireguard(&mut self) -> anyhow::Result<()> {
        self.reconcile_linux_exit_node_forwarding_cleanup()
    }

    fn restore_original_ipv4_default(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_route, false, &owned);
    }

    fn restore_original_ipv6_default(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_ipv6_route, true, &owned);
    }

    fn ipv4_default_restore_pending(&self) -> bool {
        self.original_default_route.is_some()
    }

    fn ipv6_default_restore_pending(&self) -> bool {
        self.original_default_ipv6_route.is_some()
    }

    fn flush_route_cache(&mut self) -> anyhow::Result<()> {
        crate::flush_linux_route_cache()
    }
}

#[cfg(target_os = "linux")]
impl LinuxNetworkCleanupState {
    pub(crate) fn from_runtime(runtime: &FipsPrivateTunnelRuntime) -> Option<Self> {
        let state = Self {
            iface: runtime.iface.clone(),
            endpoint_bypass_routes: runtime.endpoint_bypass_routes.clone(),
            original_default_route: runtime.original_default_route.clone(),
            original_default_ipv6_route: runtime.original_default_ipv6_route.clone(),
            exit_node_runtime: runtime.exit_node_runtime.clone(),
            secure_dns: runtime
                .secure_dns
                .as_ref()
                .and_then(crate::secure_dns_runtime::SecureDnsRuntime::linux_cleanup_state),
            magic_dns_split_dns: None,
        };
        (!state.is_empty()).then_some(state)
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.has_network_ownership()
            && self.secure_dns.is_none()
            && self.magic_dns_split_dns.is_none()
    }

    fn has_network_ownership(&self) -> bool {
        !self.endpoint_bypass_routes.is_empty()
            || self.original_default_route.is_some()
            || self.original_default_ipv6_route.is_some()
            || !linux_exit_cleanup_state_is_empty(&self.exit_node_runtime)
    }
}

#[cfg(target_os = "linux")]
fn linux_exit_cleanup_state_is_empty(state: &LinuxExitNodeRuntime) -> bool {
    state.ipv4_outbound_iface.is_none()
        && state.ipv6_outbound_iface.is_none()
        && state.ipv4_tunnel_source_cidr.is_none()
        && state.ipv4_mss_clamp.is_none()
        && state.ipv4_forward_was_enabled.is_none()
        && state.ipv6_forward_was_enabled.is_none()
        && state.wireguard_exit.is_none()
        && state.pending_wireguard_exit_cleanup.is_empty()
}

#[cfg(target_os = "linux")]
fn cleanup_linux_endpoint_bypass_routes(routes: &mut Vec<crate::LinuxManagedEndpointBypassRoute>) -> Result<()> {
    let mut remaining = Vec::new();
    let mut failures = Vec::new();
    for route in std::mem::take(routes) {
        match crate::restore_linux_managed_endpoint_bypass_route(&route) {
            Ok(()) => {}
            Err(error) => {
                failures.push(format!("{}: {error:#}", route.route.target));
                remaining.push(route);
            }
        }
    }
    *routes = remaining;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to restore endpoint bypass routes: {}",
            failures.join("; ")
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_owned_default_interfaces(iface: &str, state: &LinuxExitNodeRuntime) -> Vec<String> {
    let mut interfaces = vec![iface.to_string()];
    if let Some(runtime) = state.wireguard_exit.as_ref() {
        interfaces.push(runtime.interface.clone());
    }
    interfaces.extend(
        state
            .pending_wireguard_exit_cleanup
            .iter()
            .filter_map(crate::LinuxWireGuardExitCleanupObligation::interface)
            .map(str::to_string),
    );
    interfaces.sort();
    interfaces.dedup();
    interfaces
}

#[cfg(target_os = "linux")]
fn restore_linux_saved_default(
    route: &mut Option<String>,
    ipv6: bool,
    owned_interfaces: &[String],
) {
    let Some(saved) = route.as_deref() else {
        return;
    };
    let current = if ipv6 {
        crate::linux_current_default_ipv6_route()
    } else {
        crate::linux_current_default_route()
    };
    let current = match current {
        Ok(current) => current,
        Err(error) => {
            eprintln!(
                "fips: retaining saved {} default after current-route query failed: {error:#}",
                if ipv6 { "IPv6" } else { "IPv4" }
            );
            return;
        }
    };
    if !crate::linux_saved_default_restore_required(
        saved,
        current.as_ref(),
        owned_interfaces,
    ) {
        // Either the exact saved route is already active or the OS installed
        // a different physical default during a network switch. In both
        // cases our stale restore obligation is complete.
        *route = None;
        return;
    }
    let result = if ipv6 {
        crate::restore_linux_default_ipv6_route(saved)
    } else {
        crate::restore_linux_default_route(saved)
    };
    if let Err(error) = result {
        eprintln!(
            "fips: failed to restore saved {} default route: {error:#}",
            if ipv6 { "IPv6" } else { "IPv4" }
        );
    } else {
        *route = None;
    }
}

#[cfg(target_os = "linux")]
fn cleanup_linux_wireguard_inbound_guard(
    iface: &str,
    runtime: &LinuxWireGuardExitRuntime,
) -> Result<()> {
    let rule = crate::linux_wireguard_exit_inbound_drop_rule(
        &runtime.interface,
        iface,
        &runtime.source_cidr,
    );
    let mut last_error = None;
    for _ in 0..LINUX_NETWORK_CLEANUP_ATTEMPTS {
        match crate::linux_iptables_delete_rule(
            crate::LinuxExitNodeIpFamily::V4,
            None,
            &rule,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("cleanup attempts are non-zero"))
        .context("remove WireGuard inbound guard")
}

#[cfg(target_os = "linux")]
fn cleanup_linux_wireguard_state(iface: &str, state: &mut LinuxExitNodeRuntime) -> Result<()> {
    cleanup_linux_wireguard_state_with(
        state,
        crate::cleanup_linux_wireguard_exit_obligation,
        |runtime| {
            let guard = cleanup_linux_wireguard_inbound_guard(iface, runtime);
            let network = crate::cleanup_linux_wireguard_exit_upstream(runtime);
            match (guard, network) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(guard), Ok(())) => Err(guard),
                (Ok(()), Err(network)) => Err(network),
                (Err(guard), Err(network)) => Err(anyhow!(
                    "inbound guard cleanup failed ({guard:#}); network cleanup failed ({network:#})"
                )),
            }
        },
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn cleanup_linux_wireguard_state_with(
    state: &mut LinuxExitNodeRuntime,
    mut cleanup_obligation: impl FnMut(&mut crate::LinuxWireGuardExitCleanupObligation) -> Result<()>,
    mut cleanup_runtime: impl FnMut(&LinuxWireGuardExitRuntime) -> Result<()>,
) -> Result<()> {
    let pending = std::mem::take(&mut state.pending_wireguard_exit_cleanup);
    let mut remaining = Vec::new();
    let mut failures = Vec::new();
    for mut obligation in pending {
        if let Err(error) = cleanup_obligation(&mut obligation) {
            failures.push(format!("retained apply rollback: {error:#}"));
            remaining.push(obligation);
        }
    }
    state.pending_wireguard_exit_cleanup = remaining;

    if !state.pending_wireguard_exit_cleanup.is_empty() {
        return Err(anyhow!(
            "Linux WireGuard cleanup incomplete: {}",
            failures.join("; ")
        ));
    }

    if let Some(runtime) = state.wireguard_exit.take()
        && let Err(error) = cleanup_runtime(&runtime)
    {
        failures.push(format!("WireGuard runtime: {error:#}"));
        state.wireguard_exit = Some(runtime);
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Linux WireGuard cleanup incomplete: {}",
            failures.join("; ")
        ))
    }
}

#[cfg(target_os = "linux")]
fn cleanup_linux_legacy_forwarding_rules(iface: &str) -> Result<()> {
    let mut failures = Vec::new();
    for family in [
        crate::LinuxExitNodeIpFamily::V4,
        crate::LinuxExitNodeIpFamily::V6,
    ] {
        let forward_in = crate::linux_exit_node_legacy_forward_in_rule(iface, family);
        let forward_out = crate::linux_exit_node_legacy_forward_out_rule(iface, family);
        for (label, rule) in [("forward-out", &forward_out), ("forward-in", &forward_in)] {
            if let Err(error) = crate::linux_iptables_delete_rule(family, None, rule) {
                // This sweep is only for rules from older versions. A missing
                // tool does not prove that kernel rules are absent, but must
                // not make it a dependency of every private mesh session.
                // Cleanup of rules tracked by this runtime remains strict.
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                {
                    eprintln!("fips: skipping unavailable legacy firewall cleanup: {error:#}");
                    break;
                }
                failures.push(format!("remove legacy {label} rule: {error:#}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn cleanup_linux_forwarding_state(
    iface: &str,
    state: &mut LinuxExitNodeRuntime,
) -> Result<()> {
    let mut failures = Vec::new();
    let outbound_iface = state.ipv4_outbound_iface.clone();
    let tunnel_source_cidr = state.ipv4_tunnel_source_cidr.clone();
    let mut firewall_clean = true;
    if let (Some(outbound_iface), Some(tunnel_source_cidr)) =
        (outbound_iface.as_deref(), tunnel_source_cidr.as_deref())
    {
        if let Some(mss) = state.ipv4_mss_clamp {
            let rule = crate::linux_exit_node_ipv4_mss_clamp_rule(
                iface,
                outbound_iface,
                tunnel_source_cidr,
                mss,
            );
            if let Err(error) = crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                Some("mangle"),
                &rule,
            ) {
                firewall_clean = false;
                failures.push(format!("remove MSS clamp rule: {error:#}"));
            }
        }
        let forward_in = crate::linux_exit_node_forward_in_rule(
            iface,
            outbound_iface,
            tunnel_source_cidr,
            crate::LinuxExitNodeIpFamily::V4,
        );
        let forward_out = crate::linux_exit_node_forward_out_rule(
            iface,
            outbound_iface,
            crate::LinuxExitNodeIpFamily::V4,
        );
        let masquerade =
            crate::linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);
        for (label, table, rule) in [
            ("masquerade", Some("nat"), &masquerade),
            ("forward-out", None, &forward_out),
            ("forward-in", None, &forward_in),
        ] {
            if let Err(error) = crate::linux_iptables_delete_rule(
                crate::LinuxExitNodeIpFamily::V4,
                table,
                rule,
            ) {
                firewall_clean = false;
                failures.push(format!("remove {label} rule: {error:#}"));
            }
        }
    } else if outbound_iface.is_some()
        || tunnel_source_cidr.is_some()
        || state.ipv4_mss_clamp.is_some()
    {
        firewall_clean = false;
        failures.push("incomplete retained IPv4 firewall ownership identity".to_string());
    }
    if firewall_clean {
        state.ipv4_outbound_iface = None;
        state.ipv4_tunnel_source_cidr = None;
        state.ipv4_mss_clamp = None;
    }

    if let Err(error) = cleanup_linux_legacy_forwarding_rules(iface) {
        failures.push(format!("legacy forwarding rules: {error:#}"));
    }
    for (family, previous, label) in [
        (
            crate::LinuxExitNodeIpFamily::V4,
            &mut state.ipv4_forward_was_enabled,
            "IPv4",
        ),
        (
            crate::LinuxExitNodeIpFamily::V6,
            &mut state.ipv6_forward_was_enabled,
            "IPv6",
        ),
    ] {
        if *previous == Some(false) {
            match crate::write_linux_ip_forward(family, false) {
                Ok(()) => *previous = None,
                Err(error) => failures.push(format!("restore {label} forwarding: {error:#}")),
            }
        } else {
            *previous = None;
        }
    }
    state.ipv6_outbound_iface = None;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Linux exit forwarding cleanup incomplete: {}",
            failures.join("; ")
        ))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn cleanup_linux_exit_node_state(
    iface: &str,
    state: &mut LinuxExitNodeRuntime,
) -> Result<()> {
    let forwarding = cleanup_linux_forwarding_state(iface, state);
    let wireguard = cleanup_linux_wireguard_state(iface, state);
    match (forwarding, wireguard) {
        (Ok(()), Ok(())) => {
            *state = LinuxExitNodeRuntime::default();
            Ok(())
        }
        (Err(forwarding), Ok(())) => Err(forwarding),
        (Ok(()), Err(wireguard)) => Err(wireguard),
        (Err(forwarding), Err(wireguard)) => Err(anyhow!(
            "forwarding cleanup failed ({forwarding:#}); \
             WireGuard cleanup failed ({wireguard:#})"
        )),
    }
}

#[cfg(target_os = "linux")]
impl LinuxNetworkCleanupActions for LinuxNetworkCleanupState {
    fn cleanup_endpoint_bypass_routes(&mut self) -> Result<()> {
        cleanup_linux_endpoint_bypass_routes(&mut self.endpoint_bypass_routes)
    }

    fn cleanup_forwarding_and_wireguard(&mut self) -> Result<()> {
        let iface = self.iface.clone();
        cleanup_linux_exit_node_state(&iface, &mut self.exit_node_runtime)
    }

    fn restore_original_ipv4_default(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_route, false, &owned);
    }

    fn restore_original_ipv6_default(&mut self) {
        let owned = linux_owned_default_interfaces(&self.iface, &self.exit_node_runtime);
        restore_linux_saved_default(&mut self.original_default_ipv6_route, true, &owned);
    }

    fn ipv4_default_restore_pending(&self) -> bool {
        self.original_default_route.is_some()
    }

    fn ipv6_default_restore_pending(&self) -> bool {
        self.original_default_ipv6_route.is_some()
    }

    fn flush_route_cache(&mut self) -> Result<()> {
        crate::flush_linux_route_cache()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn repair_linux_network_cleanup_state(
    state: &mut LinuxNetworkCleanupState,
) -> Result<()> {
    let mut failures = Vec::new();
    if state.has_network_ownership()
        && let Err(error) = cleanup_linux_network_state_with_actions(state)
    {
        failures.push(format!("network cleanup failed ({error:#})"));
    }
    if let Err(error) =
        crate::secure_dns_runtime::repair_linux_secure_dns_cleanup_state(&mut state.secure_dns)
    {
        failures.push(format!("secure DNS cleanup failed ({error:#})"));
    }
    // The recorded ownership identifies exactly the split DNS settings this
    // configuration installed; another configuration's resolver state is
    // never touched.
    if let Some(owned) = state.magic_dns_split_dns.as_ref()
        && let Err(error) = nostr_vpn_core::magic_dns::uninstall_system_resolver(owned)
    {
        failures.push(format!("MagicDNS cleanup failed ({error:#})"));
    } else {
        state.magic_dns_split_dns = None;
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("; ")))
    }
}
