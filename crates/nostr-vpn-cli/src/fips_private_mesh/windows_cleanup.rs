#[cfg(target_os = "windows")]
static PENDING_WINDOWS_SECURE_DNS: std::sync::Mutex<Vec<u32>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(target_os = "windows")]
fn pending_windows_secure_dns_interface_indexes() -> Vec<u32> {
    PENDING_WINDOWS_SECURE_DNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(target_os = "windows")]
pub(crate) fn record_windows_secure_dns_cleanup(
    interface_index: u32,
    cleanup_result: &Result<()>,
) {
    let mut pending = PENDING_WINDOWS_SECURE_DNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    pending.retain(|existing| *existing != interface_index);
    if cleanup_result.is_err() {
        pending.push(interface_index);
        pending.sort_unstable();
        pending.dedup();
    }
}

#[cfg(target_os = "windows")]
impl WindowsNetworkCleanupState {
    pub(crate) fn from_runtime_and_pending(
        runtime: Option<&FipsPrivateTunnelRuntime>,
    ) -> Self {
        let mut routes =
            crate::wg_upstream_runtime::pending_windows_route_cleanup_snapshot();
        let mut native_wireguard =
            crate::wg_upstream_runtime::pending_windows_native_cleanup_snapshot();
        let mut secure_dns_interface_indexes =
            pending_windows_secure_dns_interface_indexes();
        if let Some(runtime) = runtime {
            routes.merge(runtime.route_guard.cleanup_snapshot());
            if let Some(endpoint_routes) = runtime.endpoint_bypass_routes.as_ref() {
                routes.merge(endpoint_routes.cleanup_snapshot());
            }
            if let Some(upstream) = runtime.wg_upstream.as_ref() {
                routes.merge(upstream.route_cleanup_snapshot());
                if let Some(native) = upstream.native_cleanup_state() {
                    native_wireguard.push(native);
                }
            }
            if let Some(interface_index) = runtime
                .secure_dns
                .as_ref()
                .and_then(crate::secure_dns_runtime::SecureDnsRuntime::windows_cleanup_interface_index)
            {
                secure_dns_interface_indexes.push(interface_index);
            }
        }
        secure_dns_interface_indexes.sort_unstable();
        secure_dns_interface_indexes.dedup();
        Self {
            routes,
            native_wireguard,
            secure_dns_interface_indexes,
            magic_dns_nrpt_rules: None,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
            && self.native_wireguard.is_empty()
            && self.secure_dns_interface_indexes.is_empty()
            && self.magic_dns_nrpt_rules.is_none()
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn repair_windows_network_cleanup_state(
    state: &mut WindowsNetworkCleanupState,
) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) =
        crate::wg_upstream_runtime::retry_windows_route_cleanup_snapshot(&mut state.routes)
    {
        failures.push(format!("Windows routes: {error:#}"));
    }

    let mut remaining_native = Vec::new();
    for mut cleanup in std::mem::take(&mut state.native_wireguard) {
        if let Err(error) =
            crate::wg_upstream_runtime::cleanup_windows_native_wireguard_state(&mut cleanup)
        {
            failures.push(format!("native WireGuard service/config: {error:#}"));
            remaining_native.push(cleanup);
        }
    }
    state.native_wireguard = remaining_native;

    let mut remaining_dns = Vec::new();
    for interface_index in std::mem::take(&mut state.secure_dns_interface_indexes) {
        let cleanup = crate::secure_dns_runtime::repair_windows_secure_dns(interface_index);
        record_windows_secure_dns_cleanup(interface_index, &cleanup);
        if let Err(error) = cleanup {
            failures.push(format!("secure DNS on interface {interface_index}: {error:#}"));
            remaining_dns.push(interface_index);
        }
    }
    state.secure_dns_interface_indexes = remaining_dns;

    if let Some(owned) = state.magic_dns_nrpt_rules.as_ref() {
        match nostr_vpn_core::magic_dns::uninstall_system_resolver(owned) {
            Ok(()) => state.magic_dns_nrpt_rules = None,
            Err(error) => failures.push(format!("MagicDNS NRPT rules: {error:#}")),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Windows network cleanup remains incomplete: {}",
            failures.join("; ")
        ))
    }
}
