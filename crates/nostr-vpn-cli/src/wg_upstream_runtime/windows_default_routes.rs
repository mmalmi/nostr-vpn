// POSIX, but the routing table is driven by `netsh interface ipv4`
// instead of `ip` / `route`, and the WG iface is identified by its
// kernel interface index rather than a name. The captured original
// default route is held verbatim from `route print 0.0.0.0` so we can
// re-add it on cleanup.
// ---------------------------------------------------------------------------

#[cfg(any(test, target_os = "windows"))]
const WINDOWS_ROUTE_CLEANUP_ATTEMPTS: usize = 3;

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct WindowsRouteSpec {
    prefix: String,
    interface_index: u32,
    next_hop: String,
    metric: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface_identity: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsRouteSpec {
    fn endpoint(target: std::net::Ipv4Addr, underlay: &WindowsDefaultRoute) -> Self {
        Self {
            prefix: format!("{target}/32"),
            interface_index: underlay.interface_index,
            next_hop: underlay.gateway.clone(),
            metric: 1,
            interface_identity: None,
        }
    }

    fn wireguard_default(interface_index: u32) -> Self {
        Self {
            prefix: "0.0.0.0/0".to_string(),
            interface_index,
            next_hop: "0.0.0.0".to_string(),
            metric: 1,
            interface_identity: None,
        }
    }

    fn wireguard_default_v6(interface_index: u32) -> Self {
        Self {
            prefix: "::/0".to_string(),
            interface_index,
            next_hop: "::".to_string(),
            metric: 1,
            interface_identity: None,
        }
    }

    fn direct(prefix: &str, interface_index: u32) -> Result<Self> {
        let prefix = prefix.trim();
        let (address, prefix_len) = prefix
            .split_once('/')
            .ok_or_else(|| anyhow!("Windows route prefix must be IPv4 CIDR: {prefix}"))?;
        address
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("invalid Windows route IPv4 address {address}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .with_context(|| format!("invalid Windows route prefix length {prefix_len}"))?;
        if prefix_len > 32 {
            return Err(anyhow!("invalid Windows route prefix length {prefix_len}"));
        }
        Ok(Self {
            prefix: prefix.to_string(),
            interface_index,
            next_hop: "0.0.0.0".to_string(),
            metric: 1,
            interface_identity: None,
        })
    }

    fn next_hop_is_on_link(&self) -> bool {
        self.next_hop == "0.0.0.0" || self.next_hop == "::"
    }

    fn is_identityless_legacy_physical_bypass(&self) -> bool {
        self.interface_identity.is_none() && !self.next_hop_is_on_link()
    }

    fn is_identityless_legacy_tunnel_route(&self) -> bool {
        self.interface_identity.is_none() && self.next_hop_is_on_link()
    }
}

#[cfg(any(test, target_os = "windows"))]
trait WindowsRouteCommandRunner {
    fn route_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool>;
    fn route_identity_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool>;
    fn bind_interface_identity(&mut self, _route: &mut WindowsRouteSpec) -> Result<()> {
        Ok(())
    }
    fn verify_interface_identity(&mut self, _route: &WindowsRouteSpec) -> Result<()> {
        Ok(())
    }
    fn add_route(&mut self, route: &WindowsRouteSpec) -> Result<()>;
    fn set_route(&mut self, route: &WindowsRouteSpec) -> Result<()>;
    fn delete_route(&mut self, route: &WindowsRouteSpec) -> Result<()>;
    fn finish_route_cleanup(&mut self, _route: &WindowsRouteSpec) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct WindowsRouteApplyFailure<T> {
    error: anyhow::Error,
    cleanup: T,
}

#[cfg(any(test, target_os = "windows"))]
impl<T> std::fmt::Display for WindowsRouteApplyFailure<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

#[cfg(any(test, target_os = "windows"))]
impl<T: std::fmt::Debug> std::error::Error for WindowsRouteApplyFailure<T> {}

#[cfg(target_os = "windows")]
struct SystemWindowsRouteCommandRunner {
    cleanup_journal_config_path: Option<PathBuf>,
}

#[cfg(target_os = "windows")]
impl SystemWindowsRouteCommandRunner {
    fn repair() -> Self {
        Self {
            cleanup_journal_config_path: None,
        }
    }

    fn journaled(config_path: &Path) -> Self {
        Self {
            cleanup_journal_config_path: Some(config_path.to_path_buf()),
        }
    }

    fn persist_route_intent(&self, route: &WindowsRouteSpec, retain: bool) -> Result<()> {
        let Some(config_path) = self.cleanup_journal_config_path.as_deref() else {
            return Ok(());
        };
        crate::daemon_runtime::persist_windows_route_cleanup_intent(
            config_path,
            &WindowsRouteCleanupSnapshot::from_owned_routes(vec![route.clone()]),
            retain,
        )
    }

    fn run_journaled_route_mutation(
        &self,
        route: &WindowsRouteSpec,
        operation: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.persist_route_intent(route, true)
            .context("fsync Windows route cleanup intent before mutation")?;
        let Err(mutation_error) = operation() else {
            return Ok(());
        };
        let cleanup = WindowsRouteCleanupSnapshot::from_owned_routes(vec![route.clone()]);
        match windows_route_exists(route, false) {
            Ok(true) => {
                retain_pending_windows_route_cleanup(cleanup);
                Err(mutation_error)
            }
            Ok(false) => match self.persist_route_intent(route, false) {
                Ok(()) => Err(mutation_error),
                Err(persist_error) => Err(anyhow!(
                    "{mutation_error:#}; route mutation left no matching route, but clearing its \
                     write-ahead cleanup intent failed: {persist_error:#}"
                )),
            },
            Err(audit_error) => {
                retain_pending_windows_route_cleanup(cleanup);
                Err(anyhow!(
                    "{mutation_error:#}; failed to audit route state after mutation failure, so \
                     its write-ahead cleanup intent was retained: {audit_error:#}"
                ))
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsRouteCommandRunner for SystemWindowsRouteCommandRunner {
    fn route_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool> {
        windows_route_exists(route, true)
    }

    fn route_identity_exists(&mut self, route: &WindowsRouteSpec) -> Result<bool> {
        windows_route_exists(route, false)
    }

    fn bind_interface_identity(&mut self, route: &mut WindowsRouteSpec) -> Result<()> {
        let identity = resolve_windows_interface_identity(route.interface_index)?;
        if let Some(expected) = route.interface_identity.as_deref()
            && expected != identity
        {
            return Err(anyhow!(
                "Windows interface {} identity changed from {} to {}; refusing route mutation",
                route.interface_index,
                expected,
                identity
            ));
        }
        route.interface_identity = Some(identity);
        Ok(())
    }

    fn verify_interface_identity(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        let expected = route.interface_identity.as_deref().ok_or_else(|| {
            anyhow!(
                "Windows route cleanup for {} interface={} has no durable interface identity; \
                 refusing to touch a possibly reused interface index",
                route.prefix,
                route.interface_index
            )
        })?;
        let current = resolve_windows_interface_identity(route.interface_index)?;
        if current != expected {
            return Err(anyhow!(
                "Windows interface {} was reused (expected identity {}, current {}); refusing \
                 route cleanup for {}",
                route.interface_index,
                expected,
                current,
                route.prefix
            ));
        }
        Ok(())
    }

    fn add_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.run_journaled_route_mutation(route, || {
            run_windows_netsh(&windows_route_add_args(route))
        })
    }

    fn set_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.run_journaled_route_mutation(route, || {
            run_windows_netsh(&windows_route_set_args(route))
        })
    }

    fn delete_route(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        run_windows_netsh(&windows_route_delete_args(route))
    }

    fn finish_route_cleanup(&mut self, route: &WindowsRouteSpec) -> Result<()> {
        self.persist_route_intent(route, false)
            .context("persist completed Windows route cleanup")
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct WindowsManagedDefaultRoutes {
    wg_iface_index: u32,
    bypass_target: std::net::Ipv4Addr,
    underlay: WindowsDefaultRoute,
    bypass_owned: bool,
    manage_default: bool,
    default_owned: bool,
    manage_default_v6: bool,
    default_v6_owned: bool,
    orphaned_bypass_routes: Vec<WindowsRouteSpec>,
    bypass_interface_identity: Option<Box<str>>,
    default_interface_identity: Option<Box<str>>,
    default_v6_interface_identity: Option<Box<str>>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsManagedDefaultRoutes {
    // The cold failure path retains the complete route ownership state for cleanup.
    #[allow(clippy::result_large_err)]
    fn apply_with(
        runner: &mut impl WindowsRouteCommandRunner,
        wg_iface_index: u32,
        upstream_ip: std::net::Ipv4Addr,
        underlay: WindowsDefaultRoute,
        manage_default: bool,
        manage_default_v6: bool,
    ) -> std::result::Result<Self, WindowsRouteApplyFailure<Self>> {
        let mut routes = Self {
            wg_iface_index,
            bypass_target: upstream_ip,
            underlay,
            bypass_owned: false,
            manage_default,
            default_owned: false,
            manage_default_v6,
            default_v6_owned: false,
            orphaned_bypass_routes: Vec::new(),
            bypass_interface_identity: None,
            default_interface_identity: None,
            default_v6_interface_identity: None,
        };
        if let Err(error) = validate_windows_underlay(&routes.underlay, &[wg_iface_index]) {
            return Err(WindowsRouteApplyFailure {
                error,
                cleanup: routes,
            });
        }
        let mut bypass = WindowsRouteSpec::endpoint(upstream_ip, &routes.underlay);
        if let Err(error) = runner.bind_interface_identity(&mut bypass) {
            return Err(WindowsRouteApplyFailure {
                error: error.context("bind WireGuard endpoint route to physical interface"),
                cleanup: routes,
            });
        }
        routes.bypass_interface_identity = bypass
            .interface_identity
            .as_deref()
            .map(str::to_owned)
            .map(String::into_boxed_str);
        match ensure_windows_route(runner, &bypass) {
            Ok(owned) => routes.bypass_owned = owned,
            Err(error) => {
                return Err(WindowsRouteApplyFailure {
                    error: error.context("install WireGuard endpoint bypass route"),
                    cleanup: routes,
                });
            }
        }
        if manage_default {
            let mut default = WindowsRouteSpec::wireguard_default(wg_iface_index);
            if let Err(error) = runner.bind_interface_identity(&mut default) {
                let rollback = routes.revert_with(runner);
                return Err(WindowsRouteApplyFailure {
                    error: with_windows_route_rollback(
                        error.context("bind WireGuard default route to tunnel interface"),
                        rollback,
                    ),
                    cleanup: routes,
                });
            }
            routes.default_interface_identity = default
                .interface_identity
                .as_deref()
                .map(str::to_owned)
                .map(String::into_boxed_str);
            match ensure_windows_route(runner, &default) {
                Ok(owned) => routes.default_owned = owned,
                Err(error) => {
                    let rollback = routes.revert_with(runner);
                    return Err(WindowsRouteApplyFailure {
                        error: with_windows_route_rollback(
                            error.context("install WireGuard default route"),
                            rollback,
                        ),
                        cleanup: routes,
                    });
                }
            }
        }
        if manage_default_v6 {
            let mut default = WindowsRouteSpec::wireguard_default_v6(wg_iface_index);
            if let Err(error) = runner.bind_interface_identity(&mut default) {
                let rollback = routes.revert_with(runner);
                return Err(WindowsRouteApplyFailure {
                    error: with_windows_route_rollback(
                        error.context("bind WireGuard IPv6 default route to tunnel interface"),
                        rollback,
                    ),
                    cleanup: routes,
                });
            }
            routes.default_v6_interface_identity = default
                .interface_identity
                .as_deref()
                .map(str::to_owned)
                .map(String::into_boxed_str);
            match ensure_windows_route(runner, &default) {
                Ok(owned) => routes.default_v6_owned = owned,
                Err(error) => {
                    let rollback = routes.revert_with(runner);
                    return Err(WindowsRouteApplyFailure {
                        error: with_windows_route_rollback(
                            error.context("install WireGuard IPv6 default route"),
                            rollback,
                        ),
                        cleanup: routes,
                    });
                }
            }
        }
        Ok(routes)
    }

    #[cfg(test)]
    fn refresh_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        fresh_underlay: WindowsDefaultRoute,
        excluded_tunnel_interfaces: &[u32],
    ) -> Result<bool> {
        self.reconcile_with(
            runner,
            self.bypass_target,
            fresh_underlay,
            excluded_tunnel_interfaces,
        )
    }

    fn reconcile_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        fresh_target: std::net::Ipv4Addr,
        fresh_underlay: WindowsDefaultRoute,
        excluded_tunnel_interfaces: &[u32],
    ) -> Result<bool> {
        self.cleanup_orphaned_bypasses_with(runner)
            .context("retry cleanup of a prior Windows endpoint-route rollback")?;
        let mut excluded = excluded_tunnel_interfaces.to_vec();
        excluded.push(self.wg_iface_index);
        validate_windows_underlay(&fresh_underlay, &excluded)?;
        if self.underlay == fresh_underlay && self.bypass_target == fresh_target {
            return self
                .repair_current_routes_with(runner)
                .context("repair tracked WireGuard routes");
        }

        let stale_bypass = self.bypass_route_spec();
        let mut fresh_bypass = WindowsRouteSpec::endpoint(fresh_target, &fresh_underlay);
        runner
            .bind_interface_identity(&mut fresh_bypass)
            .context("bind refreshed WireGuard endpoint route to physical interface")?;
        if stale_bypass == fresh_bypass {
            // A DHCP renewal can replace only the local source address while
            // retaining the interface/gateway tuple. The existing owned route
            // is still the exact desired bypass and must retain its ownership.
            self.repair_current_routes_with(runner)
                .context("repair tracked WireGuard routes after address renewal")?;
            self.underlay = fresh_underlay;
            return Ok(true);
        }

        // The replacement bypass must be usable before the old bypass is
        // audited or removed. Cold PowerShell route queries take hundreds of
        // milliseconds each, so checking a stale bypass first needlessly keeps
        // WireGuard offline during a physical handoff.
        let fresh_owned = ensure_windows_route(runner, &fresh_bypass)
            .context("install fresh WireGuard endpoint bypass route")?;
        if self.manage_default {
            let route = self.default_route_spec();
            match ensure_tracked_windows_route(runner, &route, self.default_owned) {
                Ok(true) => self.default_owned = true,
                Ok(false) => {}
                Err(error) => {
                    let rollback = if fresh_owned {
                        delete_windows_route_with_retry(runner, &fresh_bypass)
                    } else {
                        Ok(())
                    };
                    if fresh_owned && rollback.is_err() {
                        self.orphaned_bypass_routes.push(fresh_bypass);
                    }
                    return Err(with_windows_route_rollback(
                        error.context("repair WireGuard default route after underlay refresh"),
                        rollback,
                    ));
                }
            }
        }
        if self.manage_default_v6 {
            let route = self.default_v6_route_spec();
            match ensure_tracked_windows_route(runner, &route, self.default_v6_owned) {
                Ok(true) => self.default_v6_owned = true,
                Ok(false) => {}
                Err(error) => {
                    let rollback = if fresh_owned {
                        delete_windows_route_with_retry(runner, &fresh_bypass)
                    } else {
                        Ok(())
                    };
                    if fresh_owned && rollback.is_err() {
                        self.orphaned_bypass_routes.push(fresh_bypass);
                    }
                    return Err(with_windows_route_rollback(
                        error.context("repair WireGuard IPv6 default route after underlay refresh"),
                        rollback,
                    ));
                }
            }
        }
        if self.bypass_owned
            && let Err(error) = delete_windows_route_with_retry(runner, &stale_bypass)
        {
            let rollback = if fresh_owned {
                delete_windows_route_with_retry(runner, &fresh_bypass)
            } else {
                Ok(())
            };
            if fresh_owned && rollback.is_err() {
                self.orphaned_bypass_routes.push(fresh_bypass);
            }
            return Err(with_windows_route_rollback(
                error.context("remove stale WireGuard endpoint bypass route"),
                rollback,
            ));
        }

        self.bypass_target = fresh_target;
        self.underlay = fresh_underlay;
        self.bypass_owned = fresh_owned;
        self.bypass_interface_identity =
            fresh_bypass.interface_identity.map(String::into_boxed_str);
        Ok(true)
    }

    fn revert_with(&mut self, runner: &mut impl WindowsRouteCommandRunner) -> Result<()> {
        let mut failures = Vec::new();
        if self.default_owned {
            let route = self.default_route_spec();
            match delete_windows_route_with_retry(runner, &route) {
                Ok(()) => self.default_owned = false,
                Err(error) => failures.push(format!("remove WireGuard default route: {error:#}")),
            }
        }
        if self.default_v6_owned {
            let route = self.default_v6_route_spec();
            match delete_windows_route_with_retry(runner, &route) {
                Ok(()) => self.default_v6_owned = false,
                Err(error) => {
                    failures.push(format!("remove WireGuard IPv6 default route: {error:#}"))
                }
            }
        }
        if self.bypass_owned {
            let route = self.bypass_route_spec();
            match delete_windows_route_with_retry(runner, &route) {
                Ok(()) => self.bypass_owned = false,
                Err(error) => {
                    failures.push(format!("remove WireGuard endpoint bypass route: {error:#}"))
                }
            }
        }
        if let Err(error) = self.cleanup_orphaned_bypasses_with(runner) {
            failures.push(format!(
                "remove residual WireGuard endpoint bypass routes: {error:#}"
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    fn cleanup_orphaned_bypasses_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
    ) -> Result<()> {
        let mut remaining = Vec::new();
        let mut failures = Vec::new();
        for route in self.orphaned_bypass_routes.drain(..) {
            if let Err(error) = delete_windows_route_with_retry(runner, &route) {
                failures.push(format!("{}: {error:#}", route.prefix));
                remaining.push(route);
            }
        }
        self.orphaned_bypass_routes = remaining;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    fn repair_current_routes_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
    ) -> Result<bool> {
        let bypass = self.bypass_route_spec();
        let repaired_bypass = ensure_tracked_windows_route(runner, &bypass, self.bypass_owned)
            .context("ensure current WireGuard endpoint bypass route")?;
        if repaired_bypass {
            self.bypass_owned = true;
        }
        let repaired_default = if self.manage_default {
            let route = self.default_route_spec();
            match ensure_tracked_windows_route(runner, &route, self.default_owned) {
                Ok(owned) => {
                    if owned {
                        self.default_owned = true;
                    }
                    owned
                }
                Err(error) => {
                    let rollback = if repaired_bypass {
                        delete_windows_route_with_retry(runner, &bypass)
                    } else {
                        Ok(())
                    };
                    if repaired_bypass && rollback.is_ok() {
                        self.bypass_owned = false;
                    }
                    return Err(with_windows_route_rollback(
                        error.context("ensure current WireGuard default route"),
                        rollback,
                    ));
                }
            }
        } else {
            false
        };
        let repaired_default_v6 = if self.manage_default_v6 {
            let route = self.default_v6_route_spec();
            match ensure_tracked_windows_route(runner, &route, self.default_v6_owned) {
                Ok(owned) => {
                    if owned {
                        self.default_v6_owned = true;
                    }
                    owned
                }
                Err(error) => {
                    let rollback = if repaired_bypass {
                        delete_windows_route_with_retry(runner, &bypass)
                    } else {
                        Ok(())
                    };
                    if repaired_bypass && rollback.is_ok() {
                        self.bypass_owned = false;
                    }
                    return Err(with_windows_route_rollback(
                        error.context("ensure current WireGuard IPv6 default route"),
                        rollback,
                    ));
                }
            }
        } else {
            false
        };
        Ok(repaired_bypass || repaired_default || repaired_default_v6)
    }

    fn cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        let mut owned_routes = Vec::new();
        if self.default_owned {
            owned_routes.push(self.default_route_spec());
        }
        if self.default_v6_owned {
            owned_routes.push(self.default_v6_route_spec());
        }
        if self.bypass_owned {
            owned_routes.push(self.bypass_route_spec());
        }
        owned_routes.extend(self.orphaned_bypass_routes.iter().cloned());
        WindowsRouteCleanupSnapshot::from_owned_routes(owned_routes)
    }

    fn bypass_route_spec(&self) -> WindowsRouteSpec {
        let mut route = WindowsRouteSpec::endpoint(self.bypass_target, &self.underlay);
        route.interface_identity = self.bypass_interface_identity.as_deref().map(str::to_owned);
        route
    }

    fn default_route_spec(&self) -> WindowsRouteSpec {
        let mut route = WindowsRouteSpec::wireguard_default(self.wg_iface_index);
        route.interface_identity = self
            .default_interface_identity
            .as_deref()
            .map(str::to_owned);
        route
    }

    fn default_v6_route_spec(&self) -> WindowsRouteSpec {
        let mut route = WindowsRouteSpec::wireguard_default_v6(self.wg_iface_index);
        route.interface_identity = self
            .default_v6_interface_identity
            .as_deref()
            .map(str::to_owned);
        route
    }

    fn take_cleanup_snapshot(&mut self) -> WindowsRouteCleanupSnapshot {
        let cleanup = self.cleanup_snapshot();
        self.default_owned = false;
        self.default_v6_owned = false;
        self.bypass_owned = false;
        self.orphaned_bypass_routes.clear();
        cleanup
    }

    fn revert_retaining_pending_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
    ) -> Result<()> {
        let result = self.revert_with(runner);
        if result.is_err() {
            let cleanup = self.take_cleanup_snapshot();
            retain_pending_windows_route_cleanup(cleanup);
        }
        result
    }
}
