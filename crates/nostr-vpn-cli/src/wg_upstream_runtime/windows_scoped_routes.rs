#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone)]
struct WindowsManagedRoute {
    spec: WindowsRouteSpec,
    owned: bool,
}

#[cfg(any(test, target_os = "windows"))]
trait WindowsManagedRouteSetPolicy: std::fmt::Debug {
    const INSTALL_CONTEXT: &'static str;
    const FRESH_INSTALL_CONTEXT: &'static str;
    const STALE_REMOVE_CONTEXT: &'static str;
    const OWNED_REMOVE_CONTEXT: &'static str;
    const FRESH_ROLLBACK_CONTEXT: &'static str;
    const STALE_RESTORE_CONTEXT: &'static str;
    const RETAIN_CONTEXT: &'static str;
    const SYNCHRONIZE_CONTEXT: &'static str;

    fn sort_routes(routes: &mut [WindowsManagedRoute]);
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct WindowsEndpointRouteSet;

#[cfg(any(test, target_os = "windows"))]
impl WindowsManagedRouteSetPolicy for WindowsEndpointRouteSet {
    const INSTALL_CONTEXT: &'static str = "install FIPS endpoint bypass route";
    const FRESH_INSTALL_CONTEXT: &'static str = "install fresh FIPS endpoint bypass route";
    const STALE_REMOVE_CONTEXT: &'static str = "remove stale FIPS endpoint bypass route";
    const OWNED_REMOVE_CONTEXT: &'static str = "remove owned FIPS endpoint bypass routes";
    const FRESH_ROLLBACK_CONTEXT: &'static str = "remove freshly-owned endpoint bypass routes";
    const STALE_RESTORE_CONTEXT: &'static str = "restore stale owned endpoint bypass routes";
    const RETAIN_CONTEXT: &'static str = "retain residual endpoint route ownership";
    const SYNCHRONIZE_CONTEXT: &'static str = "synchronize endpoint route retry state";

    fn sort_routes(routes: &mut [WindowsManagedRoute]) {
        routes.sort_by_key(|route| {
            route
                .spec
                .prefix
                .strip_suffix("/32")
                .and_then(|target| target.parse::<std::net::Ipv4Addr>().ok())
                .map(u32::from)
                .unwrap_or(u32::MAX)
        });
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct WindowsInterfaceRouteSet;

#[cfg(any(test, target_os = "windows"))]
impl WindowsManagedRouteSetPolicy for WindowsInterfaceRouteSet {
    const INSTALL_CONTEXT: &'static str = "install FIPS tunnel route";
    const FRESH_INSTALL_CONTEXT: &'static str = "install fresh FIPS tunnel route";
    const STALE_REMOVE_CONTEXT: &'static str = "remove stale FIPS tunnel route";
    const OWNED_REMOVE_CONTEXT: &'static str = "remove owned FIPS tunnel routes";
    const FRESH_ROLLBACK_CONTEXT: &'static str = "remove freshly-owned FIPS tunnel routes";
    const STALE_RESTORE_CONTEXT: &'static str = "restore stale owned FIPS tunnel routes";
    const RETAIN_CONTEXT: &'static str = "retain residual interface route ownership";
    const SYNCHRONIZE_CONTEXT: &'static str = "synchronize interface route retry state";

    fn sort_routes(routes: &mut [WindowsManagedRoute]) {
        routes.sort_by(|left, right| left.spec.prefix.cmp(&right.spec.prefix));
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
struct WindowsManagedRouteSet<P> {
    routes: Vec<WindowsManagedRoute>,
    policy: std::marker::PhantomData<P>,
}

#[cfg(any(test, target_os = "windows"))]
impl<P: WindowsManagedRouteSetPolicy> WindowsManagedRouteSet<P> {
    fn empty() -> Self {
        Self {
            routes: Vec::new(),
            policy: std::marker::PhantomData,
        }
    }

    fn apply_with(
        runner: &mut impl WindowsRouteCommandRunner,
        specs: Vec<WindowsRouteSpec>,
    ) -> std::result::Result<Self, WindowsRouteApplyFailure<Self>> {
        let mut manager = Self::empty();
        manager.routes.reserve(specs.len());
        for mut spec in specs {
            if let Err(error) = runner.bind_interface_identity(&mut spec) {
                let rollback = manager.revert_with(runner);
                return Err(WindowsRouteApplyFailure {
                    error: with_windows_route_rollback(
                        error.context("bind Windows route to stable interface identity"),
                        rollback,
                    ),
                    cleanup: Box::new(manager),
                });
            }
            match ensure_windows_route(runner, &spec) {
                Ok(owned) => manager.routes.push(WindowsManagedRoute { spec, owned }),
                Err(error) => {
                    let rollback = manager.revert_with(runner);
                    return Err(WindowsRouteApplyFailure {
                        error: with_windows_route_rollback(
                            error.context(P::INSTALL_CONTEXT),
                            rollback,
                        ),
                        cleanup: Box::new(manager),
                    });
                }
            }
        }
        Ok(manager)
    }

    fn reconcile_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        specs: Vec<WindowsRouteSpec>,
        metadata_matches: bool,
    ) -> Result<bool> {
        let desired_state_matches =
            metadata_matches && self.routes.iter().map(|route| &route.spec).eq(specs.iter());
        if desired_state_matches {
            let mut every_route_present = true;
            for route in &self.routes {
                every_route_present &= runner.route_exists(&route.spec).with_context(|| {
                    format!("audit tracked Windows route {}", route.spec.prefix)
                })?;
            }
            if every_route_present {
                return Ok(false);
            }
        }

        let mut fresh_routes = Vec::with_capacity(specs.len());
        let mut newly_owned = Vec::new();
        for mut spec in specs {
            runner
                .bind_interface_identity(&mut spec)
                .context("bind reconciled Windows route to stable interface identity")?;
            let existing = self.routes.iter().find(|route| route.spec == spec).cloned();
            let ensured = if let Some(existing) = existing.as_ref() {
                ensure_tracked_windows_route(runner, &spec, existing.owned)
            } else {
                ensure_windows_route(runner, &spec)
            };
            match ensured {
                Ok(owned) => {
                    let mut route = existing.unwrap_or(WindowsManagedRoute { spec, owned: false });
                    if owned {
                        route.owned = true;
                        newly_owned.push(route.clone());
                    }
                    fresh_routes.push(route);
                }
                Err(error) => {
                    let mut rollback = rollback_owned_windows_routes::<P>(runner, &newly_owned);
                    if rollback.is_err() {
                        rollback = combine_windows_route_results(
                            rollback,
                            self.retain_cleanup_obligations(runner, &newly_owned),
                        );
                    }
                    return Err(with_windows_route_rollback(
                        error.context(P::FRESH_INSTALL_CONTEXT),
                        rollback,
                    ));
                }
            }
        }

        // Every desired route now exists. Only routes created by this guard
        // are eligible for stale cleanup; exact preexisting routes stay put.
        let stale_owned = self
            .routes
            .iter()
            .filter(|route| {
                route.owned && !fresh_routes.iter().any(|fresh| fresh.spec == route.spec)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut removed_stale = Vec::new();
        for stale in &stale_owned {
            if let Err(error) = delete_windows_route_with_retry(runner, &stale.spec) {
                let restore_stale = restore_owned_windows_routes::<P>(runner, &removed_stale);
                let remove_fresh = rollback_owned_windows_routes::<P>(runner, &newly_owned);
                let mut rollback = combine_windows_route_results(restore_stale, remove_fresh);
                if rollback.is_err() {
                    rollback = combine_windows_route_results(
                        rollback,
                        self.synchronize_failed_rollback(runner, &removed_stale, &newly_owned),
                    );
                }
                return Err(with_windows_route_rollback(
                    error.context(P::STALE_REMOVE_CONTEXT),
                    rollback,
                ));
            }
            removed_stale.push(stale.clone());
        }

        self.routes = fresh_routes;
        Ok(true)
    }

    fn revert_with(&mut self, runner: &mut impl WindowsRouteCommandRunner) -> Result<()> {
        let mut failures = Vec::new();
        for route in self.routes.iter_mut().filter(|route| route.owned) {
            match delete_windows_route_with_retry(runner, &route.spec) {
                Ok(()) => route.owned = false,
                Err(error) => failures.push(format!("{}: {error:#}", route.spec.prefix)),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "{}: {}",
                P::OWNED_REMOVE_CONTEXT,
                failures.join("; ")
            ))
        }
    }

    fn retain_cleanup_obligations(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        routes: &[WindowsManagedRoute],
    ) -> Result<()> {
        let mut failures = Vec::new();
        for route in routes.iter().filter(|route| route.owned) {
            let present = match runner.route_identity_exists(&route.spec) {
                Ok(present) => present,
                Err(error) => {
                    failures.push(format!("audit {}: {error:#}", route.spec.prefix));
                    true
                }
            };
            if !present {
                continue;
            }
            if let Some(existing) = self
                .routes
                .iter_mut()
                .find(|existing| existing.spec == route.spec)
            {
                existing.owned = true;
            } else {
                self.routes.push(route.clone());
            }
        }
        P::sort_routes(&mut self.routes);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("{}: {}", P::RETAIN_CONTEXT, failures.join("; ")))
        }
    }

    fn synchronize_failed_rollback(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        removed_stale: &[WindowsManagedRoute],
        newly_owned: &[WindowsManagedRoute],
    ) -> Result<()> {
        let mut failures = Vec::new();
        for route in removed_stale {
            match runner.route_identity_exists(&route.spec) {
                Ok(true) => {}
                Ok(false) => self.routes.retain(|existing| existing.spec != route.spec),
                Err(error) => failures.push(format!("audit {}: {error:#}", route.spec.prefix)),
            }
        }
        if let Err(error) = self.retain_cleanup_obligations(runner, newly_owned) {
            failures.push(format!("{error:#}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "{}: {}",
                P::SYNCHRONIZE_CONTEXT,
                failures.join("; ")
            ))
        }
    }

    fn cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        let owned_routes = self
            .routes
            .iter()
            .filter(|route| route.owned)
            .map(|route| route.spec.clone())
            .collect();
        WindowsRouteCleanupSnapshot::from_owned_routes(owned_routes)
    }

    fn take_cleanup_snapshot(&mut self) -> WindowsRouteCleanupSnapshot {
        let cleanup = self.cleanup_snapshot();
        for route in self.routes.iter_mut().filter(|route| route.owned) {
            route.owned = false;
        }
        cleanup
    }

    fn revert_retaining_pending_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
    ) -> Result<()> {
        let result = self.revert_with(runner);
        if result.is_err() {
            retain_pending_windows_route_cleanup(self.take_cleanup_snapshot());
        }
        result
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
pub(crate) struct WindowsManagedEndpointRoutes {
    underlay: WindowsDefaultRoute,
    routes: WindowsManagedRouteSet<WindowsEndpointRouteSet>,
    #[cfg(target_os = "windows")]
    cleanup_journal_config_path: Option<std::path::PathBuf>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsManagedEndpointRoutes {
    fn apply_with(
        runner: &mut impl WindowsRouteCommandRunner,
        targets: &[std::net::Ipv4Addr],
        underlay: WindowsDefaultRoute,
        excluded_tunnel_interfaces: &[u32],
    ) -> std::result::Result<Self, WindowsRouteApplyFailure<Self>> {
        if let Err(error) = validate_windows_underlay(&underlay, excluded_tunnel_interfaces) {
            return Err(WindowsRouteApplyFailure {
                error,
                cleanup: Box::new(Self {
                    underlay,
                    routes: WindowsManagedRouteSet::empty(),
                    #[cfg(target_os = "windows")]
                    cleanup_journal_config_path: None,
                }),
            });
        }
        let specs = sorted_windows_endpoint_targets(targets)
            .into_iter()
            .map(|target| WindowsRouteSpec::endpoint(target, &underlay))
            .collect();
        match WindowsManagedRouteSet::apply_with(runner, specs) {
            Ok(routes) => Ok(Self {
                underlay,
                routes,
                #[cfg(target_os = "windows")]
                cleanup_journal_config_path: None,
            }),
            Err(failure) => Err(WindowsRouteApplyFailure {
                error: failure.error,
                cleanup: Box::new(Self {
                    underlay,
                    routes: *failure.cleanup,
                    #[cfg(target_os = "windows")]
                    cleanup_journal_config_path: None,
                }),
            }),
        }
    }

    fn reconcile_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        targets: &[std::net::Ipv4Addr],
        fresh_underlay: WindowsDefaultRoute,
        excluded_tunnel_interfaces: &[u32],
    ) -> Result<bool> {
        validate_windows_underlay(&fresh_underlay, excluded_tunnel_interfaces)?;
        let specs = sorted_windows_endpoint_targets(targets)
            .into_iter()
            .map(|target| WindowsRouteSpec::endpoint(target, &fresh_underlay))
            .collect();
        let underlay_changed = self.underlay != fresh_underlay;
        let routes_changed = self
            .routes
            .reconcile_with(runner, specs, !underlay_changed)?;
        self.underlay = fresh_underlay;
        Ok(underlay_changed || routes_changed)
    }

    fn revert_with(&mut self, runner: &mut impl WindowsRouteCommandRunner) -> Result<()> {
        self.routes.revert_with(runner)
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug)]
pub(crate) struct WindowsManagedInterfaceRoutes {
    interface_index: u32,
    routes: WindowsManagedRouteSet<WindowsInterfaceRouteSet>,
    #[cfg(target_os = "windows")]
    cleanup_journal_config_path: Option<std::path::PathBuf>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsManagedInterfaceRoutes {
    fn apply_with(
        runner: &mut impl WindowsRouteCommandRunner,
        interface_index: u32,
        targets: &[String],
    ) -> std::result::Result<Self, WindowsRouteApplyFailure<Self>> {
        let specs = match windows_direct_route_specs(interface_index, targets) {
            Ok(specs) => specs,
            Err(error) => {
                return Err(WindowsRouteApplyFailure {
                    error,
                    cleanup: Box::new(Self {
                        interface_index,
                        routes: WindowsManagedRouteSet::empty(),
                        #[cfg(target_os = "windows")]
                        cleanup_journal_config_path: None,
                    }),
                });
            }
        };
        match WindowsManagedRouteSet::apply_with(runner, specs) {
            Ok(routes) => Ok(Self {
                interface_index,
                routes,
                #[cfg(target_os = "windows")]
                cleanup_journal_config_path: None,
            }),
            Err(failure) => Err(WindowsRouteApplyFailure {
                error: failure.error,
                cleanup: Box::new(Self {
                    interface_index,
                    routes: *failure.cleanup,
                    #[cfg(target_os = "windows")]
                    cleanup_journal_config_path: None,
                }),
            }),
        }
    }

    fn reconcile_with(
        &mut self,
        runner: &mut impl WindowsRouteCommandRunner,
        targets: &[String],
    ) -> Result<bool> {
        let specs = windows_direct_route_specs(self.interface_index, targets)?;
        self.routes.reconcile_with(runner, specs, true)
    }

    fn revert_with(&mut self, runner: &mut impl WindowsRouteCommandRunner) -> Result<()> {
        self.routes.revert_with(runner)
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WindowsRouteCleanupSnapshot {
    owned_routes: Vec<WindowsRouteSpec>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsRouteCleanupSnapshot {
    fn from_owned_routes(owned_routes: Vec<WindowsRouteSpec>) -> Self {
        let mut snapshot = Self { owned_routes };
        snapshot.normalize();
        snapshot
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.owned_routes.is_empty()
    }

    pub(crate) fn merge(&mut self, mut other: Self) {
        self.owned_routes.append(&mut other.owned_routes);
        self.normalize();
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn remove(&mut self, other: &Self) {
        self.owned_routes
            .retain(|route| !other.owned_routes.contains(route));
        self.normalize();
    }

    fn retry_with(&mut self, runner: &mut impl WindowsRouteCommandRunner) -> Result<()> {
        let mut remaining = Vec::new();
        let mut failures = Vec::new();
        for route in std::mem::take(&mut self.owned_routes) {
            // Journals written before stable adapter identities were added
            // cannot prove ownership of a route on a shared physical
            // interface. Retire those endpoint-bypass obligations
            // without issuing an unscoped delete. On-link routes belong to
            // the process-created tunnel interface; they must still be
            // removed or a stale default can leave the device offline.
            if route.is_identityless_legacy_physical_bypass() {
                continue;
            }
            if let Err(error) = delete_windows_route_with_retry(runner, &route) {
                failures.push(format!("{}: {error:#}", route.prefix));
                remaining.push(route);
            }
        }
        self.owned_routes = remaining;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "pending Windows route cleanup incomplete: {}",
                failures.join("; ")
            ))
        }
    }

    fn normalize(&mut self) {
        self.owned_routes.sort_by(windows_route_spec_order);
        self.owned_routes
            .dedup();
    }
}

#[cfg(any(test, target_os = "windows"))]
static WINDOWS_PENDING_ROUTE_CLEANUP: std::sync::Mutex<WindowsRouteCleanupSnapshot> =
    std::sync::Mutex::new(WindowsRouteCleanupSnapshot {
        owned_routes: Vec::new(),
    });

// The pending registry is global process state; tests that retain into it or
// assert on its contents must not interleave.
#[cfg(test)]
pub(crate) fn windows_pending_cleanup_registry_guard() -> std::sync::MutexGuard<'static, ()> {
    static WINDOWS_PENDING_CLEANUP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    WINDOWS_PENDING_CLEANUP_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(any(test, target_os = "windows"))]
fn retain_pending_windows_route_cleanup(cleanup: WindowsRouteCleanupSnapshot) {
    if cleanup.is_empty() {
        return;
    }
    WINDOWS_PENDING_ROUTE_CLEANUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .merge(cleanup);
}

#[cfg(any(test, target_os = "windows"))]
fn take_pending_windows_route_cleanup() -> WindowsRouteCleanupSnapshot {
    let mut registry = WINDOWS_PENDING_ROUTE_CLEANUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *registry)
}

#[cfg(target_os = "windows")]
pub(crate) fn pending_windows_route_cleanup_snapshot() -> WindowsRouteCleanupSnapshot {
    WINDOWS_PENDING_ROUTE_CLEANUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(target_os = "windows")]
pub(crate) fn retry_windows_route_cleanup_snapshot(
    cleanup: &mut WindowsRouteCleanupSnapshot,
) -> Result<()> {
    cleanup.retry_with(&mut SystemWindowsRouteCommandRunner::repair())
}

#[cfg(target_os = "windows")]
pub(crate) fn retry_pending_windows_route_cleanup() -> Result<()> {
    retry_pending_windows_route_cleanup_with_journal(None)
}

#[cfg(target_os = "windows")]
pub(crate) fn retry_pending_windows_route_cleanup_journaled(
    config_path: &std::path::Path,
) -> Result<()> {
    retry_pending_windows_route_cleanup_with_journal(Some(config_path))
}

#[cfg(target_os = "windows")]
fn retry_pending_windows_route_cleanup_with_journal(
    config_path: Option<&std::path::Path>,
) -> Result<()> {
    let mut cleanup = take_pending_windows_route_cleanup();
    let attempted = cleanup.clone();
    let result = retry_windows_route_cleanup_snapshot(&mut cleanup);
    let persist_result = config_path.map_or(Ok(()), |config_path| {
        crate::daemon_runtime::persist_windows_route_cleanup_result(
            config_path,
            &attempted,
            &cleanup,
        )
    });
    match (result, persist_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => {
            retain_pending_windows_route_cleanup(cleanup);
            Err(error)
        }
        (Ok(()), Err(error)) => {
            retain_pending_windows_route_cleanup(attempted);
            Err(error.context("persist pending Windows route cleanup result"))
        }
        (Err(cleanup_error), Err(persist_error)) => {
            retain_pending_windows_route_cleanup(attempted);
            Err(anyhow!(
                "{cleanup_error:#}; persist pending Windows route cleanup result: \
                 {persist_error:#}"
            ))
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsManagedEndpointRoutes {
    pub(crate) fn apply(
        targets: &[String],
        excluded_tunnel_interfaces: &[u32],
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Option<Self>> {
        retry_pending_windows_route_cleanup_journaled(cleanup_journal_config_path)?;
        let targets = windows_endpoint_target_ips(targets)?;
        if targets.is_empty() {
            return Ok(None);
        }
        let underlay = capture_windows_default_route_excluding(excluded_tunnel_interfaces)?;
        let mut runner =
            SystemWindowsRouteCommandRunner::journaled(cleanup_journal_config_path);
        match Self::apply_with(
            &mut runner,
            &targets,
            underlay,
            excluded_tunnel_interfaces,
        ) {
            Ok(mut routes) => {
                routes.cleanup_journal_config_path =
                    Some(cleanup_journal_config_path.to_path_buf());
                Ok(Some(routes))
            }
            Err(mut failure) => {
                failure.cleanup.cleanup_journal_config_path =
                    Some(cleanup_journal_config_path.to_path_buf());
                retain_pending_windows_route_cleanup(
                    failure.cleanup.routes.take_cleanup_snapshot(),
                );
                Err(failure.error)
            }
        }
    }

    pub(crate) fn reconcile(
        &mut self,
        targets: &[String],
        excluded_tunnel_interfaces: &[u32],
    ) -> Result<bool> {
        if let Some(config_path) = self.cleanup_journal_config_path.as_deref() {
            retry_pending_windows_route_cleanup_journaled(config_path)?;
        } else {
            retry_pending_windows_route_cleanup()?;
        }
        let targets = windows_endpoint_target_ips(targets)?;
        let underlay = if targets.is_empty() {
            self.underlay.clone()
        } else {
            capture_windows_default_route_excluding(excluded_tunnel_interfaces)?
        };
        let mut runner = self.system_runner();
        self.reconcile_with(
            &mut runner,
            &targets,
            underlay,
            excluded_tunnel_interfaces,
        )
    }

    pub(crate) fn revert(&mut self) -> Result<()> {
        let mut runner = self.system_runner();
        self.revert_with(&mut runner)
    }

    pub(crate) fn cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        self.routes.cleanup_snapshot()
    }

    fn system_runner(&self) -> SystemWindowsRouteCommandRunner {
        self.cleanup_journal_config_path.as_deref().map_or_else(
            SystemWindowsRouteCommandRunner::repair,
            SystemWindowsRouteCommandRunner::journaled,
        )
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsManagedEndpointRoutes {
    fn drop(&mut self) {
        let mut runner = self.system_runner();
        if let Err(error) = self
            .routes
            .revert_retaining_pending_with(&mut runner)
        {
            eprintln!("fips: WARNING — owned Windows endpoint bypass cleanup failed: {error:#}");
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsManagedInterfaceRoutes {
    pub(crate) fn apply(
        interface_index: u32,
        targets: &[String],
        cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Self> {
        retry_pending_windows_route_cleanup_journaled(cleanup_journal_config_path)?;
        let mut runner =
            SystemWindowsRouteCommandRunner::journaled(cleanup_journal_config_path);
        match Self::apply_with(
            &mut runner,
            interface_index,
            targets,
        ) {
            Ok(mut routes) => {
                routes.cleanup_journal_config_path =
                    Some(cleanup_journal_config_path.to_path_buf());
                Ok(routes)
            }
            Err(mut failure) => {
                failure.cleanup.cleanup_journal_config_path =
                    Some(cleanup_journal_config_path.to_path_buf());
                retain_pending_windows_route_cleanup(
                    failure.cleanup.routes.take_cleanup_snapshot(),
                );
                Err(failure.error)
            }
        }
    }

    pub(crate) fn reconcile(&mut self, targets: &[String]) -> Result<bool> {
        if let Some(config_path) = self.cleanup_journal_config_path.as_deref() {
            retry_pending_windows_route_cleanup_journaled(config_path)?;
        } else {
            retry_pending_windows_route_cleanup()?;
        }
        let mut runner = self.system_runner();
        self.reconcile_with(&mut runner, targets)
    }

    pub(crate) fn revert(&mut self) -> Result<()> {
        let mut runner = self.system_runner();
        self.revert_with(&mut runner)
    }

    pub(crate) fn cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        self.routes.cleanup_snapshot()
    }

    fn system_runner(&self) -> SystemWindowsRouteCommandRunner {
        self.cleanup_journal_config_path.as_deref().map_or_else(
            SystemWindowsRouteCommandRunner::repair,
            SystemWindowsRouteCommandRunner::journaled,
        )
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsManagedInterfaceRoutes {
    fn drop(&mut self) {
        let mut runner = self.system_runner();
        if let Err(error) = self
            .routes
            .revert_retaining_pending_with(&mut runner)
        {
            eprintln!("fips: WARNING — owned Windows tunnel route cleanup failed: {error:#}");
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_endpoint_target_ips(targets: &[String]) -> Result<Vec<std::net::Ipv4Addr>> {
    targets
        .iter()
        .map(|target| {
            let (host, prefix_len) = target
                .trim()
                .split_once('/')
                .ok_or_else(|| anyhow!("Windows endpoint bypass must be IPv4 /32: {target}"))?;
            if prefix_len != "32" {
                return Err(anyhow!(
                    "Windows endpoint bypass must be IPv4 /32: {target}"
                ));
            }
            host.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("invalid Windows endpoint bypass {target}"))
        })
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
fn windows_direct_route_specs(
    interface_index: u32,
    targets: &[String],
) -> Result<Vec<WindowsRouteSpec>> {
    let mut specs = targets
        .iter()
        .map(|target| WindowsRouteSpec::direct(target, interface_index))
        .collect::<Result<Vec<_>>>()?;
    specs.sort_by(|left, right| left.prefix.cmp(&right.prefix));
    specs.dedup();
    Ok(specs)
}

#[cfg(any(test, target_os = "windows"))]
fn sorted_windows_endpoint_targets(targets: &[std::net::Ipv4Addr]) -> Vec<std::net::Ipv4Addr> {
    let mut targets = targets.to_vec();
    targets.sort_unstable();
    targets.dedup();
    targets
}

#[cfg(any(test, target_os = "windows"))]
fn rollback_owned_windows_routes<P: WindowsManagedRouteSetPolicy>(
    runner: &mut impl WindowsRouteCommandRunner,
    routes: &[WindowsManagedRoute],
) -> Result<()> {
    let mut failures = Vec::new();
    for route in routes.iter().rev().filter(|route| route.owned) {
        if let Err(error) = delete_windows_route_with_retry(runner, &route.spec) {
            failures.push(format!("{}: {error:#}", route.spec.prefix));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "{}: {}",
            P::FRESH_ROLLBACK_CONTEXT,
            failures.join("; ")
        ))
    }
}

#[cfg(any(test, target_os = "windows"))]
fn restore_owned_windows_routes<P: WindowsManagedRouteSetPolicy>(
    runner: &mut impl WindowsRouteCommandRunner,
    routes: &[WindowsManagedRoute],
) -> Result<()> {
    let mut failures = Vec::new();
    for route in routes {
        if let Err(error) = ensure_tracked_windows_route(runner, &route.spec, true) {
            failures.push(format!("{}: {error:#}", route.spec.prefix));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "{}: {}",
            P::STALE_RESTORE_CONTEXT,
            failures.join("; ")
        ))
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_spec_order(
    left: &WindowsRouteSpec,
    right: &WindowsRouteSpec,
) -> std::cmp::Ordering {
    left.prefix
        .cmp(&right.prefix)
        .then(left.interface_index.cmp(&right.interface_index))
        .then(left.next_hop.cmp(&right.next_hop))
        .then(left.metric.cmp(&right.metric))
        .then(left.interface_identity.cmp(&right.interface_identity))
}

#[cfg(any(test, target_os = "windows"))]
fn combine_windows_route_results(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(anyhow!("{first:#}; {second:#}")),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn ensure_windows_route(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
) -> Result<bool> {
    if runner.route_exists(route)? {
        return Ok(false);
    }
    if runner.route_identity_exists(route)? {
        return Err(anyhow!(
            "Windows route identity {} interface={} nexthop={} exists with unowned attributes",
            route.prefix,
            route.interface_index,
            route.next_hop
        ));
    }
    runner.add_route(route)?;
    Ok(true)
}

#[cfg(any(test, target_os = "windows"))]
fn ensure_tracked_windows_route(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
    owned: bool,
) -> Result<bool> {
    if runner.route_exists(route)? {
        return Ok(false);
    }
    if runner.route_identity_exists(route)? {
        if !owned {
            return Err(anyhow!(
                "unowned Windows route identity {} changed attributes",
                route.prefix
            ));
        }
        runner.set_route(route)?;
        return Ok(true);
    }
    runner.add_route(route)?;
    Ok(true)
}

#[cfg(any(test, target_os = "windows"))]
fn delete_windows_route_with_retry(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
) -> Result<()> {
    let mut last_error = None;
    for _ in 0..WINDOWS_ROUTE_CLEANUP_ATTEMPTS {
        match runner.route_exists(route) {
            Ok(false) => match runner.route_identity_exists(route) {
                Ok(false) => return runner.finish_route_cleanup(route),
                Ok(true) => {}
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            },
            Ok(true) => {
                // The exact desired attributes still exist.
            }
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        }
        if !route.is_identityless_legacy_tunnel_route()
            && let Err(error) = runner.verify_interface_identity(route)
        {
            last_error = Some(error);
            continue;
        }
        match runner.delete_route(route) {
            Ok(()) => match runner.finish_route_cleanup(route) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("cleanup attempt count is non-zero"))
}

#[cfg(any(test, target_os = "windows"))]
fn validate_windows_underlay(
    underlay: &WindowsDefaultRoute,
    excluded_tunnel_interfaces: &[u32],
) -> Result<()> {
    if excluded_tunnel_interfaces.contains(&underlay.interface_index) {
        return Err(anyhow!(
            "captured Windows default route points at excluded tunnel interface {}",
            underlay.interface_index
        ));
    }
    underlay
        .gateway
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("invalid Windows underlay gateway {}", underlay.gateway))?;
    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn with_windows_route_rollback(error: anyhow::Error, rollback: Result<()>) -> anyhow::Error {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => anyhow!("{error:#}; rollback failed: {rollback_error:#}"),
    }
}
