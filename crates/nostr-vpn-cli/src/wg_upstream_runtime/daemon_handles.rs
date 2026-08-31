#[cfg(target_os = "windows")]
pub fn apply_windows_scoped_host_route(
    interface_index: u32,
    target: IpAddr,
) -> Result<WindowsScopedHostRoute> {
    let target = match target {
        IpAddr::V4(target) => target,
        IpAddr::V6(_) => {
            return Err(anyhow!(
                "Windows scoped WG upstream routes only support IPv4 targets"
            ));
        }
    };
    let route_targets = vec![format!("{target}/32")];
    let cleanup_journal_config_path = crate::default_config_path();
    let routes = WindowsManagedInterfaceRoutes::apply(
        interface_index,
        &route_targets,
        &cleanup_journal_config_path,
    )?;
    Ok(WindowsScopedHostRoute {
        routes: Some(routes),
    })
}

#[cfg(target_os = "windows")]
pub struct WindowsScopedHostRoute {
    routes: Option<WindowsManagedInterfaceRoutes>,
}

#[cfg(target_os = "windows")]
impl WindowsScopedHostRoute {
    pub fn revert(&mut self) -> Result<()> {
        if let Some(routes) = self.routes.as_mut() {
            routes.revert()?;
            self.routes.take();
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsScopedHostRoute {
    fn drop(&mut self) {
        if let Err(error) = self.revert() {
            eprintln!(
                "wg-upstream: WARNING — Windows scoped host route cleanup failed: {error:#}"
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_checked(command: &mut ProcessCommand) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("spawn {:?}", command.get_program()))?;
    if !status.success() {
        return Err(anyhow!(
            "{:?} {:?} failed: {status}",
            command.get_program(),
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Long-lived holder used by the daemon (macOS-only for now). Owns the tun,
// the userspace WG runtime, and the FullDefaultRoute guard for the lifetime
// of "WireGuard upstream is enabled". Reconciled by FipsPrivateTunnelRuntime
// whenever the config changes.
// ---------------------------------------------------------------------------

// The daemon-side code below keeps the shared WG fingerprint and
// handshake timeout definitions close to the platform routing glue.

#[cfg(target_os = "macos")]
pub struct DaemonWgUpstream {
    pub iface: String,
    pub upstream: SocketAddr,
    underlay_interface: String,
    runtime: Option<WgUpstreamRuntime>,
    full_route: Option<FullDefaultRoute>,
    // Tun is held to keep the utun fd open for the lifetime of the
    // tunnel; dropping it auto-removes the utun device on macOS.
    _tun: Arc<TunSocket>,
    config_fingerprint: WireGuardExitFingerprint,
}

#[cfg(target_os = "windows")]
pub struct DaemonWgUpstream {
    pub iface: String,
    pub upstream: SocketAddr,
    interface_index: u32,
    full_route: Option<WindowsFullDefaultRoute>,
    tunnel: WindowsNativeWireGuardTunnel,
    wg_exe: PathBuf,
    peer_public_key: String,
    config_fingerprint: WireGuardExitFingerprint,
}

#[cfg(target_os = "windows")]
struct WindowsNativeWireGuardTunnel {
    name: String,
    config_path: PathBuf,
    wireguard_exe: PathBuf,
    owner_token: String,
    service_owned: bool,
    config_owned: bool,
    cleanup_journal_config_path: PathBuf,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WindowsNativeWireGuardCleanupState {
    name: String,
    config_path: PathBuf,
    wireguard_exe: PathBuf,
    owner_token: String,
    service_owned: bool,
    config_owned: bool,
}

#[cfg(target_os = "windows")]
impl WindowsNativeWireGuardCleanupState {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.owner_token == other.owner_token
    }

    pub(crate) fn merge_ownership(&mut self, other: &Self) {
        debug_assert!(self.same_owner(other));
        self.service_owned |= other.service_owned;
        self.config_owned |= other.config_owned;
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.service_owned && !self.config_owned
    }
}

#[cfg(target_os = "windows")]
impl WindowsNativeWireGuardTunnel {
    pub(crate) fn cleanup_state(&self) -> Option<WindowsNativeWireGuardCleanupState> {
        (self.service_owned || self.config_owned).then(|| WindowsNativeWireGuardCleanupState {
            name: self.name.clone(),
            config_path: self.config_path.clone(),
            wireguard_exe: self.wireguard_exe.clone(),
            owner_token: self.owner_token.clone(),
            service_owned: self.service_owned,
            config_owned: self.config_owned,
        })
    }
}

/// Bring up the daemon-owned WG upstream tunnel: create utun, run the
/// userspace WG state machine, wait for handshake, and only then swap
/// the default route. If the handshake doesn't complete within
/// `handshake_timeout`, the tunnel is torn down and the routing table
/// is **not** modified.
///
/// This is the "happy path" entry point used by the macOS daemon
/// reconcile loop. The caller stores the returned `DaemonWgUpstream`
/// inside the long-lived runtime; dropping it (or calling `cleanup`)
/// restores the original default route.
#[cfg(target_os = "macos")]
pub async fn apply_daemon_wg_upstream(
    config: &WireGuardExitConfig,
    underlay_interface: &str,
    handshake_timeout: Duration,
) -> Result<DaemonWgUpstream> {
    let fingerprint = WireGuardExitFingerprint::from_config(config);
    let interface_hint =
        if config.interface.trim().is_empty() || !config.interface.starts_with("utun") {
            // Daemon-side: always let the kernel pick the next utunN.
            // The user-facing config's `interface` is just a label.
            "utun".to_string()
        } else {
            config.interface.clone()
        };

    let tun = TunSocket::new(&interface_hint)
        .with_context(|| format!("create utun for WG upstream (hint='{interface_hint}')"))?
        .set_non_blocking()
        .context("set utun non-blocking")?;
    let actual_iface = tun.name().context("read utun name (probably needs root)")?;
    let tun = Arc::new(tun);

    let interface_index = macos_interface_index(underlay_interface)?;
    let runtime = start_wg_runtime_with_posix_tun_on_interface(
        config,
        tun.clone(),
        interface_index,
    )
        .await
        .with_context(|| {
            format!(
                "start userspace WG runtime on physical interface {underlay_interface}"
            )
        })?;
    let upstream = runtime.upstream();

    // Watchdog: wait up to `handshake_timeout` for the WG handshake to
    // complete. If it doesn't, we never modify the routing table —
    // tear down the tun + runtime and surface the error.
    if !runtime.wait_for_handshake(handshake_timeout).await {
        runtime.shutdown().await;
        return Err(anyhow!(
            "WG upstream handshake to {upstream} did not complete within {}s; \
             routing table NOT modified",
            handshake_timeout.as_secs()
        ));
    }

    let mtu = if config.mtu > 0 { config.mtu } else { 1420 };
    let full_route = match apply_full_default_route(
        &actual_iface,
        &config.address,
        upstream,
        mtu,
        Some(underlay_interface),
    ) {
        Ok(route) => route,
        Err(error) => {
            runtime.shutdown().await;
            return Err(error.context("swap default route via WG upstream"));
        }
    };

    Ok(DaemonWgUpstream {
        iface: actual_iface,
        upstream,
        underlay_interface: underlay_interface.to_string(),
        runtime: Some(runtime),
        full_route: Some(full_route),
        _tun: tun,
        config_fingerprint: fingerprint,
    })
}

#[cfg(target_os = "macos")]
impl DaemonWgUpstream {
    /// Whether the daemon should consider this WG upstream tunnel
    /// equivalent to a fresh apply for `new_config`. Used by the
    /// reconcile loop to short-circuit a teardown+rebuild on every
    /// tick.
    pub fn matches(&self, new_config: &WireGuardExitConfig) -> bool {
        self.config_matches(new_config)
            && self
                .runtime
                .as_ref()
                .is_some_and(WgUpstreamRuntime::is_running)
    }

    pub fn config_matches(&self, new_config: &WireGuardExitConfig) -> bool {
        self.config_fingerprint == WireGuardExitFingerprint::from_config(new_config)
    }

    pub fn underlay_interface(&self) -> &str {
        &self.underlay_interface
    }

    pub(crate) fn prepare_underlay_route(
        &mut self,
        underlay_interface: &str,
    ) -> Result<Option<crate::MacosManagedRoute>> {
        self.full_route
            .as_mut()
            .ok_or_else(|| anyhow!("macOS WireGuard route guard is missing"))?
            .prepare_macos_endpoint_bypass(self.upstream.ip(), underlay_interface)
    }

    /// Move the live encrypted UDP socket to the newly selected physical
    /// interface, force a fresh handshake, and keep the split-default kill
    /// switch installed throughout. A stalled pump gets one bounded restart
    /// on the same utun and exact previously resolved endpoint; the function's
    /// deadline covers both phases.
    pub async fn rebind_underlay(
        &mut self,
        config: &WireGuardExitConfig,
        underlay_interface: &str,
        handshake_timeout: Duration,
        desired_endpoint_bypass: Option<crate::MacosManagedRoute>,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + handshake_timeout;
        let interface_index = macos_interface_index(underlay_interface)?;
        let rebind_result = if let Some(runtime) = self.runtime.as_mut() {
            let live_budget =
                std::cmp::min(handshake_timeout / 2, Duration::from_millis(1_500));
            match tokio::time::timeout(
                live_budget,
                rebind_live_macos_wg_runtime(
                    runtime,
                    interface_index,
                    underlay_interface,
                    live_budget,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow!(
                    "live WG rebind phase exceeded {}ms",
                    live_budget.as_millis()
                )),
            }
        } else {
            Err(anyhow!("WG userspace runtime is not running"))
        };

        if let Err(rebind_error) = rebind_result {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "live WG underlay rebind failed ({rebind_error:#}); no time remained inside \
                     the {}ms handoff deadline",
                    handshake_timeout.as_millis()
                ));
            }
            match tokio::time::timeout(
                remaining,
                self.restart_runtime(config, underlay_interface, interface_index, remaining),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(restart_error)) => {
                    return Err(anyhow!(
                        "live WG underlay rebind failed ({rebind_error:#}); bounded restart on \
                         the cached endpoint also failed ({restart_error:#})"
                    ));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "live WG underlay rebind failed ({rebind_error:#}); cached-endpoint \
                         restart exceeded the end-to-end {}ms deadline",
                        handshake_timeout.as_millis()
                    ));
                }
            }
        }
        self.full_route
            .as_mut()
            .ok_or_else(|| anyhow!("macOS WireGuard route guard is missing"))?
            .commit_macos_endpoint_bypass(desired_endpoint_bypass.as_ref())?;
        self.underlay_interface = underlay_interface.to_string();
        Ok(())
    }

    async fn restart_runtime(
        &mut self,
        config: &WireGuardExitConfig,
        underlay_interface: &str,
        interface_index: u32,
        handshake_timeout: Duration,
    ) -> Result<()> {
        // Split-default routes already point at this utun, so resolving a
        // hostname after stopping the old pump would route DNS into a dead
        // tunnel. Restart against the exact previously resolved endpoint.
        let upstream = self.upstream;
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().await;
        }
        let runtime = start_wg_runtime_with_posix_tun_on_interface_at_upstream(
            config,
            self._tun.clone(),
            interface_index,
            upstream,
        )
        .await
        .with_context(|| {
            format!(
                "restart WG runtime for {upstream} on physical interface {underlay_interface}"
            )
        })?;
        if !runtime.wait_for_handshake(handshake_timeout).await {
            runtime.shutdown().await;
            return Err(anyhow!(
                "restarted WG upstream handshake to {upstream} on \
                 {underlay_interface} did not complete within {}s",
                handshake_timeout.as_secs()
            ));
        }
        self.upstream = upstream;
        self.underlay_interface = underlay_interface.to_string();
        self.config_fingerprint = WireGuardExitFingerprint::from_config(config);
        self.runtime = Some(runtime);
        Ok(())
    }

    /// Tear down the WG upstream cleanly: remove the two WG split-default
    /// routes while leaving the physical default untouched, then stop the
    /// boringtun pump and drop the tun device.
    pub async fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if let Some(full_route) = self.full_route.as_mut() {
            if let Err(error) = full_route.revert() {
                failures.push(format!("revert macOS WG split-default routes: {error:#}"));
            } else {
                self.full_route.take();
            }
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().await;
        }
        // self._tun drops here, removing the utun device.
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    pub(crate) fn macos_managed_routes(&self) -> Vec<crate::MacosManagedRoute> {
        self.full_route
            .as_ref()
            .map_or_else(Vec::new, FullDefaultRoute::macos_managed_routes)
    }
}

#[cfg(target_os = "macos")]
async fn rebind_live_macos_wg_runtime(
    runtime: &mut WgUpstreamRuntime,
    interface_index: u32,
    underlay_interface: &str,
    budget: Duration,
) -> Result<()> {
    const ROUTE_SETTLE_RETRY: Duration = Duration::from_millis(25);

    let deadline = tokio::time::Instant::now() + budget;
    let receiver_index = loop {
        match runtime.rebind_interface(interface_index).await {
            Ok(receiver_index) => break receiver_index,
            Err(error) if macos_route_is_still_settling(&error) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining <= ROUTE_SETTLE_RETRY {
                    return Err(error).context("rebind live WG UDP socket after route settled");
                }
                tokio::time::sleep(ROUTE_SETTLE_RETRY).await;
            }
            Err(error) => return Err(error).context("rebind live WG UDP socket"),
        }
    };
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    runtime
        .wait_for_handshake_response(receiver_index, remaining)
        .await
        .then_some(())
        .ok_or_else(|| {
            anyhow!(
                "WG upstream did not complete the exact forced handshake on \
                 {underlay_interface}"
            )
        })
}

#[cfg(target_os = "macos")]
fn macos_route_is_still_settling(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NetworkUnreachable)
    })
}

#[cfg(target_os = "macos")]
fn macos_interface_index(interface: &str) -> Result<u32> {
    let interface = interface.trim();
    if interface.is_empty() {
        return Err(anyhow!("missing physical interface for macOS WG upstream"));
    }
    let name = std::ffi::CString::new(interface)
        .with_context(|| format!("physical interface contains NUL: {interface:?}"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("resolve macOS interface index for {interface}"));
    }
    Ok(index)
}

#[cfg(target_os = "windows")]
impl DaemonWgUpstream {
    pub fn matches(&self, new_config: &WireGuardExitConfig) -> bool {
        self.config_fingerprint == WireGuardExitFingerprint::from_config(new_config)
    }

    pub fn refresh_underlay_routes(&mut self, excluded_tunnel_interfaces: &[u32]) -> Result<bool> {
        let upstream = windows_native_wireguard_peer_endpoint(
            &self.wg_exe,
            &self.tunnel.name,
            &self.peer_public_key,
        )?;
        let changed = self
            .full_route
            .as_mut()
            .ok_or_else(|| anyhow!("Windows WireGuard route guard is missing"))?
            .reconcile_endpoint_and_underlay(upstream, excluded_tunnel_interfaces)?;
        self.upstream = upstream;
        Ok(changed)
    }

    pub(crate) fn interface_index(&self) -> u32 {
        self.interface_index
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if let Some(full_route) = self.full_route.as_mut() {
            match full_route.revert() {
                Ok(()) => self.full_route = None,
                Err(error) => {
                    failures.push(format!("revert Windows WireGuard routes: {error:#}"))
                }
            }
        }
        if let Err(error) = retry_pending_windows_route_cleanup_journaled(
            &self.tunnel.cleanup_journal_config_path,
        ) {
            failures.push(format!("retry pending Windows route cleanup: {error:#}"));
        }
        if let Err(error) = retry_pending_windows_native_cleanup_journaled(
            &self.tunnel.cleanup_journal_config_path,
        ) {
            failures.push(format!("retry pending native WireGuard cleanup: {error:#}"));
        }
        if let Err(error) = self.tunnel.cleanup() {
            failures.push(format!(
                "clean up owned WireGuardTunnel${} service/config: {error:#}",
                self.tunnel.name
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    pub(crate) fn native_cleanup_state(&self) -> Option<WindowsNativeWireGuardCleanupState> {
        self.tunnel.cleanup_state()
    }

    pub(crate) fn route_cleanup_snapshot(&self) -> WindowsRouteCleanupSnapshot {
        self.full_route
            .as_ref()
            .map_or_else(WindowsRouteCleanupSnapshot::default, |route| {
                route.cleanup_snapshot()
            })
    }
}

// ---------------------------------------------------------------------------
// Windows full default-route swap. Same shape as FullDefaultRoute on
