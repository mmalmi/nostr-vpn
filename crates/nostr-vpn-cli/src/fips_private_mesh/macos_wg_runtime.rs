#[cfg(target_os = "macos")]
const MACOS_WG_HANDOFF_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

#[cfg(target_os = "macos")]
static PENDING_MACOS_NETWORK_CLEANUP: std::sync::Mutex<
    Option<crate::MacosNetworkCleanupState>,
> = std::sync::Mutex::new(None);

#[cfg(target_os = "macos")]
pub(crate) fn pending_macos_network_cleanup_state(
) -> Option<crate::MacosNetworkCleanupState> {
    PENDING_MACOS_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(target_os = "macos")]
pub(crate) fn record_macos_stop_cleanup_ownership(
    cleanup_result: &Result<()>,
    remaining: Option<crate::MacosNetworkCleanupState>,
) {
    *PENDING_MACOS_NETWORK_CLEANUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        cleanup_result.is_err().then_some(remaining).flatten();
}

#[cfg(target_os = "macos")]
fn selected_macos_wg_underlay_interface(
    config: &FipsPrivateTunnelConfig,
) -> Result<String> {
    if let Some(interface) = config
        .underlay_interface
        .as_deref()
        .map(str::trim)
        .filter(|interface| !interface.is_empty())
    {
        if interface.starts_with("utun")
            || interface.starts_with("bridge")
            || interface == "lo0"
        {
            return Err(anyhow!(
                "refusing to bind macOS WG upstream to tunnel interface {interface}"
            ));
        }
        return Ok(interface.to_string());
    }

    crate::macos_network::macos_underlay_default_route_from_system()?
        .map(|route| route.interface)
        .ok_or_else(|| anyhow!("no physical macOS underlay interface is available"))
}

#[cfg(target_os = "macos")]
impl FipsPrivateTunnelRuntime {
    fn macos_wg_upstream_needs_cleanup(
        want_up: bool,
        existing_matches: Option<bool>,
    ) -> bool {
        existing_matches.is_some_and(|matches| !want_up || !matches)
    }

    async fn cleanup_owned_macos_wg_upstream(&mut self) -> Result<()> {
        let Some(existing) = self.wg_upstream.as_mut() else {
            return Ok(());
        };
        existing.cleanup().await?;
        self.wg_upstream.take();
        Ok(())
    }

    async fn cleanup_stale_macos_wg_upstream(
        &mut self,
        wg_config: &WireGuardExitConfig,
    ) -> Result<()> {
        let want_up = wg_config.enabled && wg_config.configured();
        let existing_matches = self
            .wg_upstream
            .as_ref()
            .map(|existing| existing.matches(wg_config));
        if Self::macos_wg_upstream_needs_cleanup(want_up, existing_matches) {
            self.cleanup_owned_macos_wg_upstream().await?;
        }
        Ok(())
    }

    async fn reconcile_macos_wg_upstream(
        &mut self,
        config: &FipsPrivateTunnelConfig,
    ) -> Result<()> {
        let wg_config = &config.wireguard_exit;
        let want_up = wg_config.enabled && wg_config.configured();
        if want_up {
            if self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.matches(wg_config))
            {
                return Ok(());
            }
            if self
                .wg_upstream
                .as_ref()
                .is_some_and(|existing| existing.config_matches(wg_config))
            {
                let underlay_interface = selected_macos_wg_underlay_interface(config)?;
                let desired_endpoint_bypass = self
                    .wg_upstream
                    .as_mut()
                    .expect("config-matching WG handle checked above")
                    .prepare_underlay_route(&underlay_interface)?;
                if let Err(error) = self.persist_network_cleanup_ownership() {
                    let cleanup = self.cleanup_owned_macos_wg_upstream().await;
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error.context(format!(
                            "clean up WireGuard routes after journal failure: {cleanup:#}"
                        ))),
                    };
                }
                self.wg_upstream
                    .as_mut()
                    .expect("prepared WG handle remains installed")
                    .rebind_underlay(
                        wg_config,
                        &underlay_interface,
                        crate::wg_upstream_runtime::DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT,
                        desired_endpoint_bypass,
                    )
                    .await?;
                self.persist_network_cleanup_ownership()?;
                return Ok(());
            }
        }
        self.cleanup_owned_macos_wg_upstream().await?;
        if !want_up {
            return Ok(());
        }

        let underlay_interface = selected_macos_wg_underlay_interface(config)?;
        let handle = crate::wg_upstream_runtime::apply_daemon_wg_upstream(
            wg_config,
            &underlay_interface,
            crate::wg_upstream_runtime::DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT,
        )
        .await?;
        eprintln!(
            "fips: WG upstream up on {} via {} bound to {} (split-default kill switch installed)",
            handle.iface, handle.upstream, underlay_interface
        );
        self.wg_upstream = Some(handle);
        if let Err(error) = self.persist_network_cleanup_ownership() {
            let cleanup = self.cleanup_owned_macos_wg_upstream().await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(format!(
                    "clean up WireGuard routes after journal failure: {cleanup:#}"
                ))),
            };
        }
        Ok(())
    }

    pub(crate) async fn rebind_macos_wg_upstream_after_link_event(
        &mut self,
        config: &FipsPrivateTunnelConfig,
    ) -> Result<()> {
        self.macos_underlay_refresh_pending = true;
        let wg_config = &config.wireguard_exit;
        let Some(existing) = self.wg_upstream.as_mut() else {
            return Ok(());
        };
        if !wg_config.enabled || !wg_config.configured() || !existing.config_matches(wg_config) {
            return Ok(());
        }

        let underlay_interface = selected_macos_wg_underlay_interface(config)?;
        let previous_underlay = existing.underlay_interface().to_string();
        let desired_endpoint_bypass = existing.prepare_underlay_route(&underlay_interface)?;
        self.persist_network_cleanup_ownership()?;
        self.wg_upstream
            .as_mut()
            .expect("prepared WG handle remains installed")
            .rebind_underlay(
                wg_config,
                &underlay_interface,
                MACOS_WG_HANDOFF_HANDSHAKE_TIMEOUT,
                desired_endpoint_bypass,
            )
            .await?;
        self.persist_network_cleanup_ownership()?;
        eprintln!(
            "fips: WG upstream rebound {} -> {} with a fresh handshake",
            previous_underlay, underlay_interface
        );
        Ok(())
    }

    pub(crate) fn macos_network_cleanup_state(
        &self,
    ) -> Option<crate::MacosNetworkCleanupState> {
        let mut managed_routes = Vec::new();
        if let Some(underlay) = self.endpoint_bypass_underlay.as_ref() {
            managed_routes.extend(self.endpoint_bypass_routes.iter().map(|target| {
                crate::MacosManagedRoute {
                    target: target.clone(),
                    gateway: underlay.gateway.clone(),
                    interface: Some(underlay.interface.clone()),
                }
            }));
        }
        // The runtime may have installed these routes before a later config
        // step failed and before self.config was committed. Recording both
        // exact routes on this owned utun is safe even when they are absent.
        managed_routes.extend(
            crate::macos_network::macos_tunnel_default_route_targets()
                .iter()
                .map(|target| crate::MacosManagedRoute {
                    target: (*target).to_string(),
                    gateway: None,
                    interface: Some(self.iface.clone()),
                }),
        );
        if let Some(wg_upstream) = self.wg_upstream.as_ref() {
            managed_routes.extend(wg_upstream.macos_managed_routes());
        }
        managed_routes.sort_by(|left, right| {
            (
                left.target.as_str(),
                left.gateway.as_deref().unwrap_or(""),
                left.interface.as_deref().unwrap_or(""),
            )
                .cmp(&(
                    right.target.as_str(),
                    right.gateway.as_deref().unwrap_or(""),
                    right.interface.as_deref().unwrap_or(""),
                ))
        });
        managed_routes.dedup();

        let state = crate::MacosNetworkCleanupState {
            iface: self.iface.clone(),
            endpoint_bypass_routes: self.endpoint_bypass_routes.clone(),
            managed_routes,
            original_default_route: None,
            ipv4_forward_was_enabled: self.exit_node_runtime.ipv4_forward_was_enabled,
            pf_was_enabled: self.exit_node_runtime.pf_was_enabled,
            pf_exit_anchor: self.exit_node_runtime.pf_was_enabled.is_some().then(|| {
                crate::macos_network::macos_exit_pf_anchor(&self.cleanup_journal_config_path)
            }),
            secure_dns_resolver_files: self.secure_dns.is_some(),
        };
        (!state.managed_routes.is_empty()
            || state.ipv4_forward_was_enabled.is_some()
            || state.pf_was_enabled.is_some()
            || state.secure_dns_resolver_files)
        .then_some(state)
    }
}
