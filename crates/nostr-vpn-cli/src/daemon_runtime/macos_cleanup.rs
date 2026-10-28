#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_route_delete_error_is_absent(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not in table")
        || lower.contains("no such process")
        || lower.contains("no such route")
        || lower.contains("bad interface name")
        || lower.contains("not a network interface")
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_cleanup_managed_routes(
    state: &MacosNetworkCleanupState,
) -> Vec<MacosManagedRoute> {
    let mut routes = state.managed_routes.clone();
    if routes.is_empty() {
        // Legacy journals did not record the gateway or interface that owned
        // endpoint bypass routes. Treat those entries as non-actionable instead
        // of risking deletion of a route now owned by another connection.
        if state.original_default_route.is_some() && !state.iface.trim().is_empty() {
            routes.extend(
                crate::macos_network::macos_tunnel_default_route_targets()
                    .iter()
                    .map(|target| MacosManagedRoute {
                        target: (*target).to_string(),
                        gateway: None,
                        interface: Some(state.iface.clone()),
                    }),
            );
        }
    }

    routes.sort_by(|left, right| {
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
    routes.dedup();
    routes
}

#[cfg(target_os = "macos")]
fn cleanup_owned_macos_secure_dns_state() -> Result<bool> {
    crate::secure_dns_runtime::cleanup_owned_macos_secure_dns_state()
}

#[cfg(target_os = "macos")]
pub(crate) fn repair_legacy_macos_network_state(config_path: &Path) -> Result<bool> {
    let app = load_or_default_config(config_path)?;
    let mut repaired =
        cleanup_owned_macos_secure_dns_state().context("remove legacy secure DNS state")?;

    if let Ok(tunnel_ip) = strip_cidr(&app.node.tunnel_ip).parse::<Ipv4Addr>() {
        let default_routes = macos_default_routes()?;
        let underlay_default =
            macos_underlay_default_route_from_routes(&default_routes).or_else(|| {
                crate::macos_network::macos_underlay_default_route_from_system()
                    .ok()
                    .flatten()
            });
        let mut tunnel_default_ifaces = Vec::new();

        for route in &default_routes {
            if !route.interface.starts_with("utun") {
                continue;
            }

            match macos_iface_has_ipv4_address(&route.interface, tunnel_ip) {
                Ok(true) => tunnel_default_ifaces.push(route.interface.clone()),
                Ok(false) => {}
                Err(error) => {
                    eprintln!(
                        "repair-network: failed to inspect macOS interface {}: {}",
                        route.interface, error
                    );
                }
            }
        }

        if tunnel_default_ifaces.is_empty() {
            tunnel_default_ifaces =
                crate::macos_network::macos_tunnel_interfaces_with_ipv4(tunnel_ip)?;
        }
        tunnel_default_ifaces.sort();
        tunnel_default_ifaces.dedup();

        let should_restore_underlay_default = default_routes.is_empty()
            || default_routes
                .iter()
                .all(|route| route.interface.starts_with("utun"));
        if let Some(underlay_default) = underlay_default {
            for iface in tunnel_default_ifaces {
                match delete_macos_default_route_for_interface(&iface) {
                    Ok(()) => repaired = true,
                    Err(error) if macos_route_delete_error_is_absent(&error.to_string()) => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to remove legacy macOS default route on {iface}")
                        });
                    }
                }
            }

            if repaired || should_restore_underlay_default {
                restore_macos_default_route(&underlay_default)
                    .context("failed to restore legacy macOS default route")?;
                repaired = true;
            }
        }
    }

    let cleanup_plan = legacy_macos_exit_cleanup_plan(&runtime_effective_advertised_routes(&app));
    if cleanup_plan.cleanup_pf_nat {
        // Journals are absent for this legacy path, so the shared anchor is
        // the only place an old install could have left exit NAT rules.
        if let Err(error) = cleanup_macos_pf_nat(crate::macos_network::MACOS_PF_EXIT_ANCHOR) {
            eprintln!("repair-network: failed to clear legacy macOS PF NAT rules: {error}");
        } else {
            repaired = true;
        }
    }

    Ok(repaired)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LegacyMacosExitCleanupPlan {
    pub(crate) cleanup_pf_nat: bool,
    pub(crate) restore_ipv4_forwarding: bool,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn legacy_macos_exit_cleanup_plan(routes: &[String]) -> LegacyMacosExitCleanupPlan {
    let route_families = linux_exit_node_default_route_families(routes);
    LegacyMacosExitCleanupPlan {
        cleanup_pf_nat: route_families.ipv4,
        // Legacy repair has no reliable saved owner for this global knob.
        // Internet Sharing and VM hosts also use it, so do not force it off.
        restore_ipv4_forwarding: false,
    }
}

pub(crate) fn repair_saved_network_state(config_path: &Path) -> Result<bool> {
    #[cfg(test)]
    crate::TEST_REPAIR_SAVED_NETWORK_STATE_CALLS.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_os = "macos")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let Some(state) = read_daemon_network_cleanup_state(&path)? else {
            return repair_legacy_macos_network_state(config_path);
        };
        let managed_routes = macos_cleanup_managed_routes(&state);
        let using_legacy_route_cleanup = state.managed_routes.is_empty();

        let mut failures = Vec::new();
        let mut other_exit_claims = false;
        if state.pf_was_enabled.is_some() || state.ipv4_forward_was_enabled == Some(false) {
            other_exit_claims = match crate::macos_privileged_files::other_exit_claims_remain(
                config_path,
            ) {
                Ok(remain) => remain,
                Err(error) => {
                    failures.push(format!("inspect macOS exit claims: {error:#}"));
                    true
                }
            };
        }

        for route in &managed_routes {
            if let Err(error) = delete_macos_managed_route(
                &route.target,
                route.gateway.as_deref(),
                route.interface.as_deref(),
            ) && !macos_route_delete_error_is_absent(&error.to_string())
            {
                failures.push(format!("remove managed route {}: {error}", route.target));
            }
        }

        if let Some(route) = state.original_default_route.as_ref()
            && let Err(error) = restore_macos_default_route(route)
        {
            failures.push(format!("restore default route: {error}"));
        }

        if state.pf_was_enabled.is_some() {
            // Journals written before per-config anchors name the shared one.
            let anchor = state
                .pf_exit_anchor
                .as_deref()
                .unwrap_or(crate::macos_network::MACOS_PF_EXIT_ANCHOR);
            if let Err(error) = cleanup_macos_pf_nat(anchor) {
                failures.push(format!("remove PF NAT rules: {error}"));
            }
            if state.pf_was_enabled == Some(false)
                && !other_exit_claims
                && let Err(error) = run_checked(ProcessCommand::new("pfctl").arg("-d"))
            {
                failures.push(format!("restore PF enabled state: {error}"));
            }
        }

        if let Err(error) = crate::macos_privileged_files::remove_exit_claim(config_path) {
            failures.push(format!("remove macOS exit forwarding claim: {error:#}"));
        }

        if state.ipv4_forward_was_enabled == Some(false)
            && !other_exit_claims
            && let Err(error) = write_macos_ipv4_forwarding(false)
        {
            failures.push(format!("restore IPv4 forwarding state: {error}"));
        }

        if state.secure_dns_resolver_files
            && let Err(error) = cleanup_owned_macos_secure_dns_state()
        {
            failures.push(format!("remove secure DNS state: {error}"));
        }

        if using_legacy_route_cleanup
            && let Err(error) = repair_legacy_macos_network_state(config_path)
        {
            failures.push(format!("repair legacy macOS routes: {error}"));
        }

        if !failures.is_empty() {
            return Err(anyhow!(failures.join("; ")))
                .with_context(|| format!("failed to repair {}", path.display()));
        }

        remove_runtime_file_if_exists(&path)?;
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let Some(mut state) = read_daemon_network_cleanup_state(&path)? else {
            return Ok(false);
        };
        if let Err(error) = crate::fips_private_mesh::repair_linux_network_cleanup_state(&mut state)
        {
            return match write_daemon_network_cleanup_state(&path, &state) {
                Ok(()) => Err(error)
                    .with_context(|| format!("failed to repair saved state {}", path.display())),
                Err(write_error) => Err(anyhow!(
                    "{error:#}; failed to persist remaining cleanup ownership: {write_error:#}"
                ))
                .with_context(|| format!("failed to repair saved state {}", path.display())),
            };
        }
        remove_runtime_file_if_exists(&path)?;
        Ok(true)
    }

    #[cfg(target_os = "windows")]
    {
        let path = daemon_network_cleanup_file_path(config_path)?;
        let Some(mut state) = read_daemon_network_cleanup_state(&path)? else {
            return Ok(false);
        };
        if let Err(error) =
            crate::fips_private_mesh::repair_windows_network_cleanup_state(&mut state)
        {
            return match write_daemon_network_cleanup_state(&path, &state) {
                Ok(()) => Err(error)
                    .with_context(|| format!("failed to repair saved state {}", path.display())),
                Err(write_error) => Err(anyhow!(
                    "{error:#}; failed to persist remaining cleanup ownership: {write_error:#}"
                ))
                .with_context(|| format!("failed to repair saved state {}", path.display())),
            };
        }
        remove_runtime_file_if_exists(&path)?;
        Ok(true)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = config_path;
        Ok(false)
    }
}
