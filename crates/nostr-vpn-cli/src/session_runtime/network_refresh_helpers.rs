fn begin_platform_network_refresh_attempt(
    latest_snapshot: crate::diagnostics::NetworkSnapshot,
    platform_network_event: bool,
    network_changed: bool,
    network_state_drift: bool,
    endpoint_changed: bool,
    resumed_after_sleep: bool,
) -> Option<PlatformNetworkRefreshAttempt> {
    let refresh = fips_link_event_refresh(
        platform_network_event,
        network_changed,
        network_state_drift,
        endpoint_changed,
        resumed_after_sleep,
    );
    if matches!(refresh, FipsLinkEventRefresh::None) {
        return None;
    }
    let (reason, diagnostic) = if network_changed {
        (
            "network change",
            "daemon: network change detected; refreshing FIPS endpoint state",
        )
    } else if resumed_after_sleep {
        (
            "sleep/wake",
            "daemon: sleep/wake detected; refreshing FIPS endpoint state",
        )
    } else if network_state_drift {
        (
            "WireGuard route drift",
            "daemon: unmanaged Linux default route detected; reconciling WireGuard network state",
        )
    } else {
        (
            "endpoint change",
            "daemon: endpoint changed; refreshing FIPS endpoint state",
        )
    };
    eprintln!("{diagnostic}");
    Some(PlatformNetworkRefreshAttempt::new(
        latest_snapshot,
        refresh,
        reason,
    ))
}

fn prefer_nonself_tunnel_snapshot(
    tunnel_runtime: &CliTunnelRuntime,
    wireguard_exit_interface: Option<&str>,
    wireguard_exit_ipv4: Option<Ipv4Addr>,
    previous: &crate::diagnostics::NetworkSnapshot,
    latest: crate::diagnostics::NetworkSnapshot,
) -> crate::diagnostics::NetworkSnapshot {
    let latest = crate::diagnostics::prefer_nonempty_network_snapshot(previous, latest);
    if latest.default_interface.is_some()
        && latest.default_interface == previous.default_interface
        && previous.primary_ipv4.is_some()
        && latest.primary_ipv4.is_none()
        && latest.gateway_ipv4.is_none()
    {
        return previous.clone();
    }
    match latest.default_interface.as_deref() {
        Some(iface)
            if tunnel_runtime.owns_interface(iface)
                || wireguard_exit_interface.is_some_and(|managed| managed == iface)
                || wireguard_exit_ipv4.is_some_and(|managed| latest.primary_ipv4 == Some(managed)) =>
        {
            previous.clone()
        }
        _ => latest,
    }
}

async fn capture_network_snapshot_for_daemon(
    tunnel_interface: &str,
    wireguard_exit_interface: Option<&str>,
    default_route_hints: Vec<String>,
) -> crate::diagnostics::NetworkSnapshotSample {
    let mut excluded_interfaces = vec![tunnel_interface.to_string()];
    if let Some(interface) = wireguard_exit_interface {
        excluded_interfaces.push(interface.to_string());
    }
    match tokio::task::spawn_blocking(move || {
        let excluded_interfaces = excluded_interfaces
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        crate::diagnostics::capture_network_snapshot_sample_excluding_interfaces(
            &excluded_interfaces,
            &default_route_hints,
        )
    })
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("daemon: network snapshot task failed: {error}");
            let snapshot = crate::diagnostics::NetworkSnapshot::default();
            crate::diagnostics::NetworkSnapshotSample {
                diagnostic: "selected=none reason=snapshot-task-failed".to_string(),
                snapshot,
                live_unmanaged_ipv4_default_present: false,
            }
        }
    }
}

fn spawn_platform_network_change_monitor() -> Option<tokio::sync::mpsc::Receiver<()>> {
    #[cfg(target_os = "linux")]
    {
        crate::linux_network::spawn_linux_route_change_monitor()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos_network::spawn_macos_route_change_monitor()
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows_network::spawn_windows_route_change_monitor()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

async fn recv_platform_network_change(
    rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
) -> Option<()> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn drain_platform_network_changes(rx: &mut Option<tokio::sync::mpsc::Receiver<()>>) {
    let Some(rx) = rx.as_mut() else {
        return;
    };
    while rx.try_recv().is_ok() {}
}

pub(crate) fn drain_platform_network_changes_for_sample(
    rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
    event_driven_sample: bool,
) {
    // Discard notifications already represented by an event-owned
    // kernel-state sample so a storm cannot starve its absolute deadline.
    if event_driven_sample {
        drain_platform_network_changes(rx);
    }
}

fn log_event_driven_network_sample(
    event_driven_sample: bool,
    sampled_network: &crate::diagnostics::NetworkSnapshotSample,
    last_diagnostic: &mut String,
) {
    if event_driven_sample && sampled_network.diagnostic != *last_diagnostic {
        eprintln!(
            "daemon: physical route sample: {}; sampled_unix_ms={}",
            sampled_network.diagnostic,
            daemon_wall_clock_unix_milliseconds()
        );
        sampled_network.diagnostic.clone_into(last_diagnostic);
    }
}
