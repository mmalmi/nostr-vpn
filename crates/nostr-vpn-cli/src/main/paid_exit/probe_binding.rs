use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PaidExitProbeBinding {
    pub(super) interface: String,
    daemon_pid: Option<u32>,
    seller: String,
    network_id: String,
    route_generation: String,
}

pub(super) fn paid_exit_probe_binding(
    config_path: &Path,
    app: &AppConfig,
    store: &PaidRouteStore,
    session_id: &str,
) -> Result<PaidExitProbeBinding> {
    if !cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )) {
        anyhow::bail!("interactive tunnel-bound paid exit probes are unavailable on this platform");
    }
    if session_id != store.selected_buyer_session_id
        || !matches!(
            app.internet_source,
            InternetSource::PaidAutomatic | InternetSource::PaidManual
        )
    {
        anyhow::bail!(
            "probe requires the selected buyer session; select and connect that exit first"
        );
    }
    let status = daemon_status(config_path)?;
    let state = status
        .state
        .as_ref()
        .ok_or_else(|| anyhow!("paid exit daemon has no tunnel state; connect the exit first"))?;
    paid_exit_probe_binding_from_state(
        app,
        store,
        session_id,
        status.running,
        status.pid,
        state,
        unix_timestamp(),
    )
}

pub(super) fn paid_exit_probe_binding_from_state(
    app: &AppConfig,
    store: &PaidRouteStore,
    session_id: &str,
    running: bool,
    pid: Option<u32>,
    state: &DaemonRuntimeState,
    now: u64,
) -> Result<PaidExitProbeBinding> {
    let seller = normalize_nostr_pubkey(&store.buyer_session_seller_npub(session_id)?)?;
    if session_id != store.selected_buyer_session_id
        || !matches!(
            app.internet_source,
            InternetSource::PaidAutomatic | InternetSource::PaidManual
        )
        || app.public_paid_exit_node_pubkey_hex().as_deref() != Some(&seller)
        || !store.buyer_session_allows_routing(session_id, now)?
        || !store.buyer_session_is_seller_admitted(session_id)?
        || !running
        || !daemon_state_is_fresh(state, now, daemon_state_running_max_age_secs())
        || !state.vpn_enabled
        || !state.vpn_active
        || state.tunnel_interface.is_empty()
        || state.probe_route_generation.is_empty()
        || state.tunnel_exit_peer.as_deref() != Some(&seller)
    {
        anyhow::bail!("probe requires the active, admitted buyer exit; connect it before probing");
    }
    Ok(PaidExitProbeBinding {
        interface: state.tunnel_interface.clone(),
        daemon_pid: pid,
        seller,
        network_id: app.effective_network_id().to_string(),
        route_generation: state.probe_route_generation.clone(),
    })
}

pub(super) fn bind_paid_exit_probe_udp(
    socket: &UdpSocket,
    interface: &str,
    ipv6: bool,
) -> Result<()> {
    bind_paid_exit_probe_socket(&socket2::SockRef::from(socket), interface, ipv6)
}

pub(crate) fn bind_paid_exit_probe_socket(
    socket: &socket2::SockRef<'_>,
    interface: &str,
    ipv6: bool,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name =
            std::ffi::CString::new(interface).context("invalid paid exit tunnel interface")?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        let index = std::num::NonZeroU32::new(index)
            .ok_or_else(|| anyhow!("paid exit tunnel interface {interface} is unavailable"))?;
        #[cfg(target_os = "linux")]
        {
            let _ = (index, ipv6);
            socket
                .bind_device(Some(interface.as_bytes()))
                .context("failed to bind probe to the paid exit tunnel")?;
        }
        #[cfg(target_os = "macos")]
        {
            if ipv6 {
                socket.bind_device_by_index_v6(Some(index))
            } else {
                socket.bind_device_by_index_v4(Some(index))
            }
            .context("failed to bind probe to the paid exit tunnel")?;
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let expected = paid_exit_probe_windows::source_address(interface, ipv6)?;
        if socket.local_addr()?.as_socket().map(|addr| addr.ip()) != Some(expected) {
            anyhow::bail!("probe socket is not bound to the paid exit tunnel address");
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (socket, interface, ipv6);
        anyhow::bail!("tunnel-bound STUN probes are unavailable on this platform")
    }
}
