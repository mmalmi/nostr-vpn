use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use crate::android_session_runtime::{open_mobile_tun_io, should_retry_tun_io, unix_timestamp};
use crate::android_vpn::{AndroidVpnExt, StartVpnArgs};
use crate::mobile_runtime_state::build_mobile_runtime_state;
use crate::mobile_wg::{MobileWireGuardRuntime, PeerRuntimeStatus, WireGuardPeerConfig};
use crate::DaemonRuntimeState;
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::NostrSignalingClient;

use super::android_session_planning::{
    local_interface_address_for_tunnel, local_signal_endpoint, planned_tunnel_peers,
    publish_private_announce_best_effort, route_targets_for_tunnel_peers, tunnel_fingerprint,
};
use super::{
    ActiveTunnelTask, AndroidSessionSnapshot, PlannedTunnelPeer, ReconcileSession,
    ReconcileTunnelState, TunnelTaskState, ANDROID_SESSION_STATUS_WAITING,
    ANDROID_TIMER_INTERVAL_MILLIS, ANDROID_TUN_MTU,
};

pub(super) async fn reconcile_tunnel(
    app_handle: &tauri::AppHandle,
    client: &NostrSignalingClient,
    config: &AppConfig,
    session: ReconcileSession<'_>,
    presence: &mut PeerPresenceBook,
    path_book: &mut PeerPathBook,
    tunnel_state: ReconcileTunnelState<'_>,
) -> Result<()> {
    let now = unix_timestamp();
    let own_endpoint = local_signal_endpoint(config, *tunnel_state.current_listen_port);
    let planned = planned_tunnel_peers(
        config,
        session.own_pubkey,
        presence.known(),
        path_book,
        Some(&own_endpoint),
        now,
    )?;

    for peer in &planned {
        path_book.note_selected(&peer.participant, &peer.endpoint, now);
    }

    if planned.is_empty() {
        eprintln!("android-session: no planned peers; stopping tunnel");
        if let Some(tunnel) = tunnel_state.current_tunnel.take() {
            stop_tunnel_task(app_handle, tunnel).await;
        } else {
            let _ = app_handle.android_vpn().stop();
        }
        *tunnel_state.current_listen_port = config.node.listen_port;
        *tunnel_state.current_fingerprint = None;
        return Ok(());
    }

    let fingerprint = tunnel_fingerprint(config, *tunnel_state.current_listen_port, &planned);
    if tunnel_state.current_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        eprintln!("android-session: planned peers unchanged; keeping existing tunnel");
        return Ok(());
    }

    if let Some(tunnel) = tunnel_state.current_tunnel.take() {
        eprintln!("android-session: restarting tunnel for updated peer plan");
        stop_tunnel_task(app_handle, tunnel).await;
    }

    eprintln!(
        "android-session: starting tunnel for {} peer(s): {}",
        planned.len(),
        planned
            .iter()
            .map(|peer| format!(
                "{}@{} [{}]",
                peer.participant,
                peer.endpoint,
                peer.peer.allowed_ips.join(",")
            ))
            .collect::<Vec<_>>()
            .join("; "),
    );
    let tunnel = start_tunnel_task(app_handle, planned.clone(), config).await?;
    *tunnel_state.current_listen_port = tunnel.listen_port;
    *tunnel_state.current_fingerprint = Some(tunnel_fingerprint(
        config,
        *tunnel_state.current_listen_port,
        &planned,
    ));
    *tunnel_state.current_tunnel = Some(tunnel);

    publish_private_announce_best_effort(
        client,
        config,
        *tunnel_state.current_listen_port,
        session.recipients,
    )
    .await;

    Ok(())
}

pub(super) async fn start_tunnel_task(
    app_handle: &tauri::AppHandle,
    planned: Vec<PlannedTunnelPeer>,
    config: &AppConfig,
) -> Result<ActiveTunnelTask> {
    eprintln!(
        "android-session: binding udp listen socket requested_port={}",
        config.node.listen_port
    );
    let bind_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, config.node.listen_port))
        .or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))
        .context("failed to bind mobile wireguard udp socket")?;
    bind_socket
        .set_nonblocking(true)
        .context("failed to set mobile wireguard udp socket nonblocking")?;
    let listen_port = bind_socket
        .local_addr()
        .context("failed to read mobile wireguard udp socket address")?
        .port();

    let local_address = local_interface_address_for_tunnel(&config.node.tunnel_ip);
    let route_targets = route_targets_for_tunnel_peers(&planned);
    eprintln!(
        "android-session: requesting android vpn start session={} local={} routes={}",
        config.effective_network_id(),
        local_address,
        route_targets.join(","),
    );
    let vpn = app_handle
        .android_vpn()
        .start(&StartVpnArgs {
            session_name: config.effective_network_id(),
            local_addresses: vec![local_address],
            routes: route_targets,
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            mtu: ANDROID_TUN_MTU,
        })
        .map_err(|error| anyhow!("failed to start android vpn service: {error}"))?;
    eprintln!(
        "android-session: android vpn service responded active={} tun_fd={}",
        vpn.active, vpn.tun_fd,
    );

    let tun_fd = vpn.tun_fd;
    if tun_fd < 0 {
        return Err(anyhow!("android vpn service returned an invalid tun fd"));
    }
    let mut tun = open_mobile_tun_io(tun_fd).context("failed to open android tun io")?;
    let udp = tokio::net::UdpSocket::from_std(bind_socket)
        .context("failed to create async mobile wireguard udp socket")?;

    let peer_configs = planned
        .iter()
        .map(|planned| WireGuardPeerConfig {
            participant_pubkey: planned.participant.clone(),
            public_key: planned.peer.pubkey_b64.clone(),
            endpoint: planned.peer.endpoint,
            allowed_ips: planned.peer.allowed_ips.clone(),
        })
        .collect::<Vec<_>>();
    let mut runtime = MobileWireGuardRuntime::new(&config.node.private_key, peer_configs)
        .context("failed to initialize mobile wireguard runtime")?;
    eprintln!(
        "android-session: mobile wireguard runtime initialized peers={}",
        planned.len()
    );

    let state = std::sync::Arc::new(std::sync::Mutex::new(TunnelTaskState {
        peer_statuses: runtime.peer_statuses(),
        last_error: None,
    }));
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let task_state = state.clone();
    let join = tokio::spawn(async move {
        let udp = udp;
        let mut timer = tokio::time::interval(Duration::from_millis(ANDROID_TIMER_INTERVAL_MILLIS));
        let mut tun_buf = vec![0_u8; 65_535];
        let mut udp_buf = vec![0_u8; 65_535];

        if let Err(error) = send_outgoing_datagrams(&udp, runtime.initiate_handshakes()).await {
            set_tunnel_error(&task_state, error);
            return;
        }
        set_tunnel_status(&task_state, runtime.peer_statuses());

        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_ok() && *stop_rx.borrow() {
                        break;
                    }
                }
                read = tun.reader.read(&mut tun_buf) => {
                    match read {
                        Ok(0) => continue,
                        Ok(read) => {
                            match runtime.queue_tunnel_packet(&tun_buf[..read]) {
                                Ok(outgoing) => {
                                    if let Err(error) = send_outgoing_datagrams(&udp, outgoing).await {
                                        set_tunnel_error(&task_state, error);
                                        break;
                                    }
                                }
                                Err(error) => {
                                    set_tunnel_error(&task_state, error);
                                    break;
                                }
                            }
                            set_tunnel_status(&task_state, runtime.peer_statuses());
                        }
                        Err(error) => {
                            if should_retry_tun_io(&error) {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                            set_tunnel_error(&task_state, anyhow!("tun read failed: {error}"));
                            break;
                        }
                    }
                }
                recv = udp.recv_from(&mut udp_buf) => {
                    match recv {
                        Ok((read, source)) => {
                            match runtime.receive_datagram(source, &udp_buf[..read]) {
                                Ok(processed) => {
                                    if let Err(error) = write_tunnel_packets(&mut tun.writer, &processed.tunnel_packets).await {
                                        set_tunnel_error(&task_state, error);
                                        break;
                                    }
                                    if let Err(error) = send_outgoing_datagrams(&udp, processed.outgoing).await {
                                        set_tunnel_error(&task_state, error);
                                        break;
                                    }
                                }
                                Err(error) => {
                                    set_tunnel_error(&task_state, error);
                                    break;
                                }
                            }
                            set_tunnel_status(&task_state, runtime.peer_statuses());
                        }
                        Err(error) => {
                            set_tunnel_error(&task_state, anyhow!("udp recv failed: {error}"));
                            break;
                        }
                    }
                }
                _ = timer.tick() => {
                    let processed = runtime.tick_timers();
                    if let Err(error) = write_tunnel_packets(&mut tun.writer, &processed.tunnel_packets).await {
                        set_tunnel_error(&task_state, error);
                        break;
                    }
                    if let Err(error) = send_outgoing_datagrams(&udp, processed.outgoing).await {
                        set_tunnel_error(&task_state, error);
                        break;
                    }
                    set_tunnel_status(&task_state, runtime.peer_statuses());
                }
            }
        }
    });

    Ok(ActiveTunnelTask {
        listen_port,
        state,
        stop_tx,
        join,
    })
}

pub(super) async fn stop_tunnel_task(app_handle: &tauri::AppHandle, tunnel: ActiveTunnelTask) {
    eprintln!("android-session: stopping active tunnel");
    let _ = tunnel.stop_tx.send(true);
    let _ = tunnel.join.await;
    let _ = app_handle.android_vpn().stop();
}

async fn send_outgoing_datagrams(
    udp: &tokio::net::UdpSocket,
    datagrams: Vec<crate::mobile_wg::OutgoingDatagram>,
) -> Result<()> {
    for datagram in datagrams {
        udp.send_to(&datagram.payload, datagram.endpoint)
            .await
            .with_context(|| {
                format!("failed to send wireguard datagram to {}", datagram.endpoint)
            })?;
    }
    Ok(())
}

pub(super) async fn write_tunnel_packets(
    tun: &mut tokio::fs::File,
    packets: &[Vec<u8>],
) -> Result<()> {
    for packet in packets {
        tun.write_all(packet)
            .await
            .context("failed to write packet to mobile tun")?;
    }
    Ok(())
}

fn set_tunnel_status(
    state: &std::sync::Arc<std::sync::Mutex<TunnelTaskState>>,
    peer_statuses: Vec<PeerRuntimeStatus>,
) {
    if let Ok(mut guard) = state.lock() {
        guard.peer_statuses = peer_statuses;
        guard.last_error = None;
    }
}

fn set_tunnel_error(
    state: &std::sync::Arc<std::sync::Mutex<TunnelTaskState>>,
    error: anyhow::Error,
) {
    eprintln!("android-session: tunnel task error: {error:#}");
    if let Ok(mut guard) = state.lock() {
        guard.last_error = Some(error.to_string());
    }
}

pub(super) fn update_snapshot(
    snapshot: &std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    state: DaemonRuntimeState,
) {
    if let Ok(mut guard) = snapshot.lock() {
        guard.running = true;
        guard.state = Some(state);
    }
}

pub(super) fn build_runtime_state(
    config: &AppConfig,
    expected_peers: usize,
    relay_connected: bool,
    current_tunnel: Option<&ActiveTunnelTask>,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
) -> DaemonRuntimeState {
    let runtime_peer_map = current_tunnel
        .and_then(|tunnel| tunnel.state.lock().ok())
        .map(|guard| {
            guard
                .peer_statuses
                .iter()
                .map(|status| (status.participant_pubkey.clone(), status.clone()))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    build_mobile_runtime_state(
        config,
        expected_peers,
        relay_connected,
        runtime_peer_map,
        own_pubkey,
        presence,
        ANDROID_SESSION_STATUS_WAITING,
    )
}
