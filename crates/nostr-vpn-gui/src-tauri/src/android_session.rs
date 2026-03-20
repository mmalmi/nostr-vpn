use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{FromRawFd, RawFd};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::android_vpn::{AndroidVpnExt, StartVpnArgs};
use crate::mobile_wg::{MobileWireGuardRuntime, PeerRuntimeStatus, WireGuardPeerConfig};
use crate::{DaemonPeerState, DaemonRuntimeState, PEER_ONLINE_GRACE_SECS};
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, maybe_autoconfigure_node, normalize_advertised_route,
};
use nostr_vpn_core::control::{PeerAnnouncement, select_peer_endpoint};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload, SignalingNetwork};

const ANDROID_TUN_MTU: u16 = 1_280;
const ANDROID_SESSION_STATUS_WAITING: &str = "Waiting for participants";
const ANDROID_ANNOUNCE_INTERVAL_SECS: u64 = 5;
const ANDROID_PUBLISH_TIMEOUT_SECS: u64 = 3;
const ANDROID_SIGNAL_STALE_AFTER_SECS: u64 = 45;
const ANDROID_TIMER_INTERVAL_MILLIS: u64 = 250;

#[derive(Default)]
struct AndroidSessionSnapshot {
    running: bool,
    state: Option<DaemonRuntimeState>,
}

pub(crate) struct AndroidSessionManager {
    app: tauri::AppHandle,
    runtime_handle: Handle,
    snapshot: std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    stop_tx: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
}

struct ActiveTunnelTask {
    listen_port: u16,
    state: std::sync::Arc<std::sync::Mutex<TunnelTaskState>>,
    stop_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

#[derive(Default)]
struct TunnelTaskState {
    peer_statuses: Vec<PeerRuntimeStatus>,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct TunnelPeer {
    participant: String,
    pubkey_b64: String,
    endpoint: SocketAddr,
    allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedTunnelPeer {
    participant: String,
    endpoint: String,
    peer: TunnelPeer,
}

impl AndroidSessionManager {
    pub(crate) fn new(app: tauri::AppHandle, runtime_handle: Handle) -> Self {
        Self {
            app,
            runtime_handle,
            snapshot: std::sync::Arc::new(std::sync::Mutex::new(AndroidSessionSnapshot::default())),
            stop_tx: None,
            task: None,
        }
    }

    pub(crate) fn start(&mut self, config: AppConfig) -> Result<()> {
        self.stop()?;
        eprintln!(
            "android-session: start requested network_id={} participants={} endpoint={} tunnel_ip={}",
            config.effective_network_id(),
            config.participant_pubkeys_hex().len(),
            config.node.endpoint,
            config.node.tunnel_ip,
        );
        self.app
            .android_vpn()
            .prepare()
            .map_err(|error| anyhow!("failed to prepare android vpn permission: {error}"))?;

        let (stop_tx, stop_rx) = watch::channel(false);
        let snapshot = self.snapshot.clone();
        let app = self.app.clone();

        self.store_snapshot(
            true,
            Some(DaemonRuntimeState {
                session_active: true,
                relay_connected: false,
                session_status: "Connecting…".to_string(),
                ..DaemonRuntimeState::default()
            }),
        );

        let join = self.runtime_handle.spawn(async move {
            if let Err(error) = run_android_session(app, config, snapshot.clone(), stop_rx).await {
                eprintln!("android-session: run failed: {error:#}");
                if let Ok(mut guard) = snapshot.lock() {
                    guard.running = false;
                    guard.state = Some(DaemonRuntimeState {
                        session_active: false,
                        relay_connected: false,
                        session_status: format!("Android session failed: {error}"),
                        ..DaemonRuntimeState::default()
                    });
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(join);
        Ok(())
    }

    pub(crate) fn reload(&mut self, config: AppConfig) -> Result<()> {
        self.start(config)
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = self.runtime_handle.block_on(task);
        }

        self.store_snapshot(
            false,
            Some(DaemonRuntimeState {
                session_active: false,
                relay_connected: false,
                session_status: "Disconnected".to_string(),
                ..DaemonRuntimeState::default()
            }),
        );
        Ok(())
    }

    pub(crate) fn status(&self) -> (bool, Option<DaemonRuntimeState>) {
        self.snapshot
            .lock()
            .map(|snapshot| (snapshot.running, snapshot.state.clone()))
            .unwrap_or((false, None))
    }

    fn store_snapshot(&self, running: bool, state: Option<DaemonRuntimeState>) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            snapshot.running = running;
            snapshot.state = state;
        }
    }
}

async fn run_android_session(
    app_handle: tauri::AppHandle,
    mut config: AppConfig,
    snapshot: std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);

    let expected_peers = expected_peer_count(&config);
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let relays = resolve_relays(&config);
    let recipients = configured_recipients(&config, own_pubkey.as_deref());
    eprintln!(
        "android-session: run starting network_id={} expected_peers={} recipients={} relays={}",
        config.effective_network_id(),
        expected_peers,
        recipients.len(),
        relays.len(),
    );

    let client = NostrSignalingClient::from_secret_key_with_networks(
        &config.nostr.secret_key,
        signaling_networks_for_app(&config),
    )?;
    eprintln!("android-session: connecting signaling client");
    client
        .connect(&relays)
        .await
        .context("failed to connect signaling client")?;
    eprintln!("android-session: signaling client connected");

    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut current_tunnel: Option<ActiveTunnelTask> = None;
    let mut current_listen_port = config.node.listen_port;
    let mut current_fingerprint: Option<String> = None;

    eprintln!(
        "android-session: publishing private announce to {} recipients on port {}",
        recipients.len(),
        current_listen_port,
    );
    publish_hello_best_effort(&client).await;
    publish_private_announce_best_effort(&client, &config, current_listen_port, &recipients).await;
    update_snapshot(
        &snapshot,
        build_runtime_state(
            &config,
            expected_peers,
            true,
            current_tunnel.as_ref(),
            own_pubkey.as_deref(),
            &presence,
        ),
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(ANDROID_ANNOUNCE_INTERVAL_SECS));
    let mut status_interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    break;
                }
            }
            envelope = client.recv() => {
                let Some(envelope) = envelope else {
                    return Err(anyhow!("signaling client closed"));
                };
                let sender_pubkey = envelope.sender_pubkey.clone();
                let payload_kind = signal_payload_kind(&envelope.payload);
                eprintln!(
                    "android-session: received {payload_kind} from {}",
                    sender_pubkey,
                );
                presence.apply_signal(
                    envelope.sender_pubkey,
                    envelope.payload,
                    unix_timestamp(),
                );
                reconcile_tunnel(
                    &app_handle,
                    &client,
                    &config,
                    own_pubkey.as_deref(),
                    &recipients,
                    &mut presence,
                    &mut path_book,
                    &mut current_tunnel,
                    &mut current_listen_port,
                    &mut current_fingerprint,
                )
                .await?;
                update_snapshot(
                    &snapshot,
                    build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_tunnel.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    ),
                );
            }
            _ = announce_interval.tick() => {
                publish_hello_best_effort(&client).await;
                publish_private_announce_best_effort(&client, &config, current_listen_port, &recipients).await;
            }
            _ = status_interval.tick() => {
                let now = unix_timestamp();
                presence.prune_stale(now, ANDROID_SIGNAL_STALE_AFTER_SECS);
                note_successful_runtime_paths(current_tunnel.as_ref(), &presence, &mut path_book, now);
                update_snapshot(
                    &snapshot,
                    build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_tunnel.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    ),
                );
            }
        }
    }

    let disconnect = SignalPayload::Disconnect {
        node_id: config.node.id.clone(),
    };
    let _ = client.publish_to(disconnect, &recipients).await;
    client.disconnect().await;

    if let Some(tunnel) = current_tunnel.take() {
        stop_tunnel_task(&app_handle, tunnel).await;
    } else {
        let _ = app_handle.android_vpn().stop();
    }

    update_snapshot(
        &snapshot,
        DaemonRuntimeState {
            session_active: false,
            relay_connected: false,
            session_status: "Disconnected".to_string(),
            ..DaemonRuntimeState::default()
        },
    );

    Ok(())
}

async fn reconcile_tunnel(
    app_handle: &tauri::AppHandle,
    client: &NostrSignalingClient,
    config: &AppConfig,
    own_pubkey: Option<&str>,
    recipients: &[String],
    presence: &mut PeerPresenceBook,
    path_book: &mut PeerPathBook,
    current_tunnel: &mut Option<ActiveTunnelTask>,
    current_listen_port: &mut u16,
    current_fingerprint: &mut Option<String>,
) -> Result<()> {
    let now = unix_timestamp();
    let own_endpoint = local_signal_endpoint(config, *current_listen_port);
    let planned = planned_tunnel_peers(
        config,
        own_pubkey,
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
        if let Some(tunnel) = current_tunnel.take() {
            stop_tunnel_task(app_handle, tunnel).await;
        } else {
            let _ = app_handle.android_vpn().stop();
        }
        *current_listen_port = config.node.listen_port;
        *current_fingerprint = None;
        return Ok(());
    }

    let fingerprint = tunnel_fingerprint(config, *current_listen_port, &planned);
    if current_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        eprintln!("android-session: planned peers unchanged; keeping existing tunnel");
        return Ok(());
    }

    if let Some(tunnel) = current_tunnel.take() {
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
    *current_listen_port = tunnel.listen_port;
    *current_fingerprint = Some(tunnel_fingerprint(config, *current_listen_port, &planned));
    *current_tunnel = Some(tunnel);

    publish_private_announce_best_effort(client, config, *current_listen_port, recipients).await;

    Ok(())
}

async fn start_tunnel_task(
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
    configure_tun_fd(tun_fd).context("failed to configure android tun fd")?;

    let std_file = unsafe { std::fs::File::from_raw_fd(tun_fd) };
    let tun = tokio::fs::File::from_std(std_file);
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
        let mut tun = tun;
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
                read = tun.read(&mut tun_buf) => {
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
                                    if let Err(error) = write_tunnel_packets(&mut tun, &processed.tunnel_packets).await {
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
                    if let Err(error) = write_tunnel_packets(&mut tun, &processed.tunnel_packets).await {
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

async fn stop_tunnel_task(app_handle: &tauri::AppHandle, tunnel: ActiveTunnelTask) {
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

async fn write_tunnel_packets(tun: &mut tokio::fs::File, packets: &[Vec<u8>]) -> Result<()> {
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

fn update_snapshot(
    snapshot: &std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    state: DaemonRuntimeState,
) {
    if let Ok(mut guard) = snapshot.lock() {
        guard.running = true;
        guard.state = Some(state);
    }
}

fn build_runtime_state(
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

    let peers = config
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| {
            let announcement = presence.announcement_for(&participant)?;
            let runtime_status = runtime_peer_map.get(&participant);
            let last_handshake_at = runtime_status.and_then(|status| {
                status
                    .last_handshake_age
                    .and_then(|age| unix_timestamp().checked_sub(age.as_secs()))
            });
            let reachable = runtime_status
                .and_then(|status| status.last_handshake_age)
                .is_some_and(|age| age <= Duration::from_secs(PEER_ONLINE_GRACE_SECS));
            Some(DaemonPeerState {
                participant_pubkey: participant,
                node_id: announcement.node_id.clone(),
                tunnel_ip: announcement.tunnel_ip.clone(),
                endpoint: runtime_status
                    .map(|status| status.endpoint.to_string())
                    .unwrap_or_else(|| announcement.endpoint.clone()),
                public_key: announcement.public_key.clone(),
                advertised_routes: announcement.advertised_routes.clone(),
                presence_timestamp: announcement.timestamp,
                last_signal_seen_at: presence.last_seen_at(&announcement.node_id),
                reachable,
                last_handshake_at,
                error: if reachable {
                    None
                } else if runtime_status.is_some() {
                    Some("awaiting handshake".to_string())
                } else {
                    Some("no signal yet".to_string())
                },
            })
        })
        .collect::<Vec<_>>();

    let connected_peer_count = peers.iter().filter(|peer| peer.reachable).count();
    let mesh_ready = expected_peers > 0 && connected_peer_count >= expected_peers;

    DaemonRuntimeState {
        updated_at: unix_timestamp(),
        session_active: true,
        relay_connected,
        session_status: if expected_peers == 0 {
            ANDROID_SESSION_STATUS_WAITING.to_string()
        } else if mesh_ready {
            "Connected".to_string()
        } else {
            format!("Connecting mesh ({connected_peer_count}/{expected_peers})")
        },
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        health: Vec::new(),
        network: Default::default(),
        port_mapping: Default::default(),
        peers,
    }
}

fn signaling_networks_for_app(app: &AppConfig) -> Vec<SignalingNetwork> {
    let networks = app
        .enabled_network_meshes()
        .into_iter()
        .map(|network| SignalingNetwork {
            network_id: network.network_id,
            participants: network.participants,
        })
        .collect::<Vec<_>>();

    if networks.is_empty() {
        return vec![SignalingNetwork {
            network_id: app.effective_network_id(),
            participants: app.participant_pubkeys_hex(),
        }];
    }

    networks
}

fn expected_peer_count(config: &AppConfig) -> usize {
    let participants = config.participant_pubkeys_hex();
    if participants.is_empty() {
        return 0;
    }

    let mut expected = participants.len();
    if let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && participants
            .iter()
            .any(|participant| participant == &own_pubkey)
    {
        expected = expected.saturating_sub(1);
    }

    expected
}

fn resolve_relays(config: &AppConfig) -> Vec<String> {
    if !config.nostr.relays.is_empty() {
        return config.nostr.relays.clone();
    }

    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

fn configured_recipients(config: &AppConfig, own_pubkey: Option<&str>) -> Vec<String> {
    config
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .collect()
}

async fn publish_private_announce_to_all(
    client: &NostrSignalingClient,
    config: &AppConfig,
    listen_port: u16,
    recipients: &[String],
) -> Result<()> {
    if recipients.is_empty() {
        return Ok(());
    }

    client
        .publish_to(
            SignalPayload::Announce(build_peer_announcement(config, listen_port)),
            recipients,
        )
        .await
        .context("failed to publish mobile private announce")?;
    Ok(())
}

async fn publish_private_announce_best_effort(
    client: &NostrSignalingClient,
    config: &AppConfig,
    listen_port: u16,
    recipients: &[String],
) {
    match tokio::time::timeout(
        Duration::from_secs(ANDROID_PUBLISH_TIMEOUT_SECS),
        publish_private_announce_to_all(client, config, listen_port, recipients),
    )
    .await
    {
        Ok(Ok(())) => eprintln!(
            "android-session: private announce published to {} recipient(s)",
            recipients.len()
        ),
        Ok(Err(error)) => eprintln!("android-session: private announce failed: {error:#}"),
        Err(_) => eprintln!(
            "android-session: private announce timed out after {}s",
            ANDROID_PUBLISH_TIMEOUT_SECS
        ),
    }
}

async fn publish_hello_best_effort(client: &NostrSignalingClient) {
    match tokio::time::timeout(
        Duration::from_secs(ANDROID_PUBLISH_TIMEOUT_SECS),
        client.publish(SignalPayload::Hello),
    )
    .await
    {
        Ok(Ok(())) => eprintln!("android-session: hello published"),
        Ok(Err(error)) => eprintln!("android-session: hello publish failed: {error:#}"),
        Err(_) => eprintln!(
            "android-session: hello publish timed out after {}s",
            ANDROID_PUBLISH_TIMEOUT_SECS
        ),
    }
}

fn build_peer_announcement(config: &AppConfig, listen_port: u16) -> PeerAnnouncement {
    let endpoint = local_signal_endpoint(config, listen_port);
    PeerAnnouncement {
        node_id: config.node.id.clone(),
        public_key: config.node.public_key.clone(),
        endpoint: endpoint.clone(),
        local_endpoint: Some(endpoint),
        public_endpoint: None,
        tunnel_ip: config.node.tunnel_ip.clone(),
        advertised_routes: config.effective_advertised_routes(),
        timestamp: unix_timestamp(),
    }
}

fn planned_tunnel_peers(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    own_local_endpoint: Option<&str>,
    now: u64,
) -> Result<Vec<PlannedTunnelPeer>> {
    let configured_participants = config.participant_pubkeys_hex();
    let route_assignments = advertised_route_assignments(config, own_pubkey, peer_announcements);
    let configured_set = configured_participants
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .cloned()
        .collect::<HashSet<_>>();
    path_book.retain_participants(&configured_set);

    let mut peers = Vec::new();
    for participant in configured_participants
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
    {
        let Some(announcement) = peer_announcements.get(participant) else {
            continue;
        };
        path_book.refresh_from_announcement(participant.clone(), announcement, now);
        let selected_endpoint = path_book
            .select_endpoint(
                participant,
                announcement,
                own_local_endpoint,
                now,
                ANDROID_SIGNAL_STALE_AFTER_SECS,
            )
            .unwrap_or_else(|| select_peer_endpoint(announcement, own_local_endpoint));
        let endpoint: SocketAddr = selected_endpoint
            .parse()
            .with_context(|| format!("invalid peer endpoint {}", selected_endpoint))?;

        let mut allowed_ips = vec![format!("{}/32", strip_cidr(&announcement.tunnel_ip))];
        for route in route_assignments
            .get(participant)
            .into_iter()
            .flatten()
            .cloned()
        {
            if !allowed_ips.iter().any(|existing| existing == &route) {
                allowed_ips.push(route);
            }
        }

        peers.push(PlannedTunnelPeer {
            participant: participant.clone(),
            endpoint: selected_endpoint,
            peer: TunnelPeer {
                participant: participant.clone(),
                pubkey_b64: announcement.public_key.clone(),
                endpoint,
                allowed_ips,
            },
        });
    }

    peers.sort_by(|left, right| left.participant.cmp(&right.participant));
    Ok(peers)
}

fn advertised_route_assignments(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> HashMap<String, Vec<String>> {
    let selected_exit_node = selected_exit_node_participant(config, own_pubkey, peer_announcements);
    let mut route_owner = HashMap::<String, String>::new();

    for participant in config
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
    {
        let Some(announcement) = peer_announcements.get(participant) else {
            continue;
        };

        for route in normalized_peer_ipv4_routes(announcement) {
            if is_exit_node_route(&route)
                && selected_exit_node.as_deref() != Some(participant.as_str())
            {
                continue;
            }
            route_owner
                .entry(route)
                .or_insert_with(|| participant.clone());
        }
    }

    let mut assignments = HashMap::<String, Vec<String>>::new();
    for (route, participant) in route_owner {
        assignments.entry(participant).or_default().push(route);
    }

    for routes in assignments.values_mut() {
        routes.sort();
        routes.dedup();
    }

    assignments
}

fn normalized_peer_ipv4_routes(announcement: &PeerAnnouncement) -> Vec<String> {
    let mut routes = Vec::new();
    let mut seen = HashSet::new();

    for route in &announcement.advertised_routes {
        let Some(route) = normalize_advertised_route(route) else {
            continue;
        };
        if strip_cidr(&route).parse::<Ipv4Addr>().is_err() {
            continue;
        }
        if seen.insert(route.clone()) {
            routes.push(route);
        }
    }

    routes
}

fn selected_exit_node_participant(
    config: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> Option<String> {
    if config.exit_node.is_empty() || Some(config.exit_node.as_str()) == own_pubkey {
        return None;
    }

    let announcement = peer_announcements.get(&config.exit_node)?;
    normalized_peer_ipv4_routes(announcement)
        .iter()
        .any(|route| route == "0.0.0.0/0")
        .then(|| config.exit_node.clone())
}

fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

fn route_targets_for_tunnel_peers(peers: &[PlannedTunnelPeer]) -> Vec<String> {
    let mut route_targets = peers
        .iter()
        .flat_map(|peer| peer.peer.allowed_ips.iter().cloned())
        .collect::<Vec<_>>();
    route_targets.sort();
    route_targets.dedup();
    route_targets
}

fn tunnel_fingerprint(config: &AppConfig, listen_port: u16, peers: &[PlannedTunnelPeer]) -> String {
    let local_address = local_interface_address_for_tunnel(&config.node.tunnel_ip);
    let mut peer_entries = peers
        .iter()
        .map(|peer| {
            format!(
                "{}|{}|{}",
                peer.peer.participant,
                peer.peer.endpoint,
                peer.peer.allowed_ips.join(",")
            )
        })
        .collect::<Vec<_>>();
    peer_entries.sort();

    format!(
        "{}|{}|{}|{}|{}",
        config.node.private_key,
        config.node.tunnel_ip,
        listen_port,
        local_address,
        peer_entries.join(";")
    )
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn local_signal_endpoint(config: &AppConfig, listen_port: u16) -> String {
    runtime_local_signal_endpoint(&config.node.endpoint, listen_port)
}

fn runtime_local_signal_endpoint(endpoint: &str, listen_port: u16) -> String {
    let value = endpoint.trim();
    if value.is_empty() || matches!(value, "127.0.0.1:51820" | "127.0.0.1" | "0.0.0.0") {
        if let Some(ip) = detect_runtime_primary_ipv4() {
            return format!("{ip}:{listen_port}");
        }
    }

    endpoint
        .parse::<SocketAddr>()
        .map(|mut parsed| {
            parsed.set_port(listen_port);
            parsed.to_string()
        })
        .unwrap_or_else(|_| endpoint.to_string())
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn note_successful_runtime_paths(
    current_tunnel: Option<&ActiveTunnelTask>,
    presence: &PeerPresenceBook,
    path_book: &mut PeerPathBook,
    now: u64,
) {
    let Some(current_tunnel) = current_tunnel else {
        return;
    };
    let Ok(state) = current_tunnel.state.lock() else {
        return;
    };

    for status in &state.peer_statuses {
        let Some(handshake_age) = status.last_handshake_age else {
            continue;
        };
        if handshake_age > Duration::from_secs(PEER_ONLINE_GRACE_SECS) {
            continue;
        }
        let success_at = now.saturating_sub(handshake_age.as_secs());
        path_book.note_success(
            status.participant_pubkey.clone(),
            &status.endpoint.to_string(),
            success_at,
        );
        let _ = presence.announcement_for(&status.participant_pubkey);
    }
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn configure_tun_fd(tun_fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(tun_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(anyhow!(
            "failed to read tun fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    if flags & libc::O_NONBLOCK == 0 {
        return Ok(());
    }

    let updated_flags = flags & !libc::O_NONBLOCK;
    let result = unsafe { libc::fcntl(tun_fd, libc::F_SETFL, updated_flags) };
    if result < 0 {
        return Err(anyhow!(
            "failed to clear O_NONBLOCK on tun fd: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn should_retry_tun_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

fn signal_payload_kind(payload: &SignalPayload) -> &'static str {
    match payload {
        SignalPayload::Hello => "hello",
        SignalPayload::Announce(_) => "announce",
        SignalPayload::Disconnect { .. } => "disconnect",
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{planned_tunnel_peers, runtime_local_signal_endpoint};
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::config::AppConfig;
    use nostr_vpn_core::control::PeerAnnouncement;
    use nostr_vpn_core::paths::PeerPathBook;
    use std::collections::HashMap;

    fn participant() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn peer_announcement(endpoint: &str, tunnel_ip: &str, routes: &[&str]) -> PeerAnnouncement {
        PeerAnnouncement {
            node_id: format!("node-{endpoint}"),
            public_key: "dummy-public-key".to_string(),
            endpoint: endpoint.to_string(),
            local_endpoint: None,
            public_endpoint: Some(endpoint.to_string()),
            tunnel_ip: tunnel_ip.to_string(),
            advertised_routes: routes.iter().map(|route| (*route).to_string()).collect(),
            timestamp: 1,
        }
    }

    #[test]
    fn planned_tunnel_peers_assign_selected_exit_node_default_route() {
        let mut config = AppConfig::generated();
        let exit_participant = participant();
        let routed_participant = participant();
        config.networks[0].participants =
            vec![exit_participant.clone(), routed_participant.clone()];
        config.exit_node = exit_participant.clone();
        config.ensure_defaults();

        let announcements = HashMap::from([
            (
                exit_participant.clone(),
                peer_announcement(
                    "203.0.113.20:51820",
                    "10.44.0.2/32",
                    &["10.60.0.0/24", "0.0.0.0/0", "::/0"],
                ),
            ),
            (
                routed_participant.clone(),
                peer_announcement("203.0.113.21:51820", "10.44.0.3/32", &["10.70.0.0/24"]),
            ),
        ]);

        let planned = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("192.0.2.10:51820"),
            10,
        )
        .expect("planned tunnel peers");

        let exit_peer = planned
            .iter()
            .find(|planned| planned.participant == exit_participant)
            .expect("exit peer");
        assert_eq!(
            exit_peer.peer.allowed_ips,
            vec![
                "10.44.0.2/32".to_string(),
                "0.0.0.0/0".to_string(),
                "10.60.0.0/24".to_string(),
            ]
        );

        let routed_peer = planned
            .iter()
            .find(|planned| planned.participant == routed_participant)
            .expect("routed peer");
        assert_eq!(
            routed_peer.peer.allowed_ips,
            vec!["10.44.0.3/32".to_string(), "10.70.0.0/24".to_string()]
        );
    }

    #[test]
    fn planned_tunnel_peers_ignore_default_route_without_selected_exit_node() {
        let mut config = AppConfig::generated();
        let exit_participant = participant();
        config.networks[0].participants = vec![exit_participant.clone()];
        config.ensure_defaults();

        let announcements = HashMap::from([(
            exit_participant,
            peer_announcement(
                "203.0.113.20:51820",
                "10.44.0.2/32",
                &["0.0.0.0/0", "10.60.0.0/24"],
            ),
        )]);

        let planned = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("192.0.2.10:51820"),
            10,
        )
        .expect("planned tunnel peers");

        assert_eq!(
            planned[0].peer.allowed_ips,
            vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
        );
    }

    #[test]
    fn runtime_local_signal_endpoint_preserves_non_loopback_host_with_new_port() {
        assert_eq!(
            runtime_local_signal_endpoint("198.51.100.10:6000", 51820),
            "198.51.100.10:51820"
        );
    }

    #[test]
    fn tun_io_retries_would_block_and_interrupted() {
        assert!(super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(!super::should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        )));
    }
}
