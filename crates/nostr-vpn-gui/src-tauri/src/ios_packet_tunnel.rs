use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::raw::c_uchar;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::{AppConfig, maybe_autoconfigure_node};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload};
use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use self::ios_tunnel_planning::{
    configured_recipients, expected_peer_count, local_interface_address_for_tunnel,
    local_signal_endpoint, note_successful_runtime_paths, planned_tunnel_peers,
    publish_hello_best_effort, publish_private_announce_best_effort, resolve_relays,
    route_targets_for_tunnel_peers, signaling_networks_for_app, tunnel_fingerprint, unix_timestamp,
};
use crate::DaemonRuntimeState;
use crate::mobile_runtime_state::build_mobile_runtime_state;
use crate::mobile_wg::{MobileWireGuardRuntime, WireGuardPeerConfig};

mod ios_tunnel_planning;

const IOS_ANNOUNCE_INTERVAL_SECS: u64 = 5;
const IOS_PUBLISH_TIMEOUT_SECS: u64 = 3;
const IOS_SIGNAL_STALE_AFTER_SECS: u64 = 45;
const IOS_TIMER_INTERVAL_MILLIS: u64 = 250;
const IOS_SESSION_STATUS_WAITING: &str = "Waiting for participants";
const IOS_TUN_MTU: u16 = 1_280;

type SettingsCallback = extern "C" fn(*const c_char, usize);
type PacketCallback = extern "C" fn(*const c_uchar, usize, usize);

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelStatusSnapshot {
    active: bool,
    error: Option<String>,
    state_json: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkSettingsPayload {
    local_addresses: Vec<String>,
    routes: Vec<String>,
    dns_servers: Vec<String>,
    search_domains: Vec<String>,
    mtu: u16,
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

#[derive(Clone, Copy)]
struct IosTunnelCallbacks {
    context: usize,
    settings_callback: SettingsCallback,
    packet_callback: PacketCallback,
}

struct IosTunnelHandle {
    runtime: tokio::runtime::Runtime,
    stop_tx: watch::Sender<bool>,
    packet_tx: mpsc::UnboundedSender<Vec<u8>>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct IosTunnelController {
    active: Option<IosTunnelHandle>,
    snapshot: Arc<Mutex<TunnelStatusSnapshot>>,
}

struct ReconcileContext<'a> {
    own_pubkey: Option<&'a str>,
    recipients: &'a [String],
    listen_port: u16,
}

static TUNNEL_CONTROLLER: OnceLock<Mutex<IosTunnelController>> = OnceLock::new();

fn controller() -> &'static Mutex<IosTunnelController> {
    TUNNEL_CONTROLLER.get_or_init(|| Mutex::new(IosTunnelController::default()))
}

impl IosTunnelCallbacks {
    fn update_settings(&self, payload: &NetworkSettingsPayload) -> Result<()> {
        let json =
            serde_json::to_string(payload).context("failed to serialize network settings")?;
        let json = CString::new(json).context("network settings payload contained nul")?;
        (self.settings_callback)(json.as_ptr(), self.context);
        Ok(())
    }

    fn write_tunnel_packets(&self, packets: &[Vec<u8>]) {
        for packet in packets {
            (self.packet_callback)(packet.as_ptr(), packet.len(), self.context);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nvpn_ios_extension_start(
    config_json: *const c_char,
    context: usize,
    settings_callback: SettingsCallback,
    packet_callback: PacketCallback,
) -> bool {
    let result = start_tunnel(
        config_json,
        IosTunnelCallbacks {
            context,
            settings_callback,
            packet_callback,
        },
    );

    if let Err(error) = result {
        set_snapshot(
            false,
            Some(format!("failed to start iOS packet tunnel: {error}")),
            None,
        );
        eprintln!("ios-packet-tunnel: start failed: {error:#}");
        return false;
    }

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn nvpn_ios_extension_push_packet(packet: *const c_uchar, length: usize) {
    if packet.is_null() || length == 0 {
        return;
    }

    let bytes = unsafe { std::slice::from_raw_parts(packet, length) }.to_vec();

    let Ok(guard) = controller().lock() else {
        return;
    };
    let Some(handle) = guard.active.as_ref() else {
        return;
    };
    let _ = handle.packet_tx.send(bytes);
}

#[unsafe(no_mangle)]
pub extern "C" fn nvpn_ios_extension_stop() {
    let handle = {
        let Ok(mut guard) = controller().lock() else {
            return;
        };
        guard.active.take()
    };

    if let Some(handle) = handle {
        let _ = handle.stop_tx.send(true);
        let _ = handle.runtime.block_on(handle.task);
    }

    set_snapshot(
        false,
        None,
        Some(DaemonRuntimeState {
            session_active: false,
            relay_connected: false,
            session_status: "Disconnected".to_string(),
            ..DaemonRuntimeState::default()
        }),
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn nvpn_ios_extension_status_json() -> *mut c_char {
    let snapshot = controller()
        .lock()
        .ok()
        .and_then(|guard| guard.snapshot.lock().ok().map(|snapshot| snapshot.clone()))
        .unwrap_or_default();

    CString::new(serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string()))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn nvpn_ios_extension_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(value);
    }
}

fn start_tunnel(config_json: *const c_char, callbacks: IosTunnelCallbacks) -> Result<()> {
    let config_json = unsafe {
        if config_json.is_null() {
            return Err(anyhow!("missing config JSON"));
        }
        CStr::from_ptr(config_json)
            .to_str()
            .context("config JSON was not valid UTF-8")?
            .to_string()
    };

    let mut config = serde_json::from_str::<AppConfig>(&config_json)
        .context("failed to parse iOS packet tunnel config")?;
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);

    nvpn_ios_extension_stop();

    let snapshot = Arc::new(Mutex::new(TunnelStatusSnapshot::default()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build iOS packet tunnel runtime")?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (packet_tx, packet_rx) = mpsc::unbounded_channel();

    set_snapshot(
        true,
        None,
        Some(DaemonRuntimeState {
            session_active: true,
            relay_connected: false,
            session_status: "Connecting…".to_string(),
            ..DaemonRuntimeState::default()
        }),
    );

    let snapshot_for_task = snapshot.clone();
    let task = runtime.spawn(async move {
        if let Err(error) = run_ios_packet_tunnel(
            config,
            snapshot_for_task.clone(),
            stop_rx,
            packet_rx,
            callbacks,
        )
        .await
        {
            eprintln!("ios-packet-tunnel: runtime failed: {error:#}");
            set_snapshot(
                false,
                Some(format!("Packet tunnel failed: {error}")),
                Some(DaemonRuntimeState {
                    session_active: false,
                    relay_connected: false,
                    session_status: format!("Packet tunnel failed: {error}"),
                    ..DaemonRuntimeState::default()
                }),
            );
        }
    });

    let mut guard = controller()
        .lock()
        .map_err(|_| anyhow!("packet tunnel controller lock poisoned"))?;
    guard.snapshot = snapshot.clone();
    guard.active = Some(IosTunnelHandle {
        runtime,
        stop_tx,
        packet_tx,
        task,
    });

    Ok(())
}

async fn run_ios_packet_tunnel(
    config: AppConfig,
    snapshot: Arc<Mutex<TunnelStatusSnapshot>>,
    mut stop_rx: watch::Receiver<bool>,
    mut packet_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    callbacks: IosTunnelCallbacks,
) -> Result<()> {
    let expected_peers = expected_peer_count(&config);
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let relays = resolve_relays(&config);
    let recipients = configured_recipients(&config, own_pubkey.as_deref());

    callbacks.update_settings(&NetworkSettingsPayload {
        local_addresses: vec![local_interface_address_for_tunnel(&config.node.tunnel_ip)],
        routes: Vec::new(),
        dns_servers: Vec::new(),
        search_domains: Vec::new(),
        mtu: IOS_TUN_MTU,
    })?;

    let bind_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, config.node.listen_port))
        .or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))
        .context("failed to bind iOS WireGuard UDP socket")?;
    bind_socket
        .set_nonblocking(true)
        .context("failed to set iOS WireGuard UDP socket nonblocking")?;
    let listen_port = bind_socket
        .local_addr()
        .context("failed to read iOS WireGuard UDP socket address")?
        .port();
    let udp = tokio::net::UdpSocket::from_std(bind_socket)
        .context("failed to create async UDP socket")?;

    let client = NostrSignalingClient::from_secret_key_with_networks(
        &config.nostr.secret_key,
        signaling_networks_for_app(&config),
    )?;
    client
        .connect(&relays)
        .await
        .context("failed to connect signaling client")?;

    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut current_runtime: Option<MobileWireGuardRuntime> = None;
    let mut current_fingerprint: Option<String> = None;
    let mut current_route_targets = Vec::<String>::new();

    publish_hello_best_effort(&client).await;
    publish_private_announce_best_effort(&client, &config, listen_port, &recipients).await;
    update_snapshot(
        &snapshot,
        true,
        None,
        Some(build_runtime_state(
            &config,
            expected_peers,
            true,
            current_runtime.as_ref(),
            own_pubkey.as_deref(),
            &presence,
        )),
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(IOS_ANNOUNCE_INTERVAL_SECS));
    let mut status_interval = tokio::time::interval(Duration::from_secs(1));
    let mut wireguard_timer =
        tokio::time::interval(Duration::from_millis(IOS_TIMER_INTERVAL_MILLIS));
    let mut udp_buf = vec![0_u8; 65_535];

    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    break;
                }
            }
            packet = packet_rx.recv() => {
                let Some(packet) = packet else {
                    break;
                };
                if let Some(runtime) = current_runtime.as_mut() {
                    let outgoing = runtime
                        .queue_tunnel_packet(&packet)
                        .context("failed to queue tunnel packet")?;
                    send_outgoing_datagrams(&udp, outgoing).await?;
                    update_snapshot(
                        &snapshot,
                        true,
                        None,
                        Some(build_runtime_state(
                            &config,
                            expected_peers,
                            true,
                            current_runtime.as_ref(),
                            own_pubkey.as_deref(),
                            &presence,
                        )),
                    );
                }
            }
            envelope = client.recv() => {
                let Some(envelope) = envelope else {
                    return Err(anyhow!("signaling client closed"));
                };
                presence.apply_signal(
                    envelope.sender_pubkey,
                    envelope.payload,
                    unix_timestamp(),
                );
                reconcile_runtime(
                    &udp,
                    &client,
                    &config,
                    ReconcileContext {
                        own_pubkey: own_pubkey.as_deref(),
                        recipients: &recipients,
                        listen_port,
                    },
                    &mut presence,
                    &mut path_book,
                    &mut current_runtime,
                    &mut current_fingerprint,
                    &mut current_route_targets,
                    callbacks,
                )
                .await?;
                update_snapshot(
                    &snapshot,
                    true,
                    None,
                    Some(build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_runtime.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    )),
                );
            }
            recv = udp.recv_from(&mut udp_buf) => {
                let (read, source) = recv.context("failed to receive UDP datagram")?;
                if let Some(runtime) = current_runtime.as_mut() {
                    let processed = runtime
                        .receive_datagram(source, &udp_buf[..read])
                        .context("failed to process WireGuard datagram")?;
                    callbacks.write_tunnel_packets(&processed.tunnel_packets);
                    send_outgoing_datagrams(&udp, processed.outgoing).await?;
                    update_snapshot(
                        &snapshot,
                        true,
                        None,
                        Some(build_runtime_state(
                            &config,
                            expected_peers,
                            true,
                            current_runtime.as_ref(),
                            own_pubkey.as_deref(),
                            &presence,
                        )),
                    );
                }
            }
            _ = wireguard_timer.tick() => {
                if let Some(runtime) = current_runtime.as_mut() {
                    let processed = runtime.tick_timers();
                    callbacks.write_tunnel_packets(&processed.tunnel_packets);
                    send_outgoing_datagrams(&udp, processed.outgoing).await?;
                    update_snapshot(
                        &snapshot,
                        true,
                        None,
                        Some(build_runtime_state(
                            &config,
                            expected_peers,
                            true,
                            current_runtime.as_ref(),
                            own_pubkey.as_deref(),
                            &presence,
                        )),
                    );
                }
            }
            _ = announce_interval.tick() => {
                publish_hello_best_effort(&client).await;
                publish_private_announce_best_effort(&client, &config, listen_port, &recipients).await;
            }
            _ = status_interval.tick() => {
                let now = unix_timestamp();
                presence.prune_stale(now, IOS_SIGNAL_STALE_AFTER_SECS);
                note_successful_runtime_paths(current_runtime.as_ref(), &mut path_book, now);
                update_snapshot(
                    &snapshot,
                    true,
                    None,
                    Some(build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_runtime.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    )),
                );
            }
        }
    }

    let _ = client
        .publish_to(
            SignalPayload::Disconnect {
                node_id: config.node.id.clone(),
            },
            &recipients,
        )
        .await;
    client.disconnect().await;

    update_snapshot(
        &snapshot,
        false,
        None,
        Some(DaemonRuntimeState {
            session_active: false,
            relay_connected: false,
            session_status: "Disconnected".to_string(),
            ..DaemonRuntimeState::default()
        }),
    );

    Ok(())
}

async fn reconcile_runtime(
    udp: &tokio::net::UdpSocket,
    client: &NostrSignalingClient,
    config: &AppConfig,
    context: ReconcileContext<'_>,
    presence: &mut PeerPresenceBook,
    path_book: &mut PeerPathBook,
    current_runtime: &mut Option<MobileWireGuardRuntime>,
    current_fingerprint: &mut Option<String>,
    current_route_targets: &mut Vec<String>,
    callbacks: IosTunnelCallbacks,
) -> Result<()> {
    let now = unix_timestamp();
    let own_endpoint = local_signal_endpoint(config, context.listen_port);
    let planned = planned_tunnel_peers(
        config,
        context.own_pubkey,
        presence.known(),
        path_book,
        Some(&own_endpoint),
        now,
    )?;

    for peer in &planned {
        path_book.note_selected(&peer.participant, &peer.endpoint, now);
    }

    let local_addresses = vec![local_interface_address_for_tunnel(&config.node.tunnel_ip)];
    let route_targets = route_targets_for_tunnel_peers(&planned);
    if &route_targets != current_route_targets {
        callbacks.update_settings(&NetworkSettingsPayload {
            local_addresses,
            routes: route_targets.clone(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            mtu: IOS_TUN_MTU,
        })?;
        *current_route_targets = route_targets;
    }

    if planned.is_empty() {
        *current_runtime = None;
        *current_fingerprint = None;
        return Ok(());
    }

    let fingerprint = tunnel_fingerprint(config, context.listen_port, &planned);
    if current_fingerprint.as_deref() == Some(fingerprint.as_str()) {
        return Ok(());
    }

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
        .context("failed to initialize iOS WireGuard runtime")?;

    send_outgoing_datagrams(udp, runtime.initiate_handshakes()).await?;
    *current_runtime = Some(runtime);
    *current_fingerprint = Some(fingerprint);
    publish_private_announce_best_effort(client, config, context.listen_port, context.recipients)
        .await;

    Ok(())
}

fn update_snapshot(
    snapshot: &Arc<Mutex<TunnelStatusSnapshot>>,
    active: bool,
    error: Option<String>,
    state: Option<DaemonRuntimeState>,
) {
    let state_json = state
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .ok()
        .flatten();

    apply_snapshot(snapshot, active, error.clone(), state_json.clone());

    if let Ok(guard) = controller().lock() {
        apply_snapshot(&guard.snapshot, active, error, state_json);
    }
}

fn set_snapshot(active: bool, error: Option<String>, state: Option<DaemonRuntimeState>) {
    if let Ok(guard) = controller().lock() {
        let state_json = state
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .ok()
            .flatten();
        apply_snapshot(&guard.snapshot, active, error, state_json);
    }
}

fn apply_snapshot(
    snapshot: &Arc<Mutex<TunnelStatusSnapshot>>,
    active: bool,
    error: Option<String>,
    state_json: Option<String>,
) {
    if let Ok(mut guard) = snapshot.lock() {
        guard.active = active;
        guard.error = error;
        guard.state_json = state_json;
    }
}

async fn send_outgoing_datagrams(
    udp: &tokio::net::UdpSocket,
    datagrams: Vec<crate::mobile_wg::OutgoingDatagram>,
) -> Result<()> {
    for datagram in datagrams {
        udp.send_to(&datagram.payload, datagram.endpoint)
            .await
            .with_context(|| {
                format!("failed to send WireGuard datagram to {}", datagram.endpoint)
            })?;
    }
    Ok(())
}

fn build_runtime_state(
    config: &AppConfig,
    expected_peers: usize,
    relay_connected: bool,
    current_runtime: Option<&MobileWireGuardRuntime>,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
) -> DaemonRuntimeState {
    let runtime_peer_map = current_runtime
        .map(|runtime| {
            runtime
                .peer_statuses()
                .into_iter()
                .map(|status| (status.participant_pubkey.clone(), status))
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
        IOS_SESSION_STATUS_WAITING,
    )
}
