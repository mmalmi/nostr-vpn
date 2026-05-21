use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(debug_assertions)]
use std::fs::OpenOptions;
#[cfg(debug_assertions)]
use std::io::Write;
#[cfg(test)]
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use fips_endpoint::{
    Config as FipsConfig, ConnectPolicy, FipsEndpoint, FipsEndpointMessage, FipsEndpointPeer,
    FipsEndpointRelayStatus, NostrDiscoveryPolicy, PeerAddress, PeerConfig as FipsPeerConfig,
    TransportInstances, UdpConfig,
};
use nostr_vpn_core::config::{
    AppConfig, MESH_TUNNEL_IPV4_CIDR, WireGuardExitConfig, derive_mesh_tunnel_ip,
    maybe_autoconfigure_node, normalize_nostr_pubkey, normalize_runtime_network_id,
};
use nostr_vpn_core::fips_control::{
    FipsControlFragmentBuffer, FipsControlFrame, NetworkRoster, PeerCapabilities, PeerEndpointHint,
    decode_fips_control_frame, encode_fips_control_frame, peer_endpoint_hint_addr,
};
use nostr_vpn_core::fips_mesh::{FipsMeshPeerConfig, FipsMeshRuntime};
use nostr_vpn_core::join_requests::{FIPS_JOIN_REQUEST_RETRY_SECS, MeshJoinRequest};
use nostr_vpn_core::wg_upstream::{DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT, WgUpstreamRuntime};
use serde::{Deserialize, Serialize};

use crate::state::{DaemonPeerState, DaemonRuntimeState};
use crate::wg_upstream_nat::{rewrite_ipv4_destination, rewrite_ipv4_source};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinHandle;

const DEFAULT_MOBILE_MTU: u16 = 1280;
const TUNNEL_CHANNEL_CAPACITY: usize = 1024;
#[cfg(test)]
const FIPS_NOSTR_DISCOVERY_APP: &str = "fips-overlay-v1";
const FIPS_DISCOVERY_BACKOFF_BASE_SECS: u64 = 30;
const FIPS_DISCOVERY_BACKOFF_MAX_SECS: u64 = 300;
const FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS: u64 = 30;
const MOBILE_NOSTR_OPEN_DISCOVERY_MAX_PENDING: usize = 4;
const MOBILE_NOSTR_FAILURE_STREAK_THRESHOLD: u32 = 2;
const FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS: u64 = 300;

/// Authenticated FIPS peer cap on mobile. fips's default is 128, which is
/// fine on AC-powered desktops but wasteful on phones once Open discovery
/// starts pulling in random nvpn nodes who have nothing to say to us at
/// the data plane (the roster gate drops their packets anyway).
const MOBILE_MAX_FIPS_PEERS: usize = 32;
/// Pre-handshake connection cap on mobile (~2x peer cap matches fips's
/// default ratio of 256:128).
const MOBILE_MAX_FIPS_CONNECTIONS: usize = 64;
/// Active-link cap on mobile (matches `MOBILE_MAX_FIPS_CONNECTIONS`).
const MOBILE_MAX_FIPS_LINKS: usize = 64;
const MOBILE_CAPABILITIES_BROADCAST_SECS: u64 = 30;
const MOBILE_CAPABILITIES_STARTUP_BURST_COUNT: usize = 4;
const MOBILE_CAPABILITIES_STARTUP_BURST_INTERVAL_MS: u64 = 750;
const MOBILE_RUNTIME_STATE_REFRESH_SECS: u64 = 2;
const MOBILE_RUNTIME_STATE_FILE: &str = "mobile-runtime-state.json";
const MOBILE_PEER_ONLINE_GRACE_SECS: u64 = 45;
const MOBILE_PEER_ACTIVE_PING_INTERVAL_SECS: u64 = 10;
const MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS: u64 = 120;
const MOBILE_CONTROL_RTT_MAX_ACCEPT_MS: u128 = 10_000;
const MOBILE_HANDSHAKE_RESEND_INTERVAL_MS: u64 = 300;
const MOBILE_HANDSHAKE_RESEND_BACKOFF: f64 = 1.5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MobileTunnelConfig {
    #[serde(default)]
    pub(crate) config_path: String,
    #[serde(default)]
    pub(crate) app_config_toml: String,
    pub(crate) identity_nsec: String,
    #[serde(default)]
    pub(crate) node_name: String,
    pub(crate) network_id: String,
    #[serde(default)]
    pub(crate) invite_secret: String,
    pub(crate) local_address: String,
    #[serde(default)]
    pub(crate) advertised_endpoint: String,
    #[serde(default)]
    pub(crate) listen_port: u16,
    pub(crate) mtu: u16,
    pub(crate) peers: Vec<FipsMeshPeerConfig>,
    #[serde(default)]
    peer_hints: HashMap<String, Vec<FipsPeerAddressHint>>,
    pub(crate) route_targets: Vec<String>,
    #[serde(default)]
    pub(crate) nostr_relays: Vec<String>,
    #[serde(default)]
    pub(crate) stun_servers: Vec<String>,
    #[serde(default)]
    pub(crate) share_local_candidates: bool,
    /// When the user has WG upstream enabled + configured, the OS-side
    /// (`NEPacketTunnelProvider` on iOS, `VpnService` on Android) is
    /// expected to:
    ///   * include `0.0.0.0/0` in the tunnel's includedRoutes (so all
    ///     non-mesh outbound traffic enters the tun and we can forward
    ///     it to boringtun)
    ///   * route every IP in `excluded_routes` outside the tunnel so
    ///     the encrypted UDP can actually reach the WG upstream
    ///     endpoint (iOS does this via `NEIPv4Settings.excludedRoutes`;
    ///     on Android the host calls `VpnService.protect(socket_fd)`
    ///     instead, see `MobileTunnel::wg_upstream_socket_fd`).
    #[serde(default)]
    pub(crate) excluded_routes: Vec<String>,
    /// DNS resolvers to install on the OS-side tunnel. Mullvad and
    /// Proton ship configs with their own DNS (e.g. `10.64.0.1`); on
    /// iOS this becomes `NEDNSSettings`. Without it, name resolution
    /// silently fails even though TCP transits the tunnel.
    #[serde(default)]
    pub(crate) dns_servers: Vec<String>,
    /// The WG upstream config to drive boringtun against. None when
    /// the user hasn't enabled WG upstream — in which case the mobile
    /// tunnel runs in pure FIPS-mesh mode.
    #[serde(default)]
    pub(crate) wireguard_exit: Option<WireGuardExitConfig>,
    #[serde(default)]
    pub(crate) join_requests_enabled: bool,
    #[serde(default)]
    pub(crate) pending_join_request_recipient: String,
    #[serde(default)]
    pub(crate) pending_join_invite_secret: String,
    #[serde(default)]
    pub(crate) pending_join_requested_at: u64,
    #[serde(default)]
    pub(crate) error: String,
}

impl MobileTunnelConfig {
    pub(crate) fn from_data_dir(data_dir: &str) -> Result<Self> {
        let config_path = native_config_path(data_dir);
        let mut app = if config_path.exists() {
            AppConfig::load(&config_path)?
        } else {
            let generated = AppConfig::generated_without_networks();
            generated.save(&config_path)?;
            generated
        };
        app.ensure_defaults();
        maybe_autoconfigure_node(&mut app);
        app.save(&config_path)?;
        Self::from_app_with_config_path(&app, &config_path)
    }

    #[cfg(test)]
    fn from_app(app: &AppConfig) -> Result<Self> {
        Self::from_app_with_config_path(app, Path::new(""))
    }

    fn from_app_with_config_path(app: &AppConfig, config_path: &Path) -> Result<Self> {
        let own_pubkey = app.own_nostr_pubkey_hex()?;
        let network_id = app.effective_network_id();
        let mut peers = Vec::new();
        let mut route_targets = Vec::new();
        let participant_pubkeys = app
            .participant_pubkeys_hex()
            .into_iter()
            .collect::<HashSet<_>>();

        for participant in app
            .active_network_signal_pubkeys_hex()
            .into_iter()
            .filter(|participant| participant != &own_pubkey)
        {
            let allowed_ips = if participant_pubkeys.contains(&participant) {
                let Some(tunnel_ip) = derive_mesh_tunnel_ip(&network_id, &participant) else {
                    continue;
                };
                let route = format!("{}/32", strip_cidr(&tunnel_ip));
                route_targets.push(route.clone());
                vec![route]
            } else {
                Vec::new()
            };
            peers.push(FipsMeshPeerConfig::from_participant_pubkey(
                participant,
                allowed_ips,
            )?);
        }

        if !network_id.trim().is_empty()
            && !route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        {
            route_targets.push(MESH_TUNNEL_IPV4_CIDR.to_string());
        }
        peers.sort_by(|left, right| left.participant_pubkey.cmp(&right.participant_pubkey));
        peers.dedup_by(|left, right| left.participant_pubkey == right.participant_pubkey);
        route_targets.sort();
        route_targets.dedup();

        let local_address = derive_mesh_tunnel_ip(&network_id, &own_pubkey).map_or_else(
            || local_interface_address_for_tunnel(&app.node.tunnel_ip),
            |tunnel_ip| local_interface_address_for_tunnel(&tunnel_ip),
        );

        // WireGuard upstream: when the user has enabled it AND the
        // config is fully populated, expand the tunnel's route set to
        // 0.0.0.0/0 (all outbound traffic should enter the tun) and
        // ask the host platform to keep the WG endpoint outside the
        // tunnel via `excluded_routes`.
        let (wireguard_exit, excluded_routes, dns_servers) =
            if app.wireguard_exit.enabled && app.wireguard_exit.configured() {
                let mut excluded = Vec::new();
                if let Some(ip) = wireguard_endpoint_host_ip(&app.wireguard_exit.endpoint) {
                    excluded.push(format!("{ip}/32"));
                }
                if !route_targets.iter().any(|route| route == "0.0.0.0/0") {
                    route_targets.push("0.0.0.0/0".to_string());
                }
                route_targets.sort();
                route_targets.dedup();
                // Fall back to Mullvad's resolver if the user's WG
                // config didn't carry DNS. Mullvad hijacks port 53 to
                // public resolvers (1.1.1.1 / 9.9.9.9), so even
                // though those DNS responses transit the tunnel they
                // come back signed as from the wrong source and iOS'
                // resolver discards them. 10.64.0.1 is Mullvad's
                // own DNS endpoint inside the tunnel and is the
                // safe default for both Mullvad and Proton.
                let dns = if app.wireguard_exit.dns.is_empty() {
                    vec!["10.64.0.1".to_string()]
                } else {
                    app.wireguard_exit.dns.clone()
                };
                // Force a 25s persistent keepalive on mobile so
                // boringtun keeps its session fresh against Mullvad's
                // server-side timeouts even when the device is idle.
                // Without this, the session goes stale, Mullvad
                // rotates indices on its side, and decap starts
                // returning WrongIndex.
                let mut wg = app.wireguard_exit.clone();
                if wg.persistent_keepalive_secs == 0 {
                    wg.persistent_keepalive_secs = 25;
                }
                (Some(wg), excluded, dns)
            } else {
                (None, Vec::new(), Vec::new())
            };
        let (pending_join_request_recipient, pending_join_invite_secret, pending_join_requested_at) =
            app.active_network_opt()
                .and_then(|network| {
                    network.outbound_join_request.as_ref().map(|request| {
                        (
                            request.recipient.clone(),
                            network.invite_secret.clone(),
                            request.requested_at,
                        )
                    })
                })
                .unwrap_or_default();

        Ok(Self {
            config_path: config_path.to_string_lossy().to_string(),
            app_config_toml: app_config_toml(app)?,
            identity_nsec: app.nostr.secret_key.clone(),
            node_name: app.node_name.trim().to_string(),
            network_id,
            invite_secret: app
                .active_network_opt()
                .map_or_else(String::new, |network| network.invite_secret.clone()),
            local_address,
            advertised_endpoint: app.node.endpoint.trim().to_string(),
            listen_port: app.node.listen_port,
            mtu: DEFAULT_MOBILE_MTU,
            peers,
            peer_hints: mobile_static_peer_hints(app),
            route_targets,
            nostr_relays: app.nostr.relays.clone(),
            stun_servers: app.nat.stun_servers.clone(),
            share_local_candidates: app.lan_discovery_enabled,
            excluded_routes,
            dns_servers,
            wireguard_exit,
            join_requests_enabled: app.join_requests_enabled(),
            pending_join_request_recipient,
            pending_join_invite_secret,
            pending_join_requested_at,
            error: String::new(),
        })
    }
}

/// Pull just the IP literal out of an `Endpoint = host:port` string.
/// Returns None if the host is a DNS name (we can't pre-resolve here
/// — the OS-side glue would need to do that). Mullvad / Proton ship
/// configs with literal IPs, so this is fine for the common case.
fn wireguard_endpoint_host_ip(endpoint: &str) -> Option<std::net::IpAddr> {
    let trimmed = endpoint.trim();
    let host = trimmed.rsplit_once(':').map_or(trimmed, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse().ok()
}

fn mobile_app_config(config: &MobileTunnelConfig) -> Result<AppConfig> {
    if !config.app_config_toml.trim().is_empty() {
        let mut app: AppConfig =
            toml::from_str(&config.app_config_toml).context("failed to parse mobile app config")?;
        app.ensure_defaults();
        return Ok(app);
    }

    let config_path = non_empty_path(&config.config_path)
        .ok_or_else(|| anyhow!("mobile app config unavailable"))?;
    let mut app = AppConfig::load(&config_path)?;
    app.ensure_defaults();
    Ok(app)
}

fn app_config_toml(app: &AppConfig) -> Result<String> {
    let mut app = app.clone();
    app.ensure_defaults();
    toml::to_string_pretty(&app).context("failed to encode mobile app config TOML")
}

pub(crate) fn tunnel_config_json(data_dir: &str) -> String {
    let config =
        MobileTunnelConfig::from_data_dir(data_dir).unwrap_or_else(|error| MobileTunnelConfig {
            error: error.to_string(),
            ..empty_config()
        });
    serde_json::to_string(&config).unwrap_or_else(|error| {
        format!(
            r#"{{"error":"{}"}}"#,
            error.to_string().replace(['\\', '"'], "")
        )
    })
}

pub(crate) struct MobileTunnel {
    runtime: Runtime,
    endpoint: Option<Arc<FipsEndpoint>>,
    mesh: Arc<RwLock<FipsMeshRuntime>>,
    presence: Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config: Arc<RwLock<MobileTunnelConfig>>,
    app_config: Arc<RwLock<AppConfig>>,
    app_config_dirty: Arc<AtomicBool>,
    outbound_tx: tokio_mpsc::Sender<Vec<u8>>,
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    tasks: Vec<JoinHandle<()>>,
    wg_upstream: Option<WgUpstreamRuntime>,
    /// Raw fd of the boringtun UDP socket. On Android the host
    /// reads this and calls `VpnService.protect(fd)` so the encrypted
    /// UDP escapes the VPN tun. -1 when WG upstream isn't running.
    wg_upstream_socket_fd: c_int,
}

impl MobileTunnel {
    pub(crate) fn start(config_json: &str) -> Result<Self> {
        mobile_debug_log("MobileTunnel::start parse begin");
        let config: MobileTunnelConfig =
            serde_json::from_str(config_json).context("invalid mobile tunnel config JSON")?;
        mobile_debug_log(format!(
            "MobileTunnel::start parsed peers={} routes={} nostr_relays={} share_lan={} listen={}",
            config.peers.len(),
            config.route_targets.len(),
            config.nostr_relays.len(),
            config.share_local_candidates,
            config.listen_port
        ));
        if !config.error.trim().is_empty() {
            return Err(anyhow!(config.error));
        }
        let app_config = mobile_app_config(&config)?;
        mobile_debug_log("MobileTunnel::start building tokio runtime");
        let runtime = RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("nvpn-mobile-fips")
            .build()
            .context("failed to start mobile FIPS runtime")?;
        mobile_debug_log("MobileTunnel::start entering start_async");
        let started = runtime.block_on(Self::start_async(config, app_config))?;
        mobile_debug_log("MobileTunnel::start start_async returned");
        Ok(Self {
            runtime,
            endpoint: Some(started.endpoint),
            mesh: started.mesh,
            presence: started.presence,
            config: started.config,
            app_config: started.app_config,
            app_config_dirty: started.app_config_dirty,
            outbound_tx: started.outbound_tx,
            inbound_rx: Mutex::new(started.inbound_rx),
            tasks: started.tasks,
            wg_upstream: started.wg_upstream,
            wg_upstream_socket_fd: started.wg_upstream_socket_fd,
        })
    }

    #[allow(clippy::large_futures, clippy::too_many_lines)]
    async fn start_async(
        config: MobileTunnelConfig,
        app_config: AppConfig,
    ) -> Result<MobileTunnelStarted> {
        mobile_debug_log("MobileTunnel::start_async begin");
        let scope = format!("nostr-vpn:{}", config.network_id.trim());
        let initial_peers = config.peers.clone();
        let config_path = non_empty_path(&config.config_path);
        let local_capability_hints = mobile_endpoint_hints(&config);
        mobile_debug_log(format!(
            "MobileTunnel::start_async binding FIPS endpoint scope={} peers={} hints={}",
            scope,
            initial_peers.len(),
            local_capability_hints.len()
        ));
        let endpoint = FipsEndpoint::builder()
            .config(fips_endpoint_config(&scope, &config))
            .identity_nsec(config.identity_nsec.clone())
            .discovery_scope(scope)
            .without_system_tun()
            .bind()
            .await
            .context("failed to bind mobile FIPS endpoint")?;
        mobile_debug_log("MobileTunnel::start_async FIPS endpoint bound");
        let endpoint = Arc::new(endpoint);
        let local_routes = vec![config.local_address.clone()];
        let mesh = Arc::new(RwLock::new(FipsMeshRuntime::with_local_routes(
            initial_peers.clone(),
            local_routes,
        )));
        let mesh_peers = Arc::new(RwLock::new(initial_peers));
        let peer_hints = Arc::new(RwLock::new(config.peer_hints.clone()));
        let presence = Arc::new(RwLock::new(HashMap::new()));
        let config_state = Arc::new(RwLock::new(config.clone()));
        let app_config = Arc::new(RwLock::new(app_config));
        let app_config_dirty = Arc::new(AtomicBool::new(false));
        let (outbound_tx, mut outbound_rx) =
            tokio_mpsc::channel::<Vec<u8>>(TUNNEL_CHANNEL_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::sync_channel::<Vec<u8>>(TUNNEL_CHANNEL_CAPACITY);

        // If the user has WG upstream enabled, stand up the boringtun
        // pump alongside the FIPS endpoint. The WG runtime is fed via
        // an mpsc::channel pair: `wg_send_tx` carries plaintext that
        // should be encapsulated and sent to the upstream;
        // `wg_recv_rx` carries plaintext we got back after
        // decapsulating the upstream's reply, ready to write back to
        // the OS tun.
        let mesh_ipv4 = parse_ipv4(&config.local_address);
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        let mut wg_runtime: Option<WgUpstreamRuntime> = None;
        let mut wg_send_tx: Option<tokio_mpsc::Sender<Vec<u8>>> = None;
        let mut wg_socket_fd: c_int = -1;
        let mut wg_address_ipv4: Option<Ipv4Addr> = None;
        if let Some(wg_config) = config.wireguard_exit.as_ref() {
            wg_address_ipv4 = parse_ipv4(&wg_config.address);
            let (send_tx, send_rx) = tokio_mpsc::channel::<Vec<u8>>(TUNNEL_CHANNEL_CAPACITY);
            let (recv_tx, mut recv_rx) = tokio_mpsc::channel::<Vec<u8>>(TUNNEL_CHANNEL_CAPACITY);
            match WgUpstreamRuntime::start_with_channels(wg_config, send_rx, recv_tx).await {
                Ok(runtime) => {
                    wg_socket_fd = runtime.udp_socket_fd();
                    let upstream = runtime.upstream();
                    wg_runtime = Some(runtime);
                    wg_send_tx = Some(send_tx);
                    // Forward decrypted WG packets back to the OS as
                    // inbound traffic. DNAT: rewrite the WG-side
                    // destination IP back to the mesh tun address so
                    // the OS routes the reply to the local app stack.
                    let inbound_tx_for_wg = inbound_tx.clone();
                    let wg_addr = wg_address_ipv4;
                    let mesh_addr = mesh_ipv4;
                    tasks.push(tokio::spawn(async move {
                        let mut count: u32 = 0;
                        while let Some(mut packet) = recv_rx.recv().await {
                            count = count.saturating_add(1);
                            // Log first 10 inbound packets so we can
                            // verify the DNAT / packet shape on iOS.
                            if count <= 10 && packet.len() >= 20 && packet[0] >> 4 == 4 {
                                let proto = packet[9];
                                let src = format!(
                                    "{}.{}.{}.{}",
                                    packet[12], packet[13], packet[14], packet[15]
                                );
                                let dst_before = format!(
                                    "{}.{}.{}.{}",
                                    packet[16], packet[17], packet[18], packet[19]
                                );
                                if let (Some(wg), Some(mesh)) = (wg_addr, mesh_addr) {
                                    rewrite_ipv4_destination(&mut packet, wg, mesh);
                                }
                                let dst_after = format!(
                                    "{}.{}.{}.{}",
                                    packet[16], packet[17], packet[18], packet[19]
                                );
                                log_pump_packet(&format!(
                                    "inbound #{count} {} bytes proto={proto} {src}:* -> {dst_before}->{dst_after}",
                                    packet.len()
                                ));
                            } else if let (Some(wg), Some(mesh)) = (wg_addr, mesh_addr) {
                                rewrite_ipv4_destination(&mut packet, wg, mesh);
                            }
                            if inbound_tx_for_wg.send(packet).is_err() {
                                break;
                            }
                        }
                    }));
                    // Watchdog: log if the handshake doesn't complete
                    // promptly. We don't tear down the tun on mobile
                    // (the OS owns it) but the host can surface the
                    // status to the UI.
                    if let Some(runtime_ref) = wg_runtime.as_ref() {
                        let timeout = DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT;
                        if runtime_ref.wait_for_handshake(timeout).await {
                            tracing::info!(
                                ?upstream,
                                "wg-upstream: mobile tunnel handshake completed"
                            );
                        } else {
                            tracing::warn!(
                                ?upstream,
                                "wg-upstream: no handshake within {timeout:?} on mobile tunnel; \
                                 traffic will queue until upstream becomes reachable"
                            );
                        }
                    }
                }
                Err(error) => {
                    // Don't fail the whole tunnel — FIPS mesh still
                    // works. Just log and continue without WG.
                    tracing::warn!(
                        ?error,
                        "wg-upstream: failed to start mobile WG runtime; continuing without WG upstream"
                    );
                }
            }
        }

        let send_task = {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let wg_send_tx_for_dispatch = wg_send_tx.clone();
            let wg_addr = wg_address_ipv4;
            let mesh_addr = mesh_ipv4;
            tokio::spawn(async move {
                let mut outbound_count: u32 = 0;
                while let Some(packet) = outbound_rx.recv().await {
                    let outgoing = mesh
                        .read()
                        .ok()
                        .and_then(|mesh| mesh.route_outbound_packet(&packet));
                    if let Some(outgoing) = outgoing {
                        let _ = endpoint.send(outgoing.endpoint_npub, outgoing.bytes).await;
                    } else if let Some(wg_tx) = wg_send_tx_for_dispatch.as_ref() {
                        // No matching mesh peer route: hand the
                        // plaintext off to the WG runtime, which will
                        // boringtun-encapsulate and send out via the
                        // upstream UDP socket. SNAT first so the inner
                        // source IP matches the WG peer's configured
                        // address — Mullvad / Proton silently drop
                        // packets whose inner source isn't an allowed
                        // peer IP.
                        let mut packet = packet;
                        let len_before = packet.len();
                        let pre_log =
                            if outbound_count <= 10 && packet.len() >= 20 && packet[0] >> 4 == 4 {
                                outbound_count = outbound_count.saturating_add(1);
                                let proto = packet[9];
                                let src_before = format!(
                                    "{}.{}.{}.{}",
                                    packet[12], packet[13], packet[14], packet[15]
                                );
                                let dst = format!(
                                    "{}.{}.{}.{}",
                                    packet[16], packet[17], packet[18], packet[19]
                                );
                                Some((proto, src_before, dst))
                            } else {
                                None
                            };
                        if let (Some(wg), Some(mesh)) = (wg_addr, mesh_addr) {
                            rewrite_ipv4_source(&mut packet, mesh, wg);
                        }
                        if let Some((proto, src_before, dst)) = pre_log {
                            let src_after = format!(
                                "{}.{}.{}.{}",
                                packet[12], packet[13], packet[14], packet[15]
                            );
                            log_pump_packet(&format!(
                                "outbound #{outbound_count} {len_before}B proto={proto} src={src_before}->{src_after} dst={dst}"
                            ));
                        }
                        let _ = wg_tx.try_send(packet);
                    }
                }
            })
        };
        tasks.push(send_task);

        let join_request_active = Arc::new(AtomicBool::new(false));
        if let Some((recipient_npub, frame)) = pending_mobile_join_request_frame(&config)? {
            let endpoint = Arc::clone(&endpoint);
            let join_request_active_for_task = Arc::clone(&join_request_active);
            join_request_active.store(true, Ordering::Relaxed);
            tasks.push(tokio::spawn(async move {
                let encoded = match encode_fips_control_frame(&frame) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        tracing::warn!(?error, "mobile: failed to encode FIPS join request");
                        return;
                    }
                };
                while join_request_active_for_task.load(Ordering::Relaxed) {
                    let _ = endpoint.send(recipient_npub.clone(), encoded.clone()).await;
                    tokio::time::sleep(Duration::from_secs(FIPS_JOIN_REQUEST_RETRY_SECS)).await;
                }
            }));
        }

        if !config.network_id.trim().is_empty() && !local_capability_hints.is_empty() {
            let endpoint = Arc::clone(&endpoint);
            let mesh_peers = Arc::clone(&mesh_peers);
            let network_id = config.network_id.clone();
            tasks.push(tokio::spawn(async move {
                let mut startup_broadcasts_remaining = MOBILE_CAPABILITIES_STARTUP_BURST_COUNT;
                loop {
                    if let Err(error) = broadcast_mobile_capabilities(
                        &endpoint,
                        &mesh_peers,
                        &network_id,
                        local_capability_hints.clone(),
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to broadcast capabilities");
                    }
                    let sleep_duration = if startup_broadcasts_remaining > 1 {
                        startup_broadcasts_remaining -= 1;
                        Duration::from_millis(MOBILE_CAPABILITIES_STARTUP_BURST_INTERVAL_MS)
                    } else {
                        startup_broadcasts_remaining = 0;
                        Duration::from_secs(MOBILE_CAPABILITIES_BROADCAST_SECS)
                    };
                    tokio::time::sleep(sleep_duration).await;
                }
            }));
        }

        if let Some(status_path) = config_path.as_deref().and_then(mobile_runtime_state_path) {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let presence = Arc::clone(&presence);
            let status_config = Arc::clone(&config_state);
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Err(error) = persist_mobile_runtime_state(
                        &status_path,
                        &endpoint,
                        &mesh,
                        &presence,
                        &status_config,
                    )
                    .await
                    {
                        tracing::warn!(?error, "mobile: failed to persist runtime state");
                    }
                    tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                        .await;
                }
            }));
        }

        if !config.network_id.trim().is_empty() {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let presence = Arc::clone(&presence);
            let network_id = config.network_id.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Err(error) =
                        mobile_ping_peers(&endpoint, &mesh, &presence, &network_id).await
                    {
                        tracing::warn!(?error, "mobile: failed to ping FIPS peers");
                    }
                    tokio::time::sleep(Duration::from_secs(MOBILE_RUNTIME_STATE_REFRESH_SECS))
                        .await;
                }
            }));
        }

        let recv_task = {
            let endpoint = Arc::clone(&endpoint);
            let mesh = Arc::clone(&mesh);
            let mesh_peers = Arc::clone(&mesh_peers);
            let peer_hints = Arc::clone(&peer_hints);
            let presence = Arc::clone(&presence);
            let config_state = Arc::clone(&config_state);
            let app_config = Arc::clone(&app_config);
            let app_config_dirty = Arc::clone(&app_config_dirty);
            let config_path = config_path.clone();
            let join_request_active = Arc::clone(&join_request_active);
            let network_id = config.network_id.clone();
            tokio::spawn(async move {
                let mut control_fragments = FipsControlFragmentBuffer::default();
                loop {
                    let Some(message) = endpoint.recv().await else {
                        break;
                    };
                    match handle_mobile_control_frame(
                        &endpoint,
                        &mesh,
                        &mesh_peers,
                        &peer_hints,
                        &presence,
                        &config_state,
                        &app_config,
                        &app_config_dirty,
                        config_path.as_deref(),
                        &network_id,
                        &join_request_active,
                        &mut control_fragments,
                        &message,
                    )
                    .await
                    {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(?error, "mobile: failed to handle FIPS control frame");
                            continue;
                        }
                    }
                    let packet = mesh.read().ok().and_then(|mesh| {
                        mesh.receive_endpoint_data(message.source_npub.as_deref(), &message.data)
                    });
                    if let Some(packet) = packet {
                        note_mobile_peer_rx(&presence, &packet.source_pubkey, message.data.len());
                        if inbound_tx.send(packet.bytes).is_err() {
                            break;
                        }
                    }
                }
            })
        };
        tasks.push(recv_task);

        Ok(MobileTunnelStarted {
            endpoint,
            mesh,
            presence,
            config: config_state,
            app_config,
            app_config_dirty,
            outbound_tx,
            inbound_rx,
            tasks,
            wg_upstream: wg_runtime,
            wg_upstream_socket_fd: wg_socket_fd,
        })
    }

    /// Raw fd of the WG upstream UDP socket, or -1 if WG upstream
    /// isn't running. On Android, the host's `VpnService` calls
    /// `protect(fd)` on this so the encrypted UDP escapes the VPN
    /// tun. iOS doesn't need this — it relies on `excludedRoutes`
    /// declared at tunnel-establish time instead.
    pub(crate) fn wg_upstream_socket_fd(&self) -> c_int {
        self.wg_upstream_socket_fd
    }

    pub(crate) fn runtime_state_json(&self) -> Result<String> {
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| anyhow!("mobile tunnel stopped"))?;
        let mesh = Arc::clone(&self.mesh);
        let presence = Arc::clone(&self.presence);
        let config = self
            .config
            .read()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
            .clone();
        self.runtime.block_on(async move {
            let endpoint_peers = endpoint
                .peers()
                .await
                .context("mobile FIPS peer snapshot")?;
            let relay_statuses = endpoint
                .relay_statuses()
                .await
                .context("mobile FIPS relay snapshot")?;
            let state = {
                let mesh = mesh
                    .read()
                    .map_err(|_| anyhow!("mobile FIPS mesh route table lock poisoned"))?;
                let presence = presence
                    .read()
                    .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
                mobile_runtime_state(
                    &config,
                    &mesh,
                    &presence,
                    endpoint_peers,
                    relay_statuses,
                    unix_timestamp(),
                )
            };
            serde_json::to_string(&state).context("serialize mobile runtime state")
        })
    }

    pub(crate) fn take_app_config_toml(&self) -> Result<String> {
        if !self.app_config_dirty.swap(false, Ordering::Relaxed) {
            return Ok(String::new());
        }
        let app = self
            .app_config
            .read()
            .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
        match app_config_toml(&app) {
            Ok(toml) => Ok(toml),
            Err(error) => {
                self.app_config_dirty.store(true, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    pub(crate) fn send_packet(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        self.outbound_tx.try_send(packet.to_vec()).is_ok()
    }

    pub(crate) fn next_packet(&self, out: &mut [u8], timeout: Duration) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let rx = self
            .inbound_rx
            .lock()
            .map_err(|_| anyhow!("mobile tunnel inbound packet lock poisoned"))?;
        match rx.recv_timeout(timeout) {
            Ok(packet) => {
                let len = packet.len().min(out.len());
                out[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(0),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!("mobile tunnel stopped")),
        }
    }
}

struct MobileTunnelStarted {
    endpoint: Arc<FipsEndpoint>,
    mesh: Arc<RwLock<FipsMeshRuntime>>,
    presence: Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config: Arc<RwLock<MobileTunnelConfig>>,
    app_config: Arc<RwLock<AppConfig>>,
    app_config_dirty: Arc<AtomicBool>,
    outbound_tx: tokio_mpsc::Sender<Vec<u8>>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    tasks: Vec<JoinHandle<()>>,
    wg_upstream: Option<WgUpstreamRuntime>,
    wg_upstream_socket_fd: c_int,
}

impl Drop for MobileTunnel {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let tasks = std::mem::take(&mut self.tasks);
        let endpoint = self.endpoint.take();
        let wg_upstream = self.wg_upstream.take();
        self.runtime.block_on(async move {
            for task in tasks {
                let _ = task.await;
            }
            if let Some(wg) = wg_upstream {
                wg.shutdown().await;
            }
            if let Some(endpoint) = endpoint
                && let Ok(endpoint) = Arc::try_unwrap(endpoint)
            {
                let _ = endpoint.shutdown().await;
            }
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FipsPeerAddressHint {
    addr: String,
    seen_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct MobilePeerPresence {
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    last_ping_started_at: Option<Instant>,
    rtt_ms: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
async fn handle_mobile_control_frame(
    endpoint: &FipsEndpoint,
    mesh: &Arc<RwLock<FipsMeshRuntime>>,
    mesh_peers: &Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config_state: &Arc<RwLock<MobileTunnelConfig>>,
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    network_id: &str,
    join_request_active: &AtomicBool,
    control_fragments: &mut FipsControlFragmentBuffer,
    message: &FipsEndpointMessage,
) -> Result<bool> {
    let Some(frame) = decode_mobile_control_frame(control_fragments, message)? else {
        return Ok(false);
    };
    if !control_frame_network_matches(network_id, &frame) {
        return Ok(true);
    }
    let Some(source_pubkey) =
        mobile_control_source_pubkey(mesh, message.source_npub.as_deref(), &frame)?
    else {
        return Ok(true);
    };
    note_mobile_peer_rx(presence, &source_pubkey, message.data.len());

    match frame {
        FipsControlFrame::Roster { network_id, roster } => {
            apply_mobile_roster_frame(
                endpoint,
                mesh,
                mesh_peers,
                peer_hints,
                config_state,
                app_config,
                app_config_dirty,
                config_path,
                join_request_active,
                &source_pubkey,
                &network_id,
                &roster,
            )
            .await?;
        }
        FipsControlFrame::Capabilities { capabilities, .. } => {
            if update_mobile_peer_hints(peer_hints, &source_pubkey, &capabilities)? {
                sync_mobile_config_peer_hints(config_state, peer_hints)?;
                persist_mobile_peer_hints(
                    app_config,
                    app_config_dirty,
                    config_path,
                    &source_pubkey,
                    &capabilities,
                )?;
                refresh_mobile_endpoint_peers(endpoint, mesh_peers, peer_hints).await?;
            }
        }
        FipsControlFrame::Ping {
            network_id,
            sent_at,
        } => {
            reply_mobile_ping(
                endpoint,
                message.source_npub.as_deref(),
                network_id,
                sent_at,
            )
            .await?;
        }
        FipsControlFrame::JoinRequest {
            requested_at,
            request,
        } => {
            record_mobile_join_request(
                app_config,
                app_config_dirty,
                config_path,
                &source_pubkey,
                requested_at,
                &request,
            )?;
        }
        FipsControlFrame::Pong { sent_at, .. } => {
            note_mobile_peer_pong(presence, &source_pubkey, sent_at);
        }
        FipsControlFrame::Fragment { .. } => {}
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn apply_mobile_roster_frame(
    endpoint: &FipsEndpoint,
    mesh: &Arc<RwLock<FipsMeshRuntime>>,
    mesh_peers: &Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
    config_state: &Arc<RwLock<MobileTunnelConfig>>,
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    join_request_active: &AtomicBool,
    source_pubkey: &str,
    network_id: &str,
    roster: &NetworkRoster,
) -> Result<()> {
    let Some(updated) = apply_mobile_roster(
        app_config,
        app_config_dirty,
        config_path,
        source_pubkey,
        network_id,
        roster,
    )?
    else {
        return Ok(());
    };
    let local_routes = vec![updated.local_address.clone()];
    let updated_peers = updated.peers.clone();
    let updated_hints = updated.peer_hints.clone();
    {
        let mut mesh = mesh
            .write()
            .map_err(|_| anyhow!("mobile FIPS mesh route table lock poisoned"))?;
        *mesh = FipsMeshRuntime::with_local_routes(updated_peers.clone(), local_routes);
    }
    {
        let mut peers = mesh_peers
            .write()
            .map_err(|_| anyhow!("mobile FIPS peer lock poisoned"))?;
        *peers = updated_peers;
    }
    {
        let mut hints = peer_hints
            .write()
            .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?;
        *hints = updated_hints;
    }
    {
        let mut config = config_state
            .write()
            .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
        *config = updated.clone();
    }
    if updated.pending_join_request_recipient.trim().is_empty() {
        join_request_active.store(false, Ordering::Relaxed);
    }
    refresh_mobile_endpoint_peers(endpoint, mesh_peers, peer_hints).await
}

async fn reply_mobile_ping(
    endpoint: &FipsEndpoint,
    source_npub: Option<&str>,
    network_id: String,
    sent_at: u64,
) -> Result<()> {
    let Some(source_npub) = source_npub else {
        return Ok(());
    };
    let reply = FipsControlFrame::Pong {
        network_id,
        sent_at,
        replied_at: unix_timestamp(),
    };
    let encoded = encode_fips_control_frame(&reply)?;
    let _ = endpoint.send(source_npub.to_string(), encoded).await;
    Ok(())
}

fn mobile_control_source_pubkey(
    mesh: &Arc<RwLock<FipsMeshRuntime>>,
    source_npub: Option<&str>,
    frame: &FipsControlFrame,
) -> Result<Option<String>> {
    let mesh = mesh
        .read()
        .map_err(|_| anyhow!("mobile FIPS mesh route table lock poisoned"))?;
    Ok(control_frame_source_pubkey(&mesh, source_npub, frame))
}

fn decode_mobile_control_frame(
    control_fragments: &mut FipsControlFragmentBuffer,
    message: &FipsEndpointMessage,
) -> Result<Option<FipsControlFrame>> {
    let Some(frame) = decode_fips_control_frame(&message.data)? else {
        return Ok(None);
    };
    let FipsControlFrame::Fragment { .. } = frame else {
        return Ok(Some(frame));
    };
    let Some(source_npub) = message.source_npub.as_deref() else {
        return Ok(None);
    };
    control_fragments.decode(source_npub, &message.data, unix_timestamp())
}

fn control_frame_network_matches(expected_network_id: &str, frame: &FipsControlFrame) -> bool {
    let frame_network_id = match frame {
        FipsControlFrame::Ping { network_id, .. }
        | FipsControlFrame::Pong { network_id, .. }
        | FipsControlFrame::Roster { network_id, .. }
        | FipsControlFrame::Capabilities { network_id, .. } => network_id,
        FipsControlFrame::JoinRequest { request, .. } => &request.network_id,
        FipsControlFrame::Fragment { .. } => return false,
    };
    normalize_runtime_network_id(expected_network_id)
        == normalize_runtime_network_id(frame_network_id)
}

fn control_frame_source_pubkey(
    mesh: &FipsMeshRuntime,
    source_npub: Option<&str>,
    frame: &FipsControlFrame,
) -> Option<String> {
    let source_npub = source_npub?;
    mesh.participant_for_endpoint_npub(source_npub).or_else(|| {
        matches!(frame, FipsControlFrame::JoinRequest { .. })
            .then(|| normalize_nostr_pubkey(source_npub).ok())
            .flatten()
    })
}

fn apply_mobile_roster(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    sender_pubkey: &str,
    network_id: &str,
    roster: &NetworkRoster,
) -> Result<Option<MobileTunnelConfig>> {
    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    app.ensure_defaults();
    let changed = app.apply_admin_signed_shared_roster(
        network_id,
        &roster.network_name,
        roster.participants.clone(),
        roster.admins.clone(),
        roster.aliases.clone(),
        roster.signed_at,
        sender_pubkey,
    )?;
    if !changed {
        return Ok(None);
    }
    maybe_autoconfigure_node(&mut app);
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: roster applied in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: roster applied in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    let config_path = config_path.unwrap_or_else(|| Path::new(""));
    MobileTunnelConfig::from_app_with_config_path(&app, config_path).map(Some)
}

fn record_mobile_join_request(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    sender_pubkey: &str,
    requested_at: u64,
    request: &MeshJoinRequest,
) -> Result<bool> {
    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    app.ensure_defaults();
    let changed = match app.record_inbound_join_request(
        &request.network_id,
        &request.invite_secret,
        sender_pubkey,
        &request.requester_node_name,
        requested_at,
    ) {
        Ok(Some(_network_name)) => true,
        Ok(None) => false,
        Err(error) => {
            mobile_debug_log(format!(
                "mobile: ignoring invalid join request from {sender_pubkey}: {error:#}"
            ));
            tracing::warn!(
                ?error,
                %sender_pubkey,
                "mobile: ignoring invalid FIPS join request"
            );
            false
        }
    };
    if !changed {
        return Ok(false);
    }
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: join request recorded in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: join request recorded in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    Ok(true)
}

fn mobile_runtime_state_path(config_path: &Path) -> Option<PathBuf> {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(MOBILE_RUNTIME_STATE_FILE))
}

async fn persist_mobile_runtime_state(
    path: &Path,
    endpoint: &FipsEndpoint,
    mesh: &Arc<RwLock<FipsMeshRuntime>>,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    config: &Arc<RwLock<MobileTunnelConfig>>,
) -> Result<()> {
    let endpoint_peers = endpoint
        .peers()
        .await
        .context("mobile FIPS peer snapshot")?;
    let relay_statuses = endpoint
        .relay_statuses()
        .await
        .context("mobile FIPS relay snapshot")?;
    let config = config
        .read()
        .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?
        .clone();
    let state = {
        let mesh = mesh
            .read()
            .map_err(|_| anyhow!("mobile FIPS mesh route table lock poisoned"))?;
        let presence = presence
            .read()
            .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
        mobile_runtime_state(
            &config,
            &mesh,
            &presence,
            endpoint_peers,
            relay_statuses,
            unix_timestamp(),
        )
    };
    write_mobile_runtime_state(path, &state)
}

fn mobile_runtime_state(
    config: &MobileTunnelConfig,
    mesh: &FipsMeshRuntime,
    presence: &HashMap<String, MobilePeerPresence>,
    endpoint_peers: Vec<FipsEndpointPeer>,
    relay_statuses: Vec<FipsEndpointRelayStatus>,
    now: u64,
) -> DaemonRuntimeState {
    let link_by_participant = endpoint_peers
        .into_iter()
        .filter_map(|peer| {
            let participant = mesh.participant_for_endpoint_npub(&peer.npub)?;
            Some((participant, peer))
        })
        .collect::<HashMap<_, _>>();
    let peer_config_by_participant = config
        .peers
        .iter()
        .map(|peer| (peer.participant_pubkey.clone(), peer))
        .collect::<HashMap<_, _>>();

    let peers = mesh
        .peer_statuses()
        .into_iter()
        .map(|status| {
            let peer_config = peer_config_by_participant.get(&status.pubkey);
            let link = link_by_participant.get(&status.pubkey);
            let peer_presence = presence.get(&status.pubkey);
            let last_seen_at = peer_presence.and_then(|presence| presence.last_seen_at);
            let presence_connected = last_seen_at.is_some_and(|last_seen_at| {
                now.saturating_sub(last_seen_at) <= MOBILE_PEER_ONLINE_GRACE_SECS
            });
            let reachable = presence_connected || link.is_some();
            let advertised_routes = peer_config
                .map(|peer| peer.allowed_ips.clone())
                .unwrap_or_default();
            let tunnel_ip = advertised_routes
                .first()
                .map(|route| strip_cidr(route).to_string())
                .or_else(|| derive_mesh_tunnel_ip(&config.network_id, &status.pubkey))
                .unwrap_or_default();

            DaemonPeerState {
                participant_pubkey: status.pubkey.clone(),
                node_id: String::new(),
                tunnel_ip,
                endpoint: String::new(),
                runtime_endpoint: link.and_then(|peer| peer.transport_addr.clone()),
                fips_endpoint_npub: link
                    .map_or_else(|| status.endpoint_npub.clone(), |peer| peer.npub.clone()),
                fips_transport_addr: link
                    .and_then(|peer| peer.transport_addr.clone())
                    .unwrap_or_default(),
                fips_transport_type: link
                    .and_then(|peer| peer.transport_type.clone())
                    .unwrap_or_default(),
                fips_srtt_ms: link
                    .and_then(|peer| peer.srtt_ms)
                    .or_else(|| peer_presence.and_then(|presence| presence.rtt_ms)),
                fips_packets_sent: link.map_or(0, |peer| peer.packets_sent),
                fips_packets_recv: link.map_or(0, |peer| peer.packets_recv),
                fips_bytes_sent: link.map_or(0, |peer| peer.bytes_sent),
                fips_bytes_recv: link.map_or(0, |peer| peer.bytes_recv),
                tx_bytes: peer_presence.map_or(0, |presence| presence.tx_bytes),
                rx_bytes: peer_presence.map_or(0, |presence| presence.rx_bytes),
                public_key: status.pubkey,
                advertised_routes,
                last_mesh_seen_at: last_seen_at
                    .unwrap_or_else(|| if link.is_some() { now } else { 0 }),
                last_fips_seen_at: last_seen_at.or_else(|| link.is_some().then_some(now)),
                reachable,
                last_handshake_at: last_seen_at.or_else(|| link.is_some().then_some(now)),
                error: if reachable {
                    None
                } else {
                    Some("fips link pending".to_string())
                },
            }
        })
        .collect::<Vec<_>>();
    let connected_peer_count = peers.iter().filter(|peer| peer.reachable).count();
    let expected_peer_count = peers.len();

    DaemonRuntimeState {
        updated_at: now,
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        local_endpoint: config.advertised_endpoint.clone(),
        advertised_endpoint: config.advertised_endpoint.clone(),
        listen_port: config.listen_port,
        vpn_enabled: true,
        vpn_active: true,
        vpn_status: if expected_peer_count == 0 {
            "VPN on".to_string()
        } else {
            format!("VPN on ({connected_peer_count}/{expected_peer_count} peers)")
        },
        expected_peer_count,
        connected_peer_count,
        mesh_ready: connected_peer_count == expected_peer_count,
        relays: relay_statuses
            .into_iter()
            .map(|relay| crate::state::RelayView {
                url: relay.url,
                status: relay.status,
                enabled: true,
            })
            .collect(),
        peers,
        ..DaemonRuntimeState::default()
    }
}

fn note_mobile_peer_rx(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    len: usize,
) {
    let now = unix_timestamp();
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.last_seen_at = Some(now);
    entry.rx_bytes = entry.rx_bytes.saturating_add(len as u64);
}

fn note_mobile_peer_tx(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    len: usize,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.tx_bytes = entry.tx_bytes.saturating_add(len as u64);
}

fn note_mobile_peer_ping_attempt(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    now: u64,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let entry = presence.entry(participant.to_string()).or_default();
    entry.last_ping_sent_at = Some(now);
    entry.last_ping_started_at = Some(Instant::now());
}

fn note_mobile_peer_pong(
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    participant: &str,
    sent_at: u64,
) {
    let Ok(mut presence) = presence.write() else {
        return;
    };
    let Some(entry) = presence.get_mut(participant) else {
        return;
    };
    if entry.last_ping_sent_at == Some(sent_at)
        && let Some(started_at) = entry.last_ping_started_at.take()
    {
        let elapsed_ms = started_at.elapsed().as_millis();
        if elapsed_ms <= MOBILE_CONTROL_RTT_MAX_ACCEPT_MS {
            let Ok(elapsed_ms) = u64::try_from(elapsed_ms) else {
                return;
            };
            entry.rtt_ms = Some(elapsed_ms);
        } else {
            entry.last_ping_sent_at = None;
        }
    }
}

fn mobile_peer_ping_due(
    last_seen_at: Option<u64>,
    last_ping_sent_at: Option<u64>,
    now: u64,
) -> bool {
    let interval = if last_seen_at.is_some_and(|last_seen_at| {
        now.saturating_sub(last_seen_at) <= MOBILE_PEER_ONLINE_GRACE_SECS
    }) {
        MOBILE_PEER_ACTIVE_PING_INTERVAL_SECS
    } else {
        MOBILE_PEER_DISCOVERY_PROBE_INTERVAL_SECS
    };
    last_ping_sent_at.is_none_or(|sent_at| now.saturating_sub(sent_at) >= interval)
}

async fn mobile_ping_peers(
    endpoint: &FipsEndpoint,
    mesh: &Arc<RwLock<FipsMeshRuntime>>,
    presence: &Arc<RwLock<HashMap<String, MobilePeerPresence>>>,
    network_id: &str,
) -> Result<usize> {
    let now = unix_timestamp();
    let peers = {
        let mesh = mesh
            .read()
            .map_err(|_| anyhow!("mobile FIPS mesh route table lock poisoned"))?;
        mesh.peer_statuses()
    };
    let participants = {
        let presence = presence
            .read()
            .map_err(|_| anyhow!("mobile FIPS presence lock poisoned"))?;
        peers
            .into_iter()
            .filter(|peer| !peer.endpoint_npub.trim().is_empty())
            .filter(|peer| {
                let peer_presence = presence.get(&peer.pubkey);
                mobile_peer_ping_due(
                    peer_presence.and_then(|value| value.last_seen_at),
                    peer_presence.and_then(|value| value.last_ping_sent_at),
                    now,
                )
            })
            .map(|peer| (peer.pubkey, peer.endpoint_npub))
            .collect::<Vec<_>>()
    };
    if participants.is_empty() {
        return Ok(0);
    }
    let frame = FipsControlFrame::Ping {
        network_id: network_id.to_string(),
        sent_at: now,
    };
    let encoded = encode_fips_control_frame(&frame)?;
    let mut sent = 0usize;
    for (participant, endpoint_npub) in participants {
        note_mobile_peer_ping_attempt(presence, &participant, now);
        if endpoint.send(endpoint_npub, encoded.clone()).await.is_ok() {
            note_mobile_peer_tx(presence, &participant, encoded.len());
            sent += 1;
        }
    }
    Ok(sent)
}

fn write_mobile_runtime_state(path: &Path, state: &DaemonRuntimeState) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(state)?;
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(MOBILE_RUNTIME_STATE_FILE)
    ));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path).or_else(|_| {
        let _ = fs::remove_file(path);
        fs::rename(&tmp, path)
    })?;
    Ok(())
}

fn update_mobile_peer_hints(
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
    source_pubkey: &str,
    capabilities: &PeerCapabilities,
) -> Result<bool> {
    let seen_at = if capabilities.signed_at == 0 {
        unix_timestamp()
    } else {
        capabilities.signed_at
    };
    let seen_at_ms = seen_at.saturating_mul(1000);
    let mut hints = capabilities
        .endpoint_hints
        .iter()
        .filter_map(peer_endpoint_hint_addr)
        .map(|addr| FipsPeerAddressHint {
            addr,
            seen_at_ms: Some(seen_at_ms),
        })
        .collect::<Vec<_>>();
    hints.sort_by(|left, right| left.addr.cmp(&right.addr));
    hints.dedup_by(|left, right| left.addr == right.addr);

    let mut peer_hints = peer_hints
        .write()
        .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?;
    if peer_hints.get(source_pubkey) == Some(&hints) {
        return Ok(false);
    }
    peer_hints.insert(source_pubkey.to_string(), hints);
    Ok(true)
}

fn sync_mobile_config_peer_hints(
    config_state: &Arc<RwLock<MobileTunnelConfig>>,
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
) -> Result<()> {
    let hints = peer_hints
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?
        .clone();
    let mut config = config_state
        .write()
        .map_err(|_| anyhow!("mobile FIPS config lock poisoned"))?;
    config.peer_hints = hints;
    Ok(())
}

fn persist_mobile_peer_hints(
    app_config: &Arc<RwLock<AppConfig>>,
    app_config_dirty: &AtomicBool,
    config_path: Option<&Path>,
    source_pubkey: &str,
    capabilities: &PeerCapabilities,
) -> Result<()> {
    let mut endpoints = capabilities
        .endpoint_hints
        .iter()
        .filter_map(peer_endpoint_hint_addr)
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        return Ok(());
    }

    let mut app = app_config
        .write()
        .map_err(|_| anyhow!("mobile app config lock poisoned"))?;
    if app.fips_peer_endpoints.get(source_pubkey) == Some(&endpoints) {
        return Ok(());
    }
    app.fips_peer_endpoints
        .insert(source_pubkey.to_string(), endpoints);
    app.ensure_defaults();
    if let Some(config_path) = config_path
        && let Err(error) = app.save(config_path)
    {
        mobile_debug_log(format!(
            "mobile: peer hints updated in memory but config save failed: {error:#}"
        ));
        tracing::warn!(
            ?error,
            "mobile: peer hints updated in memory but config save failed"
        );
    }
    app_config_dirty.store(true, Ordering::Relaxed);
    Ok(())
}

async fn refresh_mobile_endpoint_peers(
    endpoint: &FipsEndpoint,
    mesh_peers: &Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    peer_hints: &Arc<RwLock<HashMap<String, Vec<FipsPeerAddressHint>>>>,
) -> Result<()> {
    let peers = mesh_peers
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer lock poisoned"))?
        .clone();
    let hints = peer_hints
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer hint lock poisoned"))?
        .clone();
    endpoint
        .update_peers(fips_peer_configs_from_mesh(&peers, &hints))
        .await
        .context("mobile FIPS peer update failed")?;
    Ok(())
}

async fn broadcast_mobile_capabilities(
    endpoint: &FipsEndpoint,
    mesh_peers: &Arc<RwLock<Vec<FipsMeshPeerConfig>>>,
    network_id: &str,
    endpoint_hints: Vec<PeerEndpointHint>,
) -> Result<usize> {
    let peers = mesh_peers
        .read()
        .map_err(|_| anyhow!("mobile FIPS peer lock poisoned"))?
        .clone();
    if peers.is_empty() {
        return Ok(0);
    }

    let frame = FipsControlFrame::Capabilities {
        network_id: network_id.to_string(),
        capabilities: PeerCapabilities {
            advertised_routes: Vec::new(),
            endpoint_hints,
            signed_at: unix_timestamp(),
        },
    };
    let encoded = encode_fips_control_frame(&frame)?;
    let mut sent = 0usize;
    for peer in peers {
        if endpoint
            .send(peer.endpoint_npub, encoded.clone())
            .await
            .is_ok()
        {
            sent += 1;
        }
    }
    Ok(sent)
}

fn pending_mobile_join_request_frame(
    config: &MobileTunnelConfig,
) -> Result<Option<(String, FipsControlFrame)>> {
    if config.pending_join_request_recipient.trim().is_empty()
        || config.pending_join_requested_at == 0
        || config.network_id.trim().is_empty()
    {
        return Ok(None);
    }
    let recipient = FipsMeshPeerConfig::from_participant_pubkey(
        &config.pending_join_request_recipient,
        Vec::new(),
    )?;
    let frame = FipsControlFrame::JoinRequest {
        requested_at: config.pending_join_requested_at,
        request: MeshJoinRequest {
            network_id: normalize_runtime_network_id(&config.network_id),
            invite_secret: config.pending_join_invite_secret.trim().to_string(),
            requester_node_name: config.node_name.trim().to_string(),
        },
    };
    Ok(Some((recipient.endpoint_npub, frame)))
}

fn mobile_endpoint_hints(config: &MobileTunnelConfig) -> Vec<PeerEndpointHint> {
    if !config.share_local_candidates {
        return Vec::new();
    }
    mobile_endpoint_hints_with_candidates(config, mobile_lan_ipv4_candidates(&config.local_address))
}

fn mobile_endpoint_hints_with_candidates(
    config: &MobileTunnelConfig,
    local_ipv4_candidates: Vec<Ipv4Addr>,
) -> Vec<PeerEndpointHint> {
    let endpoint = endpoint_with_listen_port(&config.advertised_endpoint, config.listen_port);
    let mut endpoints = Vec::new();

    if endpoint_is_gossipable_direct_hint(&endpoint)
        && !endpoint_uses_tunnel_ip(&endpoint, &config.local_address)
    {
        endpoints.push(endpoint);
    }

    let tunnel_ipv4 = parse_ipv4(&config.local_address);
    if config.listen_port != 0 {
        for ip in local_ipv4_candidates {
            if Some(ip) == tunnel_ipv4 || !ipv4_is_lan_endpoint_hint(ip) {
                continue;
            }
            endpoints.push(SocketAddrV4::new(ip, config.listen_port).to_string());
        }
    }

    endpoints.sort();
    endpoints.dedup();
    endpoints
        .into_iter()
        .map(PeerEndpointHint::udp)
        .filter(|hint| peer_endpoint_hint_addr(hint).is_some())
        .collect()
}

fn fips_peer_configs_from_mesh(
    peers: &[FipsMeshPeerConfig],
    peer_hints: &HashMap<String, Vec<FipsPeerAddressHint>>,
) -> Vec<FipsPeerConfig> {
    let mut configs = Vec::new();
    let mut included = std::collections::HashSet::new();

    for peer in peers {
        included.insert(peer.participant_pubkey.clone());
        configs.push(fips_peer_config_from_hint(
            &peer.endpoint_npub,
            peer_hints.get(&peer.participant_pubkey),
            !peer.advertises_default_route(),
        ));
    }

    for (participant, hints) in peer_hints {
        if included.contains(participant) || hints.is_empty() {
            continue;
        }
        if let Ok(peer) = FipsMeshPeerConfig::from_participant_pubkey(participant, Vec::new()) {
            configs.push(fips_peer_config_from_hint(
                &peer.endpoint_npub,
                Some(hints),
                false,
            ));
        }
    }

    configs.sort_by(|left, right| left.npub.cmp(&right.npub));
    configs.dedup_by(|left, right| left.npub == right.npub);
    configs
}

fn fips_peer_config_from_hint(
    endpoint_npub: &str,
    hints: Option<&Vec<FipsPeerAddressHint>>,
    discovery_fallback_transit: bool,
) -> FipsPeerConfig {
    let addresses = hints
        .into_iter()
        .flatten()
        .map(|hint| {
            let mut addr = PeerAddress::new("udp", hint.addr.clone());
            if let Some(seen_at_ms) = hint.seen_at_ms {
                addr = addr.with_seen_at_ms(seen_at_ms);
            }
            addr
        })
        .collect();
    FipsPeerConfig {
        npub: endpoint_npub.to_string(),
        alias: None,
        addresses,
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit,
    }
}

fn mobile_static_peer_hints(app: &AppConfig) -> HashMap<String, Vec<FipsPeerAddressHint>> {
    app.fips_static_peer_endpoints()
        .into_iter()
        .filter_map(|(participant, endpoints)| {
            let participant = normalize_nostr_pubkey(&participant).ok()?;
            let mut hints = endpoints
                .into_iter()
                .filter_map(|endpoint| {
                    let hint = PeerEndpointHint::udp(endpoint.trim().to_string());
                    peer_endpoint_hint_addr(&hint).map(|addr| FipsPeerAddressHint {
                        addr,
                        seen_at_ms: None,
                    })
                })
                .collect::<Vec<_>>();
            hints.sort_by(|left, right| left.addr.cmp(&right.addr));
            hints.dedup_by(|left, right| left.addr == right.addr);
            if hints.is_empty() {
                None
            } else {
                Some((participant, hints))
            }
        })
        .collect()
}

fn non_empty_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

fn fips_endpoint_config(scope: &str, mobile: &MobileTunnelConfig) -> FipsConfig {
    let mut config = FipsConfig::new();
    // The fips control socket binds a UNIX socket at
    // `/tmp/fips-control.sock` by default. Inside an iOS app extension
    // the sandbox forbids /tmp writes, which crashes the
    // PacketTunnelProvider before it can finish startTunnel. Android's
    // sandbox accepts it but we don't need control on mobile either —
    // there's no daemon to talk to.
    config.node.control.enabled = false;
    // iOS packet extensions can stall while starting FIPS's desktop-oriented
    // Unix worker thread pools. Mobile traffic is latency-sensitive at tunnel
    // bring-up, so keep the shared core on its inline crypto/send path.
    config.node.worker_pools_enabled = false;
    // Keep open/public discovery available but paced. Phones can easily wake
    // several stale peers at once; failed route lookups and ambient adverts
    // must back off instead of leaning on public transit nodes indefinitely.
    config.node.discovery.backoff_base_secs = FIPS_DISCOVERY_BACKOFF_BASE_SECS;
    config.node.discovery.backoff_max_secs = FIPS_DISCOVERY_BACKOFF_MAX_SECS;
    config.node.discovery.forward_min_interval_secs = FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS;
    config.node.rate_limit.handshake_resend_interval_ms = MOBILE_HANDSHAKE_RESEND_INTERVAL_MS;
    config.node.rate_limit.handshake_resend_backoff = MOBILE_HANDSHAKE_RESEND_BACKOFF;
    // Cap concurrent FIPS peers on mobile. With Open discovery the global
    // overlay can keep introducing new peers; on phones we'd rather drop
    // ambient connection attempts than burn battery talking to strangers
    // who can't put anything on our tun anyway. Desktop nodes keep fips's
    // default of 128 because they're typically on AC power and uncapped
    // bandwidth.
    config.node.limits.max_peers = MOBILE_MAX_FIPS_PEERS;
    config.node.limits.max_connections = MOBILE_MAX_FIPS_CONNECTIONS;
    config.node.limits.max_links = MOBILE_MAX_FIPS_LINKS;
    let join_request_pending = !mobile.pending_join_request_recipient.trim().is_empty()
        && mobile.pending_join_requested_at != 0;
    let nostr_enabled = mobile.join_requests_enabled
        || join_request_pending
        || !mobile.peers.is_empty()
        || !mobile.peer_hints.is_empty();
    config.node.discovery.nostr.enabled = nostr_enabled;
    // Publish only the generic `udp:nat` overlay advert so roster peers can
    // bootstrap encrypted traversal offers to mobile nodes. LAN addresses are
    // not placed in that public advert; when enabled, they are carried inside
    // encrypted traversal signaling/control frames.
    config.node.discovery.nostr.advertise = nostr_enabled;
    // Join-request mode needs Open discovery so unknown devices can reach the
    // mobile admin/requester. Otherwise keep roster discovery scoped to
    // configured peers.
    config.node.discovery.nostr.policy = if mobile.join_requests_enabled || join_request_pending {
        NostrDiscoveryPolicy::Open
    } else {
        NostrDiscoveryPolicy::ConfiguredOnly
    };
    config.node.discovery.nostr.open_discovery_max_pending =
        MOBILE_NOSTR_OPEN_DISCOVERY_MAX_PENDING;
    config.node.discovery.nostr.failure_streak_threshold = MOBILE_NOSTR_FAILURE_STREAK_THRESHOLD;
    config.node.discovery.nostr.startup_sweep_max_age_secs = FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS;
    config.node.discovery.nostr.share_local_candidates = mobile.share_local_candidates;
    config.node.discovery.lan.enabled = mobile.share_local_candidates && nostr_enabled;
    // Leave the relay-side `app` at fips-core's default ("fips-overlay-v1");
    // see fips_private_mesh::fips_endpoint_config for the rationale (the relay
    // `protocol` tag is publicly visible, so per-network apps would let any
    // observer count members of each private network). The mesh id is still
    // used as the LAN `discovery_scope` and inside FIPS handshake payloads.
    let _ = scope;
    if !mobile.nostr_relays.is_empty() {
        config
            .node
            .discovery
            .nostr
            .advert_relays
            .clone_from(&mobile.nostr_relays);
        config
            .node
            .discovery
            .nostr
            .dm_relays
            .clone_from(&mobile.nostr_relays);
    }
    if !mobile.stun_servers.is_empty() {
        config
            .node
            .discovery
            .nostr
            .stun_servers
            .clone_from(&mobile.stun_servers);
    }
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(mobile_udp_bind_addr(mobile.listen_port)),
        outbound_only: Some(false),
        accept_connections: Some(true),
        advertise_on_nostr: Some(nostr_enabled),
        public: Some(false),
        ..UdpConfig::default()
    });
    config.peers = fips_peer_configs_from_mesh(&mobile.peers, &mobile.peer_hints);
    config
}

fn native_config_path(data_dir: &str) -> PathBuf {
    let trimmed = data_dir.trim();
    if trimmed.is_empty() {
        default_config_path()
    } else {
        PathBuf::from(trimmed).join("config.toml")
    }
}

fn default_config_path() -> PathBuf {
    dirs::config_dir().map_or_else(
        || PathBuf::from("nvpn.toml"),
        |dir| dir.join("nvpn").join("config.toml"),
    )
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    let tunnel_ip = tunnel_ip.trim();
    if tunnel_ip.is_empty() {
        return "10.44.0.1/32".to_string();
    }
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn mobile_udp_bind_addr(listen_port: u16) -> String {
    format!("0.0.0.0:{listen_port}")
}

fn endpoint_with_listen_port(endpoint: &str, listen_port: u16) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
        if addr.port() != 0 || listen_port == 0 {
            return addr.to_string();
        }
        return match addr.ip() {
            std::net::IpAddr::V4(ip) => format!("{ip}:{listen_port}"),
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{listen_port}"),
        };
    }
    if trimmed.rsplit_once(':').is_some() || listen_port == 0 {
        return trimmed.to_string();
    }
    format!("{trimmed}:{listen_port}")
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn mobile_lan_ipv4_candidates(local_address: &str) -> Vec<Ipv4Addr> {
    let tunnel_ipv4 = parse_ipv4(local_address);
    let mut ips = Vec::new();
    if let Some(ip) = detect_runtime_primary_ipv4()
        && ipv4_is_lan_endpoint_hint(ip)
        && Some(ip) != tunnel_ipv4
    {
        ips.push(ip);
    }
    for iface in netdev::get_interfaces() {
        if iface.is_loopback() {
            continue;
        }
        for net in &iface.ipv4 {
            let ip = net.addr();
            if Some(ip) == tunnel_ipv4
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || !ipv4_is_lan_endpoint_hint(ip)
            {
                continue;
            }
            ips.push(ip);
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

fn endpoint_is_gossipable_direct_hint(endpoint: &str) -> bool {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return parsed.port() != 0 && !endpoint_hint_ip_is_unusable(parsed.ip());
    }

    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return false;
    };
    let host = host.trim();
    let Ok(port) = port.trim().parse::<u16>() else {
        return false;
    };
    if host.is_empty() || port == 0 || host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if host.contains(':') {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && endpoint_hint_ip_is_unusable(ip)
    {
        return false;
    }
    true
}

fn endpoint_hint_ip_is_unusable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

fn endpoint_uses_tunnel_ip(endpoint: &str, tunnel_ip: &str) -> bool {
    let Some(tunnel_ip) = parse_ipv4(tunnel_ip).map(IpAddr::V4) else {
        return false;
    };
    endpoint_addr_ip(endpoint).is_some_and(|ip| ip == tunnel_ip)
}

fn endpoint_addr_ip(endpoint: &str) -> Option<IpAddr> {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return Some(parsed.ip());
    }

    let (host, _) = trimmed.rsplit_once(':')?;
    host.trim().parse::<IpAddr>().ok()
}

fn ipv4_is_lan_endpoint_hint(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ipv4_is_mesh_tunnel_ip(ip)
}

fn ipv4_is_mesh_tunnel_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10 && octets[1] == 44
}

#[cfg(debug_assertions)]
pub(crate) fn mobile_debug_log(message: impl AsRef<str>) {
    let dir = std::env::temp_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("nvpn-mobile-debug.log");
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "{:?} {}", SystemTime::now(), message.as_ref());
}

#[cfg(not(debug_assertions))]
pub(crate) fn mobile_debug_log(_message: impl AsRef<str>) {}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    strip_cidr(value.trim()).parse().ok()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Append-once-per-line packet diagnostic to the same `tmp/nvpn-wg.log`
/// the WG pump uses, so we can correlate SNAT/DNAT events with WG
/// activity in the same timeline. iOS extension stderr/stdout is
/// /dev/null and our tracing-without-subscriber is a no-op, so a
/// file append is the simplest reliable channel.
fn log_pump_packet(message: &str) {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join("nvpn-wg.log");
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{secs:.3} mobile-pump: {message}");
        }
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let _ = message;
}

fn empty_config() -> MobileTunnelConfig {
    MobileTunnelConfig {
        config_path: String::new(),
        app_config_toml: String::new(),
        identity_nsec: String::new(),
        node_name: String::new(),
        network_id: String::new(),
        invite_secret: String::new(),
        local_address: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        mtu: DEFAULT_MOBILE_MTU,
        peers: Vec::new(),
        peer_hints: HashMap::new(),
        route_targets: Vec::new(),
        nostr_relays: Vec::new(),
        stun_servers: Vec::new(),
        share_local_candidates: false,
        excluded_routes: Vec::new(),
        dns_servers: Vec::new(),
        wireguard_exit: None,
        join_requests_enabled: false,
        pending_join_request_recipient: String::new(),
        pending_join_invite_secret: String::new(),
        pending_join_requested_at: 0,
        error: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::{NetworkConfig, PendingOutboundJoinRequest};

    #[test]
    fn mobile_config_routes_only_private_peer_addresses() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![peer.to_string()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        app.exit_node = peer.to_string();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.route_targets.len(), 2);
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        );
        let peer_route = config
            .route_targets
            .iter()
            .find(|route| route.as_str() != MESH_TUNNEL_IPV4_CIDR)
            .expect("peer route");
        assert!(peer_route.starts_with("10."));
        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );
    }

    #[test]
    fn mobile_config_includes_static_peer_hints_from_app() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![peer.to_string()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        app.fips_peer_endpoints
            .insert(peer.to_string(), vec!["192.168.50.10:51820".to_string()]);
        app.ensure_defaults();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let hints = config
            .peer_hints
            .get(peer)
            .expect("static peer hint should be serialized into mobile config");

        assert_eq!(
            hints,
            &vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
            }]
        );
    }

    #[test]
    fn mobile_config_keeps_join_request_admin_as_control_peer_without_route() {
        let admin_keys = Keys::generate();
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let admin = admin_keys.public_key().to_hex();
        let admin_npub = admin_keys.public_key().to_bech32().expect("admin npub");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: Vec::new(),
            admins: vec![admin.clone()],
            listen_for_join_requests: false,
            invite_inviter: admin.clone(),
            outbound_join_request: Some(PendingOutboundJoinRequest {
                recipient: admin.clone(),
                requested_at: 1,
            }),
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        app.fips_peer_endpoints
            .insert(admin.clone(), vec!["192.168.50.10:51820".to_string()]);
        app.ensure_defaults();

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].participant_pubkey, admin);
        assert!(config.peers[0].allowed_ips.is_empty());
        assert!(
            !config
                .route_targets
                .iter()
                .any(|route| route.starts_with("10.") && route.ends_with("/32"))
        );
        let hints = config
            .peer_hints
            .get(&admin)
            .expect("admin static hint should stay available for FIPS control");
        assert_eq!(
            hints,
            &vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
            }]
        );
        let endpoint_config = fips_peer_configs_from_mesh(&config.peers, &config.peer_hints);
        let endpoint_peer = endpoint_config
            .iter()
            .find(|peer| peer.npub == admin_npub)
            .expect("admin endpoint config");
        assert_eq!(endpoint_peer.addresses.len(), 1);
        assert_eq!(endpoint_peer.addresses[0].addr, "192.168.50.10:51820");
    }

    #[test]
    fn mobile_admin_listener_without_roster_peers_keeps_fips_discovery_enabled() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: Vec::new(),
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        app.ensure_defaults();

        let mobile = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(mobile.join_requests_enabled);
        assert!(mobile.peers.is_empty());
        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(config.peers.is_empty());
    }

    #[test]
    fn pending_mobile_join_request_targets_invite_admin() {
        let admin = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        let expected_recipient = FipsMeshPeerConfig::from_participant_pubkey(admin, Vec::new())
            .expect("recipient")
            .endpoint_npub;
        let mobile = MobileTunnelConfig {
            network_id: "mesh-home".to_string(),
            node_name: "iPhone".to_string(),
            pending_join_request_recipient: admin.to_string(),
            pending_join_requested_at: 1_778_998_000,
            ..empty_config()
        };

        let (recipient, frame) = pending_mobile_join_request_frame(&mobile)
            .expect("join request frame")
            .expect("pending frame");

        assert_eq!(recipient, expected_recipient);
        assert_eq!(
            frame,
            FipsControlFrame::JoinRequest {
                requested_at: 1_778_998_000,
                request: MeshJoinRequest {
                    network_id: "mesh-home".to_string(),
                    invite_secret: String::new(),
                    requester_node_name: "iPhone".to_string(),
                },
            }
        );
    }

    #[test]
    fn mobile_control_source_accepts_unknown_sender_only_for_join_request() {
        let roster_peer =
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc".to_string();
        let peer = FipsMeshPeerConfig::from_participant_pubkey(&roster_peer, Vec::new())
            .expect("roster peer");
        let peer_npub = peer.endpoint_npub.clone();
        let mesh = FipsMeshRuntime::with_local_routes(vec![peer], Vec::new());
        let unknown_keys = Keys::generate();
        let unknown_npub = unknown_keys.public_key().to_bech32().expect("unknown npub");
        let unknown_hex = unknown_keys.public_key().to_hex();
        let ping = FipsControlFrame::Ping {
            network_id: "mesh-home".to_string(),
            sent_at: 1,
        };
        let join_request = FipsControlFrame::JoinRequest {
            requested_at: 2,
            request: MeshJoinRequest {
                network_id: "mesh-home".to_string(),
                invite_secret: String::new(),
                requester_node_name: "iPhone".to_string(),
            },
        };

        assert_eq!(
            control_frame_source_pubkey(&mesh, Some(&peer_npub), &ping),
            Some(roster_peer)
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, Some(&unknown_npub), &ping),
            None
        );
        assert_eq!(
            control_frame_source_pubkey(&mesh, Some(&unknown_npub), &join_request),
            Some(unknown_hex)
        );
    }

    #[test]
    fn mobile_admin_records_inbound_join_request_from_unknown_sender() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-join-request-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");

        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Home".to_string(),
            enabled: true,
            network_id: "mesh-home".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![own.clone()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        let requester = Keys::generate().public_key().to_hex();
        let app_config = Arc::new(RwLock::new(app));
        let dirty = AtomicBool::new(false);
        let request = MeshJoinRequest {
            network_id: "mesh-home".to_string(),
            invite_secret: "join-secret".to_string(),
            requester_node_name: "iPhone".to_string(),
        };

        assert!(
            record_mobile_join_request(
                &app_config,
                &dirty,
                Some(&config_path),
                &requester,
                1_778_998_000,
                &request,
            )
            .expect("record join request")
        );
        assert!(dirty.load(Ordering::Relaxed));

        let saved = AppConfig::load(&config_path).expect("load persisted config");
        assert_eq!(saved.networks[0].inbound_join_requests.len(), 1);
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester,
            requester
        );
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester_node_name,
            "iPhone"
        );
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requested_at,
            1_778_998_000
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn available_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .expect("bind test port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    fn local_mobile_fips_config(scope: &str, mobile: &MobileTunnelConfig) -> FipsConfig {
        let mut config = fips_endpoint_config(scope, mobile);
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.nostr.advertise = false;
        config.node.discovery.lan.enabled = false;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(format!("127.0.0.1:{}", mobile.listen_port)),
            outbound_only: Some(false),
            accept_connections: Some(true),
            advertise_on_nostr: Some(false),
            public: Some(false),
            ..UdpConfig::default()
        });
        config
    }

    fn bind_local_mobile_endpoint<'a>(
        scope: &'a str,
        mobile: &'a MobileTunnelConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FipsEndpoint> + 'a>> {
        Box::pin(async move {
            Box::pin(
                FipsEndpoint::builder()
                    .config(local_mobile_fips_config(scope, mobile))
                    .identity_nsec(mobile.identity_nsec.clone())
                    .discovery_scope(scope.to_string())
                    .without_system_tun()
                    .bind(),
            )
            .await
            .expect("bind local mobile FIPS endpoint")
        })
    }

    fn admin_join_request_app(admin_nsec: &str, admin_pubkey: &str, network_id: &str) -> AppConfig {
        let mut admin_app = AppConfig::generated();
        admin_app.nostr.secret_key = admin_nsec.to_string();
        admin_app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Home".to_string(),
            enabled: true,
            network_id: network_id.to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![admin_pubkey.to_string()],
            admins: vec![admin_pubkey.to_string()],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        admin_app.ensure_defaults();
        admin_app
    }

    fn admin_mobile_join_request_config(
        admin_nsec: String,
        network_id: &str,
        listen_port: u16,
    ) -> MobileTunnelConfig {
        MobileTunnelConfig {
            identity_nsec: admin_nsec,
            node_name: "admin".to_string(),
            network_id: network_id.to_string(),
            local_address: "10.44.10.1/32".to_string(),
            listen_port,
            join_requests_enabled: true,
            ..empty_config()
        }
    }

    fn requester_mobile_join_request_config(
        requester_nsec: String,
        admin_pubkey: String,
        admin_port: u16,
        requester_port: u16,
        network_id: &str,
        requested_at: u64,
    ) -> MobileTunnelConfig {
        let admin_peer = FipsMeshPeerConfig::from_participant_pubkey(&admin_pubkey, Vec::new())
            .expect("admin control peer");
        let mut requester_peer_hints = HashMap::new();
        requester_peer_hints.insert(
            admin_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: format!("127.0.0.1:{admin_port}"),
                seen_at_ms: None,
            }],
        );
        MobileTunnelConfig {
            identity_nsec: requester_nsec,
            node_name: "iPhone".to_string(),
            network_id: network_id.to_string(),
            local_address: "10.44.10.2/32".to_string(),
            listen_port: requester_port,
            peers: vec![admin_peer],
            peer_hints: requester_peer_hints,
            pending_join_request_recipient: admin_pubkey,
            pending_join_invite_secret: "join-secret".to_string(),
            pending_join_requested_at: requested_at,
            ..empty_config()
        }
    }

    async fn send_pending_mobile_join_request(
        requester_endpoint: &FipsEndpoint,
        admin_endpoint: &FipsEndpoint,
        requester_mobile: &MobileTunnelConfig,
    ) -> FipsEndpointMessage {
        let (recipient_npub, frame) = pending_mobile_join_request_frame(requester_mobile)
            .expect("pending join request frame")
            .expect("pending join request should exist");
        let encoded = encode_fips_control_frame(&frame).expect("encode join request");

        for _ in 0..50 {
            requester_endpoint
                .send(recipient_npub.clone(), encoded.clone())
                .await
                .expect("send join request over FIPS");
            if let Ok(Some(message)) =
                tokio::time::timeout(Duration::from_millis(100), admin_endpoint.recv()).await
            {
                return message;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("admin should receive mobile join request over FIPS");
    }

    async fn handle_admin_mobile_join_request(
        admin_endpoint: &FipsEndpoint,
        admin_app: AppConfig,
        admin_mobile: MobileTunnelConfig,
        config_path: &Path,
        network_id: &str,
        message: &FipsEndpointMessage,
    ) -> (Arc<RwLock<AppConfig>>, AtomicBool) {
        let admin_app_config = Arc::new(RwLock::new(admin_app));
        let app_config_dirty = AtomicBool::new(false);
        let mesh = Arc::new(RwLock::new(FipsMeshRuntime::with_local_routes(
            Vec::new(),
            vec![admin_mobile.local_address.clone()],
        )));
        let mesh_peers = Arc::new(RwLock::new(Vec::new()));
        let peer_hints = Arc::new(RwLock::new(HashMap::new()));
        let presence = Arc::new(RwLock::new(HashMap::new()));
        let config_state = Arc::new(RwLock::new(admin_mobile));
        let join_request_active = AtomicBool::new(false);
        let mut control_fragments = FipsControlFragmentBuffer::default();

        let handled = handle_mobile_control_frame(
            admin_endpoint,
            &mesh,
            &mesh_peers,
            &peer_hints,
            &presence,
            &config_state,
            &admin_app_config,
            &app_config_dirty,
            Some(config_path),
            network_id,
            &join_request_active,
            &mut control_fragments,
            message,
        )
        .await
        .expect("handle mobile join request frame");

        assert!(handled);
        (admin_app_config, app_config_dirty)
    }

    #[tokio::test]
    async fn mobile_join_request_sends_and_records_over_real_fips_endpoint() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mobile-fips-join-request-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");

        let admin_keys = Keys::generate();
        let requester_keys = Keys::generate();
        let admin_nsec = admin_keys.secret_key().to_bech32().expect("admin nsec");
        let requester_nsec = requester_keys
            .secret_key()
            .to_bech32()
            .expect("requester nsec");
        let admin_pubkey = admin_keys.public_key().to_hex();
        let requester_pubkey = requester_keys.public_key().to_hex();
        let network_id = format!("mobile-fips-join-{nonce}");
        let requested_at = 1_778_998_000;
        let scope = format!("nostr-vpn:{network_id}");

        let admin_app = admin_join_request_app(&admin_nsec, &admin_pubkey, &network_id);
        let admin_mobile =
            admin_mobile_join_request_config(admin_nsec, &network_id, available_udp_port());
        let admin_endpoint = bind_local_mobile_endpoint(&scope, &admin_mobile).await;
        let requester_mobile = requester_mobile_join_request_config(
            requester_nsec,
            admin_pubkey,
            admin_mobile.listen_port,
            available_udp_port(),
            &network_id,
            requested_at,
        );
        let requester_endpoint = bind_local_mobile_endpoint(&scope, &requester_mobile).await;

        let message = send_pending_mobile_join_request(
            &requester_endpoint,
            &admin_endpoint,
            &requester_mobile,
        )
        .await;
        assert_eq!(
            message.source_npub.as_deref(),
            Some(requester_endpoint.npub())
        );
        let (admin_app_config, app_config_dirty) = handle_admin_mobile_join_request(
            &admin_endpoint,
            admin_app,
            admin_mobile,
            &config_path,
            &network_id,
            &message,
        )
        .await;

        assert!(app_config_dirty.load(Ordering::Relaxed));
        {
            let saved = admin_app_config.read().expect("admin app config");
            let inbound = &saved.networks[0].inbound_join_requests;
            assert_eq!(inbound.len(), 1);
            assert_eq!(inbound[0].requester, requester_pubkey);
            assert_eq!(inbound[0].requester_node_name, "iPhone");
            assert_eq!(inbound[0].requested_at, requested_at);
        }
        let saved = AppConfig::load(&config_path).expect("load persisted admin config");
        assert_eq!(saved.networks[0].inbound_join_requests.len(), 1);
        assert_eq!(
            saved.networks[0].inbound_join_requests[0].requester,
            requester_pubkey
        );

        requester_endpoint
            .shutdown()
            .await
            .expect("shutdown requester endpoint");
        admin_endpoint
            .shutdown()
            .await
            .expect("shutdown admin endpoint");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mobile_runtime_state_marks_authenticated_endpoint_peer_reachable() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![peer.to_string()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = FipsMeshRuntime::with_local_routes(config.peers.clone(), vec![]);
        let endpoint_peer = FipsEndpointPeer {
            npub: config.peers[0].endpoint_npub.clone(),
            transport_addr: Some("192.168.50.10:51820".to_string()),
            transport_type: Some("udp".to_string()),
            link_id: 7,
            srtt_ms: Some(14),
            packets_sent: 3,
            packets_recv: 4,
            bytes_sent: 120,
            bytes_recv: 240,
        };

        let state = mobile_runtime_state(
            &config,
            &mesh,
            &HashMap::new(),
            vec![endpoint_peer],
            Vec::new(),
            1_778_998_000,
        );

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 1);
        assert!(state.mesh_ready);
        assert_eq!(state.peers[0].participant_pubkey, peer);
        assert!(state.peers[0].reachable);
        assert_eq!(state.peers[0].fips_transport_type, "udp");
        assert_eq!(state.peers[0].fips_srtt_ms, Some(14));
    }

    #[test]
    fn mobile_runtime_state_marks_recent_control_presence_reachable_without_link() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![peer.to_string()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");
        let mesh = FipsMeshRuntime::with_local_routes(config.peers.clone(), vec![]);
        let now = 1_778_998_000;
        let mut presence = HashMap::new();
        presence.insert(
            peer.to_string(),
            MobilePeerPresence {
                last_seen_at: Some(now - 10),
                rtt_ms: Some(91),
                tx_bytes: 32,
                rx_bytes: 64,
                ..MobilePeerPresence::default()
            },
        );

        let state = mobile_runtime_state(&config, &mesh, &presence, Vec::new(), Vec::new(), now);

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 1);
        assert!(state.mesh_ready);
        assert!(state.peers[0].reachable);
        assert_eq!(state.peers[0].fips_srtt_ms, Some(91));
        assert_eq!(state.peers[0].tx_bytes, 32);
        assert_eq!(state.peers[0].rx_bytes, 64);
        assert_eq!(state.peers[0].last_fips_seen_at, Some(now - 10));
    }

    #[test]
    fn mobile_endpoint_hints_include_current_lan_candidates() {
        let mobile = MobileTunnelConfig {
            advertised_endpoint: "192.168.50.22:51820".to_string(),
            listen_port: 51820,
            local_address: "10.44.1.2/32".to_string(),
            share_local_candidates: true,
            ..empty_config()
        };

        let hints = mobile_endpoint_hints_with_candidates(
            &mobile,
            vec![
                Ipv4Addr::new(192, 168, 50, 33),
                Ipv4Addr::new(10, 44, 1, 2),
                Ipv4Addr::new(100, 100, 50, 1),
            ],
        );
        let addrs = hints.into_iter().map(|hint| hint.addr).collect::<Vec<_>>();

        assert_eq!(
            addrs,
            vec![
                "192.168.50.22:51820".to_string(),
                "192.168.50.33:51820".to_string(),
            ]
        );
    }

    #[test]
    fn mobile_config_wireguard_exit_keeps_mesh_peer_routes_narrow() {
        let mut app = AppConfig::generated();
        app.ensure_defaults();
        let own = app.own_nostr_pubkey_hex().expect("own pubkey");
        let peer = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        app.networks = vec![NetworkConfig {
            id: "test".to_string(),
            name: "Test".to_string(),
            enabled: true,
            network_id: "test".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: vec![peer.to_string()],
            admins: vec![own],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            relay_record: None,
        }];
        app.wireguard_exit = WireGuardExitConfig {
            enabled: true,
            address: "10.99.99.2/32".to_string(),
            private_key: "client-private-key".to_string(),
            peer_public_key: "server-public-key".to_string(),
            endpoint: "198.51.100.20:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            ..WireGuardExitConfig::default()
        };

        let config = MobileTunnelConfig::from_app(&app).expect("mobile config");

        assert_eq!(config.peers.len(), 1);
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == MESH_TUNNEL_IPV4_CIDR)
        );
        assert!(
            config
                .route_targets
                .iter()
                .any(|route| route == "0.0.0.0/0")
        );

        let peer_routes = config
            .route_targets
            .iter()
            .filter(|route| route.as_str() != "0.0.0.0/0")
            .filter(|route| route.as_str() != MESH_TUNNEL_IPV4_CIDR)
            .collect::<Vec<_>>();
        assert_eq!(peer_routes.len(), 1);
        assert!(peer_routes[0].starts_with("10."));
        assert!(peer_routes[0].ends_with("/32"));
        assert_eq!(config.peers[0].allowed_ips, vec![peer_routes[0].clone()]);

        let wg_config = config.wireguard_exit.as_ref().expect("wg config");
        assert_eq!(wg_config.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(wg_config.persistent_keepalive_secs, 25);
        assert_eq!(config.excluded_routes, vec!["198.51.100.20/32"]);
        assert_eq!(config.dns_servers, vec!["10.64.0.1"]);
    }

    #[test]
    fn mobile_config_json_reports_errors_as_json() {
        let json = tunnel_config_json("\0/not-a-path");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert!(value["error"].as_str().is_some());
    }

    #[test]
    fn mobile_fips_config_uses_discovery_for_roster_peers() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer");
        let mobile = MobileTunnelConfig {
            peers: vec![peer],
            advertised_endpoint: "192.168.50.22".to_string(),
            listen_port: 51820,
            nostr_relays: vec!["wss://relay.example".to_string()],
            stun_servers: vec!["stun:stun.example:3478".to_string()],
            share_local_candidates: true,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        config
            .validate()
            .expect("mobile FIPS config should validate");
        assert_eq!(
            config.node.discovery.backoff_base_secs,
            FIPS_DISCOVERY_BACKOFF_BASE_SECS
        );
        assert_eq!(
            config.node.discovery.backoff_max_secs,
            FIPS_DISCOVERY_BACKOFF_MAX_SECS
        );
        assert_eq!(
            config.node.discovery.forward_min_interval_secs,
            FIPS_DISCOVERY_FORWARD_MIN_INTERVAL_SECS
        );
        assert_eq!(
            config.node.rate_limit.handshake_resend_interval_ms,
            MOBILE_HANDSHAKE_RESEND_INTERVAL_MS
        );
        assert!(
            (config.node.rate_limit.handshake_resend_backoff - MOBILE_HANDSHAKE_RESEND_BACKOFF)
                .abs()
                < f64::EPSILON
        );
        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert!(config.node.discovery.nostr.share_local_candidates);
        assert!(config.node.discovery.lan.enabled);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert_eq!(
            config.node.discovery.nostr.open_discovery_max_pending,
            MOBILE_NOSTR_OPEN_DISCOVERY_MAX_PENDING
        );
        assert_eq!(
            config.node.discovery.nostr.failure_streak_threshold,
            MOBILE_NOSTR_FAILURE_STREAK_THRESHOLD
        );
        assert_eq!(
            config.node.discovery.nostr.startup_sweep_max_age_secs,
            FIPS_NOSTR_STARTUP_SWEEP_MAX_AGE_SECS
        );
        // The mesh id must NOT appear in the publicly visible relay app tag.
        assert_eq!(config.node.discovery.nostr.app, FIPS_NOSTR_DISCOVERY_APP);
        assert_eq!(
            config.node.discovery.nostr.advert_relays,
            vec!["wss://relay.example".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.dm_relays,
            vec!["wss://relay.example".to_string()]
        );
        assert_eq!(
            config.node.discovery.nostr.stun_servers,
            vec!["stun:stun.example:3478".to_string()]
        );
        let TransportInstances::Single(udp) = &config.transports.udp else {
            panic!("expected single udp transport");
        };
        assert_eq!(udp.bind_addr(), "0.0.0.0:51820");
        assert!(!udp.outbound_only());
        assert!(udp.accept_connections());
        assert!(udp.advertise_on_nostr());
        assert!(!udp.is_public());
        assert_eq!(
            mobile_endpoint_hints_with_candidates(&mobile, Vec::new()),
            vec![PeerEndpointHint::udp("192.168.50.22:51820")]
        );
        assert_eq!(config.peers.len(), 1);
        // Mobile peer caps are clamped well below fips's defaults so Open
        // discovery doesn't burn battery on ambient connections.
        assert_eq!(config.node.limits.max_peers, MOBILE_MAX_FIPS_PEERS);
        assert_eq!(
            config.node.limits.max_connections,
            MOBILE_MAX_FIPS_CONNECTIONS
        );
        assert_eq!(config.node.limits.max_links, MOBILE_MAX_FIPS_LINKS);
        assert!(config.peers[0].discovery_fallback_transit);
    }

    #[test]
    fn mobile_fips_config_marks_default_route_peers_non_transit() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string(), "0.0.0.0/0".to_string()],
        )
        .expect("peer");
        let mobile = MobileTunnelConfig {
            peers: vec![peer.clone()],
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let peer_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == peer.endpoint_npub)
            .expect("exit peer");

        assert!(
            !peer_config.discovery_fallback_transit,
            "exit/default-route peers should not receive ambient lookup transit"
        );
    }

    #[test]
    fn mobile_fips_config_uses_static_peer_hints() {
        let peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("peer");
        let mut peer_hints = HashMap::new();
        peer_hints.insert(
            peer.participant_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: "192.168.50.10:51820".to_string(),
                seen_at_ms: None,
            }],
        );
        let mobile = MobileTunnelConfig {
            peers: vec![peer.clone()],
            peer_hints,
            nostr_relays: vec!["wss://relay.example".to_string()],
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let peer_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == peer.endpoint_npub)
            .expect("seeded peer");

        assert_eq!(peer_config.addresses.len(), 1);
        assert_eq!(peer_config.addresses[0].transport, "udp");
        assert_eq!(peer_config.addresses[0].addr, "192.168.50.10:51820");
    }

    #[test]
    fn mobile_fips_config_keeps_hinted_non_roster_peers() {
        let roster_peer = FipsMeshPeerConfig::from_participant_pubkey(
            "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc",
            vec!["10.44.22.44/32".to_string()],
        )
        .expect("roster peer");
        let transit_peer = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("transit pubkey");
        let transit = FipsMeshPeerConfig::from_participant_pubkey(transit_peer, Vec::new())
            .expect("transit peer");
        let mut peer_hints = HashMap::new();
        peer_hints.insert(
            transit.participant_pubkey.clone(),
            vec![FipsPeerAddressHint {
                addr: "192.168.50.33:51820".to_string(),
                seen_at_ms: Some(1234),
            }],
        );
        let mobile = MobileTunnelConfig {
            peers: vec![roster_peer],
            peer_hints,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);
        let transit_config = config
            .peers
            .iter()
            .find(|candidate| candidate.npub == transit.endpoint_npub)
            .expect("hinted non-roster peer should seed FIPS");

        assert_eq!(transit_config.addresses.len(), 1);
        assert_eq!(transit_config.addresses[0].transport, "udp");
        assert_eq!(transit_config.addresses[0].addr, "192.168.50.33:51820");
        assert_eq!(transit_config.addresses[0].seen_at_ms, Some(1234));
        assert!(
            !transit_config.discovery_fallback_transit,
            "hinted non-roster peers seed direct reconnects but not fallback fanout"
        );
    }

    #[test]
    fn mobile_fips_config_does_not_advertise_without_peers() {
        let config = fips_endpoint_config("nostr-vpn:test", &empty_config());

        config
            .validate()
            .expect("empty mobile FIPS config should validate");
        assert!(!config.node.discovery.nostr.enabled);
        assert!(!config.node.discovery.nostr.advertise);
        assert!(!config.node.discovery.lan.enabled);
        let TransportInstances::Single(udp) = &config.transports.udp else {
            panic!("expected single udp transport");
        };
        assert!(!udp.advertise_on_nostr());
        assert!(udp.accept_connections());
        assert!(config.peers.is_empty());
    }

    #[test]
    fn mobile_fips_config_uses_discovery_for_pending_join_request_without_peers() {
        let admin = Keys::generate().public_key().to_hex();
        let mobile = MobileTunnelConfig {
            pending_join_request_recipient: admin,
            pending_join_requested_at: 1,
            ..empty_config()
        };
        let config = fips_endpoint_config("nostr-vpn:test", &mobile);

        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(config.peers.is_empty());
    }
}
