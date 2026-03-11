use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Args, Parser, Subcommand};
use hex::encode as encode_hex;
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, derive_network_id_from_participants, maybe_autoconfigure_node,
    normalize_advertised_route, normalize_nostr_pubkey,
};
use nostr_vpn_core::control::{PeerAnnouncement, select_peer_endpoint};
use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::magic_dns::{
    MagicDnsResolverConfig, MagicDnsServer, build_magic_dns_records, install_system_resolver,
    uninstall_system_resolver,
};
use nostr_vpn_core::nat::{
    discover_public_udp_endpoint, discover_public_udp_endpoint_via_stun, hole_punch_udp,
};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalEnvelope, SignalPayload};
use nostr_vpn_core::wireguard::{InterfaceConfig, PeerConfig, render_wireguard_config};
use serde::{Deserialize, Serialize};
use serde_json::json;

const DAEMON_CONTROL_STOP_REQUEST: &str = "stop";
const DAEMON_CONTROL_RELOAD_REQUEST: &str = "reload";
const DAEMON_CONTROL_PAUSE_REQUEST: &str = "pause";
const DAEMON_CONTROL_RESUME_REQUEST: &str = "resume";
const TUNNEL_HEARTBEAT_PORT: u16 = 9;
const PRIMARY_LISTEN_PORT_RETRY_ATTEMPTS: usize = 40;
const PRIMARY_LISTEN_PORT_RETRY_DELAY_MS: u64 = 100;
const POST_PUNCH_REAPPLY_DELAY_MS: u64 = 1_000;
const MIN_PEER_SIGNAL_TIMEOUT_SECS: u64 = 20;
const PEER_SIGNAL_TIMEOUT_MULTIPLIER: u64 = 3;
const MIN_PEER_PATH_CACHE_TIMEOUT_SECS: u64 = 60;
const PEER_PATH_CACHE_TIMEOUT_MULTIPLIER: u64 = 3;
const PEER_PATH_RETRY_AFTER_SECS: u64 = 5;
const PEER_ONLINE_GRACE_SECS: u64 = 20;
const DIRECT_MESH_BOOTSTRAP_RELAY_DELAY_SECS: u64 = 5;
const MIN_PERSISTED_PEER_CACHE_TIMEOUT_SECS: u64 = 600;
const PERSISTED_PEER_CACHE_TIMEOUT_MULTIPLIER: u64 = 30;
const MIN_PERSISTED_PATH_CACHE_TIMEOUT_SECS: u64 = 1_800;
const PERSISTED_PATH_CACHE_TIMEOUT_MULTIPLIER: u64 = 90;
const MESH_READY_RELAYS_PAUSED_STATUS: &str = "Mesh ready (relays paused)";
#[cfg(target_os = "macos")]
const MACOS_SERVICE_LABEL: &str = "to.nostrvpn.nvpn";
#[cfg(target_os = "linux")]
const LINUX_SERVICE_UNIT_NAME: &str = "nvpn.service";
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_NAME: &str = "NvpnService";
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_DISPLAY_NAME: &str = "Nostr VPN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonControlRequest {
    Stop,
    Reload,
    Pause,
    Resume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayConnectionAction {
    KeepConnected,
    PauseForMesh,
    StayPausedForMesh,
    ReconnectWhenDue,
}

impl DaemonControlRequest {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stop => DAEMON_CONTROL_STOP_REQUEST,
            Self::Reload => DAEMON_CONTROL_RELOAD_REQUEST,
            Self::Pause => DAEMON_CONTROL_PAUSE_REQUEST,
            Self::Resume => DAEMON_CONTROL_RESUME_REQUEST,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            DAEMON_CONTROL_STOP_REQUEST => Some(Self::Stop),
            DAEMON_CONTROL_RELOAD_REQUEST => Some(Self::Reload),
            DAEMON_CONTROL_PAUSE_REQUEST => Some(Self::Pause),
            DAEMON_CONTROL_RESUME_REQUEST => Some(Self::Resume),
            _ => None,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "nvpn")]
#[command(about = "Nostr-signaled WireGuard control plane built on boringtun")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a local config file (keys are generated automatically).
    Init {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        /// Participant Nostr pubkeys (npub or hex) that define the network.
        #[arg(long = "participant")]
        participants: Vec<String>,
    },
    /// Generate a boringtun-compatible keypair.
    Keygen {
        #[arg(long)]
        json: bool,
    },
    /// Install `nvpn` into PATH (default: /usr/local/bin/nvpn).
    InstallCli(InstallCliArgs),
    /// Remove an `nvpn` binary previously installed into PATH.
    UninstallCli(UninstallCliArgs),
    /// Manage the persistent system daemon service.
    Service(ServiceArgs),
    /// Bring the node up (publish presence and optionally discover peers).
    Up(UpArgs),
    /// Start a session (foreground by default, or daemonized with --daemon).
    Start(StartArgs),
    /// Stop a background daemon started by `nvpn start --daemon`.
    Stop(StopArgs),
    /// Ask the running daemon to reload config and peer set.
    Reload(ReloadArgs),
    /// Pause VPN networking while keeping daemon running.
    Pause(ControlArgs),
    /// Resume VPN networking on a running daemon.
    Resume(ControlArgs),
    /// Run a full data-plane session from config (presence + boringtun tunnel).
    Connect(ConnectArgs),
    /// Bring the node down (publish disconnect signal).
    Down(DownArgs),
    /// Show local and discovered peer status.
    Status(StatusArgs),
    /// Update persisted node/network settings.
    Set(SetArgs),
    /// Ping a peer by node ID or tunnel IP.
    Ping(PingArgs),
    /// Check relay reachability and latency.
    Netcheck(NetcheckArgs),
    /// Show local or peer tunnel IPs.
    Ip(IpArgs),
    /// Resolve a node/tunnel IP to peer metadata.
    Whois(WhoisArgs),
    /// Broadcast this node's presence signal over Nostr.
    Announce {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
        #[arg(long = "participant")]
        participants: Vec<String>,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        tunnel_ip: Option<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        relay: Vec<String>,
    },
    /// Listen for peer presence signals.
    Listen {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
        #[arg(long = "participant")]
        participants: Vec<String>,
        #[arg(long)]
        relay: Vec<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Render a WireGuard config from local values and peer tuples.
    RenderWg {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Format: <public_key>,<allowed_ips>,<endpoint>
        #[arg(long = "peer")]
        peers: Vec<String>,
    },
    /// Discover your public UDP endpoint through a reflector.
    NatDiscover(NatDiscoverArgs),
    /// Send UDP punch packets to a peer endpoint to open NAT mappings.
    HolePunch(HolePunchArgs),
    /// Internal daemon entrypoint. Use `nvpn start --daemon`.
    #[command(hide = true)]
    Daemon(DaemonArgs),
    /// Internal low-level tunnel helper for e2e scripts.
    #[command(hide = true)]
    TunnelUp(TunnelUpArgs),
}

#[derive(Debug, Args)]
struct InstallCliArgs {
    /// Destination path for the installed executable.
    #[arg(long)]
    path: Option<PathBuf>,
    /// Overwrite destination if it already exists.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct UninstallCliArgs {
    /// Path to remove (defaults to /usr/local/bin/nvpn).
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Install and start the macOS launchd daemon.
    Install(ServiceInstallArgs),
    /// Enable and start an installed system service.
    Enable(ServiceControlArgs),
    /// Stop and disable an installed system service.
    Disable(ServiceControlArgs),
    /// Remove the macOS launchd daemon.
    Uninstall(ServiceUninstallArgs),
    /// Show service install/runtime status.
    Status(ServiceStatusArgs),
}

#[derive(Debug, Args)]
struct ServiceInstallArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "utun100")]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ServiceUninstallArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServiceStatusArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ServiceControlArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TunnelUpArgs {
    #[arg(long)]
    iface: String,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    listen_port: u16,
    #[arg(long)]
    address: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    peer_endpoint: String,
    #[arg(long)]
    peer_allowed_ip: String,
    #[arg(long, default_value_t = 5)]
    keepalive_secs: u16,
    #[arg(long, default_value_t = 0)]
    hole_punch_attempts: u32,
    #[arg(long, default_value_t = 120)]
    hole_punch_interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    hole_punch_recv_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct UpArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    tunnel_ip: Option<String>,
    #[arg(long)]
    public_key: Option<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value = "utun100")]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
}

#[derive(Debug, Args)]
struct DaemonArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value = "utun100")]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
}

#[derive(Debug, Args)]
struct StartArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value = "utun100")]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
    #[arg(long)]
    daemon: bool,
    #[arg(long, conflicts_with = "no_connect")]
    connect: bool,
    #[arg(long, conflicts_with = "connect")]
    no_connect: bool,
}

#[derive(Debug, Args)]
struct StopArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ReloadArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ControlArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DownArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SetArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long)]
    magic_dns_suffix: Option<String>,
    #[arg(long)]
    node_name: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    tunnel_ip: Option<String>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    exit_node: Option<String>,
    #[arg(long)]
    advertise_routes: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    advertise_exit_node: Option<bool>,
    #[arg(long)]
    auto_disconnect_relays_when_mesh_ready: Option<bool>,
    #[arg(long)]
    autoconnect: Option<bool>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PingArgs {
    target: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long, default_value_t = 3)]
    count: u32,
    #[arg(long, default_value_t = 2)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct NetcheckArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 4)]
    timeout_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IpArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    peer: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct WhoisArgs {
    query: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct NatDiscoverArgs {
    /// Reflector UDP endpoint (e.g. 198.51.100.1:3478).
    #[arg(long)]
    reflector: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    #[arg(long, default_value_t = 2)]
    timeout_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HolePunchArgs {
    #[arg(long)]
    peer_endpoint: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    #[arg(long, default_value_t = 40)]
    attempts: u32,
    #[arg(long, default_value_t = 120)]
    interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    recv_timeout_ms: u64,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            config,
            force,
            participants,
        } => {
            let path = config.unwrap_or_else(default_config_path);
            init_config(&path, force, participants)?;
        }
        Command::Keygen { json } => {
            let pair = generate_keypair();
            if json {
                println!("{}", serde_json::to_string_pretty(&pair)?);
            } else {
                println!("private_key={}", pair.private_key);
                println!("public_key={}", pair.public_key);
            }
        }
        Command::InstallCli(args) => {
            install_cli(args)?;
        }
        Command::UninstallCli(args) => {
            uninstall_cli(args)?;
        }
        Command::Service(args) => {
            run_service_command(args)?;
        }
        Command::Up(args) => {
            let announce = publish_announcement(AnnounceRequest {
                config: args.config,
                network_id: args.network_id,
                participants: args.participants,
                node_id: args.node_id,
                endpoint: args.endpoint,
                tunnel_ip: args.tunnel_ip,
                public_key: args.public_key,
                relay: args.relay,
            })
            .await?;

            let peers = if args.discover_secs > 0 {
                discover_peers(
                    &announce.app,
                    &announce.network_id,
                    &announce.relays,
                    args.discover_secs,
                )
                .await?
            } else {
                Vec::new()
            };

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "up",
                        "network_id": announce.network_id,
                        "relays": announce.relays,
                        "announcement": announce.announcement,
                        "peers": peers,
                    }))?
                );
            } else {
                println!(
                    "up: published presence on {} relays for network {}",
                    announce.relays.len(),
                    announce.network_id
                );
                if !peers.is_empty() {
                    println!("discovered_peers={}", peers.len());
                }
            }
        }
        Command::Start(args) => {
            start_session(args).await?;
        }
        Command::Stop(args) => {
            stop_daemon(args)?;
        }
        Command::Reload(args) => {
            reload_daemon(args)?;
        }
        Command::Pause(args) => {
            control_daemon(args, DaemonControlRequest::Pause)?;
        }
        Command::Resume(args) => {
            control_daemon(args, DaemonControlRequest::Resume)?;
        }
        Command::Connect(args) => {
            connect_session(args).await?;
        }
        Command::Down(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let node_id = args.node_id.unwrap_or_else(|| app.node.id.clone());
            let relays = resolve_relays(&args.relay, &app);

            let client = NostrSignalingClient::from_secret_key(
                network_id.clone(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(&relays).await?;
            client
                .publish(SignalPayload::Disconnect {
                    node_id: node_id.clone(),
                })
                .await
                .context("failed to publish disconnect signal")?;
            client.disconnect().await;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "down",
                        "network_id": network_id,
                        "node_id": node_id,
                        "relays": relays,
                    }))?
                );
            } else {
                println!(
                    "down: published disconnect for {} on {} relays",
                    node_id,
                    relays.len()
                );
            }
        }
        Command::Status(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let daemon = daemon_status(&config_path)?;

            let (peers, expected_peers, peer_count, mesh_ready, status_source) = if daemon.running {
                if let Some(state) = daemon.state.clone() {
                    let peers = state
                        .peers
                        .iter()
                        .filter(|peer| !peer.node_id.is_empty())
                        .map(|peer| PeerAnnouncement {
                            node_id: peer.node_id.clone(),
                            public_key: peer.public_key.clone(),
                            endpoint: peer.endpoint.clone(),
                            local_endpoint: None,
                            public_endpoint: None,
                            tunnel_ip: peer.tunnel_ip.clone(),
                            advertised_routes: peer.advertised_routes.clone(),
                            timestamp: peer.presence_timestamp,
                        })
                        .collect::<Vec<_>>();
                    (
                        peers,
                        state.expected_peer_count,
                        state.connected_peer_count,
                        state.mesh_ready,
                        "daemon",
                    )
                } else {
                    let peers =
                        discover_peers(&app, &network_id, &relays, args.discover_secs).await?;
                    let expected = expected_peer_count(&app);
                    let mesh = expected > 0 && peers.len() >= expected;
                    (peers.clone(), expected, peers.len(), mesh, "probe")
                }
            } else {
                let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;
                let expected = expected_peer_count(&app);
                let mesh = expected > 0 && peers.len() >= expected;
                (peers.clone(), expected, peers.len(), mesh, "probe")
            };

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status_source": status_source,
                        "network_id": network_id,
                        "magic_dns_suffix": app.magic_dns_suffix,
                        "autoconnect": app.autoconnect,
                        "node_id": app.node.id,
                        "tunnel_ip": app.node.tunnel_ip,
                        "endpoint": app.node.endpoint,
                        "exit_node": if app.exit_node.is_empty() {
                            None::<String>
                        } else {
                            Some(app.exit_node.clone())
                        },
                        "advertise_exit_node": app.node.advertise_exit_node,
                        "advertised_routes": app.node.advertised_routes,
                        "effective_advertised_routes": app.effective_advertised_routes(),
                        "relays": relays,
                        "auto_disconnect_relays_when_mesh_ready": app.auto_disconnect_relays_when_mesh_ready,
                        "daemon": daemon_status_json(&config_path)?,
                        "expected_peer_count": expected_peers,
                        "peer_count": peer_count,
                        "mesh_ready": mesh_ready,
                        "peers": peers,
                    }))?
                );
            } else {
                println!("network: {network_id}");
                println!("magic_dns_suffix: {}", app.magic_dns_suffix);
                println!("autoconnect: {}", app.autoconnect);
                println!("node: {}", app.node.id);
                println!("tunnel_ip: {}", app.node.tunnel_ip);
                println!("endpoint: {}", app.node.endpoint);
                if app.exit_node.is_empty() {
                    println!("exit_node: none");
                } else {
                    println!("exit_node: {}", app.exit_node);
                }
                println!("advertise_exit_node: {}", app.node.advertise_exit_node);
                let effective_routes = app.effective_advertised_routes();
                if effective_routes.is_empty() {
                    println!("advertised_routes: none");
                } else {
                    println!("advertised_routes: {}", effective_routes.join(", "));
                }
                println!("relays: {}", relays.len());
                if daemon.running {
                    println!("daemon: running (pid {})", daemon.pid.unwrap_or_default());
                    if let Some(state) = daemon.state.as_ref() {
                        println!("session_status: {}", state.session_status);
                    }
                } else {
                    println!("daemon: stopped");
                }
                println!("status_source: {status_source}");
                println!(
                    "relay_policy: {}",
                    if app.auto_disconnect_relays_when_mesh_ready {
                        "auto_disconnect_on_mesh_ready"
                    } else {
                        "keep_connected"
                    }
                );
                if expected_peers > 0 {
                    println!("mesh_progress: {}/{}", peer_count, expected_peers);
                    println!("mesh_ready: {mesh_ready}");
                }
                println!("peers: {}", peers.len());
                for peer in peers {
                    if peer.advertised_routes.is_empty() {
                        println!("  {} {} {}", peer.node_id, peer.tunnel_ip, peer.endpoint);
                    } else {
                        println!(
                            "  {} {} {} routes={}",
                            peer.node_id,
                            peer.tunnel_ip,
                            peer.endpoint,
                            peer.advertised_routes.join(",")
                        );
                    }
                }
            }
        }
        Command::Set(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;

            if let Some(value) = args.network_id {
                app.network_id = value;
            }
            if let Some(value) = args.magic_dns_suffix {
                app.magic_dns_suffix = value;
            }
            if let Some(value) = args.node_name {
                app.node_name = value;
            }
            if let Some(value) = args.node_id {
                app.node.id = value;
            }
            if let Some(value) = args.endpoint {
                app.node.endpoint = value;
            }
            if let Some(value) = args.tunnel_ip {
                app.node.tunnel_ip = value;
            }
            if let Some(value) = args.listen_port {
                app.node.listen_port = value;
            }
            if let Some(value) = args.exit_node {
                app.exit_node = parse_exit_node_arg(&value)?.unwrap_or_default();
            }
            if let Some(value) = args.advertise_routes {
                app.node.advertised_routes = parse_advertised_routes_arg(&value)?;
            }
            if let Some(value) = args.advertise_exit_node {
                app.node.advertise_exit_node = value;
            }
            if let Some(value) = args.auto_disconnect_relays_when_mesh_ready {
                app.auto_disconnect_relays_when_mesh_ready = value;
            }
            if let Some(value) = args.autoconnect {
                app.autoconnect = value;
            }
            if !args.relays.is_empty() {
                app.nostr.relays = args.relays;
            }
            apply_participants_override(&mut app, args.participants)?;
            app.ensure_defaults();
            maybe_autoconfigure_node(&mut app);
            app.save(&config_path)?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&app)?);
            } else {
                println!("saved {}", config_path.display());
                println!("network_id={}", app.effective_network_id());
                println!("node_id={}", app.node.id);
            }
        }
        Command::Ping(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;

            let target = resolve_ping_target(&args.target, &peers).ok_or_else(|| {
                anyhow!("target '{}' did not match an IP or known peer", args.target)
            })?;

            run_ping(&target, args.count, args.timeout_secs)?;
        }
        Command::Netcheck(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let checks = run_netcheck(&app, &network_id, &relays, args.timeout_secs).await;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&checks)?);
            } else {
                for check in &checks {
                    if let Some(error) = &check.error {
                        println!("relay {}: down ({error})", check.relay);
                    } else {
                        println!("relay {}: up ({} ms)", check.relay, check.latency_ms);
                    }
                }
                let ok = checks.iter().filter(|item| item.error.is_none()).count();
                println!("summary: {ok}/{} relays reachable", checks.len());
            }
        }
        Command::Ip(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;

            if !args.peer {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "node_id": app.node.id,
                            "tunnel_ip": app.node.tunnel_ip,
                            "ip": strip_cidr(&app.node.tunnel_ip),
                        }))?
                    );
                } else {
                    println!("{}", strip_cidr(&app.node.tunnel_ip));
                }
            } else {
                let relays = resolve_relays(&args.relay, &app);
                let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;
                let peer_ips: Vec<String> = peers
                    .iter()
                    .map(|peer| strip_cidr(&peer.tunnel_ip).to_string())
                    .collect();
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&peer_ips)?);
                } else {
                    for ip in peer_ips {
                        println!("{ip}");
                    }
                }
            }
        }
        Command::Whois(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;

            let found = peers
                .iter()
                .find(|peer| {
                    peer.node_id == args.query
                        || peer.public_key == args.query
                        || peer.tunnel_ip == args.query
                        || strip_cidr(&peer.tunnel_ip) == args.query
                })
                .cloned();

            let Some(peer) = found else {
                return Err(anyhow!("no peer found for '{}'", args.query));
            };

            if args.json {
                println!("{}", serde_json::to_string_pretty(&peer)?);
            } else {
                println!("node_id={}", peer.node_id);
                println!("public_key={}", peer.public_key);
                println!("tunnel_ip={}", peer.tunnel_ip);
                println!("endpoint={}", peer.endpoint);
                println!("timestamp={}", peer.timestamp);
            }
        }
        Command::Announce {
            config,
            network_id,
            participants,
            node_id,
            endpoint,
            tunnel_ip,
            public_key,
            relay,
        } => {
            let announce = publish_announcement(AnnounceRequest {
                config,
                network_id,
                participants,
                node_id,
                endpoint,
                tunnel_ip,
                public_key,
                relay,
            })
            .await?;
            println!(
                "published presence on {} relays for network {network_id}",
                announce.relays.len(),
                network_id = announce.network_id
            );
        }
        Command::Listen {
            config,
            network_id,
            participants,
            relay,
            limit,
        } => {
            let config_path = config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;

            apply_participants_override(&mut app, participants)?;
            if let Some(network_id) = network_id {
                app.network_id = network_id;
            }

            let network_id = app.effective_network_id();
            let relays = resolve_relays(&relay, &app);

            let client = NostrSignalingClient::from_secret_key(
                network_id.clone(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(&relays).await?;

            let mut seen = 0_usize;
            loop {
                let Some(message) = client.recv().await else {
                    break;
                };

                println!("{}", serde_json::to_string_pretty(&message)?);

                seen += 1;
                if let Some(limit) = limit
                    && seen >= limit
                {
                    break;
                }
            }

            client.disconnect().await;
        }
        Command::NatDiscover(args) => {
            let reflector: SocketAddr = args
                .reflector
                .parse()
                .with_context(|| format!("invalid --reflector {}", args.reflector))?;
            let timeout = Duration::from_secs(args.timeout_secs.max(1));
            let public_endpoint =
                discover_public_udp_endpoint(reflector, args.listen_port, timeout)
                    .context("nat endpoint discovery failed")?;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "reflector": reflector.to_string(),
                        "listen_port": args.listen_port,
                        "public_endpoint": public_endpoint,
                    }))?
                );
            } else {
                println!("{public_endpoint}");
            }
        }
        Command::HolePunch(args) => {
            let peer_endpoint: SocketAddr = args
                .peer_endpoint
                .parse()
                .with_context(|| format!("invalid --peer-endpoint {}", args.peer_endpoint))?;
            let report = hole_punch_udp(
                args.listen_port,
                peer_endpoint,
                args.attempts.max(1),
                Duration::from_millis(args.interval_ms.max(1)),
                Duration::from_millis(args.recv_timeout_ms.max(1)),
            )
            .context("udp hole-punch failed")?;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "listen_addr": report.local_addr.to_string(),
                        "peer_endpoint": peer_endpoint.to_string(),
                        "packets_sent": report.packets_sent,
                        "packet_received": report.packet_received,
                    }))?
                );
            } else {
                println!(
                    "hole-punch: sent {} packets from {} to {}, received_response={}",
                    report.packets_sent, report.local_addr, peer_endpoint, report.packet_received
                );
            }
        }
        Command::RenderWg { config, peers } => {
            let config_path = config.unwrap_or_else(default_config_path);
            let app = load_or_default_config(&config_path)?;

            let interface = InterfaceConfig {
                private_key: app.node.private_key.clone(),
                address: app.node.tunnel_ip.clone(),
                listen_port: app.node.listen_port,
            };

            let parsed_peers = peers
                .iter()
                .map(|value| parse_peer_arg(value))
                .collect::<Result<Vec<_>>>()?;

            print!("{}", render_wireguard_config(&interface, &parsed_peers));
        }
        Command::Daemon(args) => daemon_session(args).await?,
        Command::TunnelUp(args) => tunnel_up(&args)?,
    }

    Ok(())
}

fn parse_peer_arg(value: &str) -> Result<PeerConfig> {
    let mut parts = value.split(',');
    let public_key = parts.next().unwrap_or_default().trim().to_string();
    let allowed_ips = parts.next().unwrap_or_default().trim().to_string();
    let endpoint = parts.next().unwrap_or_default().trim().to_string();

    if public_key.is_empty() || allowed_ips.is_empty() || endpoint.is_empty() {
        return Err(anyhow!(
            "invalid --peer format, expected <public_key>,<allowed_ips>,<endpoint>"
        ));
    }

    Ok(PeerConfig {
        public_key,
        allowed_ips,
        endpoint,
        persistent_keepalive: 25,
    })
}

#[derive(Debug)]
struct AnnounceRequest {
    config: Option<PathBuf>,
    network_id: Option<String>,
    participants: Vec<String>,
    node_id: Option<String>,
    endpoint: Option<String>,
    tunnel_ip: Option<String>,
    public_key: Option<String>,
    relay: Vec<String>,
}

#[derive(Debug)]
struct PublishedAnnouncement {
    app: AppConfig,
    network_id: String,
    relays: Vec<String>,
    announcement: PeerAnnouncement,
}

#[derive(Debug, Serialize)]
struct RelayCheck {
    relay: String,
    latency_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPidRecord {
    pid: u32,
    config_path: String,
    started_at: u64,
}

#[derive(Debug, Clone)]
struct DaemonStatus {
    running: bool,
    pid: Option<u32>,
    pid_file: PathBuf,
    log_file: PathBuf,
    state_file: PathBuf,
    state: Option<DaemonRuntimeState>,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceStatusView {
    supported: bool,
    installed: bool,
    disabled: bool,
    loaded: bool,
    running: bool,
    pid: Option<u32>,
    label: String,
    plist_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DaemonRuntimeState {
    updated_at: u64,
    session_active: bool,
    relay_connected: bool,
    session_status: String,
    expected_peer_count: usize,
    connected_peer_count: usize,
    mesh_ready: bool,
    peers: Vec<DaemonPeerState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPeerState {
    participant_pubkey: String,
    node_id: String,
    tunnel_ip: String,
    endpoint: String,
    public_key: String,
    advertised_routes: Vec<String>,
    presence_timestamp: u64,
    last_signal_seen_at: Option<u64>,
    reachable: bool,
    last_handshake_at: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPeerCacheEntry {
    participant_pubkey: String,
    announcement: PeerAnnouncement,
    last_signal_seen_at: Option<u64>,
    cached_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPeerCacheState {
    version: u8,
    network_id: String,
    own_pubkey: Option<String>,
    updated_at: u64,
    peers: Vec<DaemonPeerCacheEntry>,
    path_book: PeerPathBook,
}

struct DaemonPeerCacheRestore<'a> {
    path: &'a Path,
    app: &'a AppConfig,
    network_id: &'a str,
    own_pubkey: Option<&'a str>,
    now: u64,
    announce_interval_secs: u64,
}

struct DaemonPeerCacheWrite<'a> {
    path: &'a Path,
    network_id: &'a str,
    own_pubkey: Option<&'a str>,
    presence: &'a PeerPresenceBook,
    path_book: &'a PeerPathBook,
    tunnel_runtime: &'a CliTunnelRuntime,
    now: u64,
}

fn load_config_with_overrides(
    path: &Path,
    network_id: Option<String>,
    participants: Vec<String>,
) -> Result<(AppConfig, String)> {
    let mut app = load_or_default_config(path)?;
    apply_participants_override(&mut app, participants)?;
    if let Some(network_id) = network_id {
        app.network_id = network_id;
    }
    maybe_autoconfigure_node(&mut app);

    let network_id = app.effective_network_id();
    Ok((app, network_id))
}

async fn publish_announcement(request: AnnounceRequest) -> Result<PublishedAnnouncement> {
    let config_path = request.config.unwrap_or_else(default_config_path);
    let (app, network_id) =
        load_config_with_overrides(&config_path, request.network_id, request.participants)?;
    let node_id = request.node_id.unwrap_or_else(|| app.node.id.clone());
    let endpoint = request
        .endpoint
        .unwrap_or_else(|| app.node.endpoint.clone());
    let tunnel_ip = request
        .tunnel_ip
        .unwrap_or_else(|| app.node.tunnel_ip.clone());
    let public_key = request
        .public_key
        .unwrap_or_else(|| app.node.public_key.clone());
    let relays = resolve_relays(&request.relay, &app);

    let client = NostrSignalingClient::from_secret_key(
        network_id.clone(),
        &app.nostr.secret_key,
        app.participant_pubkeys_hex(),
    )?;
    client.connect(&relays).await?;

    let announcement = PeerAnnouncement {
        node_id,
        public_key,
        endpoint,
        local_endpoint: None,
        public_endpoint: None,
        tunnel_ip,
        advertised_routes: app.effective_advertised_routes(),
        timestamp: unix_timestamp(),
    };

    client
        .publish(SignalPayload::Announce(announcement.clone()))
        .await
        .context("failed to publish presence signal")?;

    client.disconnect().await;

    Ok(PublishedAnnouncement {
        app,
        network_id,
        relays,
        announcement,
    })
}

async fn discover_peers(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    discover_secs: u64,
) -> Result<Vec<PeerAnnouncement>> {
    if discover_secs == 0 {
        return Ok(Vec::new());
    }

    let client = NostrSignalingClient::from_secret_key(
        network_id.to_string(),
        &app.nostr.secret_key,
        app.participant_pubkeys_hex(),
    )?;
    client.connect(relays).await?;
    let _ = client.publish(SignalPayload::Hello).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(discover_secs);
    let mut peers: std::collections::HashMap<String, PeerAnnouncement> =
        std::collections::HashMap::new();

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let wait_for = std::cmp::min(
            deadline.saturating_duration_since(now),
            Duration::from_millis(250),
        );

        match tokio::time::timeout(wait_for, client.recv()).await {
            Ok(Some(message)) => match message.payload {
                SignalPayload::Hello => {}
                SignalPayload::Announce(announcement) => {
                    let should_insert = peers
                        .get(&announcement.node_id)
                        .is_none_or(|existing| existing.timestamp <= announcement.timestamp);
                    if should_insert {
                        peers.insert(announcement.node_id.clone(), announcement);
                    }
                }
                SignalPayload::Disconnect { node_id } => {
                    peers.remove(&node_id);
                }
            },
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    client.disconnect().await;

    let mut values: Vec<PeerAnnouncement> = peers.into_values().collect();
    values.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(values)
}

#[derive(Debug, Clone)]
struct TunnelPeer {
    pubkey_hex: String,
    endpoint: String,
    allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedTunnelPeer {
    participant: String,
    endpoint: String,
    peer: TunnelPeer,
}

#[derive(Debug, Clone, Default)]
struct OutboundAnnounceBook {
    fingerprints: HashMap<String, String>,
}

impl OutboundAnnounceBook {
    fn needs_send(&self, participant: &str, fingerprint: &str) -> bool {
        self.fingerprints.get(participant).map(String::as_str) != Some(fingerprint)
    }

    fn mark_sent(&mut self, participant: &str, fingerprint: &str) {
        self.fingerprints
            .insert(participant.to_string(), fingerprint.to_string());
    }

    fn forget(&mut self, participant: &str) {
        self.fingerprints.remove(participant);
    }

    fn clear(&mut self) {
        self.fingerprints.clear();
    }

    fn retain_participants(&mut self, participants: &HashSet<String>) {
        self.fingerprints
            .retain(|participant, _| participants.contains(participant));
    }
}

#[derive(Debug, Clone, Default)]
struct WireGuardPeerStatus {
    endpoint: Option<String>,
    last_handshake_sec: Option<u64>,
    last_handshake_nsec: Option<u64>,
}

impl WireGuardPeerStatus {
    fn has_handshake(&self) -> bool {
        self.last_handshake_sec.unwrap_or(0) > 0 || self.last_handshake_nsec.unwrap_or(0) > 0
    }

    fn last_handshake_age(&self) -> Option<Duration> {
        if !self.has_handshake() {
            return None;
        }

        Some(Duration::new(
            self.last_handshake_sec.unwrap_or(0),
            self.last_handshake_nsec.unwrap_or(0).min(u32::MAX as u64) as u32,
        ))
    }

    fn last_handshake_at(&self, now: u64) -> Option<u64> {
        self.last_handshake_age()
            .map(|age| now.saturating_sub(age.as_secs()))
    }
}

const MAGIC_DNS_PORT: u16 = 1053;

struct ConnectMagicDnsRuntime {
    suffix: String,
    resolver_installed: bool,
    server: MagicDnsServer,
}

impl ConnectMagicDnsRuntime {
    fn start(app: &AppConfig) -> Option<Self> {
        let records = build_magic_dns_records(app);
        if records.is_empty() {
            println!("magicdns: skipped (no configured alias records)");
            return None;
        }

        let server = match MagicDnsServer::start(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, MAGIC_DNS_PORT)),
            records.clone(),
        ) {
            Ok(server) => server,
            Err(error) => {
                eprintln!(
                    "magicdns: preferred port {MAGIC_DNS_PORT} unavailable ({error}); trying random local port"
                );
                match MagicDnsServer::start(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                    records,
                ) {
                    Ok(server) => server,
                    Err(error) => {
                        eprintln!("magicdns: failed to start local dns server: {error}");
                        return None;
                    }
                }
            }
        };
        let local_addr = server.local_addr();

        let suffix = app
            .magic_dns_suffix
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            println!(
                "magicdns: local dns running on {local_addr} (system split-dns disabled; empty suffix)"
            );
            return Some(Self {
                suffix,
                resolver_installed: false,
                server,
            });
        }

        let nameserver = match local_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => {
                eprintln!("magicdns: local dns unexpectedly bound to IPv6; split-dns disabled");
                return Some(Self {
                    suffix,
                    resolver_installed: false,
                    server,
                });
            }
        };

        let resolver_config = MagicDnsResolverConfig {
            suffix: suffix.clone(),
            nameserver,
            port: local_addr.port(),
        };

        match install_system_resolver(&resolver_config) {
            Ok(()) => {
                println!(
                    "magicdns: active for .{} via {}:{}",
                    suffix, resolver_config.nameserver, resolver_config.port
                );
                Some(Self {
                    suffix,
                    resolver_installed: true,
                    server,
                })
            }
            Err(error) => {
                eprintln!(
                    "magicdns: system resolver install failed ({error}); local dns remains on {local_addr}"
                );
                Some(Self {
                    suffix,
                    resolver_installed: false,
                    server,
                })
            }
        }
    }

    fn refresh_records(
        &self,
        app: &AppConfig,
        peer_announcements: &HashMap<String, PeerAnnouncement>,
    ) {
        self.server
            .update_records(build_runtime_magic_dns_records(app, peer_announcements));
    }
}

impl Drop for ConnectMagicDnsRuntime {
    fn drop(&mut self) {
        if self.resolver_installed
            && !self.suffix.is_empty()
            && let Err(error) = uninstall_system_resolver(&self.suffix)
        {
            eprintln!(
                "magicdns: failed to remove system resolver for .{}: {error}",
                self.suffix
            );
        }

        self.server.stop();
    }
}

struct CliTunnelRuntime {
    iface: String,
    handle: Option<DeviceHandle>,
    uapi_socket_path: Option<String>,
    last_fingerprint: Option<String>,
    active_listen_port: Option<u16>,
    #[cfg(target_os = "linux")]
    endpoint_bypass_routes: Vec<String>,
    #[cfg(target_os = "linux")]
    exit_node_runtime: LinuxExitNodeRuntime,
    #[cfg(target_os = "linux")]
    original_default_route: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default)]
struct LinuxExitNodeRuntime {
    ipv4_outbound_iface: Option<String>,
    ipv6_outbound_iface: Option<String>,
    ipv4_tunnel_source_cidr: Option<String>,
    ipv4_forward_was_enabled: Option<bool>,
    ipv6_forward_was_enabled: Option<bool>,
}

impl CliTunnelRuntime {
    fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            handle: None,
            uapi_socket_path: None,
            last_fingerprint: None,
            active_listen_port: None,
            #[cfg(target_os = "linux")]
            endpoint_bypass_routes: Vec::new(),
            #[cfg(target_os = "linux")]
            exit_node_runtime: LinuxExitNodeRuntime::default(),
            #[cfg(target_os = "linux")]
            original_default_route: None,
        }
    }

    fn ensure_started(&mut self) -> Result<()> {
        if cfg!(not(unix)) {
            return Err(anyhow!(
                "connect is currently supported on unix platforms only"
            ));
        }

        if self.handle.is_some() {
            return Ok(());
        }

        let preferred_iface = self.iface.clone();
        let candidates = utun_interface_candidates(&preferred_iface);
        let mut busy = Vec::new();

        for candidate in candidates {
            let handle = DeviceHandle::new(
                &candidate,
                DeviceConfig {
                    n_threads: 2,
                    #[cfg(target_os = "linux")]
                    use_connected_socket: false,
                    #[cfg(not(target_os = "linux"))]
                    use_connected_socket: true,
                    #[cfg(target_os = "linux")]
                    use_multi_queue: false,
                    #[cfg(target_os = "linux")]
                    uapi_fd: -1,
                },
            );

            let handle = match handle {
                Ok(handle) => handle,
                Err(error) => {
                    let error_text = error.to_string();
                    if is_resource_busy_message(&error_text) {
                        busy.push(candidate);
                        continue;
                    }
                    return Err(anyhow!(
                        "failed to create boringtun interface {}: {}",
                        candidate,
                        error_text
                    ));
                }
            };

            let socket = format!("/var/run/wireguard/{}.sock", candidate);
            wait_for_socket(&socket)?;

            self.iface = candidate;
            self.handle = Some(handle);
            self.uapi_socket_path = Some(socket);
            return Ok(());
        }

        if !busy.is_empty() {
            return Err(anyhow!(
                "failed to create boringtun interface {}; busy interfaces: {}",
                preferred_iface,
                busy.join(", ")
            ));
        }

        Err(anyhow!(
            "failed to create boringtun interface {}",
            preferred_iface
        ))
    }

    fn apply(
        &mut self,
        app: &AppConfig,
        own_pubkey: Option<&str>,
        peer_announcements: &HashMap<String, PeerAnnouncement>,
        path_book: &mut PeerPathBook,
        now: u64,
    ) -> Result<()> {
        let configured_listen_port = app.node.listen_port;
        let listen_port = self.active_listen_port.unwrap_or(configured_listen_port);
        let own_local_endpoint = local_signal_endpoint(app, listen_port);
        record_successful_runtime_paths(
            peer_announcements,
            self.peer_status().ok().as_ref(),
            path_book,
            now,
        );
        let planned_peers = planned_tunnel_peers(
            app,
            own_pubkey,
            peer_announcements,
            path_book,
            Some(&own_local_endpoint),
            now,
        )?;
        let peers = planned_peers
            .iter()
            .map(|planned| planned.peer.clone())
            .collect::<Vec<_>>();
        if peers.is_empty() {
            self.stop();
            return Ok(());
        }

        let local_address = local_interface_address_for_tunnel(&app.node.tunnel_ip);
        let route_targets = route_targets_for_tunnel_peers(&peers);
        #[cfg(target_os = "linux")]
        if route_targets.iter().any(|route| route == "0.0.0.0/0") {
            self.capture_linux_original_default_route();
        } else {
            self.restore_linux_original_default_route();
        }
        #[cfg(target_os = "linux")]
        let endpoint_bypass_specs = if route_targets_require_endpoint_bypass(&route_targets) {
            linux_bypass_route_specs(
                app,
                &peers,
                &self.iface,
                self.original_default_route.as_deref(),
            )?
        } else {
            Vec::new()
        };
        let fingerprint = tunnel_fingerprint(
            &self.iface,
            &app.node.private_key,
            listen_port,
            &local_address,
            &peers,
        );
        if self.last_fingerprint.as_deref() == Some(fingerprint.as_str()) && self.handle.is_some() {
            return Ok(());
        }

        self.ensure_started()?;
        let socket = self
            .uapi_socket_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing uapi socket path"))?;

        let private_key_hex = key_b64_to_hex(&app.node.private_key)?;
        let primary_listen_port = self.active_listen_port.unwrap_or(configured_listen_port);
        let mut attempted_ports = HashSet::new();
        let mut candidate_ports = Vec::with_capacity(16);
        for _ in 0..16 {
            if let Ok(fallback_port) = pick_available_udp_port() {
                candidate_ports.push(fallback_port);
            }
        }

        let mut selected_listen_port = None;
        let mut last_bind_conflict = None;
        let mut try_listen_port =
            |listen_port: u16, warn_on_fallback: bool| -> Result<Option<u16>> {
                if can_reuse_active_listen_port(
                    self.handle.is_some(),
                    self.last_fingerprint.is_some(),
                    self.active_listen_port,
                    listen_port,
                ) {
                    return Ok(Some(listen_port));
                }
                match wg_set(
                    socket,
                    &format!("private_key={private_key_hex}\nlisten_port={listen_port}"),
                ) {
                    Ok(()) => {
                        if warn_on_fallback {
                            eprintln!(
                                "tunnel: listen_port {} busy, using fallback {}",
                                primary_listen_port, listen_port
                            );
                        }
                        Ok(Some(listen_port))
                    }
                    Err(error) => {
                        let error_text = error.to_string();
                        if !is_uapi_addr_in_use_error(&error_text) {
                            return Err(error);
                        }
                        last_bind_conflict = Some(error);
                        Ok(None)
                    }
                }
            };

        for attempt in 0..PRIMARY_LISTEN_PORT_RETRY_ATTEMPTS {
            if let Some(listen_port) = try_listen_port(primary_listen_port, false)? {
                selected_listen_port = Some(listen_port);
                break;
            }
            if attempt + 1 < PRIMARY_LISTEN_PORT_RETRY_ATTEMPTS {
                thread::sleep(Duration::from_millis(PRIMARY_LISTEN_PORT_RETRY_DELAY_MS));
            }
        }

        if selected_listen_port.is_none() {
            for listen_port in candidate_ports {
                if !attempted_ports.insert(listen_port) || listen_port == primary_listen_port {
                    continue;
                }
                if let Some(listen_port) = try_listen_port(listen_port, true)? {
                    selected_listen_port = Some(listen_port);
                    break;
                }
            }
        }

        self.active_listen_port = Some(selected_listen_port.ok_or_else(|| {
            if let Some(error) = last_bind_conflict {
                error.context("failed to allocate available wireguard listen port")
            } else {
                anyhow!("failed to configure wireguard listen port")
            }
        })?);
        wg_set(socket, "replace_peers=true")?;

        for peer in &peers {
            let mut body = format!(
                "public_key={}\nendpoint={}\nreplace_allowed_ips=true",
                peer.pubkey_hex, peer.endpoint
            );
            for allowed_ip in &peer.allowed_ips {
                body.push_str(&format!("\nallowed_ip={allowed_ip}"));
            }
            body.push_str("\npersistent_keepalive_interval=5");
            wg_set(socket, &body)?;
        }

        apply_local_interface_network(&self.iface, &local_address, &route_targets)?;
        #[cfg(target_os = "linux")]
        self.reconcile_linux_endpoint_bypass_routes(&endpoint_bypass_specs);
        #[cfg(target_os = "linux")]
        self.reconcile_linux_exit_node_forwarding(app);

        let applied_fingerprint = tunnel_fingerprint(
            &self.iface,
            &app.node.private_key,
            self.listen_port(configured_listen_port),
            &local_address,
            &peers,
        );
        for planned in &planned_peers {
            path_book.note_selected(&planned.participant, &planned.endpoint, now);
        }
        self.last_fingerprint = Some(applied_fingerprint);
        Ok(())
    }

    fn peer_status(&self) -> Result<HashMap<String, WireGuardPeerStatus>> {
        let socket = self
            .uapi_socket_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing uapi socket path"))?;
        let response = wg_get(socket)?;
        Ok(parse_wg_peer_status(&response))
    }

    fn stop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.reconcile_linux_endpoint_bypass_routes(&[]);
            self.reconcile_linux_exit_node_forwarding_cleanup();
            self.restore_linux_original_default_route();
        }
        self.handle = None;
        self.uapi_socket_path = None;
        self.last_fingerprint = None;
        self.active_listen_port = None;
    }

    fn listen_port(&self, configured: u16) -> u16 {
        self.active_listen_port.unwrap_or(configured)
    }

    #[cfg(target_os = "linux")]
    fn capture_linux_original_default_route(&mut self) {
        if self.original_default_route.is_some() {
            return;
        }

        let default_route = match linux_default_route() {
            Ok(route) => route,
            Err(error) => {
                eprintln!("exit-node: failed to snapshot default route: {error}");
                return;
            }
        };

        if default_route.dev != self.iface {
            self.original_default_route = Some(default_route.line);
        }
    }

    #[cfg(target_os = "linux")]
    fn restore_linux_original_default_route(&mut self) {
        let Some(route) = self.original_default_route.as_deref() else {
            return;
        };
        if let Err(error) = restore_linux_default_route(route) {
            eprintln!("exit-node: failed to restore default route '{route}': {error}");
            return;
        }
        self.original_default_route = None;
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_endpoint_bypass_routes(&mut self, routes: &[LinuxEndpointBypassRoute]) {
        let desired = routes
            .iter()
            .map(|route| route.target.clone())
            .collect::<HashSet<_>>();

        let stale = self
            .endpoint_bypass_routes
            .iter()
            .filter(|route| !desired.contains(*route))
            .cloned()
            .collect::<Vec<_>>();
        for route in stale {
            if let Err(error) = delete_linux_endpoint_bypass_route(&route) {
                eprintln!("tunnel: failed to remove endpoint bypass route {route}: {error}");
            }
        }

        for route in routes {
            if let Err(error) = apply_linux_endpoint_bypass_route(route) {
                eprintln!(
                    "tunnel: failed to install endpoint bypass route {}: {}",
                    route.target, error
                );
            }
        }

        self.endpoint_bypass_routes = desired.into_iter().collect();
        self.endpoint_bypass_routes.sort();
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_exit_node_forwarding(&mut self, app: &AppConfig) {
        let mut route_families =
            linux_exit_node_default_route_families(&app.effective_advertised_routes());
        if !route_families.ipv4 && !route_families.ipv6 {
            self.reconcile_linux_exit_node_forwarding_cleanup();
            return;
        }

        let ipv4_tunnel_source_cidr = if route_families.ipv4 {
            let Some(tunnel_source_cidr) = linux_exit_node_source_cidr(&app.node.tunnel_ip) else {
                eprintln!(
                    "exit-node: invalid IPv4 tunnel address '{}'",
                    app.node.tunnel_ip
                );
                self.reconcile_linux_exit_node_forwarding_cleanup();
                return;
            };
            Some(tunnel_source_cidr)
        } else {
            None
        };

        let ipv4_outbound_iface = if route_families.ipv4 {
            match linux_default_route() {
                Ok(route) => Some(route.dev),
                Err(error) => {
                    eprintln!("exit-node: failed to resolve default IPv4 route device: {error}");
                    self.reconcile_linux_exit_node_forwarding_cleanup();
                    return;
                }
            }
        } else {
            None
        };

        let ipv6_outbound_iface = if route_families.ipv6 {
            match linux_default_ipv6_route() {
                Ok(route) => Some(route.dev),
                Err(error) => {
                    eprintln!(
                        "exit-node: skipping IPv6 forwarding (default route unavailable): {error}"
                    );
                    route_families.ipv6 = false;
                    None
                }
            }
        } else {
            None
        };

        if !route_families.ipv4 && !route_families.ipv6 {
            self.reconcile_linux_exit_node_forwarding_cleanup();
            return;
        }

        let already_configured = self.exit_node_runtime.ipv4_outbound_iface == ipv4_outbound_iface
            && self.exit_node_runtime.ipv6_outbound_iface == ipv6_outbound_iface
            && self.exit_node_runtime.ipv4_tunnel_source_cidr == ipv4_tunnel_source_cidr;
        if already_configured {
            return;
        }

        self.reconcile_linux_exit_node_forwarding_cleanup();

        self.exit_node_runtime.ipv4_outbound_iface = ipv4_outbound_iface.clone();
        self.exit_node_runtime.ipv6_outbound_iface = ipv6_outbound_iface.clone();
        self.exit_node_runtime.ipv4_tunnel_source_cidr = ipv4_tunnel_source_cidr.clone();

        if route_families.ipv4 {
            match read_linux_ip_forward(LinuxExitNodeIpFamily::V4) {
                Ok(previous) => {
                    self.exit_node_runtime.ipv4_forward_was_enabled = Some(previous);
                    if !previous
                        && let Err(error) = write_linux_ip_forward(LinuxExitNodeIpFamily::V4, true)
                    {
                        eprintln!("exit-node: failed to enable IPv4 forwarding: {error}");
                        self.reconcile_linux_exit_node_forwarding_cleanup();
                        return;
                    }
                }
                Err(error) => {
                    eprintln!("exit-node: failed to read IPv4 forwarding state: {error}");
                    self.reconcile_linux_exit_node_forwarding_cleanup();
                    return;
                }
            }
        }

        if route_families.ipv6 {
            match read_linux_ip_forward(LinuxExitNodeIpFamily::V6) {
                Ok(previous) => {
                    self.exit_node_runtime.ipv6_forward_was_enabled = Some(previous);
                    if !previous
                        && let Err(error) = write_linux_ip_forward(LinuxExitNodeIpFamily::V6, true)
                    {
                        eprintln!("exit-node: skipping IPv6 forwarding setup: {error}");
                        self.exit_node_runtime.ipv6_forward_was_enabled = None;
                        self.exit_node_runtime.ipv6_outbound_iface = None;
                        route_families.ipv6 = false;
                    }
                }
                Err(error) => {
                    eprintln!("exit-node: skipping IPv6 forwarding state check: {error}");
                    self.exit_node_runtime.ipv6_forward_was_enabled = None;
                    self.exit_node_runtime.ipv6_outbound_iface = None;
                    route_families.ipv6 = false;
                }
            }
        }

        if let (Some(outbound_iface), Some(tunnel_source_cidr)) = (
            ipv4_outbound_iface.as_deref(),
            ipv4_tunnel_source_cidr.as_deref(),
        ) {
            let forward_in =
                linux_exit_node_forward_in_rule(&self.iface, LinuxExitNodeIpFamily::V4);
            let forward_out =
                linux_exit_node_forward_out_rule(&self.iface, LinuxExitNodeIpFamily::V4);
            let masquerade =
                linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);

            if let Err(error) =
                linux_iptables_ensure_rule(LinuxExitNodeIpFamily::V4, None, &forward_in)
                    .and_then(|()| {
                        linux_iptables_ensure_rule(LinuxExitNodeIpFamily::V4, None, &forward_out)
                    })
                    .and_then(|()| {
                        linux_iptables_ensure_rule(
                            LinuxExitNodeIpFamily::V4,
                            Some("nat"),
                            &masquerade,
                        )
                    })
            {
                eprintln!("exit-node: failed to install IPv4 firewall rules: {error}");
                self.reconcile_linux_exit_node_forwarding_cleanup();
                return;
            }
        }

        if route_families.ipv6 {
            let forward_in =
                linux_exit_node_forward_in_rule(&self.iface, LinuxExitNodeIpFamily::V6);
            let forward_out =
                linux_exit_node_forward_out_rule(&self.iface, LinuxExitNodeIpFamily::V6);

            if let Err(error) =
                linux_iptables_ensure_rule(LinuxExitNodeIpFamily::V6, None, &forward_in).and_then(
                    |()| linux_iptables_ensure_rule(LinuxExitNodeIpFamily::V6, None, &forward_out),
                )
            {
                eprintln!("exit-node: skipping IPv6 firewall rules: {error}");
                self.exit_node_runtime.ipv6_outbound_iface = None;
                self.exit_node_runtime.ipv6_forward_was_enabled = None;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_exit_node_forwarding_cleanup(&mut self) {
        if let (Some(outbound_iface), Some(tunnel_source_cidr)) = (
            self.exit_node_runtime.ipv4_outbound_iface.as_deref(),
            self.exit_node_runtime.ipv4_tunnel_source_cidr.as_deref(),
        ) {
            let forward_in =
                linux_exit_node_forward_in_rule(&self.iface, LinuxExitNodeIpFamily::V4);
            let forward_out =
                linux_exit_node_forward_out_rule(&self.iface, LinuxExitNodeIpFamily::V4);
            let masquerade =
                linux_exit_node_ipv4_masquerade_rule(outbound_iface, tunnel_source_cidr);

            if let Err(error) =
                linux_iptables_delete_rule(LinuxExitNodeIpFamily::V4, Some("nat"), &masquerade)
            {
                eprintln!("exit-node: failed to remove masquerade rule: {error}");
            }
            if let Err(error) =
                linux_iptables_delete_rule(LinuxExitNodeIpFamily::V4, None, &forward_out)
            {
                eprintln!("exit-node: failed to remove forward-out rule: {error}");
            }
            if let Err(error) =
                linux_iptables_delete_rule(LinuxExitNodeIpFamily::V4, None, &forward_in)
            {
                eprintln!("exit-node: failed to remove forward-in rule: {error}");
            }
        }

        if self.exit_node_runtime.ipv6_outbound_iface.is_some() {
            let forward_in =
                linux_exit_node_forward_in_rule(&self.iface, LinuxExitNodeIpFamily::V6);
            let forward_out =
                linux_exit_node_forward_out_rule(&self.iface, LinuxExitNodeIpFamily::V6);

            if let Err(error) =
                linux_iptables_delete_rule(LinuxExitNodeIpFamily::V6, None, &forward_out)
            {
                eprintln!("exit-node: failed to remove IPv6 forward-out rule: {error}");
            }
            if let Err(error) =
                linux_iptables_delete_rule(LinuxExitNodeIpFamily::V6, None, &forward_in)
            {
                eprintln!("exit-node: failed to remove IPv6 forward-in rule: {error}");
            }
        }

        if self.exit_node_runtime.ipv4_forward_was_enabled == Some(false)
            && let Err(error) = write_linux_ip_forward(LinuxExitNodeIpFamily::V4, false)
        {
            eprintln!("exit-node: failed to restore IPv4 forwarding state: {error}");
        }
        if self.exit_node_runtime.ipv6_forward_was_enabled == Some(false)
            && let Err(error) = write_linux_ip_forward(LinuxExitNodeIpFamily::V6, false)
        {
            eprintln!("exit-node: failed to restore IPv6 forwarding state: {error}");
        }

        self.exit_node_runtime = LinuxExitNodeRuntime::default();
    }
}

fn utun_interface_candidates(preferred: &str) -> Vec<String> {
    let Some(suffix) = preferred.strip_prefix("utun") else {
        return vec![preferred.to_string()];
    };
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return vec![preferred.to_string()];
    }
    let Ok(base) = suffix.parse::<u16>() else {
        return vec![preferred.to_string()];
    };

    (0u16..16u16)
        .map(|offset| format!("utun{}", base.saturating_add(offset)))
        .collect()
}

fn is_resource_busy_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("resource busy") || lower.contains("address already in use")
}

fn is_uapi_addr_in_use_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("errno=48") || lower.contains("errno=98") || lower.contains("address in use")
}

fn pick_available_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind local udp socket for free port discovery")?;
    let addr = socket
        .local_addr()
        .context("failed to read local socket addr for free port discovery")?;
    Ok(addr.port())
}

fn can_reuse_active_listen_port(
    handle_running: bool,
    config_applied: bool,
    active_listen_port: Option<u16>,
    requested_listen_port: u16,
) -> bool {
    handle_running && config_applied && active_listen_port == Some(requested_listen_port)
}

fn endpoint_with_listen_port(endpoint: &str, listen_port: u16) -> String {
    endpoint
        .parse::<SocketAddr>()
        .map(|mut parsed| {
            parsed.set_port(listen_port);
            parsed.to_string()
        })
        .unwrap_or_else(|_| endpoint.to_string())
}

fn detect_runtime_primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn endpoint_prefers_runtime_local_ipv4(endpoint: &str) -> bool {
    let value = endpoint.trim();
    if value.is_empty() {
        return true;
    }

    let host = value
        .rsplit_once(':')
        .map_or(value, |(host, _port)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

fn runtime_local_signal_endpoint(
    endpoint: &str,
    listen_port: u16,
    detected_ipv4: Option<Ipv4Addr>,
) -> String {
    if endpoint_prefers_runtime_local_ipv4(endpoint)
        && let Some(ip) = detected_ipv4
    {
        return SocketAddrV4::new(ip, listen_port).to_string();
    }

    endpoint_with_listen_port(endpoint, listen_port)
}

fn local_signal_endpoint(app: &AppConfig, listen_port: u16) -> String {
    runtime_local_signal_endpoint(
        &app.node.endpoint,
        listen_port,
        detect_runtime_primary_ipv4(),
    )
}

fn discover_public_signal_endpoint(app: &AppConfig, listen_port: u16) -> Option<String> {
    if !app.nat.enabled {
        return None;
    }

    let timeout = Duration::from_secs(app.nat.discovery_timeout_secs.max(1));

    for reflector in &app.nat.reflectors {
        let Ok(reflector_addr) = reflector.parse::<SocketAddr>() else {
            eprintln!("nat: ignoring invalid reflector address '{reflector}'");
            continue;
        };

        match discover_public_udp_endpoint(reflector_addr, listen_port, timeout) {
            Ok(endpoint) => {
                eprintln!("nat: discovered public endpoint via reflector {reflector}: {endpoint}");
                return Some(endpoint);
            }
            Err(error) => {
                eprintln!("nat: reflector discovery failed via {reflector}: {error}");
            }
        }
    }

    for server in &app.nat.stun_servers {
        match discover_public_udp_endpoint_via_stun(server, listen_port, timeout) {
            Ok(endpoint) => {
                eprintln!("nat: discovered public endpoint via STUN {server}: {endpoint}");
                return Some(endpoint);
            }
            Err(error) => {
                eprintln!("nat: stun discovery failed via {server}: {error}");
            }
        }
    }

    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredPublicSignalEndpoint {
    listen_port: u16,
    endpoint: String,
}

fn refresh_public_signal_endpoint(
    app: &AppConfig,
    listen_port: u16,
    public_signal_endpoint: &mut Option<DiscoveredPublicSignalEndpoint>,
) {
    *public_signal_endpoint = discover_public_signal_endpoint(app, listen_port).map(|endpoint| {
        DiscoveredPublicSignalEndpoint {
            listen_port,
            endpoint,
        }
    });
}

fn build_peer_announcement(
    app: &AppConfig,
    listen_port: u16,
    public_endpoint: Option<&str>,
) -> PeerAnnouncement {
    let local_endpoint = local_signal_endpoint(app, listen_port);
    let public_endpoint = public_endpoint
        .map(str::to_string)
        .filter(|value| value != &local_endpoint);
    let endpoint = public_endpoint
        .clone()
        .unwrap_or_else(|| local_endpoint.clone());

    PeerAnnouncement {
        node_id: app.node.id.clone(),
        public_key: app.node.public_key.clone(),
        endpoint,
        local_endpoint: Some(local_endpoint),
        public_endpoint,
        tunnel_ip: app.node.tunnel_ip.clone(),
        advertised_routes: app.effective_advertised_routes(),
        timestamp: unix_timestamp(),
    }
}

fn announcement_fingerprint(announcement: &PeerAnnouncement) -> String {
    [
        announcement.node_id.as_str(),
        announcement.public_key.as_str(),
        announcement.endpoint.as_str(),
        announcement.local_endpoint.as_deref().unwrap_or(""),
        announcement.public_endpoint.as_deref().unwrap_or(""),
        announcement.tunnel_ip.as_str(),
        &announcement.advertised_routes.join(","),
    ]
    .join("|")
}

fn parse_exit_node_arg(value: &str) -> Result<Option<String>> {
    let value = value.trim();
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "off" | "none" | "disable" | "disabled" | "clear"
        )
    {
        return Ok(None);
    }

    normalize_nostr_pubkey(value).map(Some)
}

fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

#[cfg(any(target_os = "linux", test))]
fn route_is_host_route(route: &str) -> bool {
    let Some((host, bits)) = route.split_once('/') else {
        return true;
    };
    let Ok(bits) = bits.parse::<u8>() else {
        return false;
    };

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => bits == 32,
        Ok(IpAddr::V6(_)) => bits == 128,
        Err(_) => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn route_targets_require_endpoint_bypass(route_targets: &[String]) -> bool {
    route_targets
        .iter()
        .any(|route| !route_is_host_route(route))
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
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> Option<String> {
    if app.exit_node.is_empty() || Some(app.exit_node.as_str()) == own_pubkey {
        return None;
    }

    let announcement = peer_announcements.get(&app.exit_node)?;
    normalized_peer_ipv4_routes(announcement)
        .iter()
        .any(|route| route == "0.0.0.0/0")
        .then(|| app.exit_node.clone())
}

fn advertised_route_assignments(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> HashMap<String, Vec<String>> {
    let selected_exit_node = selected_exit_node_participant(app, own_pubkey, peer_announcements);
    let mut route_owner = HashMap::<String, String>::new();

    for participant in app
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

fn public_endpoint_for_listen_port(
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    actual_listen_port: u16,
) -> Option<String> {
    public_signal_endpoint
        .filter(|endpoint| endpoint.listen_port == actual_listen_port)
        .map(|endpoint| endpoint.endpoint.clone())
}

fn tunnel_peer_from_endpoint(
    announcement: &PeerAnnouncement,
    endpoint: &str,
    routed_ips: &[String],
) -> Result<TunnelPeer> {
    let endpoint: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("invalid peer endpoint {}", endpoint))?;
    let pubkey_hex = key_b64_to_hex(&announcement.public_key)?;
    let mut allowed_ips = vec![format!("{}/32", strip_cidr(&announcement.tunnel_ip))];
    for routed_ip in routed_ips {
        if !allowed_ips.iter().any(|existing| existing == routed_ip) {
            allowed_ips.push(routed_ip.clone());
        }
    }

    Ok(TunnelPeer {
        pubkey_hex,
        endpoint: endpoint.to_string(),
        allowed_ips,
    })
}

fn record_successful_runtime_paths(
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    path_book: &mut PeerPathBook,
    now: u64,
) -> bool {
    let Some(runtime_peers) = runtime_peers else {
        return false;
    };

    let mut changed = false;
    for (participant, announcement) in peer_announcements {
        let Ok(peer_pubkey_hex) = key_b64_to_hex(&announcement.public_key) else {
            continue;
        };
        let Some(runtime_peer) = runtime_peers.get(&peer_pubkey_hex) else {
            continue;
        };
        if !runtime_peer.has_handshake() {
            continue;
        }
        let Some(endpoint) = runtime_peer.endpoint.as_deref() else {
            continue;
        };

        let success_at = runtime_peer.last_handshake_at(now).unwrap_or(now);
        changed |= path_book.note_success(participant.clone(), endpoint, success_at);
    }

    changed
}

fn peer_runtime_lookup<'a>(
    announcement: &PeerAnnouncement,
    runtime_peers: Option<&'a HashMap<String, WireGuardPeerStatus>>,
) -> Option<&'a WireGuardPeerStatus> {
    let peer_pubkey_hex = key_b64_to_hex(&announcement.public_key)
        .map(|value| value.to_lowercase())
        .ok()?;
    runtime_peers.and_then(|peers| peers.get(&peer_pubkey_hex))
}

fn peer_has_recent_handshake(runtime_peer: &WireGuardPeerStatus) -> bool {
    runtime_peer
        .last_handshake_age()
        .is_some_and(|age| age <= Duration::from_secs(PEER_ONLINE_GRACE_SECS))
}

fn connected_peer_count_for_runtime(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    _now: u64,
) -> usize {
    app.participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| presence.announcement_for(participant))
        .filter(|announcement| {
            peer_runtime_lookup(announcement, runtime_peers).is_some_and(peer_has_recent_handshake)
        })
        .count()
}

fn direct_peer_announcements(
    presence: &PeerPresenceBook,
    relay_connected: bool,
) -> &HashMap<String, PeerAnnouncement> {
    if relay_connected {
        presence.active()
    } else {
        presence.known()
    }
}

fn relay_connection_action(
    auto_disconnect_relays_when_mesh_ready: bool,
    relay_connected: bool,
    mesh_ready: bool,
) -> RelayConnectionAction {
    if relay_connected {
        if auto_disconnect_relays_when_mesh_ready && mesh_ready {
            RelayConnectionAction::PauseForMesh
        } else {
            RelayConnectionAction::KeepConnected
        }
    } else if auto_disconnect_relays_when_mesh_ready && mesh_ready {
        RelayConnectionAction::StayPausedForMesh
    } else {
        RelayConnectionAction::ReconnectWhenDue
    }
}

fn mesh_ready_for_tunnel_runtime(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    now: u64,
) -> bool {
    if expected_peers == 0 {
        return false;
    }

    let runtime_peers = tunnel_runtime.peer_status().ok();
    connected_peer_count_for_runtime(app, own_pubkey, presence, runtime_peers.as_ref(), now)
        >= expected_peers
}

fn should_pause_relays_for_mesh(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    now: u64,
) -> bool {
    app.auto_disconnect_relays_when_mesh_ready
        && mesh_ready_for_tunnel_runtime(
            app,
            own_pubkey,
            expected_peers,
            presence,
            tunnel_runtime,
            now,
        )
}

fn build_daemon_peer_cache_state(
    network_id: &str,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    path_book: &PeerPathBook,
    tunnel_runtime: &CliTunnelRuntime,
    now: u64,
) -> Option<DaemonPeerCacheState> {
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let mut peers = presence
        .known()
        .iter()
        .map(|(participant, announcement)| {
            let handshake_at = peer_runtime_lookup(announcement, runtime_peers.as_ref())
                .and_then(|peer| peer.last_handshake_at(now));
            let cached_at = presence
                .last_seen_at(participant)
                .unwrap_or(announcement.timestamp)
                .max(handshake_at.unwrap_or(0))
                .max(announcement.timestamp);
            DaemonPeerCacheEntry {
                participant_pubkey: participant.clone(),
                announcement: announcement.clone(),
                last_signal_seen_at: presence.last_seen_at(participant),
                cached_at,
            }
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| left.participant_pubkey.cmp(&right.participant_pubkey));
    if peers.is_empty() {
        return None;
    }

    Some(DaemonPeerCacheState {
        version: 1,
        network_id: network_id.to_string(),
        own_pubkey: own_pubkey.map(str::to_string),
        updated_at: now,
        peers,
        path_book: path_book.clone(),
    })
}

fn restore_daemon_peer_cache(
    restore: DaemonPeerCacheRestore<'_>,
    presence: &mut PeerPresenceBook,
    path_book: &mut PeerPathBook,
) -> Result<bool> {
    let Some(cache) = read_daemon_peer_cache(restore.path)? else {
        return Ok(false);
    };
    if cache.version != 1 || cache.network_id != restore.network_id {
        return Ok(false);
    }
    if let (Some(cached), Some(current)) = (cache.own_pubkey.as_deref(), restore.own_pubkey)
        && cached != current
    {
        return Ok(false);
    }

    let configured_participants = restore
        .app
        .participant_pubkeys_hex()
        .into_iter()
        .collect::<HashSet<_>>();
    let peer_cutoff = restore
        .now
        .saturating_sub(persisted_peer_cache_timeout_secs(
            restore.announce_interval_secs,
        ));
    let mut restored = 0usize;
    for entry in cache.peers {
        if entry.cached_at <= peer_cutoff {
            continue;
        }
        if !configured_participants.contains(&entry.participant_pubkey) {
            continue;
        }
        if Some(entry.participant_pubkey.as_str()) == restore.own_pubkey {
            continue;
        }

        presence.restore_known(
            entry.participant_pubkey,
            entry.announcement,
            entry.last_signal_seen_at,
        );
        restored += 1;
    }
    if restored == 0 {
        return Ok(false);
    }

    *path_book = cache.path_book;
    path_book.retain_participants(&configured_participants);
    path_book.prune_stale(
        restore.now,
        persisted_path_cache_timeout_secs(restore.announce_interval_secs),
    );

    Ok(true)
}

fn write_daemon_peer_cache_if_changed(
    write: DaemonPeerCacheWrite<'_>,
    last_written_cache: &mut Option<String>,
) -> Result<()> {
    let Some(cache) = build_daemon_peer_cache_state(
        write.network_id,
        write.own_pubkey,
        write.presence,
        write.path_book,
        write.tunnel_runtime,
        write.now,
    ) else {
        return Ok(());
    };
    let raw = serde_json::to_string(&cache)?;
    if last_written_cache.as_deref() == Some(raw.as_str()) {
        return Ok(());
    }
    write_daemon_peer_cache(write.path, &cache)?;
    *last_written_cache = Some(raw);
    Ok(())
}

async fn publish_private_announce_to_participants(
    client: &NostrSignalingClient,
    app: &AppConfig,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    outbound_announces: &mut OutboundAnnounceBook,
    participants: &[String],
) -> Result<usize> {
    if participants.is_empty() {
        return Ok(0);
    }

    let actual_listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    let public_endpoint =
        public_endpoint_for_listen_port(public_signal_endpoint, actual_listen_port);
    let announcement = build_peer_announcement(app, actual_listen_port, public_endpoint.as_deref());
    let fingerprint = announcement_fingerprint(&announcement);

    let mut recipients = participants.to_vec();
    recipients.sort();
    recipients.dedup();

    let mut sent = 0usize;
    for participant in recipients {
        if !outbound_announces.needs_send(&participant, &fingerprint) {
            continue;
        }

        client
            .publish_to(
                SignalPayload::Announce(announcement.clone()),
                std::slice::from_ref(&participant),
            )
            .await
            .with_context(|| format!("failed to publish private announce to {participant}"))?;
        outbound_announces.mark_sent(&participant, &fingerprint);
        sent += 1;
    }

    Ok(sent)
}

async fn publish_private_announce_to_active_peers(
    client: &NostrSignalingClient,
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    outbound_announces: &mut OutboundAnnounceBook,
) -> Result<usize> {
    let participants = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter(|participant| presence.active().contains_key(participant))
        .collect::<Vec<_>>();

    publish_private_announce_to_participants(
        client,
        app,
        tunnel_runtime,
        public_signal_endpoint,
        outbound_announces,
        &participants,
    )
    .await
}

fn recently_seen_participants(
    presence: &PeerPresenceBook,
    now: u64,
    stale_after_secs: u64,
) -> HashSet<String> {
    if stale_after_secs == 0 {
        return HashSet::new();
    }

    let cutoff = now.saturating_sub(stale_after_secs);
    presence
        .last_seen()
        .iter()
        .filter(|(_, last_seen)| **last_seen > cutoff)
        .map(|(participant, _)| participant.clone())
        .collect()
}

fn planned_tunnel_peers(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    own_local_endpoint: Option<&str>,
    now: u64,
) -> Result<Vec<PlannedTunnelPeer>> {
    let configured_participants = app.participant_pubkeys_hex();
    let route_assignments = advertised_route_assignments(app, own_pubkey, peer_announcements);
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
                PEER_PATH_RETRY_AFTER_SECS,
            )
            .unwrap_or_else(|| select_peer_endpoint(announcement, own_local_endpoint));
        if peer_endpoint_requires_public_signal(
            app,
            announcement,
            &selected_endpoint,
            own_local_endpoint,
        ) {
            continue;
        }

        peers.push(PlannedTunnelPeer {
            participant: participant.clone(),
            endpoint: selected_endpoint.clone(),
            peer: tunnel_peer_from_endpoint(
                announcement,
                &selected_endpoint,
                route_assignments
                    .get(participant)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )?,
        });
    }

    peers.sort_by(|left, right| left.peer.pubkey_hex.cmp(&right.peer.pubkey_hex));
    Ok(peers)
}

fn runtime_has_handshake(tunnel_runtime: &CliTunnelRuntime) -> bool {
    tunnel_runtime
        .peer_status()
        .ok()
        .is_some_and(|peers| peers.values().any(WireGuardPeerStatus::has_handshake))
}

fn ipv4_is_local_only(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_link_local()
        || ip.is_loopback()
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
}

fn endpoint_host_ip(endpoint: &str) -> Option<IpAddr> {
    let host = endpoint
        .rsplit_once(':')
        .map_or(endpoint, |(host, _)| host)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    host.parse::<IpAddr>().ok()
}

fn endpoint_is_local_only(endpoint: &str) -> bool {
    match endpoint_host_ip(endpoint) {
        Some(IpAddr::V4(ip)) => ipv4_is_local_only(ip),
        Some(IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unicast_link_local() || ip.is_unique_local()
        }
        None => endpoint.eq_ignore_ascii_case("localhost"),
    }
}

fn endpoints_share_local_only_ipv4_subnet(left: &str, right: &str) -> bool {
    let Ok(left_addr) = left.parse::<SocketAddr>() else {
        return false;
    };
    let Ok(right_addr) = right.parse::<SocketAddr>() else {
        return false;
    };

    let (SocketAddr::V4(left_v4), SocketAddr::V4(right_v4)) = (left_addr, right_addr) else {
        return false;
    };
    let left_ip = *left_v4.ip();
    let right_ip = *right_v4.ip();

    ipv4_is_local_only(left_ip)
        && ipv4_is_local_only(right_ip)
        && left_ip.octets()[0..3] == right_ip.octets()[0..3]
}

fn peer_endpoint_requires_public_signal(
    app: &AppConfig,
    announcement: &PeerAnnouncement,
    selected_endpoint: &str,
    own_local_endpoint: Option<&str>,
) -> bool {
    if !app.nat.enabled {
        return false;
    }

    if announcement
        .public_endpoint
        .as_deref()
        .is_some_and(|endpoint| !endpoint.trim().is_empty())
    {
        return false;
    }

    if announcement.local_endpoint.as_deref().is_some_and(|local| {
        local == selected_endpoint
            && own_local_endpoint
                .is_some_and(|own| endpoints_share_local_only_ipv4_subnet(local, own))
    }) {
        return false;
    }

    endpoint_is_local_only(selected_endpoint)
}

fn nat_punch_targets(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    listen_port: u16,
) -> Vec<SocketAddr> {
    let own_local_endpoint = local_signal_endpoint(app, listen_port);
    let mut targets = app
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| peer_announcements.get(participant))
        .filter_map(|announcement| {
            let selected_endpoint = select_peer_endpoint(announcement, Some(&own_local_endpoint));
            if peer_endpoint_requires_public_signal(
                app,
                announcement,
                &selected_endpoint,
                Some(&own_local_endpoint),
            ) {
                return None;
            }

            selected_endpoint.parse::<SocketAddr>().ok()
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn nat_punch_fingerprint(targets: &[SocketAddr], listen_port: u16) -> Option<String> {
    if targets.is_empty() {
        return None;
    }

    Some(format!(
        "{listen_port}|{}",
        targets
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>()
            .join(";")
    ))
}

fn hole_punch_with_retry(listen_port: u16, target: SocketAddr) -> Result<()> {
    let mut last_error = None;
    for _ in 0..20 {
        match hole_punch_udp(
            listen_port,
            target,
            20,
            Duration::from_millis(120),
            Duration::from_millis(120),
        ) {
            Ok(report) => {
                eprintln!(
                    "nat: punched {} from {} to {}, ack={}",
                    report.packets_sent, report.local_addr, target, report.packet_received
                );
                return Ok(());
            }
            Err(error) => {
                let error_text = error.to_string();
                if is_resource_busy_message(&error_text) {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                return Err(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("failed to bind hole-punch socket")))
}

fn maybe_run_nat_punch(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    tunnel_runtime: &mut CliTunnelRuntime,
    public_signal_endpoint: &mut Option<DiscoveredPublicSignalEndpoint>,
    last_attempt: &mut Option<(String, Instant)>,
) -> Result<()> {
    if !app.nat.enabled {
        *public_signal_endpoint = None;
        return Ok(());
    }

    let listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    if public_endpoint_for_listen_port(public_signal_endpoint.as_ref(), listen_port).is_none() {
        refresh_public_signal_endpoint(app, listen_port, public_signal_endpoint);
    }
    let targets = nat_punch_targets(app, own_pubkey, peer_announcements, listen_port);
    let Some(fingerprint) = nat_punch_fingerprint(&targets, listen_port) else {
        *last_attempt = None;
        return Ok(());
    };

    if runtime_has_handshake(tunnel_runtime) {
        *last_attempt = None;
        return Ok(());
    }

    let should_retry = match last_attempt {
        Some((last_fingerprint, last_at)) => {
            last_fingerprint != &fingerprint || last_at.elapsed() >= Duration::from_secs(10)
        }
        None => true,
    };
    if !should_retry {
        return Ok(());
    }

    tunnel_runtime.stop();
    thread::sleep(Duration::from_millis(150));
    refresh_public_signal_endpoint(app, listen_port, public_signal_endpoint);

    let mut punch_error = None;
    for target in &targets {
        if let Err(error) = hole_punch_with_retry(listen_port, *target) {
            punch_error = Some(error);
            break;
        }
    }

    // macOS can briefly hold the UDP port after STUN/hole-punch sockets close.
    thread::sleep(Duration::from_millis(POST_PUNCH_REAPPLY_DELAY_MS));

    tunnel_runtime.active_listen_port = Some(listen_port);
    tunnel_runtime
        .apply(
            app,
            own_pubkey,
            peer_announcements,
            path_book,
            unix_timestamp(),
        )
        .context("failed to re-apply tunnel runtime after nat punch")?;

    if let Some(error) = punch_error {
        return Err(error);
    }

    *last_attempt = Some((fingerprint, Instant::now()));
    Ok(())
}

fn pending_tunnel_heartbeat_ips(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
) -> Vec<Ipv4Addr> {
    let mut targets = app
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| {
            let announcement = peer_announcements.get(participant)?;
            let peer_pubkey_hex = key_b64_to_hex(&announcement.public_key).ok()?;
            let has_handshake = runtime_peers
                .and_then(|peers| peers.get(&peer_pubkey_hex))
                .is_some_and(WireGuardPeerStatus::has_handshake);
            if has_handshake {
                return None;
            }

            strip_cidr(&announcement.tunnel_ip).parse::<Ipv4Addr>().ok()
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn send_tunnel_heartbeat(peer_ip: Ipv4Addr) -> Result<()> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind local udp socket for tunnel heartbeat")?;
    socket
        .send_to(
            b"nvpn-heartbeat",
            SocketAddr::V4(SocketAddrV4::new(peer_ip, TUNNEL_HEARTBEAT_PORT)),
        )
        .with_context(|| format!("failed to send tunnel heartbeat to {peer_ip}"))?;
    Ok(())
}

fn heartbeat_pending_tunnel_peers(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    tunnel_runtime: &CliTunnelRuntime,
) -> Result<usize> {
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let targets =
        pending_tunnel_heartbeat_ips(app, own_pubkey, peer_announcements, runtime_peers.as_ref());
    for target in &targets {
        send_tunnel_heartbeat(*target)?;
    }
    Ok(targets.len())
}

fn build_runtime_magic_dns_records(
    app: &AppConfig,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> HashMap<String, Ipv4Addr> {
    let mut records = build_magic_dns_records(app);
    let suffix = app
        .magic_dns_suffix
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();

    for participant in &app.participant_pubkeys_hex() {
        let Some(alias) = app.peer_alias(participant) else {
            continue;
        };
        let Some(announcement) = peer_announcements.get(participant) else {
            continue;
        };
        let Ok(ipv4) = strip_cidr(&announcement.tunnel_ip).parse::<Ipv4Addr>() else {
            continue;
        };

        let alias = alias.to_ascii_lowercase();
        records.insert(alias.clone(), ipv4);
        if !suffix.is_empty() {
            records.insert(format!("{alias}.{suffix}"), ipv4);
        }
    }

    records
}

fn route_targets_for_tunnel_peers(peers: &[TunnelPeer]) -> Vec<String> {
    let mut route_targets = peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().cloned())
        .collect::<Vec<_>>();
    route_targets.sort();
    route_targets.dedup();
    route_targets
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    let tunnel_ip = tunnel_ip.trim();
    if tunnel_ip.is_empty() {
        return String::new();
    }
    if tunnel_ip.contains('/') {
        return tunnel_ip.to_string();
    }
    format!("{}/32", strip_cidr(tunnel_ip))
}

fn peer_signal_timeout_secs(announce_interval_secs: u64) -> u64 {
    announce_interval_secs
        .max(5)
        .saturating_mul(PEER_SIGNAL_TIMEOUT_MULTIPLIER)
        .max(MIN_PEER_SIGNAL_TIMEOUT_SECS)
}

fn peer_path_cache_timeout_secs(announce_interval_secs: u64) -> u64 {
    peer_signal_timeout_secs(announce_interval_secs)
        .saturating_mul(PEER_PATH_CACHE_TIMEOUT_MULTIPLIER)
        .max(MIN_PEER_PATH_CACHE_TIMEOUT_SECS)
}

fn persisted_peer_cache_timeout_secs(announce_interval_secs: u64) -> u64 {
    announce_interval_secs
        .max(5)
        .saturating_mul(PERSISTED_PEER_CACHE_TIMEOUT_MULTIPLIER)
        .max(MIN_PERSISTED_PEER_CACHE_TIMEOUT_SECS)
}

fn persisted_path_cache_timeout_secs(announce_interval_secs: u64) -> u64 {
    announce_interval_secs
        .max(5)
        .saturating_mul(PERSISTED_PATH_CACHE_TIMEOUT_MULTIPLIER)
        .max(MIN_PERSISTED_PATH_CACHE_TIMEOUT_SECS)
}

fn apply_presence_runtime_update(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    path_book: &mut PeerPathBook,
    now: u64,
    tunnel_runtime: &mut CliTunnelRuntime,
    magic_dns_runtime: Option<&ConnectMagicDnsRuntime>,
) -> Result<()> {
    tunnel_runtime.apply(app, own_pubkey, presence.known(), path_book, now)?;
    if let Some(runtime) = magic_dns_runtime {
        runtime.refresh_records(app, presence.known());
    }
    Ok(())
}

fn presence_peer_count(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
) -> usize {
    app.participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter(|participant| peer_announcements.contains_key(*participant))
        .count()
}

fn maybe_log_presence_mesh_count(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    expected_peers: usize,
    last_mesh_count: &mut usize,
) {
    let connected = presence_peer_count(app, own_pubkey, peer_announcements);
    if connected != *last_mesh_count {
        println!("mesh: {connected}/{expected_peers} peers with presence");
        *last_mesh_count = connected;
    }
}

fn tunnel_fingerprint(
    iface: &str,
    private_key: &str,
    listen_port: u16,
    local_address: &str,
    peers: &[TunnelPeer],
) -> String {
    let mut peer_entries = peers
        .iter()
        .map(|peer| {
            format!(
                "{}|{}|{}",
                peer.pubkey_hex,
                peer.endpoint,
                peer.allowed_ips.join(",")
            )
        })
        .collect::<Vec<_>>();
    peer_entries.sort();
    format!(
        "{iface}|{private_key}|{listen_port}|{local_address}|{}",
        peer_entries.join(";")
    )
}

async fn connect_session(args: ConnectArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.unwrap_or_else(default_config_path);
    let (app, network_id) =
        load_config_with_overrides(&config_path, args.network_id, args.participants)?;
    let configured_participants = app.participant_pubkeys_hex();
    if configured_participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running connect"
        ));
    }

    let relays = resolve_relays(&args.relay, &app);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let expected_peers = expected_peer_count(&app);
    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut outbound_announces = OutboundAnnounceBook::default();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut public_signal_endpoint = None;

    let mut client = NostrSignalingClient::from_secret_key(
        network_id.clone(),
        &app.nostr.secret_key,
        configured_participants.clone(),
    )?;
    client.connect(&relays).await?;
    let mut relay_connected = true;

    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    let _ = client.publish(SignalPayload::Hello).await;

    println!(
        "connect: network {} on {} relays; waiting for {expected_peers} configured peer(s)",
        network_id,
        relays.len()
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.announce_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
    reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now();
    let mut relays_paused_for_mesh = false;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = reconnect_interval.tick() => {
                if relay_connected || Instant::now() < reconnect_due {
                    continue;
                }

                let mesh_ready = should_pause_relays_for_mesh(
                    &app,
                    own_pubkey.as_deref(),
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    unix_timestamp(),
                );
                match relay_connection_action(
                    app.auto_disconnect_relays_when_mesh_ready,
                    relay_connected,
                    mesh_ready,
                ) {
                    RelayConnectionAction::StayPausedForMesh => {
                        reconnect_attempt = 0;
                        reconnect_due = Instant::now();
                        if !relays_paused_for_mesh {
                            println!("connect: {MESH_READY_RELAYS_PAUSED_STATUS}");
                            relays_paused_for_mesh = true;
                        }
                        continue;
                    }
                    RelayConnectionAction::ReconnectWhenDue => {
                        if relays_paused_for_mesh {
                            println!("connect: mesh degraded; reconnecting relays");
                            relays_paused_for_mesh = false;
                        }
                    }
                    RelayConnectionAction::KeepConnected | RelayConnectionAction::PauseForMesh => {
                        continue;
                    }
                }

                client.disconnect().await;
                client = NostrSignalingClient::from_secret_key(
                    network_id.clone(),
                    &app.nostr.secret_key,
                    configured_participants.clone(),
                )?;
                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        outbound_announces.clear();
                        if let Err(error) = publish_private_announce_to_active_peers(
                            &client,
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &mut outbound_announces,
                        )
                        .await
                        {
                            eprintln!("signal: active peer announce refresh failed after reconnect: {error}");
                        }
                        if let Err(error) = client.publish(SignalPayload::Hello).await {
                            let error_text = error.to_string();
                            reconnect_attempt = reconnect_attempt.saturating_add(1);
                            let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                            reconnect_due = Instant::now() + delay;
                            relay_connected = false;
                            eprintln!(
                                "signal: hello publish failed after reconnect (retry in {}s): {error_text}",
                                delay.as_secs()
                            );
                        }
                    }
                    Err(error) => {
                        let error_text = error.to_string();
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        eprintln!(
                            "signal: relay reconnect failed (retry in {}s): {error_text}",
                            delay.as_secs()
                        );
                    }
                }
            }
            _ = tunnel_heartbeat_interval.tick() => {
                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if !relay_connected
                    && let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        peer_announcements,
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    )
                {
                    eprintln!("nat: cached peer hole-punch failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed: {error}");
                }
            }
            _ = announce_interval.tick() => {
                let now = unix_timestamp();
                let removed = presence.prune_stale(
                    now,
                    peer_signal_timeout_secs(args.announce_interval_secs),
                );
                for participant in &removed {
                    outbound_announces.forget(participant);
                }
                let paths_pruned =
                    path_book.prune_stale(now, peer_path_cache_timeout_secs(args.announce_interval_secs));
                let recent = recently_seen_participants(
                    &presence,
                    now,
                    peer_signal_timeout_secs(args.announce_interval_secs),
                );
                outbound_announces.retain_participants(&recent);
                if !removed.is_empty() || paths_pruned {
                    last_nat_punch_attempt = None;
                    apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    )
                    .context("failed to apply tunnel update after stale peer expiry")?;
                    maybe_log_presence_mesh_count(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        expected_peers,
                        &mut last_mesh_count,
                    );
                }
                let mesh_ready = should_pause_relays_for_mesh(
                    &app,
                    own_pubkey.as_deref(),
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    now,
                );
                match relay_connection_action(
                    app.auto_disconnect_relays_when_mesh_ready,
                    relay_connected,
                    mesh_ready,
                ) {
                    RelayConnectionAction::PauseForMesh => {
                        client.disconnect().await;
                        relay_connected = false;
                        reconnect_attempt = 0;
                        reconnect_due = Instant::now();
                        if !relays_paused_for_mesh {
                            println!("connect: {MESH_READY_RELAYS_PAUSED_STATUS}");
                            relays_paused_for_mesh = true;
                        }
                    }
                    RelayConnectionAction::ReconnectWhenDue => {
                        if relays_paused_for_mesh {
                            println!("connect: mesh degraded; reconnecting relays");
                            relays_paused_for_mesh = false;
                            reconnect_due = Instant::now();
                        }
                    }
                    RelayConnectionAction::KeepConnected | RelayConnectionAction::StayPausedForMesh => {}
                }
                if !relay_connected {
                    continue;
                }

                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: periodic hole-punch failed: {error}");
                }
                if let Err(error) = publish_private_announce_to_active_peers(
                    &client,
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &mut outbound_announces,
                )
                .await
                {
                    eprintln!("signal: active peer announce refresh failed: {error}");
                }
                if let Err(error) = client.publish(SignalPayload::Hello).await {
                    let error_text = error.to_string();
                    if publish_error_requires_reconnect(&error_text) {
                        relay_connected = false;
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        eprintln!(
                            "signal: hello publish indicates disconnected relays (retry in {}s): {error_text}",
                            delay.as_secs()
                        );
                    } else {
                        eprintln!("signal: hello publish failed: {error_text}");
                    }
                }
            }
            message = async {
                if relay_connected {
                    client.recv().await
                } else {
                    std::future::pending::<Option<SignalEnvelope>>().await
                }
            } => {
                let Some(message) = message else {
                    relay_connected = false;
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                    reconnect_due = Instant::now() + delay;
                    eprintln!("signal: relay stream closed (retry in {}s)", delay.as_secs());
                    continue;
                };

                let sender_pubkey = message.sender_pubkey;
                let payload = message.payload.clone();
                let changed =
                    presence.apply_signal(sender_pubkey.clone(), message.payload, unix_timestamp());
                if matches!(&payload, SignalPayload::Disconnect { .. }) {
                    outbound_announces.forget(&sender_pubkey);
                }
                if !changed {
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    continue;
                }

                apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                )
                .context("failed to apply tunnel update")?;
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after peer signal failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after peer signal: {error}");
                }
                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_private_announce_to_participants(
                        &client,
                        &app,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &mut outbound_announces,
                        std::slice::from_ref(&sender_pubkey),
                    )
                    .await
                {
                    eprintln!("signal: targeted private announce failed: {error}");
                }

                maybe_log_presence_mesh_count(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    expected_peers,
                    &mut last_mesh_count,
                );
            }
        }
    }

    if relay_connected {
        let _ = client
            .publish(SignalPayload::Disconnect {
                node_id: app.node.id.clone(),
            })
            .await;
    }
    client.disconnect().await;
    tunnel_runtime.stop();
    println!("connect: disconnected");

    Ok(())
}

async fn daemon_session(args: DaemonArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    ensure_no_other_daemon_processes_for_config(&config_path, std::process::id())?;
    let network_override = args.network_id.clone();
    let participants_override = args.participants.clone();
    let (mut app, network_id) = load_config_with_overrides(
        &config_path,
        network_override.clone(),
        participants_override.clone(),
    )?;
    let mut configured_participants = app.participant_pubkeys_hex();
    if configured_participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running daemon"
        ));
    }

    let mut relays = resolve_relays(&args.relay, &app);
    let mut own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut expected_peers = expected_peer_count(&app);
    let state_file = daemon_state_file_path(&config_path);
    let peer_cache_file = daemon_peer_cache_file_path(&config_path);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut outbound_announces = OutboundAnnounceBook::default();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut public_signal_endpoint = None;
    let mut last_written_peer_cache = None;

    let mut client = NostrSignalingClient::from_secret_key(
        network_id.clone(),
        &app.nostr.secret_key,
        configured_participants.clone(),
    )?;

    let restored_peer_cache = match restore_daemon_peer_cache(
        DaemonPeerCacheRestore {
            path: &peer_cache_file,
            app: &app,
            network_id: &network_id,
            own_pubkey: own_pubkey.as_deref(),
            now: unix_timestamp(),
            announce_interval_secs: args.announce_interval_secs,
        },
        &mut presence,
        &mut path_book,
    ) {
        Ok(restored) => restored,
        Err(error) => {
            eprintln!("daemon: failed to restore peer cache: {error}");
            false
        }
    };

    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    if restored_peer_cache {
        let mut bootstrap_nat_attempt = None;
        if let Err(error) = maybe_run_nat_punch(
            &app,
            own_pubkey.as_deref(),
            direct_peer_announcements(&presence, false),
            &mut path_book,
            &mut tunnel_runtime,
            &mut public_signal_endpoint,
            &mut bootstrap_nat_attempt,
        ) {
            eprintln!("daemon: cached peer nat bootstrap failed: {error}");
        }
        if let Err(error) = heartbeat_pending_tunnel_peers(
            &app,
            own_pubkey.as_deref(),
            direct_peer_announcements(&presence, false),
            &tunnel_runtime,
        ) {
            eprintln!("daemon: cached peer heartbeat bootstrap failed: {error}");
        }
    }
    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.announce_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state_interval = tokio::time::interval(Duration::from_secs(1));
    state_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut reconnect_interval = tokio::time::interval(Duration::from_secs(1));
    reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tunnel_heartbeat_interval = tokio::time::interval(Duration::from_secs(2));
    tunnel_heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    #[cfg(unix)]
    let mut terminate_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
    #[cfg(unix)]
    let terminate_wait = async move {
        let _ = terminate_signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate_wait = std::future::pending::<()>();
    tokio::pin!(terminate_wait);

    let mut session_enabled = true;
    let mut session_status = if restored_peer_cache && app.auto_disconnect_relays_when_mesh_ready {
        "Trying cached mesh before relays".to_string()
    } else {
        "Connecting to relays".to_string()
    };
    let mut relay_connected = false;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now()
        + if restored_peer_cache && app.auto_disconnect_relays_when_mesh_ready {
            Duration::from_secs(DIRECT_MESH_BOOTSTRAP_RELAY_DELAY_SECS)
        } else {
            Duration::ZERO
        };
    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    write_daemon_state(
        &state_file,
        &build_daemon_runtime_state(
            &app,
            session_enabled,
            expected_peers,
            &presence,
            &tunnel_runtime,
            &session_status,
            relay_connected,
        ),
    )?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = &mut terminate_wait => {
                break;
            }
            _ = reconnect_interval.tick() => {
                if !session_enabled || relay_connected || Instant::now() < reconnect_due {
                    continue;
                }

                let mesh_ready = should_pause_relays_for_mesh(
                    &app,
                    own_pubkey.as_deref(),
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    unix_timestamp(),
                );
                match relay_connection_action(
                    app.auto_disconnect_relays_when_mesh_ready,
                    relay_connected,
                    mesh_ready,
                ) {
                    RelayConnectionAction::StayPausedForMesh => {
                        reconnect_attempt = 0;
                        reconnect_due = Instant::now();
                        session_status = MESH_READY_RELAYS_PAUSED_STATUS.to_string();
                        continue;
                    }
                    RelayConnectionAction::ReconnectWhenDue => {}
                    RelayConnectionAction::KeepConnected | RelayConnectionAction::PauseForMesh => {
                        continue;
                    }
                }

                client.disconnect().await;
                client = NostrSignalingClient::from_secret_key(
                    network_id.clone(),
                    &app.nostr.secret_key,
                    configured_participants.clone(),
                )?;

                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        session_status = "Connected".to_string();
                        outbound_announces.clear();
                        if let Err(error) = publish_private_announce_to_active_peers(
                            &client,
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &mut outbound_announces,
                        )
                        .await
                        {
                            let error_text = error.to_string();
                            session_status =
                                format!("Connected; private announce failed ({error_text})");
                            eprintln!("daemon: private announce failed after reconnect: {error_text}");
                        }
                        if let Err(error) = client.publish(SignalPayload::Hello).await {
                            let error_text = error.to_string();
                            session_status =
                                format!("Connected; hello publish failed ({error_text})");
                            eprintln!("daemon: initial hello publish failed after reconnect: {error_text}");
                        }
                    }
                    Err(error) => {
                        let error_text = error.to_string();
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        session_status = format!(
                            "Relay connect failed; retry in {}s ({error_text})",
                            delay.as_secs(),
                        );
                        eprintln!("daemon: relay connect failed (retry in {}s): {error_text}", delay.as_secs());
                    }
                }
            }
            _ = announce_interval.tick() => {
                if !session_enabled || !relay_connected {
                    continue;
                }

                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: periodic hole-punch failed: {error}");
                }
                if let Err(error) = publish_private_announce_to_active_peers(
                    &client,
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &mut outbound_announces,
                )
                .await
                {
                    let error_text = error.to_string();
                    session_status = format!("Private announce failed ({error_text})");
                }
                if let Err(error) = client.publish(SignalPayload::Hello).await {
                    let error_text = error.to_string();
                    if publish_error_requires_reconnect(&error_text) {
                        relay_connected = false;
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                        reconnect_due = Instant::now() + delay;
                        session_status = format!(
                            "Relay disconnected; retry in {}s ({error_text})",
                            delay.as_secs(),
                        );
                        eprintln!("daemon: hello publish indicates disconnected relays (retry in {}s): {error_text}", delay.as_secs());
                    } else {
                        session_status = format!("Hello publish failed ({error_text})");
                    }
                }
            }
            _ = tunnel_heartbeat_interval.tick() => {
                if !session_enabled {
                    continue;
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if !relay_connected
                    && let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        peer_announcements,
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    )
                {
                    eprintln!("nat: cached peer hole-punch failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed: {error}");
                }
            }
            _ = state_interval.tick() => {
                if let Some(request) = take_daemon_control_request(&config_path) {
                    match request {
                        DaemonControlRequest::Stop => break,
                        DaemonControlRequest::Pause => {
                            if relay_connected {
                                let _ = client
                                    .publish(SignalPayload::Disconnect {
                                        node_id: app.node.id.clone(),
                                    })
                                    .await;
                            }
                            client.disconnect().await;
                            relay_connected = false;
                            session_enabled = false;
                            reconnect_attempt = 0;
                            reconnect_due = Instant::now();
                            presence = PeerPresenceBook::default();
                            outbound_announces.clear();
                            last_nat_punch_attempt = None;
                            if let Err(error) = apply_presence_runtime_update(
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &mut path_book,
                                unix_timestamp(),
                                &mut tunnel_runtime,
                                magic_dns_runtime.as_ref(),
                            ) {
                                session_status = format!("Pause failed ({error})");
                            } else {
                                session_status = "Paused".to_string();
                            }
                        }
                        DaemonControlRequest::Resume => {
                            if !session_enabled {
                                session_enabled = true;
                                relay_connected = false;
                                reconnect_attempt = 0;
                                reconnect_due = Instant::now();
                                let restored_peer_cache = match restore_daemon_peer_cache(
                                    DaemonPeerCacheRestore {
                                        path: &peer_cache_file,
                                        app: &app,
                                        network_id: &network_id,
                                        own_pubkey: own_pubkey.as_deref(),
                                        now: unix_timestamp(),
                                        announce_interval_secs: args.announce_interval_secs,
                                    },
                                    &mut presence,
                                    &mut path_book,
                                ) {
                                    Ok(restored) => restored,
                                    Err(error) => {
                                        eprintln!("daemon: failed to restore peer cache on resume: {error}");
                                        false
                                    }
                                };
                                if let Err(error) = apply_presence_runtime_update(
                                    &app,
                                    own_pubkey.as_deref(),
                                    &presence,
                                    &mut path_book,
                                    unix_timestamp(),
                                    &mut tunnel_runtime,
                                    magic_dns_runtime.as_ref(),
                                ) {
                                    session_status = format!("Resume failed ({error})");
                                } else {
                                    session_status = if restored_peer_cache && app.auto_disconnect_relays_when_mesh_ready {
                                        reconnect_due = Instant::now() + Duration::from_secs(DIRECT_MESH_BOOTSTRAP_RELAY_DELAY_SECS);
                                        "Resuming with cached mesh".to_string()
                                    } else {
                                        "Resuming".to_string()
                                    };
                                }
                            }
                        }
                        DaemonControlRequest::Reload => {
                            match load_config_with_overrides(
                                &config_path,
                                network_override.clone(),
                                participants_override.clone(),
                            ) {
                                Ok((reloaded_app, _)) => {
                                    let reloaded_participants = reloaded_app.participant_pubkeys_hex();
                                    if reloaded_participants.is_empty() {
                                        session_status = "Config reload rejected: no participants configured".to_string();
                                    } else {
                                        app = reloaded_app;
                                        configured_participants = reloaded_participants;
                                        expected_peers = expected_peer_count(&app);
                                        own_pubkey = app.own_nostr_pubkey_hex().ok();
                                        relays = resolve_relays(&args.relay, &app);

                                        let configured_set = configured_participants
                                            .iter()
                                            .cloned()
                                            .collect::<HashSet<_>>();
                                        presence.retain_participants(&configured_set);
                                        path_book.retain_participants(&configured_set);
                                        outbound_announces.retain_participants(&configured_set);
                                        outbound_announces.clear();
                                        last_nat_punch_attempt = None;
                                        client.disconnect().await;
                                        match NostrSignalingClient::from_secret_key(
                                            network_id.clone(),
                                            &app.nostr.secret_key,
                                            configured_participants.clone(),
                                        ) {
                                            Ok(new_client) => {
                                                client = new_client;
                                                if session_enabled {
                                                    match client.connect(&relays).await {
                                                        Ok(()) => {
                                                            relay_connected = true;
                                                            reconnect_attempt = 0;
                                                            reconnect_due = Instant::now();
                                                            session_status = "Config reloaded".to_string();
                                                            if let Err(error) = publish_private_announce_to_active_peers(
                                                                &client,
                                                                &app,
                                                                own_pubkey.as_deref(),
                                                                &presence,
                                                                &tunnel_runtime,
                                                                public_signal_endpoint.as_ref(),
                                                                &mut outbound_announces,
                                                            ).await {
                                                                session_status = format!(
                                                                    "Config reloaded; private announce failed ({})",
                                                                    error
                                                                );
                                                            }
                                                            if let Err(error) = client.publish(SignalPayload::Hello).await {
                                                                session_status = format!(
                                                                    "Config reloaded; hello publish failed ({})",
                                                                    error
                                                                );
                                                            }
                                                        }
                                                        Err(error) => {
                                                            relay_connected = false;
                                                            reconnect_attempt = reconnect_attempt.saturating_add(1);
                                                            let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                                                            reconnect_due = Instant::now() + delay;
                                                            session_status = format!(
                                                                "Config reloaded; relay reconnect failed (retry in {}s: {})",
                                                                delay.as_secs(),
                                                                error
                                                            );
                                                        }
                                                    }
                                                } else {
                                                    relay_connected = false;
                                                    reconnect_attempt = 0;
                                                    reconnect_due = Instant::now();
                                                    session_status = "Config reloaded (paused)".to_string();
                                                }
                                            }
                                            Err(error) => {
                                                session_status = format!(
                                                    "Config reload failed (signal client init): {}",
                                                    error
                                                );
                                            }
                                        }

                                        if let Err(error) = apply_presence_runtime_update(
                                            &app,
                                            own_pubkey.as_deref(),
                                            &presence,
                                            &mut path_book,
                                            unix_timestamp(),
                                            &mut tunnel_runtime,
                                            magic_dns_runtime.as_ref(),
                                        ) {
                                            session_status = format!(
                                                "Config reloaded; tunnel update failed ({})",
                                                error
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    session_status = format!("Config reload failed ({})", error);
                                }
                            }
                        }
                    }
                }
                if session_enabled {
                    let now = unix_timestamp();
                    let removed = presence.prune_stale(
                        now,
                        peer_signal_timeout_secs(args.announce_interval_secs),
                    );
                    for participant in &removed {
                        outbound_announces.forget(participant);
                    }
                    let paths_pruned =
                        path_book.prune_stale(now, peer_path_cache_timeout_secs(args.announce_interval_secs));
                    let recent = recently_seen_participants(
                        &presence,
                        now,
                        peer_signal_timeout_secs(args.announce_interval_secs),
                    );
                    outbound_announces.retain_participants(&recent);
                    if !removed.is_empty() || paths_pruned {
                        last_nat_punch_attempt = None;
                        if let Err(error) = apply_presence_runtime_update(
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &mut path_book,
                            now,
                            &mut tunnel_runtime,
                            magic_dns_runtime.as_ref(),
                        ) {
                            session_status = format!("Stale peer expiry update failed ({error})");
                        } else {
                            maybe_log_presence_mesh_count(
                                &app,
                                own_pubkey.as_deref(),
                                presence.active(),
                                expected_peers,
                                &mut last_mesh_count,
                            );
                        }
                    }
                }
                let mesh_ready = should_pause_relays_for_mesh(
                    &app,
                    own_pubkey.as_deref(),
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    unix_timestamp(),
                );
                if session_enabled
                    && matches!(
                        relay_connection_action(
                            app.auto_disconnect_relays_when_mesh_ready,
                            relay_connected,
                            mesh_ready,
                        ),
                        RelayConnectionAction::PauseForMesh
                    )
                {
                    client.disconnect().await;
                    relay_connected = false;
                    reconnect_attempt = 0;
                    reconnect_due = Instant::now();
                    session_status = MESH_READY_RELAYS_PAUSED_STATUS.to_string();
                }
                if let Err(error) = write_daemon_peer_cache_if_changed(
                    DaemonPeerCacheWrite {
                        path: &peer_cache_file,
                        network_id: &network_id,
                        own_pubkey: own_pubkey.as_deref(),
                        presence: &presence,
                        path_book: &path_book,
                        tunnel_runtime: &tunnel_runtime,
                        now: unix_timestamp(),
                    },
                    &mut last_written_peer_cache,
                ) {
                    eprintln!("daemon: failed to persist peer cache: {error}");
                }
                let _ = write_daemon_state(
                    &state_file,
                    &build_daemon_runtime_state(
                        &app,
                        session_enabled,
                        expected_peers,
                        &presence,
                        &tunnel_runtime,
                        &session_status,
                        relay_connected,
                    ),
                );
            }
            message = async {
                if session_enabled && relay_connected {
                    client.recv().await
                } else {
                    std::future::pending::<Option<SignalEnvelope>>().await
                }
            } => {
                let Some(message) = message else {
                    relay_connected = false;
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let delay = daemon_reconnect_backoff_delay(reconnect_attempt);
                    reconnect_due = Instant::now() + delay;
                    session_status = format!("Signal stream closed; retry in {}s", delay.as_secs());
                    eprintln!("daemon: signal stream closed (retry in {}s)", delay.as_secs());
                    continue;
                };

                let sender_pubkey = message.sender_pubkey;
                let payload = message.payload.clone();
                let changed =
                    presence.apply_signal(sender_pubkey.clone(), message.payload, unix_timestamp());
                if matches!(&payload, SignalPayload::Disconnect { .. }) {
                    outbound_announces.forget(&sender_pubkey);
                }
                if !changed {
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    continue;
                }

                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    let error_text = error.to_string();
                    session_status = format!("Tunnel update failed ({error_text})");
                } else {
                    if let Err(error) = maybe_run_nat_punch(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        &mut path_book,
                        &mut tunnel_runtime,
                        &mut public_signal_endpoint,
                        &mut last_nat_punch_attempt,
                    ) {
                        eprintln!("nat: hole-punch after peer signal failed: {error}");
                    }
                    if let Err(error) = heartbeat_pending_tunnel_peers(
                        &app,
                        own_pubkey.as_deref(),
                        presence.active(),
                        &tunnel_runtime,
                    ) {
                        eprintln!("tunnel: peer heartbeat failed after peer signal: {error}");
                    }
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    session_status = if session_enabled {
                        "Connected".to_string()
                    } else {
                        "Paused".to_string()
                    };
                }

                maybe_log_presence_mesh_count(
                    &app,
                    own_pubkey.as_deref(),
                    presence.active(),
                    expected_peers,
                    &mut last_mesh_count,
                );
            }
        }
    }

    if relay_connected {
        let _ = client
            .publish(SignalPayload::Disconnect {
                node_id: app.node.id.clone(),
            })
            .await;
    }
    client.disconnect().await;
    tunnel_runtime.stop();

    let final_state = DaemonRuntimeState {
        updated_at: unix_timestamp(),
        session_active: false,
        relay_connected: false,
        session_status: "Disconnected".to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count: 0,
        mesh_ready: false,
        peers: Vec::new(),
    };
    let _ = write_daemon_state(&state_file, &final_state);

    Ok(())
}

fn daemon_reconnect_backoff_delay(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        3 => Duration::from_secs(4),
        4 => Duration::from_secs(8),
        5 => Duration::from_secs(16),
        _ => Duration::from_secs(30),
    }
}

fn publish_error_requires_reconnect(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("client not connected")
        || lower.contains("relay pool shutdown")
        || lower.contains("relay not connected")
        || lower.contains("status changed")
        || lower.contains("recv message response timeout")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
}

fn build_daemon_runtime_state(
    app: &AppConfig,
    session_active: bool,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    session_status: &str,
    relay_connected: bool,
) -> DaemonRuntimeState {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let now = unix_timestamp();
    let mut peers = Vec::new();

    for participant in &app.participant_pubkeys_hex() {
        if Some(participant.as_str()) == own_pubkey.as_deref() {
            continue;
        }

        let Some(announcement) = presence.announcement_for(participant) else {
            peers.push(DaemonPeerState {
                participant_pubkey: participant.clone(),
                node_id: String::new(),
                tunnel_ip: String::new(),
                endpoint: String::new(),
                public_key: String::new(),
                advertised_routes: Vec::new(),
                presence_timestamp: 0,
                last_signal_seen_at: None,
                reachable: false,
                last_handshake_at: None,
                error: Some("no signal yet".to_string()),
            });
            continue;
        };

        let signal_active = presence.active().contains_key(participant);
        let peer_pubkey_hex = key_b64_to_hex(&announcement.public_key).ok();
        let runtime_peer = peer_runtime_lookup(announcement, runtime_peers.as_ref());
        let reachable = runtime_peer.is_some_and(peer_has_recent_handshake);
        let error = if peer_pubkey_hex.is_none() {
            Some("invalid peer key".to_string())
        } else if !signal_active && !reachable {
            Some("signal stale".to_string())
        } else if runtime_peer.is_none() {
            Some("peer not in tunnel runtime".to_string())
        } else if !reachable {
            Some("awaiting handshake".to_string())
        } else {
            None
        };

        peers.push(DaemonPeerState {
            participant_pubkey: participant.clone(),
            node_id: announcement.node_id.clone(),
            tunnel_ip: announcement.tunnel_ip.clone(),
            endpoint: announcement.endpoint.clone(),
            public_key: announcement.public_key.clone(),
            advertised_routes: announcement.advertised_routes.clone(),
            presence_timestamp: announcement.timestamp,
            last_signal_seen_at: presence.last_seen_at(participant),
            reachable,
            last_handshake_at: runtime_peer.and_then(|peer| peer.last_handshake_at(now)),
            error,
        });
    }

    let connected_peer_count = connected_peer_count_for_runtime(
        app,
        own_pubkey.as_deref(),
        presence,
        runtime_peers.as_ref(),
        now,
    );
    let mesh_ready = expected_peers > 0 && connected_peer_count >= expected_peers;
    DaemonRuntimeState {
        updated_at: now,
        session_active,
        relay_connected,
        session_status: session_status.to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        peers,
    }
}

async fn start_session(args: StartArgs) -> Result<()> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let (app, _network_id) = load_config_with_overrides(
        &config_path,
        args.network_id.clone(),
        args.participants.clone(),
    )?;

    let should_connect = if args.connect {
        true
    } else if args.no_connect {
        false
    } else {
        app.autoconnect
    };

    if !should_connect {
        println!(
            "start: autoconnect is disabled; not starting a session (pass --connect to override)"
        );
        return Ok(());
    }

    let connect_args = ConnectArgs {
        config: Some(config_path.clone()),
        network_id: args.network_id,
        participants: args.participants,
        relay: args.relay,
        iface: args.iface,
        announce_interval_secs: args.announce_interval_secs,
    };

    if args.daemon {
        let status = daemon_status(&config_path)?;
        if status.running {
            return Err(anyhow!(
                "daemon already running with pid {}",
                status.pid.unwrap_or_default()
            ));
        }

        let pid = spawn_daemon_process(&connect_args, &config_path)?;
        println!("daemon started: pid {pid}");
        println!("pid_file: {}", status.pid_file.display());
        println!("log_file: {}", status.log_file.display());
        return Ok(());
    }

    connect_session(connect_args).await
}

fn stop_daemon(args: StopArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    let mut daemon_pids = find_daemon_pids_by_config(&config_path);
    if daemon_pids.is_empty()
        && let Some(pid) = status.pid
        && daemon_process_matches(pid, &config_path)
    {
        daemon_pids.push(pid);
    }
    daemon_pids.sort_unstable();
    daemon_pids.dedup();

    if daemon_pids.is_empty() {
        let _ = fs::remove_file(&status.pid_file);
        let _ = fs::remove_file(daemon_control_file_path(&config_path));
        println!("daemon: not running");
        return Ok(());
    }

    let mut requested_control_stop = false;
    for pid in &daemon_pids {
        match send_signal(*pid, "-TERM") {
            Ok(()) => {}
            Err(error) if kill_error_requires_control_fallback(&error.to_string()) => {
                if !requested_control_stop {
                    request_daemon_stop(&config_path)?;
                    requested_control_stop = true;
                }
            }
            Err(error) => return Err(error),
        }
    }

    let timeout = Duration::from_secs(args.timeout_secs.max(1));
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if find_daemon_pids_by_config(&config_path).is_empty() {
            let _ = fs::remove_file(&status.pid_file);
            let _ = fs::remove_file(daemon_control_file_path(&config_path));
            println!("daemon stopped");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(120));
    }

    if args.force {
        for pid in find_daemon_pids_by_config(&config_path) {
            if let Err(error) = send_signal(pid, "-KILL")
                && !kill_error_requires_control_fallback(&error.to_string())
            {
                return Err(error);
            }
        }
        thread::sleep(Duration::from_millis(120));
    }

    if requested_control_stop {
        request_daemon_stop(&config_path)?;
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            if find_daemon_pids_by_config(&config_path).is_empty() {
                let _ = fs::remove_file(&status.pid_file);
                let _ = fs::remove_file(daemon_control_file_path(&config_path));
                println!("daemon stopped");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(120));
        }
    }

    let remaining = find_daemon_pids_by_config(&config_path);
    if !remaining.is_empty() {
        let hint = if requested_control_stop {
            "daemon ignored local stop request; likely an older daemon binary is still running. perform one elevated stop (e.g. sudo nvpn stop --force --config <config>) to migrate"
        } else {
            "try --force"
        };
        return Err(anyhow!(
            "failed to stop daemon(s) for {}; remaining pid(s): {}; {hint}",
            config_path.display(),
            remaining
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let _ = fs::remove_file(&status.pid_file);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    println!("daemon stopped");
    Ok(())
}

fn reload_daemon(args: ReloadArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    if !status.running {
        println!("daemon: not running");
        return Ok(());
    }

    request_daemon_reload(&config_path)?;
    wait_for_daemon_control_ack(&config_path, Duration::from_secs(3))?;
    println!("daemon reload requested");
    Ok(())
}

fn control_daemon(args: ControlArgs, request: DaemonControlRequest) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    if !status.running {
        println!("daemon: not running");
        return Ok(());
    }

    write_daemon_control_request(&config_path, request)?;
    wait_for_daemon_control_ack(&config_path, Duration::from_secs(3))?;
    match request {
        DaemonControlRequest::Pause => {
            wait_for_daemon_session_active(&config_path, false, Duration::from_secs(2))?;
        }
        DaemonControlRequest::Resume => {
            wait_for_daemon_session_active(&config_path, true, Duration::from_secs(2))?;
        }
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => {}
    }

    match request {
        DaemonControlRequest::Pause => println!("daemon pause requested"),
        DaemonControlRequest::Resume => println!("daemon resume requested"),
        DaemonControlRequest::Reload => println!("daemon reload requested"),
        DaemonControlRequest::Stop => println!("daemon stop requested"),
    }
    Ok(())
}

fn daemon_status(config_path: &Path) -> Result<DaemonStatus> {
    let pid_file = daemon_pid_file_path(config_path);
    let log_file = daemon_log_file_path(config_path);
    let state_file = daemon_state_file_path(config_path);
    let pid_record = read_daemon_pid_record(&pid_file)?;
    let pid_from_record = pid_record.as_ref().map(|record| record.pid);
    let pid_from_scan = find_daemon_pid_by_config(config_path);
    let pid_from_record_running =
        pid_from_record.filter(|pid| daemon_process_matches(*pid, config_path));
    let running_pid = pid_from_scan.or(pid_from_record_running);
    let running = running_pid.is_some();
    let pid = running_pid.or(pid_from_record);
    let state = read_daemon_state(&state_file)?;

    if let Some(pid) = running_pid
        && pid_from_record != Some(pid)
    {
        let refreshed = DaemonPidRecord {
            pid,
            config_path: config_path.display().to_string(),
            started_at: unix_timestamp(),
        };
        let _ = write_daemon_pid_record(&pid_file, &refreshed);
    }

    Ok(DaemonStatus {
        running,
        pid,
        pid_file,
        log_file,
        state_file,
        state,
    })
}

fn daemon_status_json(config_path: &Path) -> Result<serde_json::Value> {
    let status = daemon_status(config_path)?;
    Ok(json!({
        "running": status.running,
        "pid": status.pid,
        "pid_file": status.pid_file,
        "log_file": status.log_file,
        "state_file": status.state_file,
        "state": status.state,
    }))
}

fn daemon_pid_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.pid")
}

fn daemon_log_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.log")
}

fn daemon_state_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.state.json")
}

fn daemon_control_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.control")
}

fn daemon_peer_cache_file_path(config_path: &Path) -> PathBuf {
    let parent = config_path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    parent.join("daemon.mesh-cache.json")
}

fn ensure_no_other_daemon_processes_for_config(config_path: &Path, current_pid: u32) -> Result<()> {
    let mut daemon_pids = find_daemon_pids_by_config(config_path);
    daemon_pids.retain(|pid| *pid != current_pid);

    let pid_file = daemon_pid_file_path(config_path);
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && record.pid != current_pid
        && daemon_process_matches(record.pid, config_path)
        && !daemon_pids.contains(&record.pid)
    {
        daemon_pids.push(record.pid);
    }

    daemon_pids.sort_unstable();
    daemon_pids.dedup();

    if let Some(existing_pid) = daemon_pids.first().copied() {
        return Err(anyhow!("daemon already running with pid {}", existing_pid));
    }

    Ok(())
}

fn write_daemon_control_request(config_path: &Path, request: DaemonControlRequest) -> Result<()> {
    let control_file = daemon_control_file_path(config_path);
    if let Some(parent) = control_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&control_file, format!("{}\n", request.as_str())).with_context(|| {
        format!(
            "failed to write daemon control request {}",
            control_file.display()
        )
    })?;
    set_daemon_runtime_file_permissions(&control_file)?;
    Ok(())
}

fn request_daemon_stop(config_path: &Path) -> Result<()> {
    write_daemon_control_request(config_path, DaemonControlRequest::Stop)
}

fn request_daemon_reload(config_path: &Path) -> Result<()> {
    write_daemon_control_request(config_path, DaemonControlRequest::Reload)
}

fn wait_for_daemon_control_ack(config_path: &Path, timeout: Duration) -> Result<()> {
    let control_file = daemon_control_file_path(config_path);
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !control_file.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(anyhow!(
        "daemon did not acknowledge control request within {}s; restart the daemon with a newer nvpn binary",
        timeout.as_secs()
    ))
}

fn wait_for_daemon_session_active(
    config_path: &Path,
    expected_active: bool,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(status) = daemon_status(config_path) {
            let current_active = status
                .state
                .as_ref()
                .map(|state| state.session_active)
                .unwrap_or(status.running);
            if current_active == expected_active {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let verb = if expected_active { "resume" } else { "pause" };
    Err(anyhow!(
        "daemon acknowledged control request but did not {verb}; likely an older nvpn daemon binary is still running. restart or reinstall the app/service so the daemon matches the current CLI"
    ))
}

fn take_daemon_control_request(config_path: &Path) -> Option<DaemonControlRequest> {
    let control_file = daemon_control_file_path(config_path);
    let raw = match fs::read_to_string(&control_file) {
        Ok(raw) => raw,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "daemon: failed to read control request {}: {}",
                    control_file.display(),
                    error
                );
            }
            return None;
        }
    };

    let _ = fs::remove_file(&control_file);
    DaemonControlRequest::parse(&raw)
}

fn read_daemon_pid_record(path: &Path) -> Result<Option<DaemonPidRecord>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon pid file {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonPidRecord>(&raw)
        .with_context(|| format!("failed to parse daemon pid file {}", path.display()))?;
    Ok(Some(parsed))
}

fn write_daemon_pid_record(path: &Path, record: &DaemonPidRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(record)?;
    write_runtime_file_atomically(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon pid file {}", path.display()))?;
    set_daemon_runtime_file_permissions(path)?;
    Ok(())
}

fn read_daemon_state(path: &Path) -> Result<Option<DaemonRuntimeState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon state file {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonRuntimeState>(&raw)
        .with_context(|| format!("failed to parse daemon state file {}", path.display()))?;
    Ok(Some(parsed))
}

fn write_daemon_state(path: &Path, state: &DaemonRuntimeState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    write_runtime_file_atomically(path, raw.as_bytes())
        .with_context(|| format!("failed to write daemon state file {}", path.display()))?;
    set_daemon_runtime_file_permissions(path)?;
    Ok(())
}

fn read_daemon_peer_cache(path: &Path) -> Result<Option<DaemonPeerCacheState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon peer cache {}", path.display()))?;
    let parsed = serde_json::from_str::<DaemonPeerCacheState>(&raw)
        .with_context(|| format!("failed to parse daemon peer cache {}", path.display()))?;
    Ok(Some(parsed))
}

fn write_daemon_peer_cache(path: &Path, state: &DaemonPeerCacheState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(path, raw)
        .with_context(|| format!("failed to write daemon peer cache {}", path.display()))?;
    set_private_cache_file_permissions(path)?;
    Ok(())
}

fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime file has no parent: {}", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("runtime"),
        std::process::id(),
        unix_timestamp()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temp runtime file {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn spawn_daemon_process(args: &ConnectArgs, config_path: &Path) -> Result<u32> {
    if let Some(existing_pid) = find_daemon_pid_by_config(config_path) {
        return Err(anyhow!("daemon already running with pid {}", existing_pid));
    }

    let pid_file = daemon_pid_file_path(config_path);
    if let Some(record) = read_daemon_pid_record(&pid_file)?
        && daemon_process_matches(record.pid, config_path)
    {
        return Err(anyhow!("daemon already running with pid {}", record.pid));
    }

    let log_file_path = daemon_log_file_path(config_path);
    if let Some(parent) = log_file_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_file_path)
        .with_context(|| format!("failed to open {}", log_file_path.display()))?;
    let _ = set_daemon_runtime_file_permissions(&log_file_path);
    let stderr_log = log_file
        .try_clone()
        .context("failed to clone daemon log file handle")?;

    let mut command = ProcessCommand::new(
        std::env::current_exe().context("failed to resolve current executable")?,
    );
    command
        .arg("daemon")
        .arg("--config")
        .arg(config_path)
        .arg("--iface")
        .arg(&args.iface)
        .arg("--announce-interval-secs")
        .arg(args.announce_interval_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_log));

    if let Some(network_id) = &args.network_id {
        command.arg("--network-id").arg(network_id);
    }
    for participant in &args.participants {
        command.arg("--participant").arg(participant);
    }
    for relay in &args.relay {
        command.arg("--relay").arg(relay);
    }

    let mut child = command
        .spawn()
        .context("failed to spawn daemonized connect process")?;
    let pid = child.id();

    // Wait briefly to catch startup failures that occur after initial bootstrapping
    // (for example: missing tunnel permissions or resolver install errors).
    for _ in 0..25 {
        if let Some(status) = child
            .try_wait()
            .context("failed to verify daemon process state")?
        {
            let log_tail = read_daemon_log_tail(&log_file_path, 20);
            return if log_tail.is_empty() {
                Err(anyhow!(
                    "daemon process exited during startup with status {status}"
                ))
            } else {
                Err(anyhow!(
                    "daemon process exited during startup with status {status}\nlog tail:\n{log_tail}"
                ))
            };
        }
        thread::sleep(Duration::from_millis(100));
    }

    let record = DaemonPidRecord {
        pid,
        config_path: config_path.display().to_string(),
        started_at: unix_timestamp(),
    };
    write_daemon_pid_record(&pid_file, &record)?;
    Ok(pid)
}

fn stop_existing_daemons_before_service_install(config_path: &Path) -> Result<()> {
    stop_daemon(StopArgs {
        config: Some(config_path.to_path_buf()),
        timeout_secs: 5,
        force: true,
    })
}

fn read_daemon_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(raw) = fs::read_to_string(path) else {
        return String::new();
    };

    let mut lines = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() > max_lines {
        lines.drain(0..(lines.len() - max_lines));
    }
    lines.join("\n")
}

fn is_process_running(pid: u32) -> bool {
    if cfg!(not(unix)) {
        return false;
    }

    ProcessCommand::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("pid=")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty())
        .unwrap_or(false)
}

fn daemon_process_matches(pid: u32, config_path: &Path) -> bool {
    if !is_process_running(pid) {
        return false;
    }

    let output = ProcessCommand::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("command=")
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let command = String::from_utf8_lossy(&output.stdout);
    let config_text = config_path.display().to_string();
    command.contains(" daemon ")
        && command.contains("--config")
        && command.contains(config_text.as_str())
}

fn find_daemon_pid_by_config(config_path: &Path) -> Option<u32> {
    find_daemon_pids_by_config(config_path).into_iter().next()
}

fn find_daemon_pids_by_config(config_path: &Path) -> Vec<u32> {
    if cfg!(not(unix)) {
        return Vec::new();
    }

    let output = ProcessCommand::new("ps")
        .arg("ax")
        .arg("-o")
        .arg("pid=,command=")
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    daemon_pids_from_ps_output(&String::from_utf8_lossy(&output.stdout), config_path)
}

fn daemon_pids_from_ps_output(ps_output: &str, config_path: &Path) -> Vec<u32> {
    let config_text = config_path.display().to_string();
    let mut pids = Vec::new();

    for line in ps_output.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let Some(pid_text) = parts.next() else {
            continue;
        };
        let Some(command) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        if command.contains(" daemon ")
            && command.contains("--config")
            && command.contains(config_text.as_str())
        {
            pids.push(pid);
        }
    }

    pids.sort_unstable();
    pids.dedup();
    pids
}

fn set_daemon_runtime_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Daemon runtime files must stay readable by the desktop app even when
        // the daemon was started with elevated privileges.
        let permissions = fs::Permissions::from_mode(0o644);
        fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "failed to set daemon runtime file permissions on {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn set_private_cache_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set daemon peer cache file permissions on {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

fn send_signal(pid: u32, signal: &str) -> Result<()> {
    if cfg!(not(unix)) {
        return Err(anyhow!("daemon signal control is only supported on unix"));
    }

    let output = ProcessCommand::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .output()
        .with_context(|| format!("failed to execute kill {signal} {pid}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "kill {signal} {pid} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

fn kill_error_requires_control_fallback(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("operation not permitted") || lower.contains("permission denied")
}

fn run_ping(target: &str, count: u32, timeout_secs: u64) -> Result<()> {
    let mut command = ProcessCommand::new("ping");
    if cfg!(target_os = "windows") {
        command
            .arg("-n")
            .arg(count.to_string())
            .arg("-w")
            .arg((timeout_secs.saturating_mul(1000)).to_string())
            .arg(target);
    } else {
        command
            .arg("-c")
            .arg(count.to_string())
            .arg("-W")
            .arg(timeout_secs.to_string())
            .arg(target);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to execute ping for {target}"))?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        return Err(anyhow!("ping failed for {target}"));
    }

    Ok(())
}

fn resolve_ping_target(target: &str, peers: &[PeerAnnouncement]) -> Option<String> {
    if target.parse::<IpAddr>().is_ok() {
        return Some(target.to_string());
    }

    peers.iter().find_map(|peer| {
        let tunnel_ip = strip_cidr(&peer.tunnel_ip);
        if peer.node_id == target || peer.tunnel_ip == target || tunnel_ip == target {
            Some(tunnel_ip.to_string())
        } else {
            None
        }
    })
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
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

async fn run_netcheck(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    timeout_secs: u64,
) -> Vec<RelayCheck> {
    let mut checks = Vec::with_capacity(relays.len());

    for relay in relays {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), async {
            let client = NostrSignalingClient::from_secret_key(
                network_id.to_string(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(std::slice::from_ref(relay)).await?;
            client.disconnect().await;
            Result::<(), anyhow::Error>::Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: None,
            }),
            Ok(Err(error)) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some(error.to_string()),
            }),
            Err(_) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some("timeout".to_string()),
            }),
        }
    }

    checks
}

fn run_service_command(args: ServiceArgs) -> Result<()> {
    match args.command {
        ServiceCommand::Install(args) => service_install(args),
        ServiceCommand::Enable(args) => service_enable(args),
        ServiceCommand::Disable(args) => service_disable(args),
        ServiceCommand::Uninstall(args) => service_uninstall(args),
        ServiceCommand::Status(args) => service_status(args),
    }
}

fn service_install(args: ServiceInstallArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let mut config = load_or_default_config(&config_path)?;
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    config.save(&config_path)?;

    if config.all_participant_pubkeys_hex().is_empty() {
        return Err(anyhow!(
            "configure at least one participant before installing the system service"
        ));
    }

    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let executable = fs::canonicalize(&executable)
        .with_context(|| format!("failed to canonicalize {}", executable.display()))?;
    let config_path = fs::canonicalize(&config_path)
        .with_context(|| format!("failed to canonicalize {}", config_path.display()))?;
    let log_path = daemon_log_file_path(&config_path);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    #[cfg(target_os = "macos")]
    {
        macos_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.announce_interval_secs.max(1),
            &log_path,
            args.force,
        )
    }

    #[cfg(target_os = "linux")]
    {
        linux_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.announce_interval_secs.max(1),
            &log_path,
            args.force,
        )
    }

    #[cfg(target_os = "windows")]
    {
        windows_install_service(
            &executable,
            &config_path,
            &args.iface,
            args.announce_interval_secs.max(1),
            args.force,
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (
            executable,
            config_path,
            log_path,
            args.iface,
            args.announce_interval_secs,
            args.force,
        );
        Err(anyhow!(
            "system service install is not implemented on this platform"
        ))
    }
}

fn service_uninstall(args: ServiceUninstallArgs) -> Result<()> {
    let _ = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_uninstall_service()
    }

    #[cfg(target_os = "linux")]
    {
        linux_uninstall_service()
    }

    #[cfg(target_os = "windows")]
    {
        windows_uninstall_service()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "system service uninstall is not implemented on this platform"
        ))
    }
}

fn service_enable(args: ServiceControlArgs) -> Result<()> {
    let _ = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_enable_service()
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(anyhow!(
            "system service enable is not implemented on this platform"
        ))
    }
}

fn service_disable(args: ServiceControlArgs) -> Result<()> {
    let _ = args.config.unwrap_or_else(default_config_path);

    #[cfg(target_os = "macos")]
    {
        macos_disable_service()
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(anyhow!(
            "system service disable is not implemented on this platform"
        ))
    }
}

fn service_status(args: ServiceStatusArgs) -> Result<()> {
    let _ = args.config.unwrap_or_else(default_config_path);
    let status = query_service_status()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if !status.supported {
        println!("service: unsupported on this platform");
        return Ok(());
    }

    println!("service_label: {}", status.label);
    println!("service_plist: {}", status.plist_path);
    println!("service_installed: {}", status.installed);
    println!("service_disabled: {}", status.disabled);
    println!("service_loaded: {}", status.loaded);
    println!("service_running: {}", status.running);
    if let Some(pid) = status.pid {
        println!("service_pid: {pid}");
    }

    Ok(())
}

fn query_service_status() -> Result<ServiceStatusView> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = macos_service_plist_path();
        let installed = plist_path.exists();
        if !installed {
            return Ok(ServiceStatusView {
                supported: true,
                installed: false,
                disabled: false,
                loaded: false,
                running: false,
                pid: None,
                label: MACOS_SERVICE_LABEL.to_string(),
                plist_path: plist_path.display().to_string(),
            });
        }

        let disabled = macos_service_disabled().unwrap_or(false);
        let (loaded, running, pid) = if disabled {
            (false, false, None)
        } else {
            match macos_service_print() {
                Ok(output) => (
                    true,
                    macos_service_print_is_running(&output),
                    macos_service_print_pid(&output),
                ),
                Err(_) => (false, false, None),
            }
        };

        Ok(ServiceStatusView {
            supported: true,
            installed: true,
            disabled,
            loaded,
            running,
            pid,
            label: MACOS_SERVICE_LABEL.to_string(),
            plist_path: plist_path.display().to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    {
        return linux_query_service_status();
    }

    #[cfg(target_os = "windows")]
    {
        return windows_query_service_status();
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(ServiceStatusView {
            supported: false,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: "nvpn".to_string(),
            plist_path: String::new(),
        })
    }
}

#[cfg(target_os = "macos")]
fn macos_service_plist_path() -> PathBuf {
    PathBuf::from(format!(
        "/Library/LaunchDaemons/{MACOS_SERVICE_LABEL}.plist"
    ))
}

#[cfg(target_os = "macos")]
fn macos_service_target() -> String {
    format!("system/{MACOS_SERVICE_LABEL}")
}

#[cfg(target_os = "macos")]
fn macos_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
    force: bool,
) -> Result<()> {
    let plist_path = macos_service_plist_path();
    if plist_path.exists() && !force {
        println!(
            "service already installed at {} (pass --force to reinstall)",
            plist_path.display()
        );
        return Ok(());
    }

    macos_service_bootout(true)?;
    stop_existing_daemons_before_service_install(config_path)?;
    let plist = macos_service_plist_content(
        executable,
        config_path,
        iface,
        announce_interval_secs,
        log_path,
    );

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let temp = plist_path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, plist).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to chmod {}", temp.display()))?;
    fs::rename(&temp, &plist_path).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp.display(),
            plist_path.display()
        )
    })?;

    macos_service_bootstrap(&plist_path)?;
    macos_service_enable()?;
    macos_service_kickstart()?;
    println!("installed system service: {}", plist_path.display());
    println!("label: {}", MACOS_SERVICE_LABEL);
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_uninstall_service() -> Result<()> {
    macos_service_bootout(true)?;
    macos_service_disable(true)?;
    let plist_path = macos_service_plist_path();
    if plist_path.exists() {
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
        println!("removed system service plist: {}", plist_path.display());
    } else {
        println!("system service plist not found: {}", plist_path.display());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_enable_service() -> Result<()> {
    let plist_path = macos_service_plist_path();
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_service_enable()?;
    macos_service_bootout(true)?;
    macos_service_bootstrap(&plist_path)?;
    macos_service_kickstart()?;
    println!("enabled system service: {}", plist_path.display());
    println!("label: {}", MACOS_SERVICE_LABEL);
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_disable_service() -> Result<()> {
    let plist_path = macos_service_plist_path();
    if !plist_path.exists() {
        return Err(anyhow!(
            "system service plist not found: {}",
            plist_path.display()
        ));
    }

    macos_service_bootout(true)?;
    macos_service_disable(false)?;
    println!("disabled system service: {}", plist_path.display());
    println!("label: {}", MACOS_SERVICE_LABEL);
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_service_plist_content(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
) -> String {
    let exec = xml_escape(&executable.display().to_string());
    let config = xml_escape(&config_path.display().to_string());
    let iface = xml_escape(iface);
    let interval = announce_interval_secs.to_string();
    let log = xml_escape(&log_path.display().to_string());

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{MACOS_SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exec}</string>
    <string>daemon</string>
    <string>--config</string>
    <string>{config}</string>
    <string>--iface</string>
    <string>{iface}</string>
    <string>--announce-interval-secs</string>
    <string>{interval}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn macos_service_bootstrap(plist_path: &Path) -> Result<()> {
    let plist = plist_path
        .to_str()
        .ok_or_else(|| anyhow!("plist path is not valid UTF-8"))?;
    run_launchctl_checked(&["bootstrap", "system", plist], "bootstrap service")
}

#[cfg(target_os = "macos")]
fn macos_service_enable() -> Result<()> {
    let target = macos_service_target();
    run_launchctl_checked(&["enable", target.as_str()], "enable service")
}

#[cfg(target_os = "macos")]
fn macos_service_disable(ignore_missing: bool) -> Result<()> {
    let target = macos_service_target();
    run_launchctl_allow_missing(
        &["disable", target.as_str()],
        "disable service",
        ignore_missing,
    )
}

#[cfg(target_os = "macos")]
fn macos_service_kickstart() -> Result<()> {
    let target = macos_service_target();
    run_launchctl_checked(&["kickstart", "-k", target.as_str()], "kickstart service")
}

#[cfg(target_os = "macos")]
fn macos_service_bootout(ignore_missing: bool) -> Result<()> {
    let target = macos_service_target();
    run_launchctl_allow_missing(
        &["bootout", target.as_str()],
        "bootout service",
        ignore_missing,
    )
}

#[cfg(target_os = "macos")]
fn macos_service_print() -> Result<String> {
    let target = macos_service_target();
    let output = run_launchctl_raw(&["print", target.as_str()], "print service")?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn macos_service_print_is_running(print_output: &str) -> bool {
    print_output
        .lines()
        .map(str::trim)
        .any(|line| line == "state = running")
}

#[cfg(target_os = "macos")]
fn macos_service_print_pid(print_output: &str) -> Option<u32> {
    for line in print_output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("pid = ")
            && let Ok(pid) = value.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn macos_service_disabled() -> Result<bool> {
    let output = run_launchctl_raw(&["print-disabled", "system"], "print disabled services")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "launchctl print disabled services failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(macos_service_disabled_from_print_disabled_output(
        &stdout,
        MACOS_SERVICE_LABEL,
    ))
}

#[cfg(any(target_os = "macos", test))]
fn macos_service_disabled_from_print_disabled_output(output: &str, label: &str) -> bool {
    for line in output.lines().map(str::trim) {
        let Some((entry_label, state)) = line.split_once("=>") else {
            continue;
        };
        if entry_label.trim().trim_matches('"') != label {
            continue;
        }

        return state.trim().trim_end_matches(',') == "disabled";
    }

    false
}

#[cfg(target_os = "macos")]
fn run_launchctl_checked(args: &[&str], context: &str) -> Result<()> {
    let output = run_launchctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "launchctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn run_launchctl_allow_missing(args: &[&str], context: &str, ignore_missing: bool) -> Result<()> {
    let output = run_launchctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && launchctl_missing_service_message(&details) {
        return Ok(());
    }

    Err(anyhow!(
        "launchctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn run_launchctl_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("launchctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to launchctl {context}"))
}

#[cfg(target_os = "macos")]
fn launchctl_missing_service_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("could not find service")
        || lowered.contains("service is disabled")
        || lowered.contains("no such process")
        || lowered.contains("no such file")
        || lowered.contains("domain does not support specified action")
}

#[cfg(target_os = "linux")]
fn linux_service_unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{LINUX_SERVICE_UNIT_NAME}"))
}

#[cfg(target_os = "linux")]
fn linux_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
    force: bool,
) -> Result<()> {
    if !linux_systemctl_available() {
        return Err(anyhow!("systemd (systemctl) is not available on this host"));
    }

    let unit_path = linux_service_unit_path();
    if unit_path.exists() && !force {
        println!(
            "service already installed at {} (pass --force to reinstall)",
            unit_path.display()
        );
        return Ok(());
    }

    let _ = run_systemctl_allow_missing(
        &["disable", "--now", LINUX_SERVICE_UNIT_NAME],
        "disable/stop existing service",
        true,
    );
    stop_existing_daemons_before_service_install(config_path)?;
    let unit = linux_service_unit_content(
        executable,
        config_path,
        iface,
        announce_interval_secs,
        log_path,
    );
    let temp = unit_path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, unit).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to chmod {}", temp.display()))?;
    fs::rename(&temp, &unit_path).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp.display(),
            unit_path.display()
        )
    })?;

    run_systemctl_checked(&["daemon-reload"], "reload systemd")?;
    run_systemctl_checked(
        &["enable", "--now", LINUX_SERVICE_UNIT_NAME],
        "enable/start service",
    )?;
    println!("installed system service: {}", unit_path.display());
    println!("label: {LINUX_SERVICE_UNIT_NAME}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_uninstall_service() -> Result<()> {
    if !linux_systemctl_available() {
        return Err(anyhow!("systemd (systemctl) is not available on this host"));
    }

    run_systemctl_allow_missing(
        &["disable", "--now", LINUX_SERVICE_UNIT_NAME],
        "disable/stop service",
        true,
    )?;

    let unit_path = linux_service_unit_path();
    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .with_context(|| format!("failed to remove {}", unit_path.display()))?;
        println!("removed system service unit: {}", unit_path.display());
    } else {
        println!("system service unit not found: {}", unit_path.display());
    }

    run_systemctl_checked(&["daemon-reload"], "reload systemd")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_query_service_status() -> Result<ServiceStatusView> {
    let unit_path = linux_service_unit_path();
    let installed = unit_path.exists();
    if !linux_systemctl_available() {
        return Ok(ServiceStatusView {
            supported: false,
            installed,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: LINUX_SERVICE_UNIT_NAME.to_string(),
            plist_path: unit_path.display().to_string(),
        });
    }

    let output = run_systemctl_raw(
        &[
            "show",
            LINUX_SERVICE_UNIT_NAME,
            "--property=LoadState,ActiveState,SubState,MainPID",
            "--no-pager",
        ],
        "query service",
    )?;

    if !output.status.success() {
        return Ok(ServiceStatusView {
            supported: true,
            installed,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: LINUX_SERVICE_UNIT_NAME.to_string(),
            plist_path: unit_path.display().to_string(),
        });
    }

    let show = String::from_utf8_lossy(&output.stdout);
    let (loaded, running, pid) = linux_service_status_from_show_output(&show);

    Ok(ServiceStatusView {
        supported: true,
        installed,
        disabled: false,
        loaded,
        running,
        pid,
        label: LINUX_SERVICE_UNIT_NAME.to_string(),
        plist_path: unit_path.display().to_string(),
    })
}

#[cfg(target_os = "linux")]
fn linux_service_unit_content(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    log_path: &Path,
) -> String {
    let exec = systemd_quote(&executable.display().to_string());
    let config = systemd_quote(&config_path.display().to_string());
    let iface = systemd_quote(iface);
    let log = systemd_quote(&log_path.display().to_string());
    format!(
        "[Unit]\nDescription=Nostr VPN daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec} daemon --config {config} --iface {iface} --announce-interval-secs {announce_interval_secs}\nRestart=always\nRestartSec=3\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

#[cfg(target_os = "linux")]
fn linux_systemctl_available() -> bool {
    ProcessCommand::new("systemctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_systemctl_checked(args: &[&str], context: &str) -> Result<()> {
    let output = run_systemctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "systemctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn run_systemctl_allow_missing(args: &[&str], context: &str, ignore_missing: bool) -> Result<()> {
    let output = run_systemctl_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && systemctl_missing_service_message(&details) {
        return Ok(());
    }

    Err(anyhow!(
        "systemctl {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn run_systemctl_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to systemctl {context}"))
}

#[cfg(target_os = "linux")]
fn systemctl_missing_service_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("could not be found")
        || lowered.contains("not loaded")
        || lowered.contains("no such file")
}

#[cfg(any(target_os = "linux", test))]
fn linux_service_status_from_show_output(show: &str) -> (bool, bool, Option<u32>) {
    let mut load_state = None;
    let mut active_state = None;
    let mut sub_state = None;
    let mut pid = None;

    for line in show.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            load_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            active_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("SubState=") {
            sub_state = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            pid = parse_nonzero_pid(value);
        }
    }

    let loaded = load_state.as_deref() == Some("loaded");
    let running =
        active_state.as_deref() == Some("active") && sub_state.as_deref() == Some("running");
    (loaded, running, pid)
}

#[cfg(target_os = "windows")]
fn windows_install_service(
    executable: &Path,
    config_path: &Path,
    iface: &str,
    announce_interval_secs: u64,
    force: bool,
) -> Result<()> {
    let existing = windows_service_query()?.is_some();
    if existing && !force {
        println!(
            "service already installed (pass --force to reinstall): {}",
            WINDOWS_SERVICE_NAME
        );
        return Ok(());
    }

    if existing && force {
        let _ = windows_stop_service(true);
        let _ = windows_delete_service(true);
    }
    stop_existing_daemons_before_service_install(config_path)?;

    let exec = executable.display().to_string();
    let config = config_path.display().to_string();
    let bin_path = format!(
        "\"{exec}\" daemon --config \"{config}\" --iface {iface} --announce-interval-secs {announce_interval_secs}"
    );
    run_sc_checked(
        &[
            "create",
            WINDOWS_SERVICE_NAME,
            "binPath=",
            bin_path.as_str(),
            "start=",
            "auto",
            "DisplayName=",
            WINDOWS_SERVICE_DISPLAY_NAME,
        ],
        "create service",
    )?;
    windows_start_service(true)?;

    println!("installed system service: {}", WINDOWS_SERVICE_NAME);
    println!("label: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_uninstall_service() -> Result<()> {
    windows_stop_service(true)?;
    windows_delete_service(true)?;
    println!("removed system service: {}", WINDOWS_SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_query_service_status() -> Result<ServiceStatusView> {
    let output = windows_service_query()?;
    let Some(output) = output else {
        return Ok(ServiceStatusView {
            supported: true,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: WINDOWS_SERVICE_NAME.to_string(),
            plist_path: WINDOWS_SERVICE_NAME.to_string(),
        });
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let (running, pid) = windows_service_status_from_query_output(&text);
    Ok(ServiceStatusView {
        supported: true,
        installed: true,
        disabled: false,
        loaded: true,
        running,
        pid,
        label: WINDOWS_SERVICE_NAME.to_string(),
        plist_path: WINDOWS_SERVICE_NAME.to_string(),
    })
}

#[cfg(target_os = "windows")]
fn windows_service_query() -> Result<Option<std::process::Output>> {
    let output = run_sc_raw(&["queryex", WINDOWS_SERVICE_NAME], "query service")?;
    if output.status.success() {
        return Ok(Some(output));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if windows_service_missing_message(&details) {
        return Ok(None);
    }

    Err(anyhow!(
        "sc query failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn windows_start_service(ignore_already_running: bool) -> Result<()> {
    let output = run_sc_raw(&["start", WINDOWS_SERVICE_NAME], "start service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_already_running && windows_service_already_running_message(&details) {
        return Ok(());
    }
    Err(anyhow!(
        "sc start failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn windows_stop_service(ignore_missing: bool) -> Result<()> {
    let output = run_sc_raw(&["stop", WINDOWS_SERVICE_NAME], "stop service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && windows_service_missing_message(&details) {
        return Ok(());
    }
    Err(anyhow!(
        "sc stop failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn windows_delete_service(ignore_missing: bool) -> Result<()> {
    let output = run_sc_raw(&["delete", WINDOWS_SERVICE_NAME], "delete service")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = format!("{}\n{}", stdout.trim(), stderr.trim());
    if ignore_missing && windows_service_missing_message(&details) {
        return Ok(());
    }
    Err(anyhow!(
        "sc delete failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn run_sc_checked(args: &[&str], context: &str) -> Result<()> {
    let output = run_sc_raw(args, context)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "sc {context} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "windows")]
fn run_sc_raw(args: &[&str], context: &str) -> Result<std::process::Output> {
    ProcessCommand::new("sc.exe")
        .args(args)
        .output()
        .with_context(|| format!("failed to sc.exe {context}"))
}

#[cfg(target_os = "windows")]
fn windows_service_missing_message(details: &str) -> bool {
    let lowered = details.to_ascii_lowercase();
    lowered.contains("failed 1060") || lowered.contains("does not exist as an installed service")
}

#[cfg(target_os = "windows")]
fn windows_service_already_running_message(details: &str) -> bool {
    details
        .to_ascii_lowercase()
        .contains("service has already been started")
}

#[cfg(any(target_os = "windows", test))]
fn windows_service_status_from_query_output(output: &str) -> (bool, Option<u32>) {
    let mut running = false;
    let mut pid = None;

    for line in output.lines().map(str::trim) {
        if line.contains("STATE") && line.to_ascii_uppercase().contains("RUNNING") {
            running = true;
        } else if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("PID")
        {
            pid = parse_nonzero_pid(value);
        }
    }

    (running, pid)
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn parse_nonzero_pid(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok().filter(|pid| *pid > 0)
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn install_cli(args: InstallCliArgs) -> Result<()> {
    let destination = args.path.unwrap_or_else(default_cli_install_path);
    install_cli_to_path(&destination, args.force)
}

fn uninstall_cli(args: UninstallCliArgs) -> Result<()> {
    let destination = args.path.unwrap_or_else(default_cli_install_path);
    uninstall_cli_path(&destination)
}

fn install_cli_to_path(destination: &Path, force: bool) -> Result<()> {
    let source = std::env::current_exe().context("failed to resolve current executable")?;
    let source = fs::canonicalize(&source)
        .with_context(|| format!("failed to canonicalize {}", source.display()))?;

    if destination.as_os_str().is_empty() {
        return Err(anyhow!("install path must not be empty"));
    }
    if destination.is_dir() {
        return Err(anyhow!(
            "install path points to a directory: {}",
            destination.display()
        ));
    }

    if let Ok(existing) = fs::canonicalize(destination)
        && existing == source
    {
        println!("nvpn already installed at {}", destination.display());
        return Ok(());
    }

    if destination.exists() && !force {
        return Err(anyhow!(
            "{} already exists (pass --force to overwrite)",
            destination.display()
        ));
    }

    if destination.exists() && force {
        let metadata = fs::symlink_metadata(destination)
            .with_context(|| format!("failed to inspect {}", destination.display()))?;
        if metadata.file_type().is_dir() {
            return Err(anyhow!(
                "refusing to overwrite directory {}",
                destination.display()
            ));
        }
        fs::remove_file(destination)
            .with_context(|| format!("failed to remove {}", destination.display()))?;
    }

    let parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "install path must include parent directory: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let install_nonce = unix_timestamp();
    let temp_path = parent.join(format!(
        ".nvpn-install-{}-{install_nonce}",
        std::process::id()
    ));
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }

    fs::copy(&source, &temp_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            temp_path.display()
        )
    })?;

    #[cfg(unix)]
    {
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755)).with_context(|| {
            format!(
                "failed to set executable permissions on {}",
                temp_path.display()
            )
        })?;
    }

    fs::rename(&temp_path, destination).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp_path.display(),
            destination.display()
        )
    })?;

    println!("installed nvpn CLI at {}", destination.display());
    Ok(())
}

fn uninstall_cli_path(destination: &Path) -> Result<()> {
    if !destination.exists() {
        println!("nvpn CLI not installed at {}", destination.display());
        return Ok(());
    }

    let metadata = fs::symlink_metadata(destination)
        .with_context(|| format!("failed to inspect {}", destination.display()))?;
    if metadata.file_type().is_dir() {
        return Err(anyhow!(
            "refusing to remove directory {}",
            destination.display()
        ));
    }

    fs::remove_file(destination)
        .with_context(|| format!("failed to remove {}", destination.display()))?;
    println!("removed nvpn CLI from {}", destination.display());
    Ok(())
}

fn init_config(path: &Path, force: bool, participants: Vec<String>) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "config already exists at {} (pass --force to overwrite)",
            path.display()
        ));
    }

    let mut config = AppConfig::generated();
    apply_participants_override(&mut config, participants)?;
    maybe_autoconfigure_node(&mut config);
    config.save(path)?;

    println!("wrote {}", path.display());
    println!("network_id={}", config.effective_network_id());
    println!("nostr_pubkey={}", config.nostr.public_key);
    Ok(())
}

fn default_cli_install_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/nvpn")
}

fn default_config_path() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        let mut path = dir;
        path.push("nvpn");
        path.push("config.toml");
        return path;
    }

    PathBuf::from("nvpn.toml")
}

fn load_or_default_config(path: &Path) -> Result<AppConfig> {
    if path.exists() {
        return AppConfig::load(path);
    }

    let config = AppConfig::generated();
    config.save(path)?;
    Ok(config)
}

fn apply_participants_override(config: &mut AppConfig, participants: Vec<String>) -> Result<()> {
    if participants.is_empty() {
        return Ok(());
    }

    let mut normalized = participants
        .iter()
        .map(|participant| normalize_nostr_pubkey(participant))
        .collect::<Result<Vec<_>>>()?;

    normalized.sort();
    normalized.dedup();
    config.ensure_defaults();
    if let Some(network) = config.networks.first_mut() {
        network.participants = normalized.clone();
        network.enabled = true;
    }

    if config.network_id.trim().is_empty() {
        config.network_id = derive_network_id_from_participants(&normalized);
    }

    Ok(())
}

fn resolve_relays(cli_relays: &[String], config: &AppConfig) -> Vec<String> {
    if !cli_relays.is_empty() {
        return cli_relays.to_vec();
    }

    if !config.nostr.relays.is_empty() {
        return config.nostr.relays.clone();
    }

    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn tunnel_up(args: &TunnelUpArgs) -> Result<()> {
    if cfg!(not(unix)) {
        return Err(anyhow!(
            "tunnel-up is currently supported on unix platforms only"
        ));
    }

    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let private_key_hex = key_b64_to_hex(&args.private_key)?;
    let peer_public_key_hex = key_b64_to_hex(&args.peer_public_key)?;

    if args.hole_punch_attempts > 0 {
        let peer_endpoint: SocketAddr = args.peer_endpoint.parse().with_context(|| {
            format!(
                "invalid --peer-endpoint '{}' (required as ip:port when hole-punching)",
                args.peer_endpoint
            )
        })?;
        let report = hole_punch_udp(
            args.listen_port,
            peer_endpoint,
            args.hole_punch_attempts,
            Duration::from_millis(args.hole_punch_interval_ms.max(1)),
            Duration::from_millis(args.hole_punch_recv_timeout_ms.max(1)),
        )
        .context("pre-tunnel hole-punch failed")?;

        println!(
            "pre-punch: sent {} packets from {} to {}, received_response={}",
            report.packets_sent, report.local_addr, peer_endpoint, report.packet_received
        );
    }

    // Keep handle alive for process lifetime; dropping tears down the device.
    let _handle = DeviceHandle::new(
        &args.iface,
        DeviceConfig {
            n_threads: 2,
            #[cfg(target_os = "linux")]
            use_connected_socket: false,
            #[cfg(not(target_os = "linux"))]
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: false,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        },
    )
    .with_context(|| format!("failed to create boringtun interface {}", args.iface))?;

    let uapi_socket = format!("/var/run/wireguard/{}.sock", args.iface);
    wait_for_socket(&uapi_socket)?;

    wg_set(
        &uapi_socket,
        &format!(
            "private_key={private_key_hex}\nlisten_port={}",
            args.listen_port
        ),
    )?;
    wg_set(
        &uapi_socket,
        &format!(
            "public_key={peer_public_key_hex}\nendpoint={}\nreplace_allowed_ips=true\nallowed_ip={}\npersistent_keepalive_interval={}",
            args.peer_endpoint, args.peer_allowed_ip, args.keepalive_secs
        ),
    )?;

    apply_local_interface_network(
        &args.iface,
        &args.address,
        std::slice::from_ref(&args.peer_allowed_ip),
    )?;

    println!(
        "boringtun interface {} up: {}, peer {} via {}",
        args.iface, args.address, args.peer_allowed_ip, args.peer_endpoint
    );

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn key_b64_to_hex(value: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(value)
        .with_context(|| "invalid base64 key encoding")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32-byte key material"));
    }
    Ok(encode_hex(bytes))
}

fn parse_advertised_routes_arg(value: &str) -> Result<Vec<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut routes = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        let normalized = normalize_advertised_route(raw)
            .ok_or_else(|| anyhow!("invalid advertised route '{raw}'"))?;
        if !routes.iter().any(|existing| existing == &normalized) {
            routes.push(normalized);
        }
    }

    Ok(routes)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxRouteGetSpec {
    gateway: Option<String>,
    dev: String,
    src: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
fn linux_default_route_device_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        tokens
            .windows(2)
            .find(|window| window[0] == "dev")
            .map(|window| window[1].to_string())
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_get_spec_from_output(output: &str) -> Option<LinuxRouteGetSpec> {
    let line = output.lines().find(|line| !line.trim().is_empty())?.trim();
    let tokens = line.split_whitespace().collect::<Vec<_>>();

    let mut gateway = None;
    let mut dev = None;
    let mut src = None;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "via" => {
                gateway = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            "dev" => {
                dev = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            "src" => {
                src = tokens.get(index + 1).map(|value| (*value).to_string());
                index += 2;
            }
            _ => {
                index += 1;
            }
        }
    }

    Some(LinuxRouteGetSpec {
        gateway,
        dev: dev?,
        src,
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxEndpointBypassRoute {
    target: String,
    gateway: Option<String>,
    dev: String,
    src: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxDefaultRouteSpec {
    line: String,
    dev: String,
}

#[cfg(target_os = "linux")]
fn linux_default_route_from_output(output: &str) -> Option<LinuxDefaultRouteSpec> {
    let line = output.lines().find(|line| !line.trim().is_empty())?.trim();
    Some(LinuxDefaultRouteSpec {
        line: line.to_string(),
        dev: linux_default_route_device_from_output(line)?,
    })
}

#[cfg(target_os = "linux")]
fn command_stdout_checked(command: &mut ProcessCommand) -> Result<String> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "command failed: {display}\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn linux_default_route() -> Result<LinuxDefaultRouteSpec> {
    linux_default_route_for_family("-4", "IPv4")
}

#[cfg(target_os = "linux")]
fn linux_default_ipv6_route() -> Result<LinuxDefaultRouteSpec> {
    linux_default_route_for_family("-6", "IPv6")
}

#[cfg(target_os = "linux")]
fn linux_default_route_for_family(
    family_flag: &str,
    family_label: &str,
) -> Result<LinuxDefaultRouteSpec> {
    let output = command_stdout_checked(
        ProcessCommand::new("ip")
            .arg(family_flag)
            .arg("route")
            .arg("show")
            .arg("default"),
    )?;
    linux_default_route_from_output(&output)
        .ok_or_else(|| anyhow!("failed to resolve default {family_label} route"))
}

#[cfg(target_os = "linux")]
fn restore_linux_default_route(route: &str) -> Result<()> {
    let mut command = ProcessCommand::new("ip");
    command.arg("-4").arg("route").arg("replace");
    for token in route.split_whitespace() {
        command.arg(token);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
fn relay_bypass_ipv4_hosts(app: &AppConfig) -> Vec<Ipv4Addr> {
    let mut hosts = app
        .nostr
        .relays
        .iter()
        .flat_map(|relay| relay_ipv4_hosts(relay))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

#[cfg(target_os = "linux")]
fn relay_ipv4_hosts(relay: &str) -> Vec<Ipv4Addr> {
    let Some((host, port)) = relay_host_port(relay) else {
        return Vec::new();
    };

    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }

    if host.parse::<IpAddr>().is_ok() {
        return Vec::new();
    }

    (host.as_str(), port)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter_map(|addr| match addr.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn relay_host_port(relay: &str) -> Option<(String, u16)> {
    let relay = relay.trim();
    if relay.is_empty() {
        return None;
    }

    let (scheme, remainder) = relay
        .split_once("://")
        .map_or(("", relay), |(scheme, rest)| (scheme, rest));
    let authority = remainder.split('/').next().unwrap_or(remainder);
    let default_port = match scheme {
        "wss" | "https" => 443,
        _ => 80,
    };

    split_host_port(authority, default_port)
}

#[cfg(target_os = "linux")]
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after_host) = rest.split_once(']')?;
        let port = after_host
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && !host.is_empty() && port.parse::<u16>().is_ok() =>
        {
            Some((host.to_string(), port.parse::<u16>().ok()?))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

#[cfg(target_os = "linux")]
fn linux_bypass_route_specs(
    app: &AppConfig,
    peers: &[TunnelPeer],
    tunnel_iface: &str,
    original_default_route: Option<&str>,
) -> Result<Vec<LinuxEndpointBypassRoute>> {
    let mut hosts = peers
        .iter()
        .filter_map(|peer| match endpoint_host_ip(&peer.endpoint) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .chain(relay_bypass_ipv4_hosts(app))
        .collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();

    let mut routes = Vec::with_capacity(hosts.len());
    for host in hosts {
        let output = command_stdout_checked(
            ProcessCommand::new("ip")
                .arg("-4")
                .arg("route")
                .arg("get")
                .arg(host.to_string()),
        )?;
        let spec = linux_route_get_spec_from_output(&output)
            .and_then(|spec| {
                if spec.dev == tunnel_iface {
                    None
                } else {
                    Some(spec)
                }
            })
            .or_else(|| {
                original_default_route
                    .and_then(linux_route_get_spec_from_output)
                    .filter(|spec| spec.dev != tunnel_iface)
            })
            .ok_or_else(|| anyhow!("failed to resolve bypass route for {host}"))?;
        routes.push(LinuxEndpointBypassRoute {
            target: format!("{host}/32"),
            gateway: spec.gateway,
            dev: spec.dev,
            src: spec.src,
        });
    }

    Ok(routes)
}

#[cfg(target_os = "linux")]
fn apply_linux_endpoint_bypass_route(route: &LinuxEndpointBypassRoute) -> Result<()> {
    let mut command = ProcessCommand::new("ip");
    command
        .arg("-4")
        .arg("route")
        .arg("replace")
        .arg(&route.target);
    if let Some(gateway) = route.gateway.as_deref() {
        command.arg("via").arg(gateway);
    }
    command.arg("dev").arg(&route.dev);
    if let Some(src) = route.src.as_deref() {
        command.arg("src").arg(src);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
fn delete_linux_endpoint_bypass_route(target: &str) -> Result<()> {
    run_checked(
        ProcessCommand::new("ip")
            .arg("-4")
            .arg("route")
            .arg("del")
            .arg(target),
    )
}

#[cfg(target_os = "linux")]
fn read_linux_ip_forward(family: LinuxExitNodeIpFamily) -> Result<bool> {
    let path = linux_ip_forward_path(family);
    Ok(fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?
        .trim()
        == "1")
}

#[cfg(target_os = "linux")]
fn write_linux_ip_forward(family: LinuxExitNodeIpFamily, enabled: bool) -> Result<()> {
    let path = linux_ip_forward_path(family);
    fs::write(path, if enabled { "1" } else { "0" })
        .with_context(|| format!("failed to write {path}"))
}

#[cfg(target_os = "linux")]
fn linux_ip_forward_path(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "/proc/sys/net/ipv4/ip_forward",
        LinuxExitNodeIpFamily::V6 => "/proc/sys/net/ipv6/conf/all/forwarding",
    }
}

#[cfg(target_os = "linux")]
fn linux_exit_node_source_cidr(tunnel_ip: &str) -> Option<String> {
    let mut octets = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok()?.octets();
    octets[3] = 0;
    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxExitNodeIpFamily {
    V4,
    V6,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LinuxExitNodeDefaultRouteFamilies {
    ipv4: bool,
    ipv6: bool,
}

#[cfg(any(target_os = "linux", test))]
fn linux_exit_node_default_route_families(routes: &[String]) -> LinuxExitNodeDefaultRouteFamilies {
    LinuxExitNodeDefaultRouteFamilies {
        ipv4: routes.iter().any(|route| route == "0.0.0.0/0"),
        ipv6: routes.iter().any(|route| route == "::/0"),
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_exit_node_firewall_binary(family: LinuxExitNodeIpFamily) -> &'static str {
    match family {
        LinuxExitNodeIpFamily::V4 => "iptables",
        LinuxExitNodeIpFamily::V6 => "ip6tables",
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_exit_node_forward_in_rule(iface: &str, family: LinuxExitNodeIpFamily) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-i".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-in",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-in",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
fn linux_exit_node_forward_out_rule(iface: &str, family: LinuxExitNodeIpFamily) -> Vec<String> {
    vec![
        "FORWARD".to_string(),
        "-o".to_string(),
        iface.to_string(),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "RELATED,ESTABLISHED".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        match family {
            LinuxExitNodeIpFamily::V4 => "nvpn-exit-forward-out",
            LinuxExitNodeIpFamily::V6 => "nvpn-exit6-forward-out",
        }
        .to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
}

#[cfg(any(target_os = "linux", test))]
fn linux_exit_node_ipv4_masquerade_rule(
    outbound_iface: &str,
    tunnel_source_cidr: &str,
) -> Vec<String> {
    vec![
        "POSTROUTING".to_string(),
        "-o".to_string(),
        outbound_iface.to_string(),
        "-s".to_string(),
        tunnel_source_cidr.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "nvpn-exit-masq".to_string(),
        "-j".to_string(),
        "MASQUERADE".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn linux_iptables_rule_exists(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<bool> {
    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-C");
    for arg in rule {
        command.arg(arg);
    }

    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "command failed: {display}\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    ))
}

#[cfg(target_os = "linux")]
fn linux_iptables_ensure_rule(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-A");
    for arg in rule {
        command.arg(arg);
    }
    run_checked(&mut command)
}

#[cfg(target_os = "linux")]
fn linux_iptables_delete_rule(
    family: LinuxExitNodeIpFamily,
    table: Option<&str>,
    rule: &[String],
) -> Result<()> {
    if !linux_iptables_rule_exists(family, table, rule)? {
        return Ok(());
    }

    let mut command = ProcessCommand::new(linux_exit_node_firewall_binary(family));
    if let Some(table) = table {
        command.arg("-t").arg(table);
    }
    command.arg("-D");
    for arg in rule {
        command.arg(arg);
    }
    run_checked(&mut command)
}

fn apply_local_interface_network(
    iface: &str,
    address: &str,
    route_targets: &[String],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_checked(
            ProcessCommand::new("ip")
                .arg("address")
                .arg("replace")
                .arg(address)
                .arg("dev")
                .arg(iface),
        )?;
        run_checked(
            ProcessCommand::new("ip")
                .arg("link")
                .arg("set")
                .arg("mtu")
                .arg("1380")
                .arg("up")
                .arg("dev")
                .arg(iface),
        )?;
        for target in route_targets {
            run_checked(
                ProcessCommand::new("ip")
                    .arg("route")
                    .arg("replace")
                    .arg(target)
                    .arg("dev")
                    .arg(iface),
            )?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let ip = strip_cidr(address).to_string();
        run_checked(
            ProcessCommand::new("ifconfig")
                .arg(iface)
                .arg("inet")
                .arg(&ip)
                .arg(&ip)
                .arg("netmask")
                .arg("255.255.255.0")
                .arg("up"),
        )?;
        for target in route_targets {
            apply_macos_route(iface, target)?;
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "interface setup is not implemented for this platform"
    ))
}

#[cfg(target_os = "macos")]
fn apply_macos_route(iface: &str, target: &str) -> Result<()> {
    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let add_result = if is_host {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("add")
                .arg("-host")
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        )
    } else {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("add")
                .arg("-net")
                .arg(target)
                .arg("-interface")
                .arg(iface),
        )
    };

    if add_result.is_ok() {
        return Ok(());
    }

    if is_host {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("change")
                .arg("-host")
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        )
    } else {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("change")
                .arg("-net")
                .arg(target)
                .arg("-interface")
                .arg(iface),
        )
    }
}

fn wait_for_socket(path: &str) -> Result<()> {
    for _ in 0..50 {
        if fs::metadata(path).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!("timed out waiting for uapi socket at {path}"))
}

fn wg_set(socket_path: &str, body: &str) -> Result<()> {
    let mut socket =
        UnixStream::connect(socket_path).with_context(|| format!("connect {socket_path}"))?;
    write!(socket, "set=1\n{body}\n\n").context("failed to send uapi set")?;
    socket
        .shutdown(std::net::Shutdown::Write)
        .context("failed to close uapi write half")?;

    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .context("failed to read uapi response")?;

    if !response.contains("errno=0") {
        return Err(anyhow!("uapi set failed: {}", response.trim()));
    }

    Ok(())
}

fn wg_get(socket_path: &str) -> Result<String> {
    let mut socket =
        UnixStream::connect(socket_path).with_context(|| format!("connect {socket_path}"))?;
    write!(socket, "get=1\n\n").context("failed to send uapi get")?;
    socket
        .shutdown(std::net::Shutdown::Write)
        .context("failed to close uapi write half")?;

    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .context("failed to read uapi get response")?;

    if !response.contains("errno=0") {
        return Err(anyhow!("uapi get failed: {}", response.trim()));
    }

    Ok(response)
}

fn parse_wg_peer_status(response: &str) -> HashMap<String, WireGuardPeerStatus> {
    let mut peers = HashMap::new();
    let mut current_pubkey: Option<String> = None;
    let mut current = WireGuardPeerStatus::default();

    let commit_current = |peers: &mut HashMap<String, WireGuardPeerStatus>,
                          current_pubkey: &mut Option<String>,
                          current: &mut WireGuardPeerStatus| {
        if let Some(pubkey) = current_pubkey.take() {
            peers.insert(pubkey, std::mem::take(current));
        }
    };

    for line in response.lines() {
        if line.is_empty() || line == "errno=0" {
            continue;
        }

        if let Some(value) = line.strip_prefix("public_key=") {
            commit_current(&mut peers, &mut current_pubkey, &mut current);
            current_pubkey = Some(value.trim().to_lowercase());
            continue;
        }

        let Some(_pubkey) = current_pubkey.as_ref() else {
            continue;
        };

        if let Some(value) = line.strip_prefix("endpoint=") {
            current.endpoint = Some(value.trim().to_string());
            continue;
        }

        if let Some(value) = line.strip_prefix("last_handshake_time_sec=") {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                current.last_handshake_sec = Some(parsed);
            }
            continue;
        }

        if let Some(value) = line.strip_prefix("last_handshake_time_nsec=")
            && let Ok(parsed) = value.trim().parse::<u64>()
        {
            current.last_handshake_nsec = Some(parsed);
        }
    }

    commit_current(&mut peers, &mut current_pubkey, &mut current);
    peers
}

fn run_checked(command: &mut ProcessCommand) -> Result<()> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "command failed: {display}\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use nostr_sdk::prelude::ToBech32;

    use crate::unix_timestamp;

    use super::{
        AppConfig, Cli, DaemonPeerCacheEntry, DaemonPeerCacheRestore, DaemonPeerCacheState,
        DiscoveredPublicSignalEndpoint, InstallCliArgs, LinuxExitNodeIpFamily,
        OutboundAnnounceBook, PeerAnnouncement, TunnelPeer, UninstallCliArgs, WireGuardPeerStatus,
        announcement_fingerprint, build_peer_announcement, build_runtime_magic_dns_records,
        can_reuse_active_listen_port, connected_peer_count_for_runtime, daemon_control_file_path,
        daemon_peer_cache_file_path, daemon_pids_from_ps_output, daemon_reconnect_backoff_delay,
        default_cli_install_path, endpoint_with_listen_port, install_cli,
        is_uapi_addr_in_use_error, key_b64_to_hex, kill_error_requires_control_fallback,
        linux_default_route_device_from_output, linux_exit_node_default_route_families,
        linux_exit_node_firewall_binary, linux_exit_node_forward_in_rule,
        linux_exit_node_forward_out_rule, linux_exit_node_ipv4_masquerade_rule,
        linux_route_get_spec_from_output, linux_service_status_from_show_output,
        local_interface_address_for_tunnel, macos_service_disabled_from_print_disabled_output,
        nat_punch_targets, parse_exit_node_arg, parse_nonzero_pid, peer_has_recent_handshake,
        peer_path_cache_timeout_secs, peer_runtime_lookup, peer_signal_timeout_secs,
        pending_tunnel_heartbeat_ips, persisted_path_cache_timeout_secs,
        persisted_peer_cache_timeout_secs, planned_tunnel_peers, public_endpoint_for_listen_port,
        publish_error_requires_reconnect, read_daemon_peer_cache, record_successful_runtime_paths,
        relay_connection_action, request_daemon_reload, request_daemon_stop,
        restore_daemon_peer_cache, route_targets_for_tunnel_peers,
        route_targets_require_endpoint_bypass, runtime_local_signal_endpoint,
        take_daemon_control_request, uninstall_cli, utun_interface_candidates,
        windows_service_status_from_query_output, write_daemon_peer_cache,
    };
    use std::collections::HashMap;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::crypto::generate_keypair;
    use nostr_vpn_core::paths::PeerPathBook;
    use nostr_vpn_core::presence::PeerPresenceBook;
    use nostr_vpn_core::signaling::SignalPayload;

    #[test]
    fn clap_binary_name_is_nvpn() {
        let command = Cli::command();
        assert_eq!(command.get_name(), "nvpn");
    }

    #[test]
    fn clap_includes_tailscale_style_commands() {
        let command = Cli::command();
        for name in [
            "start",
            "stop",
            "reload",
            "pause",
            "resume",
            "up",
            "connect",
            "down",
            "status",
            "set",
            "ping",
            "netcheck",
            "ip",
            "whois",
            "nat-discover",
            "hole-punch",
            "install-cli",
            "uninstall-cli",
            "service",
        ] {
            assert!(
                command
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() == name),
                "missing subcommand {name}"
            );
        }
    }

    #[test]
    fn clap_set_supports_autoconnect_flag() {
        let command = Cli::command();
        let set = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "set")
            .expect("set subcommand exists");
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some("autoconnect")),
            "missing --autoconnect on set command"
        );
    }

    #[test]
    fn clap_set_supports_route_advertisement_flags() {
        let command = Cli::command();
        let set = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "set")
            .expect("set subcommand exists");
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some("advertise-routes")),
            "missing --advertise-routes on set command"
        );
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some("advertise-exit-node")),
            "missing --advertise-exit-node on set command"
        );
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some("exit-node")),
            "missing --exit-node on set command"
        );
    }

    #[test]
    fn clap_service_supports_install_uninstall_status() {
        let command = Cli::command();
        let service = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "service")
            .expect("service subcommand exists");
        for name in ["install", "enable", "disable", "uninstall", "status"] {
            assert!(
                service
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() == name),
                "missing service subcommand {name}"
            );
        }
    }

    #[test]
    fn linux_service_show_parser_extracts_running_state() {
        let show = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n";
        let (loaded, running, pid) = linux_service_status_from_show_output(show);
        assert!(loaded);
        assert!(running);
        assert_eq!(pid, Some(4242));
    }

    #[test]
    fn macos_service_disabled_parser_extracts_disabled_state() {
        let output = r#"
            disabled services = {
                "to.nostrvpn.nvpn" => disabled
                "com.example.other" => enabled
            }
        "#;

        assert!(macos_service_disabled_from_print_disabled_output(
            output,
            "to.nostrvpn.nvpn"
        ));
        assert!(!macos_service_disabled_from_print_disabled_output(
            output,
            "com.example.other"
        ));
        assert!(!macos_service_disabled_from_print_disabled_output(
            output,
            "missing.service"
        ));
    }

    #[test]
    fn windows_service_query_parser_extracts_running_state() {
        let query = "SERVICE_NAME: NvpnService\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n        PID                : 1234\n        FLAGS              :\n";
        let (running, pid) = windows_service_status_from_query_output(query);
        assert!(running);
        assert_eq!(pid, Some(1234));
    }

    #[test]
    fn parse_nonzero_pid_rejects_zero_and_invalid_values() {
        assert_eq!(parse_nonzero_pid("4242"), Some(4242));
        assert_eq!(parse_nonzero_pid("0"), None);
        assert_eq!(parse_nonzero_pid("not-a-number"), None);
    }

    #[test]
    fn daemon_reconnect_backoff_is_bounded_exponential() {
        assert_eq!(daemon_reconnect_backoff_delay(1).as_secs(), 1);
        assert_eq!(daemon_reconnect_backoff_delay(2).as_secs(), 2);
        assert_eq!(daemon_reconnect_backoff_delay(3).as_secs(), 4);
        assert_eq!(daemon_reconnect_backoff_delay(4).as_secs(), 8);
        assert_eq!(daemon_reconnect_backoff_delay(5).as_secs(), 16);
        assert_eq!(daemon_reconnect_backoff_delay(6).as_secs(), 30);
        assert_eq!(daemon_reconnect_backoff_delay(99).as_secs(), 30);
    }

    #[test]
    fn reconnect_only_for_connection_class_errors() {
        assert!(publish_error_requires_reconnect(
            "client not connected to relays"
        ));
        assert!(publish_error_requires_reconnect("relay pool shutdown"));
        assert!(publish_error_requires_reconnect(
            "event not published: relay not connected (status changed)"
        ));
        assert!(publish_error_requires_reconnect(
            "event not published: recv message response timeout"
        ));
        assert!(publish_error_requires_reconnect(
            "connection closed by peer"
        ));

        assert!(!publish_error_requires_reconnect(
            "private signaling event rejected by all relays"
        ));
        assert!(!publish_error_requires_reconnect(
            "event not published: Policy violated and pubkey is not in our web of trust."
        ));
    }

    #[test]
    fn peer_signal_timeout_has_reasonable_floor_and_scale() {
        assert_eq!(peer_signal_timeout_secs(1), 20);
        assert_eq!(peer_signal_timeout_secs(5), 20);
        assert_eq!(peer_signal_timeout_secs(10), 30);
    }

    #[test]
    fn peer_path_cache_timeout_keeps_endpoint_memory_longer_than_presence_timeout() {
        assert_eq!(peer_path_cache_timeout_secs(1), 60);
        assert_eq!(peer_path_cache_timeout_secs(5), 60);
        assert_eq!(peer_path_cache_timeout_secs(10), 90);
    }

    #[test]
    fn outbound_announce_book_republishes_after_peer_forget() {
        let mut book = OutboundAnnounceBook::default();
        assert!(book.needs_send("peer-a", "fp1"));
        book.mark_sent("peer-a", "fp1");
        assert!(!book.needs_send("peer-a", "fp1"));
        assert!(book.needs_send("peer-a", "fp2"));

        book.forget("peer-a");
        assert!(book.needs_send("peer-a", "fp1"));
    }

    #[test]
    fn cached_peerbook_keeps_connected_peer_count_after_presence_expires() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 1,
        };

        let mut presence = PeerPresenceBook::default();
        assert!(presence.apply_signal(
            participant.clone(),
            SignalPayload::Announce(announcement.clone()),
            100,
        ));
        assert_eq!(presence.prune_stale(200, 20), vec![participant.clone()]);
        assert!(presence.active().is_empty());
        assert!(presence.announcement_for(&participant).is_some());

        let now = 1_700_000_000;
        let runtime_peers = HashMap::from([(
            key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.20:51820".to_string()),
                last_handshake_sec: Some(5),
                last_handshake_nsec: Some(0),
            },
        )]);

        assert_eq!(
            connected_peer_count_for_runtime(&config, None, &presence, Some(&runtime_peers), now),
            1
        );

        let runtime_peer = peer_runtime_lookup(&announcement, Some(&runtime_peers))
            .expect("runtime peer should resolve from cached announcement");
        assert!(peer_has_recent_handshake(runtime_peer));
    }

    #[test]
    fn stale_handshake_does_not_count_mesh_as_ready() {
        let runtime_peer = WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(30),
            last_handshake_nsec: Some(0),
        };

        assert!(!peer_has_recent_handshake(&runtime_peer));
    }

    #[test]
    fn handshake_age_converts_to_observed_epoch() {
        let runtime_peer = WireGuardPeerStatus {
            endpoint: Some("203.0.113.20:51820".to_string()),
            last_handshake_sec: Some(5),
            last_handshake_nsec: Some(0),
        };

        assert_eq!(
            runtime_peer.last_handshake_at(1_700_000_000),
            Some(1_699_999_995)
        );
    }

    #[test]
    fn persisted_peer_cache_roundtrips_known_peers_and_path_hints() {
        let nonce = unix_timestamp();
        let dir = std::env::temp_dir().join(format!("nvpn-peer-cache-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp cache dir");
        let config_path = dir.join("config.toml");
        let cache_path = daemon_peer_cache_file_path(&config_path);

        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.networks[0].participants = vec![participant.clone()];
        let network_id = config.effective_network_id();
        let own_pubkey = config.own_nostr_pubkey_hex().ok();

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: Some("192.168.1.20:51820".to_string()),
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 100,
        };

        let mut path_book = PeerPathBook::default();
        assert!(path_book.note_success(participant.clone(), "203.0.113.20:51820", 120,));

        let cache = DaemonPeerCacheState {
            version: 1,
            network_id: network_id.clone(),
            own_pubkey: own_pubkey.clone(),
            updated_at: 130,
            peers: vec![DaemonPeerCacheEntry {
                participant_pubkey: participant.clone(),
                announcement: announcement.clone(),
                last_signal_seen_at: Some(110),
                cached_at: 125,
            }],
            path_book,
        };
        write_daemon_peer_cache(&cache_path, &cache).expect("write peer cache");
        let loaded = read_daemon_peer_cache(&cache_path)
            .expect("read peer cache")
            .expect("cache should exist");
        assert_eq!(loaded.network_id, network_id);
        assert_eq!(loaded.peers.len(), 1);

        let mut restored_presence = PeerPresenceBook::default();
        let mut restored_paths = PeerPathBook::default();
        assert!(
            restore_daemon_peer_cache(
                DaemonPeerCacheRestore {
                    path: &cache_path,
                    app: &config,
                    network_id: &network_id,
                    own_pubkey: own_pubkey.as_deref(),
                    now: 130,
                    announce_interval_secs: 20,
                },
                &mut restored_presence,
                &mut restored_paths,
            )
            .expect("restore peer cache")
        );
        assert!(restored_presence.active().is_empty());
        assert!(restored_presence.known().contains_key(&participant));

        let planned = planned_tunnel_peers(
            &config,
            own_pubkey.as_deref(),
            restored_presence.known(),
            &mut restored_paths,
            Some("10.0.0.33:51820"),
            130,
        )
        .expect("planned peers from restored cache");
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].endpoint, "203.0.113.20:51820");

        let _ = fs::remove_file(&cache_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_persisted_peer_cache_is_ignored() {
        let nonce = unix_timestamp();
        let dir = std::env::temp_dir().join(format!("nvpn-stale-peer-cache-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp cache dir");
        let config_path = dir.join("config.toml");
        let cache_path = daemon_peer_cache_file_path(&config_path);

        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.networks[0].participants = vec![participant.clone()];
        let network_id = config.effective_network_id();
        let own_pubkey = config.own_nostr_pubkey_hex().ok();

        let cache = DaemonPeerCacheState {
            version: 1,
            network_id: network_id.clone(),
            own_pubkey: own_pubkey.clone(),
            updated_at: 10,
            peers: vec![DaemonPeerCacheEntry {
                participant_pubkey: participant,
                announcement: PeerAnnouncement {
                    node_id: "peer-a".to_string(),
                    public_key: generate_keypair().public_key,
                    endpoint: "203.0.113.20:51820".to_string(),
                    local_endpoint: None,
                    public_endpoint: Some("203.0.113.20:51820".to_string()),
                    tunnel_ip: "10.44.0.2/32".to_string(),
                    advertised_routes: Vec::new(),
                    timestamp: 1,
                },
                last_signal_seen_at: Some(10),
                cached_at: 10,
            }],
            path_book: PeerPathBook::default(),
        };
        write_daemon_peer_cache(&cache_path, &cache).expect("write stale peer cache");

        let mut restored_presence = PeerPresenceBook::default();
        let mut restored_paths = PeerPathBook::default();
        assert!(
            !restore_daemon_peer_cache(
                DaemonPeerCacheRestore {
                    path: &cache_path,
                    app: &config,
                    network_id: &network_id,
                    own_pubkey: own_pubkey.as_deref(),
                    now: 10 + persisted_peer_cache_timeout_secs(20) + 1,
                    announce_interval_secs: 20,
                },
                &mut restored_presence,
                &mut restored_paths,
            )
            .expect("restore stale cache")
        );
        assert!(restored_presence.known().is_empty());
        assert!(!restored_paths.prune_stale(
            10 + persisted_path_cache_timeout_secs(20) + 1,
            persisted_path_cache_timeout_secs(20),
        ));

        let _ = fs::remove_file(&cache_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn utun_candidates_expand_for_default_style_names() {
        let candidates = utun_interface_candidates("utun100");
        assert_eq!(candidates.len(), 16);
        assert_eq!(candidates[0], "utun100");
        assert_eq!(candidates[1], "utun101");
        assert_eq!(candidates[15], "utun115");
    }

    #[test]
    fn utun_candidates_keep_custom_iface_as_is() {
        let candidates = utun_interface_candidates("wg0");
        assert_eq!(candidates, vec!["wg0".to_string()]);
    }

    #[test]
    fn uapi_addr_in_use_matcher_detects_common_errnos() {
        assert!(is_uapi_addr_in_use_error("uapi set failed: errno=48"));
        assert!(is_uapi_addr_in_use_error("uapi set failed: errno=98"));
        assert!(!is_uapi_addr_in_use_error("uapi set failed: errno=1"));
    }

    #[test]
    fn endpoint_listen_port_rewrite_updates_socket_port() {
        assert_eq!(
            endpoint_with_listen_port("192.168.1.10:51820", 52000),
            "192.168.1.10:52000"
        );
        assert_eq!(
            endpoint_with_listen_port("[2001:db8::1]:51820", 52000),
            "[2001:db8::1]:52000"
        );
        assert_eq!(
            endpoint_with_listen_port("not-a-socket", 52000),
            "not-a-socket"
        );
    }

    #[test]
    fn local_interface_address_for_tunnel_preserves_host_prefix() {
        assert_eq!(
            local_interface_address_for_tunnel("10.44.0.1/32"),
            "10.44.0.1/32"
        );
        assert_eq!(
            local_interface_address_for_tunnel("10.44.0.1"),
            "10.44.0.1/32"
        );
    }

    #[test]
    fn route_targets_for_tunnel_peers_use_peer_allowed_ips() {
        let routes = route_targets_for_tunnel_peers(&[
            TunnelPeer {
                pubkey_hex: "a".repeat(64),
                endpoint: "203.0.113.10:51820".to_string(),
                allowed_ips: vec!["10.44.0.3/32".to_string()],
            },
            TunnelPeer {
                pubkey_hex: "b".repeat(64),
                endpoint: "203.0.113.11:51820".to_string(),
                allowed_ips: vec!["10.44.0.2/32".to_string(), "10.55.0.0/24".to_string()],
            },
            TunnelPeer {
                pubkey_hex: "c".repeat(64),
                endpoint: "203.0.113.12:51820".to_string(),
                allowed_ips: vec!["10.44.0.2/32".to_string()],
            },
        ]);

        assert_eq!(
            routes,
            vec![
                "10.44.0.2/32".to_string(),
                "10.44.0.3/32".to_string(),
                "10.55.0.0/24".to_string(),
            ]
        );
    }

    #[test]
    fn route_targets_detect_when_endpoint_bypass_is_required() {
        assert!(!route_targets_require_endpoint_bypass(&[
            "10.44.0.2/32".to_string()
        ]));
        assert!(route_targets_require_endpoint_bypass(&[
            "10.55.0.0/24".to_string()
        ]));
        assert!(route_targets_require_endpoint_bypass(&[
            "0.0.0.0/0".to_string()
        ]));
    }

    #[test]
    fn linux_exit_node_default_route_families_detect_ipv4_and_ipv6_defaults() {
        let ipv6_only = linux_exit_node_default_route_families(&["::/0".to_string()]);
        assert!(!ipv6_only.ipv4);
        assert!(ipv6_only.ipv6);

        let dual_stack = linux_exit_node_default_route_families(&[
            "10.55.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            "::/0".to_string(),
        ]);
        assert!(dual_stack.ipv4);
        assert!(dual_stack.ipv6);
    }

    #[test]
    fn linux_exit_node_ipv6_forward_rules_use_ip6tables_shape() {
        assert_eq!(
            linux_exit_node_firewall_binary(LinuxExitNodeIpFamily::V4),
            "iptables"
        );
        assert_eq!(
            linux_exit_node_firewall_binary(LinuxExitNodeIpFamily::V6),
            "ip6tables"
        );
        assert_eq!(
            linux_exit_node_ipv4_masquerade_rule("eth0", "10.44.0.0/24"),
            vec![
                "POSTROUTING".to_string(),
                "-o".to_string(),
                "eth0".to_string(),
                "-s".to_string(),
                "10.44.0.0/24".to_string(),
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                "nvpn-exit-masq".to_string(),
                "-j".to_string(),
                "MASQUERADE".to_string(),
            ]
        );
        assert_eq!(
            linux_exit_node_forward_in_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD".to_string(),
                "-i".to_string(),
                "utun100".to_string(),
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                "nvpn-exit6-forward-in".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]
        );
        assert_eq!(
            linux_exit_node_forward_out_rule("utun100", LinuxExitNodeIpFamily::V6),
            vec![
                "FORWARD".to_string(),
                "-o".to_string(),
                "utun100".to_string(),
                "-m".to_string(),
                "conntrack".to_string(),
                "--ctstate".to_string(),
                "RELATED,ESTABLISHED".to_string(),
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                "nvpn-exit6-forward-out".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]
        );
    }

    #[test]
    fn parse_exit_node_arg_normalizes_and_clears() {
        let peer = Keys::generate();
        let peer_hex = peer.public_key().to_hex();
        let peer_npub = peer.public_key().to_bech32().expect("peer npub");

        assert_eq!(
            parse_exit_node_arg(&peer_npub).expect("parse exit node"),
            Some(peer_hex)
        );
        assert_eq!(parse_exit_node_arg("off").expect("clear"), None);
        assert_eq!(parse_exit_node_arg("none").expect("clear"), None);
        assert_eq!(parse_exit_node_arg("").expect("clear"), None);
    }

    #[test]
    fn runtime_local_signal_endpoint_prefers_detected_ipv4_for_private_configured_endpoint() {
        assert_eq!(
            runtime_local_signal_endpoint(
                "192.168.178.55:51820",
                52000,
                Some(Ipv4Addr::new(172, 20, 10, 2)),
            ),
            "172.20.10.2:52000"
        );
        assert_eq!(
            runtime_local_signal_endpoint(
                "127.0.0.1:51820",
                52000,
                Some(Ipv4Addr::new(172, 20, 10, 2)),
            ),
            "172.20.10.2:52000"
        );
    }

    #[test]
    fn runtime_local_signal_endpoint_keeps_public_configured_endpoint() {
        assert_eq!(
            runtime_local_signal_endpoint(
                "93.184.216.34:51820",
                52000,
                Some(Ipv4Addr::new(172, 20, 10, 2)),
            ),
            "93.184.216.34:52000"
        );
    }

    #[test]
    fn public_endpoint_for_listen_port_requires_matching_discovery_port() {
        let endpoint = DiscoveredPublicSignalEndpoint {
            listen_port: 51820,
            endpoint: "198.51.100.20:43127".to_string(),
        };

        assert_eq!(
            public_endpoint_for_listen_port(Some(&endpoint), 51820),
            Some("198.51.100.20:43127".to_string())
        );
        assert_eq!(
            public_endpoint_for_listen_port(Some(&endpoint), 51821),
            None
        );
    }

    #[test]
    fn peer_announcement_includes_effective_advertised_routes() {
        let mut config = AppConfig::generated();
        config.node.advertise_exit_node = true;
        config.node.advertised_routes = vec!["10.0.0.0/24".to_string()];
        config.ensure_defaults();

        let announcement = build_peer_announcement(&config, 51820, None);

        assert_eq!(
            announcement.advertised_routes,
            vec![
                "10.0.0.0/24".to_string(),
                "0.0.0.0/0".to_string(),
                "::/0".to_string(),
            ]
        );
    }

    #[test]
    fn announcement_fingerprint_changes_when_routes_change() {
        let mut config = AppConfig::generated();
        let initial = build_peer_announcement(&config, 51820, None);
        let initial_fingerprint = announcement_fingerprint(&initial);

        config.node.advertise_exit_node = true;
        let updated = build_peer_announcement(&config, 51820, None);

        assert_ne!(initial_fingerprint, announcement_fingerprint(&updated));
    }

    #[test]
    fn planned_tunnel_peers_assign_selected_exit_node_default_route() {
        let mut config = AppConfig::generated();
        let exit_participant = Keys::generate().public_key().to_hex();
        let routed_participant = Keys::generate().public_key().to_hex();
        config.networks[0].participants =
            vec![exit_participant.clone(), routed_participant.clone()];
        config.exit_node = exit_participant.clone();
        config.ensure_defaults();

        let announcements = HashMap::from([
            (
                exit_participant.clone(),
                PeerAnnouncement {
                    node_id: "exit-node".to_string(),
                    public_key: generate_keypair().public_key,
                    endpoint: "203.0.113.20:51820".to_string(),
                    local_endpoint: None,
                    public_endpoint: Some("203.0.113.20:51820".to_string()),
                    tunnel_ip: "10.44.0.2/32".to_string(),
                    advertised_routes: vec![
                        "10.60.0.0/24".to_string(),
                        "0.0.0.0/0".to_string(),
                        "::/0".to_string(),
                    ],
                    timestamp: 1,
                },
            ),
            (
                routed_participant.clone(),
                PeerAnnouncement {
                    node_id: "routed-node".to_string(),
                    public_key: generate_keypair().public_key,
                    endpoint: "203.0.113.21:51820".to_string(),
                    local_endpoint: None,
                    public_endpoint: Some("203.0.113.21:51820".to_string()),
                    tunnel_ip: "10.44.0.3/32".to_string(),
                    advertised_routes: vec!["10.70.0.0/24".to_string()],
                    timestamp: 1,
                },
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
        let exit_participant = Keys::generate().public_key().to_hex();
        config.networks[0].participants = vec![exit_participant.clone()];
        config.ensure_defaults();

        let announcements = HashMap::from([(
            exit_participant.clone(),
            PeerAnnouncement {
                node_id: "exit-node".to_string(),
                public_key: generate_keypair().public_key,
                endpoint: "203.0.113.20:51820".to_string(),
                local_endpoint: None,
                public_endpoint: Some("203.0.113.20:51820".to_string()),
                tunnel_ip: "10.44.0.2/32".to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string(), "10.60.0.0/24".to_string()],
                timestamp: 1,
            },
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
    fn linux_default_route_device_parser_extracts_interface() {
        assert_eq!(
            linux_default_route_device_from_output(
                "default via 198.19.242.2 dev eth0 proto static\n"
            ),
            Some("eth0".to_string())
        );
    }

    #[test]
    fn linux_route_get_parser_extracts_gateway_interface_and_source() {
        let spec = linux_route_get_spec_from_output(
            "10.254.241.10 via 198.19.242.2 dev eth0 src 198.19.242.3 uid 0\n    cache\n",
        )
        .expect("linux route get spec");

        assert_eq!(spec.gateway.as_deref(), Some("198.19.242.2"));
        assert_eq!(spec.dev, "eth0");
        assert_eq!(spec.src.as_deref(), Some("198.19.242.3"));
    }

    #[test]
    fn reuses_running_listen_port_without_rebind() {
        assert!(can_reuse_active_listen_port(true, true, Some(51820), 51820));
        assert!(!can_reuse_active_listen_port(
            true,
            true,
            Some(51820),
            51821
        ));
        assert!(!can_reuse_active_listen_port(
            false,
            true,
            Some(51820),
            51820
        ));
        assert!(!can_reuse_active_listen_port(
            true,
            false,
            Some(51820),
            51820
        ));
        assert!(!can_reuse_active_listen_port(true, true, None, 51820));
    }

    #[test]
    fn tunnel_heartbeat_targets_only_include_peers_without_handshake() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: None,
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 1,
        };
        let announcements = HashMap::from([(participant.clone(), announcement)]);

        let pending = pending_tunnel_heartbeat_ips(&config, None, &announcements, None);
        assert_eq!(pending, vec![Ipv4Addr::new(10, 44, 0, 2)]);

        let runtime_peers = HashMap::from([(
            key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.20:51820".to_string()),
                last_handshake_sec: Some(1),
                last_handshake_nsec: Some(0),
            },
        )]);
        let pending =
            pending_tunnel_heartbeat_ips(&config, None, &announcements, Some(&runtime_peers));
        assert!(pending.is_empty(), "handshaken peer should not be probed");
    }

    #[test]
    fn relay_connection_action_pauses_when_mesh_is_ready() {
        assert_eq!(
            relay_connection_action(true, true, true),
            super::RelayConnectionAction::PauseForMesh
        );
        assert_eq!(
            relay_connection_action(true, false, true),
            super::RelayConnectionAction::StayPausedForMesh
        );
        assert_eq!(
            relay_connection_action(true, false, false),
            super::RelayConnectionAction::ReconnectWhenDue
        );
        assert_eq!(
            relay_connection_action(false, true, true),
            super::RelayConnectionAction::KeepConnected
        );
    }

    #[test]
    fn runtime_handshake_updates_path_cache() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: Some("192.168.1.20:51820".to_string()),
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 10,
        };
        let announcements = HashMap::from([(participant.clone(), announcement.clone())]);
        let mut paths = PeerPathBook::default();
        let selected = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut paths,
            Some("192.168.1.33:51820"),
            10,
        )
        .expect("initial tunnel peers");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].endpoint, "192.168.1.20:51820");
        paths.note_selected(&participant, &selected[0].endpoint, 10);

        let runtime_peers = HashMap::from([(
            key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.20:51820".to_string()),
                last_handshake_sec: Some(1),
                last_handshake_nsec: Some(0),
            },
        )]);
        assert!(record_successful_runtime_paths(
            &announcements,
            Some(&runtime_peers),
            &mut paths,
            16,
        ));

        let selected = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut paths,
            Some("192.168.1.33:51820"),
            16,
        )
        .expect("tunnel peers after handshake");
        assert_eq!(selected[0].endpoint, "203.0.113.20:51820");
    }

    #[test]
    fn cached_successful_endpoint_survives_announcement_flap_until_path_cache_expires() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.nat.enabled = false;
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let original = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "203.0.113.20:51820".to_string(),
            local_endpoint: Some("192.168.1.20:51820".to_string()),
            public_endpoint: Some("203.0.113.20:51820".to_string()),
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 10,
        };
        let flapped = PeerAnnouncement {
            public_endpoint: None,
            endpoint: "192.168.1.20:51820".to_string(),
            local_endpoint: Some("192.168.1.20:51820".to_string()),
            timestamp: 20,
            ..original.clone()
        };

        let mut paths = PeerPathBook::default();
        let original_announcements = HashMap::from([(participant.clone(), original)]);
        let runtime_peers = HashMap::from([(
            key_b64_to_hex(&peer_keys.public_key).expect("peer pubkey hex"),
            WireGuardPeerStatus {
                endpoint: Some("203.0.113.20:51820".to_string()),
                last_handshake_sec: Some(1),
                last_handshake_nsec: Some(0),
            },
        )]);
        assert!(record_successful_runtime_paths(
            &original_announcements,
            Some(&runtime_peers),
            &mut paths,
            12,
        ));

        let flapped_announcements = HashMap::from([(participant.clone(), flapped.clone())]);
        let selected = planned_tunnel_peers(
            &config,
            None,
            &flapped_announcements,
            &mut paths,
            Some("10.0.0.33:51820"),
            21,
        )
        .expect("cached tunnel peers");
        assert_eq!(selected[0].endpoint, "203.0.113.20:51820");

        paths.prune_stale(200, peer_path_cache_timeout_secs(5));

        let selected = planned_tunnel_peers(
            &config,
            None,
            &flapped_announcements,
            &mut paths,
            Some("10.0.0.33:51820"),
            200,
        )
        .expect("fallback tunnel peers");
        assert_eq!(selected[0].endpoint, "192.168.1.20:51820");
    }

    #[test]
    fn nat_remote_peer_waits_for_public_endpoint_before_runtime_apply() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.nat.enabled = true;
        config.node.endpoint = "198.19.241.3:51820".to_string();
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "198.19.242.3:51820".to_string(),
            local_endpoint: Some("198.19.242.3:51820".to_string()),
            public_endpoint: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 10,
        };
        let announcements = HashMap::from([(participant.clone(), announcement)]);

        let selected = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("198.19.241.3:51820"),
            10,
        )
        .expect("planned tunnel peers");
        assert!(selected.is_empty());
        assert!(nat_punch_targets(&config, None, &announcements, 51820).is_empty());
    }

    #[test]
    fn nat_same_subnet_peer_can_use_local_endpoint_without_public_signal() {
        let mut config = AppConfig::generated();
        let participant = "11".repeat(32);
        config.nat.enabled = true;
        config.node.endpoint = "198.19.241.3:51820".to_string();
        config.networks[0].participants = vec![participant.clone()];

        let peer_keys = generate_keypair();
        let announcement = PeerAnnouncement {
            node_id: "peer-a".to_string(),
            public_key: peer_keys.public_key.clone(),
            endpoint: "198.19.241.11:51820".to_string(),
            local_endpoint: Some("198.19.241.11:51820".to_string()),
            public_endpoint: None,
            tunnel_ip: "10.44.0.2/32".to_string(),
            advertised_routes: Vec::new(),
            timestamp: 10,
        };
        let announcements = HashMap::from([(participant.clone(), announcement)]);

        let selected = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("198.19.241.3:51820"),
            10,
        )
        .expect("planned tunnel peers");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].endpoint, "198.19.241.11:51820");
        assert_eq!(
            nat_punch_targets(&config, None, &announcements, 51820),
            vec![
                "198.19.241.11:51820"
                    .parse()
                    .expect("same-subnet punch target")
            ]
        );
    }

    #[test]
    fn runtime_magic_dns_records_prefer_live_announcement_tunnel_ip() {
        let mut config = AppConfig::generated();
        config.magic_dns_suffix = "nvpn".to_string();
        config.networks[0].participants =
            vec!["3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string()];
        config.ensure_defaults();
        config
            .set_peer_alias(
                "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645",
                "pig",
            )
            .expect("set alias");

        let mut announcements = HashMap::new();
        announcements.insert(
            "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
            PeerAnnouncement {
                node_id: "peer-node".to_string(),
                public_key: "pubkey".to_string(),
                endpoint: "192.168.1.55:51820".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip: "10.44.0.113/32".to_string(),
                advertised_routes: Vec::new(),
                timestamp: 1,
            },
        );

        let records = build_runtime_magic_dns_records(&config, &announcements);
        assert_eq!(
            records.get("pig.nvpn").map(|ip| ip.to_string()),
            Some("10.44.0.113".to_string())
        );
        assert_eq!(
            records.get("pig").map(|ip| ip.to_string()),
            Some("10.44.0.113".to_string())
        );
    }

    #[test]
    fn runtime_magic_dns_records_follow_latest_announcement_ip() {
        let mut config = AppConfig::generated();
        config.magic_dns_suffix = "nvpn".to_string();
        config.networks[0].participants =
            vec!["3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string()];
        config.ensure_defaults();
        config
            .set_peer_alias(
                "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645",
                "pig",
            )
            .expect("set alias");

        let mut announcements = HashMap::new();
        announcements.insert(
            "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
            PeerAnnouncement {
                node_id: "peer-node".to_string(),
                public_key: "pubkey".to_string(),
                endpoint: "192.168.1.55:51820".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip: "10.44.0.113/32".to_string(),
                advertised_routes: Vec::new(),
                timestamp: 1,
            },
        );
        let first = build_runtime_magic_dns_records(&config, &announcements);
        assert_eq!(
            first.get("pig.nvpn").map(|ip| ip.to_string()),
            Some("10.44.0.113".to_string())
        );

        announcements.insert(
            "3d332ed94c79863e73ff8af62882de2853c77d6a5c1fe61d7598a90db1fab645".to_string(),
            PeerAnnouncement {
                node_id: "peer-node".to_string(),
                public_key: "pubkey".to_string(),
                endpoint: "192.168.1.55:51820".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip: "10.44.0.114/32".to_string(),
                advertised_routes: Vec::new(),
                timestamp: 2,
            },
        );
        let second = build_runtime_magic_dns_records(&config, &announcements);
        assert_eq!(
            second.get("pig.nvpn").map(|ip| ip.to_string()),
            Some("10.44.0.114".to_string())
        );
    }

    #[test]
    fn daemon_pid_scan_matches_processes_for_config() {
        let config_path = Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml");
        let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
                  97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
                  55555 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /tmp/other.toml --iface utun100\n";
        let pids = daemon_pids_from_ps_output(ps, config_path);
        assert_eq!(pids, vec![42063, 97597]);
    }

    #[test]
    fn daemon_pid_scan_excludes_current_pid_when_filtering_duplicates() {
        let config_path = Path::new("/Users/sirius/Library/Application Support/nvpn/config.toml");
        let ps = "  42063 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n\
                  97597 /Applications/Nostr VPN.app/Contents/MacOS/nvpn daemon --config /Users/sirius/Library/Application Support/nvpn/config.toml --iface utun100\n";
        let mut pids = daemon_pids_from_ps_output(ps, config_path);
        pids.retain(|pid| *pid != 97597);
        assert_eq!(pids, vec![42063]);
    }

    #[test]
    fn default_cli_install_path_uses_nvpn_filename() {
        let path = default_cli_install_path();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("nvpn")
        );
    }

    #[test]
    fn install_cli_and_uninstall_cli_roundtrip_for_custom_path() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-install-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let target = dir.join("nvpn");

        install_cli(InstallCliArgs {
            path: Some(target.clone()),
            force: false,
        })
        .expect("install custom cli target");
        assert!(target.exists(), "installed target should exist");

        let duplicate = install_cli(InstallCliArgs {
            path: Some(target.clone()),
            force: false,
        });
        assert!(duplicate.is_err(), "install without --force should fail");

        install_cli(InstallCliArgs {
            path: Some(target.clone()),
            force: true,
        })
        .expect("force reinstall custom cli target");

        uninstall_cli(UninstallCliArgs {
            path: Some(target.clone()),
        })
        .expect("uninstall custom cli target");
        assert!(!target.exists(), "uninstall should remove target");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_error_fallback_matcher_detects_permission_denied() {
        assert!(kill_error_requires_control_fallback(
            "kill -TERM 123 failed\nstderr: Operation not permitted"
        ));
        assert!(kill_error_requires_control_fallback(
            "kill -TERM 123 failed\nstderr: permission denied"
        ));
        assert!(!kill_error_requires_control_fallback(
            "kill -TERM 123 failed\nstderr: no such process"
        ));
    }

    #[test]
    fn daemon_control_stop_request_roundtrip() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-control-test-{nonce}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let config = dir.join("config.toml");
        fs::write(&config, "node_name = \"test\"").expect("write config");

        request_daemon_stop(&config).expect("write stop request");
        assert!(
            take_daemon_control_request(&config) == Some(super::DaemonControlRequest::Stop),
            "daemon should read stop request"
        );
        request_daemon_reload(&config).expect("write reload request");
        assert!(
            take_daemon_control_request(&config) == Some(super::DaemonControlRequest::Reload),
            "daemon should read reload request"
        );
        control_daemon_request_for_test(&config, super::DaemonControlRequest::Pause);
        assert!(
            take_daemon_control_request(&config) == Some(super::DaemonControlRequest::Pause),
            "daemon should read pause request"
        );
        control_daemon_request_for_test(&config, super::DaemonControlRequest::Resume);
        assert!(
            take_daemon_control_request(&config) == Some(super::DaemonControlRequest::Resume),
            "daemon should read resume request"
        );
        let _ = fs::remove_file(daemon_control_file_path(&config));
        assert!(
            take_daemon_control_request(&config).is_none(),
            "without control file there should be no stop request"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn control_daemon_request_for_test(config: &Path, request: super::DaemonControlRequest) {
        super::write_daemon_control_request(config, request).expect("write control request");
    }
}
