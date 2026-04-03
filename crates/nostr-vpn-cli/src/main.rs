mod config_bootstrap;
mod daemon_runtime;
mod diagnostics;
#[cfg(any(target_os = "macos", test))]
mod macos_network;
#[cfg(any(target_os = "macos", test))]
mod macos_service;
mod network_signaling;
mod platform_routing;
mod relay_runtime;
mod service_management;
#[cfg(any(target_os = "windows", test))]
mod userspace_wg;
#[cfg(any(target_os = "windows", test))]
mod windows_tunnel;

use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
#[cfg(any(target_os = "macos", test))]
use std::hash::{Hash, Hasher};
#[cfg(unix)]
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
#[cfg(target_os = "windows")]
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
#[cfg(unix)]
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Args, Parser, Subcommand};
use hex::encode as encode_hex;
use netdev::get_interfaces;
#[cfg(test)]
use netdev::interface::interface::Interface as NetworkInterface;
#[cfg(test)]
use nostr_sdk::prelude::ToBech32;
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, maybe_autoconfigure_node, normalize_advertised_route,
    normalize_nostr_pubkey, normalize_runtime_network_id,
};
use nostr_vpn_core::control::{PeerAnnouncement, select_peer_endpoint_from_local_endpoints};
use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::diagnostics::{
    HealthIssue, HealthSeverity, NetworkSummary, PortMappingStatus, ProbeState,
};
use nostr_vpn_core::magic_dns::{
    MagicDnsResolverConfig, MagicDnsServer, build_magic_dns_records, install_system_resolver,
    uninstall_system_resolver,
};
use nostr_vpn_core::nat::{
    discover_public_udp_endpoint, discover_public_udp_endpoint_via_stun, hole_punch_udp,
};
use nostr_vpn_core::node_record::{NODE_RECORD_RELAY_TAG, NodeServiceKind, discover_node_records};
use nostr_vpn_core::paths::PeerPathBook;
#[cfg(target_os = "windows")]
use nostr_vpn_core::platform_paths::{
    legacy_config_path_from_dirs_config_dir, windows_default_config_path_for_state,
    windows_machine_config_path_from_program_data_dir,
    windows_service_config_path_from_sc_qc_output,
};
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::relay::{
    RelayAllocationGranted, RelayAllocationRejected, RelayAllocationRequest, RelayProbeRequest,
};
use nostr_vpn_core::service_signaling::{RelayServiceClient, ServicePayload};
use nostr_vpn_core::signaling::{
    NetworkRoster, NostrSignalingClient, SignalEnvelope, SignalPayload, SignalingNetwork,
};
use nostr_vpn_core::wireguard::{InterfaceConfig, PeerConfig, render_wireguard_config};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::UdpSocket;
#[cfg(target_os = "windows")]
use windows_service::define_windows_service;
#[cfg(target_os = "windows")]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(target_os = "windows")]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(target_os = "windows")]
use windows_service::service_dispatcher;

#[cfg(test)]
pub(crate) use crate::config_bootstrap::default_cli_install_path;
pub(crate) use crate::config_bootstrap::{
    apply_config_file, apply_participants_override, default_config_path, default_tunnel_iface,
    init_config, install_cli, load_or_default_config, print_version, resolve_relays, uninstall_cli,
};
#[cfg(target_os = "windows")]
pub(crate) use crate::config_bootstrap::{
    windows_installed_service_config_path, windows_service_install_config_path,
};
pub(crate) use crate::daemon_runtime::*;
use crate::diagnostics::{
    PortMappingRuntime, build_health_issues, capture_network_snapshot, detect_captive_portal,
    run_netcheck_report, write_doctor_bundle,
};
#[cfg(target_os = "macos")]
#[cfg(test)]
use crate::network_signaling::NETWORK_INVITE_PREFIX;
use crate::network_signaling::{
    AnnounceRequest, RosterEditAction, active_network_invite_code,
    apply_network_invite_to_active_network, discover_peers, maybe_reload_running_daemon,
    parse_network_invite, publish_active_network_roster, publish_announcement,
    update_active_network_roster,
};
pub(crate) use crate::platform_routing::*;
pub(crate) use crate::relay_runtime::*;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) use crate::service_management::parse_nonzero_pid;
#[cfg(any(target_os = "linux", test))]
pub(crate) use crate::service_management::{
    linux_service_executable_path_from_unit_contents, linux_service_status_from_show_output,
    linux_service_unit_content,
};
#[cfg(any(target_os = "windows", test))]
pub(crate) use crate::service_management::{
    windows_service_bin_path, windows_service_binary_path_from_sc_qc_output,
    windows_service_disabled_from_qc_output, windows_service_status_from_query_output,
    windows_should_apply_config_via_service,
};
#[cfg(any(target_os = "macos", test))]
pub(crate) use crate::service_management::{xml_escape, xml_unescape};
#[cfg(target_os = "windows")]
use crate::windows_tunnel::WindowsTunnelBackend;

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy)]
struct DeviceConfig {
    n_threads: usize,
    use_connected_socket: bool,
}

#[cfg(not(unix))]
#[derive(Debug)]
struct DeviceHandle;

#[cfg(not(unix))]
#[allow(dead_code)]
impl DeviceHandle {
    fn new(_name: &str, config: DeviceConfig) -> Result<Self> {
        let _ = (config.n_threads, config.use_connected_socket);
        Err(anyhow!(
            "WireGuard device backend is not available on this platform"
        ))
    }

    fn wait(&mut self) {}

    fn clean(&mut self) {}
}

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
// boringtun reports time since the last completed WireGuard handshake. Idle
// sessions can stay healthy for roughly the reject-after window (~180s), so a
// 20s cutoff misclassifies healthy peers as disconnected.
const PEER_ONLINE_GRACE_SECS: u64 = 180;
const RELAY_DISCOVERY_LOOKBACK_SECS: u64 = 900;
const RELAY_REQUEST_RETRY_AFTER_SECS: u64 = 30;
const RELAY_REQUEST_TIMEOUT_SECS: u64 = 120;
const RELAY_SESSION_VERIFY_TIMEOUT_SECS: u64 = 8;
const RELAY_FAILED_RETRY_AFTER_SECS: u64 = 60;
const RELAY_PROVIDER_FAILURE_MAX_COOLDOWN_SECS: u64 = 900;
const RELAY_PROVIDER_PROBE_TIMEOUT_SECS: u64 = 4;
const RELAY_PROVIDER_PROBE_RETRY_AFTER_SECS: u64 = 60;
const MAX_PARALLEL_RELAY_PROVIDER_PROBES: usize = 2;
const MAX_PARALLEL_RELAY_REQUESTS_PER_PARTICIPANT: usize = 3;
const MIN_PERSISTED_PEER_CACHE_TIMEOUT_SECS: u64 = 600;
const PERSISTED_PEER_CACHE_TIMEOUT_MULTIPLIER: u64 = 30;
const MIN_PERSISTED_PATH_CACHE_TIMEOUT_SECS: u64 = 1_800;
const PERSISTED_PATH_CACHE_TIMEOUT_MULTIPLIER: u64 = 90;
const WAITING_FOR_PARTICIPANTS_STATUS: &str = "Waiting for participants";
const LISTENING_FOR_JOIN_REQUESTS_STATUS: &str = "Listening for join requests";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(any(target_os = "windows", test))]
const WINDOWS_DAEMON_STATE_FRESHNESS_SECS: u64 = 5;
#[cfg(any(target_os = "macos", test))]
const MACOS_SERVICE_LABEL: &str = "to.nostrvpn.nvpn";
#[cfg(target_os = "linux")]
const LINUX_SERVICE_UNIT_NAME: &str = "nvpn.service";
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_NAME: &str = "NvpnService";
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_DISPLAY_NAME: &str = "Nostr VPN";
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_DESCRIPTION: &str = "Nostr VPN background mesh and tunnel service";
#[cfg(target_os = "windows")]
static WINDOWS_SERVICE_DAEMON_ARGS: OnceLock<DaemonArgs> = OnceLock::new();
#[cfg(target_os = "windows")]
define_windows_service!(ffi_windows_service_main, windows_service_main);

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
    /// Show the running CLI version.
    Version(VersionArgs),
    /// Install `nvpn` into a platform-appropriate default PATH location.
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
    /// Repair local network state left behind by a stopped or crashed VPN session.
    RepairNetwork(RepairNetworkArgs),
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
    /// Emit an `nvpn://invite/...` code for the active network.
    CreateInvite(CreateInviteArgs),
    /// Import an `nvpn://invite/...` code into the active network config.
    ImportInvite(ImportInviteArgs),
    /// Add one or more participants to the active network roster.
    AddParticipant(UpdateRosterArgs),
    /// Remove one or more participants from the active network roster.
    RemoveParticipant(UpdateRosterArgs),
    /// Add one or more admins to the active network roster.
    AddAdmin(UpdateRosterArgs),
    /// Remove one or more admins from the active network roster.
    RemoveAdmin(UpdateRosterArgs),
    /// Publish the active admin-signed roster over Nostr immediately.
    PublishRoster(PublishRosterArgs),
    /// Ping a peer by node ID or tunnel IP.
    Ping(PingArgs),
    /// Check relay reachability and latency.
    Netcheck(NetcheckArgs),
    /// Diagnose runtime/network issues and optionally write a support bundle.
    Doctor(DoctorArgs),
    /// Show local or peer tunnel IPs.
    Ip(IpArgs),
    /// Resolve a node/tunnel IP to peer metadata.
    Whois(WhoisArgs),
    /// Internal config import helper for elevated GUI writes.
    #[command(hide = true)]
    ApplyConfig(ApplyConfigArgs),
    /// Internal daemon-backed config import helper for GUI writes.
    #[command(hide = true)]
    ApplyConfigDaemon(ApplyConfigArgs),
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
struct VersionArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct UninstallCliArgs {
    /// Path to remove (defaults to the platform-appropriate install path).
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
    /// Install and start the system service.
    Install(ServiceInstallArgs),
    /// Enable and start an installed system service.
    Enable(ServiceControlArgs),
    /// Stop and disable an installed system service.
    Disable(ServiceControlArgs),
    /// Remove the system service.
    Uninstall(ServiceUninstallArgs),
    /// Show service install/runtime status.
    Status(ServiceStatusArgs),
}

#[derive(Debug, Args)]
struct ServiceInstallArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = default_tunnel_iface())]
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
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
}

#[derive(Debug, Args, Clone)]
struct DaemonArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
    #[arg(long, hide = true, default_value_t = false)]
    service: bool,
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
    #[arg(long, default_value_t = default_tunnel_iface())]
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
struct RepairNetworkArgs {
    #[arg(long)]
    config: Option<PathBuf>,
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
    relay_for_others: Option<bool>,
    #[arg(long)]
    provide_nat_assist: Option<bool>,
    #[arg(long)]
    autoconnect: Option<bool>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateInviteArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ImportInviteArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    invite: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PublishRosterArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct UpdateRosterArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant", required = true)]
    participants: Vec<String>,
    #[arg(long)]
    publish: bool,
    #[arg(long = "relay")]
    relays: Vec<String>,
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
struct DoctorArgs {
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
    #[arg(long)]
    write_bundle: Option<PathBuf>,
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
struct ApplyConfigArgs {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
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

fn main() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();
    run_cli(cli)
}

fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        #[cfg(target_os = "windows")]
        Command::Daemon(args) if args.service => run_windows_service_dispatcher(args),
        command => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?;
            runtime.block_on(run_command(command))
        }
    }
}

async fn run_command(command: Command) -> Result<()> {
    match command {
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
        Command::Version(args) => {
            print_version(args)?;
        }
        Command::InstallCli(args) => {
            install_cli(args)?;
        }
        Command::UninstallCli(args) => {
            uninstall_cli(args)?;
        }
        Command::Service(args) => {
            service_management::run_service_command(args)?;
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
        Command::RepairNetwork(args) => {
            repair_network(args)?;
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

            let client = NostrSignalingClient::from_secret_key_with_networks(
                &app.nostr.secret_key,
                signaling_networks_for_app(&app),
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
                            relay_endpoint: None,
                            relay_pubkey: None,
                            relay_expires_at: None,
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
                let endpoint = status_endpoint(&app, &daemon);
                let listen_port = status_listen_port(&app, &daemon);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status_source": status_source,
                        "network_id": network_id,
                        "magic_dns_suffix": app.magic_dns_suffix,
                        "autoconnect": app.autoconnect,
                        "node_id": app.node.id,
                        "tunnel_ip": app.node.tunnel_ip,
                        "endpoint": endpoint,
                        "configured_endpoint": app.node.endpoint,
                        "listen_port": listen_port,
                        "configured_listen_port": app.node.listen_port,
                        "exit_node": if app.exit_node.is_empty() {
                            None::<String>
                        } else {
                            Some(app.exit_node.clone())
                        },
                        "advertise_exit_node": app.node.advertise_exit_node,
                        "advertised_routes": app.node.advertised_routes,
                        "effective_advertised_routes": runtime_effective_advertised_routes(&app),
                        "relays": relays,
                        "relay_for_others": app.relay_for_others,
                        "provide_nat_assist": app.provide_nat_assist,
                        "daemon": daemon_status_json(&config_path)?,
                        "expected_peer_count": expected_peers,
                        "peer_count": peer_count,
                        "mesh_ready": mesh_ready,
                        "peers": peers,
                    }))?
                );
            } else {
                let endpoint = status_endpoint(&app, &daemon);
                let listen_port = status_listen_port(&app, &daemon);
                println!("network: {network_id}");
                println!("magic_dns_suffix: {}", app.magic_dns_suffix);
                println!("autoconnect: {}", app.autoconnect);
                println!("node: {}", app.node.id);
                println!("tunnel_ip: {}", app.node.tunnel_ip);
                println!("endpoint: {endpoint}");
                println!("listen_port: {listen_port}");
                if endpoint != app.node.endpoint {
                    println!("configured_endpoint: {}", app.node.endpoint);
                }
                if listen_port != app.node.listen_port {
                    println!("configured_listen_port: {}", app.node.listen_port);
                }
                if app.exit_node.is_empty() {
                    println!("exit_node: none");
                } else {
                    println!("exit_node: {}", app.exit_node);
                }
                println!("advertise_exit_node: {}", app.node.advertise_exit_node);
                let effective_routes = runtime_effective_advertised_routes(&app);
                if effective_routes.is_empty() {
                    println!("advertised_routes: none");
                } else {
                    println!("advertised_routes: {}", effective_routes.join(", "));
                }
                println!("relay_for_others: {}", app.relay_for_others);
                println!("provide_nat_assist: {}", app.provide_nat_assist);
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
                app.set_active_network_id(&value)?;
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
            if let Some(value) = args.relay_for_others {
                app.relay_for_others = value;
            }
            if let Some(value) = args.provide_nat_assist {
                app.provide_nat_assist = value;
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
            maybe_reload_running_daemon(&config_path);

            if args.json {
                println!("{}", serde_json::to_string_pretty(&app)?);
            } else {
                println!("saved {}", config_path.display());
                println!("network_id={}", app.effective_network_id());
                println!("node_id={}", app.node.id);
            }
        }
        Command::CreateInvite(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let app = load_or_default_config(&config_path)?;
            let invite = active_network_invite_code(&app)?;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "network_id": app.effective_network_id(),
                        "invite": invite,
                    }))?
                );
            } else {
                println!("{invite}");
            }
        }
        Command::ImportInvite(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;
            let invite = parse_network_invite(&args.invite)?;
            apply_network_invite_to_active_network(&mut app, &invite)?;
            app.ensure_defaults();
            maybe_autoconfigure_node(&mut app);
            app.save(&config_path)?;
            maybe_reload_running_daemon(&config_path);

            if args.json {
                println!("{}", serde_json::to_string_pretty(&app)?);
            } else {
                println!("saved {}", config_path.display());
                println!("network_id={}", app.effective_network_id());
                println!("invite_imported={}", invite.network_name());
            }
        }
        Command::AddParticipant(args) => {
            update_active_network_roster(args, RosterEditAction::AddParticipant).await?;
        }
        Command::RemoveParticipant(args) => {
            update_active_network_roster(args, RosterEditAction::RemoveParticipant).await?;
        }
        Command::AddAdmin(args) => {
            update_active_network_roster(args, RosterEditAction::AddAdmin).await?;
        }
        Command::RemoveAdmin(args) => {
            update_active_network_roster(args, RosterEditAction::RemoveAdmin).await?;
        }
        Command::PublishRoster(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let app = load_or_default_config(&config_path)?;
            let relays = resolve_relays(&args.relay, &app);
            let client = NostrSignalingClient::from_secret_key_with_networks(
                &app.nostr.secret_key,
                signaling_networks_for_app(&app),
            )?;
            client
                .connect(&relays)
                .await
                .context("failed to connect signaling client")?;
            let published = publish_active_network_roster(&client, &app, None).await?;
            client.disconnect().await;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "published_recipients": published,
                        "network_id": app.effective_network_id(),
                        "relays": relays,
                    }))?
                );
            } else {
                println!(
                    "published roster for {} to {} recipient(s)",
                    app.effective_network_id(),
                    published
                );
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
            let report = run_netcheck_report(&app, &network_id, &relays, args.timeout_secs).await;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "udp={} ipv4={} ipv6={} captive_portal={}",
                    report.udp,
                    report.ipv4,
                    report.ipv6,
                    report
                        .captive_portal
                        .map_or("unknown".to_string(), |value| value.to_string())
                );
                if let Some(public_ipv4) = report.public_ipv4.as_deref() {
                    println!("public_ipv4: {public_ipv4}");
                }
                if let Some(preferred_relay) = report.preferred_relay.as_deref() {
                    println!("preferred_relay: {preferred_relay}");
                }
                for check in &report.relay_checks {
                    if let Some(error) = &check.error {
                        println!("relay {}: down ({error})", check.relay);
                    } else {
                        println!("relay {}: up ({} ms)", check.relay, check.latency_ms);
                    }
                }
                let ok = report
                    .relay_checks
                    .iter()
                    .filter(|item| item.error.is_none())
                    .count();
                println!(
                    "summary: {ok}/{} relays reachable, upnp={}, nat_pmp={}, pcp={}",
                    report.relay_checks.len(),
                    format_probe_state(report.port_mapping.upnp.state),
                    format_probe_state(report.port_mapping.nat_pmp.state),
                    format_probe_state(report.port_mapping.pcp.state),
                );
            }
        }
        Command::Doctor(args) => {
            run_doctor(args).await?;
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
        Command::ApplyConfig(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            apply_config_file(&args.source, &config_path)?;
        }
        Command::ApplyConfigDaemon(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            apply_config_via_running_daemon(&args.source, &config_path)?;
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
                app.set_active_network_id(&network_id)?;
            }

            let relays = resolve_relays(&relay, &app);

            let client = NostrSignalingClient::from_secret_key_with_networks(
                &app.nostr.secret_key,
                signaling_networks_for_app(&app),
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

fn runtime_effective_advertised_routes(app: &AppConfig) -> Vec<String> {
    let mut routes = app.effective_advertised_routes();
    #[cfg(target_os = "macos")]
    {
        routes.retain(|route| route != "::/0");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        routes.retain(|route| !is_default_exit_node_route(route));
    }
    routes
}

#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
fn is_default_exit_node_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
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
    #[serde(default)]
    binary_path: String,
    #[serde(default)]
    binary_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionInfoView {
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DaemonRuntimeState {
    updated_at: u64,
    #[serde(default)]
    binary_version: String,
    #[serde(default)]
    local_endpoint: String,
    #[serde(default)]
    advertised_endpoint: String,
    #[serde(default)]
    listen_port: u16,
    session_active: bool,
    relay_connected: bool,
    session_status: String,
    expected_peer_count: usize,
    connected_peer_count: usize,
    mesh_ready: bool,
    #[serde(default)]
    health: Vec<HealthIssue>,
    #[serde(default)]
    network: NetworkSummary,
    #[serde(default)]
    port_mapping: PortMappingStatus,
    #[serde(default)]
    peers: Vec<DaemonPeerState>,
    #[serde(default)]
    relay_operator_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay_operator_pid: Option<u32>,
    #[serde(default)]
    relay_operator_status: String,
    #[serde(default)]
    nat_assist_running: bool,
    #[serde(default)]
    nat_assist_status: String,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct MacosNetworkCleanupState {
    #[serde(default)]
    iface: String,
    #[serde(default)]
    endpoint_bypass_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_default_route: Option<MacosRouteSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv4_forward_was_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pf_was_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonPeerState {
    participant_pubkey: String,
    node_id: String,
    tunnel_ip: String,
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_endpoint: Option<String>,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    rx_bytes: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableFingerprint {
    len: u64,
    modified_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, Default)]
struct LocalRelayOperatorRuntime {
    running: bool,
    pid: Option<u32>,
    status: String,
    nat_assist_running: bool,
    nat_assist_status: String,
}

#[derive(Debug)]
struct LocalRelayOperatorProcess {
    child: Child,
    pid: u32,
    advertise_host: String,
    relays: Vec<String>,
    secret_key: String,
    relay_enabled: bool,
    nat_assist_enabled: bool,
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

struct DaemonReloadConfig {
    app: AppConfig,
    network_id: String,
    configured_participants: Vec<String>,
    expected_peers: usize,
    own_pubkey: Option<String>,
    relays: Vec<String>,
}

fn load_config_with_overrides(
    path: &Path,
    network_id: Option<String>,
    participants: Vec<String>,
) -> Result<(AppConfig, String)> {
    let mut app = load_or_default_config(path)?;
    apply_participants_override(&mut app, participants)?;
    if let Some(network_id) = network_id {
        app.set_active_network_id(&network_id)?;
    }
    maybe_autoconfigure_node(&mut app);

    let network_id = app.effective_network_id();
    Ok((app, network_id))
}

fn signaling_networks_for_app(app: &AppConfig) -> Vec<SignalingNetwork> {
    let networks = app
        .enabled_network_meshes()
        .into_iter()
        .map(|network| SignalingNetwork {
            network_id: network.network_id,
            participants: app
                .network_signal_pubkeys_hex(&network.id)
                .unwrap_or(network.participants),
        })
        .collect::<Vec<_>>();

    if networks.is_empty() {
        return vec![SignalingNetwork {
            network_id: app.effective_network_id(),
            participants: app.active_network_signal_pubkeys_hex(),
        }];
    }

    networks
}

fn build_daemon_reload_config(
    app: AppConfig,
    network_id: String,
    relay_args: &[String],
) -> DaemonReloadConfig {
    let configured_participants = app.participant_pubkeys_hex();
    let expected_peers = expected_peer_count(&app);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let relays = resolve_relays(relay_args, &app);

    DaemonReloadConfig {
        app,
        network_id,
        configured_participants,
        expected_peers,
        own_pubkey,
        relays,
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRelaySession {
    relay_pubkey: String,
    local_ingress_endpoint: String,
    advertised_ingress_endpoint: String,
    granted_at: u64,
    verified_at: Option<u64>,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct PendingRelayRequest {
    participant: String,
    relay_pubkey: String,
    requested_at: u64,
}

#[derive(Debug, Clone, Default)]
struct OutboundAnnounceBook {
    fingerprints: HashMap<String, String>,
}

type RelayFailureCooldowns = HashMap<String, u64>;
type RelayProviderVerificationBook = HashMap<String, RelayProviderVerification>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayGrantAction {
    Activated(String),
    QueuedStandby(String),
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayProviderProbeOutcome {
    Verified,
    Rejected(Option<u64>),
    Failed,
}

#[derive(Debug, Clone, Default)]
struct RelayProviderVerification {
    verified_at: Option<u64>,
    failure_cooldown_until: Option<u64>,
    last_failure_at: Option<u64>,
    last_probe_attempt_at: Option<u64>,
    consecutive_failures: u32,
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

fn effective_peer_announcement_for_runtime(
    announcement: &PeerAnnouncement,
    relay_session: Option<&ActiveRelaySession>,
    now: u64,
) -> PeerAnnouncement {
    let announcement = announcement.without_expired_relay(now);
    if let Some(session) = relay_session.filter(|session| relay_session_is_active(session, now)) {
        announcement.with_relay(
            Some(session.local_ingress_endpoint.clone()),
            Some(session.relay_pubkey.clone()),
            Some(session.expires_at),
        )
    } else {
        announcement
    }
}

fn effective_peer_announcements_for_runtime(
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    now: u64,
) -> HashMap<String, PeerAnnouncement> {
    peer_announcements
        .iter()
        .map(|(participant, announcement)| {
            (
                participant.clone(),
                effective_peer_announcement_for_runtime(
                    announcement,
                    relay_sessions.get(participant),
                    now,
                ),
            )
        })
        .collect()
}

fn participant_has_pending_relay_request(
    pending_requests: &HashMap<String, PendingRelayRequest>,
    participant: &str,
    now: u64,
) -> bool {
    pending_requests.values().any(|request| {
        request.participant == participant
            && now.saturating_sub(request.requested_at) < RELAY_REQUEST_RETRY_AFTER_SECS
    })
}

fn participants_needing_relay(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    pending_requests: &HashMap<String, PendingRelayRequest>,
    now: u64,
) -> Vec<String> {
    let runtime_peers = tunnel_runtime.peer_status().ok();
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter(|participant| presence.announcement_for(participant).is_some())
        .filter(|participant| {
            relay_sessions
                .get(participant)
                .is_none_or(|session| !relay_session_is_active(session, now))
        })
        .filter(|participant| {
            !participant_has_pending_relay_request(pending_requests, participant, now)
        })
        .filter(|participant| {
            let Some(announcement) = presence.announcement_for(participant) else {
                return false;
            };
            let runtime_peer = peer_runtime_lookup(announcement, runtime_peers.as_ref());
            !runtime_peer.is_some_and(peer_has_recent_handshake)
        })
        .collect()
}

async fn probe_relay_provider_datapath(
    requester_ingress_endpoint: &str,
    target_ingress_endpoint: &str,
) -> Result<()> {
    let requester_ingress = requester_ingress_endpoint
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid requester ingress {requester_ingress_endpoint}"))?;
    let target_ingress = target_ingress_endpoint
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid target ingress {target_ingress_endpoint}"))?;
    let requester_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .context("failed to bind requester probe socket")?;
    let target_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .context("failed to bind target probe socket")?;
    let nonce_b_to_a = format!("nvpn-relay-probe-b-to-a:{requester_ingress}:{target_ingress}");
    let nonce_a_to_b = format!("nvpn-relay-probe-a-to-b:{target_ingress}:{requester_ingress}");
    let mut buf = [0_u8; 512];

    requester_socket
        .send_to(b"nvpn-relay-probe-bind", requester_ingress)
        .await
        .context("failed to bind requester probe leg")?;
    target_socket
        .send_to(nonce_b_to_a.as_bytes(), target_ingress)
        .await
        .context("failed to send target-side relay probe")?;
    let (read, src) = tokio::time::timeout(
        Duration::from_millis(750),
        requester_socket.recv_from(&mut buf),
    )
    .await
    .context("timed out waiting for requester-side relay probe")?
    .context("failed to receive requester-side relay probe")?;
    if src != requester_ingress || &buf[..read] != nonce_b_to_a.as_bytes() {
        return Err(anyhow!(
            "requester-side relay probe did not loop through the expected ingress"
        ));
    }

    requester_socket
        .send_to(nonce_a_to_b.as_bytes(), requester_ingress)
        .await
        .context("failed to send requester-side relay probe")?;
    let (read, src) = tokio::time::timeout(
        Duration::from_millis(750),
        target_socket.recv_from(&mut buf),
    )
    .await
    .context("timed out waiting for target-side relay probe")?
    .context("failed to receive target-side relay probe")?;
    if src != target_ingress || &buf[..read] != nonce_a_to_b.as_bytes() {
        return Err(anyhow!(
            "target-side relay probe did not loop through the expected ingress"
        ));
    }

    Ok(())
}

async fn probe_relay_provider(
    relays: &[String],
    secret_key: &str,
    relay_pubkey: &str,
    now: u64,
) -> Result<RelayProviderProbeOutcome> {
    let probe_client = RelayServiceClient::from_secret_key(secret_key)?;
    probe_client.connect(relays).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let request_id = format!("probe:{relay_pubkey}:{now}");
    let request = RelayProbeRequest {
        request_id: request_id.clone(),
        requested_at: now,
    };
    let publish_result = probe_client
        .publish_to(ServicePayload::RelayProbeRequest(request), relay_pubkey)
        .await;
    if let Err(error) = publish_result {
        probe_client.disconnect().await;
        return Err(error);
    }

    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(RELAY_PROVIDER_PROBE_TIMEOUT_SECS);
    let outcome = loop {
        let wait_for = deadline.saturating_duration_since(tokio::time::Instant::now());
        if wait_for.is_zero() {
            break RelayProviderProbeOutcome::Failed;
        }
        let Some(message) = tokio::time::timeout(wait_for, probe_client.recv())
            .await
            .ok()
            .flatten()
        else {
            break RelayProviderProbeOutcome::Failed;
        };
        match message.payload {
            ServicePayload::RelayProbeGranted(granted)
                if granted.request_id == request_id && granted.relay_pubkey == relay_pubkey =>
            {
                let probe = probe_relay_provider_datapath(
                    &granted.requester_ingress_endpoint,
                    &granted.target_ingress_endpoint,
                )
                .await;
                break if probe.is_ok() {
                    RelayProviderProbeOutcome::Verified
                } else {
                    RelayProviderProbeOutcome::Failed
                };
            }
            ServicePayload::RelayProbeRejected(rejected)
                if rejected.request_id == request_id && rejected.relay_pubkey == relay_pubkey =>
            {
                break RelayProviderProbeOutcome::Rejected(rejected.retry_after_secs);
            }
            _ => continue,
        }
    };

    probe_client.disconnect().await;
    Ok(outcome)
}

async fn proactively_probe_relay_providers(
    relays: &[String],
    secret_key: &str,
    relay_pubkeys: &[String],
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    now: u64,
) -> Result<usize> {
    let candidates = relay_pubkeys
        .iter()
        .map(String::as_str)
        .filter(|relay_pubkey| {
            relay_provider_probe_due(relay_provider_verifications, relay_pubkey, now)
        })
        .take(MAX_PARALLEL_RELAY_PROVIDER_PROBES)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut probed = 0usize;

    for relay_pubkey in candidates {
        note_relay_provider_probe_attempt(relay_provider_verifications, &relay_pubkey, now);
        match probe_relay_provider(relays, secret_key, &relay_pubkey, now).await {
            Ok(RelayProviderProbeOutcome::Verified) => {
                eprintln!("relay: proactive probe verified {relay_pubkey}");
                note_verified_relay_provider(relay_provider_verifications, &relay_pubkey, now);
                probed = probed.saturating_add(1);
            }
            Ok(RelayProviderProbeOutcome::Rejected(retry_after_secs)) => {
                eprintln!("relay: proactive probe rejected by {relay_pubkey}");
                note_failed_relay_provider(
                    relay_provider_verifications,
                    &relay_pubkey,
                    now,
                    retry_after_secs,
                );
                probed = probed.saturating_add(1);
            }
            Ok(RelayProviderProbeOutcome::Failed) => {
                eprintln!("relay: proactive probe failed for {relay_pubkey}");
                note_failed_relay_provider(
                    relay_provider_verifications,
                    &relay_pubkey,
                    now,
                    Some(RELAY_PROVIDER_PROBE_RETRY_AFTER_SECS),
                );
                probed = probed.saturating_add(1);
            }
            Err(error) => {
                eprintln!("relay: proactive probe failed for {relay_pubkey}: {error}");
                note_failed_relay_provider(
                    relay_provider_verifications,
                    &relay_pubkey,
                    now,
                    Some(RELAY_PROVIDER_PROBE_RETRY_AFTER_SECS),
                );
                probed = probed.saturating_add(1);
            }
        }
    }

    Ok(probed)
}

async fn discover_relay_operator_pubkeys(
    relays: &[String],
    relay_provider_verifications: &RelayProviderVerificationBook,
    now: u64,
) -> Result<Vec<String>> {
    let mut candidates = discover_node_records(
        relays,
        NODE_RECORD_RELAY_TAG,
        Duration::from_secs(RELAY_DISCOVERY_LOOKBACK_SECS),
    )
    .await?
    .into_iter()
    .filter_map(|(pubkey, record)| record.has_service(NodeServiceKind::Relay).then_some(pubkey))
    .filter(|pubkey| !relay_provider_in_failure_cooldown(relay_provider_verifications, pubkey, now))
    .collect::<Vec<_>>();
    candidates
        .sort_by_key(|pubkey| relay_provider_sort_key(relay_provider_verifications, pubkey, now));
    candidates.dedup();
    Ok(candidates)
}

fn relay_candidates_for_participant<'a>(
    relay_pubkeys: &'a [String],
    participant: &str,
    own_pubkey: Option<&str>,
    relay_failures: &RelayFailureCooldowns,
    relay_provider_verifications: &RelayProviderVerificationBook,
    now: u64,
) -> Vec<&'a str> {
    let mut candidates = relay_pubkeys
        .iter()
        .map(String::as_str)
        .filter(|candidate| *candidate != participant && Some(*candidate) != own_pubkey)
        .filter(|candidate| {
            !relay_is_in_failure_cooldown(relay_failures, participant, candidate, now)
        })
        .filter(|candidate| {
            !relay_provider_in_failure_cooldown(relay_provider_verifications, candidate, now)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| {
        relay_provider_sort_key(relay_provider_verifications, candidate, now)
    });
    candidates.truncate(MAX_PARALLEL_RELAY_REQUESTS_PER_PARTICIPANT);
    candidates
}

#[allow(clippy::too_many_arguments)]
async fn maybe_request_public_relay_fallback(
    service_client: &RelayServiceClient,
    relays: &[String],
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    relay_failures: &RelayFailureCooldowns,
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    pending_requests: &mut HashMap<String, PendingRelayRequest>,
    now: u64,
) -> Result<usize> {
    let participants = participants_needing_relay(
        app,
        own_pubkey,
        presence,
        tunnel_runtime,
        relay_sessions,
        pending_requests,
        now,
    );
    if participants.is_empty() {
        return Ok(0);
    }

    let mut relay_pubkeys =
        discover_relay_operator_pubkeys(relays, relay_provider_verifications, now).await?;
    if relay_pubkeys.is_empty() {
        return Ok(0);
    }
    let _ = proactively_probe_relay_providers(
        relays,
        &app.nostr.secret_key,
        &relay_pubkeys,
        relay_provider_verifications,
        now,
    )
    .await?;
    relay_pubkeys.retain(|pubkey| {
        !relay_provider_in_failure_cooldown(relay_provider_verifications, pubkey, now)
    });
    relay_pubkeys
        .sort_by_key(|pubkey| relay_provider_sort_key(relay_provider_verifications, pubkey, now));
    relay_pubkeys.dedup();
    if relay_pubkeys.is_empty() {
        return Ok(0);
    }

    let mut requested = 0usize;
    for participant in participants {
        let relay_candidates = relay_candidates_for_participant(
            &relay_pubkeys,
            &participant,
            own_pubkey,
            relay_failures,
            relay_provider_verifications,
            now,
        );
        if relay_candidates.is_empty() {
            continue;
        }

        for relay_pubkey in relay_candidates {
            let request_id = format!(
                "{}:{}:{}:{}",
                app.effective_network_id(),
                participant,
                relay_pubkey,
                now
            );
            let request = RelayAllocationRequest {
                request_id: request_id.clone(),
                network_id: app.effective_network_id(),
                target_pubkey: participant.clone(),
                requested_at: now,
            };
            service_client
                .publish_to(
                    ServicePayload::RelayAllocationRequest(request),
                    relay_pubkey,
                )
                .await
                .with_context(|| {
                    format!("failed to request relay allocation from {relay_pubkey}")
                })?;
            pending_requests.insert(
                request_id,
                PendingRelayRequest {
                    participant: participant.clone(),
                    relay_pubkey: relay_pubkey.to_string(),
                    requested_at: now,
                },
            );
            requested += 1;
        }
    }

    Ok(requested)
}

fn accept_relay_allocation_grant(
    granted: RelayAllocationGranted,
    pending_requests: &mut HashMap<String, PendingRelayRequest>,
    relay_sessions: &mut HashMap<String, ActiveRelaySession>,
    standby_relay_sessions: &mut HashMap<String, Vec<ActiveRelaySession>>,
    relay_failures: &RelayFailureCooldowns,
    now: u64,
) -> RelayGrantAction {
    if granted.expires_at <= now {
        return RelayGrantAction::Ignored;
    }
    let Some(pending) = pending_requests.remove(&granted.request_id) else {
        return RelayGrantAction::Ignored;
    };
    if pending.relay_pubkey != granted.relay_pubkey {
        return RelayGrantAction::Ignored;
    }
    let participant = pending.participant.clone();
    if relay_is_in_failure_cooldown(relay_failures, &participant, &pending.relay_pubkey, now) {
        return RelayGrantAction::Ignored;
    }

    let session = active_relay_session_from_grant(granted, now);
    if relay_sessions
        .get(&participant)
        .is_some_and(|existing| relay_session_is_active(existing, now))
    {
        if queue_standby_relay_session(standby_relay_sessions, &participant, session) {
            RelayGrantAction::QueuedStandby(participant)
        } else {
            RelayGrantAction::Ignored
        }
    } else {
        relay_sessions.insert(participant.clone(), session);
        RelayGrantAction::Activated(participant)
    }
}

fn accept_relay_allocation_rejection(
    rejected: RelayAllocationRejected,
    pending_requests: &mut HashMap<String, PendingRelayRequest>,
    relay_failures: &mut RelayFailureCooldowns,
    relay_provider_verifications: &mut RelayProviderVerificationBook,
    now: u64,
) -> Option<String> {
    let pending = pending_requests.remove(&rejected.request_id)?;
    if pending.relay_pubkey != rejected.relay_pubkey {
        return None;
    }
    note_failed_relay(
        relay_failures,
        &pending.participant,
        &pending.relay_pubkey,
        now,
    );
    note_failed_relay_provider(
        relay_provider_verifications,
        &pending.relay_pubkey,
        now,
        rejected.retry_after_secs,
    );
    Some(pending.participant)
}

fn maybe_reset_targeted_announce_cache_for_hello(
    outbound_announces: &mut OutboundAnnounceBook,
    sender_pubkey: &str,
    payload: &SignalPayload,
) {
    if matches!(payload, SignalPayload::Hello) {
        outbound_announces.forget(sender_pubkey);
    }
}

#[derive(Debug, Clone, Default)]
struct WireGuardPeerStatus {
    endpoint: Option<String>,
    last_handshake_sec: Option<u64>,
    last_handshake_nsec: Option<u64>,
    tx_bytes: u64,
    rx_bytes: u64,
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

#[cfg(target_os = "windows")]
const MAGIC_DNS_PORT: u16 = 53;
#[cfg(not(target_os = "windows"))]
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
    #[cfg(target_os = "windows")]
    windows_runtime: Option<WindowsTunnelBackend>,
    last_fingerprint: Option<String>,
    active_listen_port: Option<u16>,
    #[cfg(target_os = "linux")]
    endpoint_bypass_routes: Vec<String>,
    #[cfg(target_os = "linux")]
    exit_node_runtime: LinuxExitNodeRuntime,
    #[cfg(target_os = "linux")]
    original_default_route: Option<String>,
    #[cfg(target_os = "macos")]
    endpoint_bypass_routes: Vec<String>,
    #[cfg(target_os = "macos")]
    exit_node_runtime: MacosExitNodeRuntime,
    #[cfg(target_os = "macos")]
    original_default_route: Option<MacosRouteSpec>,
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

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct MacosRouteSpec {
    gateway: Option<String>,
    interface: String,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Default)]
struct MacosExitNodeRuntime {
    outbound_iface: Option<String>,
    ipv4_forward_was_enabled: Option<bool>,
    pf_was_enabled: Option<bool>,
}

impl CliTunnelRuntime {
    fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            handle: None,
            uapi_socket_path: None,
            #[cfg(target_os = "windows")]
            windows_runtime: None,
            last_fingerprint: None,
            active_listen_port: None,
            #[cfg(target_os = "linux")]
            endpoint_bypass_routes: Vec::new(),
            #[cfg(target_os = "linux")]
            exit_node_runtime: LinuxExitNodeRuntime::default(),
            #[cfg(target_os = "linux")]
            original_default_route: None,
            #[cfg(target_os = "macos")]
            endpoint_bypass_routes: Vec::new(),
            #[cfg(target_os = "macos")]
            exit_node_runtime: MacosExitNodeRuntime::default(),
            #[cfg(target_os = "macos")]
            original_default_route: None,
        }
    }

    #[cfg(any(test, not(target_os = "windows")))]
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
        let own_local_endpoints = runtime_local_signal_endpoints(app, listen_port);
        let runtime_peers = self.peer_status().ok();
        record_successful_runtime_paths(
            peer_announcements,
            runtime_peers.as_ref(),
            path_book,
            &own_local_endpoints,
            now,
        );
        let planned_peers = planned_tunnel_peers_for_local_endpoints(
            app,
            own_pubkey,
            peer_announcements,
            path_book,
            &own_local_endpoints,
            now,
        )?;
        #[cfg(target_os = "macos")]
        if !planned_peers.is_empty() {
            let summary = planned_peers
                .iter()
                .map(|planned| {
                    format!(
                        "{} endpoint={} allowed_ips=[{}]",
                        planned.participant,
                        planned.endpoint,
                        planned.peer.allowed_ips.join(", ")
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ");
            eprintln!("tunnel: planned macOS peers {summary}");
        }
        let peers = planned_peers
            .iter()
            .map(|planned| planned.peer.clone())
            .collect::<Vec<_>>();
        if peers.is_empty() {
            self.stop();
            return Ok(());
        }

        let local_address = local_interface_address_for_tunnel(&app.node.tunnel_ip);
        let fingerprint = tunnel_fingerprint(
            &self.iface,
            &app.node.private_key,
            listen_port,
            &local_address,
            &peers,
        );
        let needs_endpoint_refresh = runtime_peer_endpoints_require_refresh(
            &planned_peers,
            peer_announcements,
            runtime_peers.as_ref(),
            &own_local_endpoints,
        );
        if self.last_fingerprint.as_deref() == Some(fingerprint.as_str())
            && self.is_running()
            && !needs_endpoint_refresh
        {
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            self.apply_windows_runtime(app, &local_address, &peers)?;
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
            return Ok(());
        }

        #[cfg(not(target_os = "windows"))]
        {
            let route_targets = route_targets_for_planned_tunnel_peers(
                app,
                own_pubkey,
                peer_announcements,
                &planned_peers,
            );
            #[cfg(target_os = "macos")]
            eprintln!(
                "tunnel: planned macOS route targets [{}]",
                route_targets.join(", ")
            );
            #[cfg(target_os = "linux")]
            if route_targets.iter().any(|route| route == "0.0.0.0/0") {
                self.capture_linux_original_default_route();
            } else {
                self.restore_linux_original_default_route();
            }
            #[cfg(target_os = "macos")]
            if route_targets.iter().any(|route| route == "0.0.0.0/0") {
                self.capture_macos_original_default_route();
            } else {
                self.restore_macos_original_default_route();
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
            #[cfg(target_os = "macos")]
            let endpoint_bypass_specs = if route_targets_require_endpoint_bypass(&route_targets) {
                macos_bypass_route_specs(
                    app,
                    &peers,
                    &self.iface,
                    self.original_default_route.as_ref(),
                )?
            } else {
                Vec::new()
            };

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

            #[cfg(target_os = "linux")]
            apply_local_interface_network(&self.iface, &local_address, &route_targets)?;
            #[cfg(target_os = "linux")]
            self.reconcile_linux_endpoint_bypass_routes(&endpoint_bypass_specs);
            #[cfg(target_os = "macos")]
            {
                self.reconcile_macos_endpoint_bypass_routes(&endpoint_bypass_specs);
                apply_local_interface_network(&self.iface, &local_address, &route_targets)?;
            }
            #[cfg(target_os = "linux")]
            if let Err(error) = flush_linux_route_cache() {
                eprintln!("tunnel: failed to flush linux route cache: {error}");
            }
            #[cfg(target_os = "linux")]
            self.reconcile_linux_exit_node_forwarding(app);
            #[cfg(target_os = "macos")]
            self.reconcile_macos_exit_node_forwarding(app);

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
    }

    fn peer_status(&self) -> Result<HashMap<String, WireGuardPeerStatus>> {
        #[cfg(target_os = "windows")]
        {
            self.windows_runtime
                .as_ref()
                .ok_or_else(|| anyhow!("missing windows tunnel runtime"))?
                .peer_status()
        }

        #[cfg(not(target_os = "windows"))]
        {
            let socket = self
                .uapi_socket_path
                .as_deref()
                .ok_or_else(|| anyhow!("missing uapi socket path"))?;
            let response = wg_get(socket)?;
            Ok(parse_wg_peer_status(&response))
        }
    }

    fn stop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.reconcile_linux_endpoint_bypass_routes(&[]);
            self.reconcile_linux_exit_node_forwarding_cleanup();
            self.restore_linux_original_default_route();
            if let Err(error) = flush_linux_route_cache() {
                eprintln!("tunnel: failed to flush linux route cache: {error}");
            }
        }
        #[cfg(target_os = "macos")]
        {
            self.reconcile_macos_endpoint_bypass_routes(&[]);
            self.reconcile_macos_exit_node_forwarding_cleanup();
            self.restore_macos_original_default_route();
        }
        self.handle = None;
        self.uapi_socket_path = None;
        #[cfg(target_os = "windows")]
        {
            if let Some(runtime) = self.windows_runtime.as_mut() {
                runtime.stop();
            }
            self.windows_runtime = None;
        }
        self.last_fingerprint = None;
        self.active_listen_port = None;
    }

    #[cfg(target_os = "macos")]
    fn macos_network_cleanup_state(&self) -> Option<MacosNetworkCleanupState> {
        let has_exit_node_state = self.exit_node_runtime.ipv4_forward_was_enabled.is_some()
            || self.exit_node_runtime.pf_was_enabled.is_some();
        if self.original_default_route.is_none()
            && self.endpoint_bypass_routes.is_empty()
            && !has_exit_node_state
        {
            return None;
        }

        Some(MacosNetworkCleanupState {
            iface: self.iface.clone(),
            endpoint_bypass_routes: self.endpoint_bypass_routes.clone(),
            original_default_route: self.original_default_route.clone(),
            ipv4_forward_was_enabled: self.exit_node_runtime.ipv4_forward_was_enabled,
            pf_was_enabled: self.exit_node_runtime.pf_was_enabled,
        })
    }

    fn listen_port(&self, configured: u16) -> u16 {
        self.active_listen_port.unwrap_or(configured)
    }

    fn is_running(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            self.windows_runtime.is_some()
        }

        #[cfg(not(target_os = "windows"))]
        {
            self.handle.is_some()
        }
    }

    #[cfg(target_os = "windows")]
    fn apply_windows_runtime(
        &mut self,
        app: &AppConfig,
        local_address: &str,
        peers: &[TunnelPeer],
    ) -> Result<()> {
        let primary_listen_port = self.active_listen_port.unwrap_or(app.node.listen_port);
        let mut candidate_ports = Vec::with_capacity(16);
        for _ in 0..16 {
            if let Ok(fallback_port) = pick_available_udp_port() {
                candidate_ports.push(fallback_port);
            }
        }

        self.stop();

        let mut selected = None;
        let mut last_bind_conflict = None;
        for attempt in 0..PRIMARY_LISTEN_PORT_RETRY_ATTEMPTS {
            match WindowsTunnelBackend::start(
                &self.iface,
                &app.node.private_key,
                primary_listen_port,
                local_address,
                peers,
            ) {
                Ok(runtime) => {
                    selected = Some((primary_listen_port, runtime));
                    break;
                }
                Err(error) if is_resource_busy_message(&error.to_string()) => {
                    last_bind_conflict = Some(error);
                    if attempt + 1 < PRIMARY_LISTEN_PORT_RETRY_ATTEMPTS {
                        thread::sleep(Duration::from_millis(PRIMARY_LISTEN_PORT_RETRY_DELAY_MS));
                    }
                }
                Err(error) => return Err(error),
            }
        }

        if selected.is_none() {
            let mut attempted_ports = HashSet::new();
            attempted_ports.insert(primary_listen_port);
            for listen_port in candidate_ports {
                if !attempted_ports.insert(listen_port) {
                    continue;
                }
                match WindowsTunnelBackend::start(
                    &self.iface,
                    &app.node.private_key,
                    listen_port,
                    local_address,
                    peers,
                ) {
                    Ok(runtime) => {
                        eprintln!(
                            "tunnel: listen_port {} busy, using fallback {}",
                            primary_listen_port, listen_port
                        );
                        selected = Some((listen_port, runtime));
                        break;
                    }
                    Err(error) if is_resource_busy_message(&error.to_string()) => {
                        last_bind_conflict = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let (listen_port, runtime) = selected.ok_or_else(|| {
            if let Some(error) = last_bind_conflict {
                error.context("failed to allocate available Windows WireGuard listen port")
            } else {
                anyhow!("failed to configure Windows WireGuard runtime")
            }
        })?;

        self.windows_runtime = Some(runtime);
        self.active_listen_port = Some(listen_port);
        Ok(())
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

    #[cfg(target_os = "macos")]
    fn capture_macos_original_default_route(&mut self) {
        if self.original_default_route.is_some() {
            return;
        }

        match macos_default_route() {
            Ok(route) if route.interface != self.iface => {
                self.original_default_route = Some(route);
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("exit-node: failed to snapshot macOS default route: {error}");
            }
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

    #[cfg(target_os = "macos")]
    fn restore_macos_original_default_route(&mut self) {
        let Some(route) = self.original_default_route.as_ref() else {
            return;
        };
        if route.interface != self.iface {
            let _ = delete_macos_default_route_for_interface(&self.iface);
        }
        if let Err(error) = restore_macos_default_route(route) {
            eprintln!("exit-node: failed to restore macOS default route: {error}");
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

    #[cfg(target_os = "macos")]
    fn reconcile_macos_endpoint_bypass_routes(&mut self, routes: &[MacosEndpointBypassRoute]) {
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
            if let Err(error) = delete_macos_endpoint_bypass_route(&route) {
                eprintln!("tunnel: failed to remove macOS endpoint bypass route {route}: {error}");
            }
        }

        for route in routes {
            if let Err(error) = apply_macos_endpoint_bypass_route(route) {
                eprintln!(
                    "tunnel: failed to install macOS endpoint bypass route {}: {}",
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

    #[cfg(target_os = "macos")]
    fn reconcile_macos_exit_node_forwarding(&mut self, app: &AppConfig) {
        let route_families =
            linux_exit_node_default_route_families(&runtime_effective_advertised_routes(app));
        if !route_families.ipv4 {
            self.reconcile_macos_exit_node_forwarding_cleanup();
            return;
        }

        let outbound_iface = match macos_default_route() {
            Ok(route) if route.interface != self.iface => route.interface,
            Ok(_) => {
                eprintln!("exit-node: invalid macOS outbound route on {}", self.iface);
                self.reconcile_macos_exit_node_forwarding_cleanup();
                return;
            }
            Err(error) => {
                eprintln!("exit-node: failed to resolve macOS default route device: {error}");
                self.reconcile_macos_exit_node_forwarding_cleanup();
                return;
            }
        };

        if self.exit_node_runtime.outbound_iface.as_deref() == Some(outbound_iface.as_str()) {
            return;
        }

        self.reconcile_macos_exit_node_forwarding_cleanup();
        if let Err(error) = ensure_macos_ip_forwarding(true, &mut self.exit_node_runtime) {
            eprintln!("exit-node: failed to enable macOS IPv4 forwarding: {error}");
            self.reconcile_macos_exit_node_forwarding_cleanup();
            return;
        }

        if let Err(error) = ensure_macos_pf_nat(&outbound_iface, &mut self.exit_node_runtime) {
            eprintln!("exit-node: failed to configure macOS PF NAT: {error}");
            self.reconcile_macos_exit_node_forwarding_cleanup();
            return;
        }

        self.exit_node_runtime.outbound_iface = Some(outbound_iface);
    }

    #[cfg(target_os = "macos")]
    fn reconcile_macos_exit_node_forwarding_cleanup(&mut self) {
        if let Err(error) = cleanup_macos_pf_nat() {
            eprintln!("exit-node: failed to remove macOS PF NAT rules: {error}");
        }
        if self.exit_node_runtime.pf_was_enabled == Some(false)
            && let Err(error) = run_checked(ProcessCommand::new("pfctl").arg("-d"))
        {
            eprintln!("exit-node: failed to restore macOS PF state: {error}");
        }
        if let Some(previous) = self.exit_node_runtime.ipv4_forward_was_enabled.take()
            && let Err(error) = write_macos_ip_forward(previous)
        {
            eprintln!("exit-node: failed to restore macOS IPv4 forwarding: {error}");
        }
        self.exit_node_runtime.outbound_iface = None;
        self.exit_node_runtime.pf_was_enabled = None;
    }
}

#[cfg(any(test, not(target_os = "windows")))]
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

#[cfg(any(test, not(target_os = "windows")))]
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

#[cfg(any(test, not(target_os = "windows")))]
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
        Ok(IpAddr::V4(ip)) => ipv4_is_local_only(ip),
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

fn runtime_signal_ipv4(detected_ipv4: Option<Ipv4Addr>, tunnel_ip: &str) -> Option<Ipv4Addr> {
    let tunnel_ipv4 = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok();
    detected_ipv4.filter(|ip| Some(*ip) != tunnel_ipv4)
}

fn local_signal_endpoint(app: &AppConfig, listen_port: u16) -> String {
    runtime_local_signal_endpoint(
        &app.node.endpoint,
        listen_port,
        runtime_signal_ipv4(detect_runtime_primary_ipv4(), &app.node.tunnel_ip),
    )
}

fn runtime_local_signal_endpoints(app: &AppConfig, listen_port: u16) -> Vec<String> {
    let primary_endpoint = local_signal_endpoint(app, listen_port);
    let mut endpoints = Vec::new();
    let mut seen = HashSet::new();

    if seen.insert(primary_endpoint.clone()) {
        endpoints.push(primary_endpoint);
    }

    for interface in get_interfaces() {
        if !interface.is_up() || interface.is_loopback() || interface.is_tun() {
            continue;
        }

        for ip in interface.ipv4_addrs() {
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }

            let endpoint = SocketAddrV4::new(ip, listen_port).to_string();
            if seen.insert(endpoint.clone()) {
                endpoints.push(endpoint);
            }
        }
    }

    endpoints
}

fn discover_public_signal_endpoint(
    app: &AppConfig,
    listen_port: u16,
    existing_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
) -> Option<String> {
    if !app.nat.enabled {
        return None;
    }

    let timeout = Duration::from_secs(app.nat.discovery_timeout_secs.max(1));
    let mut saw_invalid_reflector_response = false;

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
                if existing_endpoint.is_some()
                    && error.to_string().starts_with("invalid discovery response:")
                {
                    saw_invalid_reflector_response = true;
                }
                eprintln!("nat: reflector discovery failed via {reflector}: {error}");
            }
        }
    }

    if existing_endpoint.is_some() && saw_invalid_reflector_response {
        return None;
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

#[derive(Debug, Clone, Default)]
struct RelayAnnouncementDetails {
    relay_endpoint: Option<String>,
    relay_pubkey: Option<String>,
    relay_expires_at: Option<u64>,
}

fn refresh_public_signal_endpoint(
    app: &AppConfig,
    listen_port: u16,
    public_signal_endpoint: &mut Option<DiscoveredPublicSignalEndpoint>,
) {
    let previous = public_signal_endpoint.clone();
    *public_signal_endpoint = discover_public_signal_endpoint(app, listen_port, previous.as_ref())
        .map(|endpoint| DiscoveredPublicSignalEndpoint {
            listen_port,
            endpoint,
        })
        .or_else(|| previous.filter(|endpoint| endpoint.listen_port == listen_port));
}

fn sync_public_signal_endpoint_from_mapping_or_stun(
    app: &AppConfig,
    listen_port: u16,
    port_mapping_runtime: &PortMappingRuntime,
    public_signal_endpoint: &mut Option<DiscoveredPublicSignalEndpoint>,
) {
    if !app.nat.enabled {
        *public_signal_endpoint = None;
        return;
    }

    if let Some(endpoint) = port_mapping_runtime
        .advertised_endpoint()
        .and_then(|endpoint| public_signal_endpoint_from_mapping(listen_port, endpoint))
    {
        *public_signal_endpoint = Some(endpoint);
        return;
    }

    refresh_public_signal_endpoint(app, listen_port, public_signal_endpoint);
}

fn public_signal_endpoint_from_mapping(
    listen_port: u16,
    endpoint: String,
) -> Option<DiscoveredPublicSignalEndpoint> {
    if endpoint_is_local_only(&endpoint) {
        return None;
    }

    Some(DiscoveredPublicSignalEndpoint {
        listen_port,
        endpoint,
    })
}

async fn refresh_public_signal_endpoint_with_port_mapping(
    app: &AppConfig,
    network_snapshot: &diagnostics::NetworkSnapshot,
    listen_port: u16,
    port_mapping_runtime: &mut PortMappingRuntime,
    public_signal_endpoint: &mut Option<DiscoveredPublicSignalEndpoint>,
) {
    if !app.nat.enabled {
        port_mapping_runtime.stop().await;
        *public_signal_endpoint = None;
        return;
    }

    let timeout = Duration::from_secs(app.nat.discovery_timeout_secs.max(1));
    if let Err(error) = port_mapping_runtime
        .refresh(network_snapshot, listen_port, timeout)
        .await
    {
        eprintln!("nat: port mapping refresh failed: {error}");
    }

    sync_public_signal_endpoint_from_mapping_or_stun(
        app,
        listen_port,
        port_mapping_runtime,
        public_signal_endpoint,
    );
}

fn network_probe_timeout(app: &AppConfig) -> Duration {
    Duration::from_secs(app.nat.discovery_timeout_secs.max(2))
}

fn build_explicit_peer_announcement(
    node_id: String,
    public_key: String,
    endpoint: String,
    local_endpoint: String,
    tunnel_ip: String,
    advertised_routes: Vec<String>,
) -> PeerAnnouncement {
    build_explicit_peer_announcement_with_relay(
        node_id,
        public_key,
        endpoint,
        local_endpoint,
        tunnel_ip,
        advertised_routes,
        RelayAnnouncementDetails::default(),
    )
}

fn build_explicit_peer_announcement_with_relay(
    node_id: String,
    public_key: String,
    endpoint: String,
    local_endpoint: String,
    tunnel_ip: String,
    advertised_routes: Vec<String>,
    relay: RelayAnnouncementDetails,
) -> PeerAnnouncement {
    let public_endpoint = endpoint_can_advertise_public_override(&endpoint, &local_endpoint)
        .then_some(endpoint.clone());
    let endpoint = if public_endpoint.is_some() {
        endpoint
    } else {
        local_endpoint.clone()
    };

    PeerAnnouncement {
        node_id,
        public_key,
        endpoint,
        local_endpoint: Some(local_endpoint),
        public_endpoint,
        relay_endpoint: relay.relay_endpoint,
        relay_pubkey: relay.relay_pubkey,
        relay_expires_at: relay.relay_expires_at,
        tunnel_ip,
        advertised_routes,
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
        announcement.relay_endpoint.as_deref().unwrap_or(""),
        announcement.relay_pubkey.as_deref().unwrap_or(""),
        &announcement.relay_expires_at.unwrap_or(0).to_string(),
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

fn platform_supports_exit_node_client() -> bool {
    #[cfg(target_os = "linux")]
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
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

#[cfg(any(target_os = "linux", target_os = "macos", test))]
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
    if !platform_supports_exit_node_client() {
        return None;
    }

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
    own_local_endpoints: &[String],
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
        if !runtime_endpoint_is_viable_for_peer(endpoint, announcement, own_local_endpoints) {
            continue;
        }

        let success_at = runtime_peer.last_handshake_at(now).unwrap_or(now);
        changed |= path_book.note_success(participant.clone(), endpoint, success_at);
    }

    changed
}

fn runtime_endpoint_requires_refresh(
    runtime_endpoint: &str,
    planned_endpoint: &str,
    announcement: &PeerAnnouncement,
    own_local_endpoints: &[String],
) -> bool {
    runtime_endpoint != planned_endpoint
        && !runtime_endpoint_is_same_subnet_translation_for_peer(
            runtime_endpoint,
            announcement,
            own_local_endpoints,
        )
        && !runtime_endpoint_is_viable_for_peer(runtime_endpoint, announcement, own_local_endpoints)
}

fn runtime_endpoint_is_same_subnet_translation_for_peer(
    runtime_endpoint: &str,
    announcement: &PeerAnnouncement,
    own_local_endpoints: &[String],
) -> bool {
    if !endpoint_is_local_only(runtime_endpoint) {
        return false;
    }

    if !own_local_endpoints
        .iter()
        .any(|own| endpoints_share_local_only_ipv4_subnet(runtime_endpoint, own))
    {
        return false;
    }

    let Some(runtime_addr) = parse_endpoint_socket_addr(runtime_endpoint) else {
        return false;
    };
    let Some(public_addr) = announcement
        .public_endpoint
        .as_deref()
        .and_then(parse_endpoint_socket_addr)
        .or_else(|| {
            (!endpoint_is_local_only(&announcement.endpoint))
                .then(|| parse_endpoint_socket_addr(&announcement.endpoint))
                .flatten()
        })
    else {
        return false;
    };

    runtime_addr.port() == public_addr.port()
}

fn runtime_endpoint_is_viable_for_peer(
    runtime_endpoint: &str,
    announcement: &PeerAnnouncement,
    own_local_endpoints: &[String],
) -> bool {
    if !endpoint_is_local_only(runtime_endpoint) {
        return true;
    }

    if announcement
        .relay_endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint == runtime_endpoint)
    {
        return true;
    }

    if announcement
        .public_endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint == runtime_endpoint)
    {
        return true;
    }

    if announcement.endpoint == runtime_endpoint {
        return own_local_endpoints
            .iter()
            .any(|own| endpoints_share_local_only_ipv4_subnet(runtime_endpoint, own));
    }

    announcement
        .local_endpoint
        .as_deref()
        .is_some_and(|local_endpoint| {
            local_endpoint == runtime_endpoint
                && own_local_endpoints
                    .iter()
                    .any(|own| endpoints_share_local_only_ipv4_subnet(local_endpoint, own))
        })
}

fn runtime_peer_endpoints_require_refresh(
    planned_peers: &[PlannedTunnelPeer],
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    own_local_endpoints: &[String],
) -> bool {
    let Some(runtime_peers) = runtime_peers else {
        return false;
    };

    planned_peers.iter().any(|planned| {
        let Some(announcement) = peer_announcements.get(&planned.participant) else {
            return false;
        };
        runtime_peers
            .get(&planned.peer.pubkey_hex)
            .filter(|runtime| runtime.has_handshake())
            .and_then(|runtime| runtime.endpoint.as_deref())
            .is_some_and(|runtime_endpoint| {
                runtime_endpoint_requires_refresh(
                    runtime_endpoint,
                    &planned.endpoint,
                    announcement,
                    own_local_endpoints,
                )
            })
    })
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonPeerTransportState {
    reachable: bool,
    last_handshake_at: Option<u64>,
    error: Option<String>,
}

fn daemon_peer_transport_state(
    announcement: Option<&PeerAnnouncement>,
    signal_active: bool,
    runtime_peer: Option<&WireGuardPeerStatus>,
    now: u64,
) -> DaemonPeerTransportState {
    let Some(announcement) = announcement else {
        return DaemonPeerTransportState {
            reachable: false,
            last_handshake_at: None,
            error: Some("no signal yet".to_string()),
        };
    };

    let reachable = runtime_peer.is_some_and(peer_has_recent_handshake);
    let error = if key_b64_to_hex(&announcement.public_key).is_err() {
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

    DaemonPeerTransportState {
        reachable,
        last_handshake_at: runtime_peer.and_then(|peer| peer.last_handshake_at(now)),
        error,
    }
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

fn relay_connection_action(relay_connected: bool) -> RelayConnectionAction {
    if relay_connected {
        RelayConnectionAction::KeepConnected
    } else {
        RelayConnectionAction::ReconnectWhenDue
    }
}

fn daemon_session_active(session_enabled: bool, expected_peers: usize) -> bool {
    session_enabled && expected_peers > 0
}

fn relay_session_active(
    session_enabled: bool,
    expected_peers: usize,
    join_requests_active: bool,
) -> bool {
    daemon_session_active(session_enabled, expected_peers) || join_requests_active
}

fn daemon_session_idle_status(
    session_enabled: bool,
    expected_peers: usize,
    join_requests_active: bool,
) -> &'static str {
    if session_enabled && expected_peers == 0 {
        WAITING_FOR_PARTICIPANTS_STATUS
    } else if join_requests_active {
        LISTENING_FOR_JOIN_REQUESTS_STATUS
    } else {
        "Paused"
    }
}

fn persist_inbound_join_request(
    app: &mut AppConfig,
    config_path: &Path,
    sender_pubkey: &str,
    requested_at: u64,
    network_id: &str,
    requester_node_name: &str,
    session_status: &mut String,
) {
    match app.record_inbound_join_request(
        network_id,
        sender_pubkey,
        requester_node_name,
        requested_at,
    ) {
        Ok(Some(network_name)) => {
            if let Err(error) = app.save(config_path) {
                *session_status = format!("Failed to persist join request: {error}");
            } else {
                *session_status = format!("Join request received for {network_name}.");
            }
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("daemon: ignoring invalid join request from {sender_pubkey}: {error}");
        }
    }
}

fn persist_shared_network_roster(
    app: &mut AppConfig,
    config_path: &Path,
    sender_pubkey: &str,
    network_id: &str,
    roster: &NetworkRoster,
    session_status: &mut String,
) -> Result<Option<String>> {
    let changed = app.apply_admin_signed_shared_roster(
        network_id,
        &roster.network_name,
        roster.participants.clone(),
        roster.admins.clone(),
        roster.signed_at,
        sender_pubkey,
    )?;
    if !changed {
        return Ok(None);
    }

    maybe_autoconfigure_node(app);
    app.save(config_path)?;
    let network_name = app
        .networks
        .iter()
        .find(|network| {
            normalize_runtime_network_id(&network.network_id)
                == normalize_runtime_network_id(network_id)
        })
        .map(|network| network.name.clone())
        .unwrap_or_else(|| network_id.to_string());
    *session_status = format!("Roster updated for {network_name}.");
    Ok(Some(network_name))
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

#[allow(clippy::too_many_arguments)]
async fn publish_private_announce_to_participants(
    client: &NostrSignalingClient,
    app: &AppConfig,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    outbound_announces: &mut OutboundAnnounceBook,
    participants: &[String],
    peer_announcements: Option<&HashMap<String, PeerAnnouncement>>,
) -> Result<usize> {
    if participants.is_empty() {
        return Ok(0);
    }

    let actual_listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    let public_endpoint =
        public_endpoint_for_listen_port(public_signal_endpoint, actual_listen_port);
    let own_local_endpoints = runtime_local_signal_endpoints(app, actual_listen_port);
    let fallback_local_endpoint = own_local_endpoints
        .first()
        .cloned()
        .unwrap_or_else(|| local_signal_endpoint(app, actual_listen_port));

    let mut recipients = participants.to_vec();
    recipients.sort();
    recipients.dedup();

    let mut sent = 0usize;
    for participant in recipients {
        let local_endpoint = peer_announcements
            .and_then(|announcements| announcements.get(&participant))
            .and_then(|announcement| {
                select_local_signal_endpoint_for_peer(announcement, &own_local_endpoints)
            })
            .unwrap_or_else(|| fallback_local_endpoint.clone());
        let endpoint = public_endpoint
            .clone()
            .unwrap_or_else(|| local_endpoint.clone());
        let relay_session = relay_sessions.get(&participant);
        let relay_fields = relay_session
            .filter(|session| relay_session_is_active(session, unix_timestamp()))
            .map(|session| RelayAnnouncementDetails {
                relay_endpoint: Some(session.advertised_ingress_endpoint.clone()),
                relay_pubkey: Some(session.relay_pubkey.clone()),
                relay_expires_at: Some(session.expires_at),
            })
            .unwrap_or_default();
        let announcement = build_explicit_peer_announcement_with_relay(
            app.node.id.clone(),
            app.node.public_key.clone(),
            endpoint,
            local_endpoint,
            app.node.tunnel_ip.clone(),
            runtime_effective_advertised_routes(app),
            relay_fields,
        );
        let fingerprint = announcement_fingerprint(&announcement);
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

#[allow(clippy::too_many_arguments)]
async fn publish_private_announce_to_active_peers(
    client: &NostrSignalingClient,
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    outbound_announces: &mut OutboundAnnounceBook,
) -> Result<usize> {
    let participants = active_private_announce_participants(app, own_pubkey, presence);

    publish_private_announce_to_participants(
        client,
        app,
        tunnel_runtime,
        public_signal_endpoint,
        relay_sessions,
        outbound_announces,
        &participants,
        Some(presence.active()),
    )
    .await
}

fn active_private_announce_participants(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
) -> Vec<String> {
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter(|participant| presence.active().contains_key(participant))
        .collect()
}

fn known_private_announce_participants(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
) -> Vec<String> {
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter(|participant| presence.announcement_for(participant).is_some())
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn publish_private_announce_to_known_peers(
    client: &NostrSignalingClient,
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    outbound_announces: &mut OutboundAnnounceBook,
) -> Result<usize> {
    let participants = known_private_announce_participants(app, own_pubkey, presence);

    publish_private_announce_to_participants(
        client,
        app,
        tunnel_runtime,
        public_signal_endpoint,
        relay_sessions,
        outbound_announces,
        &participants,
        Some(presence.known()),
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

fn select_local_signal_endpoint_for_peer(
    announcement: &PeerAnnouncement,
    own_local_endpoints: &[String],
) -> Option<String> {
    let peer_local_endpoint = announcement
        .local_endpoint
        .as_deref()
        .filter(|endpoint| !endpoint.trim().is_empty())
        .or_else(|| {
            endpoint_is_local_only(&announcement.endpoint).then_some(announcement.endpoint.as_str())
        })?;

    own_local_endpoints
        .iter()
        .find(|own| endpoints_share_local_only_ipv4_subnet(own, peer_local_endpoint))
        .cloned()
}

fn planned_tunnel_peers_for_local_endpoints(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    path_book: &mut PeerPathBook,
    own_local_endpoints: &[String],
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
        let effective_announcement = announcement.without_expired_relay(now);
        path_book.refresh_from_announcement(participant.clone(), &effective_announcement, now);
        let selected_endpoint = path_book
            .select_endpoint_for_local_endpoints(
                participant,
                &effective_announcement,
                own_local_endpoints,
                now,
                PEER_PATH_RETRY_AFTER_SECS,
            )
            .unwrap_or_else(|| {
                select_peer_endpoint_from_local_endpoints(
                    &effective_announcement,
                    own_local_endpoints,
                )
            });
        if peer_endpoint_requires_public_signal(
            app,
            &effective_announcement,
            &selected_endpoint,
            own_local_endpoints,
        ) {
            continue;
        }

        peers.push(PlannedTunnelPeer {
            participant: participant.clone(),
            endpoint: selected_endpoint.clone(),
            peer: tunnel_peer_from_endpoint(
                &effective_announcement,
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

fn parse_endpoint_socket_addr(endpoint: &str) -> Option<SocketAddr> {
    endpoint.parse::<SocketAddr>().ok()
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

fn endpoint_can_advertise_public_override(endpoint: &str, local_endpoint: &str) -> bool {
    endpoint != local_endpoint
        && (!endpoint_is_local_only(endpoint)
            || !endpoints_share_local_only_ipv4_subnet(endpoint, local_endpoint))
}

fn peer_endpoint_requires_public_signal(
    app: &AppConfig,
    announcement: &PeerAnnouncement,
    selected_endpoint: &str,
    own_local_endpoints: &[String],
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
            && own_local_endpoints
                .iter()
                .any(|own| endpoints_share_local_only_ipv4_subnet(local, own))
    }) {
        return false;
    }

    endpoint_is_local_only(selected_endpoint)
}

fn pending_nat_punch_targets(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    listen_port: u16,
) -> Vec<SocketAddr> {
    let own_local_endpoints = runtime_local_signal_endpoints(app, listen_port);
    pending_nat_punch_targets_for_local_endpoints(
        app,
        own_pubkey,
        peer_announcements,
        runtime_peers,
        &own_local_endpoints,
    )
}

fn pending_nat_punch_targets_for_local_endpoints(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    runtime_peers: Option<&HashMap<String, WireGuardPeerStatus>>,
    own_local_endpoints: &[String],
) -> Vec<SocketAddr> {
    let mut targets = app
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey)
        .filter_map(|participant| {
            let announcement = peer_announcements.get(participant)?;
            if peer_runtime_lookup(announcement, runtime_peers)
                .is_some_and(peer_has_recent_handshake)
            {
                return None;
            }

            let selected_endpoint =
                select_peer_endpoint_from_local_endpoints(announcement, own_local_endpoints);
            if peer_endpoint_requires_public_signal(
                app,
                announcement,
                &selected_endpoint,
                own_local_endpoints,
            ) {
                return None;
            }

            if own_local_endpoints.iter().any(|own_local_endpoint| {
                endpoints_share_local_only_ipv4_subnet(&selected_endpoint, own_local_endpoint)
            }) {
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
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let targets = pending_nat_punch_targets(
        app,
        own_pubkey,
        peer_announcements,
        runtime_peers.as_ref(),
        listen_port,
    );
    let Some(fingerprint) = nat_punch_fingerprint(&targets, listen_port) else {
        *last_attempt = None;
        return Ok(());
    };

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
            if peer_runtime_lookup(announcement, runtime_peers)
                .is_some_and(peer_has_recent_handshake)
            {
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

#[cfg(any(test, not(target_os = "windows")))]
fn route_targets_for_tunnel_peers(peers: &[TunnelPeer]) -> Vec<String> {
    let mut route_targets = peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().cloned())
        .collect::<Vec<_>>();
    route_targets.sort();
    route_targets.dedup();
    route_targets
}

fn route_targets_for_planned_tunnel_peers(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    peer_announcements: &HashMap<String, PeerAnnouncement>,
    planned_peers: &[PlannedTunnelPeer],
) -> Vec<String> {
    let mut route_targets = route_targets_for_tunnel_peers(
        &planned_peers
            .iter()
            .map(|planned| planned.peer.clone())
            .collect::<Vec<_>>(),
    );

    #[cfg(any(target_os = "macos", test))]
    if selected_exit_node_participant(app, own_pubkey, peer_announcements)
        .as_deref()
        .is_some_and(|participant| {
            planned_peers
                .iter()
                .any(|planned| planned.participant == participant)
        })
        && !route_targets.iter().any(|route| route == "0.0.0.0/0")
    {
        route_targets.push("0.0.0.0/0".to_string());
        route_targets.sort();
    }

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

#[allow(clippy::too_many_arguments)]
fn apply_presence_runtime_update(
    app: &AppConfig,
    own_pubkey: Option<&str>,
    presence: &PeerPresenceBook,
    relay_sessions: &HashMap<String, ActiveRelaySession>,
    path_book: &mut PeerPathBook,
    now: u64,
    tunnel_runtime: &mut CliTunnelRuntime,
    magic_dns_runtime: Option<&ConnectMagicDnsRuntime>,
) -> Result<()> {
    let effective_announcements =
        effective_peer_announcements_for_runtime(presence.known(), relay_sessions, now);
    tunnel_runtime.apply(app, own_pubkey, &effective_announcements, path_book, now)?;
    if let Some(runtime) = magic_dns_runtime {
        runtime.refresh_records(app, &effective_announcements);
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
    let mut relay_sessions: HashMap<String, ActiveRelaySession> = HashMap::new();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut network_snapshot = capture_network_snapshot();
    let timeout = network_probe_timeout(&app);
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let mut public_signal_endpoint = None;

    let mut client = NostrSignalingClient::from_secret_key_with_networks(
        &app.nostr.secret_key,
        signaling_networks_for_app(&app),
    )?;
    client.connect(&relays).await?;
    if let Err(error) = publish_active_network_roster(&client, &app, None).await {
        eprintln!("signal: initial roster publish failed: {error}");
    }
    let mut relay_connected = true;

    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &relay_sessions,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    let runtime_listen_port = tunnel_runtime
        .active_listen_port
        .unwrap_or(app.node.listen_port);
    refresh_public_signal_endpoint_with_port_mapping(
        &app,
        &network_snapshot,
        runtime_listen_port,
        &mut port_mapping_runtime,
        &mut public_signal_endpoint,
    )
    .await;
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
    let mut network_interval = tokio::time::interval(Duration::from_secs(5));
    network_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = reconnect_interval.tick() => {
                if relay_connected || Instant::now() < reconnect_due {
                    continue;
                }

                if matches!(
                    relay_connection_action(relay_connected),
                    RelayConnectionAction::KeepConnected
                ) {
                    continue;
                }

                client.disconnect().await;
                client = NostrSignalingClient::from_secret_key_with_networks(
                    &app.nostr.secret_key,
                    signaling_networks_for_app(&app),
                )?;
                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        outbound_announces.clear();
                        if let Err(error) = publish_active_network_roster(&client, &app, None).await
                        {
                            eprintln!("signal: roster publish failed after reconnect: {error}");
                        }
                        if let Err(error) = publish_private_announce_to_known_peers(
                            &client,
                            &app,
                            own_pubkey.as_deref(),
                            &presence,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                        )
                        .await
                        {
                            eprintln!("signal: known peer announce refresh failed after reconnect: {error}");
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
                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    eprintln!("connect: tunnel heartbeat refresh failed: {error}");
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
            _ = network_interval.tick() => {
                let latest_snapshot = capture_network_snapshot();
                let runtime_listen_port =
                    tunnel_runtime.active_listen_port.unwrap_or(app.node.listen_port);
                let network_changed = latest_snapshot.changed_since(&network_snapshot);
                let endpoint_changed = if network_changed {
                    network_snapshot = latest_snapshot;
                    println!("connect: network change detected; refreshing paths");
                    refresh_public_signal_endpoint_with_port_mapping(
                        &app,
                        &network_snapshot,
                        runtime_listen_port,
                        &mut port_mapping_runtime,
                        &mut public_signal_endpoint,
                    )
                    .await;
                    public_signal_endpoint
                        .as_ref()
                        .is_some_and(|endpoint| endpoint.listen_port == runtime_listen_port)
                } else {
                    match port_mapping_runtime
                        .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                        .await
                    {
                        Ok(changed) => {
                            if changed {
                                sync_public_signal_endpoint_from_mapping_or_stun(
                                    &app,
                                    runtime_listen_port,
                                    &port_mapping_runtime,
                                    &mut public_signal_endpoint,
                                );
                            }
                            changed
                        }
                        Err(error) => {
                            eprintln!("nat: port mapping renew failed: {error}");
                            false
                        }
                    }
                };

                if !network_changed && !endpoint_changed {
                    continue;
                }

                if network_changed {
                    last_nat_punch_attempt = None;
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        unix_timestamp(),
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        eprintln!("connect: tunnel refresh after network change failed: {error}");
                    }
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after network refresh failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after network refresh: {error}");
                }
                if relay_connected
                    && let Err(error) = publish_private_announce_to_active_peers(
                        &client,
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                    )
                    .await
                {
                    eprintln!("signal: active peer announce refresh failed after network change: {error}");
                }
                if relay_connected
                    && let Err(error) = client.publish(SignalPayload::Hello).await
                {
                    eprintln!("signal: hello publish failed after network change: {error}");
                }
            }
            _ = announce_interval.tick() => {
                let now = unix_timestamp();
                if prune_active_relay_sessions(&mut relay_sessions, now) {
                    outbound_announces.clear();
                    last_nat_punch_attempt = None;
                    apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    )
                    .context("failed to apply tunnel update after relay expiry")?;
                }
                let removed =
                    presence.prune_stale(now, peer_signal_timeout_secs(args.announce_interval_secs));
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
                        &relay_sessions,
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
                    &relay_sessions,
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
                        && let Err(error) = publish_active_network_roster(
                            &client,
                            &app,
                            Some(std::slice::from_ref(&sender_pubkey)),
                        )
                        .await
                    {
                        eprintln!("signal: targeted roster publish failed: {error}");
                    }
                    maybe_reset_targeted_announce_cache_for_hello(
                        &mut outbound_announces,
                        &sender_pubkey,
                        &payload,
                    );
                    if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
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
                    &relay_sessions,
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
                    && let Err(error) = publish_active_network_roster(
                        &client,
                        &app,
                        Some(std::slice::from_ref(&sender_pubkey)),
                    )
                    .await
                {
                    eprintln!("signal: targeted roster publish failed: {error}");
                }
                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_private_announce_to_participants(
                        &client,
                        &app,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                        std::slice::from_ref(&sender_pubkey),
                        Some(presence.known()),
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
    port_mapping_runtime.stop().await;
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
    let (mut app, mut network_id) = load_config_with_overrides(
        &config_path,
        network_override.clone(),
        participants_override.clone(),
    )?;
    let mut relays = resolve_relays(&args.relay, &app);
    let mut own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut expected_peers = expected_peer_count(&app);
    let state_file = daemon_state_file_path(&config_path);
    let peer_cache_file = daemon_peer_cache_file_path(&config_path);
    let _ = fs::remove_file(daemon_control_file_path(&config_path));
    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut outbound_announces = OutboundAnnounceBook::default();
    let mut relay_sessions: HashMap<String, ActiveRelaySession> = HashMap::new();
    let mut standby_relay_sessions: HashMap<String, Vec<ActiveRelaySession>> = HashMap::new();
    let mut relay_failures: RelayFailureCooldowns = HashMap::new();
    let mut relay_provider_verifications: RelayProviderVerificationBook = HashMap::new();
    let mut pending_relay_requests: HashMap<String, PendingRelayRequest> = HashMap::new();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);
    let mut network_snapshot = capture_network_snapshot();
    let mut network_changed_at = Some(unix_timestamp());
    let timeout = network_probe_timeout(&app);
    let mut captive_portal = detect_captive_portal(timeout).await;
    let mut port_mapping_runtime = PortMappingRuntime::default();
    let mut public_signal_endpoint = None;
    let mut last_written_peer_cache = None;
    let mut relay_operator_runtime = LocalRelayOperatorRuntime {
        status: if app.relay_for_others {
            "Waiting for relay operator startup".to_string()
        } else {
            "Relay operator disabled".to_string()
        },
        nat_assist_status: if app.provide_nat_assist {
            "Waiting for NAT assist startup".to_string()
        } else {
            "NAT assist disabled".to_string()
        },
        ..LocalRelayOperatorRuntime::default()
    };
    let mut relay_operator_process = None;

    let mut client = NostrSignalingClient::from_secret_key_with_networks(
        &app.nostr.secret_key,
        signaling_networks_for_app(&app),
    )?;
    let mut service_client = RelayServiceClient::from_secret_key(&app.nostr.secret_key)?;
    let mut relay_service_connected = false;

    let restored_peer_cache = if daemon_session_active(true, expected_peers) {
        match restore_daemon_peer_cache(
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
        }
    } else {
        false
    };

    apply_presence_runtime_update(
        &app,
        own_pubkey.as_deref(),
        &presence,
        &relay_sessions,
        &mut path_book,
        unix_timestamp(),
        &mut tunnel_runtime,
        magic_dns_runtime.as_ref(),
    )
    .context("failed to initialize tunnel runtime")?;
    let runtime_listen_port = tunnel_runtime
        .active_listen_port
        .unwrap_or(app.node.listen_port);
    if daemon_session_active(true, expected_peers) {
        refresh_public_signal_endpoint_with_port_mapping(
            &app,
            &network_snapshot,
            runtime_listen_port,
            &mut port_mapping_runtime,
            &mut public_signal_endpoint,
        )
        .await;
    }
    sync_local_relay_operator(
        &config_path,
        &app,
        &relays,
        public_signal_endpoint.as_ref(),
        &mut relay_operator_process,
        &mut relay_operator_runtime,
    )?;
    if restored_peer_cache && daemon_session_active(true, expected_peers) {
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
    let mut network_interval = tokio::time::interval(Duration::from_secs(5));
    network_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
    let mut session_status = if !daemon_session_active(session_enabled, expected_peers) {
        daemon_session_idle_status(session_enabled, expected_peers, app.join_requests_enabled())
            .to_string()
    } else {
        "Connecting to relays".to_string()
    };
    let mut relay_connected = false;
    let mut reconnect_attempt = 0u32;
    let mut reconnect_due = Instant::now();
    let mut last_mesh_count = 0_usize;
    let mut last_nat_punch_attempt: Option<(String, Instant)> = None;
    write_daemon_state(
        &state_file,
        &build_daemon_runtime_state(
            &app,
            daemon_session_active(session_enabled, expected_peers),
            expected_peers,
            &presence,
            &tunnel_runtime,
            public_signal_endpoint.as_ref(),
            &session_status,
            relay_connected,
            &network_snapshot.summary(network_changed_at, captive_portal),
            &port_mapping_runtime.status(),
            &relay_operator_runtime,
        ),
    )?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let supervised_service_executable = if args.service {
        Some(current_executable_fingerprint()?)
    } else {
        None
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let supervised_service_executable: Option<(PathBuf, ExecutableFingerprint)> = None;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = &mut terminate_wait => {
                break;
            }
            _ = reconnect_interval.tick() => {
                let join_requests_active = app.join_requests_enabled();
                let session_active = daemon_session_active(session_enabled, expected_peers);
                if !relay_session_active(session_enabled, expected_peers, join_requests_active)
                    || relay_connected
                    || Instant::now() < reconnect_due
                {
                    continue;
                }

                if matches!(
                    relay_connection_action(relay_connected),
                    RelayConnectionAction::KeepConnected
                ) {
                    continue;
                }

                client.disconnect().await;
                service_client.disconnect().await;
                relay_service_connected = false;
                client = NostrSignalingClient::from_secret_key_with_networks(
                    &app.nostr.secret_key,
                    signaling_networks_for_app(&app),
                )?;
                service_client = RelayServiceClient::from_secret_key(&app.nostr.secret_key)?;

                match client.connect(&relays).await {
                    Ok(()) => {
                        relay_connected = true;
                        reconnect_attempt = 0;
                        relay_service_connected = match service_client.connect(&relays).await {
                            Ok(()) => true,
                            Err(error) => {
                                eprintln!("daemon: relay service connect failed: {error}");
                                false
                            }
                        };
                        if let Err(error) = publish_active_network_roster(&client, &app, None).await
                        {
                            eprintln!("daemon: roster publish failed after reconnect: {error}");
                        }
                        session_status = if session_active {
                            "Connected".to_string()
                        } else {
                            daemon_session_idle_status(
                                session_enabled,
                                expected_peers,
                                join_requests_active,
                            )
                            .to_string()
                        };
                        if session_active {
                            outbound_announces.clear();
                            if let Err(error) = publish_private_announce_to_known_peers(
                                &client,
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &tunnel_runtime,
                                public_signal_endpoint.as_ref(),
                                &relay_sessions,
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
                if !daemon_session_active(session_enabled, expected_peers) || !relay_connected {
                    continue;
                }
                let now = unix_timestamp();
                let relay_sessions_changed =
                    prune_active_relay_sessions(&mut relay_sessions, now)
                    | prune_standby_relay_sessions(&mut standby_relay_sessions, now)
                    | prune_relay_failure_cooldowns(&mut relay_failures, now)
                    | prune_relay_provider_verifications(&mut relay_provider_verifications, now);
                if relay_sessions_changed {
                    outbound_announces.clear();
                    last_nat_punch_attempt = None;
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        session_status = format!("Relay expiry update failed ({error})");
                    }
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
                        let _ = prune_pending_relay_requests(&mut pending_relay_requests, now);
                        if app.use_public_relay_fallback
                            && relay_service_connected
                            && let Err(error) = maybe_request_public_relay_fallback(
                                &service_client,
                                &relays,
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &tunnel_runtime,
                                &relay_sessions,
                                &relay_failures,
                                &mut relay_provider_verifications,
                                &mut pending_relay_requests,
                                now,
                            )
                            .await
                        {
                            eprintln!("relay: allocation request failed: {error}");
                        }
                        if let Err(error) = publish_private_announce_to_active_peers(
                            &client,
                            &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &relay_sessions,
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
                if !daemon_session_active(session_enabled, expected_peers) {
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
                if let Err(error) = apply_presence_runtime_update(
                    &app,
                    own_pubkey.as_deref(),
                    &presence,
                    &relay_sessions,
                    &mut path_book,
                    unix_timestamp(),
                    &mut tunnel_runtime,
                    magic_dns_runtime.as_ref(),
                ) {
                    session_status = format!("Tunnel heartbeat refresh failed ({error})");
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
            _ = network_interval.tick() => {
                let latest_snapshot = capture_network_snapshot();
                let runtime_listen_port =
                    tunnel_runtime.active_listen_port.unwrap_or(app.node.listen_port);
                let session_active = daemon_session_active(session_enabled, expected_peers);
                let network_changed = latest_snapshot.changed_since(&network_snapshot);
                let endpoint_changed = if network_changed {
                    network_snapshot = latest_snapshot;
                    network_changed_at = Some(unix_timestamp());
                    captive_portal = detect_captive_portal(timeout).await;
                    if session_active {
                        refresh_public_signal_endpoint_with_port_mapping(
                            &app,
                            &network_snapshot,
                            runtime_listen_port,
                            &mut port_mapping_runtime,
                            &mut public_signal_endpoint,
                        )
                        .await;
                        true
                    } else {
                        port_mapping_runtime.stop().await;
                        public_signal_endpoint = None;
                        false
                    }
                } else if session_active {
                    match port_mapping_runtime
                        .renew_if_due(&network_snapshot, runtime_listen_port, timeout)
                        .await
                    {
                        Ok(changed) => {
                            if changed {
                                sync_public_signal_endpoint_from_mapping_or_stun(
                                    &app,
                                    runtime_listen_port,
                                    &port_mapping_runtime,
                                    &mut public_signal_endpoint,
                                );
                            }
                            changed
                        }
                        Err(error) => {
                            eprintln!("daemon: port mapping renew failed: {error}");
                            false
                        }
                    }
                } else {
                    false
                };

                if !network_changed && !endpoint_changed {
                    continue;
                }

                if network_changed {
                    eprintln!("daemon: network change detected; refreshing peer paths");
                    last_nat_punch_attempt = None;
                    match apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        unix_timestamp(),
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        Ok(()) => {
                            session_status = if daemon_session_active(session_enabled, expected_peers)
                            {
                                "Connected (network refresh)".to_string()
                            } else {
                                daemon_session_idle_status(
                                    session_enabled,
                                    expected_peers,
                                    app.join_requests_enabled(),
                                )
                                .to_string()
                            };
                        }
                        Err(error) => {
                            session_status =
                                format!("Network change refresh failed ({error})");
                        }
                    }
                }

                if !daemon_session_active(session_enabled, expected_peers) {
                    continue;
                }

                let peer_announcements = direct_peer_announcements(&presence, relay_connected);
                if let Err(error) = maybe_run_nat_punch(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &mut path_book,
                    &mut tunnel_runtime,
                    &mut public_signal_endpoint,
                    &mut last_nat_punch_attempt,
                ) {
                    eprintln!("nat: hole-punch after network refresh failed: {error}");
                }
                if let Err(error) = heartbeat_pending_tunnel_peers(
                    &app,
                    own_pubkey.as_deref(),
                    peer_announcements,
                    &tunnel_runtime,
                ) {
                    eprintln!("tunnel: peer heartbeat failed after network refresh: {error}");
                }
                if relay_connected
                    && let Err(error) = publish_private_announce_to_active_peers(
                        &client,
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &relay_sessions,
                        &mut outbound_announces,
                    )
                    .await
                {
                    eprintln!("signal: active peer announce refresh failed after network change: {error}");
                }
                if relay_connected
                    && let Err(error) = client.publish(SignalPayload::Hello).await
                {
                    eprintln!("signal: hello publish failed after network change: {error}");
                }
            }
            _ = state_interval.tick() => {
                let now = unix_timestamp();
                let changed_relay_participants = reconcile_active_relay_sessions(
                    &presence,
                    tunnel_runtime.peer_status().ok().as_ref(),
                    &mut relay_sessions,
                    &mut standby_relay_sessions,
                    &mut relay_failures,
                    &mut relay_provider_verifications,
                    &mut pending_relay_requests,
                    now,
                );
                if !changed_relay_participants.is_empty() {
                    last_nat_punch_attempt = None;
                    for participant in &changed_relay_participants {
                        outbound_announces.forget(participant);
                    }
                    if let Err(error) = apply_presence_runtime_update(
                        &app,
                        own_pubkey.as_deref(),
                        &presence,
                        &relay_sessions,
                        &mut path_book,
                        now,
                        &mut tunnel_runtime,
                        magic_dns_runtime.as_ref(),
                    ) {
                        session_status = format!("Relay failover update failed ({error})");
                    } else if relay_connected
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            &changed_relay_participants,
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("relay: failover announce failed: {error}");
                    }
                }

                if let Some(request) = take_daemon_control_request(&config_path) {
                    let control_result = match request {
                        DaemonControlRequest::Stop => break,
                        DaemonControlRequest::Pause => {
                            let was_session_active =
                                daemon_session_active(session_enabled, expected_peers);
                            if relay_connected && was_session_active {
                                let _ = client
                                    .publish(SignalPayload::Disconnect {
                                        node_id: app.node.id.clone(),
                                    })
                                    .await;
                            }
                            session_enabled = false;
                            let join_requests_active = app.join_requests_enabled();
                            if !join_requests_active {
                                client.disconnect().await;
                                relay_connected = false;
                            }
                            reconnect_attempt = 0;
                            reconnect_due = Instant::now();
                            port_mapping_runtime.stop().await;
                            public_signal_endpoint = None;
                            presence = PeerPresenceBook::default();
                            relay_sessions.clear();
                            standby_relay_sessions.clear();
                            relay_failures.clear();
                            relay_provider_verifications.clear();
                            pending_relay_requests.clear();
                            outbound_announces.clear();
                            last_nat_punch_attempt = None;
                            if let Err(error) = apply_presence_runtime_update(
                                &app,
                                own_pubkey.as_deref(),
                                &presence,
                                &relay_sessions,
                                &mut path_book,
                                unix_timestamp(),
                                &mut tunnel_runtime,
                                magic_dns_runtime.as_ref(),
                            ) {
                                session_status = format!("Pause failed ({error})");
                            } else {
                                session_status = daemon_session_idle_status(
                                    session_enabled,
                                    expected_peers,
                                    join_requests_active,
                                )
                                .to_string();
                            }
                            Ok(())
                        }
                        DaemonControlRequest::Resume => {
                            if !session_enabled {
                                session_enabled = true;
                                relay_connected = false;
                                reconnect_attempt = 0;
                                reconnect_due = Instant::now();
                                let _restored_peer_cache = if daemon_session_active(
                                    session_enabled,
                                    expected_peers,
                                ) {
                                    match restore_daemon_peer_cache(
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
                                    }
                                } else {
                                    false
                                };
                                if let Err(error) = apply_presence_runtime_update(
                                    &app,
                                    own_pubkey.as_deref(),
                                    &presence,
                                    &relay_sessions,
                                    &mut path_book,
                                    unix_timestamp(),
                                    &mut tunnel_runtime,
                                    magic_dns_runtime.as_ref(),
                                ) {
                                    session_status = format!("Resume failed ({error})");
                                } else if daemon_session_active(session_enabled, expected_peers) {
                                    let runtime_listen_port = tunnel_runtime
                                        .active_listen_port
                                        .unwrap_or(app.node.listen_port);
                                    refresh_public_signal_endpoint_with_port_mapping(
                                        &app,
                                        &network_snapshot,
                                        runtime_listen_port,
                                        &mut port_mapping_runtime,
                                        &mut public_signal_endpoint,
                                    )
                                    .await;
                                    session_status = "Resuming".to_string();
                                } else {
                                    port_mapping_runtime.stop().await;
                                    public_signal_endpoint = None;
                                    session_status = daemon_session_idle_status(
                                        session_enabled,
                                        expected_peers,
                                        app.join_requests_enabled(),
                                    )
                                    .to_string();
                                }
                            }
                            Ok(())
                        }
                        DaemonControlRequest::Reload => {
                            match update_daemon_config_from_staged_request(&config_path) {
                                Ok(staged_config_applied) => {
                            match load_config_with_overrides(
                                &config_path,
                                network_override.clone(),
                                participants_override.clone(),
                            ) {
                                Ok((reloaded_app, reloaded_network_id)) => {
                                    let reload = build_daemon_reload_config(
                                        reloaded_app,
                                        reloaded_network_id,
                                        &args.relay,
                                    );
                                    let configured_set = reload
                                        .configured_participants
                                        .iter()
                                        .cloned()
                                        .collect::<HashSet<_>>();
                                    app = reload.app;
                                    network_id = reload.network_id;
                                    expected_peers = reload.expected_peers;
                                    own_pubkey = reload.own_pubkey;
                                    relays = reload.relays;

                                    presence.retain_participants(&configured_set);
                                    path_book.retain_participants(&configured_set);
                                    outbound_announces.retain_participants(&configured_set);
                                    outbound_announces.clear();
                                    last_nat_punch_attempt = None;
                                    client.disconnect().await;
                                    match NostrSignalingClient::from_secret_key_with_networks(
                                        &app.nostr.secret_key,
                                        signaling_networks_for_app(&app),
                                    ) {
                                        Ok(new_client) => {
                                            client = new_client;
                                            let join_requests_active = app.join_requests_enabled();
                                            let session_active =
                                                daemon_session_active(session_enabled, expected_peers);
                                            if relay_session_active(
                                                session_enabled,
                                                expected_peers,
                                                join_requests_active,
                                            ) {
                                                match client.connect(&relays).await {
                                                    Ok(()) => {
                                                        relay_connected = true;
                                                        reconnect_attempt = 0;
                                                        reconnect_due = Instant::now();
                                                        if let Err(error) =
                                                            publish_active_network_roster(
                                                                &client,
                                                                &app,
                                                                None,
                                                            )
                                                            .await
                                                        {
                                                            eprintln!(
                                                                "daemon: roster publish failed after config reload: {error}"
                                                            );
                                                        }
                                                        session_status = if session_active {
                                                            "Config reloaded".to_string()
                                                        } else {
                                                            daemon_session_idle_status(
                                                                session_enabled,
                                                                expected_peers,
                                                                join_requests_active,
                                                            )
                                                            .to_string()
                                                        };
                                                        if session_active {
                                                            if let Err(error) = publish_private_announce_to_known_peers(
                                                                &client,
                                                                &app,
                                                                own_pubkey.as_deref(),
                                                                &presence,
                                                                &tunnel_runtime,
                                                                public_signal_endpoint.as_ref(),
                                                                &relay_sessions,
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
                                                port_mapping_runtime.stop().await;
                                                public_signal_endpoint = None;
                                                session_status = if session_enabled {
                                                    daemon_session_idle_status(
                                                        session_enabled,
                                                        expected_peers,
                                                        join_requests_active,
                                                    )
                                                    .to_string()
                                                } else {
                                                    "Config reloaded (paused)".to_string()
                                                };
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
                                        &relay_sessions,
                                        &mut path_book,
                                        unix_timestamp(),
                                        &mut tunnel_runtime,
                                        magic_dns_runtime.as_ref(),
                                    ) {
                                        session_status = format!(
                                            "Config reloaded; tunnel update failed ({})",
                                            error
                                        );
                                    } else if daemon_session_active(session_enabled, expected_peers) {
                                        let runtime_listen_port = tunnel_runtime
                                            .active_listen_port
                                            .unwrap_or(app.node.listen_port);
                                        refresh_public_signal_endpoint_with_port_mapping(
                                            &app,
                                            &network_snapshot,
                                            runtime_listen_port,
                                            &mut port_mapping_runtime,
                                            &mut public_signal_endpoint,
                                        )
                                        .await;
                                    }
                                    Ok(())
                                }
                                Err(error) => {
                                    session_status = if staged_config_applied {
                                        format!("Config apply failed (reload: {error})")
                                    } else {
                                        format!("Config reload failed ({error})")
                                    };
                                    Err(error)
                                }
                            }
                                }
                                Err(error) => {
                                    session_status = format!("Config apply failed ({error})");
                                    Err(error)
                                }
                            }
                        }
                    };
                    let _ = write_daemon_control_result(&config_path, request, control_result);
                    if let Err(error) = sync_local_relay_operator(
                        &config_path,
                        &app,
                        &relays,
                        public_signal_endpoint.as_ref(),
                        &mut relay_operator_process,
                        &mut relay_operator_runtime,
                    ) {
                        eprintln!("relay operator: sync failed after control request: {error}");
                    }
                    let _ = persist_daemon_runtime_state(
                        &state_file,
                        &app,
                        session_enabled,
                        expected_peers,
                        &presence,
                        &tunnel_runtime,
                        public_signal_endpoint.as_ref(),
                        &session_status,
                        relay_connected,
                        &network_snapshot.summary(network_changed_at, captive_portal),
                        &port_mapping_runtime.status(),
                        &relay_operator_runtime,
                    );
                    if let Err(error) =
                        persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                    {
                        eprintln!("daemon: failed to persist network cleanup state: {error}");
                    }
                }
                if let Some((executable, launched_fingerprint)) =
                    supervised_service_executable.as_ref()
                {
                    match service_supervisor_restart_due(executable, launched_fingerprint) {
                        Ok(true) => {
                            eprintln!(
                                "daemon: service executable changed on disk; exiting so the supervisor restarts the updated binary"
                            );
                            break;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            eprintln!(
                                "daemon: failed to check service executable fingerprint: {error}"
                            );
                        }
                    }
                }
                if daemon_session_active(session_enabled, expected_peers) {
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
                            &relay_sessions,
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
                if let Err(error) = sync_local_relay_operator(
                    &config_path,
                    &app,
                    &relays,
                    public_signal_endpoint.as_ref(),
                    &mut relay_operator_process,
                    &mut relay_operator_runtime,
                ) {
                    eprintln!("relay operator: sync failed: {error}");
                }
                let _ = persist_daemon_runtime_state(
                    &state_file,
                    &app,
                    session_enabled,
                    expected_peers,
                    &presence,
                    &tunnel_runtime,
                    public_signal_endpoint.as_ref(),
                    &session_status,
                    relay_connected,
                    &network_snapshot.summary(network_changed_at, captive_portal),
                    &port_mapping_runtime.status(),
                    &relay_operator_runtime,
                );
                if let Err(error) =
                    persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime)
                {
                    eprintln!("daemon: failed to persist network cleanup state: {error}");
                }
            }
            message = async {
                if relay_session_active(
                    session_enabled,
                    expected_peers,
                    app.join_requests_enabled(),
                ) && relay_connected
                {
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
                let session_active = daemon_session_active(session_enabled, expected_peers);
                if let SignalPayload::JoinRequest {
                    requested_at,
                    request,
                } = &payload
                {
                    persist_inbound_join_request(
                        &mut app,
                        &config_path,
                        &sender_pubkey,
                        *requested_at,
                        &request.network_id,
                        &request.requester_node_name,
                        &mut session_status,
                    );
                    continue;
                }

                if let SignalPayload::Roster(roster) = &payload {
                    match persist_shared_network_roster(
                        &mut app,
                        &config_path,
                        &sender_pubkey,
                        &message.network_id,
                        roster,
                        &mut session_status,
                    ) {
                        Ok(Some(_)) => {
                            let reload = build_daemon_reload_config(
                                app.clone(),
                                app.effective_network_id(),
                                &args.relay,
                            );
                            let configured_set = reload
                                .configured_participants
                                .iter()
                                .cloned()
                                .collect::<HashSet<_>>();
                            app = reload.app;
                            network_id = reload.network_id;
                            expected_peers = reload.expected_peers;
                            own_pubkey = reload.own_pubkey;
                            relays = reload.relays;

                            presence.retain_participants(&configured_set);
                            path_book.retain_participants(&configured_set);
                            outbound_announces.retain_participants(&configured_set);
                            outbound_announces.clear();
                            last_nat_punch_attempt = None;
                            client.disconnect().await;
                            match NostrSignalingClient::from_secret_key_with_networks(
                                &app.nostr.secret_key,
                                signaling_networks_for_app(&app),
                            ) {
                                Ok(new_client) => {
                                    client = new_client;
                                    let join_requests_active = app.join_requests_enabled();
                                    if relay_session_active(
                                        session_enabled,
                                        expected_peers,
                                        join_requests_active,
                                    ) {
                                        match client.connect(&relays).await {
                                            Ok(()) => {
                                                relay_connected = true;
                                                reconnect_attempt = 0;
                                                reconnect_due = Instant::now();
                                                if let Err(error) = apply_presence_runtime_update(
                                                    &app,
                                                    own_pubkey.as_deref(),
                                                    &presence,
                                                    &relay_sessions,
                                                    &mut path_book,
                                                    unix_timestamp(),
                                                    &mut tunnel_runtime,
                                                    magic_dns_runtime.as_ref(),
                                                ) {
                                                    session_status = format!(
                                                        "Roster applied, but tunnel reload failed ({error})"
                                                    );
                                                }
                                                if let Err(error) =
                                                    publish_active_network_roster(
                                                        &client,
                                                        &app,
                                                        None,
                                                    )
                                                    .await
                                                {
                                                    eprintln!(
                                                        "daemon: roster publish failed after roster apply: {error}"
                                                    );
                                                }
                                                if daemon_session_active(session_enabled, expected_peers)
                                                    && let Err(error) = client.publish(SignalPayload::Hello).await
                                                {
                                                    eprintln!(
                                                        "daemon: hello publish failed after roster apply: {error}"
                                                    );
                                                }
                                            }
                                            Err(error) => {
                                                relay_connected = false;
                                                reconnect_attempt =
                                                    reconnect_attempt.saturating_add(1);
                                                let delay =
                                                    daemon_reconnect_backoff_delay(reconnect_attempt);
                                                reconnect_due = Instant::now() + delay;
                                                session_status = format!(
                                                    "Roster applied; relay reconnect failed (retry in {}s: {error})",
                                                    delay.as_secs(),
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    relay_connected = false;
                                    session_status =
                                        format!("Roster applied, but signaling reload failed ({error})");
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!(
                                "daemon: ignoring invalid shared roster from {sender_pubkey}: {error}"
                            );
                        }
                    }
                    continue;
                }

                if matches!(&payload, SignalPayload::Hello | SignalPayload::Announce(_))
                    && let Err(error) = publish_active_network_roster(
                        &client,
                        &app,
                        Some(std::slice::from_ref(&sender_pubkey)),
                    )
                    .await
                {
                    eprintln!("daemon: targeted roster publish failed: {error}");
                }

                if !session_active {
                    continue;
                }

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
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
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
                    &relay_sessions,
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
                        && {
                            maybe_reset_targeted_announce_cache_for_hello(
                                &mut outbound_announces,
                                &sender_pubkey,
                                &payload,
                            );
                            true
                        }
                        && let Err(error) = publish_private_announce_to_participants(
                            &client,
                            &app,
                            &tunnel_runtime,
                            public_signal_endpoint.as_ref(),
                            &relay_sessions,
                            &mut outbound_announces,
                            std::slice::from_ref(&sender_pubkey),
                            Some(presence.known()),
                        )
                        .await
                    {
                        eprintln!("signal: targeted private announce failed: {error}");
                    }
                    session_status = if daemon_session_active(session_enabled, expected_peers) {
                        "Connected".to_string()
                    } else {
                        daemon_session_idle_status(
                            session_enabled,
                            expected_peers,
                            app.join_requests_enabled(),
                        )
                        .to_string()
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
            service_message = async {
                if relay_session_active(
                    session_enabled,
                    expected_peers,
                    app.join_requests_enabled(),
                ) && relay_connected && relay_service_connected
                {
                    service_client.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                let Some(service_message) = service_message else {
                    relay_service_connected = false;
                    continue;
                };
                let now = unix_timestamp();
                match service_message.payload {
                    ServicePayload::RelayAllocationGranted(granted) => {
                        match accept_relay_allocation_grant(
                            granted,
                            &mut pending_relay_requests,
                            &mut relay_sessions,
                            &mut standby_relay_sessions,
                            &relay_failures,
                            now,
                        ) {
                            RelayGrantAction::Activated(participant) => {
                                outbound_announces.forget(&participant);
                                if let Err(error) = apply_presence_runtime_update(
                                    &app,
                                    own_pubkey.as_deref(),
                                    &presence,
                                    &relay_sessions,
                                    &mut path_book,
                                    now,
                                    &mut tunnel_runtime,
                                    magic_dns_runtime.as_ref(),
                                ) {
                                    session_status = format!("Relay fallback update failed ({error})");
                                } else if let Err(error) = publish_private_announce_to_participants(
                                    &client,
                                    &app,
                                    &tunnel_runtime,
                                    public_signal_endpoint.as_ref(),
                                    &relay_sessions,
                                    &mut outbound_announces,
                                    std::slice::from_ref(&participant),
                                    Some(presence.known()),
                                )
                                .await
                                {
                                    eprintln!("relay: targeted relay announce failed: {error}");
                                }
                            }
                            RelayGrantAction::QueuedStandby(_) | RelayGrantAction::Ignored => {}
                        }
                    }
                    ServicePayload::RelayAllocationRejected(rejected) => {
                        if let Some(participant) = accept_relay_allocation_rejection(
                            rejected,
                            &mut pending_relay_requests,
                            &mut relay_failures,
                            &mut relay_provider_verifications,
                            now,
                        ) {
                            outbound_announces.forget(&participant);
                        }
                    }
                    ServicePayload::RelayAllocationRequest(_)
                    | ServicePayload::RelayProbeRequest(_)
                    | ServicePayload::RelayProbeGranted(_)
                    | ServicePayload::RelayProbeRejected(_) => {}
                }
            }
        }
    }

    if relay_connected && daemon_session_active(session_enabled, expected_peers) {
        let _ = client
            .publish(SignalPayload::Disconnect {
                node_id: app.node.id.clone(),
            })
            .await;
    }
    client.disconnect().await;
    service_client.disconnect().await;
    stop_local_relay_operator(
        &mut relay_operator_process,
        &mut relay_operator_runtime,
        "Relay operator stopped",
        "NAT assist stopped",
    );
    port_mapping_runtime.stop().await;
    tunnel_runtime.stop();
    if let Err(error) = persist_daemon_network_cleanup_state(&config_path, &tunnel_runtime) {
        eprintln!("daemon: failed to clear network cleanup state: {error}");
    }

    let final_state = DaemonRuntimeState {
        updated_at: unix_timestamp(),
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint: String::new(),
        advertised_endpoint: String::new(),
        listen_port: 0,
        session_active: false,
        relay_connected: false,
        session_status: "Disconnected".to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count: 0,
        mesh_ready: false,
        health: Vec::new(),
        network: network_snapshot.summary(network_changed_at, captive_portal),
        port_mapping: PortMappingStatus::default(),
        peers: Vec::new(),
        relay_operator_running: false,
        relay_operator_pid: None,
        relay_operator_status: relay_operator_runtime.status.clone(),
        nat_assist_running: false,
        nat_assist_status: relay_operator_runtime.nat_assist_status.clone(),
    };
    let _ = write_daemon_state(&state_file, &final_state);

    Ok(())
}

#[cfg(target_os = "windows")]
fn run_windows_service_dispatcher(args: DaemonArgs) -> Result<()> {
    WINDOWS_SERVICE_DAEMON_ARGS
        .set(args)
        .map_err(|_| anyhow!("windows service daemon arguments already initialized"))?;
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_windows_service_main)
        .context("failed to start Windows service dispatcher")
}

#[cfg(target_os = "windows")]
fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service() {
        eprintln!("windows service failed: {error:?}");
    }
}

#[cfg(target_os = "windows")]
fn run_windows_service() -> Result<()> {
    let args = WINDOWS_SERVICE_DAEMON_ARGS
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("windows service launched without daemon arguments"))?;
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, {
        let config_path = config_path.clone();
        move |control_event| match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = request_daemon_stop(&config_path);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .context("failed to register Windows service control handler")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        Duration::from_secs(10),
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for Windows service")?;

    set_windows_service_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
        Duration::default(),
    )?;

    let result = runtime.block_on(daemon_session(args));
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    set_windows_service_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::default(),
    )?;
    result
}

#[cfg(target_os = "windows")]
fn set_windows_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> Result<()> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
        .with_context(|| format!("failed to update Windows service status to {state:?}"))
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

#[allow(clippy::too_many_arguments)]
fn build_daemon_runtime_state(
    app: &AppConfig,
    session_active: bool,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    session_status: &str,
    relay_connected: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    relay_operator: &LocalRelayOperatorRuntime,
) -> DaemonRuntimeState {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let runtime_peers = tunnel_runtime.peer_status().ok();
    let now = unix_timestamp();
    let listen_port = tunnel_runtime.listen_port(app.node.listen_port);
    let local_endpoint = local_signal_endpoint(app, listen_port);
    let advertised_endpoint = public_endpoint_for_listen_port(public_signal_endpoint, listen_port)
        .unwrap_or_else(|| local_endpoint.clone());
    let mut peers = Vec::new();

    for participant in &app.participant_pubkeys_hex() {
        if Some(participant.as_str()) == own_pubkey.as_deref() {
            continue;
        }

        let Some(announcement) = presence.announcement_for(participant) else {
            let transport = daemon_peer_transport_state(None, false, None, now);
            peers.push(DaemonPeerState {
                participant_pubkey: participant.clone(),
                node_id: String::new(),
                tunnel_ip: String::new(),
                endpoint: String::new(),
                runtime_endpoint: None,
                tx_bytes: 0,
                rx_bytes: 0,
                public_key: String::new(),
                advertised_routes: Vec::new(),
                presence_timestamp: 0,
                last_signal_seen_at: None,
                reachable: transport.reachable,
                last_handshake_at: transport.last_handshake_at,
                error: transport.error,
            });
            continue;
        };

        let signal_active = presence.active().contains_key(participant);
        let runtime_peer = peer_runtime_lookup(announcement, runtime_peers.as_ref());
        let transport =
            daemon_peer_transport_state(Some(announcement), signal_active, runtime_peer, now);

        peers.push(DaemonPeerState {
            participant_pubkey: participant.clone(),
            node_id: announcement.node_id.clone(),
            tunnel_ip: announcement.tunnel_ip.clone(),
            endpoint: announcement.endpoint.clone(),
            runtime_endpoint: runtime_peer.and_then(|peer| peer.endpoint.clone()),
            tx_bytes: runtime_peer.map(|peer| peer.tx_bytes).unwrap_or(0),
            rx_bytes: runtime_peer.map(|peer| peer.rx_bytes).unwrap_or(0),
            public_key: announcement.public_key.clone(),
            advertised_routes: announcement.advertised_routes.clone(),
            presence_timestamp: announcement.timestamp,
            last_signal_seen_at: presence.last_seen_at(participant),
            reachable: transport.reachable,
            last_handshake_at: transport.last_handshake_at,
            error: transport.error,
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
    let health = build_health_issues(
        app,
        session_active,
        relay_connected,
        mesh_ready,
        network,
        port_mapping,
        &peers,
    );
    DaemonRuntimeState {
        updated_at: now,
        binary_version: PRODUCT_VERSION.to_string(),
        local_endpoint,
        advertised_endpoint,
        listen_port,
        session_active,
        relay_connected,
        session_status: session_status.to_string(),
        expected_peer_count: expected_peers,
        connected_peer_count,
        mesh_ready,
        health,
        network: network.clone(),
        port_mapping: port_mapping.clone(),
        peers,
        relay_operator_running: relay_operator.running,
        relay_operator_pid: relay_operator.pid,
        relay_operator_status: relay_operator.status.clone(),
        nat_assist_running: relay_operator.nat_assist_running,
        nat_assist_status: relay_operator.nat_assist_status.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_daemon_runtime_state(
    path: &Path,
    app: &AppConfig,
    session_enabled: bool,
    expected_peers: usize,
    presence: &PeerPresenceBook,
    tunnel_runtime: &CliTunnelRuntime,
    public_signal_endpoint: Option<&DiscoveredPublicSignalEndpoint>,
    session_status: &str,
    relay_connected: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    relay_operator: &LocalRelayOperatorRuntime,
) -> Result<()> {
    write_daemon_state(
        path,
        &build_daemon_runtime_state(
            app,
            daemon_session_active(session_enabled, expected_peers),
            expected_peers,
            presence,
            tunnel_runtime,
            public_signal_endpoint,
            session_status,
            relay_connected,
            network,
            port_mapping,
            relay_operator,
        ),
    )
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
    let current_pid = std::process::id();
    let daemon_pids = daemon_candidate_pids(&config_path, current_pid)?;

    if daemon_pids.is_empty() {
        return finish_stop_daemon(&config_path, &status, false);
    }

    #[cfg(target_os = "windows")]
    let requested_control_stop = {
        request_daemon_stop(&config_path)?;
        true
    };

    #[cfg(not(target_os = "windows"))]
    let mut requested_control_stop = false;

    #[cfg(not(target_os = "windows"))]
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
        if daemon_candidate_pids(&config_path, current_pid)?.is_empty() {
            return finish_stop_daemon(&config_path, &status, true);
        }
        thread::sleep(Duration::from_millis(120));
    }

    if args.force {
        for pid in daemon_candidate_pids(&config_path, current_pid)? {
            #[cfg(target_os = "windows")]
            windows_taskkill_pid(pid)?;

            #[cfg(not(target_os = "windows"))]
            if let Err(error) = send_signal(pid, "-KILL")
                && !kill_error_requires_control_fallback(&error.to_string())
            {
                return Err(error);
            }
        }
        thread::sleep(Duration::from_millis(120));
    }

    if requested_control_stop {
        #[cfg(not(target_os = "windows"))]
        request_daemon_stop(&config_path)?;
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            if daemon_candidate_pids(&config_path, current_pid)?.is_empty() {
                return finish_stop_daemon(&config_path, &status, true);
            }
            thread::sleep(Duration::from_millis(120));
        }
    }

    let remaining = daemon_candidate_pids(&config_path, current_pid)?;
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

    finish_stop_daemon(&config_path, &status, true)
}

fn finish_stop_daemon(config_path: &Path, status: &DaemonStatus, was_running: bool) -> Result<()> {
    let repaired = repair_saved_network_state(config_path);
    let _ = fs::remove_file(&status.pid_file);
    let _ = fs::remove_file(daemon_control_file_path(config_path));

    match repaired {
        Ok(true) if was_running => println!("daemon stopped; repaired network state"),
        Ok(true) => println!("daemon: not running; repaired network state"),
        Ok(false) if was_running => println!("daemon stopped"),
        Ok(false) => println!("daemon: not running"),
        Err(error) => {
            return Err(anyhow!(
                "{} but failed to repair network state: {error}",
                if was_running {
                    "daemon stopped"
                } else {
                    "daemon is not running"
                }
            ));
        }
    }

    Ok(())
}

fn repair_network(args: RepairNetworkArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    if let Some(pid) = daemon_candidate_pids(&config_path, std::process::id())?
        .into_iter()
        .next()
    {
        return Err(anyhow!(
            "daemon is still running with pid {pid}; stop it before repairing network state"
        ));
    }

    if repair_saved_network_state(&config_path)? {
        println!("network state repaired");
    } else {
        println!("network state already clean");
    }
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
    let ack_result = wait_for_daemon_control_ack(&config_path, Duration::from_secs(3));
    match request {
        DaemonControlRequest::Pause => {
            let session_result =
                wait_for_daemon_session_active(&config_path, false, Duration::from_secs(2));
            match (ack_result, session_result) {
                (Ok(()), Ok(())) | (Err(_), Ok(())) => {}
                (Ok(()), Err(error)) => return Err(error),
                (Err(error), Err(_)) => return Err(error),
            }
        }
        DaemonControlRequest::Resume => {
            let session_result =
                wait_for_daemon_session_active(&config_path, true, Duration::from_secs(2));
            match (ack_result, session_result) {
                (Ok(()), Ok(())) | (Err(_), Ok(())) => {}
                (Ok(()), Err(error)) => return Err(error),
                (Err(error), Err(_)) => return Err(error),
            }
        }
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => {
            ack_result?;
        }
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
    let running_pid = daemon_candidate_pids(config_path, std::process::id())?
        .into_iter()
        .next();
    let running = running_pid.is_some();

    if !running {
        match repair_saved_network_state(config_path) {
            Ok(true) => eprintln!("daemon: repaired saved network state"),
            Ok(false) => {}
            Err(error) => eprintln!("daemon: failed to repair saved network state: {error}"),
        }
    }

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
        "state": visible_daemon_state_for_status(status.running, status.state.as_ref()),
    }))
}

fn status_endpoint(app: &AppConfig, daemon: &DaemonStatus) -> String {
    daemon
        .state
        .as_ref()
        .and_then(|state| {
            let endpoint = state.advertised_endpoint.trim();
            (!endpoint.is_empty()).then(|| endpoint.to_string())
        })
        .unwrap_or_else(|| app.node.endpoint.clone())
}

fn status_listen_port(app: &AppConfig, daemon: &DaemonStatus) -> u16 {
    daemon
        .state
        .as_ref()
        .and_then(|state| (state.listen_port > 0).then_some(state.listen_port))
        .unwrap_or(app.node.listen_port)
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

fn format_probe_state(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Available => "available",
        ProbeState::Unavailable => "unavailable",
        ProbeState::Unsupported => "unsupported",
        ProbeState::Error => "error",
        ProbeState::Unknown => "unknown",
    }
}

fn format_health_severity(severity: HealthSeverity) -> &'static str {
    match severity {
        HealthSeverity::Info => "info",
        HealthSeverity::Warning => "warning",
        HealthSeverity::Critical => "critical",
    }
}

async fn run_doctor(args: DoctorArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let (app, network_id) =
        load_config_with_overrides(&config_path, args.network_id, args.participants)?;
    let relays = resolve_relays(&args.relay, &app);
    let daemon = daemon_status(&config_path)?;
    let netcheck = run_netcheck_report(&app, &network_id, &relays, args.timeout_secs).await;

    let mut network = daemon
        .state
        .as_ref()
        .map(|state| state.network.clone())
        .unwrap_or_else(|| capture_network_snapshot().summary(None, netcheck.captive_portal));
    if network.captive_portal.is_none() {
        network.captive_portal = netcheck.captive_portal;
    }
    let port_mapping = daemon
        .state
        .as_ref()
        .map(|state| state.port_mapping.clone())
        .unwrap_or_else(|| netcheck.port_mapping.clone());
    let issues = daemon
        .state
        .as_ref()
        .map(|state| {
            if state.health.is_empty() {
                build_health_issues(
                    &app,
                    state.session_active,
                    state.relay_connected,
                    state.mesh_ready,
                    &network,
                    &port_mapping,
                    &state.peers,
                )
            } else {
                state.health.clone()
            }
        })
        .unwrap_or_default();
    let log_tail = read_daemon_log_tail(&daemon.log_file, 80);
    let bundle_path = if let Some(path) = args.write_bundle.as_deref() {
        Some(
            write_doctor_bundle(
                path,
                &app,
                &network_id,
                &daemon,
                &network,
                &port_mapping,
                &issues,
                &netcheck,
                &log_tail,
            )
            .await?,
        )
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "networkId": network_id,
                "daemon": {
                    "running": daemon.running,
                    "pid": daemon.pid,
                    "logFile": daemon.log_file,
                    "stateFile": daemon.state_file,
                    "state": daemon.state,
                },
                "network": network,
                "portMapping": port_mapping,
                "health": issues,
                "netcheck": netcheck,
                "bundlePath": bundle_path,
            }))?
        );
        return Ok(());
    }

    println!("network: {network_id}");
    if daemon.running {
        println!("daemon: running (pid {})", daemon.pid.unwrap_or_default());
    } else {
        println!("daemon: stopped");
    }
    if let Some(state) = daemon.state.as_ref() {
        println!("session: {}", state.session_status);
    }
    println!(
        "netcheck: udp={} ipv4={} ipv6={} captive_portal={}",
        netcheck.udp,
        netcheck.ipv4,
        netcheck.ipv6,
        netcheck
            .captive_portal
            .map_or("unknown".to_string(), |value| value.to_string())
    );
    if let Some(interface) = network.default_interface.as_deref() {
        println!("default_interface: {interface}");
    }
    if let Some(primary_ipv4) = network.primary_ipv4.as_deref() {
        println!("primary_ipv4: {primary_ipv4}");
    }
    if let Some(primary_ipv6) = network.primary_ipv6.as_deref() {
        println!("primary_ipv6: {primary_ipv6}");
    }
    if let Some(public_ipv4) = netcheck.public_ipv4.as_deref() {
        println!("public_ipv4: {public_ipv4}");
    }
    if let Some(preferred_relay) = netcheck.preferred_relay.as_deref() {
        println!("preferred_relay: {preferred_relay}");
    }
    println!(
        "port_mapping: active={} upnp={} nat_pmp={} pcp={}",
        port_mapping.active_protocol.as_deref().unwrap_or("none"),
        format_probe_state(port_mapping.upnp.state),
        format_probe_state(port_mapping.nat_pmp.state),
        format_probe_state(port_mapping.pcp.state),
    );
    let reachable_relays = netcheck
        .relay_checks
        .iter()
        .filter(|item| item.error.is_none())
        .count();
    println!(
        "relays: {reachable_relays}/{} reachable",
        netcheck.relay_checks.len()
    );
    for check in &netcheck.relay_checks {
        if let Some(error) = check.error.as_deref() {
            println!("  relay {}: down ({error})", check.relay);
        } else {
            println!("  relay {}: up ({} ms)", check.relay, check.latency_ms);
        }
    }
    if issues.is_empty() {
        println!("health: ok");
    } else {
        println!("health:");
        for issue in &issues {
            println!(
                "  [{}] {}",
                format_health_severity(issue.severity),
                issue.summary
            );
            println!("    {}", issue.detail);
        }
    }
    if let Some(path) = bundle_path {
        println!("bundle: {}", path.display());
    }

    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn tunnel_up(args: &TunnelUpArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    #[cfg(target_os = "windows")]
    {
        let peer = TunnelPeer {
            pubkey_hex: key_b64_to_hex(&args.peer_public_key)?,
            endpoint: args.peer_endpoint.clone(),
            allowed_ips: vec![args.peer_allowed_ip.clone()],
        };
        let _runtime = WindowsTunnelBackend::start(
            &args.iface,
            &args.private_key,
            args.listen_port,
            &args.address,
            &[peer],
        )?;

        println!(
            "boringtun+wintun interface {} up: {}, peer {} via {}",
            args.iface, args.address, args.peer_allowed_ip, args.peer_endpoint
        );

        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if cfg!(not(unix)) {
            return Err(anyhow!(
                "tunnel-up is currently supported on unix platforms only"
            ));
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

#[cfg(unix)]
fn wait_for_socket(path: &str) -> Result<()> {
    for _ in 0..50 {
        if fs::metadata(path).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!("timed out waiting for uapi socket at {path}"))
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn wait_for_socket(path: &str) -> Result<()> {
    Err(anyhow!(
        "WireGuard control socket is unsupported on this platform: {path}"
    ))
}

#[cfg(unix)]
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

#[cfg(all(not(unix), not(target_os = "windows")))]
fn wg_set(socket_path: &str, _body: &str) -> Result<()> {
    Err(anyhow!(
        "WireGuard control socket is unsupported on this platform: {socket_path}"
    ))
}

#[cfg(unix)]
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

#[cfg(all(not(unix), not(target_os = "windows")))]
fn wg_get(socket_path: &str) -> Result<String> {
    Err(anyhow!(
        "WireGuard control socket is unsupported on this platform: {socket_path}"
    ))
}

#[cfg(any(test, not(target_os = "windows")))]
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
            continue;
        }

        if let Some(value) = line.strip_prefix("tx_bytes=") {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                current.tx_bytes = parsed;
            }
            continue;
        }

        if let Some(value) = line.strip_prefix("rx_bytes=")
            && let Ok(parsed) = value.trim().parse::<u64>()
        {
            current.rx_bytes = parsed;
        }
    }

    commit_current(&mut peers, &mut current_pubkey, &mut current);
    peers
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    pub(super) use support::{
        control_daemon_request_for_test, local_endpoints, sample_peer_announcement,
    };

    mod cli_smoke;
    mod config_cache;
    mod daemon_control;
    mod peer_runtime;
    mod routing;
    mod runtime_misc;
    mod service_cli;
    pub(crate) mod support;
}

#[cfg(test)]
pub(crate) use tests::support::{
    build_peer_announcement, macos_default_routes_from_netstat, macos_ifconfig_has_ipv4,
    macos_route_get_spec_from_output, nat_punch_targets, nat_punch_targets_for_local_endpoint,
    nat_punch_targets_for_local_endpoints, pending_nat_punch_targets_for_local_endpoint,
    planned_tunnel_peers,
};
