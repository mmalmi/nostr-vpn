mod config_bootstrap;
mod daemon_runtime;
mod diagnostics;
#[cfg(all(
    feature = "embedded-fips",
    any(target_os = "linux", target_os = "macos")
))]
mod fips_host_tunnel;
#[cfg(feature = "embedded-fips")]
mod fips_private_mesh;
#[cfg(any(target_os = "macos", test))]
mod macos_network;
#[cfg(any(target_os = "macos", test))]
mod macos_service;
mod network_signaling;
#[cfg(all(
    feature = "embedded-fips",
    any(target_os = "linux", target_os = "macos")
))]
mod pipeline_profile;
mod platform_routing;
#[cfg(feature = "embedded-fips")]
mod recent_peers_store;
mod service_management;
mod session_runtime;
mod updater;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod wg_upstream_runtime;
#[cfg(any(target_os = "windows", test))]
mod windows_tunnel;
#[cfg(target_os = "linux")]
mod wireguard_exit;

use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
#[cfg(any(target_os = "macos", test))]
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
#[cfg(test)]
use std::sync::Mutex;
#[cfg(any(target_os = "windows", test))]
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nostr_vpn_core::config::{
    AppConfig, SharedNetworkRoster, derive_mesh_tunnel_ip, exit_node_default_routes,
    maybe_autoconfigure_node, normalize_advertised_route, normalize_fips_peer_endpoint_hint,
    normalize_nostr_pubkey, normalize_runtime_network_id, parse_wireguard_exit_config,
};
use nostr_vpn_core::control::PeerAnnouncement;
use nostr_vpn_core::data_plane::MeshPeerStatus;
use nostr_vpn_core::diagnostics::{
    HealthIssue, HealthSeverity, NetworkSummary, PortMappingStatus, ProbeState,
};
use nostr_vpn_core::fips_control::{
    NetworkRoster, PeerCapabilities, PeerEndpointHint, SignedRoster,
};
#[cfg(feature = "embedded-fips")]
use nostr_vpn_core::join_requests::{FIPS_JOIN_REQUEST_RETRY_SECS, MeshJoinRequest};
use nostr_vpn_core::magic_dns::{
    MagicDnsResolverConfig, MagicDnsServer, build_magic_dns_records, install_system_resolver,
    uninstall_system_resolver,
};
#[cfg(target_os = "windows")]
use nostr_vpn_core::platform_paths::{
    legacy_config_path_from_dirs_config_dir, windows_default_config_path_for_state,
    windows_machine_config_path_from_program_data_dir,
    windows_service_config_path_from_sc_qc_output,
};
use nostr_vpn_core::signed_rosters::{
    load_signed_rosters, signed_rosters_file_path, upsert_signed_roster,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
#[cfg(target_os = "windows")]
pub(crate) use crate::config_bootstrap::windows_service_install_config_path;
pub(crate) use crate::config_bootstrap::{
    apply_config_file, apply_participants_override, default_config_path, default_tunnel_iface,
    init_config, install_cli, load_or_default_config, print_version, uninstall_cli,
};
pub(crate) use crate::daemon_runtime::*;
use crate::diagnostics::{
    PortMappingRuntime, build_health_issues, capture_network_snapshot, detect_captive_portal,
    run_netcheck_report, write_doctor_bundle,
};
#[cfg(test)]
use crate::network_signaling::NETWORK_INVITE_PREFIX;
use crate::network_signaling::{
    RosterEditAction, active_network_invite_code, apply_network_invite_to_active_network,
    maybe_reload_running_daemon, parse_network_invite, queue_active_network_join_request,
    update_active_network_roster,
};
#[cfg(any(test, not(target_os = "windows")))]
pub(crate) use crate::platform_routing::*;
#[cfg(test)]
pub(crate) use crate::service_management::parse_nonzero_pid;
#[cfg(any(target_os = "windows", test))]
pub(crate) use crate::service_management::windows_should_apply_config_via_service;
#[cfg(test)]
pub(crate) use crate::service_management::{
    linux_service_binary_path, linux_service_executable_path_from_unit_contents,
    linux_service_status_from_show_output, linux_service_unit_content,
};
#[cfg(test)]
pub(crate) use crate::service_management::{
    windows_service_bin_path, windows_service_binary_path_from_sc_qc_output,
    windows_service_disabled_from_qc_output, windows_service_status_from_query_output,
};
#[cfg(any(target_os = "macos", test))]
pub(crate) use crate::service_management::{xml_escape, xml_unescape};
pub(crate) use crate::session_runtime::*;
#[cfg(target_os = "linux")]
pub(crate) use crate::wireguard_exit::*;
const DAEMON_CONTROL_STOP_REQUEST: &str = "stop";
const DAEMON_CONTROL_RELOAD_REQUEST: &str = "reload";
const DAEMON_CONTROL_PAUSE_REQUEST: &str = "pause";
const DAEMON_CONTROL_RESUME_REQUEST: &str = "resume";
const DAEMON_STATUS_MODE_ENV: &str = "NVPN_DAEMON_STATUS_MODE";
const DAEMON_STATUS_MODE_STATE_FILE: &str = "state-file";
const DAEMON_STATE_RUNNING_MAX_AGE_SECS_ENV: &str = "NVPN_DAEMON_STATE_RUNNING_MAX_AGE_SECS";
const DEFAULT_DAEMON_STATE_RUNNING_MAX_AGE_SECS: u64 = 10;
const MAJOR_LINK_CHANGE_TIME_JUMP_SECS: u64 = 30;
const WAITING_FOR_PARTICIPANTS_STATUS: &str = "Waiting for participants";
const LISTENING_FOR_JOIN_REQUESTS_STATUS: &str = "Listening for join requests";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(target_os = "windows")]
const MAGIC_DNS_PORT: u16 = 53;
#[cfg(not(target_os = "windows"))]
const MAGIC_DNS_PORT: u16 = 1053;
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
#[command(about = "FIPS private mesh VPN")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
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
    /// Show the running CLI version.
    Version(VersionArgs),
    /// Update this `nvpn` binary from the latest published release.
    Update(UpdateArgs),
    /// Install `nvpn` into a platform-appropriate default PATH location.
    InstallCli(InstallCliArgs),
    /// Remove an `nvpn` binary previously installed into PATH.
    UninstallCli(UninstallCliArgs),
    /// Manage the persistent system daemon service.
    Service(ServiceArgs),
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
    /// Run a FIPS private mesh session from config.
    Connect(ConnectArgs),
    /// Show local and discovered peer status.
    Status(StatusArgs),
    /// Update persisted node/network settings.
    Set(SetArgs),
    /// Emit a full `nvpn://invite/...` code for the active network.
    CreateInvite(CreateInviteArgs),
    /// Import a full `nvpn://invite/...` code into the active network config.
    ImportInvite(ImportInviteArgs),
    /// Broadcast the active network's invite over LAN multicast so nearby
    /// devices running `nvpn discover` can pair without copy/pasting a code.
    /// Runs in the foreground; Ctrl-C stops broadcasting.
    InviteBroadcast(InviteBroadcastArgs),
    /// Listen for nearby LAN invite broadcasts and print what's found. With
    /// `--accept`, import the first valid invite seen (queues a join request
    /// to the broadcaster, same as `nvpn import-invite`).
    Discover(DiscoverArgs),
    /// Add one or more participants to the active network roster.
    AddParticipant(UpdateRosterArgs),
    /// Remove one or more participants from the active network roster.
    RemoveParticipant(UpdateRosterArgs),
    /// Add one or more admins to the active network roster.
    AddAdmin(UpdateRosterArgs),
    /// Remove one or more admins from the active network roster.
    RemoveAdmin(UpdateRosterArgs),
    /// Ping a peer by node ID or tunnel IP.
    Ping(PingArgs),
    /// Diagnose runtime/network issues and optionally write a support bundle.
    Doctor(DoctorArgs),
    /// Show local or peer tunnel IPs.
    Ip(IpArgs),
    /// Resolve a node/tunnel IP to peer metadata.
    Whois(WhoisArgs),
    /// Probe a WireGuard upstream config (Mullvad/Proton-style) by running
    /// the userspace WG state machine against it and reporting whether
    /// the handshake completes. Without --replace-default or --scoped-host,
    /// this does not create a tun device and does not modify routes.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    WgUpstreamTest(WgUpstreamTestArgs),
    /// Internal config import helper for elevated GUI writes.
    #[command(hide = true)]
    ApplyConfig(ApplyConfigArgs),
    /// Internal daemon-backed config import helper for GUI writes.
    #[command(hide = true)]
    ApplyConfigDaemon(ApplyConfigArgs),
    /// Internal daemon entrypoint. Use `nvpn start --daemon`.
    #[command(hide = true)]
    Daemon(DaemonArgs),
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Debug, Args)]
struct WgUpstreamTestArgs {
    /// Path to a WireGuard config file (the same `[Interface]` /
    /// `[Peer]` syntax wg-quick / Mullvad / Proton VPN export).
    #[arg(long)]
    config_file: PathBuf,
    /// Maximum time to wait for the WG handshake to complete.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
    /// If set, in addition to the handshake probe, bring up a userspace
    /// tun device, install a single host route to this IP via the tun
    /// (default route is **not** modified — the rest of the host's
    /// internet stays alive), wait for the WG handshake, ping the host
    /// through the tunnel, then tear everything back down. Requires
    /// root / sudo because it touches the tun and the routing table.
    #[arg(long, conflicts_with = "replace_default")]
    scoped_host: Option<std::net::IpAddr>,
    /// **DANGEROUS:** route ALL outbound traffic through the WG tunnel
    /// (Mullvad/Proton-style). Brings up the tun, runs the WG handshake
    /// FIRST, and only swaps the default route once we've confirmed the
    /// tunnel is live (so a misconfigured config can never take the
    /// host offline). The original default route + the WG-endpoint
    /// bypass are restored on Drop, even on panic / Ctrl-C. Requires
    /// root / sudo.
    #[arg(long, default_value_t = false)]
    replace_default: bool,
    /// Optional IP to ping through the tunnel for confidence after the
    /// handshake completes. Used by both `--scoped-host` (where it
    /// defaults to the scoped IP) and `--replace-default` (where it's
    /// any externally-reachable host, e.g. 1.1.1.1). When empty in
    /// `--replace-default` mode the command just holds the tunnel up
    /// for `--hold-secs` and then tears it down.
    #[arg(long)]
    probe_target: Option<std::net::IpAddr>,
    /// Number of pings to send to the probe target after the handshake.
    /// Ignored when neither `--scoped-host` nor a `--probe-target` is
    /// set.
    #[arg(long, default_value_t = 5)]
    ping_count: u8,
    /// After the data plane test completes, hold the tunnel up for
    /// this many seconds before tearing it down (lets you inspect
    /// routes / tcpdump from another shell).
    #[arg(long, default_value_t = 0)]
    hold_secs: u64,
    /// Override the tun device name. macOS picks utunN automatically
    /// when this is empty; Linux picks `nvpn-wg-test`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long)]
    tun_name: Option<String>,
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
struct UpdateArgs {
    /// Only check whether an update is available.
    #[arg(long)]
    check: bool,
    /// Select the native desktop app artifact instead of the nvpn CLI archive.
    #[arg(long)]
    app: bool,
    /// Download the selected artifact and print/save it, without installing it.
    #[arg(long)]
    download_only: bool,
    /// Directory for --download-only artifacts.
    #[arg(long)]
    download_dir: Option<PathBuf>,
    /// Emit machine-readable JSON for GUI update helpers.
    #[arg(long)]
    json: bool,
    /// Destination binary to update (defaults to the currently running executable).
    #[arg(long)]
    path: Option<PathBuf>,
    /// Install even when the latest release is not newer than this binary.
    #[arg(long)]
    force: bool,
    /// Release manifest source to query.
    #[arg(long, value_enum, default_value = "auto")]
    source: UpdateSource,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum UpdateSource {
    Auto,
    Github,
    #[value(alias = "htree")]
    Hashtree,
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
    #[arg(long, alias = "announce-interval-secs", default_value_t = 20)]
    mesh_refresh_interval_secs: u64,
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
    #[arg(long, hide = true)]
    skip_binary_version: bool,
}

#[derive(Debug, Args)]
struct ServiceControlArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 20)]
    mesh_refresh_interval_secs: u64,
}

#[derive(Debug, Args, Clone)]
struct DaemonArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 20)]
    mesh_refresh_interval_secs: u64,
    #[arg(long, hide = true, default_value_t = false)]
    paused: bool,
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
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 20)]
    mesh_refresh_interval_secs: u64,
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
struct StatusArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long, hide = true, default_value_t = 2)]
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
    node_name: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    tunnel_ip: Option<String>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    exit_node: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    exit_node_leak_protection: Option<bool>,
    #[arg(long)]
    advertise_routes: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    advertise_exit_node: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    wireguard_exit_enabled: Option<bool>,
    #[arg(long)]
    wireguard_exit_interface: Option<String>,
    #[arg(long)]
    wireguard_exit_address: Option<String>,
    #[arg(long)]
    wireguard_exit_private_key: Option<String>,
    #[arg(long)]
    wireguard_exit_peer_public_key: Option<String>,
    #[arg(long)]
    wireguard_exit_peer_preshared_key: Option<String>,
    #[arg(long)]
    wireguard_exit_endpoint: Option<String>,
    #[arg(long)]
    wireguard_exit_allowed_ips: Option<String>,
    #[arg(long)]
    wireguard_exit_dns: Option<String>,
    #[arg(long)]
    wireguard_exit_mtu: Option<u16>,
    #[arg(long)]
    wireguard_exit_keepalive: Option<u16>,
    #[arg(long)]
    wireguard_exit_config: Option<String>,
    #[arg(long)]
    wireguard_exit_config_file: Option<PathBuf>,
    #[arg(long)]
    autoconnect: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    join_requests_enabled: Option<bool>,
    #[arg(
        long = "fips-advertise-public-endpoint",
        alias = "fips-advertise-endpoint",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    fips_advertise_public_endpoint: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    fips_host_tunnel_enabled: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    connect_to_non_roster_fips_peers: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    fips_nostr_discovery_enabled: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    fips_bootstrap_enabled: Option<bool>,
    #[arg(long)]
    fips_host_inbound_tcp_ports: Option<String>,
    #[arg(long = "fips-peer-endpoint")]
    fips_peer_endpoints: Vec<String>,
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
struct InviteBroadcastArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// How long to keep broadcasting before exiting. Defaults to 15 minutes,
    /// matching the GUI's broadcast window.
    #[arg(long, value_name = "SECS")]
    duration_secs: Option<u64>,
}

#[derive(Debug, Args)]
struct DiscoverArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Stop listening after this many seconds (default: keep listening until
    /// Ctrl-C, or until the first invite when `--accept` is set).
    #[arg(long, value_name = "SECS")]
    duration_secs: Option<u64>,
    /// Import the first valid invite seen and exit. Equivalent to piping the
    /// discovered code through `nvpn import-invite`.
    #[arg(long)]
    accept: bool,
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
    #[arg(long, hide = true, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long, default_value_t = 3)]
    count: u32,
    #[arg(long, default_value_t = 2)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
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
    #[arg(long, hide = true, default_value_t = 2)]
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
    #[arg(long, hide = true, default_value_t = 2)]
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

fn main() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "warn,nostr_relay_pool=off,boringtun::noise::timers=error",
        )
    });
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();
    run_cli(cli)
}

fn run_cli(cli: Cli) -> Result<()> {
    match cli.command {
        #[cfg(target_os = "windows")]
        Command::Daemon(args) if args.service => run_windows_service_dispatcher(args),
        command => run_command_on_runtime(command),
    }
}

fn run_command_on_runtime(command: Command) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let handle = thread::Builder::new()
            .name("nvpn-runtime".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || run_command_with_runtime(command))
            .context("failed to spawn nvpn runtime thread")?;
        handle.join().map_err(|panic| {
            if let Some(message) = panic.downcast_ref::<&str>() {
                anyhow!("nvpn runtime thread panicked: {message}")
            } else if let Some(message) = panic.downcast_ref::<String>() {
                anyhow!("nvpn runtime thread panicked: {message}")
            } else {
                anyhow!("nvpn runtime thread panicked")
            }
        })?
    }

    #[cfg(not(target_os = "windows"))]
    {
        run_command_with_runtime(command)
    }
}

fn run_command_with_runtime(command: Command) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    runtime.block_on(run_command(command))
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
        Command::Version(args) => {
            print_version(args)?;
        }
        Command::Update(args) => {
            updater::run_update(args).await?;
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
            connect_vpn(args).await?;
        }
        Command::Status(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let daemon = daemon_status(&config_path)?;

            let daemon_peers: Option<Vec<DaemonPeerState>> = if daemon.running {
                daemon.state.as_ref().map(|state| {
                    state
                        .peers
                        .iter()
                        .filter(|peer| {
                            !peer.node_id.is_empty()
                                || !peer.tunnel_ip.is_empty()
                                || !peer.endpoint.is_empty()
                        })
                        .cloned()
                        .collect()
                })
            } else {
                None
            };

            let (peers, expected_peers, peer_count, mesh_ready, status_source) =
                if let Some(daemon_peers) = daemon_peers.as_ref() {
                    let state = daemon.state.as_ref().expect("daemon peers implies state");
                    let peers = daemon_peers
                        .iter()
                        .map(|peer| PeerAnnouncement {
                            node_id: if peer.node_id.is_empty() {
                                peer.participant_pubkey.clone()
                            } else {
                                peer.node_id.clone()
                            },
                            public_key: peer.public_key.clone(),
                            endpoint: peer.endpoint.clone(),
                            local_endpoint: None,
                            public_endpoint: None,
                            tunnel_ip: peer.tunnel_ip.clone(),
                            advertised_routes: peer.advertised_routes.clone(),
                            timestamp: peer.last_mesh_seen_at,
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
                    let peers = configured_fips_peer_announcements(&app, &network_id);
                    let expected = expected_peer_count(&app);
                    (peers, expected, 0, false, "config")
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
                        "tunnel_ip": runtime_local_tunnel_ip(&app, &network_id),
                        "endpoint": endpoint,
                        "configured_endpoint": app.node.endpoint,
                        "listen_port": listen_port,
                        "configured_listen_port": app.node.listen_port,
                        "exit_node": if app.exit_node.is_empty() {
                            None::<String>
                        } else {
                            Some(app.exit_node.clone())
                        },
                        "exit_node_leak_protection": app.exit_node_leak_protection,
                        "advertise_exit_node": app.node.advertise_exit_node,
                        "advertised_routes": app.node.advertised_routes,
                        "effective_advertised_routes": runtime_effective_advertised_routes(&app),
                        "fips_host_tunnel_enabled": app.fips_host_tunnel_enabled,
                        "connect_to_non_roster_fips_peers": app.connect_to_non_roster_fips_peers,
                        "fips_nostr_discovery_enabled": app.fips_nostr_discovery_enabled,
                        "fips_bootstrap_enabled": app.fips_bootstrap_enabled,
                        "fips_host_inbound_tcp_ports": app.fips_host_inbound_tcp_ports,
                        "wireguard_exit": wireguard_exit_status_json(&app),
                        "daemon": daemon_status_json_value(&daemon),
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
                println!("tunnel_ip: {}", runtime_local_tunnel_ip(&app, &network_id));
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
                println!(
                    "exit_node_leak_protection: {}",
                    app.exit_node_leak_protection
                );
                println!("advertise_exit_node: {}", app.node.advertise_exit_node);
                println!("fips_host_tunnel_enabled: {}", app.fips_host_tunnel_enabled);
                println!(
                    "connect_to_non_roster_fips_peers: {}",
                    app.connect_to_non_roster_fips_peers
                );
                println!(
                    "fips_nostr_discovery_enabled: {}",
                    app.fips_nostr_discovery_enabled
                );
                println!("fips_bootstrap_enabled: {}", app.fips_bootstrap_enabled);
                if !app.fips_host_inbound_tcp_ports.is_empty() {
                    println!(
                        "fips_host_inbound_tcp_ports: {}",
                        app.fips_host_inbound_tcp_ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
                println!(
                    "wireguard_exit: {}",
                    if app.wireguard_exit.enabled {
                        if app.wireguard_exit.configured() {
                            "enabled"
                        } else {
                            "enabled (incomplete)"
                        }
                    } else {
                        "disabled"
                    }
                );
                if app.wireguard_exit.enabled {
                    println!("wireguard_exit_interface: {}", app.wireguard_exit.interface);
                    println!("wireguard_exit_address: {}", app.wireguard_exit.address);
                    println!("wireguard_exit_endpoint: {}", app.wireguard_exit.endpoint);
                }
                let effective_routes = runtime_effective_advertised_routes(&app);
                if effective_routes.is_empty() {
                    println!("advertised_routes: none");
                } else {
                    println!("advertised_routes: {}", effective_routes.join(", "));
                }
                if daemon.running {
                    println!("daemon: running (pid {})", daemon.pid.unwrap_or_default());
                    if let Some(state) = daemon.state.as_ref() {
                        println!("vpn_status: {}", state.vpn_status);
                    }
                } else {
                    println!("daemon: stopped");
                }
                println!("status_source: {status_source}");
                if expected_peers > 0 {
                    println!("mesh_progress: {}/{}", peer_count, expected_peers);
                    println!("mesh_ready: {mesh_ready}");
                }
                if let Some(daemon_peers) = daemon_peers.as_ref() {
                    let reachable_count = daemon_peers.iter().filter(|p| p.reachable).count();
                    println!(
                        "peers: {} total, {reachable_count} reachable",
                        daemon_peers.len()
                    );
                    let now = unix_timestamp();
                    for peer in daemon_peers {
                        print_daemon_peer_line(peer, now);
                    }
                } else {
                    println!("peers: {}", peers.len());
                    for peer in &peers {
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
        }
        Command::Set(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;

            if let Some(value) = args.network_id {
                app.set_active_network_id(&value)?;
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
            if let Some(value) = args.exit_node_leak_protection {
                app.exit_node_leak_protection = value;
            }
            if let Some(value) = args.advertise_routes {
                app.node.advertised_routes = parse_advertised_routes_arg(&value)?;
            }
            if let Some(value) = args.advertise_exit_node {
                app.node.advertise_exit_node = value;
            }
            if let Some(value) = args.wireguard_exit_enabled {
                app.wireguard_exit.enabled = value;
            }
            if args.wireguard_exit_config.is_some() && args.wireguard_exit_config_file.is_some() {
                return Err(anyhow!(
                    "use either --wireguard-exit-config or --wireguard-exit-config-file, not both"
                ));
            }
            if let Some(value) = args.wireguard_exit_config {
                let enabled = app.wireguard_exit.enabled;
                let mut parsed = parse_wireguard_exit_config(&value)?;
                parsed.enabled = enabled;
                app.wireguard_exit = parsed;
            }
            if let Some(path) = args.wireguard_exit_config_file {
                let value = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read WireGuard config {}", path.display())
                })?;
                let enabled = app.wireguard_exit.enabled;
                let mut parsed = parse_wireguard_exit_config(&value)?;
                parsed.enabled = enabled;
                app.wireguard_exit = parsed;
            }
            if let Some(value) = args.wireguard_exit_interface {
                app.wireguard_exit.interface = value;
            }
            if let Some(value) = args.wireguard_exit_address {
                app.wireguard_exit.address = value;
            }
            if let Some(value) = args.wireguard_exit_private_key {
                app.wireguard_exit.private_key = value;
            }
            if let Some(value) = args.wireguard_exit_peer_public_key {
                app.wireguard_exit.peer_public_key = value;
            }
            if let Some(value) = args.wireguard_exit_peer_preshared_key {
                app.wireguard_exit.peer_preshared_key = value;
            }
            if let Some(value) = args.wireguard_exit_endpoint {
                app.wireguard_exit.endpoint = value;
            }
            if let Some(value) = args.wireguard_exit_allowed_ips {
                app.wireguard_exit.allowed_ips = parse_advertised_routes_arg(&value)?;
            }
            if let Some(value) = args.wireguard_exit_dns {
                app.wireguard_exit.dns = parse_csv_arg(&value);
            }
            if let Some(value) = args.wireguard_exit_mtu {
                app.wireguard_exit.mtu = value;
            }
            if let Some(value) = args.wireguard_exit_keepalive {
                app.wireguard_exit.persistent_keepalive_secs = value;
            }
            if let Some(value) = args.autoconnect {
                app.autoconnect = value;
            }
            if let Some(value) = args.join_requests_enabled {
                let network_id = app
                    .active_network_opt()
                    .ok_or_else(|| anyhow!("activate a network before changing join requests"))?
                    .id
                    .clone();
                app.set_network_join_requests_enabled(&network_id, value)?;
            }
            if let Some(value) = args.fips_advertise_public_endpoint {
                app.fips_advertise_public_endpoint = value;
            }
            if let Some(value) = args.fips_host_tunnel_enabled {
                app.fips_host_tunnel_enabled = value;
            }
            if let Some(value) = args.connect_to_non_roster_fips_peers {
                app.connect_to_non_roster_fips_peers = value;
            }
            if let Some(value) = args.fips_nostr_discovery_enabled {
                app.fips_nostr_discovery_enabled = value;
            }
            if let Some(value) = args.fips_bootstrap_enabled {
                app.fips_bootstrap_enabled = value;
            }
            if let Some(value) = args.fips_host_inbound_tcp_ports {
                app.fips_host_inbound_tcp_ports = parse_tcp_ports_arg(&value)?;
            }
            if !args.fips_peer_endpoints.is_empty() {
                app.fips_peer_endpoints = parse_fips_peer_endpoint_args(&args.fips_peer_endpoints)?;
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
            let join_request_queued = queue_active_network_join_request(&mut app)?;
            app.ensure_defaults();
            maybe_autoconfigure_node(&mut app);
            app.save(&config_path)?;
            maybe_reload_running_daemon(&config_path);

            if args.json {
                println!("{}", serde_json::to_string_pretty(&app)?);
            } else {
                println!("saved {}", config_path.display());
                println!("network_id={}", app.effective_network_id());
                println!("invite_imported={}", app.active_network().name);
                println!("join_request_queued={join_request_queued}");
            }
        }
        Command::InviteBroadcast(args) => {
            run_invite_broadcast(args)?;
        }
        Command::Discover(args) => {
            run_discover(args)?;
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
        Command::Ping(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let peers = configured_fips_peer_announcements(&app, &network_id);

            let target = resolve_ping_target(&args.target, &peers).ok_or_else(|| {
                anyhow!("target '{}' did not match an IP or known peer", args.target)
            })?;

            run_ping(&target, args.count, args.timeout_secs)?;
        }
        Command::Doctor(args) => {
            run_doctor(args).await?;
        }
        Command::Ip(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;

            if !args.peer {
                let tunnel_ip = runtime_local_tunnel_ip(&app, &network_id);
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "node_id": app.node.id,
                            "tunnel_ip": tunnel_ip,
                            "ip": strip_cidr(&tunnel_ip),
                        }))?
                    );
                } else {
                    println!("{}", strip_cidr(&tunnel_ip));
                }
            } else {
                let peer_ips = runtime_peer_tunnel_ips(&app, &network_id);
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&peer_ips)?);
                } else {
                    for ip in peer_ips {
                        println!("{}", strip_cidr(&ip));
                    }
                }
            }
        }
        Command::Whois(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let peers = configured_fips_peer_announcements(&app, &network_id);

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
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Command::WgUpstreamTest(args) => {
            run_wg_upstream_test(args).await?;
        }
        Command::ApplyConfig(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            apply_config_file(&args.source, &config_path)?;
        }
        Command::ApplyConfigDaemon(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            apply_config_via_running_daemon(&args.source, &config_path)?;
        }
        Command::Daemon(args) => daemon_vpn(args).await?,
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_wg_upstream_test(args: WgUpstreamTestArgs) -> Result<()> {
    use std::time::Duration;

    let raw = std::fs::read_to_string(&args.config_file)
        .with_context(|| format!("read WG config file {}", args.config_file.display()))?;
    let cfg = parse_wireguard_exit_config(&raw)
        .with_context(|| format!("parse WG config file {}", args.config_file.display()))?;

    let timeout = Duration::from_secs(args.timeout_secs);

    if args.replace_default {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return run_wg_upstream_replace_default(&cfg, &args, timeout).await;
        #[cfg(target_os = "windows")]
        return run_wg_upstream_windows_replace_default(&cfg, &args, timeout).await;
    }

    if let Some(scoped_host) = args.scoped_host {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return run_wg_upstream_scoped_host(&cfg, &args, timeout, scoped_host).await;

        #[cfg(target_os = "windows")]
        return run_wg_upstream_windows_scoped_host(&cfg, &args, timeout, scoped_host).await;
    }

    run_wg_upstream_handshake_only(&cfg, timeout, args.timeout_secs).await
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_wg_upstream_handshake_only(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    timeout: std::time::Duration,
    timeout_secs: u64,
) -> Result<()> {
    use crate::wg_upstream_runtime::WgUpstreamRuntime;

    let runtime = WgUpstreamRuntime::start_handshake_only(cfg)
        .await
        .context("start userspace WG runtime")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");
    let ok = runtime.wait_for_handshake(timeout).await;
    runtime.shutdown().await;
    if ok {
        println!("wg-upstream-test: handshake completed");
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {timeout_secs}s"
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_wg_upstream_scoped_host(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
    scoped_host: std::net::IpAddr,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_scoped_host_route;
    use boringtun::device::tun::TunSocket;
    use std::sync::Arc;
    use std::time::Duration;

    // Scoped-host mode: bring up a tun, install a single host route
    // through it, then send real pings through the WG tunnel.
    // Refuse to scope the upstream endpoint itself — that would make
    // the encrypted UDP loop back into the WG iface and never escape.
    if let Some(endpoint_host) = cfg.endpoint.split(':').next()
        && let Ok(endpoint_ip) = endpoint_host.parse::<std::net::IpAddr>()
        && endpoint_ip == scoped_host
    {
        return Err(anyhow!(
            "--scoped-host {scoped_host} matches the WG upstream endpoint; \
             that would route the encrypted UDP back into the tunnel"
        ));
    }

    let tun_name = args
        .tun_name
        .clone()
        .unwrap_or_else(default_wg_test_tun_name);
    let tun = TunSocket::new(&tun_name)
        .with_context(|| format!("create tun device {tun_name}"))?
        .set_non_blocking()
        .context("set tun non-blocking")?;
    let actual_iface = tun
        .name()
        .context("read assigned tun interface name (probably needs root)")?;
    let tun = Arc::new(tun);

    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    let _route = apply_scoped_host_route(&actual_iface, &cfg.address, scoped_host, mtu)
        .with_context(|| {
            format!(
                "install scoped host route for {scoped_host} via {actual_iface} \
                 (probably needs root)"
            )
        })?;
    println!(
        "wg-upstream-test: tun {actual_iface} up at {} mtu {mtu}, \
         host route {scoped_host} via {actual_iface} installed",
        cfg.address.trim_end_matches("/32")
    );

    let runtime = crate::wg_upstream_runtime::start_wg_runtime_with_posix_tun(cfg, tun.clone())
        .await
        .context("start userspace WG runtime with tun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    let handshake_ok = runtime.wait_for_handshake(timeout).await;
    if !handshake_ok {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, pinging {scoped_host}…");

    let mut ping = tokio::process::Command::new("ping");
    ping.arg("-c").arg(args.ping_count.to_string());
    #[cfg(target_os = "linux")]
    ping.arg("-W").arg("2");
    #[cfg(target_os = "macos")]
    ping.arg("-W").arg("2000"); // macOS ping -W is in milliseconds
    ping.arg(scoped_host.to_string());
    let status = ping.status().await.context("spawn ping")?;
    let ping_ok = status.success();

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding tunnel up for {}s…",
            args.hold_secs
        );
        tokio::time::sleep(Duration::from_secs(args.hold_secs)).await;
    }

    runtime.shutdown().await;
    drop(_route);
    // tun (Arc<TunSocket>) drops here when the last ref goes; on macOS
    // closing the utun fd auto-removes the device. Linux's tun device
    // hangs around if anyone else has it open, so name collisions on a
    // re-run will surface as ENXIO from TunSocket::new.

    if ping_ok {
        println!(
            "wg-upstream-test: pinged {scoped_host} successfully through {actual_iface} \
             via WG upstream {upstream}"
        );
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: ping {scoped_host} failed (handshake completed, \
             but no replies came back through the tunnel)"
        ))
    }
}

#[cfg(target_os = "windows")]
async fn run_wg_upstream_windows_scoped_host(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
    scoped_host: std::net::IpAddr,
) -> Result<()> {
    use crate::wg_upstream_runtime::{
        apply_windows_scoped_host_route, start_wg_runtime_with_wintun,
    };
    use std::sync::Arc;
    use std::time::Duration;

    if let Some(endpoint_host) = cfg.endpoint.split(':').next()
        && let Ok(endpoint_ip) = endpoint_host.parse::<std::net::IpAddr>()
        && endpoint_ip == scoped_host
    {
        return Err(anyhow!(
            "--scoped-host {scoped_host} matches the WG upstream endpoint; \
             that would route the encrypted UDP back into the tunnel"
        ));
    }

    let adapter_name = if cfg.interface.trim().is_empty() {
        "nvpn-wg-test".to_string()
    } else {
        cfg.interface.clone()
    };
    let wintun = nostr_vpn_wintun::load_wintun().context("load wintun.dll for WG upstream test")?;
    let adapter = wintun::Adapter::open(&wintun, &adapter_name)
        .or_else(|_| wintun::Adapter::create(&wintun, &adapter_name, "NostrVPN", None))
        .with_context(|| format!("open or create wintun adapter {adapter_name}"))?;

    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    adapter
        .set_mtu(mtu as usize)
        .with_context(|| format!("set MTU on wintun adapter {adapter_name}"))?;
    let parsed_address = crate::windows_tunnel::windows_interface_address(&cfg.address)?;
    adapter
        .set_network_addresses_tuple(
            parsed_address.address.into(),
            parsed_address.mask.into(),
            None,
        )
        .with_context(|| format!("set address on wintun adapter {adapter_name}"))?;
    let interface_index = adapter
        .get_adapter_index()
        .with_context(|| format!("read interface index for {adapter_name}"))?;
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .with_context(|| format!("start wintun session for {adapter_name}"))?,
    );
    let _route =
        apply_windows_scoped_host_route(interface_index, scoped_host).with_context(|| {
            format!(
                "install scoped host route for {scoped_host} via {adapter_name} \
             (probably needs Administrator)"
            )
        })?;
    println!(
        "wg-upstream-test: wintun {adapter_name} up at {} mtu {mtu}, \
         host route {scoped_host} via interface {interface_index} installed",
        cfg.address.trim_end_matches("/32")
    );

    let runtime = start_wg_runtime_with_wintun(cfg, session.clone())
        .await
        .context("start userspace WG runtime on wintun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    if !runtime.wait_for_handshake(timeout).await {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, pinging {scoped_host}...");

    let mut ping = tokio::process::Command::new("ping");
    ping.arg("-n")
        .arg(args.ping_count.to_string())
        .arg("-w")
        .arg("3000")
        .arg(scoped_host.to_string());
    let status = match ping.status().await.context("spawn ping") {
        Ok(status) => status,
        Err(error) => {
            runtime.shutdown().await;
            return Err(error);
        }
    };
    let ping_ok = status.success();

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding tunnel up for {}s - Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    runtime.shutdown().await;
    drop(_route);

    if ping_ok {
        println!(
            "wg-upstream-test: pinged {scoped_host} successfully through {adapter_name} \
             via WG upstream {upstream}"
        );
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: ping {scoped_host} failed (handshake completed, \
             but no replies came back through the tunnel)"
        ))
    }
}

#[cfg(target_os = "windows")]
async fn run_wg_upstream_windows_replace_default(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_daemon_wg_upstream;
    use std::time::Duration;

    let handle = apply_daemon_wg_upstream(cfg, timeout)
        .await
        .context("bring up Windows WG upstream and swap default route")?;
    println!(
        "wg-upstream-test: handshake completed, default route now via {}, upstream {}",
        handle.iface,
        handle.upstream.ip()
    );

    let probe_result = if let Some(probe) = args.probe_target {
        let mut result = Ok(false);
        for attempt in 1..=3 {
            if attempt > 1 {
                println!("wg-upstream-test: retrying probe ping through the WG tunnel...");
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                println!("wg-upstream-test: pinging {probe} through the WG tunnel...");
            }
            let mut ping = tokio::process::Command::new("ping");
            ping.arg("-n")
                .arg(args.ping_count.to_string())
                .arg("-w")
                .arg("3000")
                .arg(probe.to_string());
            let status = match ping.status().await.context("spawn ping") {
                Ok(status) => status,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            };
            if status.success() {
                result = Ok(true);
                break;
            }
        }
        result
    } else {
        Ok(true)
    };

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding the tunnel up for {}s - Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    handle.cleanup().await;

    if !probe_result? {
        return Err(anyhow!(
            "wg-upstream-test: probe ping failed (handshake completed and \
             default route swapped, but no replies came back through the tunnel)"
        ));
    }
    println!(
        "wg-upstream-test: Windows full default-route mode worked end-to-end. \
         Default route restored."
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_wg_upstream_replace_default(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_full_default_route;
    use boringtun::device::tun::TunSocket;
    use std::sync::Arc;
    use std::time::Duration;

    // 1. Bring up the tun. No routing impact yet — the host is fine
    // even if the WG handshake fails.
    let tun_name = args
        .tun_name
        .clone()
        .unwrap_or_else(default_wg_test_tun_name);
    let tun = TunSocket::new(&tun_name)
        .with_context(|| format!("create tun device {tun_name}"))?
        .set_non_blocking()
        .context("set tun non-blocking")?;
    let actual_iface = tun
        .name()
        .context("read assigned tun interface name (probably needs root)")?;
    let tun = Arc::new(tun);

    // 2. Start the WG runtime against the upstream. The first packet
    // from the runtime is the handshake init; until we wait for it
    // there's no proof the upstream is reachable / our config is
    // valid.
    let runtime = crate::wg_upstream_runtime::start_wg_runtime_with_posix_tun(cfg, tun.clone())
        .await
        .context("start userspace WG runtime with tun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    // 3. Watchdog. wait_for_handshake yields on a Notify; if no
    // handshake by the deadline, we shut down without ever touching
    // the routing table. The host's internet stays up.
    let handshake_ok = runtime.wait_for_handshake(timeout).await;
    if !handshake_ok {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s; \
             routing table NOT modified",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, swapping default route…");

    // 4. Now and only now do we swap the default route. The returned
    // guard restores the original default + deletes the bypass on
    // Drop, so a panic / Ctrl-C from this point on still recovers.
    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    let mut full_route = apply_full_default_route(&actual_iface, &cfg.address, upstream, mtu, &[])
        .with_context(|| {
            format!(
                "swap default route via {actual_iface} (probably needs root). \
                 If you see 'Network is unreachable' below, the original default \
                 was already restored — your internet should be back."
            )
        })?;
    println!(
        "wg-upstream-test: default route now via {actual_iface}, bypass for {} via captured underlay",
        upstream.ip()
    );

    // 5. Optional probe — verify data plane round-trips through WG.
    let probe_ok = if let Some(probe) = args.probe_target {
        println!("wg-upstream-test: pinging {probe} through the WG tunnel…");
        let mut ping = tokio::process::Command::new("ping");
        ping.arg("-c").arg(args.ping_count.to_string());
        #[cfg(target_os = "linux")]
        ping.arg("-W").arg("2");
        #[cfg(target_os = "macos")]
        ping.arg("-W").arg("2000");
        ping.arg(probe.to_string());
        let status = ping.status().await.context("spawn ping")?;
        status.success()
    } else {
        true
    };

    // 6. Hold the tunnel up so the user can curl ifconfig.me / inspect
    // routes / look in tcpdump. Wrap the sleep in a select! with
    // Ctrl-C so that interrupting the command still falls through to
    // the route-revert path below (rather than aborting the runtime
    // with the default route still pointed at the WG tun).
    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding the tunnel up for {}s — Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    // 7. Cleanup. Order matters here:
    //   a. Restore default route + delete bypass (FullDefaultRoute
    //      Drop). Critical to do this BEFORE the runtime stops, so the
    //      few seconds of "WG runtime stopping" don't have the kernel
    //      trying to push outgoing packets through a torn-down WG tun.
    //   b. Stop the runtime (closes UDP socket, the boringtun coordinator
    //      task exits).
    //   c. Drop the tun (utun auto-removes when its fd closes; Linux
    //      tun lingers but its routes are already gone).
    if let Err(error) = full_route.revert() {
        eprintln!("wg-upstream-test: WARNING — route revert failed: {error}");
    }
    drop(full_route);
    runtime.shutdown().await;
    drop(tun);

    if !probe_ok {
        return Err(anyhow!(
            "wg-upstream-test: probe ping failed (handshake completed and \
             default route swapped, but no replies came back through the tunnel)"
        ));
    }
    println!(
        "wg-upstream-test: full default-route mode worked end-to-end. \
         Default route restored."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_wg_test_tun_name() -> String {
    "nvpn-wg-test".to_string()
}

#[cfg(target_os = "macos")]
fn default_wg_test_tun_name() -> String {
    // boringtun's macOS TunSocket::new requires the name to start with
    // "utun". Plain "utun" tells the kernel to pick the next available
    // index; the actual assigned name is read back via tun.name().
    "utun".to_string()
}

pub(crate) fn runtime_exit_node_default_routes() -> Vec<String> {
    #[allow(unused_mut)]
    let mut routes = exit_node_default_routes();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        routes.retain(|route| route != "::/0");
    }
    #[cfg(all(
        not(target_os = "linux"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    {
        routes.retain(|route| !is_default_exit_node_route(route));
    }
    routes
}

pub(crate) fn runtime_effective_advertised_routes(app: &AppConfig) -> Vec<String> {
    #[allow(unused_mut)]
    let mut routes = app.effective_advertised_routes();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        routes.retain(|route| route != "::/0");
    }
    #[cfg(all(
        not(target_os = "linux"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    {
        routes.retain(|route| !is_default_exit_node_route(route));
    }
    routes
}

fn wireguard_exit_status_json(app: &AppConfig) -> serde_json::Value {
    json!({
        "enabled": app.wireguard_exit.enabled,
        "configured": app.wireguard_exit.configured(),
        "interface": &app.wireguard_exit.interface,
        "address": &app.wireguard_exit.address,
        "endpoint": &app.wireguard_exit.endpoint,
        "allowed_ips": &app.wireguard_exit.allowed_ips,
        "dns": &app.wireguard_exit.dns,
        "mtu": app.wireguard_exit.mtu,
        "persistent_keepalive_secs": app.wireguard_exit.persistent_keepalive_secs,
    })
}

fn runtime_local_tunnel_ip(app: &AppConfig, network_id: &str) -> String {
    if let Ok(own_pubkey) = app.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &own_pubkey)
    {
        return tunnel_ip;
    }
    app.node.tunnel_ip.clone()
}

fn runtime_peer_tunnel_ips(app: &AppConfig, network_id: &str) -> Vec<String> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut ips = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| derive_mesh_tunnel_ip(network_id, &participant))
        .collect::<Vec<_>>();
    ips.sort();
    ips.dedup();
    ips
}

fn configured_fips_peer_announcements(app: &AppConfig, network_id: &str) -> Vec<PeerAnnouncement> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut peers = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| {
            let tunnel_ip = derive_mesh_tunnel_ip(network_id, &participant)?;
            let node_id = app
                .magic_dns_name_for_participant(&participant)
                .or_else(|| app.peer_alias(&participant))
                .unwrap_or_else(|| participant.clone());
            Some(PeerAnnouncement {
                node_id,
                public_key: participant,
                endpoint: "fips".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip,
                advertised_routes: Vec::new(),
                timestamp: 0,
            })
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    peers
}

pub(crate) fn shared_roster_publish_allowed(
    app: &AppConfig,
    network_id: &str,
    own_pubkey: &str,
    signed_by: &str,
) -> bool {
    let Ok(own_pubkey) = normalize_nostr_pubkey(own_pubkey) else {
        return false;
    };
    if !app.is_network_admin(network_id, &own_pubkey) {
        return false;
    }

    let signed_by = normalize_nostr_pubkey(signed_by).unwrap_or_default();
    signed_by.is_empty() || signed_by == own_pubkey
}

fn network_roster_from_shared(shared: &SharedNetworkRoster) -> NetworkRoster {
    NetworkRoster {
        network_name: shared.name.clone(),
        participants: shared.participants.clone(),
        admins: shared.admins.clone(),
        aliases: shared.aliases.clone(),
        signed_at: if shared.updated_at > 0 {
            shared.updated_at
        } else {
            unix_timestamp()
        },
    }
}

fn signed_roster_matches_shared(
    signed_roster: &SignedRoster,
    shared: &SharedNetworkRoster,
) -> bool {
    let Ok(signed_network_id) = signed_roster.network_id() else {
        return false;
    };
    if normalize_runtime_network_id(&signed_network_id)
        != normalize_runtime_network_id(&shared.network_id)
    {
        return false;
    }

    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    let shared_signed_by = normalize_nostr_pubkey(&shared.signed_by).unwrap_or_default();
    if shared_signed_by.is_empty() || shared_signed_by != signed_by {
        return false;
    }

    let Ok(roster) = signed_roster.roster() else {
        return false;
    };
    roster == network_roster_from_shared(shared)
}

fn active_signed_roster_for_sync(
    app: &AppConfig,
    config_path: &Path,
    allow_forwarded: bool,
) -> Result<Option<SignedRoster>> {
    let Some(network) = app.active_network_opt() else {
        return Ok(None);
    };
    let shared = app.shared_network_roster(&network.id)?;
    let store_path = signed_rosters_file_path(config_path);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    if let Some(stored) = load_signed_rosters(&store_path)?
        .latest_for(&shared.network_id)
        .filter(|stored| signed_roster_matches_shared(stored, &shared))
        .filter(|stored| {
            allow_forwarded
                || own_pubkey.as_deref().is_some_and(|own_pubkey| {
                    stored.signer_pubkey_hex().ok().as_deref() == Some(own_pubkey)
                })
        })
        .cloned()
    {
        return Ok(Some(stored));
    }

    let Some(own_pubkey) = own_pubkey else {
        return Ok(None);
    };
    if !shared_roster_publish_allowed(app, &network.id, &own_pubkey, &shared.signed_by) {
        return Ok(None);
    }

    let signed_roster = SignedRoster::sign(
        &shared.network_id,
        network_roster_from_shared(&shared),
        &app.nostr_keys()?,
    )?;
    upsert_signed_roster(&store_path, signed_roster.clone())?;
    Ok(Some(signed_roster))
}

fn signed_roster_is_current_for_app(
    app: &AppConfig,
    network_id: &str,
    signed_roster: &SignedRoster,
) -> bool {
    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    app.networks.iter().any(|network| {
        normalize_runtime_network_id(&network.network_id)
            == normalize_runtime_network_id(network_id)
            && network.shared_roster_updated_at == signed_roster.signed_at()
            && normalize_nostr_pubkey(&network.shared_roster_signed_by)
                .is_ok_and(|value| value == signed_by)
    })
}

#[cfg(feature = "embedded-fips")]
const FIPS_ROSTER_RESEND_SECS: u64 = 10;

#[cfg(feature = "embedded-fips")]
#[derive(Default)]
struct FipsRosterSyncState {
    sent_by_peer: HashMap<String, FipsRosterSentState>,
}

#[cfg(feature = "embedded-fips")]
struct FipsRosterSentState {
    hash: String,
    sent_at: u64,
}

#[cfg(feature = "embedded-fips")]
async fn sync_fips_roster_with_connected_peers(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    state: &mut FipsRosterSyncState,
) -> Result<usize> {
    let Some(signed_roster) = active_signed_roster_for_sync(app, config_path, true)? else {
        return Ok(0);
    };
    let now = unix_timestamp();
    let roster_hash = signed_roster.content_hash();
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let roster_peers = app
        .active_network_signal_pubkeys_hex()
        .into_iter()
        .collect::<HashSet<_>>();
    let connected = runtime
        .peer_statuses()
        .into_iter()
        .filter(|status| status.connected)
        .filter(|status| own_pubkey.as_deref() != Some(status.pubkey.as_str()))
        .filter(|status| roster_peers.contains(&status.pubkey))
        .map(|status| status.pubkey)
        .collect::<HashSet<_>>();

    state
        .sent_by_peer
        .retain(|peer, _| connected.contains(peer));

    let mut sent = 0usize;
    for peer in connected {
        if state.sent_by_peer.get(&peer).is_some_and(|sent| {
            sent.hash == roster_hash && now.saturating_sub(sent.sent_at) < FIPS_ROSTER_RESEND_SECS
        }) {
            continue;
        }
        runtime.send_roster(&peer, signed_roster.clone()).await?;
        state.sent_by_peer.insert(
            peer,
            FipsRosterSentState {
                hash: roster_hash.clone(),
                sent_at: now,
            },
        );
        sent += 1;
    }
    Ok(sent)
}

#[cfg(all(
    not(target_os = "linux"),
    not(target_os = "macos"),
    not(target_os = "windows")
))]
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
    vpn_enabled: bool,
    vpn_active: bool,
    vpn_status: String,
    expected_peer_count: usize,
    connected_peer_count: usize,
    #[serde(default)]
    fips_direct_roster_peer_count: usize,
    #[serde(default)]
    fips_other_peer_count: usize,
    mesh_ready: bool,
    #[serde(default)]
    health: Vec<HealthIssue>,
    #[serde(default)]
    network: NetworkSummary,
    #[serde(default)]
    port_mapping: PortMappingStatus,
    #[serde(default)]
    relays: Vec<DaemonRelayState>,
    #[serde(default)]
    peers: Vec<DaemonPeerState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct DaemonRelayState {
    url: String,
    status: String,
}

#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct MacosNetworkCleanupState {
    #[serde(default)]
    iface: String,
    #[serde(default)]
    endpoint_bypass_routes: Vec<String>,
    #[serde(default)]
    managed_routes: Vec<MacosManagedRoute>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fips_endpoint_npub: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fips_transport_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fips_transport_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fips_srtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    fips_packets_sent: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    fips_packets_recv: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    fips_bytes_sent: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    fips_bytes_recv: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    direct_probe_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct_probe_after_ms: Option<u64>,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    rx_bytes: u64,
    public_key: String,
    advertised_routes: Vec<String>,
    last_mesh_seen_at: u64,
    last_fips_seen_at: Option<u64>,
    reachable: bool,
    last_handshake_at: Option<u64>,
    error: Option<String>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableFingerprint {
    len: u64,
    modified_unix_nanos: Option<u128>,
}

struct DaemonReloadConfig {
    app: AppConfig,
    network_id: String,
    expected_peers: usize,
    own_pubkey: Option<String>,
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

fn build_daemon_reload_config(app: AppConfig, network_id: String) -> DaemonReloadConfig {
    let expected_peers = expected_peer_count(&app);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();

    DaemonReloadConfig {
        app,
        network_id,
        expected_peers,
        own_pubkey,
    }
}

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
                    records.clone(),
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
            records,
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

    /// Rebuild MagicDNS records from the current `AppConfig` and push them
    /// to the in-process responder (and the `/etc/hosts` fallback block on
    /// Linux if it's active). Without this, the records map is frozen at
    /// daemon-start time and any peer added later (via `add-participant`,
    /// invite acceptance, FIPS roster event, or peer-alias rename) returns
    /// NXDOMAIN until the daemon is restarted.
    fn refresh_records(&self, app: &AppConfig) {
        let records = build_magic_dns_records(app);
        self.server.update_records(records.clone());
        #[cfg(target_os = "linux")]
        if !self.suffix.is_empty()
            && let Err(error) = nostr_vpn_core::magic_dns::refresh_linux_hosts_fallback_if_active(
                &self.suffix,
                &records,
            )
        {
            eprintln!("magicdns: failed to refresh hosts fallback: {error}");
        }
        let _ = records; // suppress unused-binding on non-Linux
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
    active_listen_port: Option<u16>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default)]
struct LinuxExitNodeRuntime {
    ipv4_outbound_iface: Option<String>,
    ipv6_outbound_iface: Option<String>,
    ipv4_tunnel_source_cidr: Option<String>,
    ipv4_mss_clamp: Option<u16>,
    ipv4_forward_was_enabled: Option<bool>,
    ipv6_forward_was_enabled: Option<bool>,
    wireguard_exit: Option<LinuxWireGuardExitRuntime>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Default)]
struct MacosExitNodeRuntime {
    outbound_iface: Option<String>,
    tunnel_source_cidr: Option<String>,
    pf_was_enabled: Option<bool>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxWireGuardExitRuntime {
    interface: String,
    source_cidr: String,
    table: u32,
    priority: u32,
    created_interface: bool,
    endpoint_bypass_routes: Vec<String>,
    previous_default_route: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct MacosRouteSpec {
    gateway: Option<String>,
    interface: String,
}

#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
struct MacosManagedRoute {
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
}

impl CliTunnelRuntime {
    fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            active_listen_port: None,
        }
    }

    fn stop(&mut self) {
        self.active_listen_port = None;
    }

    #[cfg(target_os = "macos")]
    fn macos_network_cleanup_state(&self) -> Option<MacosNetworkCleanupState> {
        None
    }

    fn listen_port(&self, configured: u16) -> u16 {
        self.active_listen_port.unwrap_or(configured)
    }

    pub(crate) fn owns_interface(&self, iface: &str) -> bool {
        self.iface == iface
    }
}

fn endpoint_with_listen_port(endpoint: &str, listen_port: u16) -> String {
    let trimmed = endpoint.trim();
    if let Ok(mut parsed) = trimmed.parse::<SocketAddr>() {
        parsed.set_port(listen_port);
        return parsed.to_string();
    }
    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return trimmed.to_string();
    };
    if host.is_empty() || host.contains(':') || port.trim().parse::<u16>().is_err() {
        return trimmed.to_string();
    }
    format!("{}:{listen_port}", host.trim())
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
    let detected_ipv4 = if endpoint_prefers_runtime_local_ipv4(&app.node.endpoint) {
        detect_runtime_primary_ipv4()
    } else {
        None
    };
    runtime_local_signal_endpoint(
        &app.node.endpoint,
        listen_port,
        runtime_signal_ipv4(detected_ipv4, &app.node.tunnel_ip),
    )
}

async fn refresh_port_mapping(
    app: &AppConfig,
    network_snapshot: &diagnostics::NetworkSnapshot,
    listen_port: u16,
    port_mapping_runtime: &mut PortMappingRuntime,
) {
    if !app.nat.enabled {
        port_mapping_runtime.stop().await;
        return;
    }

    let timeout = Duration::from_secs(app.nat.discovery_timeout_secs.max(1));
    if let Err(error) = port_mapping_runtime
        .refresh(network_snapshot, listen_port, timeout)
        .await
    {
        eprintln!("nat: port mapping refresh failed: {error}");
    }
}

fn network_probe_timeout(app: &AppConfig) -> Duration {
    Duration::from_secs(app.nat.discovery_timeout_secs.max(2))
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

#[cfg(target_os = "linux")]
fn is_exit_node_route(route: &str) -> bool {
    route == "0.0.0.0/0" || route == "::/0"
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn route_targets_require_endpoint_bypass(route_targets: &[String]) -> bool {
    route_targets
        .iter()
        .any(|route| !route_is_host_route(route))
}

fn daemon_vpn_active(vpn_enabled: bool, expected_peers: usize) -> bool {
    vpn_enabled && expected_peers > 0
}

fn daemon_start_vpn_enabled(app: &AppConfig, paused: bool) -> bool {
    app.autoconnect && !paused
}

fn fips_host_runtime_active(app: &AppConfig, vpn_enabled: bool) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        vpn_enabled && app.fips_host_tunnel_enabled
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (app, vpn_enabled);
        false
    }
}

fn fips_private_runtime_active(app: &AppConfig, vpn_enabled: bool, expected_peers: usize) -> bool {
    daemon_vpn_active(vpn_enabled, expected_peers)
        || fips_host_runtime_active(app, vpn_enabled)
        || app.join_requests_enabled()
        || app
            .active_network_opt()
            .and_then(|network| network.outbound_join_request.as_ref())
            .is_some()
        || app.has_fips_static_peer_endpoints()
}

fn daemon_vpn_idle_status(
    vpn_enabled: bool,
    expected_peers: usize,
    join_requests_active: bool,
) -> &'static str {
    if vpn_enabled && expected_peers == 0 {
        WAITING_FOR_PARTICIPANTS_STATUS
    } else if join_requests_active {
        LISTENING_FOR_JOIN_REQUESTS_STATUS
    } else {
        "Paused"
    }
}

#[derive(Clone, Copy, Debug)]
struct WallTimeJumpObserver {
    wall_observed_at: u64,
    monotonic_observed_at: Instant,
}

impl WallTimeJumpObserver {
    fn new(wall_observed_at: u64) -> Self {
        Self {
            wall_observed_at,
            monotonic_observed_at: Instant::now(),
        }
    }
}

fn wall_time_jump_detected(
    previous_wall_observed_at: u64,
    now_wall: u64,
    previous_monotonic_observed_at: Instant,
    now_monotonic: Instant,
    threshold_secs: u64,
) -> bool {
    if previous_wall_observed_at == 0 || threshold_secs == 0 {
        return false;
    }

    let wall_elapsed = now_wall.saturating_sub(previous_wall_observed_at);
    if wall_elapsed < threshold_secs {
        return false;
    }

    let monotonic_elapsed = now_monotonic
        .saturating_duration_since(previous_monotonic_observed_at)
        .as_secs();
    wall_elapsed.saturating_sub(monotonic_elapsed) >= threshold_secs
}

fn observe_wall_time_jump(
    last_observed_at: &mut WallTimeJumpObserver,
    now_wall: u64,
    now_monotonic: Instant,
    threshold_secs: u64,
) -> bool {
    let jumped = wall_time_jump_detected(
        last_observed_at.wall_observed_at,
        now_wall,
        last_observed_at.monotonic_observed_at,
        now_monotonic,
        threshold_secs,
    );
    last_observed_at.wall_observed_at = now_wall;
    last_observed_at.monotonic_observed_at = now_monotonic;
    jumped
}

#[allow(clippy::too_many_arguments)]
fn persist_inbound_join_request(
    app: &mut AppConfig,
    config_path: &Path,
    sender_pubkey: &str,
    requested_at: u64,
    network_id: &str,
    invite_secret: &str,
    requester_node_name: &str,
    vpn_status: &mut String,
) {
    match app.record_inbound_join_request(
        network_id,
        invite_secret,
        sender_pubkey,
        requester_node_name,
        requested_at,
    ) {
        Ok(Some(network_name)) => {
            if let Err(error) = app.save(config_path) {
                *vpn_status = format!("Failed to persist join request: {error}");
            } else {
                *vpn_status = format!("Join request received for {network_name}.");
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
    signed_roster: Option<&SignedRoster>,
    vpn_status: &mut String,
) -> Result<Option<String>> {
    let signed_roster =
        signed_roster.ok_or_else(|| anyhow!("FIPS roster frame is missing signed roster event"))?;
    let changed = app.apply_verified_admin_signed_shared_roster(signed_roster)?;
    let apply_network_id = signed_roster.network_id()?;
    if signed_roster_is_current_for_app(app, &apply_network_id, signed_roster) {
        upsert_signed_roster(
            &signed_rosters_file_path(config_path),
            signed_roster.clone(),
        )?;
    }
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
                == normalize_runtime_network_id(&apply_network_id)
        })
        .map(|network| network.name.clone())
        .unwrap_or_else(|| apply_network_id.to_string());
    *vpn_status = format!("Roster updated for {network_name}.");
    Ok(Some(network_name))
}

#[cfg(feature = "embedded-fips")]
fn drain_fips_mesh_events(
    runtime: &mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    vpn_status: &mut String,
) -> Result<bool> {
    let mut roster_changed = false;
    for event in runtime.drain_events() {
        match event {
            crate::fips_private_mesh::FipsPrivateMeshEvent::Packet(packet) => {
                let _ = packet.source_pubkey;
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::Presence {
                participant_pubkey,
                last_seen_at,
            } => {
                let _ = (participant_pubkey, last_seen_at);
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::JoinRequest {
                sender_pubkey,
                requested_at,
                request,
            } => {
                persist_inbound_join_request(
                    app,
                    config_path,
                    &sender_pubkey,
                    requested_at,
                    &request.network_id,
                    &request.invite_secret,
                    &request.requester_node_name,
                    vpn_status,
                );
            }
            crate::fips_private_mesh::FipsPrivateMeshEvent::Roster {
                sender_pubkey,
                signed_roster,
                ..
            } => match persist_shared_network_roster(
                app,
                config_path,
                signed_roster.as_deref(),
                vpn_status,
            ) {
                Ok(Some(_)) => roster_changed = true,
                Ok(None) => {}
                Err(error) => {
                    eprintln!("daemon: ignoring invalid FIPS roster from {sender_pubkey}: {error}");
                }
            },
            crate::fips_private_mesh::FipsPrivateMeshEvent::Capabilities {
                sender_pubkey,
                network_id,
                capabilities,
            } => {
                let _ = (sender_pubkey, network_id, capabilities);
                // The FIPS receive path records capabilities before queuing
                // this event. The daemon heartbeat applies fresh endpoint
                // hints with a signature guard, and the status tick reads
                // advertised routes from the same cache, so a capability frame
                // should not force a full FIPS config refresh by itself.
            }
        }
    }
    Ok(roster_changed)
}

#[cfg(feature = "embedded-fips")]
async fn refresh_fips_tunnel_config(
    runtime: &mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    network_id: &str,
    own_pubkey: Option<&str>,
) -> Result<()> {
    let config = fips_tunnel_config_from_app(
        app,
        network_id,
        runtime.iface().to_string(),
        own_pubkey,
        None,
        &runtime.peer_endpoint_hints(),
    )?;
    runtime.apply_config(config).await
}

#[cfg(feature = "embedded-fips")]
fn fips_tunnel_config_from_app(
    app: &AppConfig,
    network_id: &str,
    iface: impl Into<String>,
    own_pubkey: Option<&str>,
    recent_peers: Option<&nostr_vpn_core::recent_peers::RecentPeerEndpoints>,
    live_peer_endpoints: &[(String, Vec<(String, u64)>)],
) -> Result<crate::fips_private_mesh::FipsPrivateTunnelConfig> {
    let mut config = crate::fips_private_mesh::FipsPrivateTunnelConfig::from_app(
        app,
        network_id,
        iface,
        own_pubkey,
        recent_peers,
        live_peer_endpoints,
    )?;
    // Daemon no longer pre-discovers a public endpoint. fips-core's
    // build_overlay_advert performs its own STUN observation and advertises
    // <reflexive_ip>:<listen_port> directly; if that's wrong (e.g. symmetric
    // NAT), peers fall back to udp:nat traversal via Nostr signaling. Use
    // any operator-configured endpoint as a hint when set.
    let configured = endpoint_with_listen_port(&app.node.endpoint, config.listen_port);
    config.advertised_endpoint = if endpoint_is_local_only(&configured) {
        String::new()
    } else {
        configured
    };
    Ok(config)
}

#[cfg(feature = "embedded-fips")]
async fn sync_fips_private_runtime(
    runtime: &mut Option<crate::fips_private_mesh::FipsPrivateTunnelRuntime>,
    app: &AppConfig,
    network_id: &str,
    iface: &str,
    own_pubkey: Option<&str>,
    vpn_enabled: bool,
    expected_peers: usize,
) -> Result<()> {
    if !fips_private_runtime_active(app, vpn_enabled, expected_peers) {
        if let Some(runtime) = runtime.take() {
            runtime.stop().await?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !app.fips_host_tunnel_enabled {
            crate::fips_host_tunnel::FipsHostTunnelRuntime::cleanup_disabled_artifacts();
        }
        return Ok(());
    }

    let config_iface = runtime
        .as_ref()
        .map(|runtime| runtime.iface().to_string())
        .unwrap_or_else(|| iface.to_string());
    let live_peer_endpoints = runtime
        .as_ref()
        .map(|runtime| runtime.peer_endpoint_hints())
        .unwrap_or_default();
    let config = fips_tunnel_config_from_app(
        app,
        network_id,
        config_iface,
        own_pubkey,
        None,
        &live_peer_endpoints,
    )?;

    let restart = runtime
        .as_ref()
        .is_some_and(|existing| existing.requires_endpoint_restart(&config));
    if restart {
        if let Some(existing) = runtime.take() {
            existing.stop().await?;
        }
        let started = crate::fips_private_mesh::FipsPrivateTunnelRuntime::start(config).await?;
        eprintln!("daemon: restarted FIPS private mesh on {}", started.iface());
        *runtime = Some(started);
    } else if let Some(existing) = runtime.as_mut() {
        existing.apply_config(config).await?;
    } else {
        let started = crate::fips_private_mesh::FipsPrivateTunnelRuntime::start(config).await?;
        eprintln!("daemon: FIPS private mesh on {}", started.iface());
        *runtime = Some(started);
    }
    Ok(())
}

#[cfg(feature = "embedded-fips")]
async fn send_pending_fips_join_requests(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    sent_cache: &mut HashMap<String, u64>,
    now: u64,
) -> Result<usize> {
    let Some(network) = app.active_network_opt() else {
        return Ok(0);
    };
    let Some(pending) = network.outbound_join_request.as_ref() else {
        return Ok(0);
    };
    let recipients = pending_fips_join_request_recipients(app);
    if recipients.is_empty() {
        return Ok(0);
    }
    let request = MeshJoinRequest {
        network_id: normalize_runtime_network_id(&network.network_id),
        invite_secret: network.invite_secret.clone(),
        requester_node_name: app.node_name.trim().to_string(),
    };

    let mut sent = 0usize;
    for recipient in recipients {
        let fingerprint = format!(
            "{}:{recipient}:{}",
            request.network_id, pending.requested_at
        );
        if sent_cache
            .get(&fingerprint)
            .is_some_and(|last_sent| now.saturating_sub(*last_sent) < FIPS_JOIN_REQUEST_RETRY_SECS)
        {
            continue;
        }
        runtime
            .send_join_request(&recipient, pending.requested_at, request.clone())
            .await?;
        sent_cache.insert(fingerprint, now);
        sent += 1;
    }
    Ok(sent)
}

fn pending_fips_join_request_recipients(app: &AppConfig) -> Vec<String> {
    let Some(network) = app.active_network_opt() else {
        return Vec::new();
    };
    let Some(pending) = network.outbound_join_request.as_ref() else {
        return Vec::new();
    };
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut recipients = if network
        .admins
        .iter()
        .any(|admin| admin == &pending.recipient)
    {
        vec![pending.recipient.clone()]
    } else {
        network.admins.clone()
    };
    recipients.retain(|recipient| own_pubkey.as_deref() != Some(recipient.as_str()));
    recipients.sort();
    recipients.dedup();
    recipients
}

#[cfg(feature = "embedded-fips")]
async fn publish_fips_active_network_roster(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    pending_recipients: &mut HashSet<String>,
) -> Result<usize> {
    publish_fips_active_network_roster_to(runtime, app, config_path, &[], pending_recipients).await
}

#[cfg(feature = "embedded-fips")]
async fn broadcast_local_fips_capabilities(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
) -> Result<usize> {
    let Some(network) = app.active_network_opt() else {
        return Ok(0);
    };
    let advertised_routes = runtime_effective_advertised_routes(app);
    let local_ipv4_candidates =
        runtime_signal_ipv4_candidates(detect_runtime_primary_ipv4(), &app.node.tunnel_ip);
    let endpoint_hints = local_fips_endpoint_hints(app, local_ipv4_candidates);
    let desired_hint_recipients = desired_fips_endpoint_hint_recipients(app);
    let signed_at = unix_timestamp();
    let mut sent = 0usize;

    for participant in runtime.peer_pubkeys() {
        let capabilities = PeerCapabilities {
            advertised_routes: advertised_routes.clone(),
            endpoint_hints: if desired_hint_recipients.contains(&participant) {
                endpoint_hints.clone()
            } else {
                Vec::new()
            },
            signed_at,
        };
        if runtime
            .send_capabilities(&participant, &network.id, capabilities)
            .await
            .is_ok()
        {
            sent += 1;
        }
    }

    Ok(sent)
}

#[cfg(feature = "embedded-fips")]
fn local_fips_endpoint_hints(
    app: &AppConfig,
    local_ipv4_candidates: Vec<Ipv4Addr>,
) -> Vec<PeerEndpointHint> {
    let mut endpoints = Vec::new();

    let configured = endpoint_with_listen_port(&app.node.endpoint, app.node.listen_port);
    if endpoint_is_gossipable_direct_hint(&configured, true)
        && !endpoint_uses_tunnel_ip(&configured, &app.node.tunnel_ip)
    {
        endpoints.push(configured);
    }

    if app.lan_discovery_enabled {
        for ip in local_ipv4_candidates {
            if !ipv4_is_lan_endpoint_hint(ip) {
                continue;
            }
            endpoints.push(SocketAddrV4::new(ip, app.node.listen_port).to_string());
        }
    }

    endpoints.sort();
    endpoints.dedup();
    endpoints.into_iter().map(PeerEndpointHint::udp).collect()
}

#[cfg(feature = "embedded-fips")]
fn runtime_signal_ipv4_candidates(
    detected_ipv4: Option<Ipv4Addr>,
    tunnel_ip: &str,
) -> Vec<Ipv4Addr> {
    let tunnel_ipv4 = strip_cidr(tunnel_ip).parse::<Ipv4Addr>().ok();
    let mut ips = Vec::new();
    if let Some(ip) = runtime_signal_ipv4(detected_ipv4, tunnel_ip)
        && ipv4_is_lan_endpoint_hint(ip)
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

#[cfg(feature = "embedded-fips")]
fn endpoint_is_gossipable_direct_hint(endpoint: &str, allow_local: bool) -> bool {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        if parsed.port() == 0 || endpoint_hint_ip_is_unusable(parsed.ip()) {
            return false;
        }
        return allow_local || !endpoint_is_local_only(&parsed.to_string());
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
    allow_local || !endpoint_is_local_only(trimmed)
}

#[cfg(feature = "embedded-fips")]
fn endpoint_uses_tunnel_ip(endpoint: &str, tunnel_ip: &str) -> bool {
    let Ok(tunnel_ip) = strip_cidr(tunnel_ip).parse::<IpAddr>() else {
        return false;
    };
    endpoint_addr_ip(endpoint).is_some_and(|ip| ip == tunnel_ip)
}

#[cfg(feature = "embedded-fips")]
fn endpoint_addr_ip(endpoint: &str) -> Option<IpAddr> {
    let trimmed = endpoint.trim();
    if let Ok(parsed) = trimmed.parse::<SocketAddr>() {
        return Some(parsed.ip());
    }

    let (host, _) = trimmed.rsplit_once(':')?;
    host.trim().parse::<IpAddr>().ok()
}

#[cfg(feature = "embedded-fips")]
fn endpoint_hint_ip_is_unusable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ipv4_is_cgnat(ip)
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}

#[cfg(feature = "embedded-fips")]
fn ipv4_is_lan_endpoint_hint(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

#[cfg(feature = "embedded-fips")]
fn ipv4_is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

#[cfg(feature = "embedded-fips")]
fn desired_fips_endpoint_hint_recipients(app: &AppConfig) -> HashSet<String> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    app.participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| own_pubkey.as_deref() != Some(participant.as_str()))
        .collect()
}

#[cfg(feature = "embedded-fips")]
async fn publish_fips_active_network_roster_to(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    extra_recipients: &[String],
    pending_recipients: &mut HashSet<String>,
) -> Result<usize> {
    if app.active_network_opt().is_none() {
        return Ok(0);
    }
    let own_pubkey = match app.own_nostr_pubkey_hex() {
        Ok(pubkey) => pubkey,
        Err(_) => return Ok(0),
    };

    let Some(signed_roster) = active_signed_roster_for_sync(app, config_path, false)? else {
        return Ok(0);
    };
    let mut recipients = app.active_network_signal_pubkeys_hex();
    recipients.extend(extra_recipients.iter().cloned());
    recipients.extend(pending_recipients.drain());
    recipients.retain(|recipient| recipient != &own_pubkey);
    recipients.sort();
    recipients.dedup();

    let (ready_recipients, mut retry) = split_ready_fips_roster_recipients(recipients);
    let mut sent = 0usize;
    for recipient in ready_recipients {
        match runtime.send_roster(&recipient, signed_roster.clone()).await {
            Ok(()) => sent += 1,
            Err(error) => {
                eprintln!("fips: roster send to {recipient} failed: {error}");
                retry.insert(recipient);
            }
        }
    }
    *pending_recipients = retry;
    Ok(sent)
}

#[cfg(feature = "embedded-fips")]
fn split_ready_fips_roster_recipients(recipients: Vec<String>) -> (Vec<String>, HashSet<String>) {
    // Do not gate roster sends on nvpn presence. A stale-roster peer may drop
    // Ping/Pong from newly added peers as unknown until this signed roster
    // reaches it, while FIPS can still route/discover the control message.
    (recipients, HashSet::new())
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

#[cfg(test)]
const TEST_MACOS_EUID_SENTINEL: u32 = u32::MAX;
#[cfg(test)]
static TEST_MACOS_EUID_OVERRIDE: AtomicU32 = AtomicU32::new(TEST_MACOS_EUID_SENTINEL);
#[cfg(test)]
static TEST_MACOS_EUID_OVERRIDE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
static TEST_REPAIR_SAVED_NETWORK_STATE_CALLS: AtomicU32 = AtomicU32::new(0);
#[cfg(test)]
static TEST_REPAIR_SAVED_NETWORK_STATE_CALLS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn macos_euid_override_lock_for_test() -> &'static Mutex<()> {
    TEST_MACOS_EUID_OVERRIDE_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
pub(crate) fn repair_saved_network_state_call_lock_for_test() -> &'static Mutex<()> {
    TEST_REPAIR_SAVED_NETWORK_STATE_CALLS_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
pub(crate) fn set_macos_euid_override_for_test(value: Option<u32>) {
    TEST_MACOS_EUID_OVERRIDE.store(value.unwrap_or(TEST_MACOS_EUID_SENTINEL), Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn reset_repair_saved_network_state_call_count_for_test() {
    TEST_REPAIR_SAVED_NETWORK_STATE_CALLS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn repair_saved_network_state_call_count_for_test() -> u32 {
    TEST_REPAIR_SAVED_NETWORK_STATE_CALLS.load(Ordering::Relaxed)
}

#[cfg(any(target_os = "macos", test))]
fn macos_effective_uid() -> u32 {
    #[cfg(test)]
    {
        let override_uid = TEST_MACOS_EUID_OVERRIDE.load(Ordering::Relaxed);
        if override_uid != TEST_MACOS_EUID_SENTINEL {
            return override_uid;
        }
    }

    #[cfg(target_os = "macos")]
    {
        unsafe { libc::geteuid() as u32 }
    }

    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn ensure_macos_connect_privileges(config_path: &Path) -> Result<()> {
    if macos_effective_uid() == 0 {
        return Ok(());
    }

    Err(anyhow!(
        "macOS tunnel setup requires admin privileges (did you run with sudo?); run `sudo nvpn start --connect --config {}` for a one-off session or `sudo nvpn service install --config {}` to use the launchd service",
        config_path.display(),
        config_path.display()
    ))
}

async fn start_session(args: StartArgs) -> Result<()> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let (app, _network_id) = load_config_with_overrides(
        &config_path,
        args.network_id.clone(),
        args.participants.clone(),
    )?;
    if args.connect {
        persist_desired_daemon_vpn_enabled(&config_path, true)?;
    } else if args.no_connect {
        persist_desired_daemon_vpn_enabled(&config_path, false)?;
    }

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
        iface: args.iface,
        mesh_refresh_interval_secs: args.mesh_refresh_interval_secs,
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

    connect_vpn(connect_args).await
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
        let hint = stop_daemon_remaining_hint(&config_path, &remaining, requested_control_stop);
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

fn stop_daemon_remaining_hint(
    #[allow(unused_variables)] config_path: &Path,
    #[allow(unused_variables)] remaining: &[u32],
    requested_control_stop: bool,
) -> String {
    #[cfg(target_os = "macos")]
    if let Ok(service_status) = service_management::query_service_status(config_path)
        && let Some(hint) = macos_stop_daemon_hint_from_service_status(&service_status, remaining)
    {
        return hint;
    }

    if requested_control_stop {
        "daemon ignored local stop request; likely an older daemon binary is still running. perform one elevated stop (e.g. sudo nvpn stop --force --config <config>) to migrate".to_string()
    } else {
        "try --force".to_string()
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_stop_daemon_hint_from_service_status(
    service_status: &ServiceStatusView,
    remaining: &[u32],
) -> Option<String> {
    if !(service_status.supported
        && service_status.installed
        && service_status.loaded
        && service_status.running)
    {
        return None;
    }

    let pid = service_status.pid?;
    if !remaining.contains(&pid) {
        return None;
    }

    Some(format!(
        "daemon is managed by launchd service {}; it may be getting restarted automatically. use sudo nvpn service disable --config <config> to stop it completely, or sudo nvpn service enable --config <config> to restart it onto the current binary",
        service_status.label
    ))
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
    wait_for_daemon_control_ack(
        &config_path,
        daemon_control_ack_timeout(DaemonControlRequest::Reload),
    )?;
    println!("daemon reload requested");
    Ok(())
}

pub(crate) fn daemon_control_ack_timeout(request: DaemonControlRequest) -> Duration {
    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(15);
        }
    }

    // Daemon polls the control file inside its 1s state_interval tick, but
    // each tick can stall on FIPS event drain + tunnel reconfig + route
    // refresh. 3s was empirically too short — leave headroom for a busy node.
    Duration::from_secs(10)
}

pub(crate) fn daemon_control_result_timeout(request: DaemonControlRequest) -> Duration {
    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(30);
        }
    }

    Duration::from_secs(15)
}

#[cfg(test)]
pub(crate) fn daemon_control_vpn_transition_timeout(request: DaemonControlRequest) -> Duration {
    if matches!(
        request,
        DaemonControlRequest::Pause | DaemonControlRequest::Resume
    ) {
        #[cfg(target_os = "macos")]
        {
            return Duration::from_secs(30);
        }

        #[cfg(not(target_os = "macos"))]
        {
            return Duration::from_secs(2);
        }
    }

    Duration::ZERO
}

fn control_daemon(args: ControlArgs, request: DaemonControlRequest) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let status = daemon_status(&config_path)?;
    if !status.running {
        persist_desired_daemon_vpn_enabled_for_request(&config_path, request)?;
        println!("daemon: not running");
        return Ok(());
    }

    write_daemon_control_request(&config_path, request)?;
    match request {
        DaemonControlRequest::Pause | DaemonControlRequest::Resume => {}
        DaemonControlRequest::Reload | DaemonControlRequest::Stop => {
            wait_for_daemon_control_ack(&config_path, daemon_control_ack_timeout(request))?;
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

    let pid = running_pid.or(pid_from_record);
    let state = read_daemon_state(&state_file)?;
    let running = running_pid.is_some() || daemon_state_file_counts_as_running(state.as_ref());

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

fn daemon_state_file_counts_as_running(state: Option<&DaemonRuntimeState>) -> bool {
    if !daemon_state_file_status_mode_enabled() {
        return false;
    }
    let Some(state) = state else {
        return false;
    };
    daemon_state_is_fresh(state, unix_timestamp(), daemon_state_running_max_age_secs())
}

fn daemon_state_file_status_mode_enabled() -> bool {
    std::env::var(DAEMON_STATUS_MODE_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                DAEMON_STATUS_MODE_STATE_FILE | "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn daemon_state_running_max_age_secs() -> u64 {
    std::env::var(DAEMON_STATE_RUNNING_MAX_AGE_SECS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DAEMON_STATE_RUNNING_MAX_AGE_SECS)
}

fn daemon_state_is_fresh(state: &DaemonRuntimeState, now: u64, max_age_secs: u64) -> bool {
    state.updated_at > 0 && now.saturating_sub(state.updated_at) <= max_age_secs
}

fn daemon_status_json_value(status: &DaemonStatus) -> serde_json::Value {
    json!({
        "running": status.running,
        "pid": status.pid,
        "pid_file": status.pid_file,
        "log_file": status.log_file,
        "state_file": status.state_file,
        "state": visible_daemon_state_for_status(status.running, status.state.as_ref()),
    })
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
    let daemon = daemon_status(&config_path)?;
    let netcheck = run_netcheck_report(&app, args.timeout_secs).await;

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
                    state.vpn_active,
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
        println!("vpn: {}", state.vpn_status);
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
    println!(
        "port_mapping: active={} upnp={} nat_pmp={} pcp={}",
        port_mapping.active_protocol.as_deref().unwrap_or("none"),
        format_probe_state(port_mapping.upnp.state),
        format_probe_state(port_mapping.nat_pmp.state),
        format_probe_state(port_mapping.pcp.state),
    );
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

fn print_daemon_peer_line(peer: &DaemonPeerState, now: u64) {
    let marker = if peer.reachable { '✓' } else { '✗' };
    let transport = match (
        peer.fips_transport_type.as_str(),
        peer.fips_transport_addr.as_str(),
    ) {
        ("", "") if peer.reachable => "relayed".to_string(),
        ("", "") => "pending".to_string(),
        (kind, "") => kind.to_string(),
        (kind, addr) => format!("{kind} {addr}"),
    };
    let srtt = peer
        .fips_srtt_ms
        .map(|ms| format!(" srtt={ms}ms"))
        .unwrap_or_default();
    let last = peer
        .last_fips_seen_at
        .filter(|seen| *seen > 0)
        .map(|seen| format!(" last={}s", now.saturating_sub(seen)))
        .unwrap_or_default();
    let traffic = if peer.fips_bytes_sent + peer.fips_bytes_recv > 0 {
        format!(
            " io={}/{}",
            human_bytes(peer.fips_bytes_recv),
            human_bytes(peer.fips_bytes_sent),
        )
    } else {
        String::new()
    };
    let routes = if peer.advertised_routes.is_empty() {
        String::new()
    } else {
        format!(" routes={}", peer.advertised_routes.join(","))
    };
    let probe = if peer.direct_probe_pending {
        " direct_probe=pending"
    } else {
        ""
    };
    let err = peer
        .error
        .as_deref()
        .filter(|err| !err.is_empty() && !peer.reachable)
        .map(|err| format!(" ({err})"))
        .unwrap_or_default();
    let pubkey = if !peer.public_key.is_empty() {
        peer.public_key.as_str()
    } else {
        peer.participant_pubkey.as_str()
    };
    println!(
        "  {marker} {} {} {transport}{srtt}{last}{traffic}{routes}{probe}{err}",
        truncate_pubkey(pubkey),
        peer.tunnel_ip,
    );
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx + 1 < UNITS.len() {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else {
        format!("{value:.1}{}", UNITS[idx])
    }
}

fn truncate_pubkey(pubkey_hex: &str) -> String {
    if pubkey_hex.len() <= 12 {
        pubkey_hex.to_string()
    } else {
        format!("{}…", &pubkey_hex[..12])
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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

fn parse_csv_arg(value: &str) -> Vec<String> {
    let mut values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn parse_tcp_ports_arg(value: &str) -> Result<Vec<u16>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let port = raw
            .parse::<u16>()
            .with_context(|| format!("invalid TCP port '{raw}'"))?;
        if port == 0 {
            return Err(anyhow!("invalid TCP port '{raw}'"));
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    Ok(ports)
}

fn parse_fips_peer_endpoint_args(values: &[String]) -> Result<HashMap<String, Vec<String>>> {
    let mut peers = HashMap::<String, Vec<String>>::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let (peer, endpoint) = value
            .split_once('=')
            .ok_or_else(|| anyhow!("expected --fips-peer-endpoint npub=host or npub=host:port"))?;
        let peer = normalize_nostr_pubkey(peer.trim())?;
        let endpoint = normalize_fips_peer_endpoint(endpoint.trim())?;
        peers.entry(peer).or_default().push(endpoint);
    }

    for endpoints in peers.values_mut() {
        endpoints.sort();
        endpoints.dedup();
    }
    Ok(peers)
}

fn normalize_fips_peer_endpoint(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("empty FIPS peer endpoint"));
    }
    normalize_fips_peer_endpoint_hint(value)
        .ok_or_else(|| anyhow!("FIPS peer endpoint must be a usable UDP host or host:port"))
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

fn run_invite_broadcast(args: InviteBroadcastArgs) -> Result<()> {
    use nostr_vpn_core::lan_pairing::{
        LAN_PAIRING_DURATION, LanPairingAnnouncement, spawn_lan_pairing_worker,
    };

    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;

    let own_npub_hex = app.own_nostr_pubkey_hex()?;
    let own_npub = nostr_vpn_core::invite::to_npub(&own_npub_hex);
    let invite = active_network_invite_code(&app)?;
    let endpoint = app.node.endpoint.trim().to_string();
    let node_name = app.node_name.trim().to_string();

    let duration = Duration::from_secs(
        args.duration_secs
            .unwrap_or_else(|| LAN_PAIRING_DURATION.as_secs()),
    );
    let expires_at = SystemTime::now()
        .checked_add(duration)
        .ok_or_else(|| anyhow::anyhow!("broadcast duration overflows SystemTime"))?;

    let mut worker = spawn_lan_pairing_worker(LanPairingAnnouncement {
        npub: own_npub.clone(),
        node_name: node_name.clone(),
        endpoint: endpoint.clone(),
        invite: invite.clone(),
    })?;
    worker.set_broadcast_until(expires_at);

    println!("network_id={}", app.effective_network_id());
    println!("npub={own_npub}");
    println!("endpoint={endpoint}");
    println!("invite={invite}");
    println!(
        "broadcasting on 239.255.73.73:38911 for {} seconds (Ctrl-C to stop)",
        duration.as_secs()
    );

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    worker.clear_broadcast();
    worker.stop();
    println!("broadcast stopped");
    Ok(())
}

fn run_discover(args: DiscoverArgs) -> Result<()> {
    use nostr_vpn_core::lan_pairing::{
        LAN_PAIRING_DURATION, LanPairingAnnouncement, LanPairingSignal, spawn_lan_pairing_worker,
    };

    let config_path = args.config.unwrap_or_else(default_config_path);
    let mut app = load_or_default_config(&config_path)?;

    let own_npub_hex = app.own_nostr_pubkey_hex()?;
    let own_npub = nostr_vpn_core::invite::to_npub(&own_npub_hex);
    let endpoint = app.node.endpoint.trim().to_string();
    let node_name = app.node_name.trim().to_string();
    let local_invite = active_network_invite_code(&app).unwrap_or_default();

    let duration = Duration::from_secs(
        args.duration_secs
            .unwrap_or_else(|| LAN_PAIRING_DURATION.as_secs()),
    );
    let expires_at = SystemTime::now()
        .checked_add(duration)
        .ok_or_else(|| anyhow::anyhow!("discover duration overflows SystemTime"))?;

    let mut worker = spawn_lan_pairing_worker(LanPairingAnnouncement {
        npub: own_npub.clone(),
        node_name,
        endpoint,
        invite: local_invite,
    })?;
    worker.set_listen_until(expires_at);

    println!(
        "listening on 239.255.73.73:38911 for {} seconds (Ctrl-C to stop)",
        duration.as_secs()
    );

    let mut accepted: Option<LanPairingSignal> = None;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        for signal in worker.drain() {
            if !seen.insert(signal.npub.clone()) {
                continue;
            }
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "npub": signal.npub,
                        "node_name": signal.node_name,
                        "endpoint": signal.endpoint,
                        "network_id": signal.network_id,
                        "network_name": signal.network_name,
                        "invite": signal.invite,
                    }))?
                );
            } else {
                println!(
                    "npub={} node={} endpoint={} network_id={} network_name={}",
                    signal.npub,
                    if signal.node_name.is_empty() {
                        "?"
                    } else {
                        signal.node_name.as_str()
                    },
                    if signal.endpoint.is_empty() {
                        "?"
                    } else {
                        signal.endpoint.as_str()
                    },
                    signal.network_id,
                    if signal.network_name.is_empty() {
                        "-"
                    } else {
                        signal.network_name.as_str()
                    },
                );
            }
            if args.accept {
                accepted = Some(signal);
                break;
            }
        }
        if accepted.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    worker.clear_listen();
    worker.stop();

    if let Some(signal) = accepted {
        let invite = parse_network_invite(&signal.invite)?;
        apply_network_invite_to_active_network(&mut app, &invite)?;
        let join_request_queued = queue_active_network_join_request(&mut app)?;
        app.ensure_defaults();
        maybe_autoconfigure_node(&mut app);
        app.save(&config_path)?;
        maybe_reload_running_daemon(&config_path);
        if args.json {
            println!("{}", serde_json::to_string_pretty(&app)?);
        } else {
            println!("saved {}", config_path.display());
            println!("network_id={}", app.effective_network_id());
            println!("invite_imported={}", app.active_network().name);
            println!("join_request_queued={join_request_queued}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) use tests::support::{macos_default_routes_from_netstat, macos_ifconfig_has_ipv4};

#[cfg(test)]
mod tests {
    pub(super) use support::control_daemon_request_for_test;

    mod cli_smoke;
    mod config_cache;
    mod daemon_control;
    mod runtime_misc;
    mod service_cli;
    pub(crate) mod support;
}
