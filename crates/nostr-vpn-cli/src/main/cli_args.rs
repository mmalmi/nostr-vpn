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
#[command(version)]
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
        /// Device Nostr pubkeys (npub or hex) that define the network.
        #[arg(long = "device", alias = "participant")]
        devices: Vec<String>,
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
    /// Show this device's join-request link and QR, then wait for approval.
    #[command(name = "join-request")]
    JoinRequest(JoinRequestArgs),
    /// Join with an admin Device ID and Network ID exchanged out of band.
    #[command(name = "join-manual", alias = "manual-join")]
    JoinManual(ManualJoinArgs),
    /// Show local and discovered peer status.
    Status(StatusArgs),
    /// Update persisted node/network settings.
    Set(SetArgs),
    /// Add one or more devices to the active network roster.
    #[command(alias = "add-participant")]
    AddDevice(UpdateRosterArgs),
    /// Remove one or more devices from the active network roster.
    #[command(alias = "remove-participant")]
    RemoveDevice(UpdateRosterArgs),
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
    /// Queue signed Nostr control events for publication over FIPS pubsub.
    Pubsub(PubsubArgs),
    /// Probe a WireGuard upstream config (Mullvad/Proton-style) by running
    /// the userspace WG state machine against it and reporting whether
    /// the handshake completes. Without --replace-default or --scoped-host,
    /// this does not create a tun device and does not modify routes.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    WgUpstreamTest(WgUpstreamTestArgs),
    /// Manage Cashu-paid public exit routing.
    #[cfg(feature = "paid-exit")]
    #[command(name = "paid-exit")]
    PaidExit(PaidExitArgs),
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

#[derive(Debug, Clone, Args)]
struct JoinRequestArgs {
    /// nvpn configuration containing the device identity and approval state.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Print the request and current reachability without waiting for approval.
    #[arg(long)]
    no_wait: bool,
    /// Print only the link, without the terminal QR code.
    #[arg(long)]
    no_qr: bool,
    /// Replace the still-pending request, invalidating previously shared links.
    #[arg(long)]
    reset: bool,
}

#[derive(Debug, Clone, Args)]
struct ManualJoinArgs {
    /// nvpn configuration to update.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Device ID shared by the network admin (npub or hex).
    #[arg(long = "admin-device-id", alias = "admin")]
    admin_device_id: String,
    /// Network ID shared by the network admin.
    #[arg(long = "network-id")]
    network_id: String,
    /// Print machine-readable output.
    #[arg(long)]
    json: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, Args)]
struct WgUpstreamTestArgs {
    /// Path to a WireGuard config file (the same `[Interface]` /
    /// `[Peer]` syntax wg-quick / Mullvad / Proton VPN export).
    #[arg(long, required_unless_present = "self_test")]
    config_file: Option<PathBuf>,
    /// Generate a local paired WireGuard responder and test against it.
    /// This is for release-gate host/VM checks: it uses the same native
    /// tun/Wintun path as a provider config, but needs no external VPN account.
    #[arg(long, default_value_t = false)]
    self_test: bool,
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
    /// Print component build details in text output.
    #[arg(long)]
    verbose: bool,
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
    #[arg(long, alias = "announce-interval-secs", default_value_t = 60)]
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 60)]
    mesh_refresh_interval_secs: u64,
}

#[derive(Debug, Args, Clone)]
struct DaemonArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 60)]
    mesh_refresh_interval_secs: u64,
    /// Raw Ethernet interface used for local FIPS discovery and transport.
    #[arg(long, requires = "fips_ethernet_discovery_scope")]
    fips_ethernet_interface: Option<String>,
    /// Discovery scope shared by FIPS peers on the local Ethernet segment.
    #[arg(long, requires = "fips_ethernet_interface")]
    fips_ethernet_discovery_scope: Option<String>,
    /// Authenticated FIPS WebSocket seed URL. Repeat for multiple independent seeds.
    #[arg(long = "fips-websocket-seed-url", value_parser = parse_fips_websocket_seed_url)]
    fips_websocket_seed_urls: Vec<String>,
    /// Optional native plain-WebSocket listener, normally private or loopback behind TLS.
    #[arg(long)]
    fips_websocket_bind: Option<String>,
    /// Public WSS URL advertised separately from the native listener address.
    #[arg(long, requires = "fips_websocket_bind", value_parser = parse_fips_websocket_public_url)]
    fips_websocket_public_url: Option<String>,
    #[arg(long, hide = true, default_value_t = false)]
    paused: bool,
    #[arg(long, hide = true, default_value_t = false)]
    service: bool,
    /// Isolate an audited server service in its own protected runtime directory.
    #[arg(long, hide = true, value_parser = parse_daemon_instance_id)]
    daemon_instance: Option<String>,
}

fn parse_daemon_instance_id(value: &str) -> Result<String, String> {
    validate_daemon_instance_id(value)
        .map(str::to_owned)
        .map_err(|error| error.to_string())
}

fn parse_fips_websocket_seed_url(value: &str) -> Result<String, String> {
    let value = value.trim().to_string();
    fips_core::config::WebSocketConfig {
        seed_urls: vec![value.clone()],
        ..Default::default()
    }
    .validate()?;
    Ok(value)
}

fn parse_fips_websocket_public_url(value: &str) -> Result<String, String> {
    let value = value.trim().to_string();
    fips_core::config::WebSocketConfig {
        bind_addr: Some("127.0.0.1:1".into()),
        public_url: Some(value.clone()),
        ..Default::default()
    }
    .validate()?;
    Ok(value)
}

#[derive(Debug, Args)]
struct StartArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long, default_value_t = default_tunnel_iface())]
    iface: String,
    #[arg(long, alias = "announce-interval-secs", default_value_t = 60)]
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long, hide = true, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
    /// Include the daemon's ephemeral join link in JSON output for the native app.
    #[arg(long, hide = true)]
    include_join_request: bool,
}

#[derive(Debug, Args)]
struct SetArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, conflicts_with = "exit_node")]
    internet_source: Option<String>,
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long)]
    exit_node: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    exit_node_leak_protection: Option<bool>,
    #[arg(long)]
    advertise_routes: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    advertise_exit_node: Option<bool>,
    #[cfg(feature = "paid-exit")]
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    paid_exit_enabled: Option<bool>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_upstream: Option<String>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_price_msat_per_gb: Option<u64>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_accepted_mints: Option<String>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_country_code: Option<String>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_asn: Option<u32>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_max_channel_capacity_sat: Option<u64>,
    #[cfg(feature = "paid-exit")]
    #[arg(long)]
    paid_exit_channel_expiry_secs: Option<u64>,
    #[cfg(feature = "paid-exit")]
    #[arg(long, value_name = "UNITS")]
    paid_exit_free_probe_units: Option<String>,
    #[cfg(feature = "paid-exit")]
    #[arg(long, value_name = "UNITS")]
    paid_exit_grace_units: Option<String>,
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
    /// Exit DNS policy: automatic, encrypted, or through_exit.
    #[arg(long)]
    exit_dns_mode: Option<String>,
    /// Encrypted DNS preset: cloudflare, quad9, or custom.
    #[arg(long)]
    exit_dns_doh_provider: Option<String>,
    #[arg(long)]
    exit_dns_custom_doh_url: Option<String>,
    /// Comma-separated bootstrap IPs for custom encrypted DNS.
    #[arg(long)]
    exit_dns_custom_doh_bootstrap_ips: Option<String>,
    /// Comma-separated DNS IPs sent through the selected exit.
    #[arg(long)]
    exit_dns_through_exit_servers: Option<String>,
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
    /// Discover and advertise directly reachable peers with LAN mDNS.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    lan_discovery_enabled: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    fips_webrtc_enabled: Option<bool>,
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
struct UpdateRosterArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "device", alias = "participant", required = true)]
    devices: Vec<String>,
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
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
    #[arg(long = "device", alias = "participant")]
    devices: Vec<String>,
    #[arg(long, hide = true, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PubsubArgs {
    #[command(subcommand)]
    command: PubsubCommand,
}

#[derive(Debug, Subcommand)]
enum PubsubCommand {
    /// Queue one signed kind 37195, 37196, or 7368 event JSON file.
    Publish(PubsubPublishArgs),
}

#[derive(Debug, Args)]
struct PubsubPublishArgs {
    /// Signed Nostr event JSON file.
    #[arg(long)]
    event: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
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
