pub const DEFAULT_RELAYS: &[&str] = &[];

/// Public authenticated WebSocket FIPS transit seeds.
///
/// The npub and URL are kept together so the first adjacency is authenticated
/// against the expected FIPS identity rather than trusting a URL-only key hint.
pub const DEFAULT_FIPS_WEBSOCKET_SEEDS: &[(&str, &str)] = &[
    (
        "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd",
        "wss://fips1.iris.to/fips",
    ),
    (
        "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh",
        "wss://fips2.iris.to/fips",
    ),
];

/// Public FIPS transit peers used to establish the first authenticated route.
/// Native clients try UDP first and retain WebSocket as the HTTPS-shaped
/// fallback for networks that filter UDP.
pub const DEFAULT_FIPS_BOOTSTRAP_PEERS: &[(&str, &[&str])] = &[
    (
        "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd",
        &[
            "fips1.iris.to:51820",
            "websocket:wss://fips1.iris.to/fips",
        ],
    ),
    (
        "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh",
        &[
            "fips2.iris.to:51820",
            "websocket:wss://fips2.iris.to/fips",
        ],
    ),
];

const LEGACY_FIPS_UDP_BOOTSTRAP_PEERS: &[(&str, &[&str])] = &[
    (
        "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd",
        &["185.18.221.232:51820"],
    ),
    (
        "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh",
        &["65.109.48.91:51820"],
    ),
];

const LEGACY_FIPS_WEBSOCKET_BOOTSTRAP_PEERS: &[(&str, &[&str])] = &[
    (
        "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd",
        &["websocket:wss://fips1.iris.to/fips"],
    ),
    (
        "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh",
        &["websocket:wss://fips2.iris.to/fips"],
    ),
];

pub fn default_fips_websocket_seed_urls() -> Vec<String> {
    Vec::new()
}

/// The default bootstrap peer list as an owned map, used to seed configs and to
/// power "reset to defaults".
pub fn default_fips_bootstrap_peers() -> HashMap<String, Vec<String>> {
    DEFAULT_FIPS_BOOTSTRAP_PEERS
        .iter()
        .map(|(npub, addrs)| {
            (
                (*npub).to_string(),
                addrs.iter().map(|addr| (*addr).to_string()).collect(),
            )
        })
        .collect()
}

pub(crate) fn is_legacy_fips_bootstrap(
    npub: &str,
    configured_addresses: &[String],
) -> bool {
    [
        LEGACY_FIPS_UDP_BOOTSTRAP_PEERS,
        LEGACY_FIPS_WEBSOCKET_BOOTSTRAP_PEERS,
    ]
    .into_iter()
    .any(|legacy_peers| {
        legacy_peers
            .iter()
            .find(|(legacy_npub, _)| *legacy_npub == npub)
            .is_some_and(|(_, legacy_addresses)| {
                configured_addresses.len() == legacy_addresses.len()
                    && configured_addresses
                        .iter()
                        .zip(legacy_addresses.iter())
                        .all(|(configured, legacy)| configured.trim() == *legacy)
            })
    })
}

pub(crate) fn is_legacy_default_fips_websocket_seed_urls(
    configured_urls: &[String],
) -> bool {
    configured_urls.len() == DEFAULT_FIPS_WEBSOCKET_SEEDS.len()
        && configured_urls
            .iter()
            .zip(DEFAULT_FIPS_WEBSOCKET_SEEDS.iter())
            .all(|(configured, (_, legacy))| configured.trim() == *legacy)
}

/// Split a transport-tagged peer address into `(transport, address)`. A bare
/// `host:port` defaults to UDP. Used to lower bootstrap/transit address strings
/// and direct WebRTC peer IDs into fips `PeerAddress` values.
pub fn split_peer_transport_addr(value: &str) -> (String, String) {
    let value = value.trim();
    for transport in ["udp", "tcp", "tor", "webrtc", "websocket"] {
        if let Some(rest) = value.strip_prefix(&format!("{transport}:")) {
            return (transport.to_string(), rest.trim().to_string());
        }
    }
    ("udp".to_string(), value.to_string())
}

pub fn normalize_fips_peer_endpoint_hint(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    if let Some(addr) = peer_endpoint_hint_addr(&PeerEndpointHint::udp(endpoint)) {
        return Some(addr);
    }

    let default_port = default_listen_port();
    let endpoint = if let Some(host) = endpoint
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let host = host.trim();
        if host.is_empty() || !host.contains(':') {
            return None;
        }
        format!("[{host}]:{default_port}")
    } else if endpoint.contains(':') {
        return None;
    } else {
        format!("{endpoint}:{default_port}")
    };
    peer_endpoint_hint_addr(&PeerEndpointHint::udp(endpoint))
}

/// Validate and normalize a transport-tagged static FIPS address.
///
/// UDP-like host/port transports use the ordinary endpoint normalizer.
/// WebSocket addresses retain their URL because lowering them through a UDP
/// host/port parser would silently discard the authenticated seed identity pin.
pub fn normalize_fips_transport_address(endpoint: &str) -> Option<String> {
    let (transport, address) = split_peer_transport_addr(endpoint);
    if transport == "websocket" {
        let address = address.trim().to_string();
        fips_core::config::WebSocketConfig {
            seed_urls: vec![address.clone()],
            ..Default::default()
        }
        .validate()
        .ok()?;
        return Some(format!("websocket:{address}"));
    }

    let address = normalize_fips_peer_endpoint_hint(&address)?;
    Some(if transport == "udp" {
        address
    } else {
        format!("{transport}:{address}")
    })
}

pub fn normalize_relay_urls(values: Vec<String>) -> Vec<String> {
    let mut relays = values
        .into_iter()
        .flat_map(|value| {
            value
                .split([',', '\n', '\r', ' ', '\t'])
                .map(str::trim)
                .filter(|relay| !relay.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    relays.sort();
    relays.dedup();
    relays
}

include!("types/nostr.rs");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    /// Discover and advertise directly reachable peers with LAN mDNS.
    /// Disable this on nodes that have no local broadcast-domain peers, such
    /// as public WebSocket seeds, while leaving every other FIPS transport and
    /// the standard Nostr pubsub bridge active.
    #[serde(default = "default_lan_discovery_enabled")]
    pub lan_discovery_enabled: bool,
    #[serde(default = "default_launch_on_startup")]
    pub launch_on_startup: bool,
    #[serde(default = "default_autoconnect")]
    pub autoconnect: bool,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub fips_peer_endpoints: HashMap<String, Vec<String>>,
    /// Publish this node's exact UDP endpoint through public FIPS/Nostr discovery.
    /// Roster peers still receive private endpoint hints over FIPS capabilities.
    #[serde(
        default = "default_fips_advertise_public_endpoint",
        alias = "fips_advertise_endpoint",
        skip_serializing_if = "is_false"
    )]
    pub fips_advertise_public_endpoint: bool,
    #[serde(
        default = "default_fips_host_tunnel_enabled",
        skip_serializing_if = "is_false"
    )]
    pub fips_host_tunnel_enabled: bool,
    #[serde(
        default = "default_connect_to_non_roster_fips_peers",
        skip_serializing_if = "is_false"
    )]
    pub connect_to_non_roster_fips_peers: bool,
    /// Find/advertise FIPS peers over Nostr relays. When false, the node still
    /// connects to LAN, static, and bootstrap peers but does not use relays for
    /// endpoint discovery or advertising.
    #[serde(
        default = "default_fips_nostr_discovery_enabled",
        skip_serializing_if = "is_true"
    )]
    pub fips_nostr_discovery_enabled: bool,
    /// Enable the browser-compatible FIPS WebRTC transport. Nostr discovery
    /// remains available to UDP/TCP transports when this is false.
    #[serde(
        default = "default_fips_webrtc_enabled",
        skip_serializing_if = "is_false"
    )]
    pub fips_webrtc_enabled: bool,
    /// Authenticated FIPS WebSocket seed URLs. Each entry must be `wss://`;
    /// loopback-only `ws://` is accepted by FIPS for local development.
    #[serde(
        default = "default_fips_websocket_seed_urls",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub fips_websocket_seed_urls: Vec<String>,
    /// Optional native plain-WebSocket listener, normally bound to loopback or
    /// a private address behind a TLS-terminating reverse proxy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fips_websocket_bind_addr: String,
    /// Public `wss://` URL advertised separately from the native bind address.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fips_websocket_public_url: String,
    /// Master switch for dialing the bootstrap/transit peer list below. When off,
    /// the list is kept but not dialed.
    #[serde(
        default = "default_fips_bootstrap_enabled",
        skip_serializing_if = "is_true"
    )]
    pub fips_bootstrap_enabled: bool,
    /// Editable transit/bootstrap peers (npub -> transport-tagged addresses).
    /// New configs start with the public native seeds so private FIPS signaling
    /// has an authenticated route before direct peer discovery succeeds.
    #[serde(default = "default_fips_bootstrap_peers")]
    pub fips_bootstrap_peers: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fips_host_inbound_tcp_ports: Vec<u16>,
    #[serde(default, skip_serializing)]
    pub mesh_mtu_profile: String,
    #[serde(default, skip_serializing)]
    pub mesh_underlay_udp_mtu: u16,
    #[serde(default, skip_serializing)]
    pub mesh_tunnel_mtu: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exit_node: String,
    #[serde(default, skip_serializing_if = "InternetSource::is_direct")]
    pub internet_source: InternetSource,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exit_node_public_paid_exit: bool,
    #[serde(
        default = "default_exit_node_leak_protection",
        skip_serializing_if = "is_false"
    )]
    pub exit_node_leak_protection: bool,
    #[serde(default = "default_close_to_tray_on_close")]
    pub close_to_tray_on_close: bool,
    #[serde(default = "default_magic_dns_suffix", skip)]
    pub magic_dns_suffix: String,
    #[serde(default, skip_serializing_if = "ExitDnsConfig::is_default")]
    pub exit_dns: ExitDnsConfig,
    #[serde(default, skip_serializing_if = "WireGuardExitConfig::is_default")]
    pub wireguard_exit: WireGuardExitConfig,
    #[serde(default, skip_serializing_if = "PaidExitConfig::is_default")]
    pub paid_exit: PaidExitConfig,
    #[serde(default, skip_serializing_if = "ManualPaidExitProvider::is_default")]
    pub manual_paid_exit_provider: ManualPaidExitProvider,
    #[serde(
        default = "default_wallet_fiat_enabled",
        skip_serializing_if = "is_true"
    )]
    pub wallet_fiat_enabled: bool,
    #[serde(default, skip_serializing_if = "FiatCurrency::is_usd")]
    pub wallet_fiat_currency: FiatCurrency,
    #[serde(default = "default_peer_aliases")]
    pub peer_aliases: HashMap<String, String>,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default)]
    pub nostr: NostrConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_nostr_join_request: Option<PendingNostrJoinRequest>,
    #[serde(default)]
    pub node: NodeConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InternetSource {
    #[default]
    Direct,
    PrivateVpn,
    PaidAutomatic,
    PaidManual,
    WireGuard,
}

/// The local internet path a paid-exit seller actually forwards buyers into.
///
/// This is derived from `internet_source`; it is deliberately not another
/// persisted setting that can drift away from the host's selected exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaidExitSellerEgress {
    Direct,
    WireGuard,
    PrivatePeer { pubkey: String },
}

impl PaidExitSellerEgress {
    /// Preserve paid-offer v3 compatibility. `host_default` means the
    /// seller's active host path, which may itself be a private FIPS exit.
    pub fn offer_upstream(&self) -> PaidExitUpstream {
        match self {
            Self::WireGuard => PaidExitUpstream::WireGuardExit,
            Self::Direct | Self::PrivatePeer { .. } => PaidExitUpstream::HostDefault,
        }
    }

    pub fn private_peer_pubkey(&self) -> Option<&str> {
        match self {
            Self::PrivatePeer { pubkey } => Some(pubkey),
            Self::Direct | Self::WireGuard => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiatCurrency {
    #[default]
    Usd,
    Eur,
    Gbp,
    Cad,
    Aud,
    Jpy,
    Chf,
}

impl FiatCurrency {
    pub fn is_usd(&self) -> bool {
        *self == Self::Usd
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usd => "USD",
            Self::Eur => "EUR",
            Self::Gbp => "GBP",
            Self::Cad => "CAD",
            Self::Aud => "AUD",
            Self::Jpy => "JPY",
            Self::Chf => "CHF",
        }
    }
}

impl std::str::FromStr for FiatCurrency {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "USD" => Ok(Self::Usd),
            "EUR" => Ok(Self::Eur),
            "GBP" => Ok(Self::Gbp),
            "CAD" => Ok(Self::Cad),
            "AUD" => Ok(Self::Aud),
            "JPY" => Ok(Self::Jpy),
            "CHF" => Ok(Self::Chf),
            _ => Err("expected one of: USD, EUR, GBP, CAD, AUD, JPY, CHF"),
        }
    }
}

impl InternetSource {
    pub fn is_direct(&self) -> bool {
        *self == Self::Direct
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::PrivateVpn => "private_vpn",
            Self::PaidAutomatic => "paid_automatic",
            Self::PaidManual => "paid_manual",
            Self::WireGuard => "wireguard",
        }
    }
}

impl std::str::FromStr for InternetSource {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" | "this_device" | "local" | "off" => Ok(Self::Direct),
            "private_vpn" | "private" | "peer" => Ok(Self::PrivateVpn),
            "paid_automatic" | "paid_auto" | "automatic" | "auto" => Ok(Self::PaidAutomatic),
            "paid_manual" | "manual" | "paid" => Ok(Self::PaidManual),
            "wireguard" | "wg" => Ok(Self::WireGuard),
            _ => {
                Err("expected one of: direct, private_vpn, paid_automatic, paid_manual, wireguard")
            }
        }
    }
}

include!("exit_dns.rs");

include!("types/wireguard_exit.rs");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default = "default_nat_enabled")]
    pub enabled: bool,
    #[serde(default = "default_nat_stun_servers")]
    pub stun_servers: Vec<String>,
    #[serde(default = "default_nat_discovery_timeout_secs")]
    pub discovery_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_network_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub network_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub join_secret: String,
    #[serde(default, alias = "participants")]
    pub devices: Vec<String>,
    /// Locally removed members. This is deliberately not part of the shared
    /// roster wire format: an admin keeps these tombstones so a later stale
    /// whole-roster snapshot cannot resurrect a removed device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<String>,
    #[serde(
        default = "default_listen_for_join_requests",
        skip_serializing_if = "is_true"
    )]
    pub listen_for_join_requests: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub join_request_admin: String,
    /// True only for a network entered through the manual join UI until a
    /// verified roster from its configured admin explicitly contains this
    /// device. This must remain independent of ordinary roster metadata:
    /// admins can publish valid pre-acceptance rosters that omit the joiner.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local_identity_confirmation_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_join_request: Option<PendingOutboundJoinRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound_join_requests: Vec<PendingInboundJoinRequest>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub shared_roster_updated_at: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub shared_roster_signed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PendingOutboundJoinRequest {
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub requested_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PendingInboundJoinRequest {
    #[serde(default)]
    pub requester: String,
    #[serde(default)]
    pub requester_node_name: String,
    #[serde(default)]
    pub requested_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnabledNetworkMesh {
    pub id: String,
    pub name: String,
    pub network_id: String,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNetworkRoster {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub devices: Vec<String>,
    pub admins: Vec<String>,
    pub aliases: HashMap<String, String>,
    pub updated_at: u64,
    pub signed_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSignedSharedRosterUpdate {
    pub network_id: String,
    pub network_name: String,
    pub devices: Vec<String>,
    pub admins: Vec<String>,
    pub aliases: HashMap<String, String>,
    pub signed_at: u64,
    pub signed_by: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut config = Self {
            networks: vec![NetworkConfig {
                id: default_network_entry_id(1),
                name: default_network_name(1),
                enabled: default_network_enabled(),
                network_id: default_network_id(),
                join_secret: default_join_secret(),
                devices: Vec::new(),
                removed_devices: Vec::new(),
                admins: Vec::new(),
                listen_for_join_requests: default_listen_for_join_requests(),
                join_request_admin: String::new(),
                local_identity_confirmation_pending: false,
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                shared_roster_updated_at: 0,
                shared_roster_signed_by: String::new(),
            }],
            node_name: default_node_name(),
            lan_discovery_enabled: default_lan_discovery_enabled(),
            launch_on_startup: default_launch_on_startup(),
            autoconnect: default_autoconnect(),
            fips_peer_endpoints: HashMap::new(),
            fips_advertise_public_endpoint: default_fips_advertise_public_endpoint(),
            fips_host_tunnel_enabled: default_fips_host_tunnel_enabled(),
            connect_to_non_roster_fips_peers: default_connect_to_non_roster_fips_peers(),
            fips_nostr_discovery_enabled: default_fips_nostr_discovery_enabled(),
            fips_webrtc_enabled: default_fips_webrtc_enabled(),
            fips_websocket_seed_urls: default_fips_websocket_seed_urls(),
            fips_websocket_bind_addr: String::new(),
            fips_websocket_public_url: String::new(),
            fips_bootstrap_enabled: default_fips_bootstrap_enabled(),
            fips_bootstrap_peers: default_fips_bootstrap_peers(),
            fips_host_inbound_tcp_ports: Vec::new(),
            mesh_mtu_profile: String::new(),
            mesh_underlay_udp_mtu: 0,
            mesh_tunnel_mtu: 0,
            exit_node: String::new(),
            internet_source: InternetSource::Direct,
            exit_node_public_paid_exit: false,
            exit_node_leak_protection: default_exit_node_leak_protection(),
            close_to_tray_on_close: default_close_to_tray_on_close(),
            magic_dns_suffix: default_magic_dns_suffix(),
            exit_dns: ExitDnsConfig::default(),
            wireguard_exit: WireGuardExitConfig::default(),
            paid_exit: PaidExitConfig::default(),
            manual_paid_exit_provider: ManualPaidExitProvider::default(),
            wallet_fiat_enabled: default_wallet_fiat_enabled(),
            wallet_fiat_currency: FiatCurrency::default(),
            peer_aliases: default_peer_aliases(),
            nat: NatConfig::default(),
            nostr: NostrConfig::default(),
            pending_nostr_join_request: None,
            node: NodeConfig::default(),
        };
        config.ensure_defaults();
        config
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: default_nat_enabled(),
            stun_servers: default_nat_stun_servers(),
            discovery_timeout_secs: default_nat_discovery_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_id")]
    pub id: String,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_tunnel_ip")]
    pub tunnel_ip: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub advertised_routes: Vec<String>,
    #[serde(default)]
    pub advertise_exit_node: bool,
    #[serde(default, skip_serializing_if = "ConnectedUdpConfig::is_default")]
    pub connected_udp: ConnectedUdpConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: default_node_id(),
            endpoint: default_endpoint(),
            tunnel_ip: default_tunnel_ip(),
            listen_port: default_listen_port(),
            advertised_routes: Vec::new(),
            advertise_exit_node: false,
            connected_udp: ConnectedUdpConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectedUdpConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd_reserve: Option<usize>,
}

impl ConnectedUdpConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}
