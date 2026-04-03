use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct RelayStatus {
    pub(crate) state: String,
    pub(crate) status_text: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelaySummary {
    pub(crate) up: usize,
    pub(crate) down: usize,
    pub(crate) checking: usize,
    pub(crate) unknown: usize,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistConfigOutcome {
    SavedLocally,
    ReloadedRunningDaemon,
}

impl PersistConfigOutcome {
    pub(crate) fn needs_explicit_daemon_reload(self) -> bool {
        matches!(self, Self::SavedLocally)
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct CliStatusResponse {
    pub(crate) daemon: CliDaemonStatus,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct CliServiceStatusResponse {
    pub(crate) supported: bool,
    pub(crate) installed: bool,
    #[serde(default)]
    pub(crate) disabled: bool,
    pub(crate) loaded: bool,
    pub(crate) running: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) label: String,
    pub(crate) plist_path: String,
    #[serde(default)]
    pub(crate) binary_path: String,
    #[serde(default)]
    pub(crate) binary_version: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct CliDaemonStatus {
    pub(crate) running: bool,
    pub(crate) state: Option<DaemonRuntimeState>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DaemonRuntimeState {
    pub(crate) updated_at: u64,
    #[serde(default)]
    pub(crate) binary_version: String,
    #[serde(default)]
    pub(crate) local_endpoint: String,
    #[serde(default)]
    pub(crate) advertised_endpoint: String,
    #[serde(default)]
    pub(crate) listen_port: u16,
    pub(crate) session_active: bool,
    pub(crate) relay_connected: bool,
    pub(crate) session_status: String,
    pub(crate) expected_peer_count: usize,
    pub(crate) connected_peer_count: usize,
    pub(crate) mesh_ready: bool,
    #[serde(default)]
    pub(crate) health: Vec<HealthIssue>,
    #[serde(default)]
    pub(crate) network: NetworkSummary,
    #[serde(default)]
    pub(crate) port_mapping: PortMappingStatus,
    #[serde(default)]
    pub(crate) relay_operator_running: bool,
    #[serde(default)]
    pub(crate) relay_operator_status: String,
    #[serde(default)]
    pub(crate) nat_assist_running: bool,
    #[serde(default)]
    pub(crate) nat_assist_status: String,
    pub(crate) peers: Vec<DaemonPeerState>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DaemonPeerState {
    pub(crate) participant_pubkey: String,
    pub(crate) node_id: String,
    pub(crate) tunnel_ip: String,
    pub(crate) endpoint: String,
    #[serde(default)]
    pub(crate) runtime_endpoint: Option<String>,
    #[serde(default)]
    pub(crate) tx_bytes: u64,
    #[serde(default)]
    pub(crate) rx_bytes: u64,
    pub(crate) public_key: String,
    pub(crate) advertised_routes: Vec<String>,
    pub(crate) presence_timestamp: u64,
    pub(crate) last_signal_seen_at: Option<u64>,
    pub(crate) reachable: bool,
    pub(crate) last_handshake_at: Option<u64>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayView {
    pub(crate) url: String,
    pub(crate) state: String,
    pub(crate) status_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ParticipantView {
    pub(crate) npub: String,
    pub(crate) pubkey_hex: String,
    pub(crate) is_admin: bool,
    pub(crate) tunnel_ip: String,
    pub(crate) magic_dns_alias: String,
    pub(crate) magic_dns_name: String,
    pub(crate) relay_path_active: bool,
    pub(crate) runtime_endpoint: String,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) advertised_routes: Vec<String>,
    pub(crate) offers_exit_node: bool,
    pub(crate) state: String,
    pub(crate) presence_state: String,
    pub(crate) status_text: String,
    pub(crate) last_signal_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayOperatorSessionView {
    pub(crate) request_id: String,
    pub(crate) network_id: String,
    pub(crate) requester_npub: String,
    pub(crate) requester_pubkey_hex: String,
    pub(crate) target_npub: String,
    pub(crate) target_pubkey_hex: String,
    pub(crate) requester_ingress_endpoint: String,
    pub(crate) target_ingress_endpoint: String,
    pub(crate) started_text: String,
    pub(crate) expires_text: String,
    pub(crate) bytes_from_requester: u64,
    pub(crate) bytes_from_target: u64,
    pub(crate) total_forwarded_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RelayOperatorView {
    pub(crate) relay_npub: String,
    pub(crate) relay_pubkey_hex: String,
    pub(crate) advertised_endpoint: String,
    pub(crate) total_sessions_served: u64,
    pub(crate) total_forwarded_bytes: u64,
    pub(crate) current_forward_bps: u64,
    pub(crate) unique_peer_count: usize,
    pub(crate) active_session_count: usize,
    pub(crate) updated_text: String,
    pub(crate) active_sessions: Vec<RelayOperatorSessionView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OutboundJoinRequestView {
    pub(crate) recipient_npub: String,
    pub(crate) recipient_pubkey_hex: String,
    pub(crate) requested_at_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InboundJoinRequestView {
    pub(crate) requester_npub: String,
    pub(crate) requester_pubkey_hex: String,
    pub(crate) requester_node_name: String,
    pub(crate) requested_at_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) network_id: String,
    pub(crate) local_is_admin: bool,
    pub(crate) admin_npubs: Vec<String>,
    #[serde(rename = "joinRequestsEnabled")]
    pub(crate) listen_for_join_requests: bool,
    pub(crate) invite_inviter_npub: String,
    pub(crate) outbound_join_request: Option<OutboundJoinRequestView>,
    pub(crate) inbound_join_requests: Vec<InboundJoinRequestView>,
    pub(crate) online_count: usize,
    pub(crate) expected_count: usize,
    pub(crate) participants: Vec<ParticipantView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LanPeerView {
    pub(crate) npub: String,
    pub(crate) node_name: String,
    pub(crate) endpoint: String,
    pub(crate) network_name: String,
    pub(crate) network_id: String,
    pub(crate) invite: String,
    pub(crate) last_seen_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UiState {
    pub(crate) platform: String,
    pub(crate) mobile: bool,
    pub(crate) vpn_session_control_supported: bool,
    pub(crate) cli_install_supported: bool,
    pub(crate) startup_settings_supported: bool,
    pub(crate) tray_behavior_supported: bool,
    pub(crate) runtime_status_detail: String,
    pub(crate) daemon_running: bool,
    pub(crate) session_active: bool,
    pub(crate) relay_connected: bool,
    pub(crate) cli_installed: bool,
    pub(crate) service_supported: bool,
    pub(crate) service_enablement_supported: bool,
    pub(crate) service_installed: bool,
    pub(crate) service_disabled: bool,
    pub(crate) service_running: bool,
    pub(crate) service_status_detail: String,
    pub(crate) session_status: String,
    pub(crate) app_version: String,
    pub(crate) daemon_binary_version: String,
    pub(crate) service_binary_version: String,
    pub(crate) config_path: String,
    pub(crate) own_npub: String,
    pub(crate) own_pubkey_hex: String,
    pub(crate) network_id: String,
    pub(crate) active_network_invite: String,
    pub(crate) node_id: String,
    pub(crate) node_name: String,
    pub(crate) self_magic_dns_name: String,
    pub(crate) endpoint: String,
    pub(crate) tunnel_ip: String,
    pub(crate) listen_port: u16,
    pub(crate) exit_node: String,
    pub(crate) advertise_exit_node: bool,
    pub(crate) advertised_routes: Vec<String>,
    pub(crate) effective_advertised_routes: Vec<String>,
    pub(crate) use_public_relay_fallback: bool,
    pub(crate) relay_for_others: bool,
    pub(crate) provide_nat_assist: bool,
    pub(crate) relay_operator_running: bool,
    pub(crate) relay_operator_status: String,
    pub(crate) nat_assist_running: bool,
    pub(crate) nat_assist_status: String,
    pub(crate) magic_dns_suffix: String,
    pub(crate) magic_dns_status: String,
    pub(crate) autoconnect: bool,
    pub(crate) lan_pairing_active: bool,
    pub(crate) lan_pairing_remaining_secs: u64,
    pub(crate) launch_on_startup: bool,
    pub(crate) close_to_tray_on_close: bool,
    pub(crate) connected_peer_count: usize,
    pub(crate) expected_peer_count: usize,
    pub(crate) mesh_ready: bool,
    pub(crate) health: Vec<HealthIssue>,
    pub(crate) network: NetworkSummary,
    pub(crate) port_mapping: PortMappingStatus,
    pub(crate) networks: Vec<NetworkView>,
    pub(crate) relays: Vec<RelayView>,
    pub(crate) relay_summary: RelaySummary,
    pub(crate) relay_operator: Option<RelayOperatorView>,
    pub(crate) lan_peers: Vec<LanPeerView>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettingsPatch {
    pub(crate) node_name: Option<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) tunnel_ip: Option<String>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) exit_node: Option<String>,
    pub(crate) advertise_exit_node: Option<bool>,
    pub(crate) advertised_routes: Option<String>,
    pub(crate) use_public_relay_fallback: Option<bool>,
    pub(crate) relay_for_others: Option<bool>,
    pub(crate) provide_nat_assist: Option<bool>,
    pub(crate) magic_dns_suffix: Option<String>,
    pub(crate) autoconnect: Option<bool>,
    pub(crate) launch_on_startup: Option<bool>,
    pub(crate) close_to_tray_on_close: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrayNetworkGroup {
    pub(crate) title: String,
    pub(crate) devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrayExitNodeEntry {
    pub(crate) pubkey_hex: String,
    pub(crate) title: String,
    pub(crate) selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrayMenuItemSpec {
    Check {
        id: String,
        text: String,
        enabled: bool,
        checked: bool,
    },
    Text {
        id: Option<String>,
        text: String,
        enabled: bool,
    },
    Submenu {
        text: String,
        enabled: bool,
        items: Vec<TrayMenuItemSpec>,
    },
    Separator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrayRuntimeState {
    pub(crate) session_active: bool,
    pub(crate) service_setup_required: bool,
    pub(crate) service_enable_required: bool,
    pub(crate) status_text: String,
    pub(crate) this_device_text: String,
    pub(crate) this_device_copy_value: String,
    pub(crate) advertise_exit_node: bool,
    pub(crate) network_groups: Vec<TrayNetworkGroup>,
    pub(crate) exit_nodes: Vec<TrayExitNodeEntry>,
}

impl Default for TrayRuntimeState {
    fn default() -> Self {
        Self {
            session_active: false,
            service_setup_required: false,
            service_enable_required: false,
            status_text: "Disconnected".to_string(),
            this_device_text: "This Device: unavailable".to_string(),
            this_device_copy_value: String::new(),
            advertise_exit_node: false,
            network_groups: Vec::new(),
            exit_nodes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum RuntimePlatform {
    Desktop,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCapabilities {
    pub(crate) platform: &'static str,
    pub(crate) mobile: bool,
    pub(crate) vpn_session_control_supported: bool,
    pub(crate) cli_install_supported: bool,
    pub(crate) startup_settings_supported: bool,
    pub(crate) tray_behavior_supported: bool,
    pub(crate) runtime_status_detail: &'static str,
}

pub(crate) const fn current_runtime_platform() -> RuntimePlatform {
    if cfg!(target_os = "android") {
        RuntimePlatform::Android
    } else if cfg!(target_os = "ios") {
        RuntimePlatform::Ios
    } else {
        RuntimePlatform::Desktop
    }
}

pub(crate) const fn ios_runtime_is_simulator() -> bool {
    cfg!(all(target_os = "ios", target_abi = "sim"))
}

pub(crate) const fn ios_vpn_session_control_supported(ios_simulator: bool) -> bool {
    !ios_simulator
}

pub(crate) const fn ios_runtime_status_detail(ios_simulator: bool) -> &'static str {
    if ios_simulator {
        "iOS Simulator does not provide NetworkExtension VPN control; use a physical device for Packet Tunnel testing."
    } else {
        "iOS Packet Tunnel integration is available; desktop service management is unavailable."
    }
}

pub(crate) const fn runtime_capabilities_for_platform(
    platform: RuntimePlatform,
) -> RuntimeCapabilities {
    match platform {
        RuntimePlatform::Desktop => RuntimeCapabilities {
            platform: "desktop",
            mobile: false,
            vpn_session_control_supported: true,
            cli_install_supported: true,
            startup_settings_supported: true,
            tray_behavior_supported: true,
            runtime_status_detail: "",
        },
        RuntimePlatform::Android => RuntimeCapabilities {
            platform: "android",
            mobile: true,
            vpn_session_control_supported: true,
            cli_install_supported: false,
            startup_settings_supported: false,
            tray_behavior_supported: false,
            runtime_status_detail: "Android native VPN control is available; desktop service management is unavailable.",
        },
        RuntimePlatform::Ios => {
            let ios_simulator = ios_runtime_is_simulator();
            RuntimeCapabilities {
                platform: "ios",
                mobile: true,
                vpn_session_control_supported: ios_vpn_session_control_supported(ios_simulator),
                cli_install_supported: false,
                startup_settings_supported: false,
                tray_behavior_supported: false,
                runtime_status_detail: ios_runtime_status_detail(ios_simulator),
            }
        }
    }
}

pub(crate) const fn current_runtime_capabilities() -> RuntimeCapabilities {
    runtime_capabilities_for_platform(current_runtime_platform())
}

pub(crate) fn parse_service_operator_state(
    raw: &[u8],
) -> Result<SharedServiceOperatorState, serde_json::Error> {
    match serde_json::from_slice::<SharedServiceOperatorState>(raw) {
        Ok(state)
            if state.relay.is_some()
                || state.nat_assist.is_some()
                || !state.operator_pubkey.trim().is_empty() =>
        {
            Ok(state)
        }
        Err(service_error) => match serde_json::from_slice::<SharedRelayOperatorState>(raw) {
            Ok(relay_state) => Ok(SharedServiceOperatorState {
                updated_at: relay_state.updated_at,
                operator_pubkey: relay_state.relay_pubkey.clone(),
                relay: Some(relay_state),
                nat_assist: None,
            }),
            Err(_) => Err(service_error),
        },
        Ok(_) => match serde_json::from_slice::<SharedRelayOperatorState>(raw) {
            Ok(relay_state) => Ok(SharedServiceOperatorState {
                updated_at: relay_state.updated_at,
                operator_pubkey: relay_state.relay_pubkey.clone(),
                relay: Some(relay_state),
                nat_assist: None,
            }),
            Err(service_error) => Err(service_error),
        },
    }
}

pub(crate) fn within_peer_online_grace(
    last_handshake_at: Option<SystemTime>,
    now: SystemTime,
) -> bool {
    let Some(last_handshake_at) = last_handshake_at else {
        return false;
    };
    now.duration_since(last_handshake_at)
        .map(|elapsed| elapsed.as_secs() <= PEER_ONLINE_GRACE_SECS)
        .unwrap_or(false)
}

pub(crate) fn within_peer_presence_grace(
    last_signal_seen_at: Option<SystemTime>,
    now: SystemTime,
) -> bool {
    let Some(last_signal_seen_at) = last_signal_seen_at else {
        return false;
    };
    now.duration_since(last_signal_seen_at)
        .map(|elapsed| elapsed.as_secs() <= PEER_PRESENCE_GRACE_SECS)
        .unwrap_or(false)
}

pub(crate) fn peer_offers_exit_node(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

impl Drop for NvpnBackend {
    fn drop(&mut self) {
        #[cfg(target_os = "android")]
        let _ = self.android_session.stop();
        self.stop_lan_pairing();
    }
}

pub(crate) async fn run_lan_pairing_loop(
    tx: mpsc::Sender<LanPairingSignal>,
    stop_flag: Arc<AtomicBool>,
    own_npub: String,
    node_name: String,
    endpoint: String,
    invite: String,
) {
    let started_at = Instant::now();
    let multicast = std::net::Ipv4Addr::new(
        LAN_PAIRING_ADDR[0],
        LAN_PAIRING_ADDR[1],
        LAN_PAIRING_ADDR[2],
        LAN_PAIRING_ADDR[3],
    );
    let target = std::net::SocketAddr::from((LAN_PAIRING_ADDR, LAN_PAIRING_PORT));

    let std_socket =
        match std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, LAN_PAIRING_PORT)) {
            Ok(socket) => socket,
            Err(_) => return,
        };

    if std_socket
        .join_multicast_v4(&multicast, &std::net::Ipv4Addr::UNSPECIFIED)
        .is_err()
    {
        return;
    }

    if std_socket.set_nonblocking(true).is_err() {
        return;
    }

    let socket = match tokio::net::UdpSocket::from_std(std_socket) {
        Ok(socket) => socket,
        Err(_) => return,
    };

    let mut announce_interval = tokio::time::interval(Duration::from_secs(3));
    let mut idle_interval = tokio::time::interval(Duration::from_millis(250));
    let mut buffer = [0_u8; LAN_PAIRING_BUFFER_BYTES];

    loop {
        if stop_flag.load(Ordering::Relaxed)
            || started_at.elapsed() >= Duration::from_secs(LAN_PAIRING_DURATION_SECS)
        {
            return;
        }

        tokio::select! {
            _ = announce_interval.tick() => {
                let message = LanAnnouncement {
                    v: LAN_PAIRING_ANNOUNCEMENT_VERSION,
                    npub: own_npub.clone(),
                    node_name: node_name.clone(),
                    endpoint: endpoint.clone(),
                    invite: invite.clone(),
                    timestamp: unix_timestamp(),
                };

                if let Ok(encoded) = serde_json::to_vec(&message) {
                    let _ = socket.send_to(&encoded, target).await;
                }
            }
            recv = socket.recv_from(&mut buffer) => {
                if let Ok((len, _)) = recv
                    && let Some(signal) = decode_lan_pairing_announcement(&buffer[..len], &own_npub)
                {
                    let _ = tx.send(signal);
                }
            }
            _ = idle_interval.tick() => {}
        }
    }
}

pub(crate) struct AppState {
    pub(crate) backend: Arc<Mutex<NvpnBackend>>,
    pub(crate) last_tray_runtime_state: Arc<Mutex<TrayRuntimeState>>,
}

#[cfg(test)]
pub(crate) fn tauri_protocol_request_path(uri: &tauri::http::Uri, origin: &str) -> String {
    let request_uri = uri.to_string();
    let request_path = request_uri
        .split(&['?', '#'][..])
        .next()
        .unwrap_or_default()
        .strip_prefix(origin)
        .unwrap_or_default()
        .trim_start_matches('/');

    if request_path.is_empty() {
        "index.html".to_string()
    } else {
        request_path.to_string()
    }
}

#[cfg(target_os = "ios")]
pub(crate) fn reset_ios_probe() {
    let _ = std::fs::write(std::env::temp_dir().join("nvpn-ios-probe.log"), b"");
}

#[cfg(target_os = "ios")]
pub(crate) fn write_ios_probe(message: impl AsRef<str>) {
    let log_path = std::env::temp_dir().join("nvpn-ios-probe.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "{}", message.as_ref());
    }
}

#[cfg(target_os = "ios")]
pub(crate) fn ios_force_connect_requested() -> bool {
    env_flag_is_truthy(NVPN_IOS_FORCE_CONNECT_ENV)
}
