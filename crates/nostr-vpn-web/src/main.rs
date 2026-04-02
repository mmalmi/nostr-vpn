use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, PendingInboundJoinRequest, PendingOutboundJoinRequest, derive_mesh_tunnel_ip,
    maybe_autoconfigure_node, normalize_advertised_route, normalize_nostr_pubkey,
    normalize_runtime_network_id,
};
use nostr_vpn_core::diagnostics::{HealthIssue, NetworkSummary, PortMappingStatus};
use nostr_vpn_core::join_requests::{MeshJoinRequest, publish_join_request};
use serde::{Deserialize, Serialize};
use tower_http::services::{ServeDir, ServeFile};

const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const NVPN_GUI_IFACE_ENV: &str = "NVPN_GUI_IFACE";
const NETWORK_INVITE_PREFIX: &str = "nvpn://invite/";
const NETWORK_INVITE_VERSION: u8 = 2;
const PEER_PRESENCE_GRACE_SECS: u64 = 45;
const DEFAULT_STATIC_DIR: &str = "/usr/share/nostr-vpn/web";

#[derive(Debug, Parser)]
#[command(name = "nvpn-web")]
#[command(about = "HTTP API for the nostr-vpn web UI")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8081")]
    listen: SocketAddr,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    nvpn: Option<PathBuf>,
    #[arg(long)]
    static_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct ServerState {
    config_path: PathBuf,
    nvpn_bin: PathBuf,
    action_status: Arc<Mutex<String>>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": self.message,
            })),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CliStatusResponse {
    daemon: CliDaemonStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CliDaemonStatus {
    running: bool,
    state: Option<DaemonRuntimeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DaemonRuntimeState {
    updated_at: u64,
    #[serde(default)]
    binary_version: String,
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
    #[serde(default)]
    relay_operator_status: String,
    #[serde(default)]
    nat_assist_running: bool,
    #[serde(default)]
    nat_assist_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DaemonPeerState {
    participant_pubkey: String,
    node_id: String,
    tunnel_ip: String,
    endpoint: String,
    #[serde(default)]
    runtime_endpoint: Option<String>,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    rx_bytes: u64,
    public_key: String,
    #[serde(default)]
    advertised_routes: Vec<String>,
    presence_timestamp: u64,
    #[serde(default)]
    last_signal_seen_at: Option<u64>,
    reachable: bool,
    #[serde(default)]
    last_handshake_at: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct RelaySummary {
    up: usize,
    down: usize,
    checking: usize,
    unknown: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayView {
    url: String,
    state: String,
    status_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParticipantView {
    npub: String,
    pubkey_hex: String,
    is_admin: bool,
    tunnel_ip: String,
    magic_dns_alias: String,
    magic_dns_name: String,
    relay_path_active: bool,
    runtime_endpoint: String,
    tx_bytes: u64,
    rx_bytes: u64,
    advertised_routes: Vec<String>,
    offers_exit_node: bool,
    state: String,
    presence_state: String,
    status_text: String,
    last_signal_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutboundJoinRequestView {
    recipient_npub: String,
    recipient_pubkey_hex: String,
    requested_at_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InboundJoinRequestView {
    requester_npub: String,
    requester_pubkey_hex: String,
    requester_node_name: String,
    requested_at_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkView {
    id: String,
    name: String,
    enabled: bool,
    network_id: String,
    local_is_admin: bool,
    admin_npubs: Vec<String>,
    #[serde(rename = "joinRequestsEnabled")]
    listen_for_join_requests: bool,
    invite_inviter_npub: String,
    outbound_join_request: Option<OutboundJoinRequestView>,
    inbound_join_requests: Vec<InboundJoinRequestView>,
    online_count: usize,
    expected_count: usize,
    participants: Vec<ParticipantView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UiState {
    platform: String,
    mobile: bool,
    vpn_session_control_supported: bool,
    cli_install_supported: bool,
    startup_settings_supported: bool,
    tray_behavior_supported: bool,
    runtime_status_detail: String,
    daemon_running: bool,
    session_active: bool,
    relay_connected: bool,
    cli_installed: bool,
    service_supported: bool,
    service_enablement_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    service_running: bool,
    service_status_detail: String,
    session_status: String,
    app_version: String,
    daemon_binary_version: String,
    config_path: String,
    own_npub: String,
    own_pubkey_hex: String,
    network_id: String,
    active_network_invite: String,
    node_id: String,
    node_name: String,
    self_magic_dns_name: String,
    endpoint: String,
    tunnel_ip: String,
    listen_port: u16,
    exit_node: String,
    advertise_exit_node: bool,
    advertised_routes: Vec<String>,
    effective_advertised_routes: Vec<String>,
    use_public_relay_fallback: bool,
    relay_for_others: bool,
    provide_nat_assist: bool,
    relay_operator_running: bool,
    relay_operator_status: String,
    nat_assist_running: bool,
    nat_assist_status: String,
    magic_dns_suffix: String,
    magic_dns_status: String,
    autoconnect: bool,
    lan_pairing_active: bool,
    lan_pairing_remaining_secs: u64,
    launch_on_startup: bool,
    close_to_tray_on_close: bool,
    connected_peer_count: usize,
    expected_peer_count: usize,
    mesh_ready: bool,
    health: Vec<HealthIssue>,
    network: NetworkSummary,
    port_mapping: PortMappingStatus,
    networks: Vec<NetworkView>,
    relays: Vec<RelayView>,
    relay_summary: RelaySummary,
    relay_operator: Option<serde_json::Value>,
    lan_peers: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct SettingsPatch {
    node_name: Option<String>,
    endpoint: Option<String>,
    tunnel_ip: Option<String>,
    listen_port: Option<u16>,
    exit_node: Option<String>,
    advertise_exit_node: Option<bool>,
    advertised_routes: Option<String>,
    use_public_relay_fallback: Option<bool>,
    relay_for_others: Option<bool>,
    provide_nat_assist: Option<bool>,
    magic_dns_suffix: Option<String>,
    autoconnect: Option<bool>,
    launch_on_startup: Option<bool>,
    close_to_tray_on_close: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct NetworkInvite {
    v: u8,
    network_name: String,
    network_id: String,
    inviter_npub: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    inviter_node_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    admins: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    participants: Vec<String>,
    relays: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NameRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkNameRequest {
    network_id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkMeshRequest {
    network_id: String,
    mesh_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkEnabledRequest {
    network_id: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkIdRequest {
    network_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParticipantRequest {
    network_id: String,
    npub: String,
    alias: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPeerRequest {
    network_id: String,
    npub: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteRequest {
    invite: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequestAction {
    network_id: String,
    requester_npub: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AliasRequest {
    npub: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayRequest {
    relay: String,
}

#[derive(Debug, Clone, Default)]
struct PeerSnapshot {
    reachable: Option<bool>,
    last_handshake_at: Option<SystemTime>,
    endpoint: Option<String>,
    runtime_endpoint: Option<String>,
    tx_bytes: u64,
    rx_bytes: u64,
    error: Option<String>,
    last_signal_seen_at: Option<SystemTime>,
    advertised_routes: Vec<String>,
    offers_exit_node: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportStatus {
    Local,
    Online,
    Present,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresenceStatus {
    Local,
    Present,
    Absent,
    Unknown,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nostr_vpn_web=info".into()),
        )
        .init();

    let Args {
        listen,
        config,
        nvpn,
        static_dir,
    } = Args::parse();
    let config_path = config.unwrap_or_else(default_config_path);
    ensure_config_exists(&config_path)?;
    let nvpn_bin = resolve_nvpn_cli_path(nvpn)?;
    let static_dir = static_dir.or_else(discover_static_dir);

    let state = ServerState {
        config_path,
        nvpn_bin,
        action_status: Arc::new(Mutex::new(String::new())),
    };

    let mut app = Router::new()
        .route("/api/health", get(health))
        .route("/api/tick", post(tick))
        .route("/api/connect_session", post(connect_session))
        .route("/api/disconnect_session", post(disconnect_session))
        .route("/api/add_network", post(add_network))
        .route("/api/rename_network", post(rename_network))
        .route("/api/set_network_mesh_id", post(set_network_mesh_id))
        .route("/api/remove_network", post(remove_network))
        .route("/api/set_network_enabled", post(set_network_enabled))
        .route(
            "/api/set_network_join_requests_enabled",
            post(set_network_join_requests_enabled),
        )
        .route("/api/request_network_join", post(request_network_join))
        .route("/api/add_participant", post(add_participant))
        .route("/api/add_admin", post(add_admin))
        .route("/api/import_network_invite", post(import_network_invite))
        .route("/api/start_lan_pairing", post(start_lan_pairing))
        .route("/api/stop_lan_pairing", post(stop_lan_pairing))
        .route("/api/remove_participant", post(remove_participant))
        .route("/api/remove_admin", post(remove_admin))
        .route("/api/accept_join_request", post(accept_join_request))
        .route("/api/set_participant_alias", post(set_participant_alias))
        .route("/api/add_relay", post(add_relay))
        .route("/api/remove_relay", post(remove_relay))
        .route("/api/update_settings", post(update_settings))
        .with_state(state.clone());

    if let Some(static_dir) = static_dir {
        let index_path = static_dir.join("index.html");
        if !index_path.exists() {
            return Err(anyhow!(
                "static web UI directory is missing {}",
                index_path.display()
            ));
        }
        tracing::info!("serving static web UI from {}", static_dir.display());
        app = app.fallback_service(
            ServeDir::new(static_dir).not_found_service(ServeFile::new(index_path)),
        );
    } else {
        tracing::info!("static web UI disabled");
    }

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("nostr-vpn web api listening on {}", listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn tick(State(state): State<ServerState>) -> ApiResult<Json<UiState>> {
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn connect_session(State(state): State<ServerState>) -> ApiResult<Json<UiState>> {
    connect_session_inner(&state).map_err(bad_request)?;
    set_action_status(&state, "Daemon running");
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn disconnect_session(State(state): State<ServerState>) -> ApiResult<Json<UiState>> {
    disconnect_session_inner(&state).map_err(bad_request)?;
    set_action_status(&state, "Paused");
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn add_network(
    State(state): State<ServerState>,
    Json(request): Json<NameRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.add_network(&request.name);
        Ok("Network saved.".to_string())
    })
}

async fn rename_network(
    State(state): State<ServerState>,
    Json(request): Json<NetworkNameRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.rename_network(&request.network_id, &request.name)?;
        Ok("Network renamed.".to_string())
    })
}

async fn set_network_mesh_id(
    State(state): State<ServerState>,
    Json(request): Json<NetworkMeshRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.set_network_mesh_id(&request.network_id, &request.mesh_id)?;
        Ok("Mesh ID updated.".to_string())
    })
}

async fn remove_network(
    State(state): State<ServerState>,
    Json(request): Json<NetworkIdRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.remove_network(&request.network_id)?;
        Ok("Network removed.".to_string())
    })
}

async fn set_network_enabled(
    State(state): State<ServerState>,
    Json(request): Json<NetworkEnabledRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.set_network_enabled(&request.network_id, request.enabled)?;
        Ok(if request.enabled {
            "Network activated.".to_string()
        } else {
            "Network updated.".to_string()
        })
    })
}

async fn set_network_join_requests_enabled(
    State(state): State<ServerState>,
    Json(request): Json<NetworkEnabledRequest>,
) -> ApiResult<Json<UiState>> {
    let mut config = load_config(&state.config_path).map_err(internal_error)?;
    config
        .set_network_join_requests_enabled(&request.network_id, request.enabled)
        .map_err(bad_request)?;
    finalize_config_change(&state, &mut config).map_err(bad_request)?;
    if local_join_request_listener_enabled(&config) {
        connect_session_inner(&state).map_err(bad_request)?;
    }
    set_action_status(
        &state,
        if request.enabled {
            "Join requests enabled."
        } else {
            "Join requests disabled."
        },
    );
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn request_network_join(
    State(state): State<ServerState>,
    Json(request): Json<NetworkIdRequest>,
) -> ApiResult<Json<UiState>> {
    let mut config = load_config(&state.config_path).map_err(internal_error)?;
    let network = config
        .network_by_id(&request.network_id)
        .ok_or_else(|| ApiError::bad_request("network not found"))?
        .clone();

    let mut recipients = network.admins.clone();
    recipients.sort();
    recipients.dedup();
    if recipients.is_empty() {
        return Err(ApiError::bad_request(
            "this network was not imported from an invite",
        ));
    }

    let primary_recipient = preferred_join_request_recipient(&network)
        .or_else(|| recipients.first().cloned())
        .ok_or_else(|| ApiError::bad_request("this network was not imported from an invite"))?;

    if let Some(existing) = &network.outbound_join_request
        && existing.recipient == primary_recipient
    {
        return Ok(Json(build_ui_state(&state).map_err(internal_error)?));
    }

    let keys = config.nostr_keys().map_err(bad_request)?;
    let relays = config.nostr.relays.clone();
    let join_request = MeshJoinRequest {
        network_id: normalize_runtime_network_id(&network.network_id),
        requester_node_name: config.node_name.trim().to_string(),
    };

    for recipient in &recipients {
        publish_join_request(
            keys.clone(),
            &relays,
            recipient.clone(),
            join_request.clone(),
        )
        .await
        .map_err(bad_request)?;
    }

    if let Some(target) = config.network_by_id_mut(&request.network_id) {
        target.outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: primary_recipient.clone(),
            requested_at: current_unix_timestamp(),
        });
    }

    finalize_config_change(&state, &mut config).map_err(bad_request)?;
    let status = fetch_cli_status(&state).ok();
    if status.as_ref().is_none_or(|value| !value.daemon.running) {
        connect_session_inner(&state).map_err(bad_request)?;
        set_action_status(&state, "Join request sent and VPN started.");
    } else {
        set_action_status(&state, "Join request sent.");
    }
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn add_participant(
    State(state): State<ServerState>,
    Json(request): Json<ParticipantRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        let normalized =
            config.add_participant_to_network(&request.network_id, request.npub.trim())?;
        if let Some(alias) = request.alias.as_deref()
            && !alias.trim().is_empty()
        {
            config.set_peer_alias(&normalized, alias)?;
        }
        Ok("Participant saved.".to_string())
    })
}

async fn add_admin(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.add_admin_to_network(&request.network_id, &request.npub)?;
        Ok("Admin saved.".to_string())
    })
}

async fn import_network_invite(
    State(state): State<ServerState>,
    Json(request): Json<InviteRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        let invite = parse_network_invite(&request.invite)?;
        apply_network_invite_to_active_network(config, &invite)?;
        Ok(format!("Invite imported for {}.", invite.network_name))
    })
}

async fn start_lan_pairing(State(state): State<ServerState>) -> ApiResult<Json<UiState>> {
    set_action_status(
        &state,
        "LAN pairing is not available in the Umbrel web build yet.",
    );
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn stop_lan_pairing(State(state): State<ServerState>) -> ApiResult<Json<UiState>> {
    set_action_status(
        &state,
        "LAN pairing is not available in the Umbrel web build yet.",
    );
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn remove_participant(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        let normalized = normalize_nostr_pubkey(&request.npub)?;
        config.remove_participant_from_network(&request.network_id, &normalized)?;
        if let Some(network) = config.network_by_id_mut(&request.network_id) {
            if network.invite_inviter == normalized {
                network.invite_inviter.clear();
            }
            if network
                .outbound_join_request
                .as_ref()
                .is_some_and(|pending| pending.recipient == normalized)
            {
                network.outbound_join_request = None;
            }
            network
                .inbound_join_requests
                .retain(|pending| pending.requester != normalized);
        }
        Ok("Participant removed.".to_string())
    })
}

async fn remove_admin(
    State(state): State<ServerState>,
    Json(request): Json<NetworkPeerRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        let normalized = normalize_nostr_pubkey(&request.npub)?;
        config.remove_admin_from_network(&request.network_id, &normalized)?;
        Ok("Admin removed.".to_string())
    })
}

async fn accept_join_request(
    State(state): State<ServerState>,
    Json(request): Json<JoinRequestAction>,
) -> ApiResult<Json<UiState>> {
    let mut config = load_config(&state.config_path).map_err(internal_error)?;
    let requester = normalize_nostr_pubkey(&request.requester_npub).map_err(bad_request)?;
    let requester_node_name = config
        .network_by_id(&request.network_id)
        .and_then(|network| {
            network
                .inbound_join_requests
                .iter()
                .find(|pending| pending.requester == requester)
                .map(|pending| pending.requester_node_name.clone())
        })
        .unwrap_or_default();
    config
        .add_participant_to_network(&request.network_id, &requester)
        .map_err(bad_request)?;
    if !requester_node_name.trim().is_empty() {
        let _ = config.set_peer_alias(&requester, &requester_node_name);
    }
    if let Some(network) = config.network_by_id_mut(&request.network_id) {
        network
            .inbound_join_requests
            .retain(|pending| pending.requester != requester);
    }
    finalize_config_change(&state, &mut config).map_err(bad_request)?;
    let status = fetch_cli_status(&state).ok();
    if status.as_ref().is_none_or(|value| !value.daemon.running) {
        connect_session_inner(&state).map_err(bad_request)?;
        set_action_status(&state, "Join request accepted and VPN started.");
    } else {
        set_action_status(&state, "Join request accepted.");
    }
    Ok(Json(build_ui_state(&state).map_err(internal_error)?))
}

async fn set_participant_alias(
    State(state): State<ServerState>,
    Json(request): Json<AliasRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        config.set_peer_alias(&request.npub, &request.alias)?;
        Ok("Alias saved.".to_string())
    })
}

async fn add_relay(
    State(state): State<ServerState>,
    Json(request): Json<RelayRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        let relay = request.relay.trim();
        if relay.is_empty() {
            return Err(anyhow!("relay URL is empty"));
        }
        if !is_valid_relay_url(relay) {
            return Err(anyhow!("relay URL must start with ws:// or wss://"));
        }
        if !config.nostr.relays.iter().any(|existing| existing == relay) {
            config.nostr.relays.push(relay.to_string());
        }
        Ok("Relay saved.".to_string())
    })
}

async fn remove_relay(
    State(state): State<ServerState>,
    Json(request): Json<RelayRequest>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        if config.nostr.relays.len() <= 1 {
            return Err(anyhow!("at least one relay is required"));
        }
        config.nostr.relays.retain(|relay| relay != &request.relay);
        Ok("Relay removed.".to_string())
    })
}

async fn update_settings(
    State(state): State<ServerState>,
    Json(patch): Json<SettingsPatch>,
) -> ApiResult<Json<UiState>> {
    update_config_and_reload(&state, |config| {
        if let Some(node_name) = patch.node_name {
            config.node_name = node_name;
        }
        if let Some(endpoint) = patch.endpoint {
            config.node.endpoint = endpoint;
        }
        if let Some(tunnel_ip) = patch.tunnel_ip {
            config.node.tunnel_ip = tunnel_ip;
        }
        if let Some(listen_port) = patch.listen_port {
            if listen_port == 0 {
                return Err(anyhow!("listen port must be > 0"));
            }
            config.node.listen_port = listen_port;
        }
        if let Some(exit_node) = patch.exit_node {
            config.exit_node = parse_exit_node_input(&exit_node)?;
        }
        if let Some(advertise_exit_node) = patch.advertise_exit_node {
            config.node.advertise_exit_node = advertise_exit_node;
        }
        if let Some(advertised_routes) = patch.advertised_routes {
            config.node.advertised_routes = parse_advertised_routes_input(&advertised_routes)?;
        }
        if let Some(use_public_relay_fallback) = patch.use_public_relay_fallback {
            config.use_public_relay_fallback = use_public_relay_fallback;
        }
        if let Some(relay_for_others) = patch.relay_for_others {
            config.relay_for_others = relay_for_others;
        }
        if let Some(provide_nat_assist) = patch.provide_nat_assist {
            config.provide_nat_assist = provide_nat_assist;
        }
        if let Some(magic_dns_suffix) = patch.magic_dns_suffix {
            config.magic_dns_suffix = magic_dns_suffix;
        }
        if let Some(autoconnect) = patch.autoconnect {
            config.autoconnect = autoconnect;
        }
        if let Some(launch_on_startup) = patch.launch_on_startup {
            config.launch_on_startup = launch_on_startup;
        }
        if let Some(close_to_tray_on_close) = patch.close_to_tray_on_close {
            config.close_to_tray_on_close = close_to_tray_on_close;
        }
        Ok("Settings saved.".to_string())
    })
}

fn update_config_and_reload(
    state: &ServerState,
    update: impl FnOnce(&mut AppConfig) -> Result<String>,
) -> ApiResult<Json<UiState>> {
    let mut config = load_config(&state.config_path).map_err(internal_error)?;
    let message = update(&mut config).map_err(bad_request)?;
    finalize_config_change(state, &mut config).map_err(bad_request)?;
    set_action_status(state, message);
    Ok(Json(build_ui_state(state).map_err(internal_error)?))
}

fn finalize_config_change(state: &ServerState, config: &mut AppConfig) -> Result<()> {
    config.ensure_defaults();
    maybe_autoconfigure_node(config);
    save_config(&state.config_path, config)?;
    reload_daemon_if_running(state)?;
    Ok(())
}

fn build_ui_state(state: &ServerState) -> Result<UiState> {
    let mut config = load_config(&state.config_path)?;
    let daemon = fetch_cli_status(state).ok();
    clear_connected_join_requests(&state.config_path, &mut config, daemon.as_ref())?;

    let daemon_running = daemon.as_ref().is_some_and(|status| status.daemon.running);
    let daemon_state = daemon
        .as_ref()
        .and_then(|status| status.daemon.state.as_ref());
    let session_active = daemon_state.is_some_and(|value| value.session_active);
    let relay_connected = daemon_state.is_some_and(|value| value.relay_connected);
    let own_pubkey_hex = config.own_nostr_pubkey_hex().unwrap_or_default();
    let own_npub = to_npub(&own_pubkey_hex);
    let peer_snapshots = peer_snapshots(&config, daemon_state, session_active);
    let networks = network_rows(&config, &peer_snapshots, session_active);
    let relays = relay_views(&config, session_active, relay_connected);
    let relay_summary = relay_summary(&relays);
    let fallback_expected_peer_count = expected_peer_count(&config);
    let fallback_connected_peer_count = connected_configured_peer_count(&config, &peer_snapshots);
    let expected_peer_count = daemon_state
        .map(|value| value.expected_peer_count)
        .unwrap_or(fallback_expected_peer_count);
    let connected_peer_count = daemon_state
        .map(|value| value.connected_peer_count)
        .unwrap_or(fallback_connected_peer_count);
    let mesh_ready = daemon_state
        .map(|value| value.mesh_ready)
        .unwrap_or_else(|| is_mesh_complete(connected_peer_count, expected_peer_count));
    let health = daemon_state
        .map(|value| value.health.clone())
        .unwrap_or_default();
    let network = daemon_state
        .map(|value| value.network.clone())
        .unwrap_or_default();
    let port_mapping = daemon_state
        .map(|value| value.port_mapping.clone())
        .unwrap_or_default();
    let daemon_binary_version = daemon_state
        .map(|value| value.binary_version.clone())
        .unwrap_or_default();
    let session_status = if let Some(runtime) = daemon_state {
        runtime.session_status.clone()
    } else {
        let fallback = current_action_status(state);
        if fallback.trim().is_empty() {
            "Daemon not running".to_string()
        } else {
            fallback
        }
    };
    let magic_dns_status = if session_active {
        let suffix = config
            .magic_dns_suffix
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            "MagicDNS active in daemon (suffix disabled)".to_string()
        } else {
            format!("MagicDNS active in daemon for .{suffix}")
        }
    } else {
        "DNS disabled (VPN off)".to_string()
    };

    Ok(UiState {
        platform: "umbrel".to_string(),
        mobile: false,
        vpn_session_control_supported: true,
        cli_install_supported: false,
        startup_settings_supported: false,
        tray_behavior_supported: false,
        runtime_status_detail: String::new(),
        daemon_running,
        session_active,
        relay_connected,
        cli_installed: false,
        service_supported: false,
        service_enablement_supported: false,
        service_installed: false,
        service_disabled: false,
        service_running: false,
        service_status_detail: "Managed directly by the Umbrel app".to_string(),
        session_status,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        daemon_binary_version,
        config_path: state.config_path.display().to_string(),
        own_npub,
        own_pubkey_hex: own_pubkey_hex.clone(),
        network_id: config.effective_network_id(),
        active_network_invite: active_network_invite_code(&config).unwrap_or_default(),
        node_id: config.node.id.clone(),
        node_name: config.node_name.clone(),
        self_magic_dns_name: config.self_magic_dns_name().unwrap_or_default(),
        endpoint: config.node.endpoint.clone(),
        tunnel_ip: config.node.tunnel_ip.clone(),
        listen_port: config.node.listen_port,
        exit_node: npub_or_none(&config.exit_node).unwrap_or_default(),
        advertise_exit_node: config.node.advertise_exit_node,
        advertised_routes: config.node.advertised_routes.clone(),
        effective_advertised_routes: config.effective_advertised_routes(),
        use_public_relay_fallback: config.use_public_relay_fallback,
        relay_for_others: config.relay_for_others,
        provide_nat_assist: config.provide_nat_assist,
        relay_operator_running: daemon_state.is_some_and(|value| value.relay_operator_running),
        relay_operator_status: daemon_state
            .map(|value| value.relay_operator_status.clone())
            .unwrap_or_else(|| {
                if config.relay_for_others {
                    "Waiting for relay operator".to_string()
                } else {
                    "Relay operator disabled".to_string()
                }
            }),
        nat_assist_running: daemon_state.is_some_and(|value| value.nat_assist_running),
        nat_assist_status: daemon_state
            .map(|value| value.nat_assist_status.clone())
            .unwrap_or_else(|| {
                if config.provide_nat_assist {
                    "Waiting for NAT assist".to_string()
                } else {
                    "NAT assist disabled".to_string()
                }
            }),
        magic_dns_suffix: config.magic_dns_suffix.clone(),
        magic_dns_status,
        autoconnect: config.autoconnect,
        lan_pairing_active: false,
        lan_pairing_remaining_secs: 0,
        launch_on_startup: config.launch_on_startup,
        close_to_tray_on_close: config.close_to_tray_on_close,
        connected_peer_count,
        expected_peer_count,
        mesh_ready,
        health,
        network,
        port_mapping,
        networks,
        relays,
        relay_summary,
        relay_operator: None,
        lan_peers: Vec::new(),
    })
}

fn peer_snapshots(
    config: &AppConfig,
    daemon_state: Option<&DaemonRuntimeState>,
    session_active: bool,
) -> HashMap<String, PeerSnapshot> {
    let daemon_peers = daemon_state
        .map(|state| {
            state
                .peers
                .iter()
                .map(|peer| (peer.participant_pubkey.as_str(), peer))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    config
        .all_participant_pubkeys_hex()
        .into_iter()
        .map(|participant| {
            let snapshot = if !session_active {
                PeerSnapshot {
                    error: Some("vpn off".to_string()),
                    ..PeerSnapshot::default()
                }
            } else if let Some(peer) = daemon_peers.get(participant.as_str()) {
                let last_signal_seen_at = peer
                    .last_signal_seen_at
                    .and_then(epoch_secs_to_system_time)
                    .or_else(|| epoch_secs_to_system_time(peer.presence_timestamp));
                PeerSnapshot {
                    reachable: Some(peer.reachable),
                    last_handshake_at: peer.last_handshake_at.and_then(epoch_secs_to_system_time),
                    endpoint: (!peer.endpoint.trim().is_empty()).then(|| peer.endpoint.clone()),
                    runtime_endpoint: peer.runtime_endpoint.clone(),
                    tx_bytes: peer.tx_bytes,
                    rx_bytes: peer.rx_bytes,
                    error: if peer.reachable {
                        None
                    } else {
                        Some(
                            peer.error
                                .clone()
                                .unwrap_or_else(|| "awaiting handshake".to_string()),
                        )
                    },
                    last_signal_seen_at,
                    advertised_routes: peer.advertised_routes.clone(),
                    offers_exit_node: peer_offers_exit_node(&peer.advertised_routes),
                }
            } else {
                PeerSnapshot {
                    reachable: Some(false),
                    error: Some("no signal yet".to_string()),
                    ..PeerSnapshot::default()
                }
            };
            (participant, snapshot)
        })
        .collect()
}

fn network_rows(
    config: &AppConfig,
    snapshots: &HashMap<String, PeerSnapshot>,
    session_active: bool,
) -> Vec<NetworkView> {
    let own_pubkey_hex = config.own_nostr_pubkey_hex().ok();
    let mut rows = Vec::with_capacity(config.networks.len());

    for network in &config.networks {
        let mut participants = network.participants.clone();
        participants.sort();
        participants.dedup();

        let mut admin_npubs = network
            .admins
            .iter()
            .map(|admin| to_npub(admin))
            .collect::<Vec<_>>();
        admin_npubs.sort();
        admin_npubs.dedup();

        let participant_rows = participants
            .iter()
            .map(|participant| {
                participant_view(
                    config,
                    snapshots,
                    participant,
                    &network.network_id,
                    own_pubkey_hex.as_deref(),
                    network.admins.iter().any(|admin| admin == participant),
                )
            })
            .collect::<Vec<_>>();

        let remote_expected_count = if network.enabled {
            participants
                .iter()
                .filter(|participant| Some(participant.as_str()) != own_pubkey_hex.as_deref())
                .count()
        } else {
            0
        };
        let remote_online_count = if network.enabled {
            participants
                .iter()
                .filter(|participant| Some(participant.as_str()) != own_pubkey_hex.as_deref())
                .filter(|participant| {
                    matches!(
                        peer_transport_status(
                            snapshots.get(participant.as_str()),
                            participant,
                            own_pubkey_hex.as_deref()
                        ),
                        TransportStatus::Online
                    )
                })
                .count()
        } else {
            0
        };

        rows.push(NetworkView {
            id: network.id.clone(),
            name: network.name.clone(),
            enabled: network.enabled,
            network_id: normalize_runtime_network_id(&network.network_id),
            local_is_admin: own_pubkey_hex
                .as_deref()
                .is_some_and(|pubkey| network.admins.iter().any(|admin| admin == pubkey)),
            admin_npubs,
            listen_for_join_requests: network.listen_for_join_requests,
            invite_inviter_npub: if network.invite_inviter.is_empty() {
                String::new()
            } else {
                to_npub(&network.invite_inviter)
            },
            outbound_join_request: network
                .outbound_join_request
                .as_ref()
                .map(outbound_join_request_view),
            inbound_join_requests: inbound_join_request_views(&network.inbound_join_requests),
            online_count: network_online_device_count(
                remote_online_count,
                network.enabled,
                session_active,
            ),
            expected_count: network_device_count(remote_expected_count, network.enabled),
            participants: participant_rows,
        });
    }

    rows
}

fn participant_view(
    config: &AppConfig,
    snapshots: &HashMap<String, PeerSnapshot>,
    participant: &str,
    network_id: &str,
    own_pubkey_hex: Option<&str>,
    is_admin: bool,
) -> ParticipantView {
    let snapshot = snapshots.get(participant);
    let transport_status = peer_transport_status(snapshot, participant, own_pubkey_hex);
    let presence_status = peer_presence_status(snapshot, participant, own_pubkey_hex);
    let is_local = Some(participant) == own_pubkey_hex;
    let (magic_dns_alias, magic_dns_name) = if is_local {
        (
            config.self_magic_dns_label().unwrap_or_default(),
            config.self_magic_dns_name().unwrap_or_default(),
        )
    } else {
        (
            config.peer_alias(participant).unwrap_or_default(),
            config
                .magic_dns_name_for_participant(participant)
                .unwrap_or_default(),
        )
    };
    let advertised_routes = if is_local {
        config.effective_advertised_routes()
    } else {
        snapshot
            .map(|value| value.advertised_routes.clone())
            .unwrap_or_default()
    };
    let offers_exit_node = if is_local {
        config.node.advertise_exit_node
    } else {
        snapshot
            .map(|value| value.offers_exit_node)
            .unwrap_or(false)
    };
    let relay_path_active = snapshot
        .and_then(|value| value.runtime_endpoint.as_deref())
        .zip(snapshot.and_then(|value| value.endpoint.as_deref()))
        .is_some_and(|(runtime_endpoint, endpoint)| runtime_endpoint != endpoint)
        || snapshot
            .and_then(|value| value.runtime_endpoint.as_deref())
            .is_some_and(|runtime_endpoint| {
                snapshot
                    .and_then(|value| value.endpoint.as_deref())
                    .is_none()
                    && !runtime_endpoint.trim().is_empty()
            });

    ParticipantView {
        npub: to_npub(participant),
        pubkey_hex: participant.to_string(),
        is_admin,
        tunnel_ip: derive_mesh_tunnel_ip(network_id, participant)
            .unwrap_or_else(|| "-".to_string()),
        magic_dns_alias,
        magic_dns_name,
        relay_path_active,
        runtime_endpoint: snapshot
            .and_then(|value| value.runtime_endpoint.clone())
            .unwrap_or_default(),
        tx_bytes: snapshot.map(|value| value.tx_bytes).unwrap_or(0),
        rx_bytes: snapshot.map(|value| value.rx_bytes).unwrap_or(0),
        advertised_routes,
        offers_exit_node,
        state: transport_state_label(transport_status).to_string(),
        presence_state: presence_state_label(presence_status).to_string(),
        status_text: peer_status_line(snapshot, transport_status),
        last_signal_text: peer_presence_line(snapshot, participant, own_pubkey_hex),
    }
}

fn outbound_join_request_view(request: &PendingOutboundJoinRequest) -> OutboundJoinRequestView {
    OutboundJoinRequestView {
        recipient_npub: to_npub(&request.recipient),
        recipient_pubkey_hex: request.recipient.clone(),
        requested_at_text: join_request_age_text(request.requested_at),
    }
}

fn inbound_join_request_views(
    requests: &[PendingInboundJoinRequest],
) -> Vec<InboundJoinRequestView> {
    requests
        .iter()
        .map(|request| InboundJoinRequestView {
            requester_npub: to_npub(&request.requester),
            requester_pubkey_hex: request.requester.clone(),
            requester_node_name: request.requester_node_name.clone(),
            requested_at_text: join_request_age_text(request.requested_at),
        })
        .collect()
}

fn relay_views(config: &AppConfig, session_active: bool, relay_connected: bool) -> Vec<RelayView> {
    config
        .nostr
        .relays
        .iter()
        .map(|relay| {
            let (state, status_text) = if !session_active {
                ("unknown", "not checked")
            } else if relay_connected {
                ("up", "connected")
            } else {
                ("down", "disconnected")
            };
            RelayView {
                url: relay.clone(),
                state: state.to_string(),
                status_text: status_text.to_string(),
            }
        })
        .collect()
}

fn relay_summary(relays: &[RelayView]) -> RelaySummary {
    let mut summary = RelaySummary::default();
    for relay in relays {
        match relay.state.as_str() {
            "up" => summary.up += 1,
            "down" => summary.down += 1,
            "checking" => summary.checking += 1,
            _ => summary.unknown += 1,
        }
    }
    summary
}

fn peer_transport_status(
    snapshot: Option<&PeerSnapshot>,
    participant: &str,
    own_pubkey_hex: Option<&str>,
) -> TransportStatus {
    if Some(participant) == own_pubkey_hex {
        return TransportStatus::Local;
    }

    match snapshot {
        Some(status) if status.reachable == Some(true) => TransportStatus::Online,
        Some(status) if within_peer_presence_grace(status.last_signal_seen_at) => {
            TransportStatus::Present
        }
        Some(status) if status.reachable == Some(false) => TransportStatus::Offline,
        _ => TransportStatus::Unknown,
    }
}

fn peer_presence_status(
    snapshot: Option<&PeerSnapshot>,
    participant: &str,
    own_pubkey_hex: Option<&str>,
) -> PresenceStatus {
    if Some(participant) == own_pubkey_hex {
        return PresenceStatus::Local;
    }

    match snapshot {
        Some(status) if status.reachable == Some(true) => PresenceStatus::Present,
        Some(status) if within_peer_presence_grace(status.last_signal_seen_at) => {
            PresenceStatus::Present
        }
        Some(status) if status.reachable == Some(false) => PresenceStatus::Absent,
        _ => PresenceStatus::Unknown,
    }
}

fn peer_status_line(snapshot: Option<&PeerSnapshot>, status: TransportStatus) -> String {
    match status {
        TransportStatus::Local => "local".to_string(),
        TransportStatus::Online => match snapshot
            .and_then(|value| value.last_handshake_at)
            .and_then(|handshake_at| handshake_at.elapsed().ok())
            .map(|elapsed| elapsed.as_secs())
        {
            Some(age_secs) => format!("online (handshake {})", compact_age_text(age_secs)),
            None => "online".to_string(),
        },
        TransportStatus::Present => match snapshot.and_then(|value| value.endpoint.as_deref()) {
            Some(endpoint) if !endpoint.trim().is_empty() => format!(
                "awaiting WireGuard handshake via {}",
                shorten_middle(endpoint, 18, 10)
            ),
            _ => "awaiting WireGuard handshake".to_string(),
        },
        TransportStatus::Offline => match snapshot {
            Some(value) => {
                let checked = value
                    .last_signal_seen_at
                    .and_then(|seen_at| seen_at.elapsed().ok())
                    .map(|elapsed| elapsed.as_secs());
                match (value.error.as_deref(), checked) {
                    (Some(error), Some(age_secs)) => format!(
                        "offline ({}, {})",
                        shorten_middle(error, 18, 8),
                        compact_age_text(age_secs)
                    ),
                    (Some(error), None) => {
                        format!("offline ({})", shorten_middle(error, 18, 8))
                    }
                    (None, Some(age_secs)) => format!("offline ({})", compact_age_text(age_secs)),
                    (None, None) => "offline".to_string(),
                }
            }
            None => "offline".to_string(),
        },
        TransportStatus::Unknown => "unknown".to_string(),
    }
}

fn peer_presence_line(
    snapshot: Option<&PeerSnapshot>,
    participant: &str,
    own_pubkey_hex: Option<&str>,
) -> String {
    if Some(participant) == own_pubkey_hex {
        return "self".to_string();
    }

    let Some(seen_at) = snapshot.and_then(|value| value.last_signal_seen_at) else {
        return "nostr unseen".to_string();
    };

    let age_secs = seen_at
        .elapsed()
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("nostr seen {}", compact_age_text(age_secs))
}

fn transport_state_label(status: TransportStatus) -> &'static str {
    match status {
        TransportStatus::Local => "local",
        TransportStatus::Online => "online",
        TransportStatus::Present => "pending",
        TransportStatus::Offline => "offline",
        TransportStatus::Unknown => "unknown",
    }
}

fn presence_state_label(status: PresenceStatus) -> &'static str {
    match status {
        PresenceStatus::Local => "local",
        PresenceStatus::Present => "present",
        PresenceStatus::Absent => "absent",
        PresenceStatus::Unknown => "unknown",
    }
}

fn clear_connected_join_requests(
    config_path: &Path,
    config: &mut AppConfig,
    daemon_status: Option<&CliStatusResponse>,
) -> Result<()> {
    let Some(daemon_state) = daemon_status.and_then(|status| status.daemon.state.as_ref()) else {
        return Ok(());
    };
    if !daemon_state.session_active {
        return Ok(());
    }

    let own_pubkey_hex = config.own_nostr_pubkey_hex().ok();
    let peer_map = daemon_state
        .peers
        .iter()
        .map(|peer| (peer.participant_pubkey.as_str(), peer))
        .collect::<HashMap<_, _>>();

    let mut changed = false;
    for network in &mut config.networks {
        let Some(request) = network.outbound_join_request.as_ref() else {
            continue;
        };
        if Some(request.recipient.as_str()) == own_pubkey_hex.as_deref() {
            continue;
        }
        let Some(peer) = peer_map.get(request.recipient.as_str()) else {
            continue;
        };
        let Some(last_handshake_at) = peer.last_handshake_at.and_then(epoch_secs_to_system_time)
        else {
            continue;
        };
        let Some(requested_at) = epoch_secs_to_system_time(request.requested_at) else {
            continue;
        };
        if peer.reachable && last_handshake_at > requested_at {
            network.outbound_join_request = None;
            changed = true;
        }
    }

    if changed {
        save_config(config_path, config)?;
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<AppConfig> {
    let mut config = if path.exists() {
        AppConfig::load(path).with_context(|| format!("failed to load {}", path.display()))?
    } else {
        AppConfig::generated()
    };
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    Ok(config)
}

fn ensure_config_exists(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let mut config = AppConfig::generated();
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);
    save_config(path, &config)
}

fn save_config(path: &Path, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    config
        .save(path)
        .with_context(|| format!("failed to save {}", path.display()))
}

fn fetch_cli_status(state: &ServerState) -> Result<CliStatusResponse> {
    let config_path = config_path_arg(&state.config_path)?;
    let output = run_nvpn_command(
        state,
        &[
            "status",
            "--json",
            "--discover-secs",
            "0",
            "--config",
            config_path,
        ],
    )?;
    if !output.status.success() {
        return Err(command_failure("nvpn status", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_text = extract_json_document(&stdout)?;
    serde_json::from_str::<CliStatusResponse>(json_text)
        .context("failed to parse `nvpn status --json` output")
}

fn connect_session_inner(state: &ServerState) -> Result<()> {
    let config_path = config_path_arg(&state.config_path)?;
    let status = fetch_cli_status(state).ok();
    if status.as_ref().is_some_and(|value| value.daemon.running) {
        let output = run_nvpn_command(state, &["resume", "--config", config_path])?;
        if !output.status.success() {
            let failure = command_failure("nvpn resume", &output);
            if !is_not_running_message(&failure.to_string()) {
                return Err(failure);
            }
        }
        return Ok(());
    }

    if let Some(iface) = nvpn_gui_iface_override() {
        let output = run_nvpn_command(
            state,
            &[
                "start",
                "--daemon",
                "--connect",
                "--iface",
                &iface,
                "--config",
                config_path,
            ],
        )?;
        if !output.status.success() {
            let failure = command_failure("nvpn start", &output);
            if !is_already_running_message(&failure.to_string()) {
                return Err(failure);
            }
        }
    } else {
        let output = run_nvpn_command(
            state,
            &["start", "--daemon", "--connect", "--config", config_path],
        )?;
        if !output.status.success() {
            let failure = command_failure("nvpn start", &output);
            if !is_already_running_message(&failure.to_string()) {
                return Err(failure);
            }
        }
    }
    Ok(())
}

fn disconnect_session_inner(state: &ServerState) -> Result<()> {
    let config_path = config_path_arg(&state.config_path)?;
    let status = fetch_cli_status(state).ok();
    if !status.as_ref().is_some_and(|value| value.daemon.running) {
        return Ok(());
    }
    let output = run_nvpn_command(state, &["pause", "--config", config_path])?;
    if output.status.success() {
        return Ok(());
    }
    let failure = command_failure("nvpn pause", &output);
    if is_not_running_message(&failure.to_string()) {
        return Ok(());
    }
    Err(failure)
}

fn reload_daemon_if_running(state: &ServerState) -> Result<()> {
    let status = fetch_cli_status(state).ok();
    if !status.as_ref().is_some_and(|value| value.daemon.running) {
        return Ok(());
    }
    let config_path = config_path_arg(&state.config_path)?;
    let output = run_nvpn_command(state, &["reload", "--config", config_path])?;
    if output.status.success() {
        return Ok(());
    }
    let failure = command_failure("nvpn reload", &output);
    if is_not_running_message(&failure.to_string()) {
        return Ok(());
    }
    Err(failure)
}

fn run_nvpn_command(state: &ServerState, args: &[&str]) -> Result<Output> {
    Command::new(&state.nvpn_bin)
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "failed to execute {} {}",
                state.nvpn_bin.display(),
                args.join(" ")
            )
        })
}

fn resolve_nvpn_cli_path(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return validate_executable(path);
    }
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        return validate_executable(PathBuf::from(path));
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(nvpn_binary_name());
            if candidate.exists()
                && let Ok(validated) = validate_executable(candidate)
            {
                return Ok(validated);
            }
        }
    }
    Err(anyhow!(
        "nvpn CLI binary not found; set {} or add nvpn to PATH",
        NVPN_BIN_ENV
    ))
}

#[cfg(target_os = "windows")]
fn nvpn_binary_name() -> &'static str {
    "nvpn.exe"
}

#[cfg(not(target_os = "windows"))]
fn nvpn_binary_name() -> &'static str {
    "nvpn"
}

fn validate_executable(path: PathBuf) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(anyhow!("{} is not executable", canonical.display()));
        }
    }
    Ok(canonical)
}

fn default_config_path() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        return config_dir.join("nvpn").join("config.toml");
    }
    PathBuf::from("nvpn.toml")
}

fn discover_static_dir() -> Option<PathBuf> {
    let path = PathBuf::from(DEFAULT_STATIC_DIR);
    path.join("index.html").exists().then_some(path)
}

fn config_path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("config path is not valid UTF-8"))
}

fn command_failure(command: &str, output: &Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    anyhow!(
        "{command} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    )
}

fn extract_json_document(raw: &str) -> Result<&str> {
    let start = raw
        .find('{')
        .ok_or_else(|| anyhow!("command output did not contain JSON start"))?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| anyhow!("command output did not contain JSON end"))?;
    Ok(&raw[start..=end])
}

fn set_action_status(state: &ServerState, status: impl Into<String>) {
    if let Ok(mut guard) = state.action_status.lock() {
        *guard = status.into();
    }
}

fn current_action_status(state: &ServerState) -> String {
    state
        .action_status
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

fn bad_request(error: anyhow::Error) -> ApiError {
    ApiError::bad_request(error.to_string())
}

fn internal_error(error: anyhow::Error) -> ApiError {
    ApiError::internal(error.to_string())
}

fn to_npub(pubkey_hex: &str) -> String {
    PublicKey::from_hex(pubkey_hex)
        .ok()
        .and_then(|pubkey| pubkey.to_bech32().ok())
        .unwrap_or_else(|| pubkey_hex.to_string())
}

fn npub_or_none(value: &str) -> Option<String> {
    PublicKey::from_hex(value)
        .ok()
        .and_then(|pubkey| pubkey.to_bech32().ok())
}

fn active_network_invite_code(config: &AppConfig) -> Result<String> {
    let active_network = config.active_network();
    let roster = config.shared_network_roster(&active_network.id)?;
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let inviter_pubkey = own_pubkey
        .as_deref()
        .filter(|pubkey| config.is_network_admin(&active_network.id, pubkey))
        .map(str::to_string)
        .or_else(|| preferred_join_request_recipient(active_network))
        .or_else(|| active_network.admins.first().cloned())
        .ok_or_else(|| anyhow!("active network has no admin configured"))?;
    let invite = NetworkInvite {
        v: NETWORK_INVITE_VERSION,
        network_name: active_network.name.trim().to_string(),
        network_id: roster.network_id,
        inviter_npub: to_npub(&inviter_pubkey),
        inviter_node_name: if own_pubkey.as_deref() == Some(inviter_pubkey.as_str()) {
            config.node_name.trim().to_string()
        } else {
            config.peer_alias(&inviter_pubkey).unwrap_or_default()
        },
        admins: roster.admins.iter().map(|admin| to_npub(admin)).collect(),
        participants: roster
            .participants
            .iter()
            .map(|participant| to_npub(participant))
            .collect(),
        relays: normalized_invite_relays(&config.nostr.relays)?,
    };
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&invite).context("failed to encode invite JSON")?);
    Ok(format!("{NETWORK_INVITE_PREFIX}{encoded}"))
}

fn parse_network_invite(value: &str) -> Result<NetworkInvite> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("invite code is empty"));
    }

    let mut invite = if trimmed.starts_with('{') {
        serde_json::from_str::<NetworkInvite>(trimmed)
            .context("failed to parse network invite JSON")?
    } else {
        let payload = trimmed
            .strip_prefix(NETWORK_INVITE_PREFIX)
            .unwrap_or(trimmed);
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .context("failed to decode network invite payload")?;
        serde_json::from_slice::<NetworkInvite>(&decoded)
            .context("failed to parse network invite payload")?
    };

    if invite.v != 1 && invite.v != NETWORK_INVITE_VERSION {
        return Err(anyhow!(
            "unsupported invite version {}; expected 1 or {}",
            invite.v,
            NETWORK_INVITE_VERSION
        ));
    }

    invite.network_name = invite.network_name.trim().to_string();
    if invite.network_name.is_empty() {
        return Err(anyhow!("invite network name is empty"));
    }

    invite.network_id = invite.network_id.trim().to_string();
    if invite.network_id.is_empty() {
        return Err(anyhow!("invite network id is empty"));
    }

    invite.inviter_npub = to_npub(&normalize_nostr_pubkey(&invite.inviter_npub)?);
    invite.inviter_node_name = invite.inviter_node_name.trim().to_string();
    invite.admins = normalized_invite_pubkeys(&invite.admins)?;
    if !invite
        .admins
        .iter()
        .any(|admin| admin == &invite.inviter_npub)
    {
        invite.admins.push(invite.inviter_npub.clone());
        invite.admins.sort();
        invite.admins.dedup();
    }
    invite.participants = normalized_invite_pubkeys(&invite.participants)?;
    if invite.participants.is_empty() {
        invite.participants.push(invite.inviter_npub.clone());
    }
    invite.relays = normalized_invite_relays(&invite.relays)?;
    Ok(invite)
}

fn apply_network_invite_to_active_network(
    config: &mut AppConfig,
    invite: &NetworkInvite,
) -> Result<()> {
    let normalized_invite_network_id = normalize_runtime_network_id(&invite.network_id);
    let normalized_inviter_pubkey = normalize_nostr_pubkey(&invite.inviter_npub)?;
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let invite_admins = invite
        .admins
        .iter()
        .map(|admin| normalize_nostr_pubkey(admin))
        .collect::<Result<Vec<_>>>()?;
    let invite_participants = invite
        .participants
        .iter()
        .map(|participant| normalize_nostr_pubkey(participant))
        .collect::<Result<Vec<_>>>()?;

    let (target_network_id, reset_membership) = if let Some(existing) =
        config.networks.iter().find(|network| {
            normalize_runtime_network_id(&network.network_id) == normalized_invite_network_id
        }) {
        (existing.id.clone(), false)
    } else if network_should_adopt_invite(config.active_network()) {
        (config.active_network().id.clone(), true)
    } else {
        let network_id = config.add_network(&invite.network_name);
        config.set_network_enabled(&network_id, true)?;
        (network_id, true)
    };

    let should_adopt_name = config
        .network_by_id(&target_network_id)
        .map(network_should_adopt_invite)
        .unwrap_or(false);
    let inviter_already_configured = config
        .network_by_id(&target_network_id)
        .map(|network| {
            network
                .participants
                .iter()
                .any(|participant| participant == &normalized_inviter_pubkey)
                || network
                    .admins
                    .iter()
                    .any(|admin| admin == &normalized_inviter_pubkey)
        })
        .unwrap_or(false);

    config.set_network_enabled(&target_network_id, true)?;
    config.set_network_mesh_id(&target_network_id, &invite.network_id)?;
    if let Some(network) = config.network_by_id_mut(&target_network_id) {
        if reset_membership {
            network.participants.clear();
            network.admins.clear();
            network.shared_roster_updated_at = 0;
            network.shared_roster_signed_by.clear();
        }

        for participant in &invite_participants {
            if own_pubkey.as_deref() == Some(participant.as_str()) {
                continue;
            }
            network.participants.push(participant.clone());
        }
        network.participants.sort();
        network.participants.dedup();

        for admin in &invite_admins {
            network.admins.push(admin.clone());
        }
        if !network
            .admins
            .iter()
            .any(|admin| admin == &normalized_inviter_pubkey)
        {
            network.admins.push(normalized_inviter_pubkey.clone());
        }
        network.admins.sort();
        network.admins.dedup();

        network.invite_inviter = if network
            .admins
            .iter()
            .any(|admin| admin == &normalized_inviter_pubkey)
        {
            normalized_inviter_pubkey.clone()
        } else {
            network.admins.first().cloned().unwrap_or_default()
        };
        if network
            .outbound_join_request
            .as_ref()
            .is_some_and(|request| {
                !network
                    .admins
                    .iter()
                    .any(|admin| admin == &request.recipient)
            })
        {
            network.outbound_join_request = None;
        }
    }

    if !inviter_already_configured && !invite.inviter_node_name.trim().is_empty() {
        let _ = config.set_peer_alias(&normalized_inviter_pubkey, &invite.inviter_node_name);
    }

    if should_adopt_name && let Some(network) = config.network_by_id_mut(&target_network_id) {
        network.name = invite.network_name.trim().to_string();
    }

    for relay in &invite.relays {
        if !config.nostr.relays.iter().any(|existing| existing == relay) {
            config.nostr.relays.push(relay.clone());
        }
    }

    Ok(())
}

fn preferred_join_request_recipient(
    network: &nostr_vpn_core::config::NetworkConfig,
) -> Option<String> {
    if !network.invite_inviter.is_empty()
        && network
            .admins
            .iter()
            .any(|admin| admin == &network.invite_inviter)
    {
        return Some(network.invite_inviter.clone());
    }
    network.admins.first().cloned()
}

fn network_should_adopt_invite(network: &nostr_vpn_core::config::NetworkConfig) -> bool {
    let trimmed = network.name.trim();
    network.participants.is_empty() && (trimmed.is_empty() || trimmed.starts_with("Network "))
}

fn normalized_invite_pubkeys(pubkeys: &[String]) -> Result<Vec<String>> {
    let mut normalized = pubkeys
        .iter()
        .map(|pubkey| normalize_nostr_pubkey(pubkey).map(|value| to_npub(&value)))
        .collect::<Result<Vec<_>>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalized_invite_relays(relays: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for relay in relays {
        let relay = relay.trim();
        if relay.is_empty() {
            continue;
        }
        if !is_valid_relay_url(relay) {
            return Err(anyhow!("invalid invite relay '{relay}'"));
        }
        if !normalized.iter().any(|existing| existing == relay) {
            normalized.push(relay.to_string());
        }
    }
    Ok(normalized)
}

fn is_valid_relay_url(value: &str) -> bool {
    value.starts_with("ws://") || value.starts_with("wss://")
}

fn parse_exit_node_input(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("none")
    {
        return Ok(String::new());
    }
    normalize_nostr_pubkey(trimmed)
}

fn parse_advertised_routes_input(value: &str) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for raw in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let normalized = normalize_advertised_route(raw)
            .ok_or_else(|| anyhow!("invalid advertised route '{raw}'"))?;
        if !routes.iter().any(|existing| existing == &normalized) {
            routes.push(normalized);
        }
    }
    Ok(routes)
}

fn within_peer_presence_grace(last_seen_at: Option<SystemTime>) -> bool {
    last_seen_at
        .and_then(|seen_at| seen_at.elapsed().ok())
        .map(|elapsed| elapsed.as_secs() <= PEER_PRESENCE_GRACE_SECS)
        .unwrap_or(false)
}

fn peer_offers_exit_node(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

fn epoch_secs_to_system_time(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(value))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn compact_age_text(age_secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const WEEK: u64 = 7 * DAY;
    const MONTH: u64 = 30 * DAY;
    const YEAR: u64 = 365 * DAY;

    match age_secs {
        0..MINUTE => format!("{age_secs}s ago"),
        MINUTE..HOUR => format!("{}m ago", age_secs / MINUTE),
        HOUR..DAY => format!("{}h ago", age_secs / HOUR),
        DAY..WEEK => format!("{}d ago", age_secs / DAY),
        WEEK..MONTH => format!("{}w ago", age_secs / WEEK),
        MONTH..YEAR => format!("{}mo ago", age_secs / MONTH),
        _ => format!("{}y ago", age_secs / YEAR),
    }
}

fn join_request_age_text(requested_at: u64) -> String {
    let age_secs = epoch_secs_to_system_time(requested_at)
        .and_then(|requested_at| requested_at.elapsed().ok())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    compact_age_text(age_secs)
}

fn shorten_middle(value: &str, head: usize, tail: usize) -> String {
    if value.len() <= head + tail + 3 {
        return value.to_string();
    }
    format!(
        "{}...{}",
        value.chars().take(head).collect::<String>(),
        value
            .chars()
            .rev()
            .take(tail)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    )
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

fn connected_configured_peer_count(
    config: &AppConfig,
    snapshots: &HashMap<String, PeerSnapshot>,
) -> usize {
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    config
        .participant_pubkeys_hex()
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey.as_deref())
        .filter(|participant| {
            snapshots
                .get(participant.as_str())
                .and_then(|snapshot| snapshot.reachable)
                .unwrap_or(false)
        })
        .count()
}

fn network_device_count(remote_device_count: usize, enabled: bool) -> usize {
    if enabled {
        remote_device_count.saturating_add(1)
    } else {
        0
    }
}

fn network_online_device_count(
    remote_online_count: usize,
    enabled: bool,
    session_active: bool,
) -> usize {
    if enabled {
        remote_online_count.saturating_add(usize::from(session_active))
    } else {
        0
    }
}

fn is_mesh_complete(connected: usize, expected: usize) -> bool {
    expected > 0 && connected >= expected
}

fn local_join_request_listener_enabled(config: &AppConfig) -> bool {
    let Ok(own_pubkey) = config.own_nostr_pubkey_hex() else {
        return false;
    };
    config.networks.iter().any(|network| {
        network.listen_for_join_requests && network.admins.iter().any(|admin| admin == &own_pubkey)
    })
}

fn nvpn_gui_iface_override() -> Option<String> {
    env::var(NVPN_GUI_IFACE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_already_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("already running")
}

fn is_not_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("not running")
}
