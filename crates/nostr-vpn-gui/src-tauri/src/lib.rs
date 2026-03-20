#![cfg_attr(any(target_os = "android", target_os = "ios", test), allow(dead_code))]

#[cfg(any(target_os = "android", test))]
mod android_session;
#[cfg(any(target_os = "android", test))]
mod android_vpn;
#[cfg(any(target_os = "android", test))]
mod mobile_wg;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, derive_mesh_tunnel_ip, maybe_autoconfigure_node, normalize_advertised_route,
    normalize_nostr_pubkey,
};
use nostr_vpn_core::diagnostics::{HealthIssue, NetworkSummary, PortMappingStatus};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri::WindowEvent;
#[cfg(target_os = "macos")]
use tauri::image::Image;
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri::menu::{
    CheckMenuItemBuilder, Menu, MenuItemBuilder, PredefinedMenuItem, Submenu, SubmenuBuilder,
};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State};
use tokio::runtime::Runtime;

const LAN_DISCOVERY_ADDR: [u8; 4] = [239, 255, 73, 73];
const LAN_DISCOVERY_PORT: u16 = 38911;
const LAN_DISCOVERY_STALE_AFTER_SECS: u64 = 16;
// Keep the GUI's online/offline grace aligned with the daemon's WireGuard
// session window so idle peers do not flap back to "awaiting handshake".
const PEER_ONLINE_GRACE_SECS: u64 = 180;
const PEER_PRESENCE_GRACE_SECS: u64 = 45;
const TRAY_ICON_ID: &str = "nvpn-tray";
const TRAY_OPEN_MENU_ID: &str = "tray_open_main";
const TRAY_IDENTITY_MENU_ID: &str = "tray_identity";
const TRAY_VPN_TOGGLE_MENU_ID: &str = "tray_vpn_toggle";
const TRAY_RUN_EXIT_NODE_MENU_ID: &str = "tray_run_exit_node";
const TRAY_EXIT_NODE_NONE_MENU_ID: &str = "tray_exit_node_none";
const TRAY_EXIT_NODE_MENU_ID_PREFIX: &str = "tray_exit_node::";
const TRAY_QUIT_UI_MENU_ID: &str = "tray_quit_ui";
const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const AUTOSTART_LAUNCH_ARG: &str = "--autostart";
const GUI_SERVICE_SETUP_REQUIRED_STATUS: &str =
    "Install background service to turn VPN on from the app";
const GUI_SERVICE_SETUP_REQUIRED_AUTOCONNECT_STATUS: &str =
    "Install background service to enable app auto-connect";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
const NETWORK_INVITE_PREFIX: &str = "nvpn://invite/";
const NETWORK_INVITE_VERSION: u8 = 1;

#[derive(Debug, Clone, Default)]
struct RelayStatus {
    state: String,
    status_text: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct RelaySummary {
    up: usize,
    down: usize,
    checking: usize,
    unknown: usize,
}

#[derive(Debug, Clone, Default)]
struct PeerLinkStatus {
    reachable: Option<bool>,
    last_handshake_at: Option<SystemTime>,
    endpoint: Option<String>,
    error: Option<String>,
    checked_at: Option<SystemTime>,
    last_signal_seen_at: Option<SystemTime>,
    advertised_routes: Vec<String>,
    offers_exit_node: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfiguredPeerStatus {
    Local,
    Online,
    Present,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerPresenceStatus {
    Local,
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone)]
struct LanPeerRecord {
    npub: String,
    node_name: String,
    endpoint: String,
    last_seen: SystemTime,
}

#[derive(Debug, Clone)]
struct LanDiscoverySignal {
    npub: String,
    node_name: String,
    endpoint: String,
    seen_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LanAnnouncement {
    v: u8,
    npub: String,
    node_name: String,
    endpoint: String,
    timestamp: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct CliStatusResponse {
    daemon: CliDaemonStatus,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
struct CliServiceStatusResponse {
    supported: bool,
    installed: bool,
    #[serde(default)]
    disabled: bool,
    loaded: bool,
    running: bool,
    pid: Option<u32>,
    label: String,
    plist_path: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct CliDaemonStatus {
    running: bool,
    state: Option<DaemonRuntimeState>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonRuntimeState {
    updated_at: u64,
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
    peers: Vec<DaemonPeerState>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonPeerState {
    participant_pubkey: String,
    node_id: String,
    tunnel_ip: String,
    endpoint: String,
    public_key: String,
    #[serde(default)]
    advertised_routes: Vec<String>,
    presence_timestamp: u64,
    last_signal_seen_at: Option<u64>,
    reachable: bool,
    last_handshake_at: Option<u64>,
    error: Option<String>,
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
    tunnel_ip: String,
    magic_dns_alias: String,
    magic_dns_name: String,
    advertised_routes: Vec<String>,
    offers_exit_node: bool,
    state: String,
    presence_state: String,
    status_text: String,
    last_signal_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkView {
    id: String,
    name: String,
    enabled: bool,
    network_id: String,
    online_count: usize,
    expected_count: usize,
    participants: Vec<ParticipantView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LanPeerView {
    npub: String,
    node_name: String,
    endpoint: String,
    last_seen_text: String,
    configured: bool,
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
    config_path: String,
    own_npub: String,
    own_pubkey_hex: String,
    network_id: String,
    active_network_invite: String,
    node_id: String,
    node_name: String,
    endpoint: String,
    tunnel_ip: String,
    listen_port: u16,
    exit_node: String,
    advertise_exit_node: bool,
    advertised_routes: Vec<String>,
    effective_advertised_routes: Vec<String>,
    magic_dns_suffix: String,
    magic_dns_status: String,
    auto_disconnect_relays_when_mesh_ready: bool,
    autoconnect: bool,
    lan_discovery_enabled: bool,
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
    lan_peers: Vec<LanPeerView>,
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
    magic_dns_suffix: Option<String>,
    auto_disconnect_relays_when_mesh_ready: Option<bool>,
    autoconnect: Option<bool>,
    lan_discovery_enabled: Option<bool>,
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
    relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayNetworkGroup {
    title: String,
    devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayExitNodeEntry {
    pubkey_hex: String,
    title: String,
    selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrayMenuItemSpec {
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
struct TrayRuntimeState {
    session_active: bool,
    service_setup_required: bool,
    service_enable_required: bool,
    status_text: String,
    identity_npub: String,
    identity_text: String,
    this_device_text: String,
    advertise_exit_node: bool,
    network_groups: Vec<TrayNetworkGroup>,
    exit_nodes: Vec<TrayExitNodeEntry>,
}

impl Default for TrayRuntimeState {
    fn default() -> Self {
        Self {
            session_active: false,
            service_setup_required: false,
            service_enable_required: false,
            status_text: "Disconnected".to_string(),
            identity_npub: String::new(),
            identity_text: tray_identity_text(""),
            this_device_text: "This Device: unavailable".to_string(),
            advertise_exit_node: false,
            network_groups: Vec::new(),
            exit_nodes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum RuntimePlatform {
    Desktop,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeCapabilities {
    platform: &'static str,
    mobile: bool,
    vpn_session_control_supported: bool,
    cli_install_supported: bool,
    startup_settings_supported: bool,
    tray_behavior_supported: bool,
    runtime_status_detail: &'static str,
}

const fn current_runtime_platform() -> RuntimePlatform {
    if cfg!(target_os = "android") {
        RuntimePlatform::Android
    } else if cfg!(target_os = "ios") {
        RuntimePlatform::Ios
    } else {
        RuntimePlatform::Desktop
    }
}

const fn runtime_capabilities_for_platform(platform: RuntimePlatform) -> RuntimeCapabilities {
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
        RuntimePlatform::Ios => RuntimeCapabilities {
            platform: "ios",
            mobile: true,
            vpn_session_control_supported: false,
            cli_install_supported: false,
            startup_settings_supported: false,
            tray_behavior_supported: false,
            runtime_status_detail: "Mobile VPN service integration is not wired up yet. Network editing works, but tunnel control is disabled.",
        },
    }
}

const fn current_runtime_capabilities() -> RuntimeCapabilities {
    runtime_capabilities_for_platform(current_runtime_platform())
}

struct NvpnBackend {
    runtime: Runtime,
    config_path: PathBuf,
    config: AppConfig,
    nvpn_bin: Option<PathBuf>,
    #[cfg(target_os = "android")]
    android_session: android_session::AndroidSessionManager,

    session_status: String,
    daemon_running: bool,
    session_active: bool,
    relay_connected: bool,
    service_supported: bool,
    service_enablement_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    service_running: bool,
    service_status_detail: String,
    daemon_state: Option<DaemonRuntimeState>,

    relay_status: HashMap<String, RelayStatus>,
    peer_status: HashMap<String, PeerLinkStatus>,

    lan_discovery_running: bool,
    lan_discovery_rx: Option<mpsc::Receiver<LanDiscoverySignal>>,
    lan_discovery_stop: Option<Arc<AtomicBool>>,
    lan_peers: HashMap<String, LanPeerRecord>,

    magic_dns_status: String,
}

impl NvpnBackend {
    fn new(
        app_handle: tauri::AppHandle,
        config_path: PathBuf,
        launched_from_autostart: bool,
    ) -> Result<Self> {
        #[cfg(not(target_os = "android"))]
        let _ = &app_handle;

        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        #[cfg(target_os = "android")]
        let android_session =
            android_session::AndroidSessionManager::new(app_handle, runtime.handle().clone());

        let mut config = if config_path.exists() {
            AppConfig::load(&config_path).context("failed to load config")?
        } else {
            let generated = AppConfig::generated();
            generated
                .save(&config_path)
                .context("failed to persist generated config")?;
            generated
        };

        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);

        let relay_status = config
            .nostr
            .relays
            .iter()
            .map(|relay| {
                (
                    relay.clone(),
                    RelayStatus {
                        state: "unknown".to_string(),
                        status_text: "not checked".to_string(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let peer_status = config
            .all_participant_pubkeys_hex()
            .iter()
            .map(|participant| (participant.clone(), PeerLinkStatus::default()))
            .collect::<HashMap<_, _>>();

        let nvpn_bin = resolve_nvpn_cli_path().ok();

        let mut backend = Self {
            runtime,
            config_path,
            config,
            nvpn_bin,
            #[cfg(target_os = "android")]
            android_session,
            session_status: "Disconnected".to_string(),
            daemon_running: false,
            session_active: false,
            relay_connected: false,
            service_supported: cfg!(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "windows"
            )),
            service_enablement_supported: cfg!(target_os = "macos"),
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: String::new(),
            daemon_state: None,
            relay_status,
            peer_status,
            lan_discovery_running: false,
            lan_discovery_rx: None,
            lan_discovery_stop: None,
            lan_peers: HashMap::new(),
            magic_dns_status: "DNS disabled (VPN off)".to_string(),
        };

        backend.ensure_relay_status_entries();
        backend.ensure_peer_status_entries();
        backend.maybe_refresh_lan_discovery();
        backend.sync_daemon_state();

        let wants_autoconnect =
            backend.config.autoconnect && !backend.config.participant_pubkeys_hex().is_empty();
        let defer_to_installed_service = should_defer_gui_daemon_start_to_service_on_autostart(
            launched_from_autostart,
            backend.service_installed,
            backend.service_disabled,
        );
        if should_start_gui_daemon_on_launch(
            backend.config.autoconnect,
            !backend.config.participant_pubkeys_hex().is_empty(),
            backend.gui_requires_service_action(),
        ) && !backend.daemon_running
            && !defer_to_installed_service
        {
            if let Err(error) = backend.start_daemon_process() {
                backend.session_status = format!("Daemon start failed: {error}");
            }
            backend.sync_daemon_state();
        } else if wants_autoconnect && defer_to_installed_service && !backend.daemon_running {
            backend.session_status = "Waiting for background service to start".to_string();
        } else if wants_autoconnect && backend.gui_requires_service_install() {
            backend.session_status = gui_service_setup_status_text(true).to_string();
        } else if wants_autoconnect && backend.gui_requires_service_enable() {
            backend.session_status = gui_service_enable_status_text(true).to_string();
        }

        Ok(backend)
    }

    fn connect_session(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.session_status = runtime.runtime_status_detail.to_string();
            return Err(anyhow!(self.session_status.clone()));
        }
        self.persist_config()?;
        self.sync_daemon_state();
        if self.daemon_running {
            self.resume_daemon_process()?;
        } else if self.gui_requires_service_install() {
            self.session_status = gui_service_setup_status_text(false).to_string();
            return Err(anyhow!(self.session_status.clone()));
        } else if self.gui_requires_service_enable() {
            self.session_status = gui_service_enable_status_text(false).to_string();
            return Err(anyhow!(self.session_status.clone()));
        } else {
            self.start_daemon_process()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    fn disconnect_session(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.session_status = runtime.runtime_status_detail.to_string();
            return Err(anyhow!(self.session_status.clone()));
        }
        if self.daemon_running {
            self.pause_daemon_process()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    fn add_network(&mut self, name: &str) -> Result<()> {
        self.config.add_network(name);
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_peer_status_entries();
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();

        Ok(())
    }

    fn rename_network(&mut self, network_id: &str, name: &str) -> Result<()> {
        self.config.rename_network(network_id, name)?;
        self.persist_config()?;
        self.sync_daemon_state();
        Ok(())
    }

    fn set_network_mesh_id(&mut self, network_id: &str, mesh_id: &str) -> Result<()> {
        let is_active_network = self
            .config
            .network_by_id(network_id)
            .map(|network| network.enabled)
            .ok_or_else(|| anyhow!("network not found"))?;

        self.config.set_network_mesh_id(network_id, mesh_id)?;
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        if is_active_network {
            self.ensure_peer_status_entries();
            self.reload_daemon_if_running()?;
            self.maybe_refresh_lan_discovery();
            if self.daemon_running {
                self.session_status = "Mesh ID updated and applied.".to_string();
            }
        }

        self.sync_daemon_state();
        Ok(())
    }

    fn remove_network(&mut self, network_id: &str) -> Result<()> {
        self.config.remove_network(network_id)?;
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_peer_status_entries();
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();

        Ok(())
    }

    fn set_network_enabled(&mut self, network_id: &str, enabled: bool) -> Result<()> {
        self.config.set_network_enabled(network_id, enabled)?;
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.reload_daemon_if_running()?;
        self.sync_daemon_state();
        Ok(())
    }

    fn add_participant(&mut self, network_id: &str, npub: &str, alias: Option<&str>) -> Result<()> {
        let input = npub.trim();
        if input.is_empty() {
            return Err(anyhow!("participant npub is empty"));
        }
        if !input.starts_with("npub1") {
            return Err(anyhow!("participant must be an npub"));
        }

        let normalized = self.config.add_participant_to_network(network_id, input)?;
        if let Some(alias) = alias {
            let alias = alias.trim();
            if !alias.is_empty() {
                self.config.set_peer_alias(&normalized, alias)?;
            }
        }
        self.peer_status.entry(normalized).or_default();

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_peer_status_entries();
        if self.daemon_running {
            self.reload_daemon_process()?;
            self.session_status = "Participant saved and applied.".to_string();
        }
        self.sync_daemon_state();
        self.maybe_refresh_lan_discovery();

        Ok(())
    }

    fn import_network_invite(&mut self, invite_code: &str) -> Result<()> {
        let invite = parse_network_invite(invite_code)?;
        apply_network_invite_to_active_network(&mut self.config, &invite)?;
        let normalized_inviter = normalize_nostr_pubkey(&invite.inviter_npub)?;
        self.peer_status.entry(normalized_inviter).or_default();

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_peer_status_entries();
        self.ensure_relay_status_entries();
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();
        self.maybe_refresh_lan_discovery();
        self.session_status = if self.daemon_running {
            format!("Invite imported and applied for {}.", invite.network_name)
        } else {
            format!("Invite imported for {}.", invite.network_name)
        };

        Ok(())
    }

    fn remove_participant(&mut self, network_id: &str, npub_or_hex: &str) -> Result<()> {
        let normalized = normalize_nostr_pubkey(npub_or_hex)?;
        self.config
            .remove_participant_from_network(network_id, &normalized)?;
        self.peer_status.remove(&normalized);

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_peer_status_entries();
        if self.daemon_running {
            self.reload_daemon_process()?;
            self.session_status = "Participant removed and applied.".to_string();
        }
        self.sync_daemon_state();
        self.maybe_refresh_lan_discovery();

        Ok(())
    }

    fn add_relay(&mut self, relay: &str) -> Result<()> {
        let relay = relay.trim();
        if relay.is_empty() {
            return Err(anyhow!("relay URL is empty"));
        }

        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(anyhow!("relay URL must start with ws:// or wss://"));
        }

        if self
            .config
            .nostr
            .relays
            .iter()
            .any(|existing| existing == relay)
        {
            return Ok(());
        }

        self.config.nostr.relays.push(relay.to_string());
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_relay_status_entries();
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();

        Ok(())
    }

    fn remove_relay(&mut self, relay: &str) -> Result<()> {
        if self.config.nostr.relays.len() <= 1 {
            return Err(anyhow!("at least one relay is required"));
        }

        let previous_len = self.config.nostr.relays.len();
        self.config.nostr.relays.retain(|value| value != relay);

        if self.config.nostr.relays.len() == previous_len {
            return Ok(());
        }

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.ensure_relay_status_entries();
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();

        Ok(())
    }

    fn update_settings(&mut self, patch: SettingsPatch) -> Result<()> {
        let mut restart_required = false;

        if let Some(node_name) = patch.node_name {
            self.config.node_name = node_name;
            restart_required = true;
        }

        if let Some(endpoint) = patch.endpoint {
            self.config.node.endpoint = endpoint;
            restart_required = true;
        }

        if let Some(tunnel_ip) = patch.tunnel_ip {
            self.config.node.tunnel_ip = tunnel_ip;
            restart_required = true;
        }

        if let Some(listen_port) = patch.listen_port {
            if listen_port == 0 {
                return Err(anyhow!("listen port must be > 0"));
            }
            self.config.node.listen_port = listen_port;
            restart_required = true;
        }

        if let Some(exit_node) = patch.exit_node {
            self.config.exit_node = parse_exit_node_input(&exit_node)?;
            restart_required = true;
        }

        if let Some(advertise_exit_node) = patch.advertise_exit_node {
            self.config.node.advertise_exit_node = advertise_exit_node;
            restart_required = true;
        }

        if let Some(advertised_routes) = patch.advertised_routes {
            self.config.node.advertised_routes = parse_advertised_routes_input(&advertised_routes)?;
            restart_required = true;
        }

        if let Some(magic_dns_suffix) = patch.magic_dns_suffix {
            self.config.magic_dns_suffix = magic_dns_suffix;
            restart_required = true;
        }

        if let Some(auto_disconnect_relays_when_mesh_ready) =
            patch.auto_disconnect_relays_when_mesh_ready
        {
            self.config.auto_disconnect_relays_when_mesh_ready =
                auto_disconnect_relays_when_mesh_ready;
            restart_required = true;
        }

        if let Some(autoconnect) = patch.autoconnect {
            self.config.autoconnect = autoconnect;
        }

        if let Some(lan_discovery_enabled) = patch.lan_discovery_enabled {
            self.config.lan_discovery_enabled = lan_discovery_enabled;
        }

        if let Some(launch_on_startup) = patch.launch_on_startup {
            self.config.launch_on_startup = launch_on_startup;
        }

        if let Some(close_to_tray_on_close) = patch.close_to_tray_on_close {
            self.config.close_to_tray_on_close = close_to_tray_on_close;
        }

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.persist_config()?;

        self.maybe_refresh_lan_discovery();

        if restart_required {
            self.reload_daemon_if_running()?;
        }

        self.sync_daemon_state();
        Ok(())
    }

    fn set_participant_alias(&mut self, npub: &str, alias: &str) -> Result<()> {
        self.config.set_peer_alias(npub, alias)?;
        self.persist_config()?;
        self.reload_daemon_if_running()?;
        self.sync_daemon_state();
        Ok(())
    }

    fn persist_config(&mut self) -> Result<()> {
        if self.config.nostr.relays.is_empty() {
            return Err(anyhow!("at least one relay is required"));
        }

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.config.save(&self.config_path)?;
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        Ok(())
    }

    fn ensure_relay_status_entries(&mut self) {
        let configured: HashSet<String> = self.config.nostr.relays.iter().cloned().collect();
        self.relay_status
            .retain(|relay, _| configured.contains(relay));

        for relay in &self.config.nostr.relays {
            self.relay_status
                .entry(relay.clone())
                .or_insert(RelayStatus {
                    state: "unknown".to_string(),
                    status_text: "not checked".to_string(),
                });
        }
    }

    fn ensure_peer_status_entries(&mut self) {
        let configured: HashSet<String> = self
            .config
            .all_participant_pubkeys_hex()
            .into_iter()
            .collect();
        self.peer_status
            .retain(|participant, _| configured.contains(participant));

        for participant in configured {
            self.peer_status.entry(participant).or_default();
        }
    }

    fn daemon_start_args(&self) -> Result<[&str; 5]> {
        Ok([
            "start",
            "--daemon",
            "--connect",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ])
    }

    #[cfg(target_os = "android")]
    fn start_daemon_process(&mut self) -> Result<()> {
        self.android_session.start(self.config.clone())
    }

    #[cfg(target_os = "macos")]
    fn start_daemon_process(&mut self) -> Result<()> {
        let args = self.daemon_start_args()?;

        if let Ok(status) = self.fetch_cli_status()
            && status.daemon.running
        {
            return Ok(());
        }

        match self.run_nvpn_command_with_admin_privileges(args) {
            Ok(()) => Ok(()),
            Err(error) if is_already_running_message(&error.to_string()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    fn start_daemon_process(&mut self) -> Result<()> {
        let args = self.daemon_start_args()?;
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn start failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        if is_already_running_message(&message) {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        if requires_admin_privileges(&message) {
            match self.run_nvpn_command_with_admin_privileges(args) {
                Ok(()) => {}
                Err(error) if is_already_running_message(&error.to_string()) => {}
                Err(error) => return Err(error),
            }
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    fn reload_daemon_process(&mut self) -> Result<()> {
        self.android_session.reload(self.config.clone())
    }

    #[cfg(not(target_os = "android"))]
    fn reload_daemon_process(&mut self) -> Result<()> {
        let args = [
            "reload",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn reload failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    fn pause_daemon_process(&mut self) -> Result<()> {
        self.android_session.stop()
    }

    #[cfg(not(target_os = "android"))]
    fn pause_daemon_process(&mut self) -> Result<()> {
        let args = [
            "pause",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn pause failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "android")]
    fn resume_daemon_process(&mut self) -> Result<()> {
        self.android_session.start(self.config.clone())
    }

    #[cfg(not(target_os = "android"))]
    fn resume_daemon_process(&mut self) -> Result<()> {
        let args = [
            "resume",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn resume failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
        if is_not_running_message(&message) {
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn install_cli_binary(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.cli_install_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        let args = ["install-cli", "--force"];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn install-cli failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn uninstall_cli_binary(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.cli_install_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        let args = ["uninstall-cli"];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn uninstall-cli failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn install_system_service(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "install",
            "--force",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service install failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn uninstall_system_service(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "uninstall",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service uninstall failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn enable_system_service(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "enable",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service enable failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn disable_system_service(&self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        let args = [
            "service",
            "disable",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = format!(
            "nvpn service disable failed\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn reload_daemon_if_running(&mut self) -> Result<()> {
        if !self.daemon_running {
            return Ok(());
        }

        self.reload_daemon_process()
    }

    #[cfg(target_os = "android")]
    fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let (running, state) = self.android_session.status();
        Ok(CliStatusResponse {
            daemon: CliDaemonStatus { running, state },
        })
    }

    #[cfg(not(target_os = "android"))]
    fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let output = self.run_nvpn_command([
            "status",
            "--json",
            "--discover-secs",
            "0",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "nvpn status failed\nstdout: {}\nstderr: {}",
                stdout.trim(),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_text = extract_json_document(&stdout)?;
        let parsed = serde_json::from_str::<CliStatusResponse>(json_text)
            .context("failed to parse `nvpn status --json` output")?;
        Ok(parsed)
    }

    #[cfg(target_os = "android")]
    fn fetch_cli_service_status(&self) -> Result<CliServiceStatusResponse> {
        Ok(CliServiceStatusResponse {
            supported: false,
            installed: false,
            disabled: false,
            loaded: false,
            running: false,
            pid: None,
            label: "android-vpn".to_string(),
            plist_path: String::new(),
        })
    }

    #[cfg(not(target_os = "android"))]
    fn fetch_cli_service_status(&self) -> Result<CliServiceStatusResponse> {
        let output = self.run_nvpn_command([
            "service",
            "status",
            "--json",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "nvpn service status failed\nstdout: {}\nstderr: {}",
                stdout.trim(),
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_text = extract_json_document(&stdout)?;
        let parsed = serde_json::from_str::<CliServiceStatusResponse>(json_text)
            .context("failed to parse `nvpn service status --json` output")?;
        Ok(parsed)
    }

    fn run_nvpn_command<const N: usize>(&self, args: [&str; N]) -> Result<std::process::Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {} or install nvpn in PATH",
                NVPN_BIN_ENV
            ));
        };

        ProcessCommand::new(nvpn_bin)
            .args(args)
            .output()
            .with_context(|| {
                format!(
                    "failed to execute {} {}",
                    nvpn_bin.display(),
                    args.join(" ")
                )
            })
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn run_nvpn_command_with_admin_privileges<const N: usize>(
        &self,
        args: [&str; N],
    ) -> Result<()> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {} or install nvpn in PATH",
                NVPN_BIN_ENV
            ));
        };
        let nvpn_bin = nvpn_bin
            .to_str()
            .ok_or_else(|| anyhow!("nvpn binary path is not valid UTF-8"))?;

        #[cfg(target_os = "macos")]
        {
            let mut command = runas::Command::new(nvpn_bin);
            command.gui(true);
            command.args(&args);

            let status = command.status().context(
                "failed to execute elevated nvpn command via native macOS authorization prompt",
            )?;

            if status.success() {
                return Ok(());
            }
            return Err(anyhow!(
                "elevated nvpn command failed via macOS authorization: {status}"
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let output = ProcessCommand::new("pkexec")
                .arg(nvpn_bin)
                .args(args)
                .output();

            let output = match output {
                Ok(output) => output,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(anyhow!(
                        "pkexec not found; install policykit (polkit) to allow GUI privilege prompts"
                    ));
                }
                Err(error) => {
                    return Err(anyhow!(
                        "failed to execute pkexec for elevated nvpn command: {error}"
                    ));
                }
            };

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let details = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            if details
                .to_ascii_lowercase()
                .contains("no authentication agent found")
            {
                return Err(anyhow!(
                    "pkexec could not find a polkit authentication agent; run a desktop polkit agent or start nvpn with sudo"
                ));
            }
            return Err(anyhow!(
                "elevated nvpn command failed via pkexec: {details}"
            ));
        }

        #[cfg(target_os = "windows")]
        {
            let status = runas::Command::new(nvpn_bin)
                .args(&args)
                .status()
                .context("failed to execute elevated nvpn command via Windows UAC prompt")?;

            if status.success() {
                return Ok(());
            }
            return Err(anyhow!(
                "elevated nvpn command failed via Windows UAC authorization: {status}"
            ));
        }

        #[allow(unreachable_code)]
        Err(anyhow!(
            "privilege escalation helper is not implemented on this platform"
        ))
    }

    fn sync_daemon_state(&mut self) {
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        self.sync_service_state();

        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.daemon_state = None;
            self.daemon_running = false;
            self.session_active = false;
            self.relay_connected = false;
            self.session_status = runtime.runtime_status_detail.to_string();
            self.magic_dns_status =
                "DNS unavailable until mobile VPN service integration is wired up".to_string();

            for relay in &self.config.nostr.relays {
                self.relay_status.insert(
                    relay.clone(),
                    RelayStatus {
                        state: "unknown".to_string(),
                        status_text: "not checked".to_string(),
                    },
                );
            }

            for participant in self.config.all_participant_pubkeys_hex() {
                let status = self.peer_status.entry(participant).or_default();
                status.reachable = None;
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = Some("vpn unavailable on this platform".to_string());
                status.checked_at = Some(SystemTime::now());
                status.last_signal_seen_at = None;
                status.advertised_routes = Vec::new();
                status.offers_exit_node = false;
            }
            return;
        }

        let status = match self.fetch_cli_status() {
            Ok(status) => status,
            Err(error) => {
                self.daemon_state = None;
                self.daemon_running = false;
                self.session_active = false;
                self.relay_connected = false;
                self.session_status = format!("Daemon status unavailable: {error}");
                self.magic_dns_status = "DNS status unavailable (daemon not reachable)".to_string();

                for relay in &self.config.nostr.relays {
                    self.relay_status.insert(
                        relay.clone(),
                        RelayStatus {
                            state: "unknown".to_string(),
                            status_text: "not checked".to_string(),
                        },
                    );
                }

                for participant in self.config.all_participant_pubkeys_hex() {
                    let status = self.peer_status.entry(participant).or_default();
                    status.reachable = None;
                    status.last_handshake_at = None;
                    status.endpoint = None;
                    status.error = Some("vpn off".to_string());
                    status.checked_at = Some(SystemTime::now());
                    status.last_signal_seen_at = None;
                    status.advertised_routes = Vec::new();
                    status.offers_exit_node = false;
                }
                return;
            }
        };

        let state = status.daemon.state.clone();
        self.daemon_state = state.clone();
        self.daemon_running = status.daemon.running;

        if status.daemon.running {
            self.session_active = state
                .as_ref()
                .map(|value| value.session_active)
                .unwrap_or(true);
            self.relay_connected = state
                .as_ref()
                .map(|value| value.relay_connected)
                .unwrap_or(false);
            self.session_status = state
                .as_ref()
                .map(|value| value.session_status.clone())
                .unwrap_or_else(|| "Daemon running".to_string());
        } else {
            self.session_active = false;
            self.relay_connected = false;
            if self.gui_requires_service_install() {
                self.session_status =
                    gui_service_setup_status_text(self.config.autoconnect).to_string();
            } else if self.service_installed && self.service_disabled {
                self.session_status = "Background service is disabled in launchd".to_string();
            } else if !self.session_status.starts_with("Daemon start failed:") {
                self.session_status = "Daemon not running".to_string();
            }
        }

        self.refresh_relay_runtime_status();
        self.refresh_peer_runtime_status();

        #[cfg(target_os = "android")]
        {
            self.magic_dns_status = if self.session_active {
                "Android tunnel is active; MagicDNS is not wired yet".to_string()
            } else {
                "DNS unchanged (VPN off)".to_string()
            };
        }

        #[cfg(not(target_os = "android"))]
        {
            self.magic_dns_status = if self.session_active {
                let suffix = self
                    .config
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
        }
    }

    fn sync_service_state(&mut self) {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            self.service_supported = false;
            self.service_enablement_supported = false;
            self.service_installed = false;
            self.service_disabled = false;
            self.service_running = false;
            self.service_status_detail =
                "Background service unsupported on this platform".to_string();
            return;
        }

        match self.fetch_cli_service_status() {
            Ok(status) => {
                self.service_supported = status.supported;
                self.service_installed = status.installed;
                self.service_disabled = status.disabled;
                self.service_running = status.running;
                self.service_status_detail = if !status.supported {
                    "Background service unsupported on this platform".to_string()
                } else if !status.installed {
                    "Background service is not installed".to_string()
                } else if status.disabled {
                    "Background service is installed but disabled in launchd".to_string()
                } else if status.running {
                    match status.pid {
                        Some(pid) => format!("Background service running (pid {pid})"),
                        None => "Background service running".to_string(),
                    }
                } else if status.loaded {
                    "Background service installed but not running".to_string()
                } else {
                    "Background service installed but launch status is unavailable".to_string()
                };
                eprintln!(
                    "gui: service status synced supported={} installed={} disabled={} loaded={} running={} pid={:?} label={} path={}",
                    status.supported,
                    status.installed,
                    status.disabled,
                    status.loaded,
                    status.running,
                    status.pid,
                    status.label,
                    status.plist_path
                );
            }
            Err(error) => {
                self.service_supported = cfg!(any(
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                ));
                self.service_installed = false;
                self.service_disabled = false;
                self.service_running = false;
                self.service_status_detail = format!("Service status unavailable: {error}");
                eprintln!("gui: failed to sync service status: {error}");
            }
        }
    }

    fn refresh_relay_runtime_status(&mut self) {
        let mesh_ready = self
            .daemon_state
            .as_ref()
            .is_some_and(|value| value.mesh_ready);

        for relay in &self.config.nostr.relays {
            let entry = self.relay_status.entry(relay.clone()).or_default();

            if !self.session_active {
                entry.state = "unknown".to_string();
                entry.status_text = "not checked".to_string();
            } else if self.relay_connected {
                entry.state = "up".to_string();
                entry.status_text = "connected".to_string();
            } else if self.config.auto_disconnect_relays_when_mesh_ready && mesh_ready {
                entry.state = "down".to_string();
                entry.status_text = "paused (mesh ready)".to_string();
            } else {
                entry.state = "down".to_string();
                entry.status_text = "disconnected".to_string();
            }
        }
    }

    fn refresh_peer_runtime_status(&mut self) {
        let own_pubkey = self.config.own_nostr_pubkey_hex().ok();
        let now = SystemTime::now();
        let daemon_peer_map = self
            .daemon_state
            .as_ref()
            .map(|value| {
                value
                    .peers
                    .iter()
                    .map(|peer| (peer.participant_pubkey.as_str(), peer))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        for participant in self.config.all_participant_pubkeys_hex() {
            let status = self.peer_status.entry(participant.clone()).or_default();
            status.checked_at = Some(now);

            if Some(participant.as_str()) == own_pubkey.as_deref() {
                status.reachable = None;
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = None;
                status.last_signal_seen_at = None;
                status.advertised_routes = Vec::new();
                status.offers_exit_node = false;
                continue;
            }

            if !self.session_active {
                status.reachable = None;
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = Some("vpn off".to_string());
                status.last_signal_seen_at = None;
                status.advertised_routes = Vec::new();
                status.offers_exit_node = false;
                continue;
            }

            let Some(peer) = daemon_peer_map.get(participant.as_str()) else {
                status.reachable = Some(false);
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = Some("no signal yet".to_string());
                status.last_signal_seen_at = None;
                status.advertised_routes = Vec::new();
                status.offers_exit_node = false;
                continue;
            };

            let previous_reachable = status.reachable;
            let previous_handshake_at = status.last_handshake_at;
            let sticky_online = !peer.reachable
                && previous_reachable == Some(true)
                && within_peer_online_grace(previous_handshake_at, now);
            let effective_reachable = peer.reachable || sticky_online;
            status.reachable = Some(effective_reachable);
            status.endpoint = if peer.endpoint.is_empty() {
                None
            } else {
                Some(peer.endpoint.clone())
            };
            let daemon_handshake_at = peer
                .last_handshake_at
                .and_then(epoch_secs_to_system_time)
                .or(if peer.reachable { Some(now) } else { None });
            status.last_handshake_at = if daemon_handshake_at.is_some() {
                daemon_handshake_at
            } else if sticky_online {
                previous_handshake_at
            } else {
                None
            };
            status.last_signal_seen_at = peer
                .last_signal_seen_at
                .and_then(epoch_secs_to_system_time)
                .or_else(|| {
                    if peer.presence_timestamp > 0 {
                        epoch_secs_to_system_time(peer.presence_timestamp)
                    } else {
                        None
                    }
                });
            status.advertised_routes = peer.advertised_routes.clone();
            status.offers_exit_node = peer_offers_exit_node(&peer.advertised_routes);
            status.error = if effective_reachable {
                None
            } else {
                Some(
                    peer.error
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| "awaiting handshake".to_string()),
                )
            };
        }
    }

    fn relay_summary(&self) -> RelaySummary {
        let mut summary = RelaySummary::default();

        for relay in &self.config.nostr.relays {
            match self
                .relay_status
                .get(relay)
                .map(|value| value.state.as_str())
            {
                Some("up") => summary.up += 1,
                Some("down") => summary.down += 1,
                Some("checking") => summary.checking += 1,
                _ => summary.unknown += 1,
            }
        }

        summary
    }

    fn relay_state(&self, relay: &str) -> &str {
        self.relay_status
            .get(relay)
            .map(|value| value.state.as_str())
            .unwrap_or("unknown")
    }

    fn relay_status_line(&self, relay: &str) -> String {
        self.relay_status
            .get(relay)
            .map(|value| value.status_text.clone())
            .unwrap_or_else(|| "not checked".to_string())
    }

    fn participant_view(
        &self,
        participant: &str,
        network_id: &str,
        own_pubkey_hex: Option<&str>,
    ) -> ParticipantView {
        let tunnel_ip =
            derive_mesh_tunnel_ip(network_id, participant).unwrap_or_else(|| "-".to_string());
        let transport_state = self.peer_state_for(participant, own_pubkey_hex);
        let presence_state = self.peer_presence_state_for(participant, own_pubkey_hex);
        let status_text = self.peer_status_line(participant, transport_state);
        let last_signal_text = self.peer_presence_line(participant, own_pubkey_hex);
        let magic_dns_alias = self.config.peer_alias(participant).unwrap_or_default();
        let magic_dns_name = self
            .config
            .magic_dns_name_for_participant(participant)
            .unwrap_or_default();
        let is_local = Some(participant) == own_pubkey_hex;
        let advertised_routes = if is_local {
            self.config.effective_advertised_routes()
        } else {
            self.peer_status
                .get(participant)
                .map(|status| status.advertised_routes.clone())
                .unwrap_or_default()
        };
        let offers_exit_node = if is_local {
            self.config.node.advertise_exit_node
        } else {
            self.peer_status
                .get(participant)
                .map(|status| status.offers_exit_node)
                .unwrap_or(false)
        };

        ParticipantView {
            npub: to_npub(participant),
            pubkey_hex: participant.to_string(),
            tunnel_ip,
            magic_dns_alias,
            magic_dns_name,
            advertised_routes,
            offers_exit_node,
            state: peer_state_label(transport_state).to_string(),
            presence_state: peer_presence_state_label(presence_state).to_string(),
            status_text,
            last_signal_text,
        }
    }

    fn network_rows(&self) -> Vec<NetworkView> {
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().ok();
        let mut rows = Vec::with_capacity(self.config.networks.len());

        for network in &self.config.networks {
            let mut participants = network.participants.clone();
            participants.sort();
            participants.dedup();

            let participant_rows = participants
                .iter()
                .map(|participant| {
                    self.participant_view(
                        participant,
                        &network.network_id,
                        own_pubkey_hex.as_deref(),
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
                            self.peer_state_for(participant.as_str(), own_pubkey_hex.as_deref()),
                            ConfiguredPeerStatus::Online
                        )
                    })
                    .count()
            } else {
                0
            };

            let expected_count = network_device_count(remote_expected_count, network.enabled);
            let online_count = network_online_device_count(
                remote_online_count,
                network.enabled,
                self.session_active,
            );

            rows.push(NetworkView {
                id: network.id.clone(),
                name: network.name.clone(),
                enabled: network.enabled,
                network_id: network.network_id.clone(),
                online_count,
                expected_count,
                participants: participant_rows,
            });
        }

        rows
    }

    fn peer_presence_line(&self, participant: &str, own_pubkey_hex: Option<&str>) -> String {
        if Some(participant) == own_pubkey_hex {
            return "self".to_string();
        }

        let Some(seen_at) = self
            .peer_status
            .get(participant)
            .and_then(|status| status.last_signal_seen_at)
        else {
            return "nostr unseen".to_string();
        };

        let age_secs = seen_at
            .elapsed()
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!("nostr seen {age_secs}s ago")
    }

    fn peer_state_for(
        &self,
        participant: &str,
        own_pubkey_hex: Option<&str>,
    ) -> ConfiguredPeerStatus {
        if Some(participant) == own_pubkey_hex {
            return ConfiguredPeerStatus::Local;
        }

        match self.peer_status.get(participant) {
            Some(status) if status.reachable == Some(true) => ConfiguredPeerStatus::Online,
            Some(status)
                if within_peer_presence_grace(status.last_signal_seen_at, SystemTime::now()) =>
            {
                ConfiguredPeerStatus::Present
            }
            Some(status) if status.reachable == Some(false) => ConfiguredPeerStatus::Offline,
            _ => ConfiguredPeerStatus::Unknown,
        }
    }

    fn peer_presence_state_for(
        &self,
        participant: &str,
        own_pubkey_hex: Option<&str>,
    ) -> PeerPresenceStatus {
        if Some(participant) == own_pubkey_hex {
            return PeerPresenceStatus::Local;
        }

        match self.peer_status.get(participant) {
            Some(status) if status.reachable == Some(true) => PeerPresenceStatus::Present,
            Some(status)
                if within_peer_presence_grace(status.last_signal_seen_at, SystemTime::now()) =>
            {
                PeerPresenceStatus::Present
            }
            Some(status) if status.reachable == Some(false) => PeerPresenceStatus::Absent,
            _ => PeerPresenceStatus::Unknown,
        }
    }

    fn peer_status_line(&self, participant: &str, status: ConfiguredPeerStatus) -> String {
        match status {
            ConfiguredPeerStatus::Local => "local".to_string(),
            ConfiguredPeerStatus::Online => {
                let Some(link) = self.peer_status.get(participant) else {
                    return "online".to_string();
                };

                let handshake_age = link
                    .last_handshake_at
                    .and_then(|handshake_at| handshake_at.elapsed().ok())
                    .map(|elapsed| elapsed.as_secs());

                match handshake_age {
                    Some(age_secs) => format!("online (handshake {age_secs}s ago)"),
                    None => "online".to_string(),
                }
            }
            ConfiguredPeerStatus::Present => {
                let Some(link) = self.peer_status.get(participant) else {
                    return "awaiting WireGuard handshake".to_string();
                };

                match link
                    .endpoint
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                {
                    Some(endpoint) => {
                        format!(
                            "awaiting WireGuard handshake via {}",
                            shorten_middle(endpoint, 18, 10)
                        )
                    }
                    None => "awaiting WireGuard handshake".to_string(),
                }
            }
            ConfiguredPeerStatus::Offline => {
                let Some(link) = self.peer_status.get(participant) else {
                    return "offline".to_string();
                };

                let checked_age = link
                    .checked_at
                    .and_then(|checked_at| checked_at.elapsed().ok())
                    .map(|elapsed| elapsed.as_secs());

                if let Some(error) = &link.error {
                    match checked_age {
                        Some(age_secs) => {
                            format!(
                                "offline ({}, {age_secs}s ago)",
                                shorten_middle(error, 18, 8)
                            )
                        }
                        None => format!("offline ({})", shorten_middle(error, 18, 8)),
                    }
                } else {
                    match checked_age {
                        Some(age_secs) => format!("offline ({age_secs}s ago)"),
                        None => "offline".to_string(),
                    }
                }
            }
            ConfiguredPeerStatus::Unknown => "unknown".to_string(),
        }
    }

    fn tick(&mut self) {
        self.maybe_refresh_lan_discovery();
        self.handle_lan_discovery_events();
        self.prune_lan_peers();
        self.sync_daemon_state();
    }

    fn lan_discovery_should_run(&self) -> bool {
        self.config.lan_discovery_enabled || self.config.all_participant_pubkeys_hex().is_empty()
    }

    fn maybe_refresh_lan_discovery(&mut self) {
        let should_run = self.lan_discovery_should_run();

        if should_run && !self.lan_discovery_running {
            self.start_lan_discovery();
        } else if !should_run && self.lan_discovery_running {
            self.stop_lan_discovery();
            self.lan_peers.clear();
        }
    }

    fn start_lan_discovery(&mut self) {
        let own_npub = self
            .config
            .own_nostr_pubkey_hex()
            .map(|hex| to_npub(&hex))
            .unwrap_or_else(|_| self.config.nostr.public_key.clone());
        let node_name = self.config.node_name.clone();
        let endpoint = self.config.node.endpoint.clone();

        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();

        self.runtime.spawn(async move {
            run_lan_discovery_loop(tx, stop_flag, own_npub, node_name, endpoint).await;
        });

        self.lan_discovery_rx = Some(rx);
        self.lan_discovery_stop = Some(stop);
        self.lan_discovery_running = true;
    }

    fn stop_lan_discovery(&mut self) {
        if let Some(stop) = self.lan_discovery_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        self.lan_discovery_rx = None;
        self.lan_discovery_running = false;
    }

    fn handle_lan_discovery_events(&mut self) {
        let own_npub = self
            .config
            .own_nostr_pubkey_hex()
            .map(|hex| to_npub(&hex))
            .unwrap_or_default();

        let recv_result = self
            .lan_discovery_rx
            .as_ref()
            .map(|receiver| receiver.try_recv());

        match recv_result {
            Some(Ok(event)) => {
                if event.npub == own_npub {
                    return;
                }

                self.lan_peers.insert(
                    event.npub.clone(),
                    LanPeerRecord {
                        npub: event.npub,
                        node_name: event.node_name,
                        endpoint: event.endpoint,
                        last_seen: event.seen_at,
                    },
                );

                if let Some(receiver) = &self.lan_discovery_rx {
                    while let Ok(event) = receiver.try_recv() {
                        if event.npub == own_npub {
                            continue;
                        }

                        self.lan_peers.insert(
                            event.npub.clone(),
                            LanPeerRecord {
                                npub: event.npub,
                                node_name: event.node_name,
                                endpoint: event.endpoint,
                                last_seen: event.seen_at,
                            },
                        );
                    }
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.lan_discovery_running = false;
                self.lan_discovery_rx = None;
                self.lan_discovery_stop = None;
            }
            _ => {}
        }
    }

    fn prune_lan_peers(&mut self) {
        self.lan_peers.retain(|_, peer| {
            peer.last_seen
                .elapsed()
                .map(|elapsed| elapsed.as_secs() <= LAN_DISCOVERY_STALE_AFTER_SECS)
                .unwrap_or(false)
        });
    }

    fn lan_peer_rows(&self) -> Vec<LanPeerView> {
        let mut peers = self.lan_peers.values().cloned().collect::<Vec<_>>();
        peers.sort_by(|left, right| left.npub.cmp(&right.npub));
        let configured_npubs = self
            .config
            .all_participant_pubkeys_hex()
            .iter()
            .filter_map(|value| self.npub_or_none(value))
            .collect::<HashSet<_>>();

        peers
            .into_iter()
            .map(|peer| {
                let configured = configured_npubs.contains(&peer.npub);

                let last_seen_secs = peer
                    .last_seen
                    .elapsed()
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or(0);

                LanPeerView {
                    npub: peer.npub,
                    node_name: peer.node_name,
                    endpoint: peer.endpoint,
                    last_seen_text: format!("{last_seen_secs}s ago"),
                    configured,
                }
            })
            .collect()
    }

    fn npub_or_none(&self, value: &str) -> Option<String> {
        PublicKey::from_hex(value)
            .ok()
            .and_then(|key| key.to_bech32().ok())
    }

    fn ui_state(&self) -> UiState {
        let runtime_capabilities = current_runtime_capabilities();
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().unwrap_or_default();
        let own_npub = to_npub(&own_pubkey_hex);

        let networks = self.network_rows();
        let relays = self
            .config
            .nostr
            .relays
            .iter()
            .map(|relay| RelayView {
                url: relay.clone(),
                state: self.relay_state(relay).to_string(),
                status_text: self.relay_status_line(relay),
            })
            .collect::<Vec<_>>();

        let relay_summary = self.relay_summary();
        let fallback_expected_peer_count = expected_peer_count(&self.config);
        let fallback_connected_peer_count =
            connected_configured_peer_count(&self.config, &self.peer_status);

        let expected_peer_count = self
            .daemon_state
            .as_ref()
            .map(|state| state.expected_peer_count)
            .unwrap_or(fallback_expected_peer_count);
        let connected_peer_count = self
            .daemon_state
            .as_ref()
            .map(|state| state.connected_peer_count)
            .unwrap_or(fallback_connected_peer_count);
        let mesh_ready = self
            .daemon_state
            .as_ref()
            .map(|state| state.mesh_ready)
            .unwrap_or_else(|| is_mesh_complete(connected_peer_count, expected_peer_count));
        let health = self
            .daemon_state
            .as_ref()
            .map(|state| state.health.clone())
            .unwrap_or_default();
        let network = self
            .daemon_state
            .as_ref()
            .map(|state| state.network.clone())
            .unwrap_or_default();
        let port_mapping = self
            .daemon_state
            .as_ref()
            .map(|state| state.port_mapping.clone())
            .unwrap_or_default();

        UiState {
            platform: runtime_capabilities.platform.to_string(),
            mobile: runtime_capabilities.mobile,
            vpn_session_control_supported: runtime_capabilities.vpn_session_control_supported,
            cli_install_supported: runtime_capabilities.cli_install_supported,
            startup_settings_supported: runtime_capabilities.startup_settings_supported,
            tray_behavior_supported: runtime_capabilities.tray_behavior_supported,
            runtime_status_detail: runtime_capabilities.runtime_status_detail.to_string(),
            daemon_running: self.daemon_running,
            session_active: self.session_active,
            relay_connected: self.relay_connected,
            cli_installed: runtime_capabilities.cli_install_supported && cli_binary_installed(),
            service_supported: self.service_supported,
            service_enablement_supported: self.service_enablement_supported,
            service_installed: self.service_installed,
            service_disabled: self.service_disabled,
            service_running: self.service_running,
            service_status_detail: self.service_status_detail.clone(),
            session_status: self.session_status.clone(),
            app_version: PRODUCT_VERSION.to_string(),
            config_path: self.config_path.display().to_string(),
            own_npub,
            own_pubkey_hex,
            network_id: self.config.effective_network_id(),
            active_network_invite: active_network_invite_code(&self.config).unwrap_or_default(),
            node_id: self.config.node.id.clone(),
            node_name: self.config.node_name.clone(),
            endpoint: self.config.node.endpoint.clone(),
            tunnel_ip: self.config.node.tunnel_ip.clone(),
            listen_port: self.config.node.listen_port,
            exit_node: self
                .npub_or_none(&self.config.exit_node)
                .unwrap_or_default(),
            advertise_exit_node: self.config.node.advertise_exit_node,
            advertised_routes: self.config.node.advertised_routes.clone(),
            effective_advertised_routes: self.config.effective_advertised_routes(),
            magic_dns_suffix: self.config.magic_dns_suffix.clone(),
            magic_dns_status: self.magic_dns_status.clone(),
            auto_disconnect_relays_when_mesh_ready: self
                .config
                .auto_disconnect_relays_when_mesh_ready,
            autoconnect: self.config.autoconnect,
            lan_discovery_enabled: self.lan_discovery_should_run(),
            launch_on_startup: self.config.launch_on_startup,
            close_to_tray_on_close: self.config.close_to_tray_on_close,
            connected_peer_count,
            expected_peer_count,
            mesh_ready,
            health,
            network,
            port_mapping,
            networks,
            relays,
            relay_summary,
            lan_peers: self.lan_peer_rows(),
        }
    }

    fn gui_requires_service_install(&self) -> bool {
        gui_requires_service_install(
            self.service_supported,
            self.service_installed,
            self.daemon_running,
        )
    }

    fn gui_requires_service_enable(&self) -> bool {
        gui_requires_service_enable(
            self.service_enablement_supported,
            self.service_installed,
            self.service_disabled,
            self.daemon_running,
        )
    }

    fn gui_requires_service_action(&self) -> bool {
        self.gui_requires_service_install() || self.gui_requires_service_enable()
    }

    fn tray_runtime_state(&self) -> TrayRuntimeState {
        let networks = self.network_rows();
        let identity = self
            .config
            .own_nostr_pubkey_hex()
            .map(|hex| to_npub(&hex))
            .unwrap_or_else(|_| self.config.nostr.public_key.clone());
        let service_setup_required = self.gui_requires_service_install();
        let service_enable_required = self.gui_requires_service_enable();

        TrayRuntimeState {
            session_active: self.session_active,
            service_setup_required,
            service_enable_required,
            status_text: tray_status_text(
                self.session_active,
                service_setup_required,
                service_enable_required,
                &self.session_status,
            ),
            identity_npub: identity.clone(),
            identity_text: tray_identity_text(&identity),
            this_device_text: format!(
                "This Device: {} ({})",
                self.config.node_name,
                display_tunnel_ip(&self.config.node.tunnel_ip)
            ),
            advertise_exit_node: self.config.node.advertise_exit_node,
            network_groups: tray_network_groups(&networks),
            exit_nodes: tray_exit_node_entries(&networks, &self.config.exit_node),
        }
    }
}

fn within_peer_online_grace(last_handshake_at: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(last_handshake_at) = last_handshake_at else {
        return false;
    };
    now.duration_since(last_handshake_at)
        .map(|elapsed| elapsed.as_secs() <= PEER_ONLINE_GRACE_SECS)
        .unwrap_or(false)
}

fn within_peer_presence_grace(last_signal_seen_at: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(last_signal_seen_at) = last_signal_seen_at else {
        return false;
    };
    now.duration_since(last_signal_seen_at)
        .map(|elapsed| elapsed.as_secs() <= PEER_PRESENCE_GRACE_SECS)
        .unwrap_or(false)
}

fn peer_offers_exit_node(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

fn active_network_invite_code(config: &AppConfig) -> Result<String> {
    let invite = NetworkInvite {
        v: NETWORK_INVITE_VERSION,
        network_name: config.active_network().name.trim().to_string(),
        network_id: config.effective_network_id(),
        inviter_npub: to_npub(&config.own_nostr_pubkey_hex()?),
        relays: normalized_invite_relays(&config.nostr.relays)?,
    };
    let encoded = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&invite).context("failed to encode network invite JSON")?);
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

    if invite.v != NETWORK_INVITE_VERSION {
        return Err(anyhow!(
            "unsupported invite version {}; expected {}",
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
    invite.relays = normalized_invite_relays(&invite.relays)?;

    Ok(invite)
}

fn apply_network_invite_to_active_network(
    config: &mut AppConfig,
    invite: &NetworkInvite,
) -> Result<()> {
    let should_adopt_name = {
        let active = config.active_network();
        active.participants.is_empty()
            && (active.name.trim().is_empty() || active.name.trim().starts_with("Network "))
    };
    let active_network_entry_id = config.active_network().id.clone();

    config.set_active_network_id(&invite.network_id)?;
    config.add_participant_to_network(&active_network_entry_id, &invite.inviter_npub)?;

    if should_adopt_name {
        config.rename_network(&active_network_entry_id, &invite.network_name)?;
    }

    for relay in &invite.relays {
        if !config.nostr.relays.iter().any(|existing| existing == relay) {
            config.nostr.relays.push(relay.clone());
        }
    }

    Ok(())
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

fn gui_requires_service_install(
    service_supported: bool,
    service_installed: bool,
    daemon_running: bool,
) -> bool {
    service_supported && !service_installed && !daemon_running
}

fn gui_requires_service_enable(
    service_enablement_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    daemon_running: bool,
) -> bool {
    service_enablement_supported && service_installed && service_disabled && !daemon_running
}

fn should_start_gui_daemon_on_launch(
    autoconnect: bool,
    has_participants: bool,
    service_setup_required: bool,
) -> bool {
    autoconnect && has_participants && !service_setup_required
}

fn should_defer_gui_daemon_start_to_service_on_autostart(
    launched_from_autostart: bool,
    service_installed: bool,
    service_disabled: bool,
) -> bool {
    cfg!(target_os = "macos") && launched_from_autostart && service_installed && !service_disabled
}

fn gui_service_setup_status_text(autoconnect: bool) -> &'static str {
    if autoconnect {
        GUI_SERVICE_SETUP_REQUIRED_AUTOCONNECT_STATUS
    } else {
        GUI_SERVICE_SETUP_REQUIRED_STATUS
    }
}

fn gui_service_enable_status_text(autoconnect: bool) -> &'static str {
    if autoconnect {
        "Background service is disabled in launchd; enable it to auto-connect from the app"
    } else {
        "Background service is disabled in launchd; enable it to turn VPN on from the app"
    }
}

impl Drop for NvpnBackend {
    fn drop(&mut self) {
        #[cfg(target_os = "android")]
        let _ = self.android_session.stop();
        self.stop_lan_discovery();
    }
}

fn resolve_nvpn_cli_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        let candidate = PathBuf::from(path);
        return validate_nvpn_binary(candidate);
    }

    let bundled_candidates = nvpn_bundled_binary_candidates();
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for candidate_name in &bundled_candidates {
            let sibling = dir.join(candidate_name);
            if sibling.exists()
                && let Ok(validated) = validate_nvpn_binary(sibling)
            {
                return Ok(validated);
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(resources_dir) = dir
                .parent()
                .and_then(Path::parent)
                .map(|path| path.join("Resources"))
            {
                for candidate_name in &bundled_candidates {
                    let candidate = resources_dir.join(candidate_name);
                    if candidate.exists()
                        && let Ok(validated) = validate_nvpn_binary(candidate)
                    {
                        return Ok(validated);
                    }
                }
            }
        }
    }

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(nvpn_binary_name());
            if candidate.exists()
                && let Ok(validated) = validate_nvpn_binary(candidate)
            {
                return Ok(validated);
            }
        }
    }

    Err(anyhow!(
        "nvpn CLI binary not found; set {} or install nvpn",
        NVPN_BIN_ENV
    ))
}

fn validate_nvpn_binary(path: PathBuf) -> Result<PathBuf> {
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;

    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(anyhow!("{} is not executable", canonical.display()));
        }
        if mode & 0o002 != 0 {
            return Err(anyhow!(
                "{} is world-writable and rejected for daemon control safety",
                canonical.display()
            ));
        }
    }

    Ok(canonical)
}

fn default_cli_install_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/nvpn")
}

fn cli_binary_installed() -> bool {
    cli_binary_installed_at(&default_cli_install_path())
}

fn cli_binary_installed_at(path: &std::path::Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn nvpn_bundled_binary_candidates() -> Vec<String> {
    vec![nvpn_binary_name().to_string(), nvpn_sidecar_binary_name()]
}

fn nvpn_sidecar_binary_name() -> String {
    let target = current_target_triple();

    #[cfg(target_os = "windows")]
    {
        format!("{}-{target}.exe", nvpn_binary_stem())
    }

    #[cfg(not(target_os = "windows"))]
    {
        format!("{}-{target}", nvpn_binary_stem())
    }
}

fn nvpn_binary_stem() -> &'static str {
    "nvpn"
}

fn current_target_triple() -> String {
    if let Some(target) = option_env!("NVPN_GUI_TARGET")
        && !target.trim().is_empty()
    {
        return target.to_string();
    }

    let arch = env::consts::ARCH;
    match env::consts::OS {
        "macos" => format!("{arch}-apple-darwin"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        os => format!("{arch}-unknown-{os}"),
    }
}

#[cfg(target_os = "windows")]
fn nvpn_binary_name() -> &'static str {
    "nvpn.exe"
}

#[cfg(not(target_os = "windows"))]
fn nvpn_binary_name() -> &'static str {
    nvpn_binary_stem()
}

fn extract_json_document(raw: &str) -> Result<&str> {
    let start = raw
        .find('{')
        .ok_or_else(|| anyhow!("command output did not contain JSON start"))?;
    let end = raw
        .rfind('}')
        .ok_or_else(|| anyhow!("command output did not contain JSON end"))?;

    if end < start {
        return Err(anyhow!("invalid JSON range in command output"));
    }

    Ok(&raw[start..=end])
}

fn requires_admin_privileges(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("did you run with sudo")
        || lower.contains("admin privileges")
}

fn is_already_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("already running")
}

fn is_not_running_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains("not running")
}

fn epoch_secs_to_system_time(value: u64) -> Option<SystemTime> {
    if value == 0 {
        return None;
    }

    UNIX_EPOCH.checked_add(Duration::from_secs(value))
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
    peer_status: &HashMap<String, PeerLinkStatus>,
) -> usize {
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let participants = config.participant_pubkeys_hex();

    participants
        .iter()
        .filter(|participant| Some(participant.as_str()) != own_pubkey.as_deref())
        .filter(|participant| {
            peer_status
                .get(*participant)
                .and_then(|status| status.reachable)
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

fn peer_state_label(state: ConfiguredPeerStatus) -> &'static str {
    match state {
        ConfiguredPeerStatus::Local => "local",
        ConfiguredPeerStatus::Online => "online",
        ConfiguredPeerStatus::Present => "pending",
        ConfiguredPeerStatus::Offline => "offline",
        ConfiguredPeerStatus::Unknown => "unknown",
    }
}

fn peer_presence_state_label(state: PeerPresenceStatus) -> &'static str {
    match state {
        PeerPresenceStatus::Local => "local",
        PeerPresenceStatus::Present => "present",
        PeerPresenceStatus::Absent => "absent",
        PeerPresenceStatus::Unknown => "unknown",
    }
}

fn config_path_from_roots(
    app_config_dir: Option<&std::path::Path>,
    dirs_config_dir: Option<&std::path::Path>,
) -> PathBuf {
    if let Some(app_config_dir) = app_config_dir {
        return app_config_dir.join("config.toml");
    }

    if let Some(dirs_config_dir) = dirs_config_dir {
        return dirs_config_dir.join("nvpn").join("config.toml");
    }

    PathBuf::from("nvpn.toml")
}

fn default_config_path() -> PathBuf {
    let config_dir = dirs::config_dir();
    config_path_from_roots(None, config_dir.as_deref())
}

fn resolve_backend_config_path<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let app_config_dir = app
            .path()
            .app_config_dir()
            .context("failed to resolve mobile app config directory")?;
        return Ok(config_path_from_roots(Some(app_config_dir.as_path()), None));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = app;
        Ok(default_config_path())
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn to_npub(pubkey_hex: &str) -> String {
    PublicKey::from_hex(pubkey_hex)
        .ok()
        .and_then(|pubkey| pubkey.to_bech32().ok())
        .unwrap_or_else(|| pubkey_hex.to_string())
}

async fn run_lan_discovery_loop(
    tx: mpsc::Sender<LanDiscoverySignal>,
    stop_flag: Arc<AtomicBool>,
    own_npub: String,
    node_name: String,
    endpoint: String,
) {
    let multicast = std::net::Ipv4Addr::new(
        LAN_DISCOVERY_ADDR[0],
        LAN_DISCOVERY_ADDR[1],
        LAN_DISCOVERY_ADDR[2],
        LAN_DISCOVERY_ADDR[3],
    );
    let target = std::net::SocketAddr::from((LAN_DISCOVERY_ADDR, LAN_DISCOVERY_PORT));

    let std_socket =
        match std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, LAN_DISCOVERY_PORT)) {
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
    let mut buffer = [0_u8; 2048];

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            return;
        }

        tokio::select! {
            _ = announce_interval.tick() => {
                let message = LanAnnouncement {
                    v: 1,
                    npub: own_npub.clone(),
                    node_name: node_name.clone(),
                    endpoint: endpoint.clone(),
                    timestamp: unix_timestamp(),
                };

                if let Ok(encoded) = serde_json::to_vec(&message) {
                    let _ = socket.send_to(&encoded, target).await;
                }
            }
            recv = socket.recv_from(&mut buffer) => {
                if let Ok((len, _)) = recv
                    && let Ok(parsed) = serde_json::from_slice::<LanAnnouncement>(&buffer[..len])
                    && parsed.v == 1
                    && parsed.npub != own_npub
                {
                    let _ = tx.send(LanDiscoverySignal {
                        npub: parsed.npub,
                        node_name: parsed.node_name,
                        endpoint: parsed.endpoint,
                        seen_at: SystemTime::now(),
                    });
                }
            }
            _ = idle_interval.tick() => {}
        }
    }
}

struct AppState {
    backend: Mutex<NvpnBackend>,
    last_tray_runtime_state: Mutex<TrayRuntimeState>,
}

fn with_backend<T>(
    state: State<'_, AppState>,
    f: impl FnOnce(&mut NvpnBackend) -> Result<T>,
) -> Result<T, String> {
    let mut backend = state
        .backend
        .lock()
        .map_err(|_| "backend lock poisoned".to_string())?;
    f(&mut backend).map_err(|error| error.to_string())
}

fn should_close_to_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    let Some(state) = app.try_state::<AppState>() else {
        return true;
    };
    let Ok(backend) = state.backend.lock() else {
        return true;
    };
    backend.config.close_to_tray_on_close
}

fn started_from_autostart_args<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .any(|arg| arg.as_ref() == AUTOSTART_LAUNCH_ARG)
}

fn started_from_autostart() -> bool {
    started_from_autostart_args(env::args())
}

fn should_surface_existing_instance_args<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    !started_from_autostart_args(args)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningGuiInstance {
    pid: u32,
    autostart: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GuiLaunchDisposition {
    Continue { terminate_pids: Vec<u32> },
    Exit,
}

fn is_nostr_vpn_gui_process(command: &str) -> bool {
    command.contains("Contents/MacOS/nostr-vpn-gui")
        || command.ends_with("nostr-vpn-gui")
        || command.contains("/nostr-vpn-gui ")
        || command.contains("/nostr-vpn-gui --")
}

fn parse_running_gui_instances(raw: &str, current_pid: u32) -> Vec<RunningGuiInstance> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }

            let pid_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
            let pid = trimmed[..pid_end].parse::<u32>().ok()?;
            if pid == current_pid {
                return None;
            }

            let command = trimmed[pid_end..].trim();
            if !is_nostr_vpn_gui_process(command) {
                return None;
            }

            Some(RunningGuiInstance {
                pid,
                autostart: started_from_autostart_args(command.split_whitespace()),
            })
        })
        .collect()
}

fn gui_launch_disposition(
    launched_from_autostart: bool,
    other_instances: &[RunningGuiInstance],
) -> GuiLaunchDisposition {
    if launched_from_autostart {
        if other_instances.is_empty() {
            GuiLaunchDisposition::Continue {
                terminate_pids: Vec::new(),
            }
        } else {
            GuiLaunchDisposition::Exit
        }
    } else {
        let terminate_pids = other_instances
            .iter()
            .filter(|instance| instance.autostart)
            .map(|instance| instance.pid)
            .collect::<Vec<_>>();
        GuiLaunchDisposition::Continue { terminate_pids }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_gui_launch_conflicts(launched_from_autostart: bool) -> Result<GuiLaunchDisposition> {
    let output = ProcessCommand::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .context("failed to list running GUI processes")?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let other_instances = parse_running_gui_instances(&raw, std::process::id());
    Ok(gui_launch_disposition(
        launched_from_autostart,
        &other_instances,
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn resolve_gui_launch_conflicts(_launched_from_autostart: bool) -> Result<GuiLaunchDisposition> {
    Ok(GuiLaunchDisposition::Continue {
        terminate_pids: Vec::new(),
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn terminate_gui_instances(pids: &[u32]) {
    if pids.is_empty() {
        return;
    }

    let mut command = ProcessCommand::new("kill");
    for pid in pids {
        command.arg(pid.to_string());
    }
    let _ = command.status();
    std::thread::sleep(Duration::from_millis(300));
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn terminate_gui_instances(_pids: &[u32]) {}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn hide_main_window_to_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };

    let _ = window.minimize();
    let _ = window.hide();
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn hide_main_window_to_tray<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) {}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    let Some(window) = app.get_webview_window("main") else {
        return Ok(());
    };

    let _ = window.unminimize();
    window.show()?;
    window.set_focus()?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn show_main_window<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    Ok(())
}

fn short_text(value: &str, leading: usize, trailing: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= leading + trailing + 3 {
        return value.to_string();
    }

    format!(
        "{}...{}",
        chars.iter().take(leading).collect::<String>(),
        chars[chars.len() - trailing..].iter().collect::<String>()
    )
}

fn display_tunnel_ip(tunnel_ip: &str) -> String {
    let trimmed = tunnel_ip.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.split('/').next().unwrap_or(trimmed).to_string()
    }
}

fn tray_status_text(
    session_active: bool,
    service_setup_required: bool,
    service_enable_required: bool,
    session_status: &str,
) -> String {
    if session_active {
        "Connected".to_string()
    } else if service_setup_required {
        "Install background service".to_string()
    } else if service_enable_required {
        "Enable background service".to_string()
    } else if session_status.trim().is_empty() || session_status == "Disconnected" {
        "Disconnected".to_string()
    } else {
        session_status.to_string()
    }
}

fn tray_identity_text(identity_npub: &str) -> String {
    let identity_npub = identity_npub.trim();
    if identity_npub.is_empty() {
        "Copy npub unavailable".to_string()
    } else {
        format!("Copy {}", short_text(identity_npub, 16, 8))
    }
}

fn copy_text_to_clipboard(text: &str) -> Result<()> {
    let text = text.trim();
    if text.is_empty() {
        return Err(anyhow!("npub unavailable"));
    }

    #[cfg(target_os = "macos")]
    {
        copy_text_with_command("pbcopy", &[], text)
    }

    #[cfg(target_os = "linux")]
    {
        let candidates: [(&str, &[&str]); 3] = [
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ];
        let mut last_error = None;
        for (program, args) in candidates {
            match copy_text_with_command(program, args, text) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("no clipboard command available")))
    }

    #[cfg(target_os = "windows")]
    {
        copy_text_with_command("cmd", &["/C", "clip"], text)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!("clipboard copy is unsupported on this platform"))
    }
}

fn copy_text_with_command(program: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = ProcessCommand::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open stdin for {program}"))?;
    stdin
        .write_all(text.as_bytes())
        .with_context(|| format!("failed to send text to {program}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for {program}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err(anyhow!("{program} exited with status {}", output.status))
        } else {
            Err(anyhow!("{program} failed: {stderr}"))
        }
    }
}

fn tray_participant_display_name(participant: &ParticipantView) -> String {
    let alias = participant.magic_dns_alias.trim();
    if !alias.is_empty() {
        return alias.to_string();
    }

    if let Some(label) = participant
        .magic_dns_name
        .split('.')
        .find(|segment| !segment.is_empty())
    {
        return label.to_string();
    }

    short_text(&participant.npub, 16, 8)
}

fn tray_network_groups(networks: &[NetworkView]) -> Vec<TrayNetworkGroup> {
    let mut groups = Vec::new();

    for network in networks.iter().filter(|network| network.enabled) {
        let devices = network
            .participants
            .iter()
            .filter(|participant| participant.state != "local")
            .map(|participant| {
                format!(
                    "{} ({})",
                    tray_participant_display_name(participant),
                    participant.state
                )
            })
            .collect::<Vec<_>>();

        if devices.is_empty() {
            continue;
        }

        groups.push(TrayNetworkGroup {
            title: format!(
                "{} ({}/{} online)",
                network.name, network.online_count, network.expected_count
            ),
            devices,
        });
    }

    groups
}

fn tray_exit_node_entries(
    networks: &[NetworkView],
    selected_exit_node: &str,
) -> Vec<TrayExitNodeEntry> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for network in networks.iter().filter(|network| network.enabled) {
        for participant in &network.participants {
            if participant.state == "local"
                || !participant.offers_exit_node
                || !seen.insert(participant.pubkey_hex.clone())
            {
                continue;
            }

            entries.push(TrayExitNodeEntry {
                pubkey_hex: participant.pubkey_hex.clone(),
                title: tray_participant_display_name(participant),
                selected: participant.pubkey_hex == selected_exit_node,
            });
        }
    }

    entries.sort_by(|left, right| {
        left.title
            .cmp(&right.title)
            .then(left.pubkey_hex.cmp(&right.pubkey_hex))
    });
    entries
}

fn tray_menu_spec(runtime_state: &TrayRuntimeState) -> Vec<TrayMenuItemSpec> {
    let mut network_items = Vec::new();
    if runtime_state.network_groups.is_empty() {
        network_items.push(TrayMenuItemSpec::Text {
            id: None,
            text: "No network devices configured".to_string(),
            enabled: false,
        });
    } else {
        for group in &runtime_state.network_groups {
            network_items.push(TrayMenuItemSpec::Submenu {
                text: group.title.clone(),
                enabled: true,
                items: group
                    .devices
                    .iter()
                    .map(|device| TrayMenuItemSpec::Text {
                        id: None,
                        text: device.clone(),
                        enabled: false,
                    })
                    .collect(),
            });
        }
    }

    let mut exit_node_items = vec![
        TrayMenuItemSpec::Check {
            id: TRAY_EXIT_NODE_NONE_MENU_ID.to_string(),
            text: "None".to_string(),
            enabled: true,
            checked: !runtime_state.advertise_exit_node
                && !runtime_state.exit_nodes.iter().any(|entry| entry.selected),
        },
        TrayMenuItemSpec::Check {
            id: TRAY_RUN_EXIT_NODE_MENU_ID.to_string(),
            text: "Run Exit Node".to_string(),
            enabled: true,
            checked: runtime_state.advertise_exit_node,
        },
    ];
    exit_node_items.push(TrayMenuItemSpec::Separator);
    if runtime_state.exit_nodes.is_empty() {
        exit_node_items.push(TrayMenuItemSpec::Text {
            id: None,
            text: "No exit nodes available".to_string(),
            enabled: false,
        });
    } else {
        exit_node_items.extend(runtime_state.exit_nodes.iter().map(|entry| {
            TrayMenuItemSpec::Check {
                id: format!("{TRAY_EXIT_NODE_MENU_ID_PREFIX}{}", entry.pubkey_hex),
                text: entry.title.clone(),
                enabled: true,
                checked: entry.selected,
            }
        }));
    }

    vec![
        TrayMenuItemSpec::Check {
            id: TRAY_VPN_TOGGLE_MENU_ID.to_string(),
            text: "VPN On".to_string(),
            enabled: true,
            checked: runtime_state.session_active,
        },
        TrayMenuItemSpec::Text {
            id: None,
            text: runtime_state.status_text.clone(),
            enabled: false,
        },
        TrayMenuItemSpec::Separator,
        TrayMenuItemSpec::Text {
            id: Some(TRAY_IDENTITY_MENU_ID.to_string()),
            text: runtime_state.identity_text.clone(),
            enabled: !runtime_state.identity_npub.trim().is_empty(),
        },
        TrayMenuItemSpec::Text {
            id: None,
            text: runtime_state.this_device_text.clone(),
            enabled: false,
        },
        TrayMenuItemSpec::Submenu {
            text: "Network Devices".to_string(),
            enabled: true,
            items: network_items,
        },
        TrayMenuItemSpec::Submenu {
            text: "Exit Nodes".to_string(),
            enabled: true,
            items: exit_node_items,
        },
        TrayMenuItemSpec::Separator,
        TrayMenuItemSpec::Text {
            id: Some(TRAY_OPEN_MENU_ID.to_string()),
            text: "Settings...".to_string(),
            enabled: true,
        },
        TrayMenuItemSpec::Text {
            id: Some(TRAY_QUIT_UI_MENU_ID.to_string()),
            text: "Quit".to_string(),
            enabled: true,
        },
    ]
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn current_tray_runtime_state<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> TrayRuntimeState {
    let Some(state) = app.try_state::<AppState>() else {
        return TrayRuntimeState::default();
    };
    let Ok(backend) = state.backend.lock() else {
        return TrayRuntimeState::default();
    };
    backend.tray_runtime_state()
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn append_tray_spec_to_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    menu: &Menu<R>,
    spec: &TrayMenuItemSpec,
) -> tauri::Result<()> {
    match spec {
        TrayMenuItemSpec::Check {
            id,
            text,
            enabled,
            checked,
        } => {
            let item = CheckMenuItemBuilder::with_id(id.clone(), text)
                .enabled(*enabled)
                .checked(*checked)
                .build(app)?;
            menu.append(&item)?;
        }
        TrayMenuItemSpec::Text { id, text, enabled } => {
            let item = if let Some(id) = id {
                MenuItemBuilder::with_id(id.clone(), text)
                    .enabled(*enabled)
                    .build(app)?
            } else {
                MenuItemBuilder::new(text).enabled(*enabled).build(app)?
            };
            menu.append(&item)?;
        }
        TrayMenuItemSpec::Submenu {
            text,
            enabled,
            items,
        } => {
            let submenu = build_tray_submenu_from_spec(app, text, *enabled, items)?;
            menu.append(&submenu)?;
        }
        TrayMenuItemSpec::Separator => {
            let separator = PredefinedMenuItem::separator(app)?;
            menu.append(&separator)?;
        }
    }

    Ok(())
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn append_tray_spec_to_submenu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    submenu: &Submenu<R>,
    spec: &TrayMenuItemSpec,
) -> tauri::Result<()> {
    match spec {
        TrayMenuItemSpec::Check {
            id,
            text,
            enabled,
            checked,
        } => {
            let item = CheckMenuItemBuilder::with_id(id.clone(), text)
                .enabled(*enabled)
                .checked(*checked)
                .build(app)?;
            submenu.append(&item)?;
        }
        TrayMenuItemSpec::Text { id, text, enabled } => {
            let item = if let Some(id) = id {
                MenuItemBuilder::with_id(id.clone(), text)
                    .enabled(*enabled)
                    .build(app)?
            } else {
                MenuItemBuilder::new(text).enabled(*enabled).build(app)?
            };
            submenu.append(&item)?;
        }
        TrayMenuItemSpec::Submenu {
            text,
            enabled,
            items,
        } => {
            let child = build_tray_submenu_from_spec(app, text, *enabled, items)?;
            submenu.append(&child)?;
        }
        TrayMenuItemSpec::Separator => {
            let separator = PredefinedMenuItem::separator(app)?;
            submenu.append(&separator)?;
        }
    }

    Ok(())
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn build_tray_submenu_from_spec<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    text: &str,
    enabled: bool,
    items: &[TrayMenuItemSpec],
) -> tauri::Result<Submenu<R>> {
    let submenu = SubmenuBuilder::new(app, text).enabled(enabled).build()?;
    for item in items {
        append_tray_spec_to_submenu(app, &submenu, item)?;
    }
    Ok(submenu)
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn build_tray_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    runtime_state: &TrayRuntimeState,
) -> tauri::Result<Menu<R>> {
    let menu = Menu::new(app)?;
    for item in tray_menu_spec(runtime_state) {
        append_tray_spec_to_menu(app, &menu, &item)?;
    }
    Ok(menu)
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn refresh_tray_menu<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(tray) = app.tray_by_id(TRAY_ICON_ID) else {
        return;
    };

    let runtime_state = current_tray_runtime_state(app);
    let Some(state) = app.try_state::<AppState>() else {
        if let Ok(menu) = build_tray_menu(app, &runtime_state) {
            let _ = tray.set_menu(Some(menu));
        }
        return;
    };
    let Ok(mut last_tray_runtime_state) = state.last_tray_runtime_state.lock() else {
        return;
    };

    if *last_tray_runtime_state == runtime_state {
        return;
    }

    if let Ok(menu) = build_tray_menu(app, &runtime_state)
        && tray.set_menu(Some(menu)).is_ok()
    {
        *last_tray_runtime_state = runtime_state;
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn refresh_tray_menu<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) {}

fn run_tray_backend_action<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    action: impl FnOnce(&mut NvpnBackend) -> Result<()>,
) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let Ok(mut backend) = state.backend.lock() else {
        return;
    };

    if let Err(error) = action(&mut backend) {
        backend.session_status = format!("Tray action failed: {error}");
    }
    backend.tick();
}

#[tauri::command]
fn tick(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn connect_session(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.connect_session()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn disconnect_session(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.disconnect_session()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn install_cli(state: State<'_, AppState>) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.install_cli_binary()?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn uninstall_cli(state: State<'_, AppState>) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.uninstall_cli_binary()?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn install_system_service(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.install_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn uninstall_system_service(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.uninstall_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn enable_system_service(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.enable_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn disable_system_service(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.disable_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn add_network(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.add_network(&name)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn rename_network(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
    name: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.rename_network(&network_id, &name)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn remove_network(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.remove_network(&network_id)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn set_network_mesh_id(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
    mesh_id: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.set_network_mesh_id(&network_id, &mesh_id)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn set_network_enabled(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
    enabled: bool,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.set_network_enabled(&network_id, enabled)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn add_participant(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
    npub: String,
    alias: Option<String>,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.add_participant(&network_id, &npub, alias.as_deref())?;
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn import_network_invite(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    invite: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.import_network_invite(&invite)?;
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn remove_participant(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    network_id: String,
    npub: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.remove_participant(&network_id, &npub)?;
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn set_participant_alias(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    npub: String,
    alias: String,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.set_participant_alias(&npub, &alias)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[tauri::command]
fn add_relay(state: State<'_, AppState>, relay: String) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.add_relay(&relay)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn remove_relay(state: State<'_, AppState>, relay: String) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.remove_relay(&relay)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn update_settings(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    patch: SettingsPatch,
) -> Result<UiState, String> {
    let ui = with_backend(state, |backend| {
        backend.update_settings(patch)?;
        backend.tick();
        Ok(backend.ui_state())
    })?;
    refresh_tray_menu(&app);
    Ok(ui)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let launched_from_autostart = started_from_autostart();
    match resolve_gui_launch_conflicts(launched_from_autostart) {
        Ok(GuiLaunchDisposition::Continue { terminate_pids }) => {
            terminate_gui_instances(&terminate_pids);
        }
        Ok(GuiLaunchDisposition::Exit) => return,
        Err(error) => {
            eprintln!("gui: failed to resolve GUI launch conflicts: {error}");
        }
    }
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if should_surface_existing_instance_args(args.iter()) {
                let _ = show_main_window(app);
            }
        }));
    #[cfg(target_os = "android")]
    let builder = tauri::Builder::default().plugin(android_vpn::Builder::new().build());
    #[cfg(target_os = "ios")]
    let builder = tauri::Builder::default();
    let app = builder
        .setup(move |app| {
            #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
            let _ = app;

            let config_path = resolve_backend_config_path(app.handle())
                .context("failed to resolve GUI config path")?;
            let backend =
                NvpnBackend::new(app.handle().clone(), config_path, launched_from_autostart)
                    .context("failed to initialize GUI backend state")?;
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            let launch_on_startup_default = backend.config.launch_on_startup;
            let initial_tray_state = backend.tray_runtime_state();
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            let setup_tray_state = initial_tray_state.clone();
            if !app.manage(AppState {
                backend: Mutex::new(backend),
                last_tray_runtime_state: Mutex::new(initial_tray_state),
            }) {
                return Err(anyhow!("application state already initialized").into());
            }

            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            app.handle().plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                Some(vec![AUTOSTART_LAUNCH_ARG]),
            ))?;

            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            {
                use tauri_plugin_autostart::ManagerExt;

                let auto = app.handle().autolaunch();
                let currently_enabled = auto.is_enabled().unwrap_or(false);
                if launch_on_startup_default {
                    if currently_enabled {
                        let _ = auto.disable();
                    }
                    let _ = auto.enable();
                } else if !launch_on_startup_default && currently_enabled {
                    let _ = auto.disable();
                }
            }

            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            {
                let tray_menu = build_tray_menu(app.handle(), &setup_tray_state)?;

                let tray_builder = TrayIconBuilder::with_id(TRAY_ICON_ID)
                    .tooltip("Nostr VPN")
                    .menu(&tray_menu)
                    .on_menu_event(|app, event| {
                        let menu_id = event.id().as_ref();
                        match menu_id {
                            TRAY_OPEN_MENU_ID => {
                                let _ = show_main_window(app);
                            }
                            TRAY_IDENTITY_MENU_ID => {
                                let runtime_state = current_tray_runtime_state(app);
                                if let Err(error) =
                                    copy_text_to_clipboard(&runtime_state.identity_npub)
                                {
                                    run_tray_backend_action(app, |_backend| Err(error));
                                    refresh_tray_menu(app);
                                }
                            }
                            TRAY_VPN_TOGGLE_MENU_ID => {
                                let runtime_state = current_tray_runtime_state(app);
                                run_tray_backend_action(app, |backend| {
                                    if runtime_state.session_active {
                                        backend
                                            .disconnect_session()
                                            .context("failed to pause VPN session")?;
                                    } else if runtime_state.service_setup_required {
                                        backend
                                            .install_system_service()
                                            .context("failed to install background service")?;
                                        backend.tick();
                                        if !backend.session_active {
                                            backend
                                                .connect_session()
                                                .context("failed to resume VPN session")?;
                                        }
                                    } else if runtime_state.service_enable_required {
                                        backend
                                            .enable_system_service()
                                            .context("failed to enable background service")?;
                                        backend.tick();
                                        if !backend.session_active {
                                            backend
                                                .connect_session()
                                                .context("failed to resume VPN session")?;
                                        }
                                    } else {
                                        backend
                                            .connect_session()
                                            .context("failed to resume VPN session")?;
                                    }
                                    Ok(())
                                });
                                refresh_tray_menu(app);
                            }
                            TRAY_RUN_EXIT_NODE_MENU_ID => {
                                let runtime_state = current_tray_runtime_state(app);
                                run_tray_backend_action(app, |backend| {
                                    backend
                                        .update_settings(SettingsPatch {
                                            advertise_exit_node: Some(
                                                !runtime_state.advertise_exit_node,
                                            ),
                                            ..Default::default()
                                        })
                                        .context("failed to toggle run exit node setting")
                                });
                                refresh_tray_menu(app);
                            }
                            TRAY_EXIT_NODE_NONE_MENU_ID => {
                                run_tray_backend_action(app, |backend| {
                                    backend
                                        .update_settings(SettingsPatch {
                                            exit_node: Some(String::new()),
                                            ..Default::default()
                                        })
                                        .context("failed to clear exit node")
                                });
                                refresh_tray_menu(app);
                            }
                            TRAY_QUIT_UI_MENU_ID => {
                                app.exit(0);
                            }
                            _ if menu_id.starts_with(TRAY_EXIT_NODE_MENU_ID_PREFIX) => {
                                let selected = menu_id
                                    .strip_prefix(TRAY_EXIT_NODE_MENU_ID_PREFIX)
                                    .unwrap_or_default()
                                    .to_string();
                                run_tray_backend_action(app, |backend| {
                                    backend
                                        .update_settings(SettingsPatch {
                                            exit_node: Some(selected),
                                            ..Default::default()
                                        })
                                        .context("failed to set exit node")
                                });
                                refresh_tray_menu(app);
                            }
                            _ => {}
                        }
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button,
                            button_state,
                            ..
                        } = event
                            && button == MouseButton::Left
                            && button_state == MouseButtonState::Up
                        {
                            let _ = show_main_window(tray.app_handle());
                        }
                    });

                #[cfg(target_os = "macos")]
                let tray_builder = if let Ok(icon) =
                    Image::from_bytes(include_bytes!("../icons/tray-template.png"))
                {
                    tray_builder.icon(icon).icon_as_template(true)
                } else {
                    eprintln!("tray: failed to load bundled template icon");
                    tray_builder
                };

                tray_builder.build(app)?;

                if launched_from_autostart {
                    hide_main_window_to_tray(app.handle());
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            tick,
            connect_session,
            disconnect_session,
            install_cli,
            uninstall_cli,
            install_system_service,
            uninstall_system_service,
            enable_system_service,
            disable_system_service,
            add_network,
            rename_network,
            remove_network,
            set_network_mesh_id,
            set_network_enabled,
            add_participant,
            import_network_invite,
            remove_participant,
            set_participant_alias,
            add_relay,
            remove_relay,
            update_settings,
        ])
        .on_window_event(|window, event| {
            #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
            let _ = (window, event);

            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            if let WindowEvent::CloseRequested { api, .. } = event
                && should_close_to_tray(window.app_handle())
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    app.run(|_app_handle, _event| {});
}

#[cfg(test)]
mod tests {
    use super::{
        ConfiguredPeerStatus, DaemonPeerState, DaemonRuntimeState, GuiLaunchDisposition,
        NETWORK_INVITE_PREFIX, NetworkInvite, NetworkView, NvpnBackend, ParticipantView,
        PeerPresenceStatus, RuntimePlatform, TRAY_EXIT_NODE_NONE_MENU_ID,
        TRAY_RUN_EXIT_NODE_MENU_ID, TrayMenuItemSpec, TrayRuntimeState, active_network_invite_code,
        apply_network_invite_to_active_network, cli_binary_installed_at, config_path_from_roots,
        expected_peer_count, extract_json_document, gui_launch_disposition,
        gui_requires_service_enable, gui_requires_service_install, is_already_running_message,
        is_mesh_complete, is_not_running_message, network_device_count,
        network_online_device_count, parse_advertised_routes_input, parse_exit_node_input,
        parse_network_invite, parse_running_gui_instances, peer_offers_exit_node,
        peer_presence_state_label, peer_state_label, runtime_capabilities_for_platform,
        should_defer_gui_daemon_start_to_service_on_autostart, should_start_gui_daemon_on_launch,
        should_surface_existing_instance_args, started_from_autostart_args, to_npub,
        tray_exit_node_entries, tray_identity_text, tray_menu_spec, tray_network_groups,
        tray_status_text, validate_nvpn_binary, within_peer_online_grace,
        within_peer_presence_grace,
    };
    use nostr_vpn_core::config::AppConfig;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tokio::runtime::Runtime;

    fn test_backend(participant: &str) -> NvpnBackend {
        let mut config = AppConfig::generated();
        config.networks[0].participants = vec![participant.to_string()];

        NvpnBackend {
            runtime: Runtime::new().expect("test runtime"),
            config_path: PathBuf::from("/tmp/nvpn-gui-test.toml"),
            config,
            nvpn_bin: None,
            session_status: "Disconnected".to_string(),
            daemon_running: false,
            session_active: false,
            relay_connected: false,
            service_supported: false,
            service_enablement_supported: false,
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: String::new(),
            daemon_state: None,
            relay_status: HashMap::new(),
            peer_status: HashMap::new(),
            lan_discovery_running: false,
            lan_discovery_rx: None,
            lan_discovery_stop: None,
            lan_peers: HashMap::new(),
            magic_dns_status: String::new(),
        }
    }

    fn epoch_secs_ago(age_secs: u64) -> u64 {
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after epoch")
            .as_secs()
            .saturating_sub(age_secs)
    }

    fn daemon_peer(
        participant: &str,
        reachable: bool,
        signal_age_secs: Option<u64>,
        error: Option<&str>,
        endpoint: &str,
    ) -> DaemonPeerState {
        DaemonPeerState {
            participant_pubkey: participant.to_string(),
            node_id: "peer-a".to_string(),
            tunnel_ip: "10.44.0.2/32".to_string(),
            endpoint: endpoint.to_string(),
            public_key: "peer-public-key".to_string(),
            advertised_routes: Vec::new(),
            presence_timestamp: signal_age_secs.map(epoch_secs_ago).unwrap_or(0),
            last_signal_seen_at: signal_age_secs.map(epoch_secs_ago),
            reachable,
            last_handshake_at: if reachable {
                Some(epoch_secs_ago(5))
            } else {
                None
            },
            error: error.map(str::to_string),
        }
    }

    fn daemon_state_with_peer(
        peer: Option<DaemonPeerState>,
        session_active: bool,
    ) -> DaemonRuntimeState {
        let connected_peer_count = usize::from(peer.as_ref().is_some_and(|value| value.reachable));
        DaemonRuntimeState {
            updated_at: epoch_secs_ago(0),
            session_active,
            relay_connected: false,
            session_status: if session_active {
                "Connecting to relays".to_string()
            } else {
                "Disconnected".to_string()
            },
            expected_peer_count: 1,
            connected_peer_count,
            mesh_ready: connected_peer_count > 0,
            health: Vec::new(),
            network: Default::default(),
            port_mapping: Default::default(),
            peers: peer.into_iter().collect(),
        }
    }

    #[test]
    fn expected_peer_count_excludes_own_participant_when_present() {
        let mut config = AppConfig::generated();
        let own_hex =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
        config.networks[0].participants = vec![
            own_hex.clone(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        config.nostr.public_key = to_npub(&own_hex);

        assert_eq!(expected_peer_count(&config), 2);
    }

    #[test]
    fn mesh_completion_requires_expected_non_zero() {
        assert!(!is_mesh_complete(0, 0));
        assert!(!is_mesh_complete(1, 2));
        assert!(is_mesh_complete(2, 2));
    }

    #[test]
    fn enabled_network_device_count_includes_local_device() {
        assert_eq!(network_device_count(0, true), 1);
        assert_eq!(network_device_count(2, true), 3);
        assert_eq!(network_device_count(2, false), 0);
    }

    #[test]
    fn online_network_device_count_only_includes_local_when_session_is_active() {
        assert_eq!(network_online_device_count(0, true, true), 1);
        assert_eq!(network_online_device_count(1, true, true), 2);
        assert_eq!(network_online_device_count(1, true, false), 1);
        assert_eq!(network_online_device_count(1, false, true), 0);
    }

    #[test]
    fn extract_json_document_ignores_prefix_noise() {
        let raw = "INFO something\n{\"daemon\":{\"running\":false}}\n";
        let extracted = extract_json_document(raw).expect("should extract json object");
        assert_eq!(extracted, "{\"daemon\":{\"running\":false}}")
    }

    #[test]
    fn service_status_response_parses_snake_case_cli_json() {
        let raw = r#"{
          "supported": true,
          "installed": true,
          "disabled": false,
          "loaded": true,
          "running": true,
          "pid": 123,
          "label": "to.nostrvpn.nvpn",
          "plist_path": "/Library/LaunchDaemons/to.nostrvpn.nvpn.plist"
        }"#;
        let parsed: super::CliServiceStatusResponse =
            serde_json::from_str(raw).expect("service status JSON should parse");
        assert!(parsed.supported);
        assert!(parsed.installed);
        assert!(!parsed.disabled);
        assert!(parsed.loaded);
        assert!(parsed.running);
        assert_eq!(parsed.pid, Some(123));
        assert_eq!(parsed.label, "to.nostrvpn.nvpn");
        assert_eq!(
            parsed.plist_path,
            "/Library/LaunchDaemons/to.nostrvpn.nvpn.plist"
        );
    }

    #[test]
    fn idempotent_daemon_error_matchers_work_for_elevated_messages() {
        assert!(is_already_running_message(
            "elevated nvpn command failed ... Error: daemon already running with pid 42"
        ));
        assert!(is_not_running_message(
            "elevated nvpn command failed ... daemon: not running"
        ));
        assert!(!is_already_running_message("permission denied"));
        assert!(!is_not_running_message("permission denied"));
    }

    #[test]
    fn peer_online_grace_matches_wireguard_session_window() {
        let now = SystemTime::now();
        assert!(within_peer_online_grace(
            Some(now - Duration::from_secs(5)),
            now
        ));
        assert!(within_peer_online_grace(
            Some(now - Duration::from_secs(120)),
            now
        ));
        assert!(!within_peer_online_grace(
            Some(now - Duration::from_secs(181)),
            now
        ));
        assert!(!within_peer_online_grace(None, now));
    }

    #[test]
    fn peer_presence_grace_keeps_recent_signal_present() {
        let now = SystemTime::now();
        assert!(within_peer_presence_grace(
            Some(now - Duration::from_secs(5)),
            now
        ));
        assert!(!within_peer_presence_grace(
            Some(now - Duration::from_secs(90)),
            now
        ));
        assert!(!within_peer_presence_grace(None, now));
    }

    #[test]
    fn peer_labels_distinguish_transport_and_presence() {
        assert_eq!(peer_state_label(ConfiguredPeerStatus::Present), "pending");
        assert_eq!(
            peer_presence_state_label(PeerPresenceStatus::Present),
            "present"
        );
        assert_eq!(
            peer_presence_state_label(PeerPresenceStatus::Absent),
            "absent"
        );
    }

    #[test]
    fn refresh_peer_runtime_status_marks_missing_signal_as_offline() {
        let participant = "11".repeat(32);
        let mut backend = test_backend(&participant);
        backend.session_active = true;
        backend.daemon_state = Some(daemon_state_with_peer(None, true));

        backend.refresh_peer_runtime_status();

        assert_eq!(
            backend.peer_state_for(&participant, None),
            ConfiguredPeerStatus::Offline
        );
        assert_eq!(
            backend
                .peer_status
                .get(&participant)
                .and_then(|status| status.error.as_deref()),
            Some("no signal yet")
        );
    }

    #[test]
    fn refresh_peer_runtime_status_marks_fresh_signal_without_handshake_as_pending() {
        let participant = "22".repeat(32);
        let mut backend = test_backend(&participant);
        backend.session_active = true;
        backend.daemon_state = Some(daemon_state_with_peer(
            Some(daemon_peer(
                &participant,
                false,
                Some(5),
                Some("awaiting handshake"),
                "203.0.113.20:51820",
            )),
            true,
        ));

        backend.refresh_peer_runtime_status();

        assert_eq!(
            backend.peer_state_for(&participant, None),
            ConfiguredPeerStatus::Present
        );
        assert_eq!(
            backend.peer_presence_state_for(&participant, None),
            PeerPresenceStatus::Present
        );
        assert!(
            backend
                .peer_status_line(&participant, ConfiguredPeerStatus::Present)
                .contains("awaiting WireGuard handshake via")
        );
    }

    #[test]
    fn refresh_peer_runtime_status_marks_stale_signal_as_offline() {
        let participant = "33".repeat(32);
        let mut backend = test_backend(&participant);
        backend.session_active = true;
        backend.daemon_state = Some(daemon_state_with_peer(
            Some(daemon_peer(
                &participant,
                false,
                Some(90),
                Some("signal stale"),
                "203.0.113.20:51820",
            )),
            true,
        ));

        backend.refresh_peer_runtime_status();

        assert_eq!(
            backend.peer_state_for(&participant, None),
            ConfiguredPeerStatus::Offline
        );
        assert_eq!(
            backend.peer_presence_state_for(&participant, None),
            PeerPresenceStatus::Absent
        );
        assert!(
            backend
                .peer_status_line(&participant, ConfiguredPeerStatus::Offline)
                .contains("signal stale")
        );
    }

    #[test]
    fn tray_status_text_distinguishes_connected_service_and_disconnected_states() {
        assert_eq!(
            tray_status_text(true, false, false, "Connecting to relays"),
            "Connected"
        );
        assert_eq!(
            tray_status_text(false, true, false, "Disconnected"),
            "Install background service"
        );
        assert_eq!(
            tray_status_text(false, false, true, "Disconnected"),
            "Enable background service"
        );
        assert_eq!(
            tray_status_text(false, false, false, "Disconnected"),
            "Disconnected"
        );
        assert_eq!(
            tray_status_text(false, false, false, "Private announce failed"),
            "Private announce failed"
        );
    }

    #[test]
    fn parse_advertised_routes_input_normalizes_and_deduplicates() {
        let routes = parse_advertised_routes_input("10.0.0.1/24, 10.0.0.0/24, ::1/64")
            .expect("routes should parse");
        assert_eq!(routes, vec!["10.0.0.0/24".to_string(), "::/64".to_string()]);
    }

    #[test]
    fn peer_offers_exit_node_detects_default_routes() {
        assert!(peer_offers_exit_node(&["0.0.0.0/0".to_string()]));
        assert!(peer_offers_exit_node(&["::/0".to_string()]));
        assert!(!peer_offers_exit_node(&["10.0.0.0/24".to_string()]));
    }

    #[test]
    fn parse_exit_node_input_normalizes_and_clears() {
        let peer_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let peer_npub = to_npub(&peer_hex);

        assert_eq!(
            parse_exit_node_input(&peer_npub).expect("npub exit node should parse"),
            peer_hex
        );
        assert_eq!(
            parse_exit_node_input("off").expect("off should clear selection"),
            String::new()
        );
        assert_eq!(
            parse_exit_node_input("none").expect("none should clear selection"),
            String::new()
        );
        assert_eq!(
            parse_exit_node_input("").expect("empty should clear selection"),
            String::new()
        );
    }

    #[test]
    fn active_network_invite_round_trips() {
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let inviter_npub = to_npub(&inviter_hex);
        let mut config = AppConfig::generated();
        config.nostr.public_key = inviter_npub.clone();
        config.networks[0].name = "Home".to_string();
        config.networks[0].network_id = "mesh-home".to_string();
        config.nostr.relays = vec![
            "wss://relay.one.example".to_string(),
            "wss://relay.two.example".to_string(),
        ];

        let code = active_network_invite_code(&config).expect("invite code should encode");
        assert!(code.starts_with(NETWORK_INVITE_PREFIX));

        let parsed = parse_network_invite(&code).expect("invite code should decode");
        assert_eq!(
            parsed,
            NetworkInvite {
                v: 1,
                network_name: "Home".to_string(),
                network_id: "mesh-home".to_string(),
                inviter_npub,
                relays: vec![
                    "wss://relay.one.example".to_string(),
                    "wss://relay.two.example".to_string(),
                ],
            }
        );
    }

    #[test]
    fn applying_network_invite_updates_active_network_and_merges_relays() {
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let invite = NetworkInvite {
            v: 1,
            network_name: "Home".to_string(),
            network_id: "mesh-home".to_string(),
            inviter_npub: to_npub(&inviter_hex),
            relays: vec![
                "wss://existing.example".to_string(),
                "wss://invite.example".to_string(),
            ],
        };
        let mut config = AppConfig::generated();
        config.networks[0].name = "Network 1".to_string();
        config.nostr.public_key =
            "npub1j4c4x0w2g6q3jz9q8ruy6xw0jfs6w8szk8dks3l8h0f5syv2sgzq9w8m7n".to_string();
        config.nostr.relays = vec!["wss://existing.example".to_string()];

        apply_network_invite_to_active_network(&mut config, &invite).expect("invite should apply");

        assert_eq!(config.networks[0].name, "Home");
        assert_eq!(config.effective_network_id(), "mesh-home");
        assert_eq!(config.participant_pubkeys_hex(), vec![inviter_hex]);
        assert_eq!(
            config.nostr.relays,
            vec![
                "wss://existing.example".to_string(),
                "wss://invite.example".to_string(),
            ]
        );
    }

    #[test]
    fn tray_network_groups_skip_disabled_networks_and_local_participants() {
        let groups = tray_network_groups(&[
            NetworkView {
                id: "home".to_string(),
                name: "Home".to_string(),
                enabled: true,
                network_id: "mesh-home".to_string(),
                online_count: 1,
                expected_count: 2,
                participants: vec![
                    ParticipantView {
                        npub: "npub1local".to_string(),
                        pubkey_hex: "local".to_string(),
                        tunnel_ip: "10.44.0.10".to_string(),
                        magic_dns_alias: "self".to_string(),
                        magic_dns_name: "self.nvpn".to_string(),
                        advertised_routes: Vec::new(),
                        offers_exit_node: false,
                        state: "local".to_string(),
                        presence_state: "local".to_string(),
                        status_text: "local".to_string(),
                        last_signal_text: "now".to_string(),
                    },
                    ParticipantView {
                        npub: "npub1alice".to_string(),
                        pubkey_hex: "alice".to_string(),
                        tunnel_ip: "10.44.0.11".to_string(),
                        magic_dns_alias: "alice".to_string(),
                        magic_dns_name: "alice.nvpn".to_string(),
                        advertised_routes: Vec::new(),
                        offers_exit_node: false,
                        state: "online".to_string(),
                        presence_state: "present".to_string(),
                        status_text: "online".to_string(),
                        last_signal_text: "just now".to_string(),
                    },
                ],
            },
            NetworkView {
                id: "lab".to_string(),
                name: "Lab".to_string(),
                enabled: false,
                network_id: "mesh-lab".to_string(),
                online_count: 0,
                expected_count: 1,
                participants: vec![ParticipantView {
                    npub: "npub1bob".to_string(),
                    pubkey_hex: "bob".to_string(),
                    tunnel_ip: "10.44.0.12".to_string(),
                    magic_dns_alias: "bob".to_string(),
                    magic_dns_name: "bob.nvpn".to_string(),
                    advertised_routes: Vec::new(),
                    offers_exit_node: false,
                    state: "offline".to_string(),
                    presence_state: "absent".to_string(),
                    status_text: "offline".to_string(),
                    last_signal_text: "1m ago".to_string(),
                }],
            },
        ]);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].title, "Home (1/2 online)");
        assert_eq!(groups[0].devices, vec!["alice (online)".to_string()]);
    }

    #[test]
    fn tray_exit_nodes_deduplicate_and_mark_selected_entry() {
        let entries = tray_exit_node_entries(
            &[
                NetworkView {
                    id: "home".to_string(),
                    name: "Home".to_string(),
                    enabled: true,
                    network_id: "mesh-home".to_string(),
                    online_count: 1,
                    expected_count: 1,
                    participants: vec![ParticipantView {
                        npub: "npub1alice".to_string(),
                        pubkey_hex: "alice".to_string(),
                        tunnel_ip: "10.44.0.11".to_string(),
                        magic_dns_alias: "alice".to_string(),
                        magic_dns_name: "alice.nvpn".to_string(),
                        advertised_routes: vec!["0.0.0.0/0".to_string()],
                        offers_exit_node: true,
                        state: "online".to_string(),
                        presence_state: "present".to_string(),
                        status_text: "online".to_string(),
                        last_signal_text: "just now".to_string(),
                    }],
                },
                NetworkView {
                    id: "work".to_string(),
                    name: "Work".to_string(),
                    enabled: true,
                    network_id: "mesh-work".to_string(),
                    online_count: 1,
                    expected_count: 1,
                    participants: vec![
                        ParticipantView {
                            npub: "npub1alice".to_string(),
                            pubkey_hex: "alice".to_string(),
                            tunnel_ip: "10.44.0.11".to_string(),
                            magic_dns_alias: "alice".to_string(),
                            magic_dns_name: "alice.nvpn".to_string(),
                            advertised_routes: vec!["0.0.0.0/0".to_string()],
                            offers_exit_node: true,
                            state: "online".to_string(),
                            presence_state: "present".to_string(),
                            status_text: "online".to_string(),
                            last_signal_text: "just now".to_string(),
                        },
                        ParticipantView {
                            npub: "npub1bob".to_string(),
                            pubkey_hex: "bob".to_string(),
                            tunnel_ip: "10.44.0.12".to_string(),
                            magic_dns_alias: "bob".to_string(),
                            magic_dns_name: "bob.nvpn".to_string(),
                            advertised_routes: vec!["::/0".to_string()],
                            offers_exit_node: true,
                            state: "offline".to_string(),
                            presence_state: "absent".to_string(),
                            status_text: "offline".to_string(),
                            last_signal_text: "1m ago".to_string(),
                        },
                    ],
                },
            ],
            "bob",
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "alice");
        assert!(!entries[0].selected);
        assert_eq!(entries[1].title, "bob");
        assert!(entries[1].selected);
    }

    #[test]
    fn tray_identity_text_formats_copy_action() {
        assert_eq!(
            tray_identity_text("npub1j4c4x0w2g6q3jz9q8ruy6xw0jfs6w8szk8dks3l8h0f5syv2sgzq9w8m7n"),
            "Copy npub1j4c4x0w2g6q...zq9w8m7n"
        );
        assert_eq!(tray_identity_text(""), "Copy npub unavailable");
    }

    #[test]
    fn tray_menu_spec_puts_toggle_first_and_settings_last() {
        let spec = tray_menu_spec(&TrayRuntimeState {
            session_active: true,
            service_setup_required: false,
            service_enable_required: false,
            status_text: tray_status_text(true, false, false, "Connected"),
            identity_npub: "npub1j4c4x0w2g6q3jz9q8ruy6xw0jfs6w8szk8dks3l8h0f5syv2sgzq9w8m7n"
                .to_string(),
            identity_text: "Copy npub1j4c4x0w2g6q...zq9w8m7n".to_string(),
            this_device_text: "This Device: sirius (10.44.0.10)".to_string(),
            advertise_exit_node: false,
            network_groups: tray_network_groups(&[NetworkView {
                id: "home".to_string(),
                name: "Home".to_string(),
                enabled: true,
                network_id: "mesh-home".to_string(),
                online_count: 1,
                expected_count: 1,
                participants: vec![ParticipantView {
                    npub: "npub1alice".to_string(),
                    pubkey_hex: "alice".to_string(),
                    tunnel_ip: "10.44.0.11".to_string(),
                    magic_dns_alias: "alice".to_string(),
                    magic_dns_name: "alice.nvpn".to_string(),
                    advertised_routes: Vec::new(),
                    offers_exit_node: false,
                    state: "online".to_string(),
                    presence_state: "present".to_string(),
                    status_text: "online".to_string(),
                    last_signal_text: "just now".to_string(),
                }],
            }]),
            exit_nodes: tray_exit_node_entries(&[], ""),
        });

        assert!(matches!(
            spec.first(),
            Some(TrayMenuItemSpec::Check {
                text,
                checked: true,
                ..
            }) if text == "VPN On"
        ));
        assert!(spec.iter().any(|item| matches!(
            item,
            TrayMenuItemSpec::Submenu { text, .. } if text == "Network Devices"
        )));
        assert!(spec.iter().any(|item| match item {
            TrayMenuItemSpec::Submenu { text, items, .. } if text == "Exit Nodes" =>
                items.iter().any(|entry| matches!(
                    entry,
                    TrayMenuItemSpec::Check {
                        id,
                        text,
                        checked: false,
                        ..
                    } if id == TRAY_RUN_EXIT_NODE_MENU_ID && text == "Run Exit Node"
                )),
            _ => false,
        }));
        assert!(spec.iter().any(|item| matches!(
            item,
            TrayMenuItemSpec::Text {
                text,
                enabled: true,
                ..
            } if text == "Settings..."
        )));
        assert!(matches!(
            spec.last(),
            Some(TrayMenuItemSpec::Text {
                text,
                enabled: true,
                ..
            }) if text == "Quit"
        ));
    }

    #[test]
    fn tray_menu_spec_marks_local_exit_node_toggle_checked_when_enabled() {
        let spec = tray_menu_spec(&TrayRuntimeState {
            advertise_exit_node: true,
            ..TrayRuntimeState::default()
        });

        assert!(spec.iter().any(|item| match item {
            TrayMenuItemSpec::Submenu { text, items, .. } if text == "Exit Nodes" =>
                items.iter().any(|entry| matches!(
                    entry,
                    TrayMenuItemSpec::Check {
                        id,
                        text,
                        checked: true,
                        ..
                    } if id == TRAY_RUN_EXIT_NODE_MENU_ID && text == "Run Exit Node"
                )),
            _ => false,
        }));
        assert!(spec.iter().any(|item| match item {
            TrayMenuItemSpec::Submenu { text, items, .. } if text == "Exit Nodes" =>
                items.iter().any(|entry| matches!(
                    entry,
                    TrayMenuItemSpec::Check {
                        id,
                        checked: false,
                        ..
                    } if id == TRAY_EXIT_NODE_NONE_MENU_ID
                )),
            _ => false,
        }));
    }

    #[test]
    fn ui_state_reports_product_version() {
        let backend = test_backend(&"44".repeat(32));
        let state = backend.ui_state();

        assert_eq!(state.app_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn parse_running_gui_instances_filters_self_and_marks_autostart() {
        let instances = parse_running_gui_instances(
            "  627 /Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn-gui\n 1573 /Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn-gui --autostart\n 9000 /usr/bin/ssh-agent -l\n",
            627,
        );

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].pid, 1573);
        assert!(instances[0].autostart);
    }

    #[test]
    fn autostart_launch_exits_when_any_other_gui_instance_exists() {
        let instances = parse_running_gui_instances(
            "  627 /Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn-gui\n",
            1573,
        );

        assert_eq!(
            gui_launch_disposition(true, &instances),
            GuiLaunchDisposition::Exit
        );
    }

    #[test]
    fn manual_launch_replaces_hidden_autostart_instance() {
        let instances = parse_running_gui_instances(
            " 1573 /Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn-gui --autostart\n",
            627,
        );

        assert_eq!(
            gui_launch_disposition(false, &instances),
            GuiLaunchDisposition::Continue {
                terminate_pids: vec![1573]
            }
        );
    }

    #[test]
    fn validate_nvpn_binary_rejects_missing_path() {
        let result = validate_nvpn_binary("/path/that/does/not/exist".into());
        assert!(result.is_err());
    }

    #[test]
    fn autostart_launch_detection_matches_explicit_flag() {
        assert!(started_from_autostart_args([
            "/Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn",
            "--autostart",
        ]));
        assert!(!started_from_autostart_args([
            "/Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn",
            "--autostarted",
        ]));
    }

    #[test]
    fn existing_instance_surface_skips_autostart_relaunches() {
        assert!(should_surface_existing_instance_args([
            "/Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn",
            "--launched-from-cli",
        ]));
        assert!(!should_surface_existing_instance_args([
            "/Applications/Nostr VPN.app/Contents/MacOS/nostr-vpn",
            "--autostart",
        ]));
    }

    #[test]
    fn gui_requires_service_install_only_when_no_service_and_no_daemon() {
        assert!(gui_requires_service_install(true, false, false));
        assert!(!gui_requires_service_install(true, false, true));
        assert!(!gui_requires_service_install(true, true, false));
        assert!(!gui_requires_service_install(false, false, false));
    }

    #[test]
    fn gui_requires_service_enable_only_when_service_is_disabled_and_idle() {
        assert!(gui_requires_service_enable(true, true, true, false));
        assert!(!gui_requires_service_enable(true, true, true, true));
        assert!(!gui_requires_service_enable(true, true, false, false));
        assert!(!gui_requires_service_enable(true, false, true, false));
        assert!(!gui_requires_service_enable(false, true, true, false));
    }

    #[test]
    fn gui_launch_autoconnect_skips_direct_start_until_service_exists() {
        assert!(!should_start_gui_daemon_on_launch(true, true, true));
        assert!(should_start_gui_daemon_on_launch(true, true, false));
        assert!(!should_start_gui_daemon_on_launch(true, false, false));
        assert!(!should_start_gui_daemon_on_launch(false, true, false));
    }

    #[test]
    fn gui_launch_autoconnect_defers_to_installed_service_on_autostart() {
        assert!(should_defer_gui_daemon_start_to_service_on_autostart(
            true, true, false
        ));
        assert!(!should_defer_gui_daemon_start_to_service_on_autostart(
            false, true, false
        ));
        assert!(!should_defer_gui_daemon_start_to_service_on_autostart(
            true, false, false
        ));
        assert!(!should_defer_gui_daemon_start_to_service_on_autostart(
            true, true, true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn validate_nvpn_binary_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let mut path = std::env::temp_dir();
        path.push(format!(
            "nvpn-test-{}-{}",
            std::process::id(),
            super::unix_timestamp()
        ));
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write test executable");
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&path, perms).expect("set permissions");

        let result = validate_nvpn_binary(path.clone());
        assert!(result.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_install_detection_accepts_files_but_not_directories() {
        let base = std::env::temp_dir().join(format!(
            "nvpn-gui-cli-install-test-{}-{}",
            std::process::id(),
            super::unix_timestamp()
        ));
        let file_path = base.join("nvpn");
        let dir_path = base.join("bin");

        assert!(!cli_binary_installed_at(&file_path));

        std::fs::create_dir_all(&base).expect("create base dir");
        std::fs::write(&file_path, b"#!/bin/sh\n").expect("write cli file");
        assert!(cli_binary_installed_at(&file_path));

        std::fs::create_dir_all(&dir_path).expect("create dir path");
        assert!(!cli_binary_installed_at(&dir_path));

        let _ = std::fs::remove_file(file_path);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn android_runtime_capabilities_disable_desktop_management_features() {
        let capabilities = runtime_capabilities_for_platform(RuntimePlatform::Android);

        assert_eq!(capabilities.platform, "android");
        assert!(capabilities.mobile);
        assert!(capabilities.vpn_session_control_supported);
        assert!(!capabilities.cli_install_supported);
        assert!(!capabilities.startup_settings_supported);
        assert!(!capabilities.tray_behavior_supported);
        assert!(
            capabilities
                .runtime_status_detail
                .contains("Android native VPN control")
        );
    }

    #[test]
    fn desktop_runtime_capabilities_keep_existing_management_features() {
        let capabilities = runtime_capabilities_for_platform(RuntimePlatform::Desktop);

        assert_eq!(capabilities.platform, "desktop");
        assert!(!capabilities.mobile);
        assert!(capabilities.vpn_session_control_supported);
        assert!(capabilities.cli_install_supported);
        assert!(capabilities.startup_settings_supported);
        assert!(capabilities.tray_behavior_supported);
        assert_eq!(capabilities.runtime_status_detail, "");
    }

    #[test]
    fn config_path_from_roots_prefers_mobile_app_config_dir() {
        let path = config_path_from_roots(
            Some(std::path::Path::new("/data/user/0/to.iris.nvpn/files")),
            Some(std::path::Path::new("/home/test/.config")),
        );

        assert_eq!(
            path,
            PathBuf::from("/data/user/0/to.iris.nvpn/files/config.toml")
        );
    }

    #[test]
    fn config_path_from_roots_uses_dirs_config_dir_when_mobile_dir_missing() {
        let path = config_path_from_roots(None, Some(std::path::Path::new("/home/test/.config")));

        assert_eq!(path, PathBuf::from("/home/test/.config/nvpn/config.toml"));
    }
}
