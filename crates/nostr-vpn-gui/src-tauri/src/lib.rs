use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, derive_mesh_tunnel_ip, maybe_autoconfigure_node, normalize_nostr_pubkey,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use tauri::image::Image;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State, WindowEvent};
use tokio::runtime::Runtime;

const LAN_DISCOVERY_ADDR: [u8; 4] = [239, 255, 73, 73];
const LAN_DISCOVERY_PORT: u16 = 38911;
const LAN_DISCOVERY_STALE_AFTER_SECS: u64 = 16;
const PEER_ONLINE_GRACE_SECS: u64 = 20;
const TRAY_ICON_ID: &str = "nvpn-tray";
const TRAY_OPEN_MENU_ID: &str = "tray_open_main";
const TRAY_VPN_TOGGLE_MENU_ID: &str = "tray_vpn_toggle";
const TRAY_QUIT_UI_MENU_ID: &str = "tray_quit_ui";
const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const AUTOSTART_LAUNCH_ARG: &str = "--autostart";
const GUI_SERVICE_SETUP_REQUIRED_STATUS: &str =
    "Install background service to turn VPN on from the app";
const GUI_SERVICE_SETUP_REQUIRED_AUTOCONNECT_STATUS: &str =
    "Install background service to enable app auto-connect";

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfiguredPeerStatus {
    Local,
    Online,
    Offline,
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
    state: String,
    status_text: String,
    last_signal_text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkView {
    id: String,
    name: String,
    enabled: bool,
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
    daemon_running: bool,
    session_active: bool,
    relay_connected: bool,
    cli_installed: bool,
    service_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    service_running: bool,
    service_status_detail: String,
    session_status: String,
    config_path: String,
    own_npub: String,
    own_pubkey_hex: String,
    node_id: String,
    node_name: String,
    endpoint: String,
    tunnel_ip: String,
    listen_port: u16,
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
    networks: Vec<NetworkView>,
    relays: Vec<RelayView>,
    relay_summary: RelaySummary,
    lan_peers: Vec<LanPeerView>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsPatch {
    node_name: Option<String>,
    endpoint: Option<String>,
    tunnel_ip: Option<String>,
    listen_port: Option<u16>,
    magic_dns_suffix: Option<String>,
    auto_disconnect_relays_when_mesh_ready: Option<bool>,
    autoconnect: Option<bool>,
    lan_discovery_enabled: Option<bool>,
    launch_on_startup: Option<bool>,
    close_to_tray_on_close: Option<bool>,
}

struct NvpnBackend {
    runtime: Runtime,
    config_path: PathBuf,
    config: AppConfig,
    nvpn_bin: Option<PathBuf>,

    session_status: String,
    daemon_running: bool,
    session_active: bool,
    relay_connected: bool,
    service_supported: bool,
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
    fn new() -> Result<Self> {
        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        let config_path = default_config_path();

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
            session_status: "Disconnected".to_string(),
            daemon_running: false,
            session_active: false,
            relay_connected: false,
            service_supported: cfg!(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "windows"
            )),
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
        if should_start_gui_daemon_on_launch(
            backend.config.autoconnect,
            !backend.config.participant_pubkeys_hex().is_empty(),
            backend.gui_requires_service_install(),
        ) && !backend.daemon_running
        {
            if let Err(error) = backend.start_daemon_process() {
                backend.session_status = format!("Daemon start failed: {error}");
            }
            backend.sync_daemon_state();
        } else if wants_autoconnect && backend.gui_requires_service_install() {
            backend.session_status = gui_service_setup_status_text(true).to_string();
        }

        Ok(backend)
    }

    fn connect_session(&mut self) -> Result<()> {
        self.persist_config()?;
        self.sync_daemon_state();
        if self.daemon_running {
            self.resume_daemon_process()?;
        } else if self.gui_requires_service_install() {
            self.session_status = gui_service_setup_status_text(false).to_string();
            return Err(anyhow!(self.session_status.clone()));
        } else {
            self.start_daemon_process()?;
        }
        self.sync_daemon_state();
        Ok(())
    }

    fn disconnect_session(&mut self) -> Result<()> {
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

    #[cfg(target_os = "macos")]
    fn start_daemon_process(&self) -> Result<()> {
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

    #[cfg(not(target_os = "macos"))]
    fn start_daemon_process(&self) -> Result<()> {
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

    fn reload_daemon_process(&self) -> Result<()> {
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

    fn pause_daemon_process(&self) -> Result<()> {
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

    fn resume_daemon_process(&self) -> Result<()> {
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

    fn reload_daemon_if_running(&self) -> Result<()> {
        if !self.daemon_running {
            return Ok(());
        }

        self.reload_daemon_process()
    }

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

    fn sync_service_state(&mut self) {
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
                continue;
            }

            if !self.session_active {
                status.reachable = None;
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = Some("vpn off".to_string());
                status.last_signal_seen_at = None;
                continue;
            }

            let Some(peer) = daemon_peer_map.get(participant.as_str()) else {
                status.reachable = Some(false);
                status.last_handshake_at = None;
                status.endpoint = None;
                status.error = Some("no signal yet".to_string());
                status.last_signal_seen_at = None;
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
        mesh_members: &[String],
        own_pubkey_hex: Option<&str>,
    ) -> ParticipantView {
        let tunnel_ip =
            derive_mesh_tunnel_ip(mesh_members, participant).unwrap_or_else(|| "-".to_string());
        let state = self.peer_state_for(participant, own_pubkey_hex);
        let status_text = self.peer_status_line(participant, state);
        let last_signal_text = self.peer_presence_line(participant, own_pubkey_hex);
        let magic_dns_alias = self.config.peer_alias(participant).unwrap_or_default();
        let magic_dns_name = self
            .config
            .magic_dns_name_for_participant(participant)
            .unwrap_or_default();

        ParticipantView {
            npub: to_npub(participant),
            pubkey_hex: participant.to_string(),
            tunnel_ip,
            magic_dns_alias,
            magic_dns_name,
            state: peer_state_label(state).to_string(),
            status_text,
            last_signal_text,
        }
    }

    fn network_rows(&self) -> Vec<NetworkView> {
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().ok();
        let mesh_members = self.config.mesh_members_pubkeys();
        let mut rows = Vec::with_capacity(self.config.networks.len());

        for network in &self.config.networks {
            let mut participants = network.participants.clone();
            participants.sort();
            participants.dedup();

            let participant_rows = participants
                .iter()
                .map(|participant| {
                    self.participant_view(participant, &mesh_members, own_pubkey_hex.as_deref())
                })
                .collect::<Vec<_>>();

            let expected_count = if network.enabled {
                participants
                    .iter()
                    .filter(|participant| Some(participant.as_str()) != own_pubkey_hex.as_deref())
                    .count()
            } else {
                0
            };

            let online_count = if network.enabled {
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

            rows.push(NetworkView {
                id: network.id.clone(),
                name: network.name.clone(),
                enabled: network.enabled,
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
            return "no presence yet".to_string();
        };

        let age_secs = seen_at
            .elapsed()
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!("presence {age_secs}s ago")
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
            Some(status) if status.reachable == Some(false) => ConfiguredPeerStatus::Offline,
            _ => ConfiguredPeerStatus::Unknown,
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

        UiState {
            daemon_running: self.daemon_running,
            session_active: self.session_active,
            relay_connected: self.relay_connected,
            cli_installed: cli_binary_installed(),
            service_supported: self.service_supported,
            service_installed: self.service_installed,
            service_disabled: self.service_disabled,
            service_running: self.service_running,
            service_status_detail: self.service_status_detail.clone(),
            session_status: self.session_status.clone(),
            config_path: self.config_path.display().to_string(),
            own_npub,
            own_pubkey_hex,
            node_id: self.config.node.id.clone(),
            node_name: self.config.node_name.clone(),
            endpoint: self.config.node.endpoint.clone(),
            tunnel_ip: self.config.node.tunnel_ip.clone(),
            listen_port: self.config.node.listen_port,
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
}

fn within_peer_online_grace(last_handshake_at: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(last_handshake_at) = last_handshake_at else {
        return false;
    };
    now.duration_since(last_handshake_at)
        .map(|elapsed| elapsed.as_secs() <= PEER_ONLINE_GRACE_SECS)
        .unwrap_or(false)
}

fn gui_requires_service_install(
    service_supported: bool,
    service_installed: bool,
    daemon_running: bool,
) -> bool {
    service_supported && !service_installed && !daemon_running
}

fn should_start_gui_daemon_on_launch(
    autoconnect: bool,
    has_participants: bool,
    service_setup_required: bool,
) -> bool {
    autoconnect && has_participants && !service_setup_required
}

fn gui_service_setup_status_text(autoconnect: bool) -> &'static str {
    if autoconnect {
        GUI_SERVICE_SETUP_REQUIRED_AUTOCONNECT_STATUS
    } else {
        GUI_SERVICE_SETUP_REQUIRED_STATUS
    }
}

impl Drop for NvpnBackend {
    fn drop(&mut self) {
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

fn is_mesh_complete(connected: usize, expected: usize) -> bool {
    expected > 0 && connected >= expected
}

fn peer_state_label(state: ConfiguredPeerStatus) -> &'static str {
    match state {
        ConfiguredPeerStatus::Local => "local",
        ConfiguredPeerStatus::Online => "online",
        ConfiguredPeerStatus::Offline => "offline",
        ConfiguredPeerStatus::Unknown => "unknown",
    }
}

fn default_config_path() -> PathBuf {
    if let Some(mut path) = dirs::config_dir() {
        path.push("nvpn");
        path.push("config.toml");
        return path;
    }

    PathBuf::from("nvpn.toml")
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

fn hide_main_window_to_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };

    let _ = window.minimize();
    let _ = window.hide();
}

fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    let Some(window) = app.get_webview_window("main") else {
        return Ok(());
    };

    let _ = window.unminimize();
    window.show()?;
    window.set_focus()?;
    Ok(())
}

fn tray_vpn_toggle_label(session_active: bool, service_setup_required: bool) -> &'static str {
    if service_setup_required && !session_active {
        "Install Service"
    } else if session_active {
        "Turn VPN Off"
    } else {
        "Turn VPN On"
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TrayRuntimeState {
    session_active: bool,
    service_setup_required: bool,
}

fn current_tray_runtime_state<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> TrayRuntimeState {
    let Some(state) = app.try_state::<AppState>() else {
        return TrayRuntimeState {
            session_active: false,
            service_setup_required: false,
        };
    };
    let Ok(backend) = state.backend.lock() else {
        return TrayRuntimeState {
            session_active: false,
            service_setup_required: false,
        };
    };
    TrayRuntimeState {
        session_active: backend.session_active,
        service_setup_required: backend.gui_requires_service_install(),
    }
}

fn build_tray_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    runtime_state: TrayRuntimeState,
) -> tauri::Result<tauri::menu::Menu<R>> {
    let open_item = MenuItemBuilder::with_id(TRAY_OPEN_MENU_ID, "Open Nostr VPN").build(app)?;
    let vpn_toggle_item = MenuItemBuilder::with_id(
        TRAY_VPN_TOGGLE_MENU_ID,
        tray_vpn_toggle_label(
            runtime_state.session_active,
            runtime_state.service_setup_required,
        ),
    )
    .build(app)?;
    let quit_ui_item =
        MenuItemBuilder::with_id(TRAY_QUIT_UI_MENU_ID, "Quit Nostr VPN").build(app)?;

    MenuBuilder::new(app)
        .item(&open_item)
        .separator()
        .item(&vpn_toggle_item)
        .separator()
        .item(&quit_ui_item)
        .build()
}

fn refresh_tray_menu<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let Some(tray) = app.tray_by_id(TRAY_ICON_ID) else {
        return;
    };

    let runtime_state = current_tray_runtime_state(app);
    let Some(state) = app.try_state::<AppState>() else {
        if let Ok(menu) = build_tray_menu(app, runtime_state) {
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

    if let Ok(menu) = build_tray_menu(app, runtime_state) {
        if tray.set_menu(Some(menu)).is_ok() {
            *last_tray_runtime_state = runtime_state;
}

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
fn install_system_service(state: State<'_, AppState>) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.install_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn uninstall_system_service(state: State<'_, AppState>) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.uninstall_system_service()?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn add_network(state: State<'_, AppState>, name: String) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.add_network(&name)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn rename_network(
    state: State<'_, AppState>,
    network_id: String,
    name: String,
) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.rename_network(&network_id, &name)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn remove_network(state: State<'_, AppState>, network_id: String) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.remove_network(&network_id)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn set_network_enabled(
    state: State<'_, AppState>,
    network_id: String,
    enabled: bool,
) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.set_network_enabled(&network_id, enabled)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn add_participant(
    state: State<'_, AppState>,
    network_id: String,
    npub: String,
    alias: Option<String>,
) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.add_participant(&network_id, &npub, alias.as_deref())?;
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn remove_participant(
    state: State<'_, AppState>,
    network_id: String,
    npub: String,
) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.remove_participant(&network_id, &npub)?;
        Ok(backend.ui_state())
    })
}

#[tauri::command]
fn set_participant_alias(
    state: State<'_, AppState>,
    npub: String,
    alias: String,
) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.set_participant_alias(&npub, &alias)?;
        backend.tick();
        Ok(backend.ui_state())
    })
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
fn update_settings(state: State<'_, AppState>, patch: SettingsPatch) -> Result<UiState, String> {
    with_backend(state, |backend| {
        backend.update_settings(patch)?;
        backend.tick();
        Ok(backend.ui_state())
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let backend = NvpnBackend::new().expect("failed to initialize GUI backend state");
    let launch_on_startup_default = backend.config.launch_on_startup;
    let initial_tray_state = TrayRuntimeState {
        session_active: backend.session_active,
        service_setup_required: backend.gui_requires_service_install(),
    };
    let launched_from_autostart = started_from_autostart();
    let app = tauri::Builder::default()
        .setup(move |app| {
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

            let tray_menu = build_tray_menu(app.handle(), initial_tray_state)?;

            let mut tray_builder = TrayIconBuilder::with_id(TRAY_ICON_ID)
                .tooltip("Nostr VPN")
                .menu(&tray_menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    TRAY_OPEN_MENU_ID => {
                        let _ = show_main_window(app);
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
                            } else {
                                backend
                                    .connect_session()
                                    .context("failed to resume VPN session")?;
                            }
                            Ok(())
                        });
                        refresh_tray_menu(app);
                    }
                    TRAY_QUIT_UI_MENU_ID => {
                        app.exit(0);
                    }
                    _ => {}
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
            {
                if let Ok(icon) = Image::from_bytes(include_bytes!("../icons/tray-template.png")) {
                    tray_builder = tray_builder.icon(icon).icon_as_template(true);
                } else {
                    eprintln!("tray: failed to load bundled template icon");
                }
            }

            tray_builder.build(app)?;

            if launched_from_autostart {
                hide_main_window_to_tray(app.handle());
            }

            Ok(())
        })
        .manage(AppState {
            backend: Mutex::new(backend),
            last_tray_runtime_state: Mutex::new(initial_tray_state),
        })
        .invoke_handler(tauri::generate_handler![
            tick,
            connect_session,
            disconnect_session,
            install_cli,
            uninstall_cli,
            install_system_service,
            uninstall_system_service,
            add_network,
            rename_network,
            remove_network,
            set_network_enabled,
            add_participant,
            remove_participant,
            set_participant_alias,
            add_relay,
            remove_relay,
            update_settings,
        ])
        .on_window_event(|window, event| {
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
        cli_binary_installed_at, expected_peer_count, extract_json_document,
        gui_requires_service_install, is_already_running_message, is_mesh_complete,
        is_not_running_message, should_start_gui_daemon_on_launch, started_from_autostart_args,
        to_npub, validate_nvpn_binary, within_peer_online_grace,
    };
    use nostr_vpn_core::config::AppConfig;
    use std::time::{Duration, SystemTime};

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
    fn peer_online_grace_keeps_recent_handshake_online() {
        let now = SystemTime::now();
        assert!(within_peer_online_grace(
            Some(now - Duration::from_secs(5)),
            now
        ));
        assert!(!within_peer_online_grace(
            Some(now - Duration::from_secs(25)),
            now
        ));
        assert!(!within_peer_online_grace(None, now));
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
    fn gui_requires_service_install_only_when_no_service_and_no_daemon() {
        assert!(gui_requires_service_install(true, false, false));
        assert!(!gui_requires_service_install(true, false, true));
        assert!(!gui_requires_service_install(true, true, false));
        assert!(!gui_requires_service_install(false, false, false));
    }

    #[test]
    fn gui_launch_autoconnect_skips_direct_start_until_service_exists() {
        assert!(!should_start_gui_daemon_on_launch(true, true, true));
        assert!(should_start_gui_daemon_on_launch(true, true, false));
        assert!(!should_start_gui_daemon_on_launch(true, false, false));
        assert!(!should_start_gui_daemon_on_launch(false, true, false));
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
}
