use std::collections::HashMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::{
    AppConfig, NetworkConfig, PendingInboundJoinRequest, PendingOutboundJoinRequest,
    derive_mesh_tunnel_ip, maybe_autoconfigure_node, normalize_advertised_route,
    normalize_nostr_pubkey, normalize_relay_urls, normalize_runtime_network_id,
    parse_wireguard_exit_config, wireguard_exit_config_text,
};
use nostr_vpn_core::diagnostics::ProbeStatus;
use nostr_vpn_core::process_ext::CommandWindowExt;
use serde::Deserialize;

use crate::actions::NativeAppAction;
use crate::invite::{
    NETWORK_INVITE_VERSION, NetworkInvite, active_network_invite_code,
    apply_network_invite_to_active_network, parse_network_invite, preferred_join_request_recipient,
    to_npub,
};
use crate::lan_pairing::{
    LAN_PAIRING_DURATION, LAN_PAIRING_STALE_AFTER, LanPairingAnnouncement, LanPairingSignal,
};
#[cfg(not(test))]
use crate::lan_pairing::{LanPairingWorker, spawn_lan_pairing_worker};
use crate::native_state::{
    NativeAppState, NativeHealthIssue, NativeInboundJoinRequestState, NativeLanPeerState,
    NativeNetworkState, NativeNetworkSummary, NativeOutboundJoinRequestState,
    NativeParticipantState, NativePortMappingStatus, NativeProbeStatus, NativeRelayState,
};
use crate::platform::current_runtime_capabilities;
use crate::state::{
    DaemonPeerState, DaemonRuntimeState, HealthIssue, NetworkSummary, PortMappingStatus,
    SettingsPatch,
};

const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const EXTERNAL_DAEMON_ENV: &str = "NVPN_EXTERNAL_DAEMON";
const SERVICE_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MOBILE_RUNTIME_STATE_FILE: &str = "mobile-runtime-state.json";
const MOBILE_RUNTIME_STATE_STALE_SECS: u64 = 10;

/// Output of running a privileged command from foreign code.
///
/// `cancelled = true` means the user dismissed the elevation dialog (e.g.
/// hit Cancel on the Touch ID / password prompt). Surfaced separately so
/// the UI can avoid showing it as a hard error.
#[derive(uniffi::Record, Debug, Default)]
pub struct PrivilegedCommandOutput {
    pub success: bool,
    pub cancelled: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Foreign-implemented runner for executing the bundled `nvpn` CLI as root.
///
/// The Mac shell implements this with Authorization Services so the
/// elevation prompt can use Touch ID. When no runner is registered, the
/// Rust core falls back to spawning `osascript ... with administrator
/// privileges` (password-only).
#[uniffi::export(with_foreign)]
pub trait PrivilegedCommandRunner: Send + Sync {
    fn run(&self, executable: String, args: Vec<String>) -> PrivilegedCommandOutput;
}

#[derive(uniffi::Object, Debug)]
pub struct FfiApp {
    runtime: Mutex<NativeAppRuntime>,
}

#[uniffi::export]
impl FfiApp {
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn new(data_dir: String, app_version: String) -> Arc<Self> {
        let runtime = NativeAppRuntime::new(&data_dir, app_version)
            .unwrap_or_else(|error| NativeAppRuntime::from_startup_error(&error));
        Arc::new(Self {
            runtime: Mutex::new(runtime),
        })
    }

    #[must_use]
    pub fn state(&self) -> NativeAppState {
        self.with_runtime(|runtime| runtime.state())
    }

    #[must_use]
    pub fn refresh(&self) -> NativeAppState {
        self.dispatch(NativeAppAction::Tick)
    }

    #[must_use]
    pub fn dispatch(&self, action: NativeAppAction) -> NativeAppState {
        self.with_runtime(|runtime| {
            runtime.dispatch(action);
            runtime.state()
        })
    }

    pub fn set_privileged_command_runner(&self, runner: Arc<dyn PrivilegedCommandRunner>) {
        self.with_runtime(|runtime| {
            runtime.privileged_command_runner = Some(PrivilegedCommandRunnerHandle(runner));
            runtime.state()
        });
    }
}

impl FfiApp {
    #[must_use]
    pub fn new_with_config_path(
        config_path: PathBuf,
        app_version: String,
        nvpn_bin: Option<PathBuf>,
    ) -> Arc<Self> {
        let runtime = NativeAppRuntime::new_with_config_path(config_path, app_version, nvpn_bin)
            .unwrap_or_else(|error| NativeAppRuntime::from_startup_error(&error));
        Arc::new(Self {
            runtime: Mutex::new(runtime),
        })
    }
}

impl FfiApp {
    fn with_runtime(
        &self,
        f: impl FnOnce(&mut NativeAppRuntime) -> NativeAppState,
    ) -> NativeAppState {
        match self.runtime.lock() {
            Ok(mut runtime) => f(&mut runtime),
            Err(poisoned) => {
                let mut runtime = poisoned.into_inner();
                runtime.set_error("native app state lock was poisoned");
                f(&mut runtime)
            }
        }
    }
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct NativeAppRuntime {
    rev: u64,
    app_version: String,
    config_path: PathBuf,
    config: AppConfig,
    nvpn_bin: Option<PathBuf>,
    mobile_runtime: bool,
    startup_error: Option<String>,
    last_error: String,
    daemon_running: bool,
    vpn_enabled: bool,
    vpn_active: bool,
    vpn_status: String,
    daemon_state: Option<DaemonRuntimeState>,
    service_supported: bool,
    service_enablement_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    service_running: bool,
    service_status_detail: String,
    service_binary_version: String,
    expected_service_binary_version: String,
    last_service_status_refresh_at: Option<Instant>,
    lan_pairing_worker: Option<NativeLanPairingWorker>,
    invite_broadcast_expires_at: Option<SystemTime>,
    nearby_discovery_expires_at: Option<SystemTime>,
    lan_peers: HashMap<String, LanPeerRecord>,
    privileged_command_runner: Option<PrivilegedCommandRunnerHandle>,
}

#[derive(Clone)]
struct PrivilegedCommandRunnerHandle(
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))] Arc<dyn PrivilegedCommandRunner>,
);

impl std::fmt::Debug for PrivilegedCommandRunnerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivilegedCommandRunnerHandle(<foreign>)")
    }
}

#[derive(Debug, Clone)]
struct LanPeerRecord {
    signal: LanPairingSignal,
    last_seen: SystemTime,
}

#[cfg(not(test))]
#[derive(Debug)]
struct NativeLanPairingWorker(LanPairingWorker);

#[cfg(test)]
#[derive(Debug)]
struct NativeLanPairingWorker;

#[cfg_attr(test, allow(clippy::unnecessary_wraps, clippy::unused_self))]
impl NativeLanPairingWorker {
    #[cfg(not(test))]
    fn spawn(announcement: LanPairingAnnouncement) -> Result<Self> {
        Ok(Self(spawn_lan_pairing_worker(announcement)?))
    }

    #[cfg(test)]
    fn spawn(_announcement: LanPairingAnnouncement) -> Result<Self> {
        Ok(Self)
    }

    #[cfg(not(test))]
    fn drain(&mut self) -> Vec<LanPairingSignal> {
        self.0.drain()
    }

    #[cfg(test)]
    fn drain(&mut self) -> Vec<LanPairingSignal> {
        Vec::new()
    }

    #[cfg(not(test))]
    fn set_broadcast_until(&self, expires_at: SystemTime) {
        self.0.set_broadcast_until(expires_at);
    }

    #[cfg(test)]
    fn set_broadcast_until(&self, _expires_at: SystemTime) {}

    #[cfg(not(test))]
    fn set_listen_until(&self, expires_at: SystemTime) {
        self.0.set_listen_until(expires_at);
    }

    #[cfg(test)]
    fn set_listen_until(&self, _expires_at: SystemTime) {}

    #[cfg(not(test))]
    fn clear_broadcast(&self) {
        self.0.clear_broadcast();
    }

    #[cfg(test)]
    fn clear_broadcast(&self) {}

    #[cfg(not(test))]
    fn clear_listen(&self) {
        self.0.clear_listen();
    }

    #[cfg(test)]
    fn clear_listen(&self) {}

    #[cfg(not(test))]
    fn update_announcement(&self, announcement: LanPairingAnnouncement) {
        self.0.update_announcement(announcement);
    }

    #[cfg(test)]
    fn update_announcement(&self, _announcement: LanPairingAnnouncement) {}

    #[cfg(not(test))]
    fn stop(&mut self) {
        self.0.stop();
    }

    #[cfg(test)]
    fn stop(&mut self) {}
}

#[derive(Debug, Deserialize)]
struct CliStatusResponse {
    daemon: CliDaemonStatus,
}

#[derive(Debug, Deserialize)]
struct CliDaemonStatus {
    running: bool,
    state: Option<DaemonRuntimeState>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(clippy::struct_excessive_bools)]
struct CliServiceStatusResponse {
    supported: bool,
    installed: bool,
    #[serde(default)]
    disabled: bool,
    loaded: bool,
    running: bool,
    pid: Option<u32>,
    #[serde(default)]
    label: String,
    #[serde(default)]
    plist_path: String,
    #[serde(default)]
    binary_version: String,
}

#[derive(Debug, Clone, Default)]
struct ExitNodeUiStatus {
    active: bool,
    blocked: bool,
    text: String,
}

impl NativeAppRuntime {
    fn new(data_dir: &str, app_version: String) -> Result<Self> {
        let config_path = native_config_path(data_dir);
        Self::new_with_config_path(config_path, app_version, None)
    }

    fn new_with_config_path(
        config_path: PathBuf,
        app_version: String,
        nvpn_bin: Option<PathBuf>,
    ) -> Result<Self> {
        let config_exists = config_path
            .try_exists()
            .with_context(|| format!("failed to inspect config {}", config_path.display()))?;
        let persist_identity_defaults = config_exists
            && config_file_missing_persisted_identity(&config_path).with_context(|| {
                format!(
                    "failed to inspect persisted identity in {}",
                    config_path.display()
                )
            })?;
        let mut config = if config_exists {
            AppConfig::load(&config_path)?
        } else {
            AppConfig::generated_without_networks()
        };
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        if !config_exists || persist_identity_defaults {
            config.save(&config_path)?;
        }

        let capabilities = current_runtime_capabilities();
        let mut runtime = Self {
            rev: 0,
            app_version,
            config_path,
            config,
            nvpn_bin: nvpn_bin.or_else(|| resolve_nvpn_cli_path().ok()),
            mobile_runtime: capabilities.mobile,
            startup_error: None,
            last_error: String::new(),
            daemon_running: false,
            vpn_enabled: false,
            vpn_active: false,
            vpn_status: "Disconnected".to_string(),
            daemon_state: None,
            service_supported: !capabilities.mobile && desktop_service_supported(),
            service_enablement_supported: !capabilities.mobile && desktop_service_supported(),
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: String::new(),
            service_binary_version: String::new(),
            expected_service_binary_version: String::new(),
            last_service_status_refresh_at: None,
            lan_pairing_worker: None,
            invite_broadcast_expires_at: None,
            nearby_discovery_expires_at: None,
            lan_peers: HashMap::new(),
            privileged_command_runner: None,
        };
        runtime.refresh_expected_service_binary_version();
        if runtime.mobile_runtime {
            let _ = runtime.refresh_mobile_status();
        } else {
            let _ = runtime.refresh_status();
        }
        Ok(runtime)
    }

    fn from_startup_error(error: &anyhow::Error) -> Self {
        let error = error.to_string();
        #[cfg(not(test))]
        let config = AppConfig::generated_without_networks();
        #[cfg(test)]
        let mut config = AppConfig::generated_without_networks();
        #[cfg(test)]
        {
            config.node.endpoint = "198.51.100.10:51820".to_string();
        }
        Self {
            rev: 0,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            config_path: default_config_path(),
            config,
            nvpn_bin: resolve_nvpn_cli_path().ok(),
            mobile_runtime: current_runtime_capabilities().mobile,
            startup_error: Some(error.clone()),
            last_error: error,
            daemon_running: false,
            vpn_enabled: false,
            vpn_active: false,
            vpn_status: "Startup failed".to_string(),
            daemon_state: None,
            service_supported: desktop_service_supported(),
            service_enablement_supported: desktop_service_supported(),
            service_installed: false,
            service_disabled: false,
            service_running: false,
            service_status_detail: "Service status unavailable during startup failure".to_string(),
            service_binary_version: String::new(),
            expected_service_binary_version: String::new(),
            last_service_status_refresh_at: None,
            lan_pairing_worker: None,
            invite_broadcast_expires_at: None,
            nearby_discovery_expires_at: None,
            lan_peers: HashMap::new(),
            privileged_command_runner: None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn state(&self) -> NativeAppState {
        let capabilities = current_runtime_capabilities();
        let config_unavailable = self.startup_error.is_some();
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().unwrap_or_default();
        let active_network = self.config.active_network_opt();
        let network_setup_required =
            !config_unavailable && network_setup_required_for_config(&self.config);
        let daemon_state = self.daemon_state.as_ref();
        let vpn_enabled = self
            .daemon_state
            .as_ref()
            .map_or(self.vpn_enabled, |state| state.vpn_enabled);
        let vpn_active = self
            .daemon_state
            .as_ref()
            .map_or(self.vpn_active, |state| state.vpn_active);
        let expected_peer_count = if network_setup_required {
            0
        } else {
            daemon_state.map_or_else(
                || {
                    active_network.map_or(0, |network| {
                        remote_network_participant_count(network, &own_pubkey_hex)
                    })
                },
                |state| state.expected_peer_count,
            )
        };
        let connected_peer_count = if vpn_active && !network_setup_required {
            daemon_state.map_or(0, |state| state.connected_peer_count)
        } else {
            0
        };
        let endpoint = daemon_state
            .and_then(|state| non_empty(&state.advertised_endpoint))
            .unwrap_or_else(|| self.config.node.endpoint.clone());
        let listen_port = daemon_state
            .and_then(|state| (state.listen_port > 0).then_some(state.listen_port))
            .unwrap_or(self.config.node.listen_port);
        let health = daemon_state
            .map(|state| native_health_issues(&state.health))
            .unwrap_or_default();
        let network = daemon_state
            .map(|state| native_network_summary(&state.network))
            .unwrap_or_default();
        let port_mapping = daemon_state
            .map(|state| native_port_mapping_status(&state.port_mapping))
            .unwrap_or_default();
        let exit_node_status = if network_setup_required {
            ExitNodeUiStatus::default()
        } else {
            active_network
                .map(|network| {
                    self.exit_node_ui_status(vpn_enabled, vpn_active, daemon_state, network)
                })
                .unwrap_or_default()
        };

        NativeAppState {
            rev: self.rev,
            platform: capabilities.platform,
            mobile: capabilities.mobile,
            vpn_control_supported: capabilities.vpn_control_supported,
            cli_install_supported: capabilities.cli_install_supported,
            startup_settings_supported: capabilities.startup_settings_supported,
            tray_behavior_supported: capabilities.tray_behavior_supported,
            runtime_status_detail: capabilities.runtime_status_detail,
            app_version: if self.app_version.is_empty() {
                env!("CARGO_PKG_VERSION").to_string()
            } else {
                self.app_version.clone()
            },
            config_path: self.config_path.display().to_string(),
            error: self
                .startup_error
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| self.last_error.clone()),
            cli_installed: capabilities.cli_install_supported && cli_binary_installed(),
            service_supported: self.service_supported,
            service_enablement_supported: self.service_enablement_supported,
            service_installed: self.service_installed,
            service_disabled: self.service_disabled,
            service_running: self.service_running,
            service_status_detail: self.service_status_detail.clone(),
            daemon_running: self.daemon_running,
            vpn_enabled,
            vpn_active,
            vpn_status: self.vpn_status.clone(),
            daemon_binary_version: daemon_state
                .map(|state| state.binary_version.clone())
                .unwrap_or_default(),
            service_binary_version: self.service_binary_version.clone(),
            expected_service_binary_version: self.expected_service_binary_version.clone(),
            own_npub: if config_unavailable {
                String::new()
            } else {
                to_npub(&own_pubkey_hex)
            },
            own_pubkey_hex: if config_unavailable {
                String::new()
            } else {
                own_pubkey_hex.clone()
            },
            node_id: if config_unavailable {
                String::new()
            } else {
                self.config.node.id.clone()
            },
            node_name: if config_unavailable {
                String::new()
            } else {
                self.config.node_name.clone()
            },
            self_magic_dns_name: if config_unavailable {
                String::new()
            } else {
                self.config.self_magic_dns_name().unwrap_or_default()
            },
            endpoint: if config_unavailable {
                String::new()
            } else {
                endpoint
            },
            tunnel_ip: if config_unavailable {
                String::new()
            } else {
                self.config.node.tunnel_ip.clone()
            },
            listen_port: if config_unavailable {
                0
            } else {
                u32::from(listen_port)
            },
            relays: if config_unavailable {
                Vec::new()
            } else {
                self.relay_views()
            },
            network_id: if config_unavailable || network_setup_required {
                String::new()
            } else {
                self.config.effective_network_id()
            },
            active_network_invite: if config_unavailable || network_setup_required {
                String::new()
            } else {
                active_network_invite_code(&self.config).unwrap_or_default()
            },
            exit_node: if self.config.exit_node.trim().is_empty() {
                String::new()
            } else {
                to_npub(&self.config.exit_node)
            },
            exit_node_leak_protection: self.config.exit_node_leak_protection,
            exit_node_active: exit_node_status.active,
            exit_node_blocked: exit_node_status.blocked,
            exit_node_status_text: exit_node_status.text,
            advertise_exit_node: !config_unavailable && self.config.node.advertise_exit_node,
            advertised_routes: if config_unavailable {
                Vec::new()
            } else {
                self.config.node.advertised_routes.clone()
            },
            effective_advertised_routes: if config_unavailable {
                Vec::new()
            } else {
                self.config.effective_advertised_routes()
            },
            wireguard_exit_enabled: !config_unavailable && self.config.wireguard_exit.enabled,
            wireguard_exit_configured: !config_unavailable
                && self.config.wireguard_exit.configured(),
            wireguard_exit_interface: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.interface.clone()
            },
            wireguard_exit_address: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.address.clone()
            },
            wireguard_exit_private_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.private_key.clone()
            },
            wireguard_exit_peer_public_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.peer_public_key.clone()
            },
            wireguard_exit_peer_preshared_key: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.peer_preshared_key.clone()
            },
            wireguard_exit_endpoint: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.endpoint.clone()
            },
            wireguard_exit_allowed_ips: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.allowed_ips.join(", ")
            },
            wireguard_exit_dns: if config_unavailable {
                String::new()
            } else {
                self.config.wireguard_exit.dns.join(", ")
            },
            wireguard_exit_mtu: if config_unavailable {
                0
            } else {
                self.config.wireguard_exit.mtu
            },
            wireguard_exit_persistent_keepalive_secs: if config_unavailable {
                0
            } else {
                self.config.wireguard_exit.persistent_keepalive_secs
            },
            wireguard_exit_config: if config_unavailable {
                String::new()
            } else {
                wireguard_exit_config_text(&self.config.wireguard_exit)
            },
            magic_dns_suffix: if config_unavailable {
                String::new()
            } else {
                self.config.magic_dns_suffix.clone()
            },
            magic_dns_status: if config_unavailable {
                String::new()
            } else {
                self.magic_dns_status()
            },
            autoconnect: !config_unavailable && self.config.autoconnect,
            invite_broadcast_active: self.invite_broadcast_active(),
            invite_broadcast_remaining_secs: self.invite_broadcast_remaining_secs(),
            nearby_discovery_active: self.nearby_discovery_active(),
            nearby_discovery_remaining_secs: self.nearby_discovery_remaining_secs(),
            launch_on_startup: !config_unavailable && self.config.launch_on_startup,
            close_to_tray_on_close: !config_unavailable && self.config.close_to_tray_on_close,
            connected_peer_count: connected_peer_count as u64,
            expected_peer_count: expected_peer_count as u64,
            mesh_ready: !network_setup_required
                && vpn_active
                && daemon_state.is_some_and(|state| state.mesh_ready),
            health,
            network,
            port_mapping,
            networks: if config_unavailable {
                Vec::new()
            } else {
                self.network_states(&own_pubkey_hex, vpn_active)
            },
            lan_peers: self.lan_peer_states(),
        }
    }

    fn dispatch(&mut self, action: NativeAppAction) {
        let result = self.apply_action(action);
        match result {
            Ok(()) => self.last_error.clear(),
            Err(error) => self.set_error(error.to_string()),
        }
        self.rev = self.rev.saturating_add(1);
    }

    #[allow(clippy::too_many_lines)]
    fn apply_action(&mut self, action: NativeAppAction) -> Result<()> {
        if self.startup_error.is_some() {
            match &action {
                NativeAppAction::GetState => return Ok(()),
                NativeAppAction::InstallCli
                | NativeAppAction::UninstallCli
                | NativeAppAction::InstallSystemService => {}
                _ => self.recover_from_startup_error().with_context(
                    || "cannot modify VPN config until the config file is readable",
                )?,
            }
        }

        match action {
            NativeAppAction::GetState | NativeAppAction::Tick => {
                if self.mobile_runtime {
                    self.refresh_mobile_status()
                } else {
                    self.refresh_status()
                }
            }
            NativeAppAction::ConnectVpn => self.connect_vpn(),
            NativeAppAction::DisconnectVpn => self.disconnect_vpn(),
            NativeAppAction::InstallCli => {
                let output = self.run_nvpn(["install-cli", "--force"])?;
                ensure_success("nvpn install-cli", &output)
            }
            NativeAppAction::UninstallCli => {
                let output = self.run_nvpn(["uninstall-cli"])?;
                ensure_success("nvpn uninstall-cli", &output)
            }
            NativeAppAction::InstallSystemService => {
                // Preserve "VPN was on" across the service swap: --force tears
                // down the old daemon and starts a fresh one, which by default
                // comes up disconnected. Without restoring, the user sees the
                // VPN switch flip to OFF every time they update the service —
                // doubly bad after an in-app update where they didn't ask to
                // disconnect.
                let was_vpn_on = self.vpn_enabled || self.vpn_active;
                let output = self.run_nvpn_service_action([
                    "service",
                    "install",
                    "--force",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service install", &output)?;
                self.invalidate_service_status();
                self.recover_from_startup_error()?;
                self.refresh_service_status()?;
                // Refresh the daemon state after the service swap before
                // deciding whether to reconnect. Otherwise stale pre-bootout
                // `vpn_active` can make us skip the restore and the next UI
                // tick flips the VPN switch off.
                let _ = self.refresh_status();
                if was_vpn_on && !(self.vpn_enabled || self.vpn_active) {
                    // Best-effort: ignore connect_vpn errors so a transient
                    // race (new daemon not quite ready yet) doesn't surface
                    // as a "service install failed" message — the install
                    // itself succeeded.
                    let _ = self.connect_vpn();
                }
                Ok(())
            }
            NativeAppAction::UninstallSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "uninstall",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service uninstall", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()
            }
            NativeAppAction::EnableSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "enable",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service enable", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()
            }
            NativeAppAction::DisableSystemService => {
                let output = self.run_nvpn_service_action([
                    "service",
                    "disable",
                    "--config",
                    self.config_path_str()?,
                ])?;
                ensure_success("nvpn service disable", &output)?;
                self.invalidate_service_status();
                self.refresh_service_status()
            }
            NativeAppAction::AddNetwork { name } => {
                self.config.add_owned_network(&name);
                self.save_reload_and_refresh()
            }
            NativeAppAction::RenameNetwork { network_id, name } => {
                self.config.rename_network(&network_id, &name)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::RemoveNetwork { network_id } => {
                self.config.remove_network(&network_id)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkMeshId {
                network_id,
                mesh_id,
            } => {
                self.config.set_network_mesh_id(&network_id, &mesh_id)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkEnabled {
                network_id,
                enabled,
            } => {
                self.config.set_network_enabled(&network_id, enabled)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetNetworkJoinRequestsEnabled {
                network_id,
                enabled,
            } => {
                self.config
                    .set_network_join_requests_enabled(&network_id, enabled)?;
                self.save_reload_refresh_and_maybe_connect_for_join_requests(enabled)
            }
            NativeAppAction::RequestNetworkJoin { network_id } => {
                self.request_network_join(&network_id)
            }
            NativeAppAction::StartInviteBroadcast => self.start_invite_broadcast(),
            NativeAppAction::StopInviteBroadcast => {
                self.stop_invite_broadcast();
                Ok(())
            }
            NativeAppAction::StartNearbyDiscovery => self.start_nearby_discovery(),
            NativeAppAction::StopNearbyDiscovery => {
                self.stop_nearby_discovery();
                Ok(())
            }
            NativeAppAction::AddParticipant {
                network_id,
                npub,
                alias,
            } => {
                let normalized = self.config.add_participant_to_network(&network_id, &npub)?;
                if let Some(alias) = alias
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    self.config.set_peer_alias(&normalized, alias)?;
                }
                self.save_reload_and_refresh()
            }
            NativeAppAction::AddAdmin { network_id, npub } => {
                self.config.add_admin_to_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::ImportNetworkInvite { invite } => {
                self.import_network_invite(&invite)?;
                if !self.vpn_enabled {
                    self.connect_vpn()?;
                }
                Ok(())
            }
            NativeAppAction::ManualAddNetwork {
                admin_npub,
                mesh_network_id,
            } => {
                self.manual_add_network(&admin_npub, &mesh_network_id)?;
                if !self.vpn_enabled {
                    self.connect_vpn()?;
                }
                Ok(())
            }
            NativeAppAction::RemoveParticipant { network_id, npub } => {
                self.config
                    .remove_participant_from_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::RemoveAdmin { network_id, npub } => {
                self.config.remove_admin_from_network(&network_id, &npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::AcceptJoinRequest {
                network_id,
                requester_npub,
            } => self.accept_join_request(&network_id, &requester_npub),
            NativeAppAction::RejectJoinRequest {
                network_id,
                requester_npub,
            } => {
                self.config
                    .reject_inbound_join_request(&network_id, &requester_npub)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::SetParticipantAlias { npub, alias } => {
                self.config.set_peer_alias(&npub, &alias)?;
                self.save_reload_and_refresh()
            }
            NativeAppAction::UpdateSettings { patch } => {
                self.apply_settings_patch(patch)?;
                self.save_reload_and_refresh()
            }
        }
    }

    fn import_network_invite(&mut self, invite: &str) -> Result<()> {
        let parsed = parse_network_invite(invite)?;
        apply_network_invite_to_active_network(&mut self.config, &parsed)?;
        let network_id = self
            .config
            .active_network_opt()
            .ok_or_else(|| anyhow!("network not found"))?
            .id
            .clone();
        self.queue_network_join_request(&network_id)?;
        self.save_reload_and_refresh()
    }

    fn manual_add_network(&mut self, admin_npub: &str, mesh_network_id: &str) -> Result<()> {
        let admin = admin_npub.trim();
        let mesh_id = mesh_network_id.trim();
        if admin.is_empty() {
            return Err(anyhow!("admin device id is empty"));
        }
        if mesh_id.is_empty() {
            return Err(anyhow!("network id is empty"));
        }
        let synthetic = NetworkInvite {
            v: NETWORK_INVITE_VERSION,
            network_name: String::new(),
            network_id: mesh_id.to_string(),
            inviter_npub: admin.to_string(),
            inviter_node_name: String::new(),
            inviter_endpoints: Vec::new(),
            admins: vec![admin.to_string()],
            participants: Vec::new(),
            relays: Vec::new(),
            relay_record: None,
        };
        let encoded = serde_json::to_string(&synthetic)
            .map_err(|err| anyhow!("failed to encode manual invite: {err}"))?;
        let parsed = parse_network_invite(&encoded)?;
        apply_network_invite_to_active_network(&mut self.config, &parsed)?;
        self.save_reload_and_refresh()
    }

    fn request_network_join(&mut self, network_id: &str) -> Result<()> {
        self.queue_network_join_request(network_id)?;
        self.save_reload_and_refresh()?;
        if !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

    fn queue_network_join_request(&mut self, network_id: &str) -> Result<bool> {
        let network = self
            .config
            .network_by_id(network_id)
            .ok_or_else(|| anyhow!("network not found"))?
            .clone();
        if self.network_contains_own_identity(&network) {
            return Ok(false);
        }
        let recipient = preferred_join_request_recipient(&network)
            .ok_or_else(|| anyhow!("this network was not imported from an invite"))?;
        if network
            .outbound_join_request
            .as_ref()
            .is_some_and(|existing| existing.recipient == recipient)
        {
            return Ok(false);
        }

        let _ = self.config.ensure_temporary_self_magic_dns_alias();
        let network = self
            .config
            .network_by_id_mut(network_id)
            .ok_or_else(|| anyhow!("network not found"))?;
        network.outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient,
            requested_at: unix_timestamp(),
        });
        Ok(true)
    }

    fn network_contains_own_identity(&self, network: &NetworkConfig) -> bool {
        let Some(own_pubkey) = self.config.own_nostr_pubkey_hex().ok() else {
            return false;
        };
        network
            .participants
            .iter()
            .chain(network.admins.iter())
            .any(|member| member == &own_pubkey)
    }

    fn accept_join_request(&mut self, network_id: &str, requester_npub: &str) -> Result<()> {
        let requester = normalize_nostr_pubkey(requester_npub)?;
        let requester_node_name = self
            .config
            .network_by_id(network_id)
            .and_then(|network| {
                network
                    .inbound_join_requests
                    .iter()
                    .find(|pending| pending.requester == requester)
                    .map(|pending| pending.requester_node_name.clone())
            })
            .unwrap_or_default();

        self.config
            .add_participant_to_network(network_id, &requester)?;
        if !requester_node_name.trim().is_empty() {
            let _ = self.config.set_peer_alias(&requester, &requester_node_name);
        }
        if let Some(network) = self.config.network_by_id_mut(network_id) {
            network
                .inbound_join_requests
                .retain(|pending| pending.requester != requester);
        }
        self.save_reload_and_refresh()?;
        if !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

    fn start_invite_broadcast(&mut self) -> Result<()> {
        if network_setup_required_for_config(&self.config) {
            return Err(anyhow!("Create or join a network first"));
        }
        self.ensure_active_network_accepts_join_requests()?;
        self.refresh_lan_pairing();
        let announcement = self.build_lan_pairing_announcement()?;
        let expires_at = lan_pairing_deadline();
        self.ensure_lan_pairing_worker(announcement.clone())?;
        if let Some(worker) = self.lan_pairing_worker.as_ref() {
            worker.update_announcement(announcement);
            worker.set_broadcast_until(expires_at);
        }
        self.invite_broadcast_expires_at = Some(expires_at);
        Ok(())
    }

    fn ensure_active_network_accepts_join_requests(&mut self) -> Result<()> {
        let Some(network) = self.config.active_network_opt() else {
            return Ok(());
        };
        let enabled = network.listen_for_join_requests;
        let network_id = network.id.clone();
        if !enabled {
            self.config
                .set_network_join_requests_enabled(&network_id, true)?;
        }
        self.save_reload_refresh_and_maybe_connect_for_join_requests(true)
    }

    fn stop_invite_broadcast(&mut self) {
        if let Some(worker) = self.lan_pairing_worker.as_ref() {
            worker.clear_broadcast();
        }
        self.invite_broadcast_expires_at = None;
        self.gc_lan_pairing_worker();
    }

    fn start_nearby_discovery(&mut self) -> Result<()> {
        self.refresh_lan_pairing();
        let announcement = self.build_lan_pairing_announcement()?;
        let expires_at = lan_pairing_deadline();
        self.ensure_lan_pairing_worker(announcement)?;
        if let Some(worker) = self.lan_pairing_worker.as_ref() {
            worker.set_listen_until(expires_at);
        }
        self.nearby_discovery_expires_at = Some(expires_at);
        self.lan_peers.clear();
        Ok(())
    }

    fn stop_nearby_discovery(&mut self) {
        if let Some(worker) = self.lan_pairing_worker.as_ref() {
            worker.clear_listen();
        }
        self.nearby_discovery_expires_at = None;
        self.lan_peers.clear();
        self.gc_lan_pairing_worker();
    }

    fn ensure_lan_pairing_worker(&mut self, announcement: LanPairingAnnouncement) -> Result<()> {
        if self.lan_pairing_worker.is_some() {
            return Ok(());
        }
        let worker = NativeLanPairingWorker::spawn(announcement)?;
        self.lan_pairing_worker = Some(worker);
        Ok(())
    }

    fn gc_lan_pairing_worker(&mut self) {
        if self.invite_broadcast_expires_at.is_none()
            && self.nearby_discovery_expires_at.is_none()
            && let Some(mut worker) = self.lan_pairing_worker.take()
        {
            worker.stop();
        }
    }

    fn build_lan_pairing_announcement(&self) -> Result<LanPairingAnnouncement> {
        let own_npub = to_npub(&self.config.own_nostr_pubkey_hex()?);
        let invite = active_network_invite_code(&self.config).unwrap_or_default();
        let endpoint = self
            .daemon_state
            .as_ref()
            .and_then(|state| non_empty(&state.advertised_endpoint))
            .unwrap_or_else(|| self.config.node.endpoint.clone());
        Ok(LanPairingAnnouncement {
            npub: own_npub,
            node_name: self.config.node_name.clone(),
            endpoint,
            invite,
        })
    }

    fn refresh_lan_pairing(&mut self) {
        let now = SystemTime::now();
        if self
            .invite_broadcast_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            self.invite_broadcast_expires_at = None;
            if let Some(worker) = self.lan_pairing_worker.as_ref() {
                worker.clear_broadcast();
            }
        }
        if self
            .nearby_discovery_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            self.nearby_discovery_expires_at = None;
            if let Some(worker) = self.lan_pairing_worker.as_ref() {
                worker.clear_listen();
            }
            self.lan_peers.clear();
        }
        self.gc_lan_pairing_worker();

        let Some(worker) = &mut self.lan_pairing_worker else {
            return;
        };
        if self.nearby_discovery_expires_at.is_none() {
            // Drain + drop — listen stopped, don't surface stale signals.
            let _ = worker.drain();
            return;
        }
        let signals = worker.drain();
        for signal in signals {
            if self.lan_signal_is_existing_peer(&signal) {
                continue;
            }
            let key = format!("{}:{}", signal.network_id, signal.npub);
            self.lan_peers.insert(
                key,
                LanPeerRecord {
                    signal,
                    last_seen: now,
                },
            );
        }
    }

    fn invite_broadcast_active(&self) -> bool {
        self.lan_pairing_worker.is_some() && self.invite_broadcast_remaining_secs() > 0
    }

    fn invite_broadcast_remaining_secs(&self) -> u64 {
        Self::remaining_secs(self.invite_broadcast_expires_at)
    }

    fn nearby_discovery_active(&self) -> bool {
        self.lan_pairing_worker.is_some() && self.nearby_discovery_remaining_secs() > 0
    }

    fn nearby_discovery_remaining_secs(&self) -> u64 {
        Self::remaining_secs(self.nearby_discovery_expires_at)
    }

    fn remaining_secs(expires_at: Option<SystemTime>) -> u64 {
        expires_at
            .and_then(|expires| expires.duration_since(SystemTime::now()).ok())
            .map_or(0, |remaining| remaining.as_secs())
    }

    fn lan_peer_states(&self) -> Vec<NativeLanPeerState> {
        let mut peers = self
            .lan_peers
            .values()
            .filter(|record| {
                record
                    .last_seen
                    .elapsed()
                    .is_ok_and(|age| age <= LAN_PAIRING_STALE_AFTER)
            })
            .map(|record| NativeLanPeerState {
                npub: record.signal.npub.clone(),
                node_name: record.signal.node_name.clone(),
                endpoint: record.signal.endpoint.clone(),
                network_name: record.signal.network_name.clone(),
                network_id: record.signal.network_id.clone(),
                invite: record.signal.invite.clone(),
                last_seen_text: record.last_seen.elapsed().map_or_else(
                    |_| "just now".to_string(),
                    |age| compact_age_text(age.as_secs()),
                ),
            })
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| {
            left.network_name
                .cmp(&right.network_name)
                .then_with(|| left.node_name.cmp(&right.node_name))
                .then_with(|| left.npub.cmp(&right.npub))
        });
        peers
    }

    fn lan_signal_is_existing_peer(&self, signal: &LanPairingSignal) -> bool {
        let Ok(sender_hex) = normalize_nostr_pubkey(&signal.npub) else {
            return false;
        };
        let signal_network_id = normalize_runtime_network_id(&signal.network_id);
        self.config.networks.iter().any(|network| {
            normalize_runtime_network_id(&network.network_id) == signal_network_id
                && (network.admins.iter().any(|admin| admin == &sender_hex)
                    || network
                        .participants
                        .iter()
                        .any(|participant| participant == &sender_hex))
        })
    }

    fn apply_settings_patch(&mut self, patch: SettingsPatch) -> Result<()> {
        if let Some(value) = patch.node_name {
            self.config.node_name = value.trim().to_string();
        }
        if let Some(value) = patch.endpoint {
            self.config.node.endpoint = value.trim().to_string();
        }
        if let Some(value) = patch.tunnel_ip {
            self.config.node.tunnel_ip = value.trim().to_string();
        }
        if let Some(value) = patch.listen_port {
            self.config.node.listen_port = value;
        }
        self.apply_relay_settings_patch(patch.relays, patch.disabled_relays);
        // Exit-node selection is mutually exclusive: at most one of
        // (peer exit_node, WireGuard upstream) can be active at a
        // time. The daemon enforces this so every UI / CLI client
        // can push a single field and get the right end state —
        // they don't have to remember to clear the other side. When
        // both fields are in the same patch, both are applied as
        // sent (so the patch fully specifies the intent).
        let exit_node_in_patch = patch.exit_node.is_some();
        let wg_enabled_in_patch = patch.wireguard_exit_enabled.is_some();
        if let Some(value) = patch.exit_node {
            self.config.exit_node = if value.trim().is_empty() {
                String::new()
            } else {
                normalize_nostr_pubkey(&value)?
            };
        }
        if let Some(value) = patch.exit_node_leak_protection {
            self.config.exit_node_leak_protection = value;
        }
        if let Some(value) = patch.advertise_exit_node {
            self.config.node.advertise_exit_node = value;
        }
        if let Some(value) = patch.advertised_routes {
            self.config.node.advertised_routes = parse_advertised_routes(&value);
        }
        if let Some(value) = patch.wireguard_exit_enabled {
            self.config.wireguard_exit.enabled = value;
        }
        // Mutual-exclusion guard. After both fields have landed,
        // resolve any conflict by preferring the field the patch
        // *explicitly* set. If both are set explicitly, the patch
        // already declared the full intent — trust it. If only one
        // is in the patch, clear the other side when the new value
        // would otherwise leave both "selected".
        let peer_set = !self.config.exit_node.is_empty();
        let wg_on = self.config.wireguard_exit.enabled;
        if peer_set && wg_on {
            if exit_node_in_patch && !wg_enabled_in_patch {
                self.config.wireguard_exit.enabled = false;
            } else if wg_enabled_in_patch && !exit_node_in_patch {
                self.config.exit_node = String::new();
            }
            // both-in-patch: leave as the caller sent — caller will
            // typically have set them consistently (one true, other
            // empty), so this branch is dead in practice.
        }
        if let Some(value) = patch.wireguard_exit_interface {
            self.config.wireguard_exit.interface = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_address {
            self.config.wireguard_exit.address = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_private_key {
            self.config.wireguard_exit.private_key = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_peer_public_key {
            self.config.wireguard_exit.peer_public_key = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_peer_preshared_key {
            self.config.wireguard_exit.peer_preshared_key = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_endpoint {
            self.config.wireguard_exit.endpoint = value.trim().to_string();
        }
        if let Some(value) = patch.wireguard_exit_allowed_ips {
            self.config.wireguard_exit.allowed_ips = parse_advertised_routes(&value);
        }
        if let Some(value) = patch.wireguard_exit_dns {
            self.config.wireguard_exit.dns = parse_csv_values(&value);
        }
        if let Some(value) = patch.wireguard_exit_mtu {
            self.config.wireguard_exit.mtu = value;
        }
        if let Some(value) = patch.wireguard_exit_persistent_keepalive_secs {
            self.config.wireguard_exit.persistent_keepalive_secs = value;
        }
        if let Some(value) = patch.wireguard_exit_config {
            let enabled = self.config.wireguard_exit.enabled;
            let mut parsed = parse_wireguard_exit_config(&value)?;
            parsed.enabled = enabled;
            self.config.wireguard_exit = parsed;
        }
        if let Some(value) = patch.magic_dns_suffix {
            self.config.magic_dns_suffix = value.trim().trim_matches('.').to_ascii_lowercase();
        }
        if let Some(value) = patch.autoconnect {
            self.config.autoconnect = value;
        }
        if let Some(value) = patch.launch_on_startup {
            self.config.launch_on_startup = value;
        }
        if let Some(value) = patch.close_to_tray_on_close {
            self.config.close_to_tray_on_close = value;
        }
        Ok(())
    }

    fn apply_relay_settings_patch(
        &mut self,
        relays: Option<Vec<String>>,
        disabled_relays: Option<Vec<String>>,
    ) {
        if let Some(value) = relays {
            self.config.nostr.relays = normalize_relay_urls(value);
            let enabled_relays = self
                .config
                .nostr
                .relays
                .iter()
                .cloned()
                .collect::<std::collections::HashSet<_>>();
            self.config
                .nostr
                .disabled_relays
                .retain(|relay| !enabled_relays.contains(relay));
        }
        if let Some(value) = disabled_relays {
            self.config.nostr.disabled_relays = normalize_relay_urls(value);
            let disabled_relays = self
                .config
                .nostr
                .disabled_relays
                .iter()
                .cloned()
                .collect::<std::collections::HashSet<_>>();
            self.config
                .nostr
                .relays
                .retain(|relay| !disabled_relays.contains(relay));
        }
    }

    fn connect_vpn(&mut self) -> Result<()> {
        if network_setup_required_for_config(&self.config) {
            self.vpn_enabled = false;
            self.vpn_active = false;
            self.vpn_status = "Create or join a network first".to_string();
            return Err(anyhow!(self.vpn_status.clone()));
        }
        self.vpn_enabled = true;
        if self.mobile_runtime {
            self.vpn_enabled = true;
            self.vpn_active = true;
            self.daemon_running = true;
            self.vpn_status = "VPN on".to_string();
            return self.refresh_mobile_status();
        }
        let _ = self.refresh_status();
        if self.daemon_running {
            let output = self.run_nvpn(["resume", "--config", self.config_path_str()?])?;
            ensure_success("nvpn resume", &output)?;
            return self.refresh_status();
        }
        if external_daemon_mode() {
            self.vpn_enabled = false;
            self.vpn_active = false;
            self.vpn_status = "VPN service starting".to_string();
            return Err(anyhow!(self.vpn_status.clone()));
        }
        #[cfg(target_os = "macos")]
        {
            self.refresh_service_status_if_due();
            if !self.service_running {
                self.vpn_enabled = false;
                self.vpn_active = false;
                self.vpn_status = if self.service_installed {
                    "Start background service first".to_string()
                } else {
                    "Install background service first".to_string()
                };
                return Err(anyhow!(self.vpn_status.clone()));
            }
        }
        let output = self.run_nvpn([
            "start",
            "--daemon",
            "--connect",
            "--config",
            self.config_path_str()?,
        ])?;
        ensure_success("nvpn start", &output)?;
        self.refresh_status()
    }

    fn disconnect_vpn(&mut self) -> Result<()> {
        self.vpn_enabled = false;
        if self.mobile_runtime {
            self.vpn_enabled = false;
            self.vpn_active = false;
            self.daemon_running = false;
            self.vpn_status = "Disconnected".to_string();
            self.clear_mobile_runtime_state();
            return self.refresh_mobile_status();
        }
        let output = self.run_nvpn(["pause", "--config", self.config_path_str()?])?;
        ensure_success("nvpn pause", &output)?;
        self.refresh_status()
    }

    fn refresh_mobile_status(&mut self) -> Result<()> {
        self.reload_config_from_disk()?;
        self.refresh_lan_pairing();
        self.daemon_state = None;
        self.service_supported = false;
        self.service_enablement_supported = false;
        self.service_installed = false;
        self.service_disabled = false;
        self.service_running = false;
        self.service_binary_version.clear();
        self.service_status_detail = "Background service unsupported on mobile".to_string();
        let mobile_state = self.load_mobile_runtime_state();
        if self.vpn_enabled || mobile_state.is_some() {
            self.daemon_running = true;
            self.vpn_active = true;
            if self.vpn_status.trim().is_empty()
                || self.vpn_status == "CLI unavailable"
                || self.vpn_status.starts_with("nvpn CLI binary not found")
            {
                self.vpn_status = "VPN on".to_string();
            }
            if let Some(state) = mobile_state {
                self.daemon_state = Some(state.clone());
                self.daemon_running = state.vpn_enabled;
                self.vpn_enabled = state.vpn_enabled;
                self.vpn_active = state.vpn_active;
                self.vpn_status = state.vpn_status;
            }
        } else {
            self.daemon_running = false;
            self.vpn_active = false;
            self.vpn_status = "Disconnected".to_string();
        }
        Ok(())
    }

    fn load_mobile_runtime_state(&self) -> Option<DaemonRuntimeState> {
        let path = self.mobile_runtime_state_path()?;
        let raw = fs::read_to_string(path).ok()?;
        let state = serde_json::from_str::<DaemonRuntimeState>(&raw).ok()?;
        if age_secs_since(state.updated_at) > MOBILE_RUNTIME_STATE_STALE_SECS {
            return None;
        }
        Some(state)
    }

    fn clear_mobile_runtime_state(&self) {
        if let Some(path) = self.mobile_runtime_state_path() {
            let _ = fs::remove_file(path);
        }
    }

    fn mobile_runtime_state_path(&self) -> Option<PathBuf> {
        self.config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| parent.join(MOBILE_RUNTIME_STATE_FILE))
    }

    fn refresh_status(&mut self) -> Result<()> {
        self.reload_config_from_disk()?;
        self.refresh_service_status_if_due();
        self.refresh_lan_pairing();
        let output = self.run_nvpn([
            "status",
            "--json",
            "--discover-secs",
            "0",
            "--config",
            self.config_path_str()?,
        ]);

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let json_text = extract_json_document(&stdout)?;
                let parsed = serde_json::from_str::<CliStatusResponse>(json_text)
                    .context("failed to parse `nvpn status --json` output")?;
                self.daemon_state = parsed.daemon.state;
                self.daemon_running = parsed.daemon.running;
                self.vpn_enabled = self
                    .daemon_state
                    .as_ref()
                    .map_or(parsed.daemon.running, |state| state.vpn_enabled);
                self.vpn_active = self
                    .daemon_state
                    .as_ref()
                    .map_or(parsed.daemon.running, |state| state.vpn_active);
                self.vpn_status = self.daemon_state.as_ref().map_or_else(
                    || {
                        if parsed.daemon.running {
                            "Daemon running".to_string()
                        } else {
                            "Disconnected".to_string()
                        }
                    },
                    |state| state.vpn_status.clone(),
                );
                Ok(())
            }
            Ok(output) => {
                self.daemon_state = None;
                self.daemon_running = false;
                self.vpn_enabled = false;
                self.vpn_active = false;
                self.vpn_status = "Daemon status unavailable".to_string();
                Err(command_failure("nvpn status", &output))
            }
            Err(error) => {
                self.daemon_state = None;
                self.daemon_running = false;
                self.vpn_enabled = false;
                self.vpn_active = false;
                self.vpn_status = "CLI unavailable".to_string();
                Err(error)
            }
        }
    }

    fn save_reload_and_refresh(&mut self) -> Result<()> {
        self.save_config()?;
        if self.mobile_runtime {
            self.refresh_mobile_status()
        } else {
            if self.daemon_running {
                let output = self.run_nvpn(["reload", "--config", self.config_path_str()?])?;
                ensure_success("nvpn reload", &output)?;
            }
            self.refresh_status()
        }
    }

    fn relay_views(&self) -> Vec<NativeRelayState> {
        let active_relays = effective_config_relays(&self.config);
        let active_lookup = active_relays
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut live_status = HashMap::new();
        if let Some(daemon_state) = self.daemon_state.as_ref()
            && !daemon_state.relays.is_empty()
        {
            live_status.extend(
                daemon_state
                    .relays
                    .iter()
                    .map(|relay| (relay.url.clone(), relay.status.clone())),
            );
        }

        let mut rows = active_relays
            .iter()
            .map(|url| NativeRelayState {
                url: url.clone(),
                status: live_status
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                enabled: true,
            })
            .collect::<Vec<_>>();

        rows.extend(
            normalize_relay_urls(self.config.nostr.disabled_relays.clone())
                .into_iter()
                .filter(|url| !active_lookup.contains(url))
                .map(|url| NativeRelayState {
                    url,
                    status: "disabled".to_string(),
                    enabled: false,
                }),
        );
        rows
    }

    fn save_reload_refresh_and_maybe_connect_for_join_requests(
        &mut self,
        enabled: bool,
    ) -> Result<()> {
        self.save_reload_and_refresh()?;
        if enabled && !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

    fn save_config(&mut self) -> Result<()> {
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        self.config.save(&self.config_path)
    }

    fn reload_config_from_disk(&mut self) -> Result<()> {
        if !self
            .config_path
            .try_exists()
            .with_context(|| format!("failed to inspect config {}", self.config_path.display()))?
        {
            return Err(anyhow!(
                "config file disappeared: {}",
                self.config_path.display()
            ));
        }

        self.config = AppConfig::load(&self.config_path)?;
        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);
        Ok(())
    }

    fn recover_from_startup_error(&mut self) -> Result<()> {
        if self.startup_error.is_none() {
            return Ok(());
        }

        let config_exists = self
            .config_path
            .try_exists()
            .with_context(|| format!("failed to inspect config {}", self.config_path.display()))?;
        let mut config = if config_exists {
            AppConfig::load(&self.config_path)?
        } else {
            AppConfig::generated_without_networks()
        };
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        if !config_exists {
            config.save(&self.config_path)?;
        }

        self.config = config;
        self.startup_error = None;
        self.last_error.clear();
        self.refresh_expected_service_binary_version();
        Ok(())
    }

    fn network_states(&self, own_pubkey_hex: &str, vpn_active: bool) -> Vec<NativeNetworkState> {
        self.config
            .networks
            .iter()
            .map(|network| self.network_state(network, own_pubkey_hex, vpn_active))
            .collect()
    }

    fn exit_node_ui_status(
        &self,
        vpn_enabled: bool,
        vpn_active: bool,
        daemon_state: Option<&DaemonRuntimeState>,
        active_network: &NetworkConfig,
    ) -> ExitNodeUiStatus {
        let selected_exit_node = self.config.exit_node.trim();
        if !selected_exit_node.is_empty() {
            let name = exit_node_display_name(&self.config, active_network, selected_exit_node);
            let selected_peer = daemon_state.and_then(|state| {
                state
                    .peers
                    .iter()
                    .find(|peer| peer.participant_pubkey == selected_exit_node)
            });
            let selected_exit_active = vpn_active
                && selected_peer.is_some_and(|peer| {
                    peer.reachable && peer_offers_exit_node(&peer.advertised_routes)
                });
            let blocked =
                self.config.exit_node_leak_protection && vpn_enabled && !selected_exit_active;
            let text = if blocked {
                format!("Internet blocked: waiting for {name}")
            } else if selected_exit_active {
                format!("Exit: {name}")
            } else {
                format!("Exit pending: {name}")
            };
            return ExitNodeUiStatus {
                active: selected_exit_active,
                blocked,
                text,
            };
        }

        let wireguard_exit_selected =
            self.config.node.advertise_exit_node && self.config.wireguard_exit.enabled;
        if wireguard_exit_selected {
            let wireguard_exit_active = vpn_active && self.config.wireguard_exit.configured();
            let blocked =
                self.config.exit_node_leak_protection && vpn_enabled && !wireguard_exit_active;
            let text = if blocked {
                "Internet blocked: waiting for WireGuard exit".to_string()
            } else if wireguard_exit_active {
                "Exit: WireGuard upstream".to_string()
            } else {
                "Exit pending: WireGuard upstream".to_string()
            };
            return ExitNodeUiStatus {
                active: wireguard_exit_active,
                blocked,
                text,
            };
        }

        ExitNodeUiStatus::default()
    }

    fn network_state(
        &self,
        network: &NetworkConfig,
        own_pubkey_hex: &str,
        vpn_active: bool,
    ) -> NativeNetworkState {
        let mut admins = network
            .admins
            .iter()
            .map(|admin| to_npub(admin))
            .collect::<Vec<_>>();
        admins.sort();
        admins.dedup();
        let mut participant_keys = network.participants.clone();
        participant_keys.extend(network.admins.iter().cloned());
        participant_keys.sort();
        participant_keys.dedup();
        if !own_pubkey_hex.is_empty()
            && !participant_keys.iter().any(|value| value == own_pubkey_hex)
        {
            participant_keys.push(own_pubkey_hex.to_string());
        }
        let participants = participant_keys
            .iter()
            .map(|participant| {
                self.participant_state(participant, network, own_pubkey_hex, vpn_active)
            })
            .collect::<Vec<_>>();
        let online_count = participants
            .iter()
            .filter(|participant| participant.reachable)
            .count() as u64;
        let expected_count = participants.len() as u64;

        NativeNetworkState {
            id: network.id.clone(),
            name: network.name.clone(),
            enabled: network.enabled,
            network_id: normalize_runtime_network_id(&network.network_id),
            local_is_admin: self.config.is_network_admin(&network.id, own_pubkey_hex),
            join_requests_enabled: network.listen_for_join_requests,
            invite_inviter_npub: if network.invite_inviter.is_empty() {
                String::new()
            } else {
                to_npub(&network.invite_inviter)
            },
            admin_npubs: admins.clone(),
            outbound_join_request: network
                .outbound_join_request
                .as_ref()
                .map(native_outbound_join_request),
            inbound_join_requests: network
                .inbound_join_requests
                .iter()
                .map(native_inbound_join_request)
                .collect(),
            online_count,
            expected_count,
            admins,
            participants,
        }
    }

    fn participant_state(
        &self,
        participant: &str,
        network: &NetworkConfig,
        own_pubkey_hex: &str,
        vpn_active: bool,
    ) -> NativeParticipantState {
        let daemon_peer = vpn_active.then_some(()).and_then(|()| {
            self.daemon_state.as_ref().and_then(|state| {
                state
                    .peers
                    .iter()
                    .find(|peer| peer.participant_pubkey == participant)
            })
        });
        let is_local = participant == own_pubkey_hex;
        let reachable = vpn_active && (is_local || daemon_peer.is_some_and(|peer| peer.reachable));
        let access_pending = Self::network_access_pending(network, own_pubkey_hex) && !is_local;
        let assigned_magic_dns_alias = self.config.peer_alias(participant).unwrap_or_default();
        let magic_dns_alias = if assigned_magic_dns_alias.is_empty() && is_local {
            self.config.self_magic_dns_label().unwrap_or_default()
        } else {
            assigned_magic_dns_alias
        };
        let assigned_magic_dns_name = self
            .config
            .magic_dns_name_for_participant(participant)
            .unwrap_or_default();
        let magic_dns_name = if assigned_magic_dns_name.is_empty() && is_local {
            self.config.self_magic_dns_name().unwrap_or_default()
        } else {
            assigned_magic_dns_name
        };
        let alias = non_empty(&magic_dns_alias).unwrap_or_else(|| short_pubkey(participant));
        let tunnel_ip = daemon_peer
            .map(|peer| peer.tunnel_ip.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                derive_mesh_tunnel_ip(&network.network_id, participant)
                    .unwrap_or_else(|| "-".to_string())
            });
        let advertised_routes = if is_local {
            self.config.effective_advertised_routes()
        } else {
            daemon_peer
                .map(|peer| peer.advertised_routes.clone())
                .unwrap_or_default()
        };
        let offers_exit_node = if is_local {
            self.config.node.advertise_exit_node
        } else {
            peer_offers_exit_node(&advertised_routes)
        };
        let peer_state = if access_pending {
            "pending".to_string()
        } else {
            self.peer_state_label(participant, daemon_peer, is_local, vpn_active)
        };
        let mesh_state = Self::peer_mesh_label(daemon_peer, is_local, vpn_active);
        let status_text = if access_pending {
            if network
                .outbound_join_request
                .as_ref()
                .is_some_and(|request| request.recipient == participant)
            {
                "join request sent".to_string()
            } else {
                "waiting for admin".to_string()
            }
        } else {
            Self::peer_status_text(daemon_peer, is_local, &peer_state)
        };

        NativeParticipantState {
            npub: to_npub(participant),
            pubkey_hex: participant.to_string(),
            alias,
            magic_dns_alias,
            magic_dns_name,
            tunnel_ip,
            is_admin: network.admins.iter().any(|admin| admin == participant),
            reachable,
            tx_bytes: daemon_peer.map_or(0, |peer| peer.tx_bytes),
            rx_bytes: daemon_peer.map_or(0, |peer| peer.rx_bytes),
            advertised_routes,
            offers_exit_node,
            fips_endpoint_npub: daemon_peer
                .map(|peer| peer.fips_endpoint_npub.clone())
                .unwrap_or_default(),
            fips_transport_addr: daemon_peer
                .map(|peer| peer.fips_transport_addr.clone())
                .unwrap_or_default(),
            fips_transport_type: daemon_peer
                .map(|peer| peer.fips_transport_type.clone())
                .unwrap_or_default(),
            fips_srtt_ms: daemon_peer.and_then(|peer| peer.fips_srtt_ms).unwrap_or(0),
            fips_packets_sent: daemon_peer.map_or(0, |peer| peer.fips_packets_sent),
            fips_packets_recv: daemon_peer.map_or(0, |peer| peer.fips_packets_recv),
            fips_bytes_sent: daemon_peer.map_or(0, |peer| peer.fips_bytes_sent),
            fips_bytes_recv: daemon_peer.map_or(0, |peer| peer.fips_bytes_recv),
            state: peer_state.clone(),
            mesh_state,
            status_text,
            last_seen_text: Self::peer_last_fips_seen_text(daemon_peer, is_local),
        }
    }

    fn network_access_pending(network: &NetworkConfig, own_pubkey_hex: &str) -> bool {
        if own_pubkey_hex.is_empty() || network.outbound_join_request.is_none() {
            return false;
        }
        !network
            .participants
            .iter()
            .chain(network.admins.iter())
            .any(|member| member == own_pubkey_hex)
    }

    fn refresh_service_status_if_due(&mut self) {
        if !desktop_service_supported() {
            self.service_supported = false;
            self.service_enablement_supported = false;
            self.service_installed = false;
            self.service_disabled = false;
            self.service_running = false;
            self.service_binary_version.clear();
            self.service_status_detail =
                "Background service unsupported on this platform".to_string();
            return;
        }

        let now = Instant::now();
        if self
            .last_service_status_refresh_at
            .is_some_and(|last| now.duration_since(last) < SERVICE_STATUS_REFRESH_INTERVAL)
        {
            return;
        }

        if let Err(error) = self.refresh_service_status() {
            self.service_supported = true;
            self.service_enablement_supported = true;
            self.service_installed = false;
            self.service_disabled = false;
            self.service_running = false;
            self.service_binary_version.clear();
            self.service_status_detail = format!("Service status unavailable: {error}");
        }
    }

    fn refresh_service_status(&mut self) -> Result<()> {
        self.last_service_status_refresh_at = Some(Instant::now());
        let output = self.run_nvpn([
            "service",
            "status",
            "--json",
            "--config",
            self.config_path_str()?,
        ])?;
        if !output.status.success() {
            return Err(command_failure("nvpn service status", &output));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_text = extract_json_document(&stdout)?;
        let status = serde_json::from_str::<CliServiceStatusResponse>(json_text)
            .context("failed to parse `nvpn service status --json` output")?;
        self.service_supported = status.supported;
        self.service_enablement_supported = status.supported;
        self.service_installed = status.installed;
        self.service_disabled = status.disabled;
        self.service_running = status.running;
        self.service_binary_version
            .clone_from(&status.binary_version);
        self.service_status_detail = service_status_detail(&status);
        Ok(())
    }

    fn invalidate_service_status(&mut self) {
        self.last_service_status_refresh_at = None;
    }

    /// Cache the version of the bundled `nvpn` CLI — i.e. the version that
    /// `service install --force` would deploy. Compared against the installed
    /// daemon binary version to decide whether a service update is needed.
    fn refresh_expected_service_binary_version(&mut self) {
        #[derive(Deserialize)]
        struct VersionView {
            version: String,
        }
        let Some(nvpn_bin) = self.nvpn_bin.as_deref() else {
            self.expected_service_binary_version.clear();
            return;
        };
        let Ok(output) = Command::new(nvpn_bin)
            .args(["version", "--json"])
            .hide_console_window()
            .output()
        else {
            return;
        };
        if !output.status.success() {
            return;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(info) = serde_json::from_str::<VersionView>(stdout.trim()) {
            let trimmed = info.version.trim();
            if !trimmed.is_empty() {
                self.expected_service_binary_version = trimmed.to_string();
            }
        }
    }

    fn magic_dns_status(&self) -> String {
        if self.config.magic_dns_suffix.trim().is_empty() {
            return "DNS disabled".to_string();
        }
        if self.vpn_active {
            format!("Serving .{} names", self.config.magic_dns_suffix)
        } else {
            "DNS disabled (VPN off)".to_string()
        }
    }

    fn peer_state_label(
        &self,
        participant: &str,
        peer: Option<&DaemonPeerState>,
        is_local: bool,
        vpn_active: bool,
    ) -> String {
        if !vpn_active {
            return "off".to_string();
        }
        if is_local {
            return "local".to_string();
        }
        if peer.is_some_and(|peer| peer.reachable) {
            return "online".to_string();
        }
        if peer
            .and_then(peer_last_fips_seen_secs)
            .is_some_and(within_presence_grace)
        {
            return "pending".to_string();
        }
        if peer.is_some() {
            return "offline".to_string();
        }
        if self
            .config
            .all_participant_pubkeys_hex()
            .iter()
            .any(|configured| configured == participant)
        {
            return "unknown".to_string();
        }
        "unknown".to_string()
    }

    fn peer_mesh_label(peer: Option<&DaemonPeerState>, is_local: bool, vpn_active: bool) -> String {
        if !vpn_active {
            return "off".to_string();
        }
        if is_local {
            return "local".to_string();
        }
        if peer.is_some_and(|peer| peer.reachable)
            || peer
                .and_then(peer_last_fips_seen_secs)
                .is_some_and(within_presence_grace)
        {
            return "present".to_string();
        }
        if peer.is_some() {
            return "absent".to_string();
        }
        "unknown".to_string()
    }

    fn peer_status_text(peer: Option<&DaemonPeerState>, is_local: bool, state: &str) -> String {
        if is_local {
            return "local".to_string();
        }
        match state {
            "online" => peer.map_or_else(
                || "online".to_string(),
                |peer| {
                    if let Some(link) = peer_link_text(peer) {
                        format!("online via {link}")
                    } else if let Some(seen) = peer.last_handshake_at {
                        format!("online (seen {})", compact_age_text(age_secs_since(seen)))
                    } else {
                        "online".to_string()
                    }
                },
            ),
            "pending" => peer
                .and_then(|peer| {
                    peer_link_text(peer).or_else(|| {
                        non_empty(peer.runtime_endpoint.as_deref().unwrap_or(&peer.endpoint))
                    })
                })
                .map_or_else(
                    || "fips link pending".to_string(),
                    |endpoint| format!("fips pending via {}", shorten_middle(&endpoint, 18, 10)),
                ),
            "offline" => peer.and_then(peer_last_fips_seen_secs).map_or_else(
                || "offline".to_string(),
                |seen| format!("offline ({})", compact_age_text(age_secs_since(seen))),
            ),
            _ => "unknown".to_string(),
        }
    }

    fn peer_last_fips_seen_text(peer: Option<&DaemonPeerState>, is_local: bool) -> String {
        if is_local {
            return "this device".to_string();
        }
        peer.and_then(peer_last_fips_seen_secs)
            .map_or_else(String::new, |seen| {
                format!("seen {}", compact_age_text(age_secs_since(seen)))
            })
    }

    fn config_path_str(&self) -> Result<&str> {
        self.config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))
    }

    fn run_nvpn<const N: usize>(&self, args: [&str; N]) -> Result<Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {NVPN_BIN_ENV} or install nvpn"
            ));
        };
        Command::new(nvpn_bin)
            .args(args)
            .hide_console_window()
            .output()
            .with_context(|| format!("failed to execute {}", nvpn_bin.display()))
    }

    fn run_nvpn_service_action<const N: usize>(&self, args: [&str; N]) -> Result<Output> {
        #[cfg(target_os = "macos")]
        {
            self.run_nvpn_service_action_with_macos_admin(args)
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.run_nvpn(args)
        }
    }

    #[cfg(target_os = "macos")]
    fn run_nvpn_service_action_with_macos_admin<const N: usize>(
        &self,
        args: [&str; N],
    ) -> Result<Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {NVPN_BIN_ENV} or install nvpn"
            ));
        };
        if let Some(handle) = &self.privileged_command_runner {
            let outcome = handle.0.run(
                nvpn_bin.display().to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            );
            if outcome.cancelled {
                return Err(anyhow!("user cancelled the administrator prompt"));
            }
            return Ok(privileged_outcome_to_output(outcome));
        }
        let shell_command = macos_service_action_shell_command(nvpn_bin, &args);
        let script = format!(
            "do shell script {} with administrator privileges",
            applescript_quote(&shell_command)
        );
        Command::new("osascript")
            .arg("-e")
            .arg(script)
            .output()
            .context("failed to request administrator privileges")
    }

    fn set_error(&mut self, error: impl Into<String>) {
        let error = error.into();
        self.last_error.clone_from(&error);
        if !error.trim().is_empty() {
            self.vpn_status = error;
        }
    }
}

impl Drop for NativeAppRuntime {
    fn drop(&mut self) {
        self.stop_invite_broadcast();
        self.stop_nearby_discovery();
    }
}

fn native_outbound_join_request(
    request: &PendingOutboundJoinRequest,
) -> NativeOutboundJoinRequestState {
    NativeOutboundJoinRequestState {
        recipient_npub: to_npub(&request.recipient),
        recipient_pubkey_hex: request.recipient.clone(),
        requested_at_text: join_request_age_text(request.requested_at),
    }
}

fn native_inbound_join_request(
    request: &PendingInboundJoinRequest,
) -> NativeInboundJoinRequestState {
    NativeInboundJoinRequestState {
        requester_npub: to_npub(&request.requester),
        requester_pubkey_hex: request.requester.clone(),
        requester_node_name: request.requester_node_name.clone(),
        requested_at_text: join_request_age_text(request.requested_at),
    }
}

fn remote_network_participant_count(network: &NetworkConfig, own_pubkey_hex: &str) -> usize {
    let mut participants = network.participants.clone();
    participants.extend(network.admins.iter().cloned());
    participants.sort();
    participants.dedup();
    participants
        .iter()
        .filter(|participant| participant.as_str() != own_pubkey_hex)
        .count()
}

fn network_setup_required_for_config(config: &AppConfig) -> bool {
    config.active_network_opt().is_none()
}

fn native_health_issues(issues: &[HealthIssue]) -> Vec<NativeHealthIssue> {
    issues
        .iter()
        .map(|issue| NativeHealthIssue {
            code: issue.code.clone(),
            severity: format!("{:?}", issue.severity).to_ascii_lowercase(),
            summary: issue.summary.clone(),
            detail: issue.detail.clone(),
        })
        .collect()
}

fn native_network_summary(summary: &NetworkSummary) -> NativeNetworkSummary {
    NativeNetworkSummary {
        default_interface: summary.default_interface.clone().unwrap_or_default(),
        primary_ipv4: summary.primary_ipv4.clone().unwrap_or_default(),
        primary_ipv6: summary.primary_ipv6.clone().unwrap_or_default(),
        gateway_ipv4: summary.gateway_ipv4.clone().unwrap_or_default(),
        gateway_ipv6: summary.gateway_ipv6.clone().unwrap_or_default(),
        changed_at: summary.changed_at.unwrap_or_default(),
        captive_portal: summary
            .captive_portal
            .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
    }
}

fn native_probe_status(status: &ProbeStatus) -> NativeProbeStatus {
    NativeProbeStatus {
        state: format!("{:?}", status.state).to_ascii_lowercase(),
        detail: status.detail.clone(),
    }
}

fn native_port_mapping_status(status: &PortMappingStatus) -> NativePortMappingStatus {
    NativePortMappingStatus {
        upnp: native_probe_status(&status.upnp),
        nat_pmp: native_probe_status(&status.nat_pmp),
        pcp: native_probe_status(&status.pcp),
        active_protocol: status.active_protocol.clone().unwrap_or_default(),
        external_endpoint: status.external_endpoint.clone().unwrap_or_default(),
        gateway: status.gateway.clone().unwrap_or_default(),
        good_until: status.good_until.unwrap_or_default(),
    }
}

fn service_status_detail(status: &CliServiceStatusResponse) -> String {
    if !status.supported {
        return "Background service unsupported on this platform".to_string();
    }
    if !status.installed {
        return "Background service is not installed".to_string();
    }
    if status.disabled {
        return "Background service is installed but disabled in launchd".to_string();
    }
    if status.running {
        let label = status
            .label
            .trim()
            .strip_prefix("to.iris.")
            .unwrap_or_else(|| status.label.trim());
        let label_suffix = if label.is_empty() {
            String::new()
        } else {
            format!(" ({label})")
        };
        return status.pid.map_or_else(
            || format!("Background service running{label_suffix}"),
            |pid| format!("Background service running{label_suffix}, pid {pid}"),
        );
    }
    if status.loaded {
        return "Background service installed but not running".to_string();
    }
    if !status.plist_path.trim().is_empty() {
        return format!(
            "Background service installed but launch status is unavailable: {}",
            status.plist_path
        );
    }
    "Background service installed but launch status is unavailable".to_string()
}

fn desktop_service_supported() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))
}

fn cli_binary_installed() -> bool {
    resolve_nvpn_cli_path().is_ok()
}

fn external_daemon_mode() -> bool {
    env::var(EXTERNAL_DAEMON_ENV).is_ok_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes")
    })
}

fn peer_offers_exit_node(routes: &[String]) -> bool {
    routes
        .iter()
        .any(|route| route == "0.0.0.0/0" || route == "::/0")
}

fn lan_pairing_deadline() -> SystemTime {
    SystemTime::now()
        .checked_add(LAN_PAIRING_DURATION)
        .unwrap_or_else(SystemTime::now)
}

fn peer_last_fips_seen_secs(peer: &DaemonPeerState) -> Option<u64> {
    peer.last_fips_seen_at
        .or_else(|| (peer.last_mesh_seen_at > 0).then_some(peer.last_mesh_seen_at))
}

fn within_presence_grace(seen_at: u64) -> bool {
    age_secs_since(seen_at) <= 90
}

fn age_secs_since(epoch_secs: u64) -> u64 {
    unix_timestamp().saturating_sub(epoch_secs)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn join_request_age_text(requested_at: u64) -> String {
    if requested_at == 0 {
        return "just now".to_string();
    }
    compact_age_text(age_secs_since(requested_at))
}

fn compact_age_text(age_secs: u64) -> String {
    match age_secs {
        0..=59 => format!("{age_secs}s ago"),
        60..=3_599 => format!("{}m ago", age_secs / 60),
        3_600..=86_399 => format!("{}h ago", age_secs / 3_600),
        86_400..=604_799 => format!("{}d ago", age_secs / 86_400),
        604_800..=2_591_999 => format!("{}w ago", age_secs / 604_800),
        2_592_000..=31_535_999 => format!("{}mo ago", age_secs / 2_592_000),
        _ => format!("{}y ago", age_secs / 31_536_000),
    }
}

fn shorten_middle(value: &str, prefix: usize, suffix: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= prefix + suffix + 1 {
        return value.to_string();
    }
    let start = chars.iter().take(prefix).collect::<String>();
    let end = chars
        .iter()
        .skip(chars.len().saturating_sub(suffix))
        .collect::<String>();
    format!("{start}...{end}")
}

fn peer_link_text(peer: &DaemonPeerState) -> Option<String> {
    if let Some(addr) = non_empty(&peer.fips_transport_addr) {
        let transport = non_empty(&peer.fips_transport_type).unwrap_or_else(|| "fips".to_string());
        let mut text = format!("{transport} {}", shorten_middle(&addr, 22, 10));
        if let Some(srtt_ms) = peer.fips_srtt_ms.filter(|value| *value > 0) {
            let _ = write!(text, " ({srtt_ms} ms)");
        }
        return Some(text);
    }

    let is_fips_peer = !peer.fips_endpoint_npub.trim().is_empty()
        || peer.endpoint.trim().eq_ignore_ascii_case("fips")
        || peer
            .runtime_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.trim().eq_ignore_ascii_case("fips"));
    let recently_seen =
        peer.reachable || peer_last_fips_seen_secs(peer).is_some_and(within_presence_grace);
    if is_fips_peer && recently_seen {
        let mut text = "mesh".to_string();
        if let Some(srtt_ms) = peer.fips_srtt_ms.filter(|value| *value > 0) {
            let _ = write!(text, " ({srtt_ms} ms)");
        }
        return Some(text);
    }

    None
}

fn native_config_path(data_dir: &str) -> PathBuf {
    let trimmed = data_dir.trim();
    if trimmed.is_empty() {
        default_config_path()
    } else {
        PathBuf::from(trimmed).join("config.toml")
    }
}

fn config_file_missing_persisted_identity(path: &Path) -> Result<bool> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw).context("failed to parse config TOML")?;
    let Some(nostr) = value.get("nostr").and_then(toml::Value::as_table) else {
        return Ok(true);
    };

    let secret_key = nostr
        .get("secret_key")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .trim();
    let public_key = nostr
        .get("public_key")
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .trim();

    Ok(secret_key.is_empty() || public_key.is_empty())
}

fn default_config_path() -> PathBuf {
    dirs::config_dir().map_or_else(
        || PathBuf::from("nvpn.toml"),
        |dir| dir.join("nvpn").join("config.toml"),
    )
}

fn resolve_nvpn_cli_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os(NVPN_BIN_ENV) {
        return validate_nvpn_binary(&PathBuf::from(path));
    }
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        for candidate in bundled_nvpn_candidate_paths(dir) {
            if let Ok(validated) = validate_nvpn_binary(&candidate) {
                return Ok(validated);
            }
        }
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            if let Ok(validated) = validate_nvpn_binary(&dir.join(nvpn_binary_name())) {
                return Ok(validated);
            }
        }
    }
    Err(anyhow!("nvpn CLI binary not found"))
}

fn bundled_nvpn_candidate_paths(exe_dir: &Path) -> Vec<PathBuf> {
    let name = nvpn_binary_name();
    let mut paths = vec![exe_dir.join(name)];
    paths.push(exe_dir.join("binaries").join(name));
    if let Some(contents_dir) = exe_dir.parent() {
        paths.push(contents_dir.join("Resources").join("binaries").join(name));
        paths.push(contents_dir.join("Resources").join(name));
    }
    paths
}

fn nvpn_binary_name() -> &'static str {
    if cfg!(windows) { "nvpn.exe" } else { "nvpn" }
}

fn validate_nvpn_binary(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect {}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", canonical.display()));
    }
    Ok(canonical)
}

fn ensure_success(command_name: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure(command_name, output))
    }
}

fn command_failure(command_name: &str, output: &Output) -> anyhow::Error {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow!(
        "{command_name} failed\nstdout: {}\nstderr: {}",
        stdout.trim(),
        stderr.trim()
    )
}

fn extract_json_document(output: &str) -> Result<&str> {
    let start = output
        .find('{')
        .ok_or_else(|| anyhow!("command output did not contain JSON"))?;
    let end = output
        .rfind('}')
        .ok_or_else(|| anyhow!("command output did not contain complete JSON"))?;
    Ok(&output[start..=end])
}

fn parse_advertised_routes(input: &str) -> Vec<String> {
    let mut routes = input
        .split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(normalize_advertised_route)
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    routes
}

fn parse_csv_values(input: &str) -> Vec<String> {
    let mut values = input
        .split([',', '\n', ' ', '\t'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn effective_config_relays(config: &AppConfig) -> Vec<String> {
    let disabled_relays = normalize_relay_urls(config.nostr.disabled_relays.clone())
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let fips = fips_endpoint::NostrDiscoveryConfig::default();
    let mut relays = if config.nostr.relays.is_empty() {
        normalize_relay_urls(
            fips.advert_relays
                .into_iter()
                .chain(fips.dm_relays)
                .collect(),
        )
    } else {
        normalize_relay_urls(config.nostr.relays.clone())
    };
    relays.retain(|relay| !disabled_relays.contains(relay));
    relays
}

fn short_pubkey(pubkey_hex: &str) -> String {
    if pubkey_hex.len() <= 12 {
        pubkey_hex.to_string()
    } else {
        format!(
            "{}...{}",
            &pubkey_hex[..8],
            &pubkey_hex[pubkey_hex.len() - 4..]
        )
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn exit_node_display_name(
    config: &AppConfig,
    active_network: &NetworkConfig,
    pubkey_hex: &str,
) -> String {
    if let Some(name) = config
        .magic_dns_name_for_participant(pubkey_hex)
        .and_then(|value| non_empty(&value))
    {
        return name;
    }
    if let Some(name) = config
        .peer_alias(pubkey_hex)
        .and_then(|value| non_empty(&value))
    {
        return name;
    }
    if active_network
        .admins
        .iter()
        .any(|admin| admin == pubkey_hex)
    {
        return "admin".to_string();
    }
    short_pubkey(pubkey_hex)
}

#[cfg(target_os = "macos")]
fn privileged_outcome_to_output(outcome: PrivilegedCommandOutput) -> Output {
    use std::os::unix::process::ExitStatusExt;
    let raw = if outcome.success { 0 } else { 1 << 8 };
    Output {
        status: std::process::ExitStatus::from_raw(raw),
        stdout: outcome.stdout,
        stderr: outcome.stderr,
    }
}

#[cfg(target_os = "macos")]
fn macos_service_action_shell_command(nvpn_bin: &Path, args: &[&str]) -> String {
    std::iter::once(shell_quote(&nvpn_bin.display().to_string()))
        .chain(args.iter().map(|arg| shell_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};

    fn create_test_network(runtime: &mut NativeAppRuntime, name: &str) -> String {
        runtime.config.add_network(name)
    }

    #[test]
    fn advertised_routes_are_normalized_and_deduplicated() {
        assert_eq!(
            parse_advertised_routes(" 10.0.0.0/8,10.0.0.0/8\n::/0 "),
            vec!["10.0.0.0/8".to_string(), "::/0".to_string()]
        );
    }

    #[test]
    fn relay_urls_are_normalized_and_deduplicated() {
        assert_eq!(
            normalize_relay_urls(vec![
                " wss://relay.example\nwss://b.example ".to_string(),
                "wss://relay.example,wss://a.example".to_string(),
            ]),
            vec![
                "wss://a.example".to_string(),
                "wss://b.example".to_string(),
                "wss://relay.example".to_string(),
            ]
        );
    }

    #[test]
    fn empty_app_relay_config_exposes_fips_defaults() {
        let mut config = AppConfig::generated();
        config.nostr.relays.clear();

        let relays = effective_config_relays(&config);

        assert!(!relays.is_empty());
        assert!(relays.iter().all(|relay| relay.starts_with("wss://")));
        assert!(relays.contains(&"wss://temp.iris.to".to_string()));
    }

    #[test]
    fn disabled_app_relays_filter_effective_relays() {
        let mut config = AppConfig::generated();
        let defaults = effective_config_relays(&config);
        let disabled = defaults.first().expect("fips default relay").clone();
        config.nostr.disabled_relays = vec![disabled.clone()];

        let relays = effective_config_relays(&config);

        assert!(!relays.contains(&disabled));
    }

    #[test]
    fn default_config_path_matches_desktop_config_location() {
        let path = default_config_path();

        assert!(path.ends_with(Path::new("nvpn").join("config.toml")));
    }

    #[test]
    fn startup_persists_identity_defaults_for_seeded_mobile_config() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-seeded-config-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "node_name = \"iPhone\"\n").expect("write seeded config");

        let runtime = NativeAppRuntime::new(dir.to_str().expect("utf8 temp dir"), String::new())
            .expect("runtime starts");
        let saved = AppConfig::load(&config_path).expect("saved config loads");

        assert_eq!(runtime.config.node_name, "iPhone");
        assert_eq!(saved.node_name, "iPhone");
        assert!(saved.networks.is_empty());
        assert!(!saved.nostr.secret_key.trim().is_empty());
        assert!(!saved.nostr.public_key.trim().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_error_state_does_not_expose_generated_config_as_real_config() {
        let error = anyhow!("boom");
        let runtime = NativeAppRuntime::from_startup_error(&error);
        let state = runtime.state();

        assert_eq!(state.error, "boom");
        assert!(state.own_pubkey_hex.is_empty());
        assert!(state.node_name.is_empty());
        assert!(state.tunnel_ip.is_empty());
        assert!(state.network_id.is_empty());
        assert_eq!(state.expected_peer_count, 0);
        assert_eq!(state.connected_peer_count, 0);
        assert!(state.networks.is_empty());
    }

    #[test]
    fn startup_error_blocks_config_mutation_until_real_config_loads() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-startup-guard-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        fs::write(&config_path, "not valid toml").expect("write invalid config");

        let error = anyhow!("startup failed");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.config_path = config_path.clone();
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                node_name: Some("should-not-save".to_string()),
                ..SettingsPatch::default()
            },
        });

        assert!(runtime.last_error.contains("cannot modify VPN config"));
        assert_eq!(
            fs::read_to_string(&config_path).expect("read config"),
            "not valid toml"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_error_recovers_after_config_becomes_readable() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-startup-recover-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let config_path = dir.join("config.toml");
        let config = AppConfig {
            node_name: "real-config".to_string(),
            ..AppConfig::generated_without_networks()
        };
        config.save(&config_path).expect("save config");

        let error = anyhow!("startup failed");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.mobile_runtime = true;
        runtime.config_path = config_path;
        runtime.dispatch(NativeAppAction::Tick);
        let state = runtime.state();

        assert!(state.error.is_empty(), "{}", state.error);
        assert_eq!(state.node_name, "real-config");
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());
        assert!(state.active_network_invite.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_config_has_no_network_until_created() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-create-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        let state = runtime.state();
        assert!(runtime.config.networks.is_empty());
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());
        assert!(state.active_network_invite.is_empty());

        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });

        let state = runtime.state();
        assert!(state.error.is_empty(), "{}", state.error);
        assert_eq!(runtime.config.networks.len(), 1);
        assert_eq!(state.networks.len(), 1);
        assert_eq!(state.networks[0].name, "Home");
        assert!(!state.network_id.is_empty());
        assert!(!state.active_network_invite.is_empty());
        assert_eq!(state.expected_peer_count, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_network_allows_returning_to_setup() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-remove-last-network-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.dispatch(NativeAppAction::AddNetwork {
            name: "Home".to_string(),
        });
        let network_id = runtime.config.networks[0].id.clone();

        runtime.dispatch(NativeAppAction::RemoveNetwork { network_id });

        let state = runtime.state();
        assert!(state.error.is_empty(), "{}", state.error);
        assert!(state.networks.is_empty());
        assert!(state.network_id.is_empty());
        assert!(state.active_network_invite.is_empty());
        assert_eq!(state.expected_peer_count, 0);

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn connect_vpn_requires_created_or_joined_network() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;

        runtime.dispatch(NativeAppAction::ConnectVpn);
        let state = runtime.state();

        assert!(state.error.contains("Create or join a network first"));
        assert!(!state.vpn_enabled);
        assert!(!state.vpn_active);
    }

    #[test]
    fn native_counts_keep_peer_and_device_totals_separate() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime.config.networks[0].participants = vec![peer_pubkey.to_string()];

        let state = runtime.state();
        let network = &state.networks[0];

        assert_eq!(state.expected_peer_count, 1);
        assert_eq!(state.connected_peer_count, 0);
        assert_eq!(network.expected_count, 2);
        assert_eq!(network.online_count, 0);
        assert_eq!(network.participants.len(), 2);
        assert!(network.participants.iter().any(|participant| {
            participant.pubkey_hex == own_pubkey
                && !participant.reachable
                && participant.state == "off"
                && participant.mesh_state == "off"
        }));
    }

    #[test]
    fn self_admin_alias_action_updates_network_state_for_ui_shells() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-self-alias-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime.config.networks[0].participants = Vec::new();

        runtime.dispatch(NativeAppAction::SetParticipantAlias {
            npub: to_npub(&own_pubkey),
            alias: "My iPhone".to_string(),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let state = runtime.state();
        let network = &state.networks[0];
        assert!(network.local_is_admin);
        let self_participant = network
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == own_pubkey)
            .expect("self participant");
        assert_eq!(self_participant.magic_dns_alias, "my-iphone");
        assert_eq!(self_participant.magic_dns_name, "my-iphone.nvpn");
        assert_eq!(state.self_magic_dns_name, "my-iphone.nvpn");

        let roster = runtime
            .config
            .shared_network_roster(&network.id)
            .expect("shared roster");
        assert_eq!(
            roster.aliases.get(&own_pubkey).map(String::as_str),
            Some("my-iphone")
        );

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(saved.peer_alias(&own_pubkey).as_deref(), Some("my-iphone"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn join_request_seeds_working_temporary_magic_dns_names() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-join-dns-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let admin = Keys::generate();
        let admin_hex = admin.public_key().to_hex();
        let admin_npub = admin.public_key().to_bech32().expect("admin npub");
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::ManualAddNetwork {
            admin_npub,
            mesh_network_id: "mesh-home".to_string(),
        });
        let network_id = runtime.config.networks[0].id.clone();
        runtime.dispatch(NativeAppAction::RequestNetworkJoin { network_id });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(
            runtime.config.peer_alias(&admin_hex).as_deref(),
            Some("admin")
        );
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let self_alias = runtime
            .config
            .peer_alias(&own_pubkey)
            .expect("join request seeds local alias");
        assert_eq!(self_alias, "self");

        let records = nostr_vpn_core::magic_dns::build_magic_dns_records(&runtime.config);
        let admin_ip = derive_mesh_tunnel_ip("mesh-home", &admin_hex)
            .expect("admin tunnel ip")
            .trim_end_matches("/32")
            .parse()
            .expect("admin ipv4");
        let own_ip = derive_mesh_tunnel_ip("mesh-home", &own_pubkey)
            .expect("own tunnel ip")
            .trim_end_matches("/32")
            .parse()
            .expect("own ipv4");
        assert_eq!(records.get("admin.nvpn").copied(), Some(admin_ip));
        assert_eq!(records.get("self.nvpn").copied(), Some(own_ip));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_flags_blocked_exit_node_when_protection_is_enabled() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let exit_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        runtime.config.exit_node = exit_pubkey.to_string();
        runtime.config.exit_node_leak_protection = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].participants = vec![exit_pubkey.to_string()];
        runtime
            .config
            .set_peer_alias(exit_pubkey, "lab-exit")
            .unwrap();
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 0,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: exit_pubkey.to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                reachable: false,
                error: Some("fips link pending".to_string()),
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        assert!(state.exit_node_blocked);
        assert!(!state.exit_node_active);
        assert_eq!(
            state.exit_node_status_text,
            "Internet blocked: waiting for lab-exit.nvpn"
        );
    }

    #[test]
    fn native_state_reports_active_exit_node_when_selected_peer_is_reachable() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let exit_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        runtime.config.exit_node = exit_pubkey.to_string();
        runtime.config.exit_node_leak_protection = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].participants = vec![exit_pubkey.to_string()];
        runtime
            .config
            .set_peer_alias(exit_pubkey, "lab-exit")
            .unwrap();
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: exit_pubkey.to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        assert!(!state.exit_node_blocked);
        assert!(state.exit_node_active);
        assert_eq!(state.exit_node_status_text, "Exit: lab-exit.nvpn");
    }

    #[test]
    fn native_state_reports_routed_fips_peer_latency() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey];
        runtime.config.networks[0].participants = vec![peer_pubkey.to_string()];
        let now = unix_timestamp();
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer_pubkey.to_string(),
                endpoint: "fips".to_string(),
                runtime_endpoint: Some("fips".to_string()),
                fips_endpoint_npub: "npub1peer".to_string(),
                fips_srtt_ms: Some(112),
                last_fips_seen_at: Some(now),
                last_handshake_at: Some(now),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let peer = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer_pubkey)
            .expect("peer participant");

        assert_eq!(peer.status_text, "online via mesh (112 ms)");
        assert_eq!(peer.fips_srtt_ms, 112);
    }

    #[test]
    fn invite_import_queues_join_request_to_invite_admin() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-invite-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let admin_hex = normalize_nostr_pubkey(&admin_npub).expect("normalize admin");
        let invite = serde_json::json!({
            "v": 3,
            "networkId": "8d4f34f5425bc50e",
            "inviterEndpoints": ["192.168.50.20:51820"],
            "admins": [admin_npub],
            "relays": ["wss://temp.iris.to"]
        })
        .to_string();

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime
            .import_network_invite(&invite)
            .expect("import invite");

        let network = runtime.config.active_network();
        let pending = network
            .outbound_join_request
            .as_ref()
            .expect("join request should be queued");
        assert_eq!(pending.recipient, admin_hex);
        assert!(network.participants.is_empty());
        assert_eq!(
            runtime.config.fips_peer_endpoints.get(&admin_npub),
            Some(&vec!["192.168.50.20:51820".to_string()])
        );
        let state = runtime.state();
        assert_eq!(state.networks.len(), 1);
        assert_eq!(state.networks[0].network_id, "8d4f34f5425bc50e");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invite_import_creates_new_network_when_active_network_is_named() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-named-active-invite-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let admin_npub = "npub1akgu9lxldpt32lnjf97k005a4kgasewmvsrmkpzqeff398ssev0ssd6t3u";
        let admin_hex = normalize_nostr_pubkey(admin_npub).expect("normalize admin");
        let invite = "nvpn://invite/eyJ2IjozLCJuZXR3b3JrSWQiOiI3YTYwMTQ4MzVkNDA0Y2IwIiwiYWRtaW5zIjpbIm5wdWIxYWtndTlseGxkcHQzMmxuamY5N2swMDVhNGtnYXNld212c3Jta3B6cWVmZjM5OHNzZXYwc3NkNnQzdSJdfQ";

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        let old_network_id = create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].network_id = "5a249444c4254f98".to_string();
        runtime.config.networks[0].admins = vec![admin_hex.clone()];

        runtime
            .import_network_invite(invite)
            .expect("import invite");

        assert_eq!(runtime.config.networks.len(), 2);
        let old_network = runtime
            .config
            .network_by_id(&old_network_id)
            .expect("old network should remain");
        assert_eq!(old_network.network_id, "5a249444c4254f98");
        assert!(!old_network.enabled);

        let network = runtime.config.active_network();
        assert_eq!(network.network_id, "7a6014835d404cb0");
        assert_eq!(network.admins, vec![admin_hex.clone()]);
        assert_eq!(network.invite_inviter, admin_hex);
        assert!(network.outbound_join_request.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_marks_reachable_invite_admin_as_pending_until_join_is_accepted() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        create_test_network(&mut runtime, "Home");

        let admin_hex = Keys::generate().public_key().to_hex();
        runtime.config.networks[0].network_id = "mesh-home".to_string();
        runtime.config.networks[0].participants = Vec::new();
        runtime.config.networks[0].admins = vec![admin_hex.clone()];
        runtime.config.networks[0].invite_inviter = admin_hex.clone();
        runtime.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin_hex.clone(),
            requested_at: 1_726_000_000,
        });
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: admin_hex.clone(),
                tunnel_ip: "10.44.135.191".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let admin = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == admin_hex)
            .expect("admin participant should be visible");

        assert!(admin.reachable);
        assert_eq!(admin.state, "pending");
        assert_eq!(admin.status_text, "join request sent");
    }

    #[test]
    fn manual_add_network_does_not_queue_join_request() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-manual-add-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let admin_hex = normalize_nostr_pubkey(&admin_npub).expect("normalize admin");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::ManualAddNetwork {
            admin_npub,
            mesh_network_id: "8d4f34f5425bc50e".to_string(),
        });

        let network = runtime.config.active_network();
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(network.network_id, "8d4f34f5425bc50e");
        assert!(network.participants.is_empty());
        assert_eq!(network.admins, vec![admin_hex]);
        assert!(network.outbound_join_request.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lan_pairing_runs_for_fifteen_minutes_until_cancelled() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-lan-pairing-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");

        runtime.dispatch(NativeAppAction::StartInviteBroadcast);
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        runtime.dispatch(NativeAppAction::StartNearbyDiscovery);
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);

        let state = runtime.state();
        assert!(state.invite_broadcast_active);
        assert!(state.nearby_discovery_active);
        assert!(state.invite_broadcast_remaining_secs <= LAN_PAIRING_DURATION.as_secs());
        assert!(state.invite_broadcast_remaining_secs > LAN_PAIRING_DURATION.as_secs() - 10);
        assert!(state.nearby_discovery_remaining_secs <= LAN_PAIRING_DURATION.as_secs());
        assert!(state.nearby_discovery_remaining_secs > LAN_PAIRING_DURATION.as_secs() - 10);

        runtime.dispatch(NativeAppAction::StopInviteBroadcast);
        let state = runtime.state();
        assert!(!state.invite_broadcast_active);
        assert_eq!(state.invite_broadcast_remaining_secs, 0);
        assert!(
            state.nearby_discovery_active,
            "discovery should keep running"
        );

        runtime.dispatch(NativeAppAction::StopNearbyDiscovery);
        let state = runtime.state();
        assert!(!state.nearby_discovery_active);
        assert_eq!(state.nearby_discovery_remaining_secs, 0);
        assert!(state.lan_peers.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invite_broadcast_enables_join_requests() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-broadcast-joins-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].listen_for_join_requests = false;

        runtime.dispatch(NativeAppAction::StartInviteBroadcast);

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.networks[0].listen_for_join_requests);
        assert!(runtime.state().networks[0].join_requests_enabled);

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks[0].listen_for_join_requests);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn enabling_join_requests_starts_background_fips_listener() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-join-listener-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let calls_path = dir.join("calls.txt");
        let started_path = dir.join("started");
        let script_path = dir.join("nvpn");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let started_literal = started_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = format!(
            r#"#!/bin/sh
CALLS="{calls_literal}"
STARTED="{started_literal}"
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"to.iris.nvpn.test","binary_version":"test"}}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  if [ -f "$STARTED" ]; then
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":false,"vpn_status":"Listening for join requests","expected_peer_count":0,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  else
    cat <<'JSON'
{{"daemon":{{"running":false,"state":null}}}}
JSON
  fi
  exit 0
fi
if [ "$1" = "start" ]; then
  touch "$STARTED"
  exit 0
fi
if [ "$1" = "resume" ] || [ "$1" = "reload" ]; then
  exit 0
fi
exit 0
"#
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = false;
        runtime.config_path = dir.join("config.toml");
        let network_id = create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].listen_for_join_requests = false;
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::SetNetworkJoinRequestsEnabled {
            network_id,
            enabled: true,
        });

        let calls = fs::read_to_string(&calls_path).expect("read fake nvpn calls");
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            started_path.exists(),
            "join listener daemon was not started"
        );
        assert!(calls.contains("start --daemon --connect --config"));
        assert!(runtime.config.networks[0].listen_for_join_requests);
        assert!(runtime.vpn_enabled);
        assert_eq!(runtime.vpn_status, "Listening for join requests");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_exposes_inbound_join_requests_for_ui_shells() {
        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "iPhone".to_string(),
                requested_at: 1_778_998_000,
            });

        let state = runtime.state();
        let request = state.networks[0]
            .inbound_join_requests
            .first()
            .expect("join request should be visible in native state");

        assert_eq!(request.requester_npub, requester_npub);
        assert_eq!(request.requester_pubkey_hex, requester_hex);
        assert_eq!(request.requester_node_name, "iPhone");
        assert!(!request.requested_at_text.trim().is_empty());

        let json = serde_json::to_value(&state).expect("serialize native state");
        assert_eq!(
            json["networks"][0]["inboundJoinRequests"][0]["requesterNpub"],
            requester_npub
        );
        assert_eq!(
            json["networks"][0]["inboundJoinRequests"][0]["requesterNodeName"],
            "iPhone"
        );
    }

    #[test]
    fn accepting_join_request_uses_requester_node_name_as_alias() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-accept-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let network_id = runtime.config.networks[0].id.clone();
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "Linux Dev".to_string(),
                requested_at: 1_726_000_000,
            });

        runtime.dispatch(NativeAppAction::AcceptJoinRequest {
            network_id: network_id.clone(),
            requester_npub,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            runtime.config.networks[0]
                .participants
                .contains(&requester_hex)
        );
        assert!(runtime.config.networks[0].inbound_join_requests.is_empty());
        assert_eq!(
            runtime.config.peer_alias(&requester_hex).as_deref(),
            Some("linux-dev")
        );

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert_eq!(
            saved.peer_alias(&requester_hex).as_deref(),
            Some("linux-dev")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejecting_join_request_removes_it_without_adding_participant() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-reject-join-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let requester_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("requester npub");
        let requester_hex = normalize_nostr_pubkey(&requester_npub).expect("normalize requester");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        let network_id = runtime.config.networks[0].id.clone();
        runtime.config.networks[0]
            .inbound_join_requests
            .push(PendingInboundJoinRequest {
                requester: requester_hex.clone(),
                requester_node_name: "Ubuntu Dev".to_string(),
                requested_at: 1_726_000_000,
            });

        runtime.dispatch(NativeAppAction::RejectJoinRequest {
            network_id,
            requester_npub,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            !runtime.config.networks[0]
                .participants
                .contains(&requester_hex)
        );
        assert!(runtime.config.networks[0].inbound_join_requests.is_empty());

        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.networks[0].inbound_join_requests.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn native_state_hides_reachable_peers_when_vpn_is_paused() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        let own_pubkey = runtime
            .config
            .own_nostr_pubkey_hex()
            .expect("generated config should have own pubkey");
        let peer_pubkey = "26525c442dd039de4e728b41ee8d7f717b267ab25b7c219d53a3249e1c9174cc";
        create_test_network(&mut runtime, "Home");
        runtime.config.networks[0].admins = vec![own_pubkey.clone()];
        runtime.config.networks[0].participants = vec![peer_pubkey.to_string()];
        runtime.daemon_running = true;
        runtime.vpn_enabled = false;
        runtime.vpn_active = false;
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: false,
            vpn_active: false,
            expected_peer_count: 1,
            connected_peer_count: 1,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer_pubkey.to_string(),
                tunnel_ip: "10.44.10.23".to_string(),
                reachable: true,
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        });

        let state = runtime.state();
        let network = &state.networks[0];

        assert!(!state.vpn_active);
        assert_eq!(state.connected_peer_count, 0);
        assert_eq!(network.online_count, 0);
        assert!(
            network
                .participants
                .iter()
                .all(|participant| { !participant.reachable && participant.state == "off" })
        );
    }

    #[test]
    fn mobile_connect_reports_vpn_on_without_pending_placeholder() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-mobile-connect-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save config");

        runtime.dispatch(NativeAppAction::ConnectVpn);
        let state = runtime.state();

        assert!(state.vpn_enabled);
        assert!(state.vpn_active);
        assert_eq!(state.vpn_status, "VPN on");
    }

    #[test]
    fn mobile_refresh_restores_fresh_runtime_state_after_app_recreation() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-mobile-refresh-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        runtime.config_path = dir.join("config.toml");
        let network_id = create_test_network(&mut runtime, "Home");
        let peer = Keys::generate().public_key().to_hex();
        runtime
            .config
            .add_participant_to_network(&network_id, &peer)
            .expect("add peer");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save config");
        let now = unix_timestamp();
        let runtime_state = DaemonRuntimeState {
            updated_at: now,
            binary_version: "test".to_string(),
            vpn_enabled: true,
            vpn_active: true,
            vpn_status: "VPN on (1/1 peers)".to_string(),
            expected_peer_count: 1,
            connected_peer_count: 1,
            mesh_ready: true,
            peers: vec![DaemonPeerState {
                participant_pubkey: peer.clone(),
                reachable: true,
                last_fips_seen_at: Some(now),
                ..DaemonPeerState::default()
            }],
            ..DaemonRuntimeState::default()
        };
        fs::write(
            dir.join(MOBILE_RUNTIME_STATE_FILE),
            serde_json::to_vec(&runtime_state).expect("encode runtime state"),
        )
        .expect("write runtime state");

        runtime.dispatch(NativeAppAction::Tick);
        let state = runtime.state();
        let participant = state.networks[0]
            .participants
            .iter()
            .find(|participant| participant.pubkey_hex == peer)
            .expect("peer participant");

        assert!(state.vpn_enabled);
        assert!(state.vpn_active);
        assert_eq!(state.connected_peer_count, 1);
        assert!(participant.reachable);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mobile_disconnect_clears_persisted_runtime_state() {
        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-mobile-disconnect-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save config");
        let state_path = dir.join(MOBILE_RUNTIME_STATE_FILE);
        fs::write(
            &state_path,
            serde_json::to_vec(&DaemonRuntimeState {
                updated_at: unix_timestamp(),
                vpn_enabled: true,
                vpn_active: true,
                vpn_status: "VPN on".to_string(),
                ..DaemonRuntimeState::default()
            })
            .expect("encode runtime state"),
        )
        .expect("write runtime state");

        runtime.dispatch(NativeAppAction::DisconnectVpn);
        let state = runtime.state();

        assert!(!state_path.exists());
        assert!(!state.vpn_enabled);
        assert!(!state.vpn_active);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn install_service_restores_vpn_after_refreshing_stale_state() {
        use std::os::unix::fs::PermissionsExt;

        #[cfg(target_os = "macos")]
        #[derive(Debug)]
        struct TestPrivilegedRunner {
            calls_path: PathBuf,
        }

        #[cfg(target_os = "macos")]
        impl PrivilegedCommandRunner for TestPrivilegedRunner {
            fn run(&self, executable: String, args: Vec<String>) -> PrivilegedCommandOutput {
                use std::io::Write;

                let mut command = vec![format!("privileged:{executable}")];
                command.extend(args);
                if let Ok(mut calls) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.calls_path)
                {
                    let _ = writeln!(calls, "{}", command.join(" "));
                }

                PrivilegedCommandOutput {
                    success: true,
                    cancelled: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
        }

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-service-restore-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let calls_path = dir.join("calls.txt");
        let resumed_path = dir.join("resumed");
        let script_path = dir.join("nvpn");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let resumed_literal = resumed_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = format!(
            r#"#!/bin/sh
CALLS="{calls_literal}"
RESUMED="{resumed_literal}"
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = "service" ] && [ "$2" = "install" ]; then
  exit 0
fi
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"to.iris.nvpn.test","binary_version":"test"}}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  if [ -f "$RESUMED" ]; then
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":2,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":true,"vpn_active":true,"vpn_status":"VPN on","expected_peer_count":1,"connected_peer_count":1,"mesh_ready":true,"peers":[]}}}}}}
JSON
  else
    cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":false,"vpn_active":false,"vpn_status":"Paused","expected_peer_count":1,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  fi
  exit 0
fi
if [ "$1" = "resume" ]; then
  touch "$RESUMED"
  exit 0
fi
if [ "$1" = "start" ]; then
  echo "unexpected elevated start" >&2
  exit 42
fi
exit 0
"#
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);
        runtime.daemon_running = true;
        runtime.vpn_enabled = true;
        runtime.vpn_active = true;
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            vpn_status: "VPN on".to_string(),
            expected_peer_count: 1,
            connected_peer_count: 1,
            ..DaemonRuntimeState::default()
        });
        #[cfg(target_os = "macos")]
        {
            runtime.privileged_command_runner = Some(PrivilegedCommandRunnerHandle(Arc::new(
                TestPrivilegedRunner {
                    calls_path: calls_path.clone(),
                },
            )));
        }

        runtime.dispatch(NativeAppAction::InstallSystemService);

        let calls = fs::read_to_string(&calls_path).expect("read fake nvpn calls");
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(resumed_path.exists(), "service reinstall should resume VPN");
        assert!(calls.contains("status --json --discover-secs 0 --config"));
        assert!(calls.contains("resume --config"));
        assert!(!calls.contains("start --daemon --connect"));
        assert!(runtime.vpn_enabled);
        assert!(runtime.vpn_active);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_patch_persists_wireguard_exit_config() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-wireguard-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(true),
                wireguard_exit_interface: Some("custom-wg".to_string()),
                wireguard_exit_address: Some("10.200.0.2/32".to_string()),
                wireguard_exit_private_key: Some("private".to_string()),
                wireguard_exit_peer_public_key: Some("peer".to_string()),
                wireguard_exit_peer_preshared_key: Some("psk".to_string()),
                wireguard_exit_endpoint: Some("198.51.100.20:51830".to_string()),
                wireguard_exit_allowed_ips: Some("0.0.0.0/0".to_string()),
                wireguard_exit_dns: Some("9.9.9.9".to_string()),
                wireguard_exit_mtu: Some(1380),
                wireguard_exit_persistent_keepalive_secs: Some(20),
                exit_node_leak_protection: Some(true),
                ..SettingsPatch::default()
            },
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.wireguard_exit.enabled);
        assert_eq!(saved.wireguard_exit.interface, "custom-wg");
        assert_eq!(saved.wireguard_exit.address, "10.200.0.2/32");
        assert_eq!(saved.wireguard_exit.private_key, "private");
        assert_eq!(saved.wireguard_exit.peer_public_key, "peer");
        assert_eq!(saved.wireguard_exit.peer_preshared_key, "psk");
        assert_eq!(saved.wireguard_exit.endpoint, "198.51.100.20:51830");
        assert_eq!(saved.wireguard_exit.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(saved.wireguard_exit.dns, vec!["9.9.9.9"]);
        assert_eq!(saved.wireguard_exit.mtu, 1380);
        assert_eq!(saved.wireguard_exit.persistent_keepalive_secs, 20);
        assert!(saved.exit_node_leak_protection);

        let state = runtime.state();
        assert!(state.exit_node_leak_protection);
        assert!(state.wireguard_exit_enabled);
        assert!(state.wireguard_exit_configured);
        assert_eq!(state.wireguard_exit_interface, "custom-wg");
        assert_eq!(state.wireguard_exit_allowed_ips, "0.0.0.0/0");
        assert!(state.wireguard_exit_config.contains("[Interface]"));
        assert!(state.wireguard_exit_config.contains("[Peer]"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_patch_enforces_exit_node_mutual_exclusion() {
        use nostr_sdk::prelude::{Keys, ToBech32};

        // Selecting a peer exit clears WG upstream, and selecting WG
        // upstream clears the peer exit — the daemon enforces this
        // so every UI can just push the new selection.
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-mutual-exit-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let peer_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("peer npub");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        // Add the peer as a participant in the active network so the
        // ensure_defaults pass at save time doesn't clear our chosen
        // exit_node as "not a participant".
        if let Some(network) = runtime.config.networks.first_mut() {
            network.participants.push(peer_npub.clone());
        }

        // Start with WG upstream enabled.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(true),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        // Now push a peer exit. WG must clear.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node: Some(peer_npub.clone()),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(!runtime.config.wireguard_exit.enabled);
        assert!(!runtime.config.exit_node.is_empty());

        // Flip back to WG: peer exit must clear.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(true),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        // Selecting Direct (clearing exit_node) leaves WG alone — the
        // user has to explicitly disable WG to go fully direct.
        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node: Some(String::new()),
                ..SettingsPatch::default()
            },
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.config.wireguard_exit.enabled);
        assert_eq!(runtime.config.exit_node, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_patch_imports_wireguard_exit_config_block() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-wireguard-import-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        runtime.config.wireguard_exit.enabled = true;

        runtime.dispatch(NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_config: Some(
                    r"
                    [Interface]
                    PrivateKey = client-private
                    Address = 10.64.70.195/32
                    DNS = 10.64.0.1
                    MTU = 1380

                    [Peer]
                    PublicKey = provider-public
                    AllowedIPs = 0.0.0.0/0
                    Endpoint = vpn.example.test:51820
                    PersistentKeepalive = 20
                    "
                    .to_string(),
                ),
                ..SettingsPatch::default()
            },
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let saved = AppConfig::load(&runtime.config_path).expect("load persisted config");
        assert!(saved.wireguard_exit.enabled);
        assert_eq!(saved.wireguard_exit.address, "10.64.70.195/32");
        assert_eq!(saved.wireguard_exit.private_key, "client-private");
        assert_eq!(saved.wireguard_exit.peer_public_key, "provider-public");
        assert_eq!(saved.wireguard_exit.endpoint, "vpn.example.test:51820");
        assert_eq!(saved.wireguard_exit.mtu, 1380);
        assert_eq!(saved.wireguard_exit.persistent_keepalive_secs, 20);

        let state = runtime.state();
        assert!(
            state
                .wireguard_exit_config
                .contains("Endpoint = vpn.example.test:51820")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn connect_vpn_resumes_running_daemon_without_elevated_start() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-resume-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let calls_path = dir.join("calls.txt");
        let script_path = dir.join("nvpn");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = format!(
            r#"#!/bin/sh
CALLS="{calls_literal}"
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":true,"disabled":false,"loaded":true,"running":true,"pid":123,"label":"to.iris.nvpn.test","binary_version":"test"}}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  cat <<'JSON'
{{"daemon":{{"running":true,"state":{{"updated_at":1,"binary_version":"test","local_endpoint":"","advertised_endpoint":"","listen_port":0,"vpn_enabled":false,"vpn_active":false,"vpn_status":"Paused","expected_peer_count":0,"connected_peer_count":0,"mesh_ready":false,"peers":[]}}}}}}
JSON
  exit 0
fi
if [ "$1" = "resume" ]; then
  exit 0
fi
if [ "$1" = "start" ]; then
  echo "unexpected elevated start" >&2
  exit 42
fi
exit 0
"#
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::ConnectVpn);

        let calls = fs::read_to_string(&calls_path).expect("read fake nvpn calls");
        assert!(calls.contains("resume --config"));
        assert!(!calls.contains("start --daemon --connect"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_connect_without_service_does_not_start_or_prompt() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nvpn-app-core-no-service-{nonce}"));
        fs::create_dir_all(&dir).expect("create test dir");
        let calls_path = dir.join("calls.txt");
        let script_path = dir.join("nvpn");
        let calls_literal = calls_path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = format!(
            r#"#!/bin/sh
CALLS="{calls_literal}"
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = "service" ] && [ "$2" = "status" ]; then
  cat <<'JSON'
{{"supported":true,"installed":false,"disabled":false,"loaded":false,"running":false,"pid":null,"label":"to.iris.nvpn.test","binary_version":""}}
JSON
  exit 0
fi
if [ "$1" = "status" ]; then
  cat <<'JSON'
{{"daemon":{{"running":false,"state":null}}}}
JSON
  exit 0
fi
if [ "$1" = "start" ]; then
  echo "unexpected start" >&2
  exit 42
fi
exit 0
"#
        );
        fs::write(&script_path, script).expect("write fake nvpn");
        let mut permissions = fs::metadata(&script_path)
            .expect("fake nvpn metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("make fake nvpn executable");

        let error = anyhow!("boom");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Home");
        runtime
            .config
            .save(&runtime.config_path)
            .expect("save test config");
        runtime.nvpn_bin = Some(script_path);

        runtime.dispatch(NativeAppAction::ConnectVpn);

        let calls = fs::read_to_string(&calls_path).expect("read fake nvpn calls");
        assert!(calls.contains("service status --json --config"));
        assert!(calls.contains("status --json --discover-secs 0 --config"));
        assert!(!calls.contains("start --daemon --connect"));
        assert_eq!(runtime.last_error, "Install background service first");
        assert!(!runtime.vpn_enabled);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_service_action_shell_command_quotes_bundled_cli_path() {
        let command = macos_service_action_shell_command(
            Path::new("/Applications/Nostr VPN.app/Contents/Resources/nvpn"),
            &["service", "install", "--force"],
        );

        assert!(command.starts_with("'/Applications/Nostr VPN.app/Contents/Resources/nvpn' "));
        assert!(command.contains(" 'service' 'install' '--force'"));
    }
}
