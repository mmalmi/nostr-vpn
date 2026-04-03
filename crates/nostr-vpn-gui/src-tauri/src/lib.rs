#![cfg_attr(any(target_os = "android", target_os = "ios", test), allow(dead_code))]

#[cfg(any(target_os = "android", test))]
mod android_session;
#[cfg(any(target_os = "android", test))]
mod android_session_runtime;
#[cfg(any(target_os = "android", test))]
mod android_vpn;
mod app_runtime;
mod backend_configuration;
mod daemon_runtime;
mod gui_launch;
#[cfg(any(target_os = "android", target_os = "ios", test))]
mod ios_packet_tunnel;
#[cfg(target_os = "ios")]
mod ios_vpn;
mod lan_pairing;
#[cfg(any(target_os = "android", target_os = "ios", test))]
mod mobile_runtime_state;
#[cfg(any(target_os = "android", target_os = "ios", test))]
mod mobile_wg;
mod path_resolution;
mod peer_state;
mod relay_operator_state;
mod service_status;
mod tauri_commands;
mod tray_runtime;

#[allow(unused_imports)]
pub(crate) use app_runtime::*;
#[cfg(target_os = "ios")]
pub(crate) use gui_launch::env_flag_is_truthy;
#[cfg(test)]
pub(crate) use gui_launch::{
    DebugAutomationCommand, extract_debug_automation_command_from_deep_link,
    extract_invite_from_deep_link, gui_launch_disposition, parse_running_gui_instances,
    started_from_autostart_args,
};
pub(crate) use gui_launch::{
    GuiLaunchDisposition, PendingLaunchAction, extract_app_deep_links_from_args,
    gui_requires_service_enable, gui_requires_service_install, gui_service_enable_status_text,
    gui_service_setup_status_text, hide_main_window_to_tray,
    import_network_invites_from_deep_links, is_valid_relay_url,
    local_join_request_listener_enabled, nvpn_gui_iface_override, parse_advertised_routes_input,
    parse_exit_node_input, pending_launch_action, resolve_gui_launch_conflicts,
    should_close_to_tray, should_defer_gui_daemon_start_to_service_on_autostart,
    should_defer_gui_daemon_start_until_first_tick, should_start_gui_daemon_on_launch,
    should_surface_existing_instance_args, show_main_window, started_from_autostart,
    tauri_automation_enabled, terminate_gui_instances,
};
#[cfg(test)]
pub(crate) use path_resolution::cli_binary_installed_at;
#[allow(unused_imports)]
pub(crate) use path_resolution::{
    bundled_nvpn_candidate_paths, cli_binary_installed, compact_age_text, compact_remaining_text,
    config_path_from_roots, current_target_triple, current_unix_timestamp, default_config_path,
    epoch_secs_to_system_time, expected_peer_count, extract_json_document,
    is_already_running_message, is_mesh_complete, is_not_running_message, join_request_age_text,
    network_device_count, network_online_device_count, nvpn_binary_name, nvpn_binary_stem,
    nvpn_bundled_binary_candidates, nvpn_sidecar_binary_name, requires_admin_privileges,
    resolve_backend_config_path, resolve_nvpn_cli_path, service_state_refresh_due, shorten_middle,
    validate_nvpn_binary,
};
#[cfg(any(target_os = "windows", test))]
pub(crate) use path_resolution::{
    desktop_config_path_from_roots, requires_admin_privileges_error, strip_windows_verbatim_prefix,
    windows_daemon_apply_requires_service_repair, windows_daemon_config_import_args,
    windows_elevated_config_import_args, windows_should_start_installed_service,
    windows_should_use_daemon_owned_config_apply,
};
#[cfg(target_os = "windows")]
pub(crate) use path_resolution::{
    normalize_windows_elevated_args, windows_temp_config_import_path,
};
#[allow(unused_imports)]
pub(crate) use peer_state::{
    ConfiguredPeerStatus, LanAnnouncement, LanPairingSignal, LanPeerRecord, NetworkInvite,
    PeerLinkStatus, PeerPresenceStatus, active_network_invite_code,
    apply_network_invite_to_active_network, connected_configured_peer_count,
    decode_lan_pairing_announcement, parse_network_invite, peer_link_uses_relay_path,
    peer_presence_state_label, peer_state_label, preferred_join_request_recipient, to_npub,
    unix_timestamp,
};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
pub(crate) use tray_runtime::{
    build_tray_menu, current_tray_runtime_state, refresh_tray_menu, run_tray_backend_action,
};
pub(crate) use tray_runtime::{
    copy_text_to_clipboard, display_tunnel_ip, tray_exit_node_entries, tray_network_groups,
    tray_status_text,
};
#[cfg(test)]
pub(crate) use tray_runtime::{tray_menu_spec, tray_vpn_status_menu_text, tray_vpn_toggle_text};

use std::collections::{HashMap, HashSet};
use std::env;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use nostr_vpn_core::config::{
    AppConfig, PendingInboundJoinRequest, PendingOutboundJoinRequest, derive_mesh_tunnel_ip,
    maybe_autoconfigure_node, normalize_nostr_pubkey, normalize_runtime_network_id,
};
use nostr_vpn_core::diagnostics::{HealthIssue, NetworkSummary, PortMappingStatus};
use nostr_vpn_core::join_requests::{MeshJoinRequest, publish_join_request};
#[cfg(target_os = "windows")]
use nostr_vpn_core::platform_paths::legacy_config_path_from_dirs_config_dir;
#[cfg(any(target_os = "windows", test))]
use nostr_vpn_core::platform_paths::windows_default_config_path_for_state;
#[cfg(any(target_os = "windows", test))]
use nostr_vpn_core::platform_paths::windows_machine_config_path_from_program_data_dir;
#[cfg(target_os = "windows")]
use nostr_vpn_core::platform_paths::windows_service_binary_path_from_sc_qc_output;
#[cfg(target_os = "windows")]
use nostr_vpn_core::platform_paths::windows_service_config_path_from_sc_qc_output;
use nostr_vpn_core::relay::{
    RelayOperatorState as SharedRelayOperatorState,
    ServiceOperatorState as SharedServiceOperatorState,
};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri::WindowEvent;
#[cfg(target_os = "macos")]
use tauri::image::Image;
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State};
use tauri_plugin_deep_link::DeepLinkExt;
use tokio::runtime::Runtime;

#[allow(unused_imports)]
pub(crate) use tauri_commands::{
    accept_join_request, add_admin, add_network, add_participant, add_relay,
    apply_windows_subprocess_flags, connect_session, disable_system_service, disconnect_session,
    enable_system_service, import_network_invite, install_cli, install_system_service,
    remove_admin, remove_network, remove_participant, remove_relay, rename_network,
    request_network_join, run_blocking_mutex_action, set_network_enabled,
    set_network_join_requests_enabled, set_network_mesh_id, set_participant_alias,
    start_lan_pairing, stop_lan_pairing, tick, uninstall_cli, uninstall_system_service,
    update_settings,
};

const LAN_PAIRING_ADDR: [u8; 4] = [239, 255, 73, 73];
const LAN_PAIRING_PORT: u16 = 38911;
const LAN_PAIRING_STALE_AFTER_SECS: u64 = 16;
const LAN_PAIRING_DURATION_SECS: u64 = 15 * 60;
const LAN_PAIRING_ANNOUNCEMENT_VERSION: u8 = 2;
const LAN_PAIRING_BUFFER_BYTES: usize = 8192;
// Keep the GUI's online/offline grace aligned with the daemon's WireGuard
// session window so idle peers do not flap back to "awaiting handshake".
const PEER_ONLINE_GRACE_SECS: u64 = 180;
const PEER_PRESENCE_GRACE_SECS: u64 = 45;
const SERVICE_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TRAY_ICON_ID: &str = "nvpn-tray";
const TRAY_OPEN_MENU_ID: &str = "tray_open_main";
const TRAY_THIS_DEVICE_MENU_ID: &str = "tray_this_device";
const TRAY_VPN_TOGGLE_MENU_ID: &str = "tray_vpn_toggle";
const TRAY_RUN_EXIT_NODE_MENU_ID: &str = "tray_run_exit_node";
const TRAY_EXIT_NODE_NONE_MENU_ID: &str = "tray_exit_node_none";
const TRAY_EXIT_NODE_MENU_ID_PREFIX: &str = "tray_exit_node::";
const TRAY_QUIT_UI_MENU_ID: &str = "tray_quit_ui";
const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const NVPN_GUI_IFACE_ENV: &str = "NVPN_GUI_IFACE";
#[cfg(target_os = "ios")]
const NVPN_IOS_FORCE_CONNECT_ENV: &str = "NVPN_IOS_FORCE_CONNECT";
const AUTOSTART_LAUNCH_ARG: &str = "--autostart";
const GUI_SERVICE_SETUP_REQUIRED_STATUS: &str =
    "Install background service to turn VPN on from the app";
const GUI_SERVICE_SETUP_REQUIRED_AUTOCONNECT_STATUS: &str =
    "Install background service to enable app auto-connect";
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(test)]
const IOS_TAURI_ORIGIN: &str = "tauri://localhost";
const NETWORK_INVITE_PREFIX: &str = "nvpn://invite/";
const DEBUG_AUTOMATION_DEEP_LINK_PREFIX: &str = "nvpn://debug/";
const NETWORK_INVITE_VERSION: u8 = 2;

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
    service_binary_version: String,
    last_service_status_refresh_at: Option<Instant>,
    daemon_state: Option<DaemonRuntimeState>,
    relay_operator_state: Option<SharedServiceOperatorState>,
    launch_start_pending: bool,
    force_connect_pending: bool,

    relay_status: HashMap<String, RelayStatus>,
    peer_status: HashMap<String, PeerLinkStatus>,

    lan_pairing_running: bool,
    lan_pairing_rx: Option<mpsc::Receiver<LanPairingSignal>>,
    lan_pairing_stop: Option<Arc<AtomicBool>>,
    lan_pairing_expires_at: Option<SystemTime>,
    lan_peers: HashMap<String, LanPeerRecord>,

    magic_dns_status: String,
}

impl NvpnBackend {
    fn new(
        app_handle: tauri::AppHandle,
        config_path: PathBuf,
        launched_from_autostart: bool,
    ) -> Result<Self> {
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: new entry");
        #[cfg(not(target_os = "android"))]
        let _ = &app_handle;

        let runtime = Runtime::new().context("failed to create tokio runtime")?;
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: runtime ready");
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
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: config loaded");
        #[cfg(target_os = "ios")]
        {
            let active_participants = config.participant_pubkeys_hex();
            write_ios_probe(format!(
                "backend: config summary autoconnect={} active_network_id={} active_participants={} own_npub={} config_path={}",
                config.autoconnect,
                config.effective_network_id(),
                active_participants.len(),
                shorten_middle(&config.nostr.public_key, 18, 8),
                config_path.display()
            ));
        }

        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: config normalized");

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
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: cli path resolved");

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
            service_binary_version: String::new(),
            last_service_status_refresh_at: None,
            daemon_state: None,
            relay_operator_state: None,
            launch_start_pending: false,
            force_connect_pending: false,
            relay_status,
            peer_status,
            lan_pairing_running: false,
            lan_pairing_rx: None,
            lan_pairing_stop: None,
            lan_pairing_expires_at: None,
            lan_peers: HashMap::new(),
            magic_dns_status: "DNS disabled (VPN off)".to_string(),
        };
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: state allocated");

        backend.ensure_relay_status_entries();
        backend.ensure_peer_status_entries();
        backend.refresh_relay_operator_state();
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: status entries ensured");
        #[cfg(target_os = "ios")]
        {
            backend.sync_service_state();
            write_ios_probe("backend: initial daemon sync deferred");
        }
        #[cfg(not(target_os = "ios"))]
        {
            backend.sync_daemon_state();
        }
        #[cfg(not(target_os = "ios"))]
        let _ = ();
        #[cfg(target_os = "ios")]
        write_ios_probe("backend: daemon sync complete");

        let runtime_capabilities = current_runtime_capabilities();
        let wants_autoconnect =
            backend.config.autoconnect && !backend.config.participant_pubkeys_hex().is_empty();
        let wants_join_request_listener = local_join_request_listener_enabled(&backend.config);
        let wants_background_start = wants_autoconnect || wants_join_request_listener;
        let should_start_on_launch = should_start_gui_daemon_on_launch(
            runtime_capabilities.vpn_session_control_supported,
            wants_background_start,
            backend.gui_requires_service_action(),
        );
        let defer_to_installed_service = should_defer_gui_daemon_start_to_service_on_autostart(
            launched_from_autostart,
            backend.service_installed,
            backend.service_disabled,
        );
        #[cfg(target_os = "ios")]
        write_ios_probe(format!(
            "backend: launch background_start wants_autoconnect={} wants_join_listener={} should_start={} defer_to_service={} has_participants={} service_action_required={}",
            wants_autoconnect,
            wants_join_request_listener,
            should_start_on_launch,
            defer_to_installed_service,
            !backend.config.participant_pubkeys_hex().is_empty(),
            backend.gui_requires_service_action()
        ));
        if should_defer_gui_daemon_start_until_first_tick(
            current_runtime_platform(),
            should_start_on_launch,
            defer_to_installed_service,
        ) {
            backend.launch_start_pending = true;
            backend.session_status = "Waiting for initial VPN start".to_string();
        } else if should_start_on_launch && !backend.daemon_running && !defer_to_installed_service {
            #[cfg(target_os = "ios")]
            write_ios_probe("backend: starting daemon on launch");
            if let Err(error) = backend.start_daemon_process() {
                backend.session_status = format!("Daemon start failed: {error}");
            }
            backend.sync_daemon_state();
            #[cfg(target_os = "ios")]
            write_ios_probe("backend: launch daemon sync complete");
        } else if wants_background_start && defer_to_installed_service && !backend.daemon_running {
            backend.session_status = "Waiting for background service to start".to_string();
        } else if wants_background_start && backend.gui_requires_service_install() {
            backend.session_status = gui_service_setup_status_text(wants_autoconnect).to_string();
        } else if wants_background_start && backend.gui_requires_service_enable() {
            backend.session_status = gui_service_enable_status_text(wants_autoconnect).to_string();
        }

        #[cfg(target_os = "ios")]
        if ios_force_connect_requested() {
            backend.force_connect_pending = true;
            write_ios_probe("backend: force connect deferred until first tick");
        }

        #[cfg(target_os = "ios")]
        write_ios_probe("backend: new complete");
        Ok(backend)
    }

    fn persist_config(&mut self) -> Result<PersistConfigOutcome> {
        if self.config.nostr.relays.is_empty() {
            return Err(anyhow!("at least one relay is required"));
        }

        self.config.ensure_defaults();
        maybe_autoconfigure_node(&mut self.config);

        #[cfg(target_os = "windows")]
        {
            self.refresh_windows_config_path()?;
            if windows_should_use_daemon_owned_config_apply(
                &self.config_path,
                windows_program_data_dir().as_deref(),
                self.daemon_running,
                self.service_installed,
            ) {
                match self.persist_config_via_running_daemon() {
                    Ok(()) => {
                        self.ensure_relay_status_entries();
                        self.ensure_peer_status_entries();
                        return Ok(PersistConfigOutcome::ReloadedRunningDaemon);
                    }
                    Err(error) => {
                        eprintln!(
                            "gui: daemon-backed config apply failed, falling back to direct save: {error}"
                        );
                    }
                }
            }
        }

        if let Err(error) = self.config.save(&self.config_path) {
            #[cfg(target_os = "windows")]
            {
                if requires_admin_privileges_error(&error) {
                    self.persist_config_with_admin_privileges()?;
                } else {
                    return Err(error);
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                return Err(error);
            }
        }
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        Ok(PersistConfigOutcome::SavedLocally)
    }

    fn persist_config_without_daemon_reload(&mut self) -> Result<()> {
        let _ = self.persist_config()?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn persist_config_via_running_daemon(&mut self) -> Result<()> {
        let temp_path = windows_temp_config_import_path();
        self.config.save(&temp_path).with_context(|| {
            format!(
                "failed to stage config for daemon import {}",
                temp_path.display()
            )
        })?;

        let result = (|| {
            let source = temp_path
                .to_str()
                .ok_or_else(|| anyhow!("temp config path is not valid UTF-8"))?;
            let target = self
                .config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?
                .to_string();
            let args = windows_daemon_config_import_args(source, target.as_str());
            let mut output = self.run_nvpn_command(args)?;

            if !output.status.success() {
                let failure = windows_nvpn_command_failure("apply-config-daemon", &output);
                if windows_daemon_apply_requires_service_repair(&failure) {
                    eprintln!(
                        "gui: daemon-backed config apply detected stale Windows service; reinstalling service and retrying"
                    );
                    self.reinstall_windows_system_service()?;
                    self.invalidate_service_status_cache();
                    output = self.run_nvpn_command(args)?;
                }
            }

            if output.status.success() {
                Ok(())
            } else {
                let failure = windows_nvpn_command_failure("apply-config-daemon", &output);
                if requires_admin_privileges(&failure) {
                    self.run_nvpn_command_with_admin_privileges(args)?;
                    Ok(())
                } else {
                    Err(anyhow!("{failure}"))
                }
            }
        })();

        let _ = fs::remove_file(&temp_path);
        result
    }

    #[cfg(target_os = "windows")]
    fn persist_config_with_admin_privileges(&self) -> Result<()> {
        let temp_path = windows_temp_config_import_path();
        self.config.save(&temp_path).with_context(|| {
            format!(
                "failed to stage config for elevated import {}",
                temp_path.display()
            )
        })?;

        let result = (|| {
            let source = temp_path
                .to_str()
                .ok_or_else(|| anyhow!("temp config path is not valid UTF-8"))?;
            let target = self
                .config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
            self.run_nvpn_command_with_admin_privileges(windows_elevated_config_import_args(
                source, target,
            ))
        })();

        let _ = fs::remove_file(&temp_path);
        result
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

    fn daemon_config_path_arg(&self) -> Result<&str> {
        self.config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))
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

    fn install_system_service(&mut self) -> Result<()> {
        let runtime = current_runtime_capabilities();
        if !runtime.vpn_session_control_supported {
            return Err(anyhow!(runtime.runtime_status_detail));
        }
        if !self.service_supported {
            return Err(anyhow!(self.service_status_detail.clone()));
        }
        #[cfg(target_os = "windows")]
        let args = [
            "service",
            "install",
            "--force",
            "--config",
            self.config_path
                .to_str()
                .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?,
        ];

        #[cfg(not(target_os = "windows"))]
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
            self.invalidate_service_status_cache();
            #[cfg(target_os = "windows")]
            self.reload_preferred_windows_config_path()?;
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
            self.invalidate_service_status_cache();
            #[cfg(target_os = "windows")]
            self.reload_preferred_windows_config_path()?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "windows")]
    fn reinstall_windows_system_service(&self) -> Result<()> {
        let config_path = self
            .config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
        let args = ["service", "install", "--force", "--config", config_path];
        let output = self.run_nvpn_command(args)?;

        if output.status.success() {
            return Ok(());
        }

        let message = windows_nvpn_command_failure("service install", &output);
        if requires_admin_privileges(&message) {
            self.run_nvpn_command_with_admin_privileges(args)?;
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn uninstall_system_service(&mut self) -> Result<()> {
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
            self.invalidate_service_status_cache();
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
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn enable_system_service(&mut self) -> Result<()> {
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
            self.invalidate_service_status_cache();
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
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    fn disable_system_service(&mut self) -> Result<()> {
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
            self.invalidate_service_status_cache();
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
            self.invalidate_service_status_cache();
            return Ok(());
        }

        Err(anyhow!(message))
    }

    #[cfg(target_os = "windows")]
    fn reload_preferred_windows_config_path(&mut self) -> Result<()> {
        let preferred_path = default_config_path();
        if preferred_path == self.config_path {
            return Ok(());
        }

        if preferred_path.exists() {
            let mut config = AppConfig::load(&preferred_path)
                .with_context(|| format!("failed to load config {}", preferred_path.display()))?;
            config.ensure_defaults();
            maybe_autoconfigure_node(&mut config);
            self.config = config;
        }
        self.config_path = preferred_path;
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn refresh_windows_config_path(&mut self) -> Result<()> {
        self.reload_preferred_windows_config_path()
    }

    #[cfg(not(target_os = "windows"))]
    fn refresh_windows_config_path(&mut self) -> Result<()> {
        Ok(())
    }

    fn reload_config_from_disk_if_present(&mut self) {
        if !self.config_path.exists() {
            return;
        }

        let mut config = match AppConfig::load(&self.config_path) {
            Ok(config) => config,
            Err(error) => {
                eprintln!(
                    "gui: failed to reload config from {}: {error}",
                    self.config_path.display()
                );
                return;
            }
        };
        config.ensure_defaults();
        maybe_autoconfigure_node(&mut config);
        self.config = config;
        self.ensure_relay_status_entries();
        self.ensure_peer_status_entries();
    }

    #[cfg(target_os = "android")]
    fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let (running, state) = self.android_session.status();
        Ok(CliStatusResponse {
            daemon: CliDaemonStatus { running, state },
        })
    }

    #[cfg(target_os = "ios")]
    fn fetch_cli_status(&self) -> Result<CliStatusResponse> {
        let status = ios_vpn::status()?;
        Ok(CliStatusResponse {
            daemon: CliDaemonStatus {
                running: status.active,
                state: status.state,
            },
        })
    }

    #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
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

    fn run_nvpn_command<const N: usize>(&self, args: [&str; N]) -> Result<std::process::Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {} or install nvpn in PATH",
                NVPN_BIN_ENV
            ));
        };

        let mut command = ProcessCommand::new(nvpn_bin);
        apply_windows_subprocess_flags(&mut command)
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
            let normalized_args = normalize_windows_elevated_args(args);
            let status = runas::Command::new(nvpn_bin)
                .args(&normalized_args)
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
        if let Err(error) = self.refresh_windows_config_path() {
            eprintln!("gui: failed to refresh Windows config path: {error}");
        }
        self.reload_config_from_disk_if_present();
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
                status.tx_bytes = 0;
                status.rx_bytes = 0;
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
                    status.runtime_endpoint = None;
                    status.tx_bytes = 0;
                    status.rx_bytes = 0;
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

        #[cfg(target_os = "ios")]
        {
            self.magic_dns_status = if self.session_active {
                "iOS tunnel is active; MagicDNS is not wired yet".to_string()
            } else {
                "DNS unchanged (VPN off)".to_string()
            };
        }

        #[cfg(all(not(target_os = "android"), not(target_os = "ios")))]
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

    fn refresh_relay_runtime_status(&mut self) {
        for relay in &self.config.nostr.relays {
            let entry = self.relay_status.entry(relay.clone()).or_default();

            if !self.session_active {
                entry.state = "unknown".to_string();
                entry.status_text = "not checked".to_string();
            } else if self.relay_connected {
                entry.state = "up".to_string();
                entry.status_text = "connected".to_string();
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
                status.runtime_endpoint = None;
                status.tx_bytes = 0;
                status.rx_bytes = 0;
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
                status.runtime_endpoint = None;
                status.tx_bytes = 0;
                status.rx_bytes = 0;
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
                status.runtime_endpoint = None;
                status.tx_bytes = 0;
                status.rx_bytes = 0;
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
            status.runtime_endpoint = peer.runtime_endpoint.clone();
            status.tx_bytes = peer.tx_bytes;
            status.rx_bytes = peer.rx_bytes;
            let daemon_handshake_at = peer.last_handshake_at.and_then(epoch_secs_to_system_time);
            status.last_handshake_at = if daemon_handshake_at.is_some() {
                daemon_handshake_at
            } else if effective_reachable {
                previous_handshake_at.or(Some(now))
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
        is_admin: bool,
    ) -> ParticipantView {
        let tunnel_ip =
            derive_mesh_tunnel_ip(network_id, participant).unwrap_or_else(|| "-".to_string());
        let is_local = Some(participant) == own_pubkey_hex;
        let transport_state = self.peer_state_for(participant, own_pubkey_hex);
        let presence_state = self.peer_presence_state_for(participant, own_pubkey_hex);
        let status_text = self.peer_status_line(participant, transport_state);
        let last_signal_text = self.peer_presence_line(participant, own_pubkey_hex);
        let link = self.peer_status.get(participant);
        let relay_path_active = link.is_some_and(peer_link_uses_relay_path);
        let runtime_endpoint = link
            .and_then(|status| status.runtime_endpoint.clone())
            .unwrap_or_default();
        let tx_bytes = link.map(|status| status.tx_bytes).unwrap_or(0);
        let rx_bytes = link.map(|status| status.rx_bytes).unwrap_or(0);
        let (magic_dns_alias, magic_dns_name) = if is_local {
            (
                self.config.self_magic_dns_label().unwrap_or_default(),
                self.config.self_magic_dns_name().unwrap_or_default(),
            )
        } else {
            (
                self.config.peer_alias(participant).unwrap_or_default(),
                self.config
                    .magic_dns_name_for_participant(participant)
                    .unwrap_or_default(),
            )
        };
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
            is_admin,
            tunnel_ip,
            magic_dns_alias,
            magic_dns_name,
            relay_path_active,
            runtime_endpoint,
            tx_bytes,
            rx_bytes,
            advertised_routes,
            offers_exit_node,
            state: peer_state_label(transport_state).to_string(),
            presence_state: peer_presence_state_label(presence_state).to_string(),
            status_text,
            last_signal_text,
        }
    }

    fn outbound_join_request_view(
        &self,
        request: &PendingOutboundJoinRequest,
    ) -> OutboundJoinRequestView {
        OutboundJoinRequestView {
            recipient_npub: to_npub(&request.recipient),
            recipient_pubkey_hex: request.recipient.clone(),
            requested_at_text: join_request_age_text(request.requested_at),
        }
    }

    fn inbound_join_request_views(
        &self,
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

    fn network_rows(&self) -> Vec<NetworkView> {
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().ok();
        let mut rows = Vec::with_capacity(self.config.networks.len());

        for network in &self.config.networks {
            let mut participants = network.participants.clone();
            participants.sort();
            participants.dedup();
            let own_is_admin = own_pubkey_hex
                .as_deref()
                .map(|pubkey| network.admins.iter().any(|admin| admin == pubkey))
                .unwrap_or(false);
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
                    self.participant_view(
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
                network_id: normalize_runtime_network_id(&network.network_id),
                local_is_admin: own_is_admin,
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
                    .map(|request| self.outbound_join_request_view(request)),
                inbound_join_requests: self
                    .inbound_join_request_views(&network.inbound_join_requests),
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
        format!("nostr seen {}", compact_age_text(age_secs))
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

                if peer_link_uses_relay_path(link) {
                    let runtime_endpoint = link.runtime_endpoint.as_deref().unwrap_or_default();
                    return format!(
                        "online via relay {}",
                        shorten_middle(runtime_endpoint, 18, 10)
                    );
                }

                let handshake_age = link
                    .last_handshake_at
                    .and_then(|handshake_at| handshake_at.elapsed().ok())
                    .map(|elapsed| elapsed.as_secs());

                match handshake_age {
                    Some(age_secs) => format!("online (handshake {})", compact_age_text(age_secs)),
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
                                "offline ({}, {})",
                                shorten_middle(error, 18, 8),
                                compact_age_text(age_secs)
                            )
                        }
                        None => format!("offline ({})", shorten_middle(error, 18, 8)),
                    }
                } else {
                    match checked_age {
                        Some(age_secs) => format!("offline ({})", compact_age_text(age_secs)),
                        None => "offline".to_string(),
                    }
                }
            }
            ConfiguredPeerStatus::Unknown => "unknown".to_string(),
        }
    }

    fn tick(&mut self) {
        self.refresh_lan_pairing();
        self.clear_connected_join_requests();
        self.maybe_perform_pending_launch_action();
        self.sync_daemon_state();
        self.refresh_relay_operator_state();
        self.clear_connected_join_requests();
    }

    fn maybe_perform_pending_launch_action(&mut self) {
        match pending_launch_action(self.launch_start_pending, self.force_connect_pending) {
            PendingLaunchAction::None => {}
            PendingLaunchAction::StartDaemon => {
                #[cfg(target_os = "ios")]
                write_ios_probe("backend: starting pending launch daemon");
                self.launch_start_pending = false;
                if let Err(error) = self.start_daemon_process() {
                    self.session_status = format!("Daemon start failed: {error}");
                    #[cfg(target_os = "ios")]
                    write_ios_probe(format!("backend: pending launch daemon failed: {error}"));
                } else {
                    #[cfg(target_os = "ios")]
                    write_ios_probe("backend: pending launch daemon started");
                }
            }
            PendingLaunchAction::ForceConnect => {
                #[cfg(target_os = "ios")]
                write_ios_probe("backend: starting pending force connect");
                self.launch_start_pending = false;
                self.force_connect_pending = false;
                if let Err(error) = self.connect_session() {
                    self.session_status = format!("Daemon start failed: {error}");
                    #[cfg(target_os = "ios")]
                    write_ios_probe(format!("backend: pending force connect failed: {error}"));
                } else {
                    #[cfg(target_os = "ios")]
                    write_ios_probe("backend: pending force connect complete");
                }
            }
        }
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
        let daemon_binary_version = self
            .daemon_state
            .as_ref()
            .map(|state| state.binary_version.clone())
            .unwrap_or_default();
        let endpoint = self
            .daemon_state
            .as_ref()
            .and_then(|state| {
                let endpoint = state.advertised_endpoint.trim();
                (!endpoint.is_empty()).then(|| endpoint.to_string())
            })
            .unwrap_or_else(|| self.config.node.endpoint.clone());
        let listen_port = self
            .daemon_state
            .as_ref()
            .and_then(|state| (state.listen_port > 0).then_some(state.listen_port))
            .unwrap_or(self.config.node.listen_port);

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
            daemon_binary_version,
            service_binary_version: self.service_binary_version.clone(),
            config_path: self.config_path.display().to_string(),
            own_npub,
            own_pubkey_hex,
            network_id: self.config.effective_network_id(),
            active_network_invite: active_network_invite_code(&self.config).unwrap_or_default(),
            node_id: self.config.node.id.clone(),
            node_name: self.config.node_name.clone(),
            self_magic_dns_name: self.config.self_magic_dns_name().unwrap_or_default(),
            endpoint,
            tunnel_ip: self.config.node.tunnel_ip.clone(),
            listen_port,
            exit_node: self
                .npub_or_none(&self.config.exit_node)
                .unwrap_or_default(),
            advertise_exit_node: self.config.node.advertise_exit_node,
            advertised_routes: self.config.node.advertised_routes.clone(),
            effective_advertised_routes: self.config.effective_advertised_routes(),
            use_public_relay_fallback: self.config.use_public_relay_fallback,
            relay_for_others: self.config.relay_for_others,
            provide_nat_assist: self.config.provide_nat_assist,
            relay_operator_running: self
                .daemon_state
                .as_ref()
                .map(|state| state.relay_operator_running)
                .unwrap_or(false),
            relay_operator_status: self
                .daemon_state
                .as_ref()
                .map(|state| state.relay_operator_status.clone())
                .unwrap_or_else(|| {
                    if self.config.relay_for_others {
                        "Relay operator starts with the daemon".to_string()
                    } else {
                        "Relay operator disabled".to_string()
                    }
                }),
            nat_assist_running: self
                .daemon_state
                .as_ref()
                .map(|state| state.nat_assist_running)
                .unwrap_or(false),
            nat_assist_status: self
                .daemon_state
                .as_ref()
                .map(|state| state.nat_assist_status.clone())
                .unwrap_or_else(|| {
                    if self.config.provide_nat_assist {
                        "NAT assist starts with the daemon".to_string()
                    } else {
                        "NAT assist disabled".to_string()
                    }
                }),
            magic_dns_suffix: self.config.magic_dns_suffix.clone(),
            magic_dns_status: self.magic_dns_status.clone(),
            autoconnect: self.config.autoconnect,
            lan_pairing_active: self.lan_pairing_running && self.lan_pairing_remaining_secs() > 0,
            lan_pairing_remaining_secs: self.lan_pairing_remaining_secs(),
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
            relay_operator: self.relay_operator_view(),
            lan_peers: self.lan_peer_rows(),
        }
    }

    fn tray_runtime_state(&self) -> TrayRuntimeState {
        let networks = self.network_rows();
        let service_setup_required = self.gui_requires_service_install();
        let service_enable_required = self.gui_requires_service_enable();
        let this_device_tunnel_ip = display_tunnel_ip(&self.config.node.tunnel_ip);

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
            this_device_text: format!(
                "This Device: {} ({})",
                self.config.node_name, this_device_tunnel_ip
            ),
            this_device_copy_value: if this_device_tunnel_ip == "-" {
                String::new()
            } else {
                this_device_tunnel_ip
            },
            advertise_exit_node: self.config.node.advertise_exit_node,
            network_groups: tray_network_groups(&networks),
            exit_nodes: tray_exit_node_entries(&networks, &self.config.exit_node),
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "ios")]
    reset_ios_probe();
    #[cfg(target_os = "ios")]
    write_ios_probe("run: entry");

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        #[cfg(target_os = "ios")]
        {
            tracing_subscriber::EnvFilter::new("info,wry=trace,tauri=trace")
        }
        #[cfg(not(target_os = "ios"))]
        {
            tracing_subscriber::EnvFilter::new("warn")
        }
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let launched_from_autostart = started_from_autostart();
    let automation_enabled = tauri_automation_enabled();
    if !automation_enabled {
        match resolve_gui_launch_conflicts(launched_from_autostart) {
            Ok(GuiLaunchDisposition::Continue { terminate_pids }) => {
                terminate_gui_instances(&terminate_pids);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Ok(GuiLaunchDisposition::Exit) => return,
            Err(error) => {
                eprintln!("gui: failed to resolve GUI launch conflicts: {error}");
            }
        }
    }
    let builder = tauri::Builder::default();
    #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
    let builder = if automation_enabled {
        builder
    } else {
        builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let deep_link_urls = extract_app_deep_links_from_args(args.iter());
            if !deep_link_urls.is_empty()
                && let Err(error) = import_network_invites_from_deep_links(
                    app,
                    deep_link_urls.iter().map(|url| url.as_str()),
                )
            {
                eprintln!("deep-link: failed to import existing-instance URL: {error:#}");
            }
            if should_surface_existing_instance_args(args.iter()) {
                let _ = show_main_window(app);
            }
        }))
    };
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android_vpn::Builder::new().build());
    let builder = if automation_enabled {
        builder
    } else {
        builder.plugin(tauri_plugin_deep_link::init())
    };
    let app = builder
        .on_page_load(|webview, payload| {
            #[cfg(not(target_os = "ios"))]
            let _ = (&webview, &payload);
            #[cfg(target_os = "ios")]
            {
                eprintln!(
                    "gui: page load event={:?} label={} url={}",
                    payload.event(),
                    webview.label(),
                    payload.url()
                );
                write_ios_probe(format!(
                    "page_load: event={:?} label={} url={}",
                    payload.event(),
                    webview.label(),
                    payload.url()
                ));
            }
        })
        .setup(move |app| {
            #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
            let _ = app;

            #[cfg(target_os = "ios")]
            {
                eprintln!("gui: setup begin");
                write_ios_probe("setup: begin");
            }
            let config_path = resolve_backend_config_path(app.handle())
                .context("failed to resolve GUI config path")?;
            #[cfg(target_os = "ios")]
            {
                eprintln!("gui: setup resolved config path={}", config_path.display());
                write_ios_probe(format!("setup: config_path={}", config_path.display()));
            }
            let backend =
                NvpnBackend::new(app.handle().clone(), config_path, launched_from_autostart)
                    .context("failed to initialize GUI backend state")?;
            #[cfg(target_os = "ios")]
            {
                eprintln!("gui: setup backend initialized");
                write_ios_probe("setup: backend initialized");
            }
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            let launch_on_startup_default = backend.config.launch_on_startup;
            let initial_tray_state = backend.tray_runtime_state();
            #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
            let setup_tray_state = initial_tray_state.clone();
            if !app.manage(AppState {
                backend: Arc::new(Mutex::new(backend)),
                last_tray_runtime_state: Arc::new(Mutex::new(initial_tray_state)),
            }) {
                return Err(anyhow!("application state already initialized").into());
            }
            #[cfg(target_os = "ios")]
            {
                eprintln!("gui: setup state managed");
                write_ios_probe("setup: state managed");
            }

            if !automation_enabled {
                #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
                app.deep_link().register_all()?;

                #[cfg(target_os = "ios")]
                {
                    eprintln!("gui: setup querying deep links");
                    write_ios_probe("setup: querying deep links");
                }
                let mut startup_urls = extract_app_deep_links_from_args(env::args());
                if let Some(urls) = app.deep_link().get_current()? {
                    for url in urls {
                        let url = url.as_str().trim();
                        if url.is_empty() || startup_urls.iter().any(|existing| existing == url) {
                            continue;
                        }
                        startup_urls.push(url.to_string());
                    }
                }
                if !startup_urls.is_empty()
                    && let Err(error) = import_network_invites_from_deep_links(
                        app.handle(),
                        startup_urls.iter().map(|url| url.as_str()),
                    )
                {
                    eprintln!("deep-link: failed to import startup URL: {error:#}");
                }

                let deep_link_handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    if let Err(error) = import_network_invites_from_deep_links(
                        &deep_link_handle,
                        event.urls().iter().map(|url| url.as_str()),
                    ) {
                        eprintln!("deep-link: failed to import open URL: {error:#}");
                    }
                });
                #[cfg(target_os = "ios")]
                {
                    eprintln!("gui: setup deep-link handlers ready");
                    write_ios_probe("setup: deep-link handlers ready");
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
                                TRAY_THIS_DEVICE_MENU_ID => {
                                    let runtime_state = current_tray_runtime_state(app);
                                    if let Err(error) = copy_text_to_clipboard(
                                        &runtime_state.this_device_copy_value,
                                    ) {
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
            } else {
                eprintln!("gui: automation mode active, skipping desktop shell integrations");
            }

            #[cfg(target_os = "ios")]
            {
                eprintln!("gui: setup complete");
                write_ios_probe("setup: complete");
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
            set_network_join_requests_enabled,
            request_network_join,
            add_participant,
            add_admin,
            import_network_invite,
            start_lan_pairing,
            stop_lan_pairing,
            remove_participant,
            remove_admin,
            accept_join_request,
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
    use base64::Engine as _;

    use super::{
        ConfiguredPeerStatus, DaemonPeerState, DaemonRuntimeState, GuiLaunchDisposition,
        IOS_TAURI_ORIGIN, LAN_PAIRING_ANNOUNCEMENT_VERSION, LAN_PAIRING_DURATION_SECS,
        NETWORK_INVITE_PREFIX, NetworkInvite, NetworkView, NvpnBackend, ParticipantView,
        PeerPresenceStatus, PendingLaunchAction, RuntimePlatform, SettingsPatch,
        TRAY_EXIT_NODE_NONE_MENU_ID, TRAY_RUN_EXIT_NODE_MENU_ID, TRAY_THIS_DEVICE_MENU_ID,
        TRAY_VPN_TOGGLE_MENU_ID, TrayMenuItemSpec, TrayRuntimeState, active_network_invite_code,
        apply_network_invite_to_active_network, bundled_nvpn_candidate_paths,
        cli_binary_installed_at, config_path_from_roots, decode_lan_pairing_announcement,
        desktop_config_path_from_roots, epoch_secs_to_system_time, expected_peer_count,
        extract_json_document, gui_launch_disposition, gui_requires_service_enable,
        gui_requires_service_install, ios_runtime_status_detail, ios_vpn_session_control_supported,
        is_already_running_message, is_mesh_complete, is_not_running_message, network_device_count,
        network_online_device_count, parse_advertised_routes_input, parse_exit_node_input,
        parse_network_invite, parse_running_gui_instances, peer_offers_exit_node,
        peer_presence_state_label, peer_state_label, pending_launch_action,
        run_blocking_mutex_action, runtime_capabilities_for_platform,
        should_defer_gui_daemon_start_to_service_on_autostart,
        should_defer_gui_daemon_start_until_first_tick, should_start_gui_daemon_on_launch,
        should_surface_existing_instance_args, started_from_autostart_args,
        strip_windows_verbatim_prefix, tauri_protocol_request_path, to_npub,
        tray_exit_node_entries, tray_menu_spec, tray_network_groups, tray_status_text,
        tray_vpn_status_menu_text, tray_vpn_toggle_text, validate_nvpn_binary,
        windows_daemon_config_import_args, windows_elevated_config_import_args,
        windows_should_start_installed_service, windows_should_use_daemon_owned_config_apply,
        within_peer_online_grace, within_peer_presence_grace,
    };
    use nostr_vpn_core::config::{
        AppConfig, PendingInboundJoinRequest, PendingOutboundJoinRequest,
    };
    use nostr_vpn_core::relay::{RelayOperatorSessionState, RelayOperatorState};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::runtime::Runtime;

    fn unique_test_config_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "nvpn-gui-test-{}-{}.toml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        ))
    }

    fn relay_state_path(config_path: &Path) -> PathBuf {
        config_path.with_file_name("relay.operator.json")
    }

    fn test_backend(participant: &str) -> NvpnBackend {
        let mut config = AppConfig::generated();
        config.networks[0].participants = vec![participant.to_string()];

        NvpnBackend {
            runtime: Runtime::new().expect("test runtime"),
            config_path: unique_test_config_path(),
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
            service_binary_version: String::new(),
            last_service_status_refresh_at: None,
            daemon_state: None,
            relay_operator_state: None,
            launch_start_pending: false,
            force_connect_pending: false,
            relay_status: HashMap::new(),
            peer_status: HashMap::new(),
            lan_pairing_running: false,
            lan_pairing_rx: None,
            lan_pairing_stop: None,
            lan_pairing_expires_at: None,
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
            runtime_endpoint: None,
            tx_bytes: 0,
            rx_bytes: 0,
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
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            local_endpoint: "192.168.1.20:51820".to_string(),
            advertised_endpoint: "198.51.100.20:53083".to_string(),
            listen_port: 53083,
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
            relay_operator_running: false,
            relay_operator_status: "Relay operator disabled".to_string(),
            nat_assist_running: false,
            nat_assist_status: "NAT assist disabled".to_string(),
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
    fn tray_vpn_menu_texts_separate_status_from_action() {
        assert_eq!(
            tray_vpn_status_menu_text("Connected"),
            "VPN Status: Connected"
        );
        assert_eq!(tray_vpn_toggle_text(true), "Turn VPN Off");
        assert_eq!(tray_vpn_toggle_text(false), "Turn VPN On");
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
        config.node_name = "sirius-mini".to_string();
        config.networks[0].name = "Home".to_string();
        config.networks[0].network_id = "mesh-home".to_string();
        config.networks[0].admins = vec![inviter_hex.clone()];
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
                v: 2,
                network_name: "Home".to_string(),
                network_id: "mesh-home".to_string(),
                inviter_npub,
                inviter_node_name: "sirius-mini".to_string(),
                admins: vec![to_npub(&inviter_hex)],
                participants: vec![to_npub(&inviter_hex)],
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
            v: 2,
            network_name: "Home".to_string(),
            network_id: "mesh-home".to_string(),
            inviter_npub: to_npub(&inviter_hex),
            inviter_node_name: "macbook-pro".to_string(),
            admins: vec![to_npub(&inviter_hex)],
            participants: vec![to_npub(&inviter_hex)],
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
            config
                .magic_dns_name_for_participant(&config.participant_pubkeys_hex()[0])
                .as_deref(),
            Some("macbook-pro.nvpn")
        );
        assert_eq!(
            config.nostr.relays,
            vec![
                "wss://existing.example".to_string(),
                "wss://invite.example".to_string(),
            ]
        );
    }

    #[test]
    fn applying_network_invite_reuses_existing_matching_network_and_activates_it() {
        let work_peer_hex = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("work peer hex");
        let work_peer_npub = to_npub(&work_peer_hex);
        let home_peer_hex = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("home peer hex");
        let home_peer_npub = to_npub(&home_peer_hex);
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let invite = NetworkInvite {
            v: 2,
            network_name: "Home".to_string(),
            network_id: "mesh-home".to_string(),
            inviter_npub: to_npub(&inviter_hex),
            inviter_node_name: String::new(),
            admins: vec![to_npub(&inviter_hex)],
            participants: vec![to_npub(&inviter_hex)],
            relays: vec!["wss://invite.example".to_string()],
        };
        let mut config = AppConfig::generated();
        let work_id = config.networks[0].id.clone();
        config.networks[0].name = "Work".to_string();
        config
            .set_active_network_id("mesh-work")
            .expect("work mesh id");
        config
            .add_participant_to_network(&work_id, &work_peer_npub)
            .expect("work peer");
        let home_id = config.add_network("Home");
        config
            .set_network_mesh_id(&home_id, "mesh-home")
            .expect("home mesh id");
        config
            .add_participant_to_network(&home_id, &home_peer_npub)
            .expect("home peer");

        apply_network_invite_to_active_network(&mut config, &invite).expect("invite should apply");

        let work = config.network_by_id(&work_id).expect("work network exists");
        let home = config.network_by_id(&home_id).expect("home network exists");

        assert!(!work.enabled);
        assert_eq!(work.name, "Work");
        assert_eq!(work.network_id, "mesh-work");
        assert_eq!(work.participants, vec![work_peer_hex]);

        assert!(home.enabled);
        assert_eq!(home.name, "Home");
        assert_eq!(home.network_id, "mesh-home");
        let mut expected_participants = vec![home_peer_hex, inviter_hex];
        expected_participants.sort();
        assert_eq!(home.participants, expected_participants);
        assert_eq!(config.effective_network_id(), "mesh-home");
    }

    #[test]
    fn applying_network_invite_creates_new_network_when_active_network_is_populated() {
        let work_peer_hex = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("work peer hex");
        let work_peer_npub = to_npub(&work_peer_hex);
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let invite = NetworkInvite {
            v: 2,
            network_name: "Home".to_string(),
            network_id: "mesh-home".to_string(),
            inviter_npub: to_npub(&inviter_hex),
            inviter_node_name: String::new(),
            admins: vec![to_npub(&inviter_hex)],
            participants: vec![to_npub(&inviter_hex)],
            relays: vec!["wss://invite.example".to_string()],
        };
        let mut config = AppConfig::generated();
        let work_id = config.networks[0].id.clone();
        config.networks[0].name = "Work".to_string();
        config
            .set_active_network_id("mesh-work")
            .expect("work mesh id");
        config
            .add_participant_to_network(&work_id, &work_peer_npub)
            .expect("work peer");

        apply_network_invite_to_active_network(&mut config, &invite).expect("invite should apply");

        assert_eq!(config.networks.len(), 2);

        let work = config.network_by_id(&work_id).expect("work network exists");
        let home = config
            .networks
            .iter()
            .find(|network| network.id != work_id)
            .expect("home network exists");

        assert!(!work.enabled);
        assert_eq!(work.name, "Work");
        assert_eq!(work.network_id, "mesh-work");
        assert_eq!(work.participants, vec![work_peer_hex]);

        assert!(home.enabled);
        assert_eq!(home.name, "Home");
        assert_eq!(home.network_id, "mesh-home");
        assert_eq!(home.participants, vec![inviter_hex]);
        assert_eq!(config.effective_network_id(), "mesh-home");
    }

    #[test]
    fn applying_network_invite_tracks_inviter_for_join_requests() {
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let invite = NetworkInvite {
            v: 2,
            network_name: "Home".to_string(),
            network_id: "mesh-home".to_string(),
            inviter_npub: to_npub(&inviter_hex),
            inviter_node_name: String::new(),
            admins: vec![to_npub(&inviter_hex)],
            participants: vec![to_npub(&inviter_hex)],
            relays: vec!["wss://invite.example".to_string()],
        };
        let mut config = AppConfig::generated();

        apply_network_invite_to_active_network(&mut config, &invite).expect("invite should apply");

        let network = config.active_network();
        assert!(network.listen_for_join_requests);
        assert_eq!(network.invite_inviter, inviter_hex);
    }

    #[test]
    fn decode_lan_pairing_announcement_extracts_invite_metadata() {
        let inviter_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let inviter_npub = to_npub(&inviter_hex);
        let invite = format!(
            "{NETWORK_INVITE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&NetworkInvite {
                    v: 1,
                    network_name: "Home".to_string(),
                    network_id: "mesh-home".to_string(),
                    inviter_npub: inviter_npub.clone(),
                    inviter_node_name: String::new(),
                    admins: Vec::new(),
                    participants: Vec::new(),
                    relays: vec!["wss://relay.one.example".to_string()],
                })
                .expect("invite payload"),
            )
        );
        let payload = serde_json::to_vec(&super::LanAnnouncement {
            v: LAN_PAIRING_ANNOUNCEMENT_VERSION,
            npub: inviter_npub.clone(),
            node_name: "home-server".to_string(),
            endpoint: "192.168.1.20:51820".to_string(),
            invite: invite.clone(),
            timestamp: 123,
        })
        .expect("announcement payload");

        let parsed =
            decode_lan_pairing_announcement(&payload, "npub1self").expect("announcement parses");

        assert_eq!(parsed.npub, inviter_npub);
        assert_eq!(parsed.node_name, "home-server");
        assert_eq!(parsed.endpoint, "192.168.1.20:51820");
        assert_eq!(parsed.network_name, "Home");
        assert_eq!(parsed.network_id, "mesh-home");
        assert_eq!(parsed.invite, invite);
    }

    #[test]
    fn decode_lan_pairing_announcement_rejects_invites_for_other_identities() {
        let announcer_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let other_hex =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        let payload = serde_json::to_vec(&super::LanAnnouncement {
            v: LAN_PAIRING_ANNOUNCEMENT_VERSION,
            npub: to_npub(&announcer_hex),
            node_name: "home-server".to_string(),
            endpoint: "192.168.1.20:51820".to_string(),
            invite: format!(
                "{NETWORK_INVITE_PREFIX}{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&NetworkInvite {
                        v: 1,
                        network_name: "Home".to_string(),
                        network_id: "mesh-home".to_string(),
                        inviter_npub: to_npub(&other_hex),
                        inviter_node_name: String::new(),
                        admins: Vec::new(),
                        participants: Vec::new(),
                        relays: vec!["wss://relay.one.example".to_string()],
                    })
                    .expect("invite payload"),
                )
            ),
            timestamp: 123,
        })
        .expect("announcement payload");

        assert!(decode_lan_pairing_announcement(&payload, "npub1self").is_none());
    }

    #[test]
    fn lan_pairing_start_sets_countdown_and_expiry_stops_it() {
        let participant = "44".repeat(32);
        let mut backend = test_backend(&participant);

        backend.start_lan_pairing().expect("pairing should start");
        let pairing_ui = backend.ui_state();

        assert!(pairing_ui.lan_pairing_active);
        assert!(pairing_ui.lan_pairing_remaining_secs > 0);
        assert!(pairing_ui.lan_pairing_remaining_secs <= LAN_PAIRING_DURATION_SECS);

        backend.lan_pairing_expires_at = Some(SystemTime::now() - Duration::from_secs(1));
        backend.tick();
        let expired_ui = backend.ui_state();

        assert!(!expired_ui.lan_pairing_active);
        assert_eq!(expired_ui.lan_pairing_remaining_secs, 0);
        assert!(backend.lan_peers.is_empty());
    }

    #[test]
    fn network_rows_include_join_request_metadata() {
        let inviter = "66".repeat(32);
        let requester = "77".repeat(32);
        let mut backend = test_backend(&inviter);
        backend.config.networks[0].invite_inviter = inviter.clone();
        backend.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: inviter.clone(),
            requested_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_secs(),
        });
        backend.config.networks[0].inbound_join_requests = vec![PendingInboundJoinRequest {
            requester: requester.clone(),
            requester_node_name: "alice-phone".to_string(),
            requested_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_secs(),
        }];

        let rows = backend.network_rows();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].invite_inviter_npub, to_npub(&inviter));
        assert!(rows[0].outbound_join_request.is_some());
        assert_eq!(rows[0].inbound_join_requests.len(), 1);
        assert_eq!(
            rows[0].inbound_join_requests[0].requester_npub,
            to_npub(&requester)
        );
        assert_eq!(
            rows[0].inbound_join_requests[0].requester_node_name,
            "alice-phone"
        );
    }

    #[test]
    fn sync_daemon_state_reloads_config_written_by_daemon() {
        let requester = "77".repeat(32);
        let mut backend = test_backend(&"66".repeat(32));
        let config_path = std::env::temp_dir().join(format!(
            "nvpn-gui-sync-{}-{}.toml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        ));
        backend.config_path = config_path.clone();
        backend
            .config
            .save(&config_path)
            .expect("write initial test config");

        let mut updated = backend.config.clone();
        updated.networks[0].inbound_join_requests = vec![PendingInboundJoinRequest {
            requester: requester.clone(),
            requester_node_name: "alice-phone".to_string(),
            requested_at: 1_726_000_000,
        }];
        updated
            .save(&config_path)
            .expect("write daemon-updated config");

        backend.sync_daemon_state();

        assert_eq!(backend.config.networks[0].inbound_join_requests.len(), 1);
        assert_eq!(
            backend.config.networks[0].inbound_join_requests[0].requester,
            requester
        );

        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn refresh_relay_operator_state_loads_snapshot_for_ui() {
        let participant = "66".repeat(32);
        let mut backend = test_backend(&participant);
        let state_path = relay_state_path(&backend.config_path);
        let now = super::current_unix_timestamp();
        let snapshot = RelayOperatorState {
            updated_at: now.saturating_sub(2),
            relay_pubkey: "aa".repeat(32),
            advertised_endpoint: "198.51.100.23:0".to_string(),
            total_sessions_served: 7,
            total_forwarded_bytes: 9_216,
            current_forward_bps: 1_024,
            unique_peer_count: 4,
            known_peer_pubkeys: vec!["bb".repeat(32), "cc".repeat(32)],
            active_sessions: vec![RelayOperatorSessionState {
                request_id: "relay-req-1".to_string(),
                network_id: "mesh-home".to_string(),
                requester_pubkey: "bb".repeat(32),
                target_pubkey: "cc".repeat(32),
                requester_ingress_endpoint: "198.51.100.23:41001".to_string(),
                target_ingress_endpoint: "198.51.100.23:41002".to_string(),
                started_at: now.saturating_sub(8),
                expires_at: now + 52,
                bytes_from_requester: 2_048,
                bytes_from_target: 1_024,
            }],
        };

        fs::write(
            &state_path,
            serde_json::to_vec_pretty(&snapshot).expect("serialize relay snapshot"),
        )
        .expect("write relay snapshot");

        backend.refresh_relay_operator_state();
        let ui = backend.ui_state();
        let relay = ui.relay_operator.expect("relay operator view");

        assert_eq!(relay.relay_pubkey_hex, snapshot.relay_pubkey);
        assert_eq!(relay.advertised_endpoint, "198.51.100.23:0");
        assert_eq!(relay.total_sessions_served, 7);
        assert_eq!(relay.total_forwarded_bytes, 9_216);
        assert_eq!(relay.current_forward_bps, 1_024);
        assert_eq!(relay.unique_peer_count, 4);
        assert_eq!(relay.active_session_count, 1);
        assert_eq!(relay.active_sessions.len(), 1);
        assert_eq!(relay.active_sessions[0].request_id, "relay-req-1");
        assert_eq!(relay.active_sessions[0].total_forwarded_bytes, 3_072);
        assert!(relay.active_sessions[0].started_text.ends_with("ago"));
        assert!(relay.active_sessions[0].expires_text.ends_with("left"));
        assert!(relay.updated_text.ends_with("ago"));

        let _ = fs::remove_file(state_path);
        let _ = fs::remove_file(backend.config_path.clone());
    }

    #[test]
    fn tick_keeps_pending_outbound_join_request_when_connection_predates_request() {
        let inviter = "88".repeat(32);
        let mut backend = test_backend(&inviter);
        backend.config.networks[0].invite_inviter = inviter.clone();
        let requested_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        backend.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: inviter.clone(),
            requested_at,
        });
        backend.peer_status.insert(
            inviter.clone(),
            super::PeerLinkStatus {
                reachable: Some(true),
                last_handshake_at: epoch_secs_to_system_time(requested_at),
                ..super::PeerLinkStatus::default()
            },
        );

        backend.tick();

        assert!(backend.config.networks[0].outbound_join_request.is_some());
    }

    #[test]
    fn tick_clears_pending_outbound_join_request_after_new_connection_arrives() {
        let inviter = "88".repeat(32);
        let mut backend = test_backend(&inviter);
        backend.config.networks[0].invite_inviter = inviter.clone();
        let requested_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs()
            .saturating_sub(5);
        backend.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: inviter.clone(),
            requested_at,
        });
        backend.peer_status.insert(
            inviter.clone(),
            super::PeerLinkStatus {
                reachable: Some(true),
                last_handshake_at: epoch_secs_to_system_time(requested_at.saturating_add(1)),
                ..super::PeerLinkStatus::default()
            },
        );

        backend.tick();

        assert!(backend.config.networks[0].outbound_join_request.is_none());
    }

    #[test]
    fn clearing_join_requests_keeps_existing_reachable_peer_without_new_handshake() {
        let inviter = "88".repeat(32);
        let mut backend = test_backend(&inviter);
        backend.config.networks[0].invite_inviter = inviter.clone();
        let requested_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        let previous_handshake_at = epoch_secs_to_system_time(requested_at.saturating_sub(10));
        backend.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: inviter.clone(),
            requested_at,
        });
        backend.session_active = true;
        backend.peer_status.insert(
            inviter.clone(),
            super::PeerLinkStatus {
                reachable: Some(true),
                last_handshake_at: previous_handshake_at,
                ..super::PeerLinkStatus::default()
            },
        );

        let mut peer = daemon_peer(&inviter, true, Some(0), None, "198.51.100.10:51820");
        peer.last_handshake_at = None;
        backend.daemon_state = Some(daemon_state_with_peer(Some(peer), true));

        backend.refresh_peer_runtime_status();
        backend.clear_connected_join_requests();

        assert!(backend.config.networks[0].outbound_join_request.is_some());
        assert_eq!(
            backend.peer_status[&inviter].last_handshake_at,
            previous_handshake_at
        );
    }

    #[test]
    fn clearing_join_requests_clears_when_peer_becomes_reachable_without_daemon_timestamp() {
        let inviter = "88".repeat(32);
        let mut backend = test_backend(&inviter);
        backend.config.networks[0].invite_inviter = inviter.clone();
        let requested_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs()
            .saturating_sub(5);
        backend.config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: inviter.clone(),
            requested_at,
        });
        backend.session_active = true;

        let mut peer = daemon_peer(&inviter, true, Some(0), None, "198.51.100.10:51820");
        peer.last_handshake_at = None;
        backend.daemon_state = Some(daemon_state_with_peer(Some(peer), true));

        backend.refresh_peer_runtime_status();
        backend.clear_connected_join_requests();

        assert!(backend.config.networks[0].outbound_join_request.is_none());
        assert!(
            backend.peer_status[&inviter].last_handshake_at.is_some_and(
                |value| value > epoch_secs_to_system_time(requested_at).expect("epoch")
            )
        );
    }

    #[test]
    fn record_inbound_join_request_ignores_mismatched_mesh_id() {
        let requester = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("requester pubkey");
        let mut backend = test_backend(&"88".repeat(32));
        backend.config.networks[0].network_id = "mesh-home".to_string();

        let changed = backend
            .config
            .record_inbound_join_request("mesh-other", &requester, "alice-phone", 1_726_000_000)
            .expect("record join request");

        assert!(changed.is_none());
        assert!(backend.config.networks[0].inbound_join_requests.is_empty());
    }

    #[test]
    fn accept_join_request_persists_acceptance_even_when_vpn_start_fails() {
        let owner = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("owner pubkey");
        let requester = AppConfig::generated()
            .own_nostr_pubkey_hex()
            .expect("requester pubkey");
        let mut backend = test_backend(&owner);
        backend.service_supported = true;
        backend.service_enablement_supported = true;
        backend.service_installed = false;
        backend.config.networks[0].inbound_join_requests = vec![PendingInboundJoinRequest {
            requester: requester.clone(),
            requester_node_name: "alice-phone".to_string(),
            requested_at: 1_726_000_000,
        }];

        backend
            .accept_join_request(&backend.config.networks[0].id.clone(), &to_npub(&requester))
            .expect("accept join request");

        assert!(
            backend.config.networks[0]
                .participants
                .iter()
                .any(|participant| participant == &requester)
        );
        assert_eq!(
            backend
                .config
                .magic_dns_name_for_participant(&requester)
                .as_deref(),
            Some("alice-phone.nvpn")
        );
        assert!(backend.config.networks[0].inbound_join_requests.is_empty());
        assert!(
            backend
                .session_status
                .contains("Join request accepted, but VPN start failed:")
        );
    }

    #[test]
    fn lan_peer_rows_include_invite_metadata_for_join_actions() {
        let participant = "55".repeat(32);
        let invite = format!("{NETWORK_INVITE_PREFIX}payload-123");
        let mut backend = test_backend(&participant);
        backend.lan_peers.insert(
            "npub1alice".to_string(),
            super::LanPeerRecord {
                npub: "npub1alice".to_string(),
                node_name: "alice-laptop".to_string(),
                endpoint: "192.168.1.40:51820".to_string(),
                network_name: "Home".to_string(),
                network_id: "mesh-home".to_string(),
                invite: invite.clone(),
                last_seen: SystemTime::now() - Duration::from_secs(64_000),
            },
        );

        let rows = backend.lan_peer_rows();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].network_name, "Home");
        assert_eq!(rows[0].network_id, "mesh-home");
        assert_eq!(rows[0].invite, invite);
        assert_eq!(rows[0].last_seen_text, "17h ago");
    }

    #[test]
    fn compact_age_text_uses_larger_units_for_longer_durations() {
        assert_eq!(super::compact_age_text(59), "59s ago");
        assert_eq!(super::compact_age_text(60), "1m ago");
        assert_eq!(super::compact_age_text(3_600), "1h ago");
        assert_eq!(super::compact_age_text(64_000), "17h ago");
        assert_eq!(super::compact_age_text(86_400), "1d ago");
        assert_eq!(super::compact_age_text(604_800), "1w ago");
        assert_eq!(super::compact_age_text(2_592_000), "1mo ago");
        assert_eq!(super::compact_age_text(31_536_000), "1y ago");
    }

    #[test]
    fn extract_invite_from_deep_link_accepts_nvpn_invite_urls() {
        let invite = format!("{NETWORK_INVITE_PREFIX}payload-123");
        assert_eq!(
            super::extract_invite_from_deep_link(&invite).as_deref(),
            Some(invite.as_str())
        );
    }

    #[test]
    fn extract_invite_from_deep_link_ignores_non_invite_urls() {
        assert_eq!(
            super::extract_invite_from_deep_link("https://example.com"),
            None
        );
        assert_eq!(
            super::extract_invite_from_deep_link("nvpn://settings"),
            None
        );
        assert_eq!(super::extract_invite_from_deep_link("nvpn://invite/"), None);
    }

    #[test]
    fn extract_app_deep_links_from_args_collects_invite_and_debug_urls() {
        let invite = format!("{NETWORK_INVITE_PREFIX}payload-123");
        assert_eq!(
            super::extract_app_deep_links_from_args([
                "nostr-vpn-gui.exe",
                &invite,
                "--autostart",
                "nvpn://debug/request-join",
                &invite,
                "https://example.com",
            ]),
            vec![invite, "nvpn://debug/request-join".to_string()]
        );
    }

    #[test]
    fn extract_debug_automation_command_from_deep_link_accepts_request_join_urls() {
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link("nvpn://debug/request-join"),
            Some(super::DebugAutomationCommand::RequestActiveJoin)
        );
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link("nvpn://debug/tick"),
            Some(super::DebugAutomationCommand::Tick)
        );
    }

    #[test]
    fn extract_debug_automation_command_from_deep_link_accepts_accept_join_urls() {
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link(
                "nvpn://debug/accept-join?requester=npub1requester"
            ),
            Some(super::DebugAutomationCommand::AcceptActiveJoin {
                requester_npub: "npub1requester".to_string(),
            })
        );
    }

    #[test]
    fn extract_debug_automation_command_from_deep_link_ignores_invalid_urls() {
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link("nvpn://invite/payload"),
            None
        );
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link("nvpn://debug/accept-join"),
            None
        );
        assert_eq!(
            super::extract_debug_automation_command_from_deep_link("nvpn://debug/unknown"),
            None
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
                local_is_admin: false,
                admin_npubs: Vec::new(),
                listen_for_join_requests: true,
                invite_inviter_npub: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                online_count: 1,
                expected_count: 2,
                participants: vec![
                    ParticipantView {
                        npub: "npub1local".to_string(),
                        pubkey_hex: "local".to_string(),
                        is_admin: false,
                        tunnel_ip: "10.44.0.10".to_string(),
                        magic_dns_alias: "self".to_string(),
                        magic_dns_name: "self.nvpn".to_string(),
                        relay_path_active: false,
                        runtime_endpoint: String::new(),
                        tx_bytes: 0,
                        rx_bytes: 0,
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
                        is_admin: false,
                        tunnel_ip: "10.44.0.11".to_string(),
                        magic_dns_alias: "alice".to_string(),
                        magic_dns_name: "alice.nvpn".to_string(),
                        relay_path_active: false,
                        runtime_endpoint: String::new(),
                        tx_bytes: 0,
                        rx_bytes: 0,
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
                local_is_admin: false,
                admin_npubs: Vec::new(),
                listen_for_join_requests: true,
                invite_inviter_npub: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                online_count: 0,
                expected_count: 1,
                participants: vec![ParticipantView {
                    npub: "npub1bob".to_string(),
                    pubkey_hex: "bob".to_string(),
                    is_admin: false,
                    tunnel_ip: "10.44.0.12".to_string(),
                    magic_dns_alias: "bob".to_string(),
                    magic_dns_name: "bob.nvpn".to_string(),
                    relay_path_active: false,
                    runtime_endpoint: String::new(),
                    tx_bytes: 0,
                    rx_bytes: 0,
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
                    local_is_admin: false,
                    admin_npubs: Vec::new(),
                    listen_for_join_requests: true,
                    invite_inviter_npub: String::new(),
                    outbound_join_request: None,
                    inbound_join_requests: Vec::new(),
                    online_count: 1,
                    expected_count: 1,
                    participants: vec![ParticipantView {
                        npub: "npub1alice".to_string(),
                        pubkey_hex: "alice".to_string(),
                        is_admin: false,
                        tunnel_ip: "10.44.0.11".to_string(),
                        magic_dns_alias: "alice".to_string(),
                        magic_dns_name: "alice.nvpn".to_string(),
                        relay_path_active: false,
                        runtime_endpoint: String::new(),
                        tx_bytes: 0,
                        rx_bytes: 0,
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
                    local_is_admin: false,
                    admin_npubs: Vec::new(),
                    listen_for_join_requests: true,
                    invite_inviter_npub: String::new(),
                    outbound_join_request: None,
                    inbound_join_requests: Vec::new(),
                    online_count: 1,
                    expected_count: 1,
                    participants: vec![
                        ParticipantView {
                            npub: "npub1alice".to_string(),
                            pubkey_hex: "alice".to_string(),
                            is_admin: false,
                            tunnel_ip: "10.44.0.11".to_string(),
                            magic_dns_alias: "alice".to_string(),
                            magic_dns_name: "alice.nvpn".to_string(),
                            relay_path_active: false,
                            runtime_endpoint: String::new(),
                            tx_bytes: 0,
                            rx_bytes: 0,
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
                            is_admin: false,
                            tunnel_ip: "10.44.0.12".to_string(),
                            magic_dns_alias: "bob".to_string(),
                            magic_dns_name: "bob.nvpn".to_string(),
                            relay_path_active: false,
                            runtime_endpoint: String::new(),
                            tx_bytes: 0,
                            rx_bytes: 0,
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
    fn tray_menu_spec_puts_status_first_and_settings_last() {
        let spec = tray_menu_spec(&TrayRuntimeState {
            session_active: true,
            service_setup_required: false,
            service_enable_required: false,
            status_text: tray_status_text(true, false, false, "Connected"),
            this_device_text: "This Device: sirius (10.44.0.10)".to_string(),
            this_device_copy_value: "10.44.0.10".to_string(),
            advertise_exit_node: false,
            network_groups: tray_network_groups(&[NetworkView {
                id: "home".to_string(),
                name: "Home".to_string(),
                enabled: true,
                network_id: "mesh-home".to_string(),
                local_is_admin: false,
                admin_npubs: Vec::new(),
                listen_for_join_requests: true,
                invite_inviter_npub: String::new(),
                outbound_join_request: None,
                inbound_join_requests: Vec::new(),
                online_count: 1,
                expected_count: 1,
                participants: vec![ParticipantView {
                    npub: "npub1alice".to_string(),
                    pubkey_hex: "alice".to_string(),
                    is_admin: false,
                    tunnel_ip: "10.44.0.11".to_string(),
                    magic_dns_alias: "alice".to_string(),
                    magic_dns_name: "alice.nvpn".to_string(),
                    relay_path_active: false,
                    runtime_endpoint: String::new(),
                    tx_bytes: 0,
                    rx_bytes: 0,
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
            Some(TrayMenuItemSpec::Text {
                text,
                enabled: false,
                ..
            }) if text == "VPN Status: Connected"
        ));
        assert!(matches!(
            spec.get(1),
            Some(TrayMenuItemSpec::Text {
                id: Some(id),
                text,
                enabled: true,
            }) if id == TRAY_VPN_TOGGLE_MENU_ID && text == "Turn VPN Off"
        ));
        assert!(spec.iter().any(|item| matches!(
            item,
            TrayMenuItemSpec::Submenu { text, .. } if text == "Network Devices"
        )));
        assert!(spec.iter().any(|item| matches!(
            item,
            TrayMenuItemSpec::Text {
                id: Some(id),
                text,
                enabled: true,
            } if id == TRAY_THIS_DEVICE_MENU_ID && text == "This Device: sirius (10.44.0.10)"
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
                    } if id == TRAY_RUN_EXIT_NODE_MENU_ID && text == "Offer Private Exit Node"
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
    fn tray_menu_spec_disables_this_device_copy_when_tunnel_ip_is_unavailable() {
        let spec = tray_menu_spec(&TrayRuntimeState {
            this_device_text: "This Device: sirius (-)".to_string(),
            ..TrayRuntimeState::default()
        });

        assert!(spec.iter().any(|item| matches!(
            item,
            TrayMenuItemSpec::Text {
                id: Some(id),
                text,
                enabled: false,
            } if id == TRAY_THIS_DEVICE_MENU_ID && text == "This Device: sirius (-)"
        )));
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
                    } if id == TRAY_RUN_EXIT_NODE_MENU_ID && text == "Offer Private Exit Node"
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
    fn ui_state_reports_daemon_binary_version() {
        let mut backend = test_backend(&"44".repeat(32));
        backend.daemon_state = Some(daemon_state_with_peer(None, true));
        let state = backend.ui_state();

        assert_eq!(state.daemon_binary_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn ui_state_reports_service_binary_version() {
        let mut backend = test_backend(&"44".repeat(32));
        backend.service_binary_version = "0.3.4".to_string();
        let state = backend.ui_state();

        assert_eq!(state.service_binary_version, "0.3.4");
    }

    #[test]
    fn ui_state_prefers_live_daemon_endpoint_and_listen_port() {
        let mut backend = test_backend(&"44".repeat(32));
        backend.daemon_state = Some(daemon_state_with_peer(None, true));

        let state = backend.ui_state();

        assert_eq!(state.endpoint, "198.51.100.20:53083");
        assert_eq!(state.listen_port, 53083);
    }

    #[test]
    fn ui_state_reports_assigned_self_magic_dns_name() {
        let own = nostr_sdk::prelude::Keys::generate();
        let peer = nostr_sdk::prelude::Keys::generate();
        let own_hex = own.public_key().to_hex();
        let peer_hex = peer.public_key().to_hex();
        let peer_npub = to_npub(&peer_hex);

        let mut backend = test_backend(&peer_hex);
        backend.config.nostr.secret_key = own.secret_key().to_secret_hex();
        backend.config.nostr.public_key = own_hex;
        backend.config.node_name = "Home Server".to_string();
        backend.config.ensure_defaults();
        backend
            .config
            .peer_aliases
            .insert(peer_npub, "home-server".to_string());
        backend.config.ensure_defaults();

        let state = backend.ui_state();

        assert_eq!(state.self_magic_dns_name, "home-server.nvpn");
        assert_eq!(
            backend.config.peer_alias(&peer_hex).as_deref(),
            Some("home-server-2")
        );
    }

    #[test]
    fn ui_state_serializes_join_request_checkbox_field_for_frontend() {
        let backend = test_backend(&"44".repeat(32));
        let value = serde_json::to_value(backend.ui_state()).expect("ui state should serialize");
        let network = value["networks"][0]
            .as_object()
            .expect("first network should serialize as an object");

        assert_eq!(
            network.get("joinRequestsEnabled"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(!network.contains_key("listenForJoinRequests"));
    }

    #[test]
    fn ui_state_enables_public_relay_fallback_by_default() {
        let backend = test_backend(&"44".repeat(32));
        let state = backend.ui_state();

        assert!(state.use_public_relay_fallback);
    }

    #[test]
    fn ui_state_disables_relay_for_others_by_default() {
        let backend = test_backend(&"44".repeat(32));
        let state = backend.ui_state();

        assert!(!state.relay_for_others);
        assert!(!state.provide_nat_assist);
        assert!(!state.relay_operator_running);
        assert_eq!(state.relay_operator_status, "Relay operator disabled");
        assert!(!state.nat_assist_running);
        assert_eq!(state.nat_assist_status, "NAT assist disabled");
    }

    #[test]
    fn update_settings_can_disable_public_relay_fallback() {
        let mut backend = test_backend(&"44".repeat(32));

        backend
            .update_settings(SettingsPatch {
                use_public_relay_fallback: Some(false),
                ..SettingsPatch::default()
            })
            .expect("update settings");

        assert!(!backend.ui_state().use_public_relay_fallback);
    }

    #[test]
    fn update_settings_can_enable_relay_for_others() {
        let mut backend = test_backend(&"44".repeat(32));

        backend
            .update_settings(SettingsPatch {
                relay_for_others: Some(true),
                ..SettingsPatch::default()
            })
            .expect("update settings");

        let state = backend.ui_state();
        assert!(state.relay_for_others);
        assert_eq!(
            state.relay_operator_status,
            "Relay operator starts with the daemon"
        );
    }

    #[test]
    fn update_settings_can_enable_nat_assist() {
        let mut backend = test_backend(&"44".repeat(32));

        backend
            .update_settings(SettingsPatch {
                provide_nat_assist: Some(true),
                ..SettingsPatch::default()
            })
            .expect("update settings");

        let state = backend.ui_state();
        assert!(state.provide_nat_assist);
        assert_eq!(state.nat_assist_status, "NAT assist starts with the daemon");
    }

    #[test]
    fn ui_state_uses_daemon_relay_operator_runtime_status() {
        let mut backend = test_backend(&"44".repeat(32));
        backend.config.relay_for_others = true;
        let mut daemon_state = daemon_state_with_peer(None, false);
        daemon_state.relay_operator_running = true;
        daemon_state.relay_operator_status =
            "Relaying for others on 198.51.100.7 (pid 4242)".to_string();
        daemon_state.nat_assist_running = true;
        daemon_state.nat_assist_status = "Providing NAT assist on 198.51.100.7:3478".to_string();
        backend.daemon_state = Some(daemon_state);

        let state = backend.ui_state();
        assert!(state.relay_for_others);
        assert!(state.relay_operator_running);
        assert_eq!(
            state.relay_operator_status,
            "Relaying for others on 198.51.100.7 (pid 4242)"
        );
        assert!(state.nat_assist_running);
        assert_eq!(
            state.nat_assist_status,
            "Providing NAT assist on 198.51.100.7:3478"
        );
    }

    #[test]
    fn peer_status_line_reports_when_runtime_uses_relay_endpoint() {
        let participant = "44".repeat(32);
        let mut backend = test_backend(&participant);
        let mut peer = daemon_peer(&participant, true, Some(3), None, "203.0.113.10:51820");
        peer.runtime_endpoint = Some("198.51.100.9:45000".to_string());
        peer.tx_bytes = 4_096;
        peer.rx_bytes = 8_192;
        backend.daemon_state = Some(daemon_state_with_peer(Some(peer), true));
        backend.session_active = true;
        backend.refresh_peer_runtime_status();

        let view = backend.participant_view(&participant, "mesh-test", None, false);
        assert!(view.status_text.contains("relay"));
        assert!(view.status_text.contains("198.51.100.9:45000"));
        assert!(view.relay_path_active);
        assert_eq!(view.runtime_endpoint, "198.51.100.9:45000");
        assert_eq!(view.tx_bytes, 4_096);
        assert_eq!(view.rx_bytes, 8_192);
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

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_mutex_action_keeps_async_runtime_responsive() {
        let state = Arc::new(Mutex::new(0usize));
        let worker = tokio::spawn({
            let state = state.clone();
            async move {
                run_blocking_mutex_action(state, "test", |_value| {
                    std::thread::sleep(Duration::from_millis(150));
                    Ok::<_, anyhow::Error>(())
                })
                .await
            }
        });

        tokio::time::timeout(Duration::from_millis(75), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        })
        .await
        .expect("runtime should remain responsive during blocking backend work");

        worker.await.expect("join").expect("blocking action");
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
    fn admin_privilege_detection_matches_windows_access_denied_errors() {
        let message = "nvpn service install failed\nstdout: daemon: not running\nError: sc create service failed\nstdout: [SC] OpenSCManager FAILED 5: Access is denied.\nstderr:";
        assert!(super::requires_admin_privileges(message));
    }

    #[test]
    fn admin_privilege_detection_matches_windows_error_chain_context() {
        let error = anyhow::anyhow!("Access is denied.")
            .context(r"failed to write \\?\C:\ProgramData\Nostr VPN\config.toml");

        assert!(super::requires_admin_privileges_error(&error));
    }

    #[test]
    fn windows_daemon_apply_repair_detection_matches_stale_service_errors() {
        assert!(super::windows_daemon_apply_requires_service_repair(
            "daemon did not acknowledge control request within 3s; restart the daemon with a newer nvpn binary"
        ));
        assert!(super::windows_daemon_apply_requires_service_repair(
            "daemon acknowledged control request but did not reload; likely an older nvpn daemon binary is still running. restart or reinstall the app/service so the daemon matches the current CLI"
        ));
        assert!(!super::windows_daemon_apply_requires_service_repair(
            "daemon: not running"
        ));
    }

    #[test]
    fn gui_launch_autoconnect_skips_direct_start_until_service_exists() {
        assert!(!should_start_gui_daemon_on_launch(true, true, true));
        assert!(should_start_gui_daemon_on_launch(true, true, false));
        assert!(!should_start_gui_daemon_on_launch(true, false, false));
        assert!(!should_start_gui_daemon_on_launch(false, true, false));
    }

    #[test]
    fn local_join_request_listener_requires_local_admin() {
        let mut config = AppConfig::generated();
        let own_pubkey = config
            .own_nostr_pubkey_hex()
            .expect("generated config own pubkey");
        config.networks[0].listen_for_join_requests = true;
        config.networks[0].admins = vec![own_pubkey.clone()];
        assert!(super::local_join_request_listener_enabled(&config));

        config.networks[0].admins = vec!["11".repeat(32)];
        assert!(!super::local_join_request_listener_enabled(&config));

        config.networks[0].admins = vec![own_pubkey];
        config.networks[0].listen_for_join_requests = false;
        assert!(!super::local_join_request_listener_enabled(&config));
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

    #[test]
    fn ios_launch_autoconnect_defers_until_first_tick() {
        assert!(should_defer_gui_daemon_start_until_first_tick(
            RuntimePlatform::Ios,
            true,
            false
        ));
        assert!(!should_defer_gui_daemon_start_until_first_tick(
            RuntimePlatform::Desktop,
            true,
            false
        ));
        assert!(!should_defer_gui_daemon_start_until_first_tick(
            RuntimePlatform::Ios,
            false,
            false
        ));
        assert!(!should_defer_gui_daemon_start_until_first_tick(
            RuntimePlatform::Ios,
            true,
            true
        ));
    }

    #[test]
    fn pending_launch_action_prioritizes_force_connect() {
        assert_eq!(
            pending_launch_action(false, false),
            PendingLaunchAction::None
        );
        assert_eq!(
            pending_launch_action(true, false),
            PendingLaunchAction::StartDaemon
        );
        assert_eq!(
            pending_launch_action(false, true),
            PendingLaunchAction::ForceConnect
        );
        assert_eq!(
            pending_launch_action(true, true),
            PendingLaunchAction::ForceConnect
        );
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
    fn bundled_nvpn_candidates_include_tauri_resource_binaries_subdir_on_macos() {
        let exe_dir = PathBuf::from("/Applications/Nostr VPN.app/Contents/MacOS");
        let candidates =
            bundled_nvpn_candidate_paths(&exe_dir, &[String::from("nvpn-aarch64-apple-darwin")]);

        assert!(candidates.contains(&PathBuf::from(
            "/Applications/Nostr VPN.app/Contents/Resources/binaries/nvpn-aarch64-apple-darwin"
        )));
    }

    #[test]
    fn bundled_nvpn_candidates_include_tauri_binaries_subdir_on_windows_layouts() {
        let exe_dir = PathBuf::from(r"C:\Program Files\Nostr VPN");
        let candidates = bundled_nvpn_candidate_paths(
            &exe_dir,
            &[String::from("nvpn-aarch64-pc-windows-msvc.exe")],
        );
        let expected = exe_dir
            .join("binaries")
            .join("nvpn-aarch64-pc-windows-msvc.exe");

        assert!(candidates.contains(&expected));
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
    fn ios_runtime_capabilities_enable_mobile_vpn_control() {
        let capabilities = runtime_capabilities_for_platform(RuntimePlatform::Ios);

        assert_eq!(capabilities.platform, "ios");
        assert!(capabilities.mobile);
        assert!(capabilities.vpn_session_control_supported);
        assert!(!capabilities.cli_install_supported);
        assert!(!capabilities.startup_settings_supported);
        assert!(!capabilities.tray_behavior_supported);
        assert!(
            capabilities
                .runtime_status_detail
                .contains("iOS Packet Tunnel integration")
        );
    }

    #[test]
    fn ios_simulator_runtime_capabilities_disable_mobile_vpn_control() {
        assert!(!ios_vpn_session_control_supported(true));
        assert!(ios_runtime_status_detail(true).contains("iOS Simulator"));
    }

    #[test]
    fn desktop_runtime_capabilities_keep_existing_management_features() {
        let capabilities = runtime_capabilities_for_platform(RuntimePlatform::Desktop);

        assert_eq!(capabilities.platform, "desktop");
        assert!(!capabilities.mobile);
        assert!(capabilities.cli_install_supported);
        assert!(capabilities.startup_settings_supported);
        assert!(capabilities.tray_behavior_supported);
        if cfg!(target_os = "windows") {
            assert!(!capabilities.vpn_session_control_supported);
            assert!(
                capabilities
                    .runtime_status_detail
                    .contains("tunnel control is not wired up yet")
            );
        } else {
            assert!(capabilities.vpn_session_control_supported);
            assert_eq!(capabilities.runtime_status_detail, "");
        }
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

    #[test]
    fn desktop_config_path_prefers_windows_service_config() {
        let path = desktop_config_path_from_roots(
            Some(std::path::Path::new(r"C:\Users\sirius\AppData\Roaming")),
            Some(std::path::Path::new(r"C:\ProgramData")),
            Some(std::path::Path::new(
                r"C:\Users\sirius\AppData\Roaming\nvpn\config.toml",
            )),
            false,
            true,
        );

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\sirius\AppData\Roaming\nvpn\config.toml")
        );
    }

    #[test]
    fn desktop_config_path_prefers_windows_machine_path_for_new_install() {
        let path = desktop_config_path_from_roots(
            Some(std::path::Path::new(r"C:\Users\sirius\AppData\Roaming")),
            Some(std::path::Path::new(r"C:\ProgramData")),
            None,
            false,
            false,
        );

        assert_eq!(path, PathBuf::from(r"C:\ProgramData\Nostr VPN\config.toml"));
    }

    #[test]
    fn windows_elevated_config_import_command_uses_source_and_target_paths() {
        let args = windows_elevated_config_import_args(
            r"C:\Users\sirius\AppData\Local\Temp\nvpn-import.toml",
            r"C:\ProgramData\Nostr VPN\config.toml",
        );

        assert_eq!(
            args,
            [
                "apply-config",
                "--source",
                r"C:\Users\sirius\AppData\Local\Temp\nvpn-import.toml",
                "--config",
                r"C:\ProgramData\Nostr VPN\config.toml",
            ]
        );
    }

    #[test]
    fn windows_daemon_config_import_command_uses_source_and_target_paths() {
        let args = windows_daemon_config_import_args(
            r"C:\Users\sirius\AppData\Local\Temp\nvpn-import.toml",
            r"C:\ProgramData\Nostr VPN\config.toml",
        );

        assert_eq!(
            args,
            [
                "apply-config-daemon",
                "--source",
                r"C:\Users\sirius\AppData\Local\Temp\nvpn-import.toml",
                "--config",
                r"C:\ProgramData\Nostr VPN\config.toml",
            ]
        );
    }

    #[test]
    fn desktop_config_path_prefers_windows_service_path_even_before_config_exists() {
        let path = desktop_config_path_from_roots(
            Some(std::path::Path::new(r"C:\Users\sirius\AppData\Roaming")),
            Some(std::path::Path::new(r"C:\ProgramData")),
            Some(std::path::Path::new(
                r"C:\ProgramData\Nostr VPN\config.toml",
            )),
            false,
            true,
        );

        assert_eq!(
            path,
            std::path::PathBuf::from(r"C:\ProgramData\Nostr VPN\config.toml")
        );
    }

    #[test]
    fn windows_daemon_owned_config_apply_only_targets_machine_config_with_running_daemon() {
        assert!(windows_should_use_daemon_owned_config_apply(
            std::path::Path::new(r"C:\ProgramData\Nostr VPN\config.toml"),
            Some(std::path::Path::new(r"C:\ProgramData")),
            true,
            false,
        ));
        assert!(windows_should_use_daemon_owned_config_apply(
            std::path::Path::new(r"\\?\C:\ProgramData\Nostr VPN\config.toml"),
            Some(std::path::Path::new(r"C:\ProgramData")),
            true,
            false,
        ));
        assert!(!windows_should_use_daemon_owned_config_apply(
            std::path::Path::new(r"C:\Users\sirius\AppData\Roaming\nvpn\config.toml"),
            Some(std::path::Path::new(r"C:\ProgramData")),
            true,
            true,
        ));
        assert!(windows_should_use_daemon_owned_config_apply(
            std::path::Path::new(r"C:\ProgramData\Nostr VPN\config.toml"),
            Some(std::path::Path::new(r"C:\ProgramData")),
            false,
            true,
        ));
        assert!(!windows_should_use_daemon_owned_config_apply(
            std::path::Path::new(r"C:\ProgramData\Nostr VPN\config.toml"),
            Some(std::path::Path::new(r"C:\ProgramData")),
            false,
            false,
        ));
    }

    #[test]
    fn windows_start_daemon_prefers_installed_service_when_available() {
        assert!(windows_should_start_installed_service(true, false));
        assert!(!windows_should_start_installed_service(false, false));
        assert!(!windows_should_start_installed_service(true, true));
    }

    #[test]
    fn strip_windows_verbatim_prefix_keeps_non_verbatim_paths() {
        assert_eq!(
            strip_windows_verbatim_prefix(r"C:\ProgramData\Nostr VPN\config.toml"),
            r"C:\ProgramData\Nostr VPN\config.toml"
        );
    }

    #[test]
    fn strip_windows_verbatim_prefix_removes_local_verbatim_prefix() {
        assert_eq!(
            strip_windows_verbatim_prefix(r"\\?\C:\ProgramData\Nostr VPN\config.toml"),
            r"C:\ProgramData\Nostr VPN\config.toml"
        );
    }

    #[test]
    fn service_state_refresh_due_only_after_interval() {
        let now = Instant::now();

        assert!(super::service_state_refresh_due(
            None,
            now,
            Duration::from_secs(5)
        ));
        assert!(!super::service_state_refresh_due(
            Some(now),
            now + Duration::from_secs(4),
            Duration::from_secs(5)
        ));
        assert!(super::service_state_refresh_due(
            Some(now),
            now + Duration::from_secs(5),
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn tauri_protocol_request_path_defaults_root_to_index_html() {
        let uri: tauri::http::Uri = "tauri://localhost".parse().expect("uri");

        assert_eq!(
            tauri_protocol_request_path(&uri, IOS_TAURI_ORIGIN),
            "index.html"
        );
    }

    #[test]
    fn tauri_protocol_request_path_strips_query_and_fragment() {
        let uri: tauri::http::Uri = "tauri://localhost/assets/index.js?v=42#boot"
            .parse()
            .expect("uri");

        assert_eq!(
            tauri_protocol_request_path(&uri, IOS_TAURI_ORIGIN),
            "assets/index.js"
        );
    }

    #[test]
    fn tauri_protocol_request_path_trims_leading_slashes() {
        let uri: tauri::http::Uri = "tauri://localhost//nested/path.css".parse().expect("uri");

        assert_eq!(
            tauri_protocol_request_path(&uri, IOS_TAURI_ORIGIN),
            "nested/path.css"
        );
    }
}
