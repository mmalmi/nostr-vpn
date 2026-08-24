use std::collections::HashMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::config::PaidExitSellerEgress;
use nostr_vpn_core::config::{
    AppConfig, ExitDnsMode, ExitDohProvider, FiatCurrency, InternetSource, NetworkConfig,
    NostrPubsubMode, PendingInboundJoinRequest, PendingOutboundJoinRequest, derive_mesh_tunnel_ip,
    maybe_autoconfigure_node, normalize_advertised_route, normalize_magic_dns_label,
    normalize_nostr_pubkey, normalize_relay_urls, normalize_runtime_network_id,
    npub_for_pubkey_hex, parse_wireguard_exit_config, wireguard_exit_config_text,
};
use nostr_vpn_core::diagnostics::ProbeStatus;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_route_store::normalize_paid_route_mint_url;
use nostr_vpn_core::paid_routes::{PaidExitUpstream, normalize_paid_route_country_code};
use nostr_vpn_core::process_ext::CommandWindowExt;
use serde::Deserialize;

use crate::actions::NativeAppAction;
use crate::exchange_rate::{ExchangeRateService, apply_exchange_rate};
use crate::join_approval::{prepare_join_approval, prepare_manual_join_delivery};
use crate::join_request_link::{
    own_join_request_qr_code_or_link, parse_join_request_qr_code_or_link,
};
use crate::native_state::{
    NativeAppState, NativeHealthIssue, NativeInboundJoinRequestState, NativeNetworkState,
    NativeNetworkSummary, NativeOutboundJoinRequestState, NativePaidExitSellerState,
    NativePaidRouteMarketFilterState, NativePaidRouteMarketState,
    NativePaidRoutePaymentActionState, NativePaidRouteWalletActionState,
    NativePaidRouteWalletState, NativeParticipantState, NativePortMappingStatus, NativeProbeStatus,
    NativeRelayState,
};
use crate::platform::current_runtime_capabilities;
use crate::state::{
    DaemonPeerState, DaemonRuntimeState, HealthIssue, NetworkSummary, PortMappingStatus,
    SettingsPatch,
};

const NVPN_BIN_ENV: &str = "NVPN_CLI_PATH";
const EXTERNAL_DAEMON_ENV: &str = "NVPN_EXTERNAL_DAEMON";
const SERVICE_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DAEMON_STARTUP_STATUS_GRACE: Duration = Duration::from_secs(20);
const MOBILE_RUNTIME_STATE_FILE: &str = "mobile-runtime-state.json";
const MOBILE_RUNTIME_STATE_STALE_SECS: u64 = 10;
const MOBILE_RUNTIME_STATE_MAX_FUTURE_SKEW_SECS: u64 = 2;
const PEER_PRESENCE_GRACE_SECS: u64 = 90;
const PEER_PRESENCE_MAX_FUTURE_SKEW_SECS: u64 = 2;

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
        let config_path = native_config_path(&data_dir);
        let runtime =
            NativeAppRuntime::new_with_config_path(config_path.clone(), app_version.clone(), None)
                .unwrap_or_else(|error| {
                    NativeAppRuntime::from_startup_error_for_config(
                        &error,
                        config_path,
                        app_version,
                    )
                });
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

    #[allow(clippy::needless_pass_by_value)]
    pub fn set_privileged_command_runner(&self, runner: Arc<dyn PrivilegedCommandRunner>) {
        self.with_runtime(|runtime| {
            #[cfg(target_os = "macos")]
            {
                runtime.privileged_command_runner = Some(PrivilegedCommandRunnerHandle(runner));
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = runner;
            }
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
    join_request_qr_code_or_link: String,
    daemon_state: Option<DaemonRuntimeState>,
    service_supported: bool,
    service_enablement_supported: bool,
    service_installed: bool,
    service_disabled: bool,
    service_running: bool,
    service_status_detail: String,
    service_binary_version: String,
    expected_service_binary_version: String,
    daemon_status_grace_until: Option<Instant>,
    last_service_status_refresh_at: Option<Instant>,
    paid_route_market_filter: NativePaidRouteMarketFilterState,
    paid_route_wallet_last_action: NativePaidRouteWalletActionState,
    #[cfg(feature = "paid-exit")]
    paid_route_wallet_next_refresh_at: Option<Instant>,
    #[cfg(all(feature = "paid-exit", any(target_os = "ios", target_os = "android")))]
    cashu_wallet_runtime: Option<paid_exit::PaidRouteWalletRuntime>,
    paid_route_payment_last_action: NativePaidRoutePaymentActionState,
    exchange_rate_service: ExchangeRateService,
    #[cfg(test)]
    queued_join_rosters: Vec<nostr_vpn_core::fips_control::JoinRosterControl>,
    #[cfg(target_os = "macos")]
    privileged_command_runner: Option<PrivilegedCommandRunnerHandle>,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct PrivilegedCommandRunnerHandle(Arc<dyn PrivilegedCommandRunner>);

#[cfg(target_os = "macos")]
impl std::fmt::Debug for PrivilegedCommandRunnerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivilegedCommandRunnerHandle(<foreign>)")
    }
}

#[derive(Debug, Deserialize)]
struct CliStatusResponse {
    daemon: CliDaemonStatus,
    #[serde(default)]
    join_request_qr_code_or_link: String,
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

include!("ffi/runtime_lifecycle.rs");
include!("ffi/runtime_paid_exit.rs");
include!("ffi/runtime_actions.rs");
include!("ffi/runtime_config.rs");
include!("ffi/runtime_network.rs");
include!("ffi/runtime_service.rs");
include!("ffi/helpers.rs");

#[cfg(test)]
mod tests {
    include!("ffi/tests_core.rs");
    include!("ffi/tests_network.rs");
    include!("ffi/tests_network_join_actions.rs");
    include!("ffi/tests_service.rs");
    include!("ffi/tests_service_wireguard.rs");
    include!("ffi/tests_exit_dns.rs");
    include!("ffi/tests_service_paid_exit_config.rs");
    include!("ffi/tests_service_paid_exit_buy.rs");
    include!("ffi/tests_service_macos.rs");
}
