#[cfg(feature = "paid-exit")]
mod cashu_wallet_daemon;
mod config_bootstrap;
use nvpn::control_pubsub_runtime;
mod daemon_runtime;
mod diagnostics;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod fips_host_tunnel;
mod fips_private_mesh;
#[cfg(unix)]
mod join_request_ipc;
#[cfg(target_os = "linux")]
mod linux_network;
#[cfg(any(target_os = "macos", test))]
mod macos_network;
#[cfg(any(target_os = "macos", test))]
mod macos_service;
mod network_signaling;
mod pairing_qr;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod pipeline_profile;
mod platform_routing;
mod recent_peers_store;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod secure_dns_runtime;
mod service_management;
mod session_runtime;
mod updater;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod wg_upstream_runtime;
#[cfg(target_os = "windows")]
mod windows_network;
#[cfg(any(target_os = "windows", test))]
mod windows_tunnel;
#[cfg(target_os = "linux")]
mod wireguard_exit;

#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use fips_core::discovery::nostr::{OverlayEndpointAdvert, OverlayTransportKind};
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
#[cfg(any(target_os = "macos", test))]
use std::hash::{Hash, Hasher};
#[cfg(feature = "paid-exit")]
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(feature = "paid-exit")]
use std::net::{ToSocketAddrs, UdpSocket};
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
#[cfg(feature = "paid-exit")]
use cashu_service::{
    CashuSpilmanPayment, CashuSpilmanPaymentSigner, CashuSpilmanReceiverCloseResult,
    CashuWalletOverview, FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig,
    FileSpilmanPaymentSigner, SharedSpilmanClientStoreLock, StreamingRouteCashuTokenLease,
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest, StreamingRoutePaymentEnvelope,
    StreamingRoutePaymentPayload, load_or_create_cashu_spilman_receiver_key, normalize_mint_url,
    spilman_client_store_path,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(all(feature = "paid-exit", test))]
use nostr_sdk::prelude::{Alphabet, Filter, SingleLetterTag};
#[cfg(feature = "paid-exit")]
use nostr_sdk::prelude::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp, ToBech32};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::config::normalize_relay_urls;
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::config::write_private_file_preserving_user_owner;
use nostr_vpn_core::config::{
    AppConfig, ExitDnsMode, ExitDohProvider, InternetSource, SharedNetworkRoster,
    derive_mesh_tunnel_ip, exit_node_default_routes, maybe_autoconfigure_node,
    normalize_advertised_route, normalize_fips_peer_endpoint_hint, normalize_nostr_pubkey,
    normalize_runtime_network_id, parse_wireguard_exit_config,
};
use nostr_vpn_core::control::PeerAnnouncement;
use nostr_vpn_core::data_plane::MeshPeerStatus;
use nostr_vpn_core::diagnostics::{
    HealthIssue, HealthSeverity, NetworkSummary, PortMappingStatus, ProbeState,
};
use nostr_vpn_core::fips_control::{
    JoinRosterControl, NetworkRoster, PeerCapabilities, PeerEndpointHint, SignedRoster,
    local_fips_dataplane_features,
};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::fips_mesh::FipsPaidRouteAdmission;
use nostr_vpn_core::join_requests::{FIPS_JOIN_REQUEST_RETRY_SECS, MeshJoinRequest};
use nostr_vpn_core::magic_dns::{
    MagicDnsResolverConfig, MagicDnsServer, build_magic_dns_records, install_system_resolver,
    uninstall_system_resolver,
};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_route_probe::{
    DEFAULT_PAID_ROUTE_BANDWIDTH_BYTES, DEFAULT_PAID_ROUTE_DOWNLOAD_URL,
    DEFAULT_PAID_ROUTE_GEOIP_URL_TEMPLATE, DEFAULT_PAID_ROUTE_PUBLIC_IP_URL,
    DEFAULT_PAID_ROUTE_UPLOAD_URL, PaidRouteProbeMeasurement, PaidRouteProbeSample,
    build_paid_route_probe_measurement, paid_route_bandwidth_bps, paid_route_download_url,
    paid_route_geoip_url, paid_route_stun_binding_request, paid_route_stun_host_port,
    paid_route_stun_transaction_id, parse_paid_route_geoip_response,
    parse_paid_route_public_ip_response, parse_paid_route_stun_binding_response,
};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_route_store::{
    ApplyPaidRouteSellerPaymentRequest, ApplyPaidRouteSellerSessionOpenRequest,
    AttachPaidRouteBuyerSpilmanChannelRequest, BuildPaidRouteBuyerPaymentEnvelopeKind,
    BuildPaidRouteBuyerPaymentEnvelopeRequest, BuildPaidRouteBuyerPaymentEnvelopeResult,
    BuildPaidRouteBuyerSignedPaymentEnvelopeRequest, BuildPaidRouteBuyerTokenLeaseEnvelopeRequest,
    OpenPaidRouteBuyerSessionRequest, OpenPaidRouteBuyerSessionResult,
    PaidRouteBuyerPaymentUpdateDue, PaidRouteBuyerPaymentUpdatesDueRequest, PaidRouteChannelRecord,
    PaidRouteChannelRole, PaidRouteLifecycleStatus, PaidRouteSellerCollectionState,
    PaidRouteSessionRecord, PaidRouteStore, RecordPaidRouteBuyerUsageRequest,
    RecordPaidRouteSellerUsageRequest, UpdatePaidRouteSessionProbeRequest,
    UpdatePaidRouteSessionProbeResult, load_paid_route_store, paid_route_store_file_path,
    update_paid_route_store, upsert_paid_route_offer,
};
#[cfg(feature = "paid-exit")]
use nostr_vpn_core::paid_routes::{
    ManualPaidExitProvider, PaidExitConfig, PaidExitUpstream, PaidRouteOffer, PaidRoutePaymentMode,
    PaidRouteQualityMetrics, PaidRouteRoutingDecision, PaidRouteSessionOpen, SignedPaidRouteOffer,
    paid_route_country_claim, paid_route_offer_filter,
    signed_paid_exit_offer_from_config_with_receiver,
    signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints,
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
    apply_config_file, apply_devices_override, apply_participants_override, default_config_path,
    default_tunnel_iface, init_config, install_cli, load_config_read_only, load_or_default_config,
    print_version, uninstall_cli,
};
pub(crate) use crate::daemon_runtime::*;
use crate::diagnostics::{
    PortMappingRuntime, build_health_issues, capture_network_snapshot, detect_captive_portal,
    run_netcheck_report, write_doctor_bundle,
};
#[cfg(any(feature = "paid-exit", not(unix)))]
use crate::network_signaling::maybe_reload_running_daemon;
use crate::network_signaling::{
    RosterEditAction, reload_running_daemon_after_save, save_config_and_reload_transactionally,
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
    WindowsServiceState, WindowsServiceStopAction, windows_service_bin_path,
    windows_service_binary_path_from_sc_qc_output, windows_service_disabled_from_qc_output,
    windows_service_state_from_query_output, windows_service_status_from_query_output,
    windows_service_stop_action, windows_service_stop_failure_is_joinable,
};
#[cfg(test)]
pub(crate) use crate::service_management::{
    linux_service_binary_path, linux_service_config_path_from_unit_contents,
    linux_service_executable_path_from_unit_contents, linux_service_status_from_show_output,
    linux_service_unit_content, linux_service_unit_matches_config,
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
const DAEMON_STATE_RUNNING_MAX_FUTURE_SKEW_SECS: u64 = 2;
const DAEMON_PEER_STATUS_MAX_FUTURE_SKEW_SECS: u64 = 2;
const MAJOR_LINK_CHANGE_TIME_JUMP_SECS: u64 = 30;
const WAITING_FOR_PARTICIPANTS_STATUS: &str = "Waiting for participants";
const LISTENING_FOR_JOIN_REQUESTS_STATUS: &str = "Listening for join requests";
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct DaemonJoinRequestIpcRequest {
    pub(crate) reset: bool,
    pub(crate) response: tokio::sync::oneshot::Sender<Result<String, String>>,
}

pub(crate) fn fips_core_build_version() -> String {
    fips_core::version::short_version().to_string()
}

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
const WINDOWS_SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "windows")]
static WINDOWS_SERVICE_DAEMON_ARGS: OnceLock<DaemonArgs> = OnceLock::new();
#[cfg(target_os = "windows")]
define_windows_service!(ffi_windows_service_main, windows_service_main);

include!("main/cli_args.rs");
include!("main/command_dispatch.rs");
include!("main/wg_self_test.rs");
include!("main/roster_sync.rs");
include!("main/status_types.rs");
#[cfg(feature = "paid-exit")]
include!("main/paid_exit.rs");
include!("main/runtime_helpers.rs");
include!("main/runtime_roster.rs");
include!("main/daemon_commands.rs");
include!("main/doctor_and_parsing.rs");

#[cfg(test)]
mod tests {
    #[path = "../tests/cli_smoke.rs"]
    mod cli_smoke;
    #[path = "../tests/config_cache.rs"]
    mod config_cache;
    #[path = "../tests/daemon_control.rs"]
    mod daemon_control;
    #[path = "../tests/runtime_misc.rs"]
    mod runtime_misc;
    #[cfg(feature = "paid-exit")]
    #[path = "../tests/runtime_misc_paid_exit_relay.rs"]
    mod runtime_misc_paid_exit_relay;
    #[path = "../tests/runtime_network_transitions.rs"]
    mod runtime_network_transitions;
    #[path = "../tests/service_cli.rs"]
    mod service_cli;
}
