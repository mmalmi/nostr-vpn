pub mod actions;
pub mod c_abi;
#[cfg(feature = "paid-exit")]
mod exchange_rate;
#[cfg(not(feature = "paid-exit"))]
#[path = "exchange_rate_disabled.rs"]
mod exchange_rate;
mod ffi;
pub mod join_approval;
pub mod join_request_link;
mod mobile_tunnel;
pub mod native_state;
pub mod platform;
pub mod state;
mod wg_upstream_nat;

pub use actions::NativeAppAction;
pub use ffi::FfiApp;
pub use native_state::{NativeAppState, NativeNetworkState, NativeParticipantState};
pub use native_state::{NativeFileTransferState, NativeTransferFileState};
#[cfg(feature = "updater")]
pub use nostr_vpn_core::updater::UpdateAutoCheckPolicy;
pub use platform::{
    NativeRuntimeCapabilities, RuntimePlatform, current_runtime_capabilities,
    current_runtime_platform, runtime_capabilities_for,
};
pub use state::{
    DaemonPeerState, DaemonRuntimeState, InboundJoinRequestView, NetworkView,
    OutboundJoinRequestView, ParticipantView, SettingsPatch, TrayExitNodeEntry, TrayMenuItemSpec,
    TrayNetworkGroup, TrayRuntimeState, UiState,
};

uniffi::setup_scaffolding!();
