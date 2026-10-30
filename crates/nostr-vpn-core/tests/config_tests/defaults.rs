use super::*;
use nostr_vpn_core::config::{
    AdminSignedSharedRosterUpdate, PendingOutboundJoinRequest, normalize_runtime_network_id,
};
use nostr_vpn_core::fips_control::{NetworkRoster, SignedRoster};
use nostr_vpn_core::join_requests::prepare_manual_join_delivery;
use nostr_vpn_core::signed_rosters::SignedRosterStore;

#[allow(clippy::too_many_arguments)]
fn admin_signed_roster_update(
    network_id: &str,
    network_name: &str,
    devices: Vec<String>,
    admins: Vec<String>,
    aliases: std::collections::HashMap<String, String>,
    signed_at: u64,
    signed_by: &str,
    artifact_hash: &str,
) -> AdminSignedSharedRosterUpdate {
    AdminSignedSharedRosterUpdate {
        network_id: network_id.to_string(),
        network_name: network_name.to_string(),
        devices,
        admins,
        aliases,
        signed_at,
        signed_by: signed_by.to_string(),
        artifact_hash: artifact_hash.to_string(),
    }
}

include!("defaults/generated_and_defaults.rs");
include!("defaults/roster_apply.rs");
include!("defaults/aliases_and_join.rs");
