use anyhow::{Context, Result, anyhow};
use nostr_identity::{
    NOSTR_IDENTITY_DEVICE_APPROVAL_LABEL_MAX_BYTES, nostr_identity_device_approval_request_relays,
};
use nostr_sdk::prelude::Keys;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{AppConfig, normalize_nostr_pubkey, normalize_runtime_network_id};
use crate::fips_control::{JoinRosterControl, NetworkRoster, SignedRoster};
use crate::identity_bridge::{
    CreateNostrIdentityDeviceApprovalRequestOptions, NostrIdentityDeviceApprovalRequest,
    create_nostr_identity_device_approval_request, encode_nostr_identity_device_approval_bootstrap,
    nostr_identity_device_approval_bootstrap,
};

// A pending join request also refreshes the authenticated return route used by
// the approving device. Keep several attempts inside the 15-second public-UI
// delivery budget so approval timing cannot add a full ten-second blind spot.
pub const FIPS_JOIN_REQUEST_RETRY_SECS: u64 = 3;
pub const NOSTR_VPN_JOIN_REQUEST_TYPE: &str = "nostr-vpn.join-request";
pub const NOSTR_JOIN_REQUEST_TTL_SECS: u64 = 15 * 60;
pub const MAX_NOSTR_JOIN_ROSTER_AGE_SECS: u64 = 7 * 24 * 60 * 60;
pub const MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS: u64 = 10 * 60;
pub(crate) const PENDING_NOSTR_JOIN_REQUEST_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedNostrJoinRoster {
    pub network_id: String,
    pub request_pubkey: String,
    pub device_app_key_pubkey: String,
    pub roster_event_id: String,
    pub signed_by_pubkey: String,
    pub signed_at: u64,
    pub applied_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingNostrJoinRequest {
    #[serde(default)]
    pub version: u8,
    pub request: NostrIdentityDeviceApprovalRequest,
    pub request_private_key: String,
}

pub fn prepare_manual_join_delivery(
    config: &AppConfig,
    network_entry_id: &str,
    recipient: &str,
) -> Result<JoinRosterControl> {
    let signer_keys = config.nostr_keys()?;
    let signer = signer_keys.public_key().to_hex();
    let recipient = normalize_nostr_pubkey(recipient)?;
    let network = config
        .network_by_id(network_entry_id)
        .ok_or_else(|| anyhow!("network not found"))?;
    if !network.admins.iter().any(|admin| admin == &signer) {
        return Err(anyhow!("active network is not administered by this device"));
    }
    if !network
        .devices
        .iter()
        .chain(network.admins.iter())
        .any(|member| member == &recipient)
    {
        return Err(anyhow!(
            "manual join recipient is not in the network roster"
        ));
    }
    let shared = config.shared_network_roster(network_entry_id)?;
    if shared.updated_at == 0 {
        return Err(anyhow!("manual join roster has no signed update timestamp"));
    }
    let signed_roster = SignedRoster::sign(
        shared.network_id.clone(),
        NetworkRoster {
            network_name: shared.name,
            devices: shared.devices,
            admins: shared.admins,
            aliases: shared.aliases,
            signed_at: shared.updated_at,
        },
        &signer_keys,
    )
    .context("failed to sign manual join network roster")?;
    let token = manual_join_request_token(&shared.network_id, &signer, &recipient)?;
    JoinRosterControl::new(signed_roster, &token)
        .context("failed to bind roster to manual join identifiers")
}

impl PendingNostrJoinRequest {
    pub fn request_keys(&self) -> Result<Keys> {
        let keys = Keys::parse(self.request_private_key.trim())
            .context("pending join request private key is invalid")?;
        if keys.public_key().to_hex() != self.request.request_pubkey {
            return Err(anyhow!(
                "pending join request private key does not match request pubkey"
            ));
        }
        Ok(keys)
    }

    pub fn validate_for_device(&self, device_app_key_pubkey: &str) -> Result<()> {
        if self.version != PENDING_NOSTR_JOIN_REQUEST_VERSION {
            return Err(anyhow!(
                "pending join request has an unsupported local version"
            ));
        }
        let expected_device = normalize_nostr_pubkey(device_app_key_pubkey)?;
        let bootstrap = nostr_identity_device_approval_bootstrap(&self.request)
            .map_err(|error| anyhow!("pending join request is invalid: {error}"))?;
        encode_nostr_identity_device_approval_bootstrap(&bootstrap, None)
            .map_err(|error| anyhow!("pending join request bootstrap is invalid: {error}"))?;
        if self.request.device_app_key_pubkey != expected_device {
            return Err(anyhow!(
                "pending join request device AppKey does not match local identity"
            ));
        }
        if self.request.request_type.as_deref() != Some(NOSTR_VPN_JOIN_REQUEST_TYPE) {
            return Err(anyhow!("pending join request has invalid request type"));
        }
        if self.request.request_pubkey == self.request.device_app_key_pubkey {
            return Err(anyhow!(
                "pending join request must use a separate ephemeral request key"
            ));
        }
        let relays = nostr_identity_device_approval_request_relays(&self.request)
            .map_err(|error| anyhow!("pending join request approval relay is invalid: {error}"))?;
        if !relays.is_empty() {
            return Err(anyhow!(
                "pending join request must not use Nostr approval relays"
            ));
        }
        self.request_keys()?;
        Ok(())
    }

    pub fn encode(&self, prefix: &str) -> Result<String> {
        let bootstrap = nostr_identity_device_approval_bootstrap(&self.request)
            .map_err(|error| anyhow!("failed to build pending join request bootstrap: {error}"))?;
        encode_nostr_identity_device_approval_bootstrap(&bootstrap, Some(prefix))
            .map_err(|error| anyhow!("failed to encode pending join request: {error}"))
    }
}

impl AppConfig {
    pub fn ensure_pending_nostr_join_request(&mut self, requested_at: u64) -> Result<bool> {
        let device_keys = self.nostr_keys()?;
        let device_pubkey = device_keys.public_key().to_hex();
        if let Some(pending) = &self.pending_nostr_join_request {
            let not_expired = pending
                .request
                .expires_at
                .and_then(|expires_at| u64::try_from(expires_at).ok())
                .is_some_and(|expires_at| requested_at < expires_at);
            if not_expired && pending.validate_for_device(&device_pubkey).is_ok() {
                return Ok(false);
            }
            self.pending_nostr_join_request = None;
        }
        let requested_at =
            i64::try_from(requested_at).context("pending join request timestamp overflows i64")?;
        let expires_at = requested_at
            .checked_add(
                i64::try_from(NOSTR_JOIN_REQUEST_TTL_SECS)
                    .context("pending join request TTL overflows i64")?,
            )
            .context("pending join request expiry overflows i64")?;
        let node_name = bounded_device_approval_label(&self.node_name);
        let local = create_nostr_identity_device_approval_request(
            &device_keys,
            CreateNostrIdentityDeviceApprovalRequestOptions {
                request_keys: None,
                request_secret: None,
                requested_at,
                request_type: Some(NOSTR_VPN_JOIN_REQUEST_TYPE.to_string()),
                resources: Vec::new(),
                expires_at: Some(expires_at),
                profile_id: self.nostr.identity_profile_id,
                admin_app_key_pubkey: None,
                label: node_name,
            },
        )
        .map_err(|error| anyhow!("failed to create pending join request: {error}"))?;
        let pending = PendingNostrJoinRequest {
            version: PENDING_NOSTR_JOIN_REQUEST_VERSION,
            request: local.request,
            request_private_key: local.request_keys.secret_key().to_secret_hex(),
        };
        pending.validate_for_device(&device_pubkey)?;
        self.pending_nostr_join_request = Some(pending);
        Ok(true)
    }

    pub fn pending_nostr_join_request_link(&self, prefix: &str) -> Result<String> {
        let pending = self
            .pending_nostr_join_request
            .as_ref()
            .ok_or_else(|| anyhow!("no pending Nostr join request"))?;
        pending.validate_for_device(&self.own_nostr_pubkey_hex()?)?;
        pending.encode(prefix)
    }

    pub fn clear_pending_nostr_join_request(&mut self) -> bool {
        self.pending_nostr_join_request.take().is_some()
    }

    pub fn apply_nostr_join_roster(
        &mut self,
        join_control: &JoinRosterControl,
        now: u64,
    ) -> Result<Option<AppliedNostrJoinRoster>> {
        let Some(pending) = self.pending_nostr_join_request.as_ref() else {
            return Ok(None);
        };
        let own_pubkey = self.own_nostr_pubkey_hex()?;
        pending.validate_for_device(&own_pubkey)?;
        join_control.verify_for_request(&pending.request.request_secret)?;
        let signed_roster = &join_control.signed_roster;
        validate_join_roster_freshness(pending, signed_roster.signed_at(), now)?;

        let roster = signed_roster.roster()?;
        let signer = normalize_nostr_pubkey(&signed_roster.signer_pubkey_hex()?)?;
        let members = roster
            .devices
            .iter()
            .chain(roster.admins.iter())
            .filter_map(|member| normalize_nostr_pubkey(member).ok())
            .collect::<Vec<_>>();
        if !members.iter().any(|member| member == &own_pubkey) {
            return Err(anyhow!("signed join roster does not contain this device"));
        }
        if !roster
            .admins
            .iter()
            .filter_map(|admin| normalize_nostr_pubkey(admin).ok())
            .any(|admin| admin == signer)
        {
            return Err(anyhow!("signed join roster signer is not a roster admin"));
        }

        let (mut updated, applied) = self.stage_signed_join_roster(signed_roster, &signer, now)?;
        updated.ensure_pending_nostr_join_request(now)?;
        *self = updated;
        Ok(Some(applied))
    }

    /// Applies a receipt-backed roster sent after an admin and joiner exchange
    /// their device and network identifiers out of band. The deterministic
    /// token is not an authentication secret: the configured admin's roster
    /// signature remains the authority. It only binds this delivery to the
    /// exact manual-join tuple and keeps it distinct from QR approvals.
    pub fn apply_manual_join_roster(
        &mut self,
        join_control: &JoinRosterControl,
        now: u64,
    ) -> Result<Option<String>> {
        let signed_roster = &join_control.signed_roster;
        signed_roster.verify()?;
        let network_id = normalize_runtime_network_id(&signed_roster.network_id()?);
        if network_id.is_empty() {
            return Err(anyhow!("signed manual join roster has no network id"));
        }
        let signer = normalize_nostr_pubkey(&signed_roster.signer_pubkey_hex()?)?;
        let own_pubkey = self.own_nostr_pubkey_hex()?;
        let Some(network_entry_id) = self.networks.iter().find_map(|network| {
            (normalize_runtime_network_id(&network.network_id) == network_id
                && network.local_identity_confirmation_pending
                && network.join_request_admin == signer
                && network.admins.iter().any(|admin| admin == &signer))
            .then(|| network.id.clone())
        }) else {
            return Ok(None);
        };

        let expected_token = manual_join_request_token(&network_id, &signer, &own_pubkey)?;
        join_control.verify_for_request(&expected_token)?;
        validate_manual_join_roster_freshness(signed_roster.signed_at(), now)?;
        let roster = signed_roster.roster()?;
        let members = roster
            .devices
            .iter()
            .chain(roster.admins.iter())
            .filter_map(|member| normalize_nostr_pubkey(member).ok())
            .collect::<Vec<_>>();
        if !members.iter().any(|member| member == &own_pubkey) {
            return Err(anyhow!(
                "signed manual join roster does not contain this device"
            ));
        }
        if !roster
            .admins
            .iter()
            .filter_map(|admin| normalize_nostr_pubkey(admin).ok())
            .any(|admin| admin == signer)
        {
            return Err(anyhow!(
                "signed manual join roster signer is not a roster admin"
            ));
        }
        if !self.apply_verified_admin_signed_shared_roster(signed_roster)? {
            return Err(anyhow!("signed manual join roster was not applied"));
        }
        self.set_network_enabled(&network_entry_id, true)?;
        self.ensure_defaults();
        Ok(Some(network_id))
    }

    fn stage_signed_join_roster(
        &self,
        signed_roster: &SignedRoster,
        signer: &str,
        now: u64,
    ) -> Result<(Self, AppliedNostrJoinRoster)> {
        let pending = self
            .pending_nostr_join_request
            .as_ref()
            .ok_or_else(|| anyhow!("no pending join request"))?;
        let roster = signed_roster.roster()?;
        let network_id = normalize_runtime_network_id(&signed_roster.network_id()?);
        if network_id.is_empty() {
            return Err(anyhow!("signed join roster has no network id"));
        }
        let mut updated = self.clone();
        let matching_network = updated
            .networks
            .iter()
            .find(|network| normalize_runtime_network_id(&network.network_id) == network_id)
            .map(|network| network.id.clone());
        let network_entry_id = if let Some(network_id) = matching_network {
            let network = updated
                .network_by_id(&network_id)
                .ok_or_else(|| anyhow!("approved network disappeared"))?;
            if !network.admins.is_empty() && !network.admins.iter().any(|admin| admin == signer) {
                return Err(anyhow!(
                    "signed join roster signer is not a configured admin"
                ));
            }
            network_id
        } else {
            let entry_id = updated.add_network(if roster.network_name.trim().is_empty() {
                "Network"
            } else {
                roster.network_name.trim()
            });
            let network = updated
                .network_by_id_mut(&entry_id)
                .ok_or_else(|| anyhow!("failed to create approved network"))?;
            network.network_id = network_id.clone();
            network.admins = vec![signer.to_string()];
            network.shared_roster_updated_at = 0;
            network.shared_roster_signed_by.clear();
            updated.set_network_enabled(&entry_id, true)?;
            entry_id
        };

        if !updated.apply_verified_admin_signed_shared_roster(signed_roster)? {
            return Err(anyhow!("signed join roster was not applied"));
        }
        updated.pending_nostr_join_request = None;
        updated.ensure_defaults();
        updated.set_network_enabled(&network_entry_id, true)?;
        let applied = AppliedNostrJoinRoster {
            network_id,
            request_pubkey: pending.request.request_pubkey.clone(),
            device_app_key_pubkey: pending.request.device_app_key_pubkey.clone(),
            roster_event_id: signed_roster.event.id.to_hex(),
            signed_by_pubkey: signer.to_string(),
            signed_at: signed_roster.signed_at(),
            applied_at: now,
        };
        Ok((updated, applied))
    }
}

pub fn manual_join_request_token(
    network_id: &str,
    admin_pubkey: &str,
    device_pubkey: &str,
) -> Result<String> {
    let network_id = normalize_runtime_network_id(network_id);
    if network_id.is_empty() {
        return Err(anyhow!("manual join network id is empty"));
    }
    let admin_pubkey = normalize_nostr_pubkey(admin_pubkey)?;
    let device_pubkey = normalize_nostr_pubkey(device_pubkey)?;
    let mut digest = Sha256::new();
    digest.update(b"nostr-vpn-manual-join-v1\0");
    for value in [
        network_id.as_bytes(),
        admin_pubkey.as_bytes(),
        device_pubkey.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    Ok(format!("manual-v1:{:x}", digest.finalize()))
}

fn validate_manual_join_roster_freshness(signed_at: u64, now: u64) -> Result<()> {
    if signed_at > now.saturating_add(MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS) {
        return Err(anyhow!(
            "signed manual join roster is too far in the future"
        ));
    }
    if now.saturating_sub(signed_at) > MAX_NOSTR_JOIN_ROSTER_AGE_SECS {
        return Err(anyhow!("signed manual join roster is too old"));
    }
    Ok(())
}

fn bounded_device_approval_label(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let mut end = value
        .len()
        .min(NOSTR_IDENTITY_DEVICE_APPROVAL_LABEL_MAX_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Some(value[..end].trim_end().to_string())
}

fn validate_join_roster_freshness(
    pending: &PendingNostrJoinRequest,
    signed_at: u64,
    now: u64,
) -> Result<()> {
    let requested_at = u64::try_from(pending.request.requested_at)
        .context("pending Nostr join request timestamp is negative")?;
    if signed_at < requested_at {
        return Err(anyhow!("signed join roster predates the pending request"));
    }
    if signed_at > now.saturating_add(MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS) {
        return Err(anyhow!("signed join roster is too far in the future"));
    }
    if now > signed_at.saturating_add(MAX_NOSTR_JOIN_ROSTER_AGE_SECS) {
        return Err(anyhow!("signed join roster is stale"));
    }
    if let Some(expires_at) = pending.request.expires_at {
        let expires_at =
            u64::try_from(expires_at).context("pending Nostr join request expiry is negative")?;
        if signed_at > expires_at || now > expires_at {
            return Err(anyhow!("pending Nostr join request has expired"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshJoinRequest {
    pub network_id: String,
    #[serde(default)]
    pub join_secret: String,
    #[serde(default)]
    pub requester_node_name: String,
}

pub fn normalize_join_request(request: MeshJoinRequest) -> Result<MeshJoinRequest> {
    let network_id = normalize_runtime_network_id(&request.network_id);
    if network_id.is_empty() {
        return Err(anyhow!("mesh join request network_id must not be empty"));
    }

    Ok(MeshJoinRequest {
        network_id,
        join_secret: request.join_secret.trim().to_string(),
        requester_node_name: request.requester_node_name.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_join_request_retry_keeps_multiple_delivery_opportunities_inside_ui_budget() {
        const RELEASE_JOIN_VISIBILITY_BUDGET_SECS: u64 = 15;

        const {
            assert!(
                RELEASE_JOIN_VISIBILITY_BUDGET_SECS / FIPS_JOIN_REQUEST_RETRY_SECS >= 4,
                "a pending joiner needs several authenticated route refreshes inside the UI deadline"
            );
        }
    }

    #[test]
    fn pending_join_request_rotates_at_fifteen_minute_expiry() {
        let requested_at = 1_778_998_000;
        let mut app = AppConfig::generated_without_networks();
        assert!(
            app.ensure_pending_nostr_join_request(requested_at)
                .expect("create request")
        );
        let first = app
            .pending_nostr_join_request
            .as_ref()
            .expect("pending request")
            .clone();
        assert_eq!(
            first.request.expires_at,
            Some(i64::try_from(requested_at + NOSTR_JOIN_REQUEST_TTL_SECS).expect("expiry"))
        );
        assert!(
            !app.ensure_pending_nostr_join_request(requested_at + NOSTR_JOIN_REQUEST_TTL_SECS - 1)
                .expect("reuse unexpired request")
        );
        assert!(
            app.ensure_pending_nostr_join_request(requested_at + NOSTR_JOIN_REQUEST_TTL_SECS)
                .expect("rotate expired request")
        );
        assert_ne!(
            app.pending_nostr_join_request
                .as_ref()
                .expect("replacement request")
                .request
                .request_pubkey,
            first.request.request_pubkey
        );
    }

    #[test]
    fn join_request_normalizes_network_id_and_node_name() {
        let request = normalize_join_request(MeshJoinRequest {
            network_id: "  Mesh Home  ".to_string(),
            join_secret: " join-secret ".to_string(),
            requester_node_name: " alice-phone ".to_string(),
        })
        .expect("normalize");

        assert_eq!(request.network_id, "Mesh Home");
        assert_eq!(request.join_secret, "join-secret");
        assert_eq!(request.requester_node_name, "alice-phone");
    }
}
