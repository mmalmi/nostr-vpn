use anyhow::{Result, anyhow};
use nostr_vpn_core::config::{
    AppConfig, NetworkConfig, maybe_autoconfigure_node, normalize_fips_peer_endpoint_hint,
    normalize_nostr_pubkey, normalize_runtime_network_id,
};
pub(crate) use nostr_vpn_core::invite::{
    NETWORK_INVITE_VERSION, NetworkInvite, encode_network_invite, parse_network_invite, to_npub,
};

pub(crate) fn active_network_invite_code_with_endpoints(
    config: &AppConfig,
    extra_inviter_endpoints: &[String],
) -> Result<String> {
    let active_network = config
        .active_network_opt()
        .ok_or_else(|| anyhow!("create or join a network first"))?;
    let roster = config.shared_network_roster(&active_network.id)?;
    if roster.admins.is_empty() {
        return Err(anyhow!("active network has no admin configured"));
    }
    let invite = NetworkInvite {
        v: NETWORK_INVITE_VERSION,
        network_name: String::new(),
        network_id: roster.network_id,
        invite_secret: active_network.invite_secret.clone(),
        inviter_npub: String::new(),
        inviter_node_name: String::new(),
        inviter_endpoints: active_inviter_endpoints(config, extra_inviter_endpoints),
        admins: roster.admins.iter().map(|admin| to_npub(admin)).collect(),
        participants: Vec::new(),
        relays: Vec::new(),
        relay_record: active_network.relay_record.clone(),
    };
    encode_network_invite(&invite)
}

pub(crate) fn apply_network_invite_to_active_network(
    config: &mut AppConfig,
    invite: &NetworkInvite,
) -> Result<()> {
    let prepared = PreparedNetworkInvite::from_invite(invite)?;
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let (target_network_id, reset_membership) =
        target_network_for_invite(config, invite, &prepared.normalized_network_id);
    let should_adopt_name = config
        .network_by_id(&target_network_id)
        .is_some_and(network_should_adopt_invite);
    let inviter_already_configured =
        network_has_pubkey_configured(config, &target_network_id, &prepared.inviter_pubkey);

    config.set_network_enabled(&target_network_id, true)?;
    config.set_network_mesh_id(&target_network_id, &invite.network_id)?;
    if let Some(network) = config.network_by_id_mut(&target_network_id) {
        network.invite_secret = invite.invite_secret.trim().to_string();
        merge_invite_membership(network, &prepared, own_pubkey.as_deref(), reset_membership);
    }
    config.add_fips_peer_endpoint_hints(&prepared.inviter_pubkey, &invite.inviter_endpoints)?;

    if !inviter_already_configured {
        let inviter_alias = invite.inviter_node_name.trim();
        let inviter_alias = if inviter_alias.is_empty() {
            "admin"
        } else {
            inviter_alias
        };
        let _ = config.set_peer_alias(&prepared.inviter_pubkey, inviter_alias);
    }

    if should_adopt_name
        && !invite.network_name.trim().is_empty()
        && let Some(network) = config.network_by_id_mut(&target_network_id)
    {
        network.name = invite.network_name.trim().to_string();
    }

    Ok(())
}

fn active_inviter_endpoints(config: &AppConfig, extra_inviter_endpoints: &[String]) -> Vec<String> {
    let mut configured = config.clone();
    maybe_autoconfigure_node(&mut configured);
    let mut endpoints = normalize_fips_peer_endpoint_hint(configured.node.endpoint.trim())
        .into_iter()
        .collect::<Vec<_>>();
    endpoints.extend(
        extra_inviter_endpoints
            .iter()
            .filter_map(|endpoint| normalize_fips_peer_endpoint_hint(endpoint)),
    );
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

struct PreparedNetworkInvite {
    normalized_network_id: String,
    inviter_pubkey: String,
    admins: Vec<String>,
    participants: Vec<String>,
    relay_record: Option<String>,
}

impl PreparedNetworkInvite {
    fn from_invite(invite: &NetworkInvite) -> Result<Self> {
        let inviter_npub = if invite.inviter_npub.trim().is_empty() {
            invite
                .admins
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("invite must include at least one admin"))?
        } else {
            invite.inviter_npub.clone()
        };

        Ok(Self {
            normalized_network_id: normalize_runtime_network_id(&invite.network_id),
            inviter_pubkey: normalize_nostr_pubkey(&inviter_npub)?,
            admins: invite
                .admins
                .iter()
                .map(|admin| normalize_nostr_pubkey(admin))
                .collect::<Result<Vec<_>>>()?,
            participants: invite
                .participants
                .iter()
                .map(|participant| normalize_nostr_pubkey(participant))
                .collect::<Result<Vec<_>>>()?,
            relay_record: invite.relay_record.clone(),
        })
    }
}

fn target_network_for_invite(
    config: &mut AppConfig,
    invite: &NetworkInvite,
    normalized_invite_network_id: &str,
) -> (String, bool) {
    if let Some(existing) = config.networks.iter().find(|network| {
        normalize_runtime_network_id(&network.network_id) == normalized_invite_network_id
    }) {
        return (existing.id.clone(), false);
    }
    if let Some(active_network) = config.active_network_opt()
        && network_should_adopt_invite(active_network)
    {
        return (active_network.id.clone(), true);
    }
    (config.add_network(&invite.network_name), true)
}

fn network_has_pubkey_configured(config: &AppConfig, network_id: &str, pubkey: &str) -> bool {
    config.network_by_id(network_id).is_some_and(|network| {
        network
            .participants
            .iter()
            .any(|participant| participant == pubkey)
            || network.admins.iter().any(|admin| admin == pubkey)
    })
}

fn merge_invite_membership(
    network: &mut NetworkConfig,
    prepared: &PreparedNetworkInvite,
    own_pubkey: Option<&str>,
    reset_membership: bool,
) {
    if reset_membership {
        network.participants.clear();
        network.admins.clear();
        network.shared_roster_updated_at = 0;
        network.shared_roster_signed_by.clear();
    }
    if prepared.relay_record.is_some() {
        network.relay_record.clone_from(&prepared.relay_record);
    }

    for participant in &prepared.participants {
        if own_pubkey != Some(participant.as_str()) {
            network.participants.push(participant.clone());
        }
    }
    network.participants.sort();
    network.participants.dedup();

    for admin in &prepared.admins {
        network.admins.push(admin.clone());
    }
    if !network
        .admins
        .iter()
        .any(|admin| admin == &prepared.inviter_pubkey)
    {
        network.admins.push(prepared.inviter_pubkey.clone());
    }
    network.admins.sort();
    network.admins.dedup();
    network.invite_inviter = if network
        .admins
        .iter()
        .any(|admin| admin == &prepared.inviter_pubkey)
    {
        prepared.inviter_pubkey.clone()
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

pub(crate) fn preferred_join_request_recipient(network: &NetworkConfig) -> Option<String> {
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

fn network_should_adopt_invite(network: &NetworkConfig) -> bool {
    let trimmed = network.name.trim();
    network.participants.is_empty() && (trimmed.is_empty() || trimmed.starts_with("Network "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::NetworkConfig;

    #[test]
    fn active_invite_includes_live_inviter_endpoints() {
        let keys = Keys::generate();
        let admin_hex = keys.public_key().to_hex();
        let admin_npub = keys.public_key().to_bech32().expect("admin npub");
        let mut config = AppConfig::generated_without_networks();
        config.nostr.secret_key = keys.secret_key().to_secret_hex();
        config.nostr.public_key = admin_npub;
        config.node.endpoint = "172.20.10.2:51821".to_string();
        config.networks.push(NetworkConfig {
            id: "network-1".to_string(),
            name: "Network 1".to_string(),
            enabled: true,
            network_id: "8d4f34f5425bc50e".to_string(),
            invite_secret: "join-secret".to_string(),
            participants: Vec::new(),
            admins: vec![admin_hex],
            listen_for_join_requests: true,
            invite_inviter: String::new(),
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
        });

        let code = active_network_invite_code_with_endpoints(
            &config,
            &[
                "192.168.1.5:51821".to_string(),
                "10.68.114.105:51821".to_string(),
                "192.168.1.5:51821".to_string(),
                "not an endpoint".to_string(),
            ],
        )
        .expect("invite code");
        let invite = parse_network_invite(&code).expect("invite parses");

        assert_eq!(invite.invite_secret, "join-secret");
        assert_eq!(
            invite.inviter_endpoints,
            vec![
                "10.68.114.105:51821".to_string(),
                "172.20.10.2:51821".to_string(),
                "192.168.1.5:51821".to_string(),
            ]
        );
    }
}
