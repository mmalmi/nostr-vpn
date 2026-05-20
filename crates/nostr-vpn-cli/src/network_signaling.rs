use std::path::Path;

use anyhow::{Result, anyhow};
use nostr_vpn_core::config::{
    AppConfig, NetworkConfig, PendingOutboundJoinRequest, maybe_autoconfigure_node,
    normalize_fips_peer_endpoint_hint, normalize_nostr_pubkey, normalize_runtime_network_id,
};
#[cfg(test)]
pub(crate) use nostr_vpn_core::invite::NETWORK_INVITE_PREFIX;
pub(crate) use nostr_vpn_core::invite::{
    NetworkInvite, encode_network_invite, parse_network_invite,
};
use serde_json::json;

use super::{
    DaemonControlRequest, UpdateRosterArgs, clear_daemon_control_result, daemon_status,
    default_config_path, load_or_default_config, request_daemon_reload, unix_timestamp,
    wait_for_daemon_control_ack, wait_for_daemon_control_result,
};

pub(crate) fn apply_network_invite_to_active_network(
    config: &mut AppConfig,
    invite: &NetworkInvite,
) -> Result<()> {
    let normalized_invite_network_id = normalize_runtime_network_id(&invite.network_id);
    let inviter_pubkey = if invite.inviter_npub.trim().is_empty() {
        invite
            .admins
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("invite must include at least one admin"))?
    } else {
        invite.inviter_npub.clone()
    };
    let normalized_inviter_pubkey = normalize_nostr_pubkey(&inviter_pubkey)?;
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let invite_admins = invite
        .admins
        .iter()
        .map(|admin| normalize_nostr_pubkey(admin))
        .collect::<Result<Vec<_>>>()?;
    let invite_participants = invite
        .participants
        .iter()
        .map(|participant| normalize_nostr_pubkey(participant))
        .collect::<Result<Vec<_>>>()?;

    let (target_network_id, reset_membership) = if let Some(existing) =
        config.networks.iter().find(|network| {
            normalize_runtime_network_id(&network.network_id) == normalized_invite_network_id
        }) {
        (existing.id.clone(), false)
    } else if let Some(active_network) = config.active_network_opt() {
        if network_should_adopt_invite(active_network) {
            (active_network.id.clone(), true)
        } else {
            let network_id = config.add_network(&invite.network_name);
            config.set_network_enabled(&network_id, true)?;
            (network_id, true)
        }
    } else {
        let network_id = config.add_network(&invite.network_name);
        config.set_network_enabled(&network_id, true)?;
        (network_id, true)
    };
    let should_adopt_name = config
        .network_by_id(&target_network_id)
        .map(network_should_adopt_invite)
        .unwrap_or(false);
    let inviter_already_configured = config
        .network_by_id(&target_network_id)
        .map(|network| {
            network
                .participants
                .iter()
                .any(|participant| participant == &normalized_inviter_pubkey)
                || network
                    .admins
                    .iter()
                    .any(|admin| admin == &normalized_inviter_pubkey)
        })
        .unwrap_or(false);

    config.set_network_enabled(&target_network_id, true)?;
    config.set_network_mesh_id(&target_network_id, &invite.network_id)?;
    if let Some(network) = config.network_by_id_mut(&target_network_id) {
        if reset_membership {
            network.participants.clear();
            network.admins.clear();
            network.shared_roster_updated_at = 0;
            network.shared_roster_signed_by.clear();
        }

        for participant in &invite_participants {
            if own_pubkey.as_deref() == Some(participant.as_str()) {
                continue;
            }
            network.participants.push(participant.clone());
        }
        network.participants.sort();
        network.participants.dedup();

        for admin in &invite_admins {
            network.admins.push(admin.clone());
        }
        if !network
            .admins
            .iter()
            .any(|admin| admin == &normalized_inviter_pubkey)
        {
            network.admins.push(normalized_inviter_pubkey.clone());
        }
        network.admins.sort();
        network.admins.dedup();
        network.invite_inviter = if network
            .admins
            .iter()
            .any(|admin| admin == &normalized_inviter_pubkey)
        {
            normalized_inviter_pubkey.clone()
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
    config.add_fips_peer_endpoint_hints(&normalized_inviter_pubkey, &invite.inviter_endpoints)?;

    if !inviter_already_configured && !invite.inviter_node_name.trim().is_empty() {
        let _ = config.set_peer_alias(&normalized_inviter_pubkey, &invite.inviter_node_name);
    }

    if should_adopt_name
        && !invite.network_name.trim().is_empty()
        && let Some(network) = config.network_by_id_mut(&target_network_id)
    {
        network.name = invite.network_name.trim().to_string();
    }

    Ok(())
}

pub(crate) fn queue_active_network_join_request(config: &mut AppConfig) -> Result<bool> {
    let network = config
        .active_network_opt()
        .ok_or_else(|| anyhow!("create or join a network first"))?
        .clone();
    if network_contains_own_identity(config, &network) {
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

    let network = config
        .network_by_id_mut(&network.id)
        .ok_or_else(|| anyhow!("network not found"))?;
    network.outbound_join_request = Some(PendingOutboundJoinRequest {
        recipient,
        requested_at: unix_timestamp(),
    });
    Ok(true)
}

fn network_contains_own_identity(config: &AppConfig, network: &NetworkConfig) -> bool {
    let Some(own_pubkey) = config.own_nostr_pubkey_hex().ok() else {
        return false;
    };
    network
        .participants
        .iter()
        .chain(network.admins.iter())
        .any(|member| member == &own_pubkey)
}

fn preferred_join_request_recipient(network: &NetworkConfig) -> Option<String> {
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

pub(crate) fn maybe_reload_running_daemon(config_path: &Path) {
    let status = match daemon_status(config_path) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("config: failed to inspect daemon status after save: {error}");
            return;
        }
    };
    if !status.running {
        return;
    }
    clear_daemon_control_result(config_path);
    if let Err(error) = request_daemon_reload(config_path) {
        eprintln!("config: failed to request daemon reload after save: {error}");
        return;
    }
    if let Err(error) = wait_for_daemon_control_ack(
        config_path,
        crate::daemon_control_ack_timeout(DaemonControlRequest::Reload),
    ) {
        eprintln!("config: daemon did not acknowledge reload after save: {error}");
        return;
    }
    if let Err(error) = wait_for_daemon_control_result(
        config_path,
        DaemonControlRequest::Reload,
        crate::daemon_control_result_timeout(DaemonControlRequest::Reload),
    ) {
        eprintln!("config: daemon reload after save failed: {error}");
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RosterEditAction {
    AddParticipant,
    RemoveParticipant,
    AddAdmin,
    RemoveAdmin,
}

pub(crate) fn active_network_invite_code(config: &AppConfig) -> Result<String> {
    let active_network = config
        .active_network_opt()
        .ok_or_else(|| anyhow!("create or join a network first"))?;
    let roster = config.shared_network_roster(&active_network.id)?;
    if roster.admins.is_empty() {
        return Err(anyhow!("active network has no admin configured"));
    }
    let invite = NetworkInvite {
        v: nostr_vpn_core::invite::NETWORK_INVITE_VERSION,
        network_name: String::new(),
        network_id: roster.network_id,
        inviter_npub: String::new(),
        inviter_node_name: String::new(),
        inviter_endpoints: active_inviter_endpoints(config),
        admins: roster
            .admins
            .iter()
            .map(|admin| nostr_vpn_core::invite::to_npub(admin))
            .collect(),
        participants: Vec::new(),
        relays: Vec::new(),
    };
    encode_network_invite(&invite)
}

fn active_inviter_endpoints(config: &AppConfig) -> Vec<String> {
    let mut configured = config.clone();
    maybe_autoconfigure_node(&mut configured);
    let endpoint = configured.node.endpoint.trim();
    normalize_fips_peer_endpoint_hint(endpoint)
        .into_iter()
        .collect()
}

pub(crate) async fn update_active_network_roster(
    args: UpdateRosterArgs,
    action: RosterEditAction,
) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let mut app = load_or_default_config(&config_path)?;
    if let Some(network_id) = args.network_id {
        app.set_active_network_id(&network_id)?;
    }
    let active_network_id = app
        .active_network_opt()
        .ok_or_else(|| anyhow!("create or join a network first"))?
        .id
        .clone();

    let resolver = crate::namecoin_resolver::ResolverHandle::from_config(&app)?;

    let mut changed = Vec::new();
    for participant in &args.participants {
        // Resolve `.bit` aliases (or canonicalize bare pubkeys) up-front so
        // the per-network mutators only ever see canonical hex/npub input.
        let resolved =
            crate::namecoin_resolver::resolve_with_handle(participant, resolver.as_ref()).await?;
        let canonical = resolved.hex_pubkey.clone();
        let normalized = match action {
            RosterEditAction::AddParticipant => {
                app.add_participant_to_network(&active_network_id, &canonical)?
            }
            RosterEditAction::RemoveParticipant => {
                app.remove_participant_from_network(&active_network_id, &canonical)?;
                canonical.clone()
            }
            RosterEditAction::AddAdmin => {
                app.add_admin_to_network(&active_network_id, &canonical)?
            }
            RosterEditAction::RemoveAdmin => {
                app.remove_admin_from_network(&active_network_id, &canonical)?;
                canonical.clone()
            }
        };
        if let Some(alias) = resolved.alias
            && matches!(
                action,
                RosterEditAction::AddParticipant | RosterEditAction::AddAdmin
            )
            && let Some(network) = app.network_by_id_mut(&active_network_id)
        {
            network.aliases.insert(normalized.clone(), alias);
        } else if matches!(
            action,
            RosterEditAction::RemoveParticipant | RosterEditAction::RemoveAdmin
        ) && let Some(network) = app.network_by_id_mut(&active_network_id)
        {
            network.aliases.remove(&normalized);
        }
        changed.push(normalized);
    }

    app.ensure_defaults();
    maybe_autoconfigure_node(&mut app);
    app.save(&config_path)?;
    maybe_reload_running_daemon(&config_path);

    let published = 0usize;

    if args.json {
        let active_network = app
            .active_network_opt()
            .ok_or_else(|| anyhow!("create or join a network first"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "network_id": app.effective_network_id(),
                "participants": active_network.participants,
                "admins": active_network.admins,
                "changed": changed,
                "published_recipients": published,
                "published": args.publish,
            }))?
        );
    } else {
        println!("saved {}", config_path.display());
        println!("network_id={}", app.effective_network_id());
        println!("changed={}", changed.join(","));
        if args.publish {
            println!("published_recipients={published}");
        }
    }

    Ok(())
}

fn network_should_adopt_invite(network: &nostr_vpn_core::config::NetworkConfig) -> bool {
    let trimmed = network.name.trim();
    network.participants.is_empty() && (trimmed.is_empty() || trimmed.starts_with("Network "))
}
