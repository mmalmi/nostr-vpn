use std::fs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use crate::config::{AppConfig, SharedNetworkRoster, normalize_nostr_pubkey};
use crate::fips_control::{JoinRosterControl, NetworkRoster, SignedRoster};
use crate::identity_bridge::NostrIdentityDeviceApprovalBootstrap;
use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct PreparedJoinApproval {
    pub updated_config: AppConfig,
    pub join_roster: JoinRosterControl,
}

pub fn prepare_join_approval(
    config: &AppConfig,
    network_entry_id: &str,
    bootstrap: &NostrIdentityDeviceApprovalBootstrap,
    approved_at: u64,
) -> Result<PreparedJoinApproval> {
    let signer_keys = config.nostr_keys()?;
    let signer_pubkey = signer_keys.public_key().to_hex();
    let network = config
        .network_by_id(network_entry_id)
        .ok_or_else(|| anyhow!("network not found"))?;
    if !network.admins.iter().any(|admin| admin == &signer_pubkey) {
        return Err(anyhow!("active network is not administered by this device"));
    }

    let (updated_config, shared) =
        stage_approved_config(config, network_entry_id, bootstrap, approved_at)?;
    let signed_roster = SignedRoster::sign(
        shared.network_id.clone(),
        NetworkRoster {
            network_name: shared.name.clone(),
            devices: shared.devices.clone(),
            admins: shared.admins.clone(),
            aliases: shared.aliases.clone(),
            signed_at: shared.updated_at,
        },
        &signer_keys,
    )
    .context("failed to sign approved Nostr VPN network roster")?;
    let join_roster = JoinRosterControl::new(signed_roster, &bootstrap.request_secret)
        .context("failed to bind approved roster to the join request")?;
    Ok(PreparedJoinApproval {
        updated_config,
        join_roster,
    })
}

fn stage_approved_config(
    config: &AppConfig,
    network_entry_id: &str,
    bootstrap: &NostrIdentityDeviceApprovalBootstrap,
    approved_at: u64,
) -> Result<(AppConfig, SharedNetworkRoster)> {
    let mut updated = config.clone();
    let previous_signed_at = updated
        .network_by_id(network_entry_id)
        .ok_or_else(|| anyhow!("network not found"))?
        .shared_roster_updated_at;
    let device_pubkey = normalize_nostr_pubkey(&bootstrap.device_app_key_npub)?;
    updated.add_participant_to_network(network_entry_id, &device_pubkey)?;
    if let Some(label) = bootstrap
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let _ = updated.set_peer_alias(&device_pubkey, label);
    }
    let signer_pubkey = updated.own_nostr_pubkey_hex()?;
    if let Some(network) = updated.network_by_id_mut(network_entry_id) {
        network
            .inbound_join_requests
            .retain(|pending| pending.requester != device_pubkey);
        network.shared_roster_updated_at = approved_at.max(previous_signed_at.saturating_add(1));
        network.shared_roster_signed_by = signer_pubkey;
    }
    let shared = updated.shared_network_roster(network_entry_id)?;
    Ok((updated, shared))
}

/// Serializes one approval read-modify-write across processes: the on-disk
/// roster freshness check and the durable writes hold the same exclusive lock
/// beside the config, so two writers that loaded the same roster timestamp can
/// no longer both pass the check and overwrite each other. `apply` queues the
/// durable outbox entry and saves the approved config while the lock is held;
/// nothing is written when the snapshot no longer matches disk, because saving
/// a stale snapshot would revert a concurrently approved device and kick it on
/// missing-self.
pub fn commit_join_approval(
    config_path: &Path,
    snapshot: &AppConfig,
    network_entry_id: &str,
    apply: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let _config_lock = exclusive_config_lock(config_path)?;
    let snapshot_at = snapshot
        .network_by_id(network_entry_id)
        .ok_or_else(|| anyhow!("network not found"))?
        .shared_roster_updated_at;
    let on_disk_at = AppConfig::load(config_path)?
        .network_by_id(network_entry_id)
        .map(|network| network.shared_roster_updated_at);
    if on_disk_at != Some(snapshot_at) {
        return Err(anyhow!(
            "network roster changed on disk while this approval was prepared; reload the network and approve again"
        ));
    }
    apply()
}

/// Same cross-process convention as the paid-route store: a private sidecar
/// lock file guarded by a blocking exclusive `File` lock.
fn exclusive_config_lock(config_path: &Path) -> Result<fs::File> {
    let lock_path = config_path.with_extension("toml.lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    options.custom_flags(libc::O_NOFOLLOW);
    let lock = options
        .open(&lock_path)
        .with_context(|| format!("failed to open config lock {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("failed to lock {}", config_path.display()))?;
    Ok(lock)
}
