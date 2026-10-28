use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::fips_control::JoinRosterControl;
use nostr_vpn_core::join_delivery::{
    expire_join_roster, join_roster_delivery_expired, load_join_rosters, record_join_roster_attempt,
};
use nostr_vpn_core::join_requests::AppliedNostrJoinRoster;
pub use nostr_vpn_core::join_requests::{
    PreparedJoinApproval, prepare_join_approval, prepare_manual_join_delivery,
};

use crate::mobile_tunnel::{MobileTunnel, MobileTunnelConfig};

pub fn apply_join_roster(
    config: &mut AppConfig,
    join_roster: &JoinRosterControl,
    now: u64,
) -> Result<Option<AppliedNostrJoinRoster>> {
    config.apply_nostr_join_roster(join_roster, now)
}

/// Delivers the ordinary queued join-roster outbox through the embedded FIPS
/// control plane. The runtime has no system tunnel and does not install or
/// control a platform service.
pub fn deliver_queued_join_rosters(config_path: &Path, timeout: Duration) -> Result<usize> {
    let app = AppConfig::load(config_path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let queued = load_join_rosters(config_path)
        .into_iter()
        .filter(|(path, delivery)| {
            if !join_roster_delivery_expired(delivery, now) {
                return true;
            }
            if let Err(error) = expire_join_roster(path, delivery) {
                eprintln!(
                    "failed to remove expired join approval {}: {error}",
                    path.display()
                );
            }
            false
        })
        .collect::<Vec<_>>();
    if queued.is_empty() {
        return Ok(0);
    }

    let participants = app.participant_pubkeys_hex();
    for (_, delivery) in &queued {
        if !participants.contains(&delivery.recipient_npub) {
            return Err(anyhow!(
                "join roster recipient {} is not in the active roster",
                delivery.recipient_npub
            ));
        }
    }

    let mut runtime_config = MobileTunnelConfig::from_app_with_config_path(&app, config_path)?;
    runtime_config.config_path.clear();
    runtime_config.network_id.clear();
    runtime_config.advertised_endpoint.clear();
    runtime_config.listen_port = 0;
    runtime_config.route_targets.clear();
    runtime_config.connect_to_non_roster_fips_peers = true;
    runtime_config.device_approval_pending = true;
    runtime_config.excluded_routes.clear();
    runtime_config.dns_servers.clear();
    runtime_config.magic_dns_server.clear();
    runtime_config.wireguard_exit = None;
    let runtime_json =
        serde_json::to_string(&runtime_config).context("encode FIPS join delivery runtime")?;
    let runtime = MobileTunnel::start(&runtime_json)?;

    let mut delivered = 0;
    for (path, mut delivery) in queued {
        let result =
            runtime.send_join_roster(&delivery.recipient_npub, &delivery.join_roster, timeout);
        let attempted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        record_join_roster_attempt(&path, &mut delivery, attempted_at)?;
        if result.is_ok() {
            nostr_vpn_core::join_delivery::complete_join_roster_delivery(&path, &delivery)?;
            delivered += 1;
        }
        result?;
    }
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::config::normalize_nostr_pubkey;
    use nostr_vpn_core::fips_control::{NetworkRoster, SignedRoster};
    use nostr_vpn_core::identity_bridge::NostrIdentityDeviceApprovalBootstrap;
    use nostr_vpn_core::identity_bridge::nostr_identity_device_approval_bootstrap;

    use super::*;

    const REQUESTED_AT: u64 = 1_778_998_000;

    fn pending_joiner() -> AppConfig {
        let mut joiner = AppConfig::generated_without_networks();
        joiner.node_name = "Joining device".to_string();
        joiner
            .ensure_pending_nostr_join_request(REQUESTED_AT)
            .expect("pending request");
        joiner
    }

    fn pending_bootstrap(config: &AppConfig) -> NostrIdentityDeviceApprovalBootstrap {
        let pending = config
            .pending_nostr_join_request
            .as_ref()
            .expect("pending request");
        nostr_identity_device_approval_bootstrap(&pending.request).expect("request bootstrap")
    }

    fn approval_admin() -> (AppConfig, String) {
        let keys = Keys::generate();
        let mut admin = AppConfig::generated();
        admin.nostr.secret_key = keys.secret_key().to_secret_hex();
        admin.nostr.public_key = keys.public_key().to_hex();
        admin.networks[0].name = "Home".to_string();
        admin.networks[0].enabled = true;
        admin.networks[0].network_id = "8d4f34f5425bc50e".to_string();
        admin.networks[0].devices = vec![keys.public_key().to_hex()];
        admin.networks[0].admins = vec![keys.public_key().to_hex()];
        admin.node.advertise_exit_node = true;
        admin.ensure_defaults();
        admin.networks[0].shared_roster_updated_at = REQUESTED_AT;
        admin.networks[0].shared_roster_signed_by = keys.public_key().to_hex();
        let network_entry_id = admin.networks[0].id.clone();
        (admin, network_entry_id)
    }

    #[test]
    fn approval_is_one_admin_signed_roster() {
        let joiner = pending_joiner();
        let bootstrap = pending_bootstrap(&joiner);
        let (admin, network_id) = approval_admin();

        let prepared = prepare_join_approval(&admin, &network_id, &bootstrap, REQUESTED_AT + 1)
            .expect("prepare signed roster");
        prepared
            .join_roster
            .signed_roster
            .verify()
            .expect("verify roster");
        let roster = prepared
            .join_roster
            .signed_roster
            .roster()
            .expect("decode roster");
        assert!(roster.devices.contains(
            &normalize_nostr_pubkey(&bootstrap.device_app_key_npub).expect("device pubkey")
        ));
        assert_eq!(
            prepared
                .join_roster
                .signed_roster
                .signer_pubkey_hex()
                .expect("signer"),
            admin.own_nostr_pubkey_hex().expect("admin pubkey")
        );
        let shared = prepared
            .updated_config
            .shared_network_roster(&network_id)
            .expect("updated shared roster");
        assert_eq!(
            roster.signed_at, shared.updated_at,
            "approval and durable config must use one canonical roster timestamp"
        );
        let regenerated = SignedRoster::sign(
            shared.network_id,
            NetworkRoster {
                network_name: shared.name,
                devices: shared.devices,
                admins: shared.admins,
                aliases: shared.aliases,
                signed_at: shared.updated_at,
            },
            &prepared.updated_config.nostr_keys().expect("admin keys"),
        )
        .expect("regenerate active roster");
        assert_eq!(
            prepared.join_roster.signed_roster.artifact_hash(),
            regenerated.artifact_hash(),
            "background roster sync must reuse the exact approved artifact identity"
        );
    }

    #[test]
    fn accepting_a_fresh_request_for_an_existing_device_is_idempotent() {
        let joiner = pending_joiner();
        let bootstrap = pending_bootstrap(&joiner);
        let device_pubkey =
            normalize_nostr_pubkey(&bootstrap.device_app_key_npub).expect("device pubkey");
        let (mut admin, network_id) = approval_admin();
        admin.networks[0].devices.push(device_pubkey.clone());
        admin.networks[0].devices.sort();
        admin.networks[0].devices.dedup();

        let prepared = prepare_join_approval(&admin, &network_id, &bootstrap, REQUESTED_AT + 1)
            .expect("re-accept existing device");
        let roster = prepared
            .join_roster
            .signed_roster
            .roster()
            .expect("decode refreshed roster");

        assert_eq!(
            roster
                .devices
                .iter()
                .filter(|configured| *configured == &device_pubkey)
                .count(),
            1,
            "re-acceptance must not duplicate the roster member"
        );
        assert_eq!(
            prepared.join_roster.request_secret,
            bootstrap.request_secret
        );
        assert_eq!(roster.signed_at, REQUESTED_AT + 1);
    }

    #[test]
    fn joiner_applies_the_signed_roster_without_receipt_or_context() {
        let mut joiner = pending_joiner();
        let bootstrap = pending_bootstrap(&joiner);
        let request_pubkey = joiner
            .pending_nostr_join_request
            .as_ref()
            .expect("pending request")
            .request
            .request_pubkey
            .clone();
        let (admin, network_id) = approval_admin();
        let prepared = prepare_join_approval(&admin, &network_id, &bootstrap, REQUESTED_AT + 30)
            .expect("prepare signed roster");

        let applied = apply_join_roster(&mut joiner, &prepared.join_roster, REQUESTED_AT + 31)
            .expect("apply roster")
            .expect("roster applied");
        assert_eq!(applied.request_pubkey, request_pubkey);
        assert_eq!(
            applied.signed_by_pubkey,
            admin.own_nostr_pubkey_hex().expect("admin pubkey")
        );
        let next_request = joiner
            .pending_nostr_join_request
            .as_ref()
            .expect("next join request remains available");
        assert_ne!(next_request.request.request_pubkey, request_pubkey);
        assert_eq!(joiner.networks.len(), 1);
        assert_eq!(
            joiner.internet_source,
            nostr_vpn_core::config::InternetSource::Direct
        );
        assert!(
            joiner.exit_node.is_empty(),
            "joining a network must not silently make its admin the internet exit"
        );
    }

    #[test]
    fn joined_device_can_accept_another_network() {
        let mut joiner = pending_joiner();
        let first_bootstrap = pending_bootstrap(&joiner);
        let (first_admin, first_network_id) = approval_admin();
        let first = prepare_join_approval(
            &first_admin,
            &first_network_id,
            &first_bootstrap,
            REQUESTED_AT + 10,
        )
        .expect("prepare first network");
        apply_join_roster(&mut joiner, &first.join_roster, REQUESTED_AT + 11)
            .expect("apply first network")
            .expect("first network applied");

        joiner
            .ensure_pending_nostr_join_request(REQUESTED_AT + 12)
            .expect("request another network");
        let second_bootstrap = pending_bootstrap(&joiner);
        let (mut second_admin, second_network_id) = approval_admin();
        second_admin.networks[0].network_id = "second-network".to_string();
        let second = prepare_join_approval(
            &second_admin,
            &second_network_id,
            &second_bootstrap,
            REQUESTED_AT + 20,
        )
        .expect("prepare second network");

        apply_join_roster(&mut joiner, &second.join_roster, REQUESTED_AT + 21)
            .expect("apply second network")
            .expect("second network applied");

        assert_eq!(joiner.networks.len(), 2);
        assert_eq!(joiner.active_network().network_id, "second-network");
        assert!(joiner.pending_nostr_join_request.is_some());
    }

    #[test]
    fn non_admin_cannot_prepare_a_join_roster() {
        let joiner = pending_joiner();
        let bootstrap = pending_bootstrap(&joiner);
        let (mut admin, network_id) = approval_admin();
        admin.networks[0].admins = vec![Keys::generate().public_key().to_hex()];

        let error = prepare_join_approval(&admin, &network_id, &bootstrap, REQUESTED_AT + 1)
            .expect_err("non-admin must be rejected");
        assert!(error.to_string().contains("not administered"));
    }

    #[test]
    fn invalid_bootstrap_device_key_is_rejected() {
        let (admin, network_id) = approval_admin();
        let bootstrap = NostrIdentityDeviceApprovalBootstrap {
            device_app_key_npub: "not-a-key".to_string(),
            request_npub: Keys::generate()
                .public_key()
                .to_bech32()
                .expect("request npub"),
            request_secret: "unused-over-fips-tcp".to_string(),
            label: None,
        };
        assert!(prepare_join_approval(&admin, &network_id, &bootstrap, REQUESTED_AT + 1).is_err());
    }

    #[test]
    fn manual_join_delivery_requires_the_configured_admin_and_exact_identifier_tuple() {
        let joiner_keys = Keys::generate();
        let joiner = joiner_keys.public_key().to_hex();
        let (mut admin, network_entry_id) = approval_admin();
        admin
            .add_participant_to_network(&network_entry_id, &joiner)
            .expect("preauthorize manual joiner");
        let delivery = prepare_manual_join_delivery(&admin, &network_entry_id, &joiner)
            .expect("prepare manual delivery");
        let mesh_network_id = admin.networks[0].network_id.clone();
        let admin_pubkey = admin.own_nostr_pubkey_hex().expect("admin pubkey");

        let mut joining = AppConfig::generated_without_networks();
        joining.nostr.secret_key = joiner_keys.secret_key().to_secret_hex();
        joining.nostr.public_key = joiner.clone();
        joining
            .add_manual_join_network(&admin_pubkey, &mesh_network_id)
            .expect("configure manual join");
        let signed_at = delivery.signed_roster.signed_at();
        assert_eq!(
            joining
                .apply_manual_join_roster(&delivery, signed_at)
                .expect("apply exact manual delivery"),
            Some(mesh_network_id.clone())
        );
        assert!(joining.active_network().shared_roster_updated_at > 0);
        assert_eq!(
            joining
                .apply_manual_join_roster(&delivery, signed_at)
                .expect("confirmed network ignores replay"),
            None
        );

        let wrong_admin = Keys::generate().public_key().to_hex();
        let mut untrusted = AppConfig::generated_without_networks();
        untrusted.nostr.secret_key = joiner_keys.secret_key().to_secret_hex();
        untrusted.nostr.public_key = joiner;
        untrusted
            .add_manual_join_network(&wrong_admin, &mesh_network_id)
            .expect("configure different manual admin");
        assert_eq!(
            untrusted
                .apply_manual_join_roster(&delivery, signed_at)
                .expect("unconfigured signer is ignored"),
            None
        );

        let mut wrong_token = delivery;
        wrong_token.request_secret.push('x');
        let mut exact = AppConfig::generated_without_networks();
        exact.nostr.secret_key = joiner_keys.secret_key().to_secret_hex();
        exact.nostr.public_key = joiner_keys.public_key().to_hex();
        exact
            .add_manual_join_network(&admin_pubkey, &mesh_network_id)
            .expect("configure exact manual admin");
        assert!(
            exact
                .apply_manual_join_roster(&wrong_token, signed_at)
                .is_err(),
            "wrong tuple token must be rejected"
        );
    }
}
