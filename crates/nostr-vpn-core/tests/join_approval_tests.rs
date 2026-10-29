use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::time::{SystemTime, UNIX_EPOCH};

use nostr_sdk::prelude::Keys;
use nostr_vpn_core::config::{AppConfig, InternetSource, normalize_nostr_pubkey};
use nostr_vpn_core::fips_control::{JoinRosterControl, NetworkRoster, SignedRoster};
use nostr_vpn_core::identity_bridge::{
    NostrIdentityDeviceApprovalBootstrap, nostr_identity_device_approval_bootstrap,
};
use nostr_vpn_core::join_delivery::{
    complete_join_roster_delivery, join_roster_outbox_directory, load_join_rosters,
    queue_join_roster,
};
use nostr_vpn_core::join_requests::{
    MAX_NOSTR_JOIN_ROSTER_AGE_SECS, MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS,
    MAX_NOSTR_JOIN_ROSTER_PAST_SECS, commit_join_approval, prepare_join_approval,
};

const REQUESTED_AT: u64 = 1_778_998_000;
const SIGNED_AT: u64 = REQUESTED_AT + 30;

fn pending_joiner() -> AppConfig {
    let mut config = AppConfig::generated_without_networks();
    config.node_name = "Joining device".to_string();
    config
        .ensure_pending_nostr_join_request(REQUESTED_AT)
        .expect("create pending join request");
    config
}

fn signed_roster(joiner: &AppConfig, signer: &Keys, signed_at: u64) -> JoinRosterControl {
    let pending = joiner
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request");
    let roster = SignedRoster::sign(
        "8d4f34f5425bc50e",
        NetworkRoster {
            network_name: "Home Mesh".to_string(),
            devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
            admins: vec![signer.public_key().to_hex()],
            aliases: HashMap::from([(signer.public_key().to_hex(), "home-exit".to_string())]),
            signed_at,
        },
        signer,
    )
    .expect("sign roster");
    JoinRosterControl::new(roster, &pending.request.request_secret).expect("join roster control")
}

fn unique_temp_config_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "nostr-vpn-{name}-{}-{}.toml",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ))
}

fn approval_admin() -> (AppConfig, String) {
    let keys = Keys::generate();
    let mut admin = AppConfig::generated();
    admin.nostr.secret_key = keys.secret_key().to_secret_hex();
    admin.nostr.public_key = keys.public_key().to_hex();
    admin.networks[0].name = "Home Mesh".to_string();
    admin.networks[0].enabled = true;
    admin.networks[0].network_id = "8d4f34f5425bc50e".to_string();
    admin.networks[0].devices = vec![keys.public_key().to_hex()];
    admin.networks[0].admins = vec![keys.public_key().to_hex()];
    admin.ensure_defaults();
    admin.networks[0].shared_roster_updated_at = REQUESTED_AT;
    admin.networks[0].shared_roster_signed_by = keys.public_key().to_hex();
    let network_entry_id = admin.networks[0].id.clone();
    (admin, network_entry_id)
}

fn pending_bootstrap(config: &AppConfig) -> NostrIdentityDeviceApprovalBootstrap {
    let pending = config
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request");
    nostr_identity_device_approval_bootstrap(&pending.request).expect("request bootstrap")
}

fn approved_device_pubkey(config: &AppConfig) -> String {
    normalize_nostr_pubkey(&pending_bootstrap(config).device_app_key_npub).expect("device pubkey")
}

/// Both writers load the same on-disk roster snapshot, then race the commit.
/// The barrier holds both writers at the lock boundary so the interleaving is
/// deterministic: exactly one commit passes the freshness check and saves.
fn stage_and_commit(
    config_path: &std::path::Path,
    network_entry_id: &str,
    joiner: &AppConfig,
    approved_at: u64,
    both_loaded: &std::sync::Barrier,
) -> anyhow::Result<String> {
    let snapshot = AppConfig::load(config_path)?;
    both_loaded.wait();
    let prepared = prepare_join_approval(
        &snapshot,
        network_entry_id,
        &pending_bootstrap(joiner),
        approved_at,
    )?;
    commit_join_approval(config_path, &snapshot, network_entry_id, || {
        queue_join_roster(
            config_path,
            &approved_device_pubkey(joiner),
            &prepared.join_roster,
        )?;
        prepared.updated_config.save(config_path)
    })?;
    Ok(approved_device_pubkey(joiner))
}

#[test]
fn two_concurrent_approvals_serialize_into_exactly_one_durable_save() {
    let (admin, network_entry_id) = approval_admin();
    let config_path = unique_temp_config_path("approval-two-writers");
    admin.save(&config_path).expect("persist admin config");

    let first_joiner = pending_joiner();
    let second_joiner = pending_joiner();
    let first_pubkey = approved_device_pubkey(&first_joiner);
    let second_pubkey = approved_device_pubkey(&second_joiner);
    let both_loaded = std::sync::Barrier::new(2);

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            stage_and_commit(
                &config_path,
                &network_entry_id,
                &first_joiner,
                SIGNED_AT + 1,
                &both_loaded,
            )
        });
        let second = scope.spawn(|| {
            stage_and_commit(
                &config_path,
                &network_entry_id,
                &second_joiner,
                SIGNED_AT + 2,
                &both_loaded,
            )
        });
        (
            first.join().expect("first writer"),
            second.join().expect("second writer"),
        )
    });

    let (winner, error) = match (first, second) {
        (Ok(winner), Err(error)) | (Err(error), Ok(winner)) => (winner, error),
        _ => panic!("the config lock must admit exactly one of two concurrent approvals"),
    };
    assert!(
        error.to_string().contains("changed on disk"),
        "the losing writer must report the stale snapshot: {error:#}"
    );

    let on_disk = AppConfig::load(&config_path).expect("reload config");
    let devices = &on_disk
        .network_by_id(&network_entry_id)
        .expect("network")
        .devices;
    assert!(devices.contains(&winner), "winning approval stays durable");
    let loser = if winner == first_pubkey {
        &second_pubkey
    } else {
        &first_pubkey
    };
    assert!(!devices.contains(loser), "losing approval wrote nothing");

    let queued = load_join_rosters(&config_path);
    assert_eq!(queued.len(), 1, "only the winning approval queues delivery");
    assert_eq!(queued[0].1.recipient_npub, winner);

    let _ = fs::remove_dir_all(join_roster_outbox_directory(&config_path));
    let _ = fs::remove_file(config_path.with_extension("toml.lock"));
    fs::remove_file(&config_path).expect("remove temp config");
}

#[test]
fn one_signed_roster_completes_the_pending_join() {
    let mut joiner = pending_joiner();
    let signer = Keys::generate();
    let roster = signed_roster(&joiner, &signer, SIGNED_AT);
    let request_pubkey = joiner
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request")
        .request
        .request_pubkey
        .clone();

    let applied = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect("apply roster")
        .expect("join completed");

    assert_eq!(applied.request_pubkey, request_pubkey);
    assert_eq!(applied.signed_by_pubkey, signer.public_key().to_hex());
    assert_eq!(joiner.internet_source, InternetSource::Direct);
    assert!(
        joiner.exit_node.is_empty(),
        "joining a network must not silently select its admin as an exit node"
    );
    assert_ne!(
        joiner
            .pending_nostr_join_request
            .as_ref()
            .expect("next device approval request")
            .request
            .request_pubkey,
        request_pubkey
    );
    assert!(joiner.active_network_has_confirmed_local_identity());
    joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 2)
        .expect_err("consumed approval cannot be replayed");
}

#[test]
fn roster_for_another_device_is_rejected_without_mutating_the_joiner() {
    let mut joiner = pending_joiner();
    let other = pending_joiner();
    let signer = Keys::generate();
    let roster = signed_roster(&other, &signer, SIGNED_AT);
    let request_pubkey = joiner
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request")
        .request
        .request_pubkey
        .clone();

    let error = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect_err("wrong recipient must fail");
    assert!(error.to_string().contains("different join request"));
    assert!(joiner.networks.is_empty());
    assert_eq!(
        joiner
            .pending_nostr_join_request
            .as_ref()
            .expect("request remains pending")
            .request
            .request_pubkey,
        request_pubkey
    );
}

#[test]
fn self_signed_admin_roster_with_the_wrong_request_secret_is_rejected() {
    let mut joiner = pending_joiner();
    let attacker = Keys::generate();
    let roster = SignedRoster::sign(
        "attacker-network",
        NetworkRoster {
            network_name: "Not the requested network".to_string(),
            devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
            admins: vec![attacker.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: SIGNED_AT,
        },
        &attacker,
    )
    .expect("sign attacker roster");
    let roster = JoinRosterControl::new(roster, "attacker-secret").expect("join control");

    let error = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect_err("roster carrying the wrong request secret must fail");
    assert!(error.to_string().contains("different join request"));
    assert!(joiner.networks.is_empty());
    assert!(joiner.pending_nostr_join_request.is_some());
}

#[test]
fn roster_with_the_wrong_request_secret_is_rejected() {
    let mut joiner = pending_joiner();
    let signer = Keys::generate();
    let roster = SignedRoster::sign(
        "8d4f34f5425bc50e",
        NetworkRoster {
            network_name: "Home Mesh".to_string(),
            devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
            admins: vec![signer.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: SIGNED_AT,
        },
        &signer,
    )
    .expect("sign roster");
    let roster =
        JoinRosterControl::new(roster, "not-the-qr-request-secret").expect("bind unrelated secret");

    let error = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect_err("wrong request secret must fail");
    assert!(error.to_string().contains("different join request"));
    assert!(joiner.networks.is_empty());
    assert!(joiner.pending_nostr_join_request.is_some());
}

#[test]
fn roster_signer_must_be_listed_as_an_admin() {
    let mut joiner = pending_joiner();
    let signer = Keys::generate();
    let other_admin = Keys::generate();
    let pending = joiner
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request");
    let roster = SignedRoster::sign(
        "8d4f34f5425bc50e",
        NetworkRoster {
            network_name: "Home Mesh".to_string(),
            devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
            admins: vec![other_admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: SIGNED_AT,
        },
        &signer,
    )
    .expect("sign roster");
    let roster = JoinRosterControl::new(roster, &pending.request.request_secret)
        .expect("join roster control");

    let error = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect_err("unlisted signer must fail");
    assert!(error.to_string().contains("signer is not a roster admin"));
}

#[test]
fn invalid_roster_signature_is_rejected() {
    let mut joiner = pending_joiner();
    let signer = Keys::generate();
    let mut roster = signed_roster(&joiner, &signer, SIGNED_AT);
    roster.signed_roster.event.content = "tampered".to_string();

    assert!(
        joiner
            .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
            .expect_err("tampered roster must fail")
            .to_string()
            .contains("content must be empty")
    );
}

#[test]
fn roster_must_be_fresh_for_the_pending_request() {
    let signer = Keys::generate();

    let mut predating = pending_joiner();
    let roster = signed_roster(
        &predating,
        &signer,
        REQUESTED_AT - MAX_NOSTR_JOIN_ROSTER_PAST_SECS - 1,
    );
    assert!(
        predating
            .apply_nostr_join_roster(&roster, SIGNED_AT)
            .expect_err("predating roster must fail")
            .to_string()
            .contains("predates")
    );

    let mut future = pending_joiner();
    let roster = signed_roster(
        &future,
        &signer,
        SIGNED_AT + MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS + 1,
    );
    assert!(
        future
            .apply_nostr_join_roster(&roster, SIGNED_AT)
            .expect_err("future roster must fail")
            .to_string()
            .contains("future")
    );

    let mut stale = pending_joiner();
    let roster = signed_roster(&stale, &signer, SIGNED_AT);
    assert!(
        stale
            .apply_nostr_join_roster(&roster, SIGNED_AT + MAX_NOSTR_JOIN_ROSTER_AGE_SECS + 1)
            .expect_err("stale roster must fail")
            .to_string()
            .contains("stale")
    );
}

#[test]
fn roster_signed_before_the_request_still_joins_within_clock_skew_tolerance() {
    let signer = Keys::generate();

    // An admin clock two minutes behind the joiner must still approve the QR.
    let mut joiner = pending_joiner();
    let roster = signed_roster(&joiner, &signer, REQUESTED_AT - 120);
    joiner
        .apply_nostr_join_roster(&roster, REQUESTED_AT + 30)
        .expect("slightly predating roster joins within tolerance")
        .expect("join completed");

    // A roster signed before the pending request beyond the tolerance fails.
    let mut laggard = pending_joiner();
    let roster = signed_roster(
        &laggard,
        &signer,
        REQUESTED_AT - MAX_NOSTR_JOIN_ROSTER_PAST_SECS - 1,
    );
    assert!(
        laggard
            .apply_nostr_join_roster(&roster, REQUESTED_AT + 30)
            .expect_err("roster beyond the past tolerance must fail")
            .to_string()
            .contains("predates")
    );
}

#[test]
fn roster_signer_must_be_a_configured_admin_of_an_existing_network() {
    let signer = Keys::generate();

    // A matching network with no locally configured admins must not accept a
    // roster signer just because it administers the roster itself.
    let mut joiner = pending_joiner();
    let entry_id = joiner.add_network("Home Mesh");
    joiner
        .network_by_id_mut(&entry_id)
        .expect("network entry")
        .network_id = "8d4f34f5425bc50e".to_string();
    let roster = signed_roster(&joiner, &signer, SIGNED_AT);
    let error = joiner
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect_err("empty local admin list must reject a foreign signer");
    assert!(error.to_string().contains("not a configured admin"));
    assert!(joiner.pending_nostr_join_request.is_some());
    assert!(joiner.networks[0].devices.is_empty());

    // The same roster from a signer the network already lists joins normally.
    let mut configured = pending_joiner();
    let entry_id = configured.add_network("Home Mesh");
    let network = configured
        .network_by_id_mut(&entry_id)
        .expect("network entry");
    network.network_id = "8d4f34f5425bc50e".to_string();
    network.admins = vec![signer.public_key().to_hex()];
    let roster = signed_roster(&configured, &signer, SIGNED_AT);
    configured
        .apply_nostr_join_roster(&roster, SIGNED_AT + 1)
        .expect("configured admin signer completes the join")
        .expect("join completed");
}

#[test]
fn durable_delivery_contains_only_the_recipient_and_join_roster_control() {
    let joiner = pending_joiner();
    let signer = Keys::generate();
    let roster = signed_roster(&joiner, &signer, SIGNED_AT);
    let config_path = unique_temp_config_path("signed-roster-outbox");
    let recipient = joiner.own_nostr_pubkey_hex().expect("recipient");

    let path = queue_join_roster(&config_path, &recipient, &roster).expect("queue signed roster");
    let raw = fs::read_to_string(&path).expect("read queued roster");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse queued roster");
    let keys = value
        .as_object()
        .expect("outbox object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "attempts",
            "join_roster",
            "last_attempt_at",
            "recipient_npub",
            "version"
        ]
    );
    assert_eq!(value["attempts"], 0);
    assert_eq!(value["last_attempt_at"], 0);
    assert_eq!(
        value["join_roster"]["request_secret"],
        roster.request_secret
    );
    assert!(!raw.contains("receipt"));
    assert!(!raw.contains("context"));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path)
            .expect("outbox metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let queued = load_join_rosters(&config_path);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].1.join_roster, roster);

    complete_join_roster_delivery(&path, &queued[0].1).expect("confirm queued roster");
    fs::remove_dir(join_roster_outbox_directory(&config_path)).expect("remove outbox");
}
