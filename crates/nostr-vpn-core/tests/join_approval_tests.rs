use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::time::{SystemTime, UNIX_EPOCH};

use nostr_sdk::prelude::Keys;
use nostr_vpn_core::config::{AppConfig, InternetSource};
use nostr_vpn_core::fips_control::{JoinRosterControl, NetworkRoster, SignedRoster};
use nostr_vpn_core::join_delivery::{
    complete_join_roster_delivery, join_roster_outbox_directory, load_join_rosters,
    queue_join_roster,
};
use nostr_vpn_core::join_requests::{
    MAX_NOSTR_JOIN_ROSTER_AGE_SECS, MAX_NOSTR_JOIN_ROSTER_FUTURE_SECS,
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
    let roster = signed_roster(&predating, &signer, REQUESTED_AT - 1);
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
fn durable_delivery_contains_only_the_recipient_and_join_roster_control() {
    let joiner = pending_joiner();
    let signer = Keys::generate();
    // A fixed timestamp would expire the entry before load_join_rosters reads it.
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let roster = signed_roster(&joiner, &signer, signed_at);
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
