use std::{collections::HashMap, fs};

use crate::*;
use nostr_sdk::prelude::{Keys, Tag};
use nostr_vpn_core::config::{NetworkConfig, PendingOutboundJoinRequest};

fn activate_first_network(config: &mut AppConfig) {
    let network_id = config.networks[0].id.clone();
    config
        .set_network_enabled(&network_id, true)
        .expect("activate first network");
}

#[test]
fn participants_override_targets_the_active_network() {
    let alice = Keys::generate().public_key().to_hex();
    let bob = Keys::generate().public_key().to_hex();
    let carol = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    config.networks = vec![
        NetworkConfig {
            id: "home".to_string(),
            name: "Home".to_string(),
            enabled: false,
            network_id: "mesh-home".to_string(),
            join_secret: "home-secret".to_string(),
            devices: vec![alice.clone()],
            removed_devices: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        },
        NetworkConfig {
            id: "work".to_string(),
            name: "Work".to_string(),
            enabled: true,
            network_id: "mesh-work".to_string(),
            join_secret: "work-secret".to_string(),
            devices: vec![bob],
            removed_devices: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        },
    ];
    config.ensure_defaults();

    apply_participants_override(&mut config, vec![carol.clone()]).expect("apply override");

    assert_eq!(config.participant_pubkeys_hex(), vec![carol.clone()]);
    assert_eq!(
        config.network_by_id("home").expect("home network").devices,
        vec![alice]
    );
    assert_eq!(
        config.network_by_id("work").expect("work network").devices,
        vec![carol]
    );
}

#[test]
fn participants_override_preserves_selected_exit_node_when_it_remains_a_member() {
    let exit_peer = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    config.exit_node = exit_peer.clone();

    apply_participants_override(&mut config, vec![exit_peer.clone()]).expect("apply override");

    assert_eq!(config.participant_pubkeys_hex(), vec![exit_peer.clone()]);
    assert_eq!(config.exit_node, exit_peer);
}

#[test]
fn pending_join_request_recipients_use_selected_admin_and_skip_self() {
    let mut config = AppConfig::generated();
    let own_pubkey = Keys::parse(&config.nostr.secret_key)
        .expect("own keys")
        .public_key()
        .to_hex();
    let admin = Keys::generate().public_key().to_hex();
    let backup_admin = Keys::generate().public_key().to_hex();

    config.networks[0].enabled = true;
    config.networks[0].devices.clear();
    config.networks[0].admins = vec![own_pubkey, admin.clone(), backup_admin];
    config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
        recipient: admin.clone(),
        requested_at: 123,
    });

    assert_eq!(pending_fips_join_request_recipients(&config), vec![admin]);
}

#[test]
fn pending_join_request_recipients_fall_back_to_admins_without_self() {
    let mut config = AppConfig::generated();
    let own_pubkey = Keys::parse(&config.nostr.secret_key)
        .expect("own keys")
        .public_key()
        .to_hex();
    let admin = Keys::generate().public_key().to_hex();
    let stale_recipient = Keys::generate().public_key().to_hex();

    config.networks[0].enabled = true;
    config.networks[0].devices.clear();
    config.networks[0].admins = vec![own_pubkey, admin.clone()];
    config.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
        recipient: stale_recipient,
        requested_at: 123,
    });

    assert_eq!(pending_fips_join_request_recipients(&config), vec![admin]);
}

#[test]
fn participants_override_marks_shared_roster_updated_for_admin_owned_network() {
    let member = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    let own_pubkey = config.own_nostr_pubkey_hex().expect("own nostr pubkey");
    config.networks[0].admins = vec![own_pubkey.clone()];
    config.networks[0].shared_roster_updated_at = 0;
    config.networks[0].shared_roster_signed_by.clear();

    apply_participants_override(&mut config, vec![member.clone()]).expect("apply override");

    let active_network = config.active_network();
    assert_eq!(active_network.devices, vec![member]);
    assert!(active_network.shared_roster_updated_at > 0);
    assert_eq!(active_network.shared_roster_signed_by, own_pubkey);
}

#[test]
fn shared_roster_publish_allowed_only_for_current_signer() {
    let other_admin = Keys::generate().public_key().to_hex();
    let outsider = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    let own_pubkey = config.own_nostr_pubkey_hex().expect("own nostr pubkey");
    activate_first_network(&mut config);
    let network_id = config.active_network().id.clone();
    config.networks[0].admins = vec![own_pubkey.clone(), other_admin.clone()];

    assert!(shared_roster_publish_allowed(
        &config,
        &network_id,
        &own_pubkey,
        ""
    ));
    assert!(shared_roster_publish_allowed(
        &config,
        &network_id,
        &own_pubkey,
        &own_pubkey
    ));
    assert!(!shared_roster_publish_allowed(
        &config,
        &network_id,
        &own_pubkey,
        &other_admin
    ));
    assert!(!shared_roster_publish_allowed(
        &config,
        &network_id,
        &outsider,
        &outsider
    ));
}

#[test]
fn forwarded_signed_roster_can_be_selected_for_peer_sync() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-forwarded-signed-roster-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");

    let mut alice = AppConfig::generated();
    activate_first_network(&mut alice);
    let alice_pubkey = alice.own_nostr_pubkey_hex().expect("alice pubkey");

    let mut bob = AppConfig::generated();
    activate_first_network(&mut bob);
    let bob_pubkey = bob.own_nostr_pubkey_hex().expect("bob pubkey");
    let carol_pubkey = Keys::generate().public_key().to_hex();

    alice.networks[0].name = "Home".to_string();
    alice.networks[0].network_id = "mesh".to_string();
    alice.networks[0].devices = vec![bob_pubkey.clone(), carol_pubkey.clone()];
    alice.networks[0].admins = vec![alice_pubkey.clone(), bob_pubkey.clone()];
    alice.networks[0].shared_roster_updated_at = 1_726_000_000;
    alice.networks[0].shared_roster_signed_by = alice_pubkey.clone();

    let alice_shared = alice
        .shared_network_roster(&alice.networks[0].id)
        .expect("alice shared roster");
    let signed = SignedRoster::sign(
        &alice_shared.network_id,
        network_roster_from_shared(&alice_shared),
        &alice.nostr_keys().expect("alice keys"),
    )
    .expect("sign roster");

    bob.networks[0].name = "Home".to_string();
    bob.networks[0].network_id = "mesh".to_string();
    bob.networks[0].devices = vec![alice_pubkey.clone(), carol_pubkey];
    bob.networks[0].admins = vec![alice_pubkey, bob_pubkey];
    bob.networks[0].shared_roster_updated_at = signed.signed_at();
    bob.networks[0].shared_roster_signed_by = signed.signer_pubkey_hex().expect("signer");

    upsert_signed_roster(&signed_rosters_file_path(&config_path), signed.clone())
        .expect("persist signed roster");

    let forwarded = active_signed_roster_for_sync(&bob, &config_path, true)
        .expect("load forwarded roster")
        .expect("forwarded roster should be selected");
    assert_eq!(forwarded.artifact_hash(), signed.artifact_hash());
    assert!(
        active_signed_roster_for_sync(&bob, &config_path, false)
            .expect("load own-signed roster")
            .is_none(),
        "explicit admin publish should not re-sign or forward another admin's stored artifact"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inbound_fips_roster_requires_signed_event() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-unsigned-roster-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut status = String::new();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.networks[0].network_id = "mesh".to_string();

    let error = persist_shared_network_roster(&mut config, &config_path, None, &mut status)
        .expect_err("unsigned roster frame must be rejected");

    assert!(
        error.to_string().contains("missing signed roster event"),
        "unexpected error: {error:#}"
    );
    assert_eq!(config.networks[0].shared_roster_updated_at, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn join_roster_receipt_requires_exact_durable_config_and_roster_artifact() {
    let now = unix_timestamp();
    let dir = std::env::temp_dir().join(format!(
        "nvpn-durable-join-roster-{}-{now}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut joiner = AppConfig::generated_without_networks();
    joiner
        .ensure_pending_nostr_join_request(now.saturating_sub(10))
        .expect("create pending join request");
    joiner.save(&config_path).expect("persist pending joiner");
    let admin = Keys::generate();
    let signed_roster = SignedRoster::sign(
        "durable-network",
        NetworkRoster {
            network_name: "Durable Home".to_string(),
            devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
            admins: vec![admin.public_key().to_hex()],
            aliases: HashMap::new(),
            signed_at: now,
        },
        &admin,
    )
    .expect("sign join roster");
    let request_secret = joiner
        .pending_nostr_join_request
        .as_ref()
        .expect("pending request")
        .request
        .request_secret
        .clone();
    let control = JoinRosterControl::new(signed_roster.clone(), &request_secret)
        .expect("join roster control");
    let mut status = String::new();

    assert!(
        persist_join_roster(&mut joiner, &config_path, &control, &mut status)
            .expect("persist join roster")
            .is_some()
    );
    assert!(
        join_roster_is_durably_persisted(&config_path, &control)
            .expect("verify durable join roster")
    );
    assert!(
        persist_join_roster(&mut joiner, &config_path, &control, &mut status)
            .expect("duplicate join roster")
            .is_none()
    );
    assert!(
        join_roster_is_durably_persisted(&config_path, &control).expect("verify durable duplicate")
    );

    let other = JoinRosterControl::new(
        SignedRoster::sign(
            "durable-network",
            NetworkRoster {
                network_name: "Other".to_string(),
                devices: vec![joiner.own_nostr_pubkey_hex().expect("joiner pubkey")],
                admins: vec![admin.public_key().to_hex()],
                aliases: HashMap::new(),
                signed_at: now.saturating_add(1),
            },
            &admin,
        )
        .expect("sign other roster"),
        &request_secret,
    )
    .expect("other join roster control");
    assert!(
        !join_roster_is_durably_persisted(&config_path, &other)
            .expect("reject unpersisted receipt")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inbound_fips_roster_accepts_admin_signed_event() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-admin-roster-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut status = String::new();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    let admin = config.nostr_keys().expect("admin keys");
    let admin_hex = admin.public_key().to_hex();
    let member_hex = Keys::generate().public_key().to_hex();
    config.networks[0].name = "Original".to_string();
    config.networks[0].network_id = "mesh".to_string();
    config.networks[0].admins = vec![admin_hex.clone()];
    config.networks[0].shared_roster_updated_at = 0;
    config.networks[0].shared_roster_signed_by.clear();

    let signed = SignedRoster::sign(
        "mesh",
        NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member_hex.clone()],
            admins: vec![admin_hex.clone()],
            aliases: HashMap::new(),
            signed_at: 1_726_000_000,
        },
        &admin,
    )
    .expect("sign roster");

    let result =
        persist_shared_network_roster(&mut config, &config_path, Some(&signed), &mut status)
            .expect("admin-signed roster should apply");

    assert_eq!(result.as_deref(), Some("Home"));
    assert_eq!(config.networks[0].name, "Home");
    assert_eq!(config.networks[0].devices, vec![member_hex]);
    assert_eq!(config.networks[0].admins, vec![admin_hex.clone()]);
    assert_eq!(config.networks[0].shared_roster_updated_at, 1_726_000_000);
    assert_eq!(config.networks[0].shared_roster_signed_by, admin_hex);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inbound_fips_roster_rejects_tampered_signed_event() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-tampered-roster-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut status = String::new();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    let admin = config.nostr_keys().expect("admin keys");
    let admin_hex = admin.public_key().to_hex();
    let member_hex = Keys::generate().public_key().to_hex();
    config.networks[0].name = "Original".to_string();
    config.networks[0].network_id = "mesh".to_string();
    config.networks[0].admins = vec![admin_hex.clone()];
    config.networks[0].shared_roster_updated_at = 0;
    config.networks[0].shared_roster_signed_by.clear();

    let signed = SignedRoster::sign(
        "mesh",
        NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member_hex],
            admins: vec![admin_hex],
            aliases: HashMap::new(),
            signed_at: 1_726_000_000,
        },
        &admin,
    )
    .expect("sign roster");
    let mut event = signed.event.clone();
    event
        .tags
        .push(Tag::parse(["name", "Office"]).expect("tag"));
    let tampered = SignedRoster { event };

    let error =
        persist_shared_network_roster(&mut config, &config_path, Some(&tampered), &mut status)
            .expect_err("tampered signed roster frame must be rejected");

    assert!(
        error.to_string().contains("invalid roster event signature"),
        "unexpected error: {error:#}"
    );
    assert_eq!(config.networks[0].name, "Original");
    assert_eq!(config.networks[0].shared_roster_updated_at, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inbound_fips_roster_ignores_signed_event_from_non_admin_author() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-non-admin-roster-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");
    let mut status = String::new();

    let known_admin = Keys::generate();
    let outsider = Keys::generate();
    let known_admin_hex = known_admin.public_key().to_hex();
    let outsider_hex = outsider.public_key().to_hex();
    let member_hex = Keys::generate().public_key().to_hex();

    let mut config = AppConfig::generated();
    activate_first_network(&mut config);
    config.networks[0].name = "Original".to_string();
    config.networks[0].network_id = "mesh".to_string();
    config.networks[0].admins = vec![known_admin_hex.clone()];
    config.networks[0].shared_roster_updated_at = 0;
    config.networks[0].shared_roster_signed_by.clear();

    let signed = SignedRoster::sign(
        "mesh",
        NetworkRoster {
            network_name: "Home".to_string(),
            devices: vec![member_hex],
            admins: vec![known_admin_hex, outsider_hex],
            aliases: HashMap::new(),
            signed_at: 1_726_000_000,
        },
        &outsider,
    )
    .expect("sign roster");

    let result =
        persist_shared_network_roster(&mut config, &config_path, Some(&signed), &mut status)
            .expect("valid event from non-admin author should be ignored");

    assert!(result.is_none());
    assert_eq!(config.networks[0].name, "Original");
    assert_eq!(config.networks[0].shared_roster_updated_at, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_overrides_set_the_active_network_mesh_id() {
    let nonce = unix_timestamp();
    let dir = std::env::temp_dir().join(format!("nvpn-load-config-override-{nonce}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");

    let mut config = AppConfig::generated();
    config.networks = vec![
        NetworkConfig {
            id: "home".to_string(),
            name: "Home".to_string(),
            enabled: false,
            network_id: "mesh-home".to_string(),
            join_secret: "home-secret".to_string(),
            devices: vec!["11".repeat(32)],
            removed_devices: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        },
        NetworkConfig {
            id: "work".to_string(),
            name: "Work".to_string(),
            enabled: true,
            network_id: "mesh-work".to_string(),
            join_secret: "work-secret".to_string(),
            devices: vec!["22".repeat(32)],
            removed_devices: Vec::new(),
            admins: Vec::new(),
            listen_for_join_requests: true,
            join_request_admin: String::new(),
            local_identity_confirmation_pending: false,
            outbound_join_request: None,
            inbound_join_requests: Vec::new(),
            shared_roster_updated_at: 0,
            shared_roster_signed_by: String::new(),
            shared_roster_artifact_hash: String::new(),
        },
    ];
    config.ensure_defaults();
    config.save(&config_path).expect("save temp config");

    let (loaded, network_id) = load_config_with_overrides(
        &config_path,
        Some("mesh-override".to_string()),
        Vec::new(),
        ConfigLoadMode::Persist,
    )
    .expect("load config with override");

    assert_eq!(network_id, "mesh-override");
    assert_eq!(loaded.effective_network_id(), "mesh-override");
    assert_eq!(
        loaded
            .network_by_id("home")
            .expect("home network")
            .network_id,
        "mesh-home"
    );
    assert_eq!(
        loaded
            .network_by_id("work")
            .expect("work network")
            .network_id,
        "mesh-override"
    );

    let _ = fs::remove_file(&config_path);
    let _ = fs::remove_dir_all(&dir);
}
