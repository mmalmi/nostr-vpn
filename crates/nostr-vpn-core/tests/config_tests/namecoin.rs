use nostr_sdk::prelude::Keys;
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::namecoin_name_verify::{ChainNetworkRecord, parse_namecoin_network_id};
use std::collections::HashMap;

fn seed_namecoin_network(network_id: &str, admins: &[String]) -> (AppConfig, Keys) {
    let own = Keys::generate();
    let mut config = AppConfig::generated();
    config.nostr.secret_key = own.secret_key().to_secret_hex();
    config.nostr.public_key = own.public_key().to_hex();
    config.networks[0].network_id = network_id.to_string();
    config.networks[0].admins = admins.to_vec();
    config.networks[0].participants = admins.to_vec();
    config.ensure_defaults();
    (config, own)
}

#[test]
fn legacy_network_ids_still_apply_rosters_without_chain_record() {
    let admin = Keys::generate();
    let admin_hex = admin.public_key().to_hex();
    let (mut config, _own) = seed_namecoin_network("mesh-home", std::slice::from_ref(&admin_hex));
    let own_hex = config.nostr.public_key.clone();

    let changed = config
        .apply_admin_signed_shared_roster_with_chain(
            "mesh-home",
            "Home",
            vec![admin_hex.clone(), own_hex.clone()],
            vec![admin_hex.clone()],
            HashMap::new(),
            1_726_000_000,
            &admin_hex,
            None,
        )
        .expect("non-namecoin apply");
    assert!(changed);
    assert_eq!(config.networks[0].admins, vec![admin_hex]);
    assert!(config.networks[0].chain_quarantine_reason.is_empty());
}

#[test]
fn namecoin_anchored_roster_apply_quarantines_when_admin_diverges() {
    let admin = Keys::generate();
    let admin_hex = admin.public_key().to_hex();
    let attacker = Keys::generate().public_key().to_hex();
    let (mut config, _own) = seed_namecoin_network("d/acmevpn", std::slice::from_ref(&admin_hex));

    let chain = ChainNetworkRecord {
        admins: vec![admin_hex.clone()],
        network_name_hint: Some("Acme".to_string()),
    };

    // Proposed roster injects a new admin that is NOT in the chain anchor.
    let proposed_admins = vec![admin_hex.clone(), attacker.clone()];
    let changed = config
        .apply_admin_signed_shared_roster_with_chain(
            "d/acmevpn",
            "Acme",
            vec![admin_hex.clone()],
            proposed_admins,
            HashMap::new(),
            1_726_000_000,
            &admin_hex,
            Some(&chain),
        )
        .expect("apply returns Ok and quarantines silently");
    assert!(!changed, "diverging roster must not be applied");
    assert!(
        config.networks[0]
            .chain_quarantine_reason
            .contains("admin set diverged"),
        "quarantine reason set: {}",
        config.networks[0].chain_quarantine_reason
    );
}

#[test]
fn namecoin_anchored_roster_apply_succeeds_for_subset() {
    let admin = Keys::generate();
    let admin_hex = admin.public_key().to_hex();
    let extra = Keys::generate().public_key().to_hex();
    let (mut config, _own) = seed_namecoin_network("acmevpn.bit", std::slice::from_ref(&admin_hex));

    let chain = ChainNetworkRecord {
        admins: vec![admin_hex.clone(), extra.clone()],
        network_name_hint: None,
    };

    let changed = config
        .apply_admin_signed_shared_roster_with_chain(
            "acmevpn.bit",
            "Acme",
            vec![admin_hex.clone()],
            vec![admin_hex.clone(), extra.clone()],
            HashMap::new(),
            1_726_000_000,
            &admin_hex,
            Some(&chain),
        )
        .expect("subset apply");
    assert!(changed);
    assert!(config.networks[0].chain_quarantine_reason.is_empty());
    let mut expected = vec![admin_hex, extra];
    expected.sort();
    assert_eq!(config.networks[0].admins, expected);
}

#[test]
fn namecoin_anchored_roster_apply_refuses_without_chain_record() {
    let admin = Keys::generate();
    let admin_hex = admin.public_key().to_hex();
    let (mut config, _own) = seed_namecoin_network("d/acmevpn", std::slice::from_ref(&admin_hex));

    let result = config.apply_admin_signed_shared_roster_with_chain(
        "d/acmevpn",
        "Acme",
        vec![admin_hex.clone()],
        vec![admin_hex.clone()],
        HashMap::new(),
        1_726_000_000,
        &admin_hex,
        None,
    );
    let err = result.expect_err("must refuse anchored apply when chain is missing");
    assert!(
        format!("{err}").contains("chain-anchored"),
        "error mentions chain anchor: {err}"
    );
}

#[test]
fn quarantine_helpers_are_idempotent() {
    let admin = Keys::generate().public_key().to_hex();
    let (mut config, _own) = seed_namecoin_network("d/acmevpn", &[admin]);

    assert!(config.quarantine_network("d/acmevpn", "first reason"));
    assert_eq!(config.networks[0].chain_quarantine_reason, "first reason");
    assert!(config.quarantine_network("d/acmevpn", "second reason"));
    assert_eq!(config.networks[0].chain_quarantine_reason, "second reason");
    assert!(config.clear_network_chain_quarantine("d/acmevpn"));
    assert!(config.networks[0].chain_quarantine_reason.is_empty());
    assert!(!config.clear_network_chain_quarantine("d/acmevpn"));
    assert!(!config.quarantine_network("does-not-exist", "x"));
}

#[test]
fn parse_namecoin_network_id_smoke_through_public_api() {
    assert!(parse_namecoin_network_id("d/acmevpn").is_some());
    assert!(parse_namecoin_network_id("ACME.bit").is_some());
    assert!(parse_namecoin_network_id("not-an-anchor").is_none());
}
