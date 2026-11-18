#![cfg(feature = "paid-exit")]
use nostr_sdk::prelude::*;
use nostr_vpn_core::paid_provider_names::*;

fn list(author: &Keys, kind: Kind, users: &[&Keys], at: u64) -> Event {
    EventBuilder::new(kind, "")
        .tags(users.iter().map(|u| Tag::public_key(u.public_key())))
        .custom_created_at(Timestamp::from(at))
        .sign_with_keys(author)
        .unwrap()
}
fn profile(author: &Keys, content: &str, at: u64) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .custom_created_at(Timestamp::from(at))
        .sign_with_keys(author)
        .unwrap()
}
#[test]
fn seller_identity_uses_stable_alias_until_trusted_and_reverts_when_overmuted() {
    let root = Keys::generate();
    let friend = Keys::generate();
    let seller = Keys::generate();
    let npub = seller.public_key().to_bech32().unwrap();
    let hex = seller.public_key().to_hex();
    let alias = provider_alias(&npub);
    assert_eq!(alias, provider_alias(&hex));
    assert_eq!(alias.split_whitespace().count(), 2);
    let mut events = vec![profile(
        &seller,
        r#"{"display_name":"River","name":"old"}"#,
        100,
    )];
    let resolve = |events: &[Event]| {
        provider_display_name(
            &npub,
            &provider_name_graph(&root.public_key().to_hex(), events, 200),
            events,
            200,
        )
    };
    assert_eq!(resolve(&events), alias);
    events.push(list(&root, Kind::ContactList, &[&friend], 100));
    events.push(list(&friend, Kind::ContactList, &[&seller], 100));
    assert_eq!(resolve(&events), "River");
    events.push(profile(&seller, r#"{"name":"Future impostor"}"#, 10_000));
    assert_eq!(resolve(&events), "River");
    events.push(list(&root, Kind::MuteList, &[&seller], 150));
    assert_eq!(resolve(&events), alias);
    events.push(list(&root, Kind::MuteList, &[], 160));
    assert_eq!(resolve(&events), "River");
    events.push(list(&root, Kind::ContactList, &[], 170));
    assert_eq!(resolve(&events), alias);
}

#[test]
fn newer_empty_profile_removes_old_name_and_unverified_profiles_never_name_a_provider() {
    let root = Keys::generate();
    let seller = Keys::generate();
    let npub = seller.public_key().to_bech32().unwrap();
    let mut events = vec![
        list(&root, Kind::ContactList, &[&seller], 100),
        profile(&seller, r#"{"name":"River"}"#, 100),
        profile(&seller, "{}", 101),
    ];
    let mut forged = profile(&seller, r#"{"name":"Forged"}"#, 102);
    forged.pubkey = root.public_key();
    events.push(forged);
    let graph = provider_name_graph(&root.public_key().to_hex(), &events, 200);
    assert_eq!(
        provider_display_name(&npub, &graph, &events, 200),
        provider_alias(&npub)
    );
}

#[cfg(feature = "peer-credit")]
#[test]
fn exit_credit_discovery_requires_an_authentic_path_and_signed_local_terms() {
    use peer_payments::{Agreement, PurchaseIntent, Signed, WireMessage, sign_message};
    let root = Keys::generate();
    let friend = Keys::generate();
    let seller = Keys::generate();
    let terms = Agreement {
        id: "exit-quote".into(),
        payer: root.public_key().to_hex(),
        provider: seller.public_key().to_hex(),
        service: "vpn.exit.upload_bytes".into(),
        resource: "internet-exit-upload:10.0.0.2".into(),
        max_units: 1000,
        price_sat: 1,
        price_per_units: 100,
        max_amount_sat: 10,
        created_at: 100,
        expires_at: 300,
    };
    let offers = [Signed {
        signature: sign_message(
            &seller.secret_key().to_secret_hex().parse().unwrap(),
            &WireMessage::Agreement(terms.clone()),
        )
        .unwrap(),
        payload: terms.clone(),
    }];
    let intents = [PurchaseIntent {
        provider: &terms.provider,
        service: &terms.service,
        resource: &terms.resource,
        units: 1000,
        max_price_sat: 1,
        price_per_units: 100,
        max_amount_sat: 10,
        max_duration_secs: 200,
    }];
    let mut forged = list(&friend, Kind::ContactList, &[&seller], 120);
    forged.pubkey = root.public_key();
    let mut events = vec![forged, list(&friend, Kind::ContactList, &[&seller], 110)];
    let select = |events: &[Event]| {
        select_exit_credit_offer(&root.public_key(), events, &offers, &intents, 200).unwrap()
    };
    assert!(select(&events).is_none());
    events.push(list(&root, Kind::ContactList, &[&friend], 100));
    assert_eq!(select(&events), Some(&offers[0]));
    events.push(list(&root, Kind::MuteList, &[&friend], 121));
    assert!(select(&events).is_none());
}
