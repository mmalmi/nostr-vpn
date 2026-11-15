#![cfg(feature = "paid-exit")]

use nostr_sdk::prelude::*;
use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
use nostr_vpn_core::paid_routes::{
    ManualPaidExitProvider, PaidExitConfig, signed_paid_exit_offer_from_config,
};

#[test]
fn provider_link_to_purchase_uses_an_affordable_channel_not_the_seller_maximum() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = PaidExitConfig {
        enabled: true,
        ..Default::default()
    };
    config.pricing.price_msat_per_gb = 100_000;
    config.channel.max_channel_capacity_sat = 1_000;
    config.channel.accepted_mints = vec!["https://mint.example".into()];
    let link = ManualPaidExitProvider::seller_link(&seller.public_key().to_hex(), &config).unwrap();
    let provider =
        ManualPaidExitProvider::parse(&link.replace("paid-exit/npub", "paid-exit/@npub")).unwrap();
    let now = Timestamp::now().as_secs();
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, now).unwrap();
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint(&provider.mint, "", Some(56_000), now);
    store.upsert_signed_offer(signed, vec![], now).unwrap();
    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: provider.npub,
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            mint_url: Some(provider.mint),
            channel_capacity_sat: None,
            initial_paid_msat: 0,
            now_unix: now,
        })
        .unwrap();
    assert_eq!(result.channel_capacity_sat, 11);
    assert_eq!(store.channels[&result.channel_id].payment.capacity_sat, 11);
}

#[test]
fn multi_mint_provider_link_uses_the_buyers_approved_default() {
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut config = PaidExitConfig {
        enabled: true,
        ..Default::default()
    };
    config.pricing.price_msat_per_gb = 100_000;
    config.channel.accepted_mints = vec![
        "https://a-mint.example".into(),
        "https://z-mint.example".into(),
    ];
    config.normalize();
    let link = ManualPaidExitProvider::seller_link(&seller.public_key().to_hex(), &config).unwrap();
    let provider = ManualPaidExitProvider::parse(&link).unwrap();
    assert!(provider.mint.is_empty());
    assert_eq!(provider.max_price_msat_per_gb, Some(100_000));
    let now = Timestamp::now().as_secs();
    let signed =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, now).unwrap();
    provider.accepts(&signed.offer().unwrap()).unwrap();

    // The last alphabetically accepted mint works both as the only trusted
    // mint and as the buyer's explicit default among several trusted mints.
    for trust_first_mint in [false, true] {
        let mut store = PaidRouteStore::default();
        if trust_first_mint {
            store.upsert_wallet_mint("https://a-mint.example", "", Some(56_000), now);
        }
        store.upsert_wallet_mint("https://z-mint.example", "", Some(56_000), now);
        store.set_default_mint("https://z-mint.example");
        store
            .upsert_signed_offer(signed.clone(), vec![], now)
            .unwrap();
        let result = store
            .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                offer_selector: provider.npub.clone(),
                buyer_npub: buyer.public_key().to_bech32().unwrap(),
                mint_url: (!provider.mint.is_empty()).then(|| provider.mint.clone()),
                channel_capacity_sat: None,
                initial_paid_msat: 0,
                now_unix: now,
            })
            .unwrap();
        assert_eq!(result.mint_url, "https://z-mint.example");
    }

    // A generic seller link does not grant wallet trust to any listed mint:
    // paying is refused, and only the advertised free allowance opens.
    let mut store = PaidRouteStore::default();
    store.upsert_signed_offer(signed, vec![], now).unwrap();
    let request = |initial_paid_msat| OpenPaidRouteBuyerSessionRequest {
        offer_selector: provider.npub.clone(),
        buyer_npub: buyer.public_key().to_bech32().unwrap(),
        mint_url: None,
        channel_capacity_sat: None,
        initial_paid_msat,
        now_unix: now,
    };
    let error = store.open_buyer_session(request(1)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires an approved wallet mint")
    );
    assert!(store.wallet.mints.is_empty());
    assert!(store.sessions.is_empty());
    let trial = store.open_buyer_session(request(0)).unwrap();
    assert!(trial.mint_url.is_empty());
    assert!(store.wallet.mints.is_empty());
    assert_eq!(store.channels[&trial.channel_id].payment.paid_msat, 0);

    config.channel.free_probe_units = 0;
    let paid_only =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &config, None, now).unwrap();
    let mut store = PaidRouteStore::default();
    store.upsert_signed_offer(paid_only, vec![], now).unwrap();
    for amount in [0, 1] {
        let error = store.open_buyer_session(request(amount)).unwrap_err();
        assert!(error.to_string().contains("no accepted mint approved"));
        assert!(store.wallet.mints.is_empty());
        assert!(store.sessions.is_empty());
    }
}

#[test]
fn expired_offers_do_not_make_a_live_provider_ambiguous() {
    use nostr_vpn_core::paid_route_store::paid_route_offer_store_key;

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().unwrap();
    let mut config = PaidExitConfig {
        enabled: true,
        ..Default::default()
    };
    config.channel.accepted_mints = vec!["https://mint.example".into()];
    config.pricing.price_msat_per_gb = 100_000;
    let now = 10_000;
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "", Some(56_000), now);
    for (id, created_at) in [
        ("old-offer", 100),
        ("live-offer", now - 60),
        ("future-offer", now + 3_600),
    ] {
        let signed =
            signed_paid_exit_offer_from_config(id, &seller, &config, None, created_at).unwrap();
        store.upsert_signed_offer(signed, vec![], now).unwrap();
    }
    assert_eq!(
        store
            .live_offer_for_selector(&seller_npub, now)
            .unwrap()
            .offer_id,
        "live-offer"
    );
    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: seller_npub.clone(),
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            mint_url: None,
            channel_capacity_sat: None,
            initial_paid_msat: 0,
            now_unix: now,
        })
        .unwrap();
    assert_eq!(store.channels[&result.channel_id].offer_id, "live-offer");
    assert_eq!(store.offers.len(), 3, "selection preserves offer history");
    for id in ["old-offer", "future-offer"] {
        let key = paid_route_offer_store_key(&seller_npub, id);
        assert!(store.live_offer_for_selector(&key, now).is_err());
    }

    let signed =
        signed_paid_exit_offer_from_config("second-live-offer", &seller, &config, None, now)
            .unwrap();
    store.upsert_signed_offer(signed, vec![], now).unwrap();
    assert!(
        store
            .live_offer_for_selector(&seller_npub, now)
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    let exact = paid_route_offer_store_key(&seller_npub, "second-live-offer");
    assert_eq!(
        store.live_offer_for_selector(&exact, now).unwrap().offer_id,
        "second-live-offer"
    );
}
