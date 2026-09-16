#![cfg(feature = "paid-exit")]

use nostr_sdk::prelude::*;
use nostr_social_graph::SocialGraph;
use nostr_social_memory::{Rating, RatingEventExt, rating_from_event};
use nostr_vpn_core::paid_route_ratings::*;
use nostr_vpn_core::paid_route_store::PaidRouteStore;

#[test]
fn signed_local_opinion_survives_reload_and_cannot_be_overwritten_by_a_probe() {
    let buyer = Keys::generate();
    let seller = Keys::generate().public_key().to_bech32().unwrap();
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    store
        .record_exit_rating(&buyer, &seller, -100, true, now)
        .unwrap();
    assert!(store.exit_provider_is_avoided(&seller));
    assert!(
        !store
            .record_exit_rating(&buyer, &seller, 90, false, now + 60)
            .unwrap()
    );
    let mut reloaded: PaidRouteStore =
        serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
    assert!(reloaded.exit_provider_is_avoided(&seller));
    reloaded
        .record_exit_rating(&buyer, &seller, 0, true, now + 120)
        .unwrap();
    assert!(!reloaded.exit_provider_is_avoided(&seller));
    let rating = rating_from_event(&reloaded.exit_ratings[&seller].event).unwrap();
    assert_eq!(rating.rating, 0);
    assert_eq!(rating.scope.as_deref(), Some(EXIT_RATING_SCOPE));
    assert!(rating.evidence.is_empty());
    assert!(rating.window_start.is_none());
}

#[test]
fn publication_is_bounded_and_retains_pending_events_until_queued() {
    let buyer = Keys::generate();
    let seller = Keys::generate().public_key().to_bech32().unwrap();
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    assert!(
        store
            .record_exit_rating(&buyer, &seller, 80, false, now)
            .unwrap()
    );
    let first = store.pending_exit_ratings();
    assert_eq!(first.len(), 1);
    assert!(
        !store
            .record_exit_rating(&buyer, &seller, 81, false, now + 1)
            .unwrap()
    );
    assert_eq!(store.pending_exit_ratings(), first);
    store.mark_exit_rating_queued(&first[0].id.to_hex());
    assert!(store.pending_exit_ratings().is_empty());
    assert!(
        !store
            .record_exit_rating(&buyer, &seller, 80, false, now + 60)
            .unwrap()
    );
    assert!(
        store
            .record_exit_rating(&buyer, &seller, -80, false, now + EXIT_RATING_MIN_INTERVAL)
            .unwrap()
    );
    assert_eq!(store.pending_exit_ratings().len(), 1);
    assert!(
        !store.exit_provider_is_avoided(&seller),
        "only an explicit downvote excludes"
    );
}

#[test]
fn unknown_authors_and_forged_raters_do_not_influence_exit_reputation() {
    let viewer = Keys::generate();
    let trusted = Keys::generate();
    let attacker = Keys::generate();
    let seller = Keys::generate().public_key();
    let now = Timestamp::now().as_secs();
    let mut graph = SocialGraph::new(&viewer.public_key().to_hex());
    trust_exit_rating_authors(&mut graph, &[trusted.public_key().to_hex()]).unwrap();
    let good = exit_rating_event(&trusted, &seller.to_bech32().unwrap(), 80, false, now).unwrap();
    let spam = exit_rating_event(&attacker, &seller.to_bech32().unwrap(), -100, true, now).unwrap();
    let mut forged = Rating::new(
        trusted.public_key().to_hex(),
        seller.to_hex(),
        -100,
        -100,
        100,
    );
    forged.scope = Some(EXIT_RATING_SCOPE.into());
    forged.created_at = now;
    let forged = forged.to_event(&attacker).unwrap();
    let scores = exit_rating_scores([&good, &spam, &forged], &graph, now);
    assert_eq!(scores[&seller.to_bech32().unwrap()].score, 80);
    assert_eq!(scores[&seller.to_bech32().unwrap()].authors, 1);
}

fn add_session(store: &mut PaidRouteStore, buyer: &Keys, seller: &Keys, now: u64) -> String {
    use nostr_vpn_core::paid_route_store::OpenPaidRouteBuyerSessionRequest;
    use nostr_vpn_core::paid_routes::*;
    let mut config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    config.channel.accepted_mints = vec!["https://mint.example".into()];
    let offer_id = seller.public_key().to_hex();
    let signed = signed_paid_exit_offer_from_config(&offer_id, seller, &config, None, now).unwrap();
    store.upsert_signed_offer(signed, vec![], now).unwrap();
    store.upsert_wallet_mint("https://mint.example", "Test", Some(100_000), now);
    store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: offer_id,
            buyer_npub: buyer.public_key().to_bech32().unwrap(),
            mint_url: Some("https://mint.example".into()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: now,
        })
        .unwrap()
        .session_id
}

#[test]
fn retrospective_feedback_requires_a_recent_healthy_alternative_without_a_reconnect() {
    let buyer = Keys::generate();
    let bad = Keys::generate();
    let good = Keys::generate();
    let now = Timestamp::now().as_secs();
    for (reset, delay, should_rate) in [(false, 20, true), (true, 20, false), (false, 61, false)] {
        let mut store = PaidRouteStore::default();
        let a = add_session(&mut store, &buyer, &bad, now);
        let b = add_session(&mut store, &buyer, &good, now);
        let mut feedback = ExitProbeFeedback::default();
        let generation = feedback.generation();
        feedback
            .observe(&mut store, &buyer, &a, -100, now, generation)
            .unwrap();
        assert!(
            store.pending_exit_ratings().is_empty(),
            "ambiguous failure stays local"
        );
        if reset {
            feedback.reset();
        }
        feedback
            .observe(
                &mut store,
                &buyer,
                &b,
                90,
                now + delay,
                feedback.generation(),
            )
            .unwrap();
        let bad_npub = bad.public_key().to_bech32().unwrap();
        assert_eq!(store.exit_ratings.contains_key(&bad_npub), should_rate);
        if should_rate {
            assert_eq!(
                rating_from_event(&store.exit_ratings[&bad_npub].event)
                    .unwrap()
                    .rating,
                -100
            );
            assert!(
                !store.exit_provider_is_avoided(&bad_npub),
                "automatic feedback is not a manual exclusion"
            );
        }
        // A probe finishing after a network change cannot reintroduce old evidence.
        feedback.reset();
        feedback
            .observe(&mut store, &buyer, &a, -100, now + 25, generation)
            .unwrap();
        assert!(feedback.generation() > generation);
    }
}

#[test]
fn common_outage_never_blames_a_provider_and_manual_opinion_wins() {
    let buyer = Keys::generate();
    let sellers = [Keys::generate(), Keys::generate(), Keys::generate()];
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    let sessions: Vec<_> = sellers
        .iter()
        .map(|s| add_session(&mut store, &buyer, s, now))
        .collect();
    let mut feedback = ExitProbeFeedback::default();
    for session in &sessions {
        feedback
            .observe(&mut store, &buyer, session, -100, now, 0)
            .unwrap();
    }
    assert!(store.pending_exit_ratings().is_empty());
    let seller = sellers[0].public_key().to_bech32().unwrap();
    store
        .record_exit_rating(&buyer, &seller, 100, true, now)
        .unwrap();
    feedback
        .observe(&mut store, &buyer, &sessions[2], 90, now + 20, 0)
        .unwrap();
    assert_eq!(store.personal_exit_rating(&seller), 1);
    assert_eq!(
        rating_from_event(&store.exit_ratings[&seller].event)
            .unwrap()
            .rating,
        100
    );
}

#[test]
fn downvote_blocks_existing_and_new_sessions_without_losing_accounting() {
    let buyer = Keys::generate();
    let seller = Keys::generate();
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    let session = add_session(&mut store, &buyer, &seller, now);
    let npub = seller.public_key().to_bech32().unwrap();
    let channels = store.channels.clone();
    assert!(
        !store.can_rate_exit(&npub),
        "opening a channel is not a successful connection"
    );
    store
        .update_session_probe(
            nostr_vpn_core::paid_route_store::UpdatePaidRouteSessionProbeRequest {
                session_id: session.clone(),
                realized_exit_ip: Some("203.0.113.7".into()),
                observed_country_code: None,
                observed_asn: None,
                quality: Some(nostr_vpn_core::paid_routes::PaidRouteQualityMetrics {
                    latency_ms: Some(30),
                    packet_loss_ppm: Some(0),
                    last_seen_unix: Some(now),
                    ..Default::default()
                }),
                now_unix: now,
            },
        )
        .unwrap();
    assert!(store.can_rate_exit(&npub));
    // Losing present readiness does not erase the user's past experience.
    store
        .update_session_probe(
            nostr_vpn_core::paid_route_store::UpdatePaidRouteSessionProbeRequest {
                session_id: session.clone(),
                realized_exit_ip: None,
                observed_country_code: None,
                observed_asn: None,
                quality: Some(nostr_vpn_core::paid_routes::PaidRouteQualityMetrics {
                    packet_loss_ppm: Some(1_000_000),
                    last_seen_unix: Some(now + 1),
                    ..Default::default()
                }),
                now_unix: now + 1,
            },
        )
        .unwrap();
    let mut store: PaidRouteStore =
        serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
    assert!(
        store.can_rate_exit(&npub),
        "previously used providers remain rateable after reload"
    );
    assert!(!store.can_rate_exit(&Keys::generate().public_key().to_hex()));
    store
        .record_exit_rating(&buyer, &npub, -100, true, now)
        .unwrap();
    assert!(!store.buyer_session_allows_routing(&session, now).unwrap());
    let request = nostr_vpn_core::paid_route_store::OpenPaidRouteBuyerSessionRequest {
        offer_selector: seller.public_key().to_hex(),
        buyer_npub: buyer.public_key().to_bech32().unwrap(),
        mint_url: Some("https://mint.example".into()),
        channel_capacity_sat: Some(10),
        initial_paid_msat: 0,
        now_unix: now + 1,
    };
    assert!(store.open_buyer_session(request).is_err());
    assert_eq!(store.channels, channels);
    store
        .record_exit_rating(&buyer, &npub, 0, true, now + 2)
        .unwrap();
    assert!(!store.exit_provider_is_avoided(&npub));
    assert_eq!(store.channels, channels);
}

#[test]
fn a_thousand_sybils_cannot_amplify_a_compromised_followed_author() {
    let viewer = Keys::generate();
    let honest = Keys::generate();
    let compromised = Keys::generate();
    let seller = Keys::generate();
    let subject = seller.public_key().to_bech32().unwrap();
    let now = Timestamp::now().as_secs();
    let mut graph = SocialGraph::new(&viewer.public_key().to_hex());
    trust_exit_rating_authors(
        &mut graph,
        &[
            honest.public_key().to_hex(),
            compromised.public_key().to_hex(),
        ],
    )
    .unwrap();
    let mut events = vec![exit_rating_event(&honest, &subject, 100, true, now).unwrap()];
    for n in 0..1000 {
        let sybil = Keys::generate();
        graph
            .add_positive_relation(
                &compromised.public_key().to_hex(),
                &sybil.public_key().to_hex(),
                now,
            )
            .unwrap();
        events.push(exit_rating_event(&sybil, &subject, -100, true, now).unwrap());
        events.push(exit_rating_event(&compromised, &subject, -100, true, now - n % 60).unwrap());
    }
    graph.recalculate_follow_distances();
    let scores = exit_rating_scores(&events, &graph, now);
    assert_eq!(scores[&subject].authors, 2);
    assert_eq!(
        scores[&subject].score, 0,
        "a directly trusted malicious author has one vote, not a thousand"
    );
    events.reverse();
    assert_eq!(
        exit_rating_scores(&events, &graph, now),
        scores,
        "arrival order cannot amplify influence"
    );
    // Public ratings never create graph edges or authority of their own.
    assert_eq!(
        graph.get_follow_distance(&seller.public_key().to_hex()),
        1000
    );
}

#[test]
fn signed_follow_and_mute_updates_revoke_cached_scores_and_replays_do_not_restore_them() {
    let viewer = Keys::generate();
    let trusted = Keys::generate();
    let seller = Keys::generate();
    let now = Timestamp::now().as_secs();
    let follows = EventBuilder::new(Kind::ContactList, "")
        .tags([Tag::public_key(trusted.public_key())])
        .custom_created_at(Timestamp::from(now - 10))
        .sign_with_keys(&viewer)
        .unwrap();
    let review =
        exit_rating_event(&trusted, &seller.public_key().to_hex(), -100, true, now).unwrap();
    let mut events = vec![follows.clone(), review];
    let mut store = PaidRouteStore::default();
    add_session(&mut store, &viewer, &seller, now);
    let graph = exit_rating_graph(&viewer.public_key().to_hex(), &events, &[], now).unwrap();
    store.refresh_exit_reputation(&events, &graph, now);
    assert_eq!(
        store.offers.values().next().unwrap().rating_score,
        Some(-100)
    );
    let unfollow = EventBuilder::new(Kind::ContactList, "")
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(&viewer)
        .unwrap();
    events.extend([unfollow, follows]);
    let graph = exit_rating_graph(&viewer.public_key().to_hex(), &events, &[], now).unwrap();
    store.refresh_exit_reputation(&events, &graph, now);
    assert_eq!(store.offers.values().next().unwrap().rating_score, None);
    let mute = EventBuilder::new(Kind::MuteList, "")
        .tags([Tag::public_key(trusted.public_key())])
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(&viewer)
        .unwrap();
    events.push(mute);
    let graph = exit_rating_graph(
        &viewer.public_key().to_hex(),
        &events,
        &[trusted.public_key().to_hex()],
        now,
    )
    .unwrap();
    assert!(exit_rating_scores(&events, &graph, now).is_empty());
}

#[test]
fn replay_future_events_wrong_scope_and_self_promotion_are_ignored() {
    let viewer = Keys::generate();
    let author = Keys::generate();
    let seller = Keys::generate();
    let subject = seller.public_key().to_bech32().unwrap();
    let now = Timestamp::now().as_secs();
    let mut graph = SocialGraph::new(&viewer.public_key().to_hex());
    trust_exit_rating_authors(
        &mut graph,
        &[author.public_key().to_hex(), seller.public_key().to_hex()],
    )
    .unwrap();
    let older = exit_rating_event(&author, &subject, -100, true, now - 10).unwrap();
    let newer = exit_rating_event(&author, &subject, 80, false, now).unwrap();
    let future = exit_rating_event(&author, &subject, -100, true, now + 301).unwrap();
    let stale =
        exit_rating_event(&author, &subject, -100, true, now - EXIT_RATING_MAX_AGE - 1).unwrap();
    let own = exit_rating_event(&seller, &subject, 100, true, now).unwrap();
    let mut wrong = Rating::new(
        author.public_key().to_hex(),
        seller.public_key().to_hex(),
        -100,
        -100,
        100,
    );
    wrong.scope = Some("fips.peer".into());
    wrong.created_at = now;
    let wrong = wrong.to_event(&author).unwrap();
    let scores = exit_rating_scores(
        [&newer, &older, &future, &stale, &own, &wrong, &newer],
        &graph,
        now,
    );
    assert_eq!(scores[&subject].score, 80);
    assert_eq!(scores[&subject].authors, 1);
    let clear = exit_rating_event(&author, &subject, 0, true, now + 1).unwrap();
    assert!(exit_rating_scores([&newer, &clear, &older], &graph, now + 1).is_empty());
}

#[test]
fn network_class_roundtrips_as_a_signed_claim_and_old_offers_still_verify() {
    use nostr_vpn_core::paid_routes::*;
    let keys = Keys::generate();
    let now = Timestamp::now().as_secs();
    for class in [
        ExitNetworkClass::Residential,
        ExitNetworkClass::Datacenter,
        ExitNetworkClass::Mobile,
        ExitNetworkClass::Business,
        ExitNetworkClass::Unknown,
    ] {
        let mut config = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        config.pricing.price_msat_per_gb = 0;
        config.location.network_class = class;
        let signed = signed_paid_exit_offer_from_config("test", &keys, &config, None, now).unwrap();
        let imported = SignedPaidRouteOffer::from_event(signed.event.clone()).unwrap();
        assert_eq!(imported.offer().unwrap().location.network_class, class);
        let tag = signed
            .event
            .tags
            .iter()
            .find(|tag| tag.as_slice()[0] == "network_class");
        if class.is_unknown() {
            assert!(tag.is_none());
            assert!(
                !signed.event.content.contains("network_class"),
                "old offers need no new field"
            );
        } else {
            assert_eq!(tag.unwrap().as_slice()[1], class.as_str());
        }
    }
}

#[test]
fn reputation_cannot_override_price_limits_and_downvotes_override_high_scores() {
    use nostr_vpn_core::paid_routes::*;
    let viewer = Keys::generate();
    let trusted = Keys::generate();
    let cheap = Keys::generate();
    let expensive = Keys::generate();
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Test", Some(100_000), now);
    let mut config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    config.channel.accepted_mints = vec!["https://mint.example".into()];
    config.channel.free_probe_units = 1024 * 1024;
    for (seller, price) in [(&cheap, 25_000), (&expensive, 100_001)] {
        config.pricing.price_msat_per_gb = price;
        let signed =
            signed_paid_exit_offer_from_config("test", seller, &config, None, now).unwrap();
        store.upsert_signed_offer(signed, vec![], now).unwrap();
    }
    let mut graph = SocialGraph::new(&viewer.public_key().to_hex());
    trust_exit_rating_authors(&mut graph, &[trusted.public_key().to_hex()]).unwrap();
    let events = vec![
        exit_rating_event(&trusted, &expensive.public_key().to_hex(), 100, true, now).unwrap(),
    ];
    store.refresh_exit_reputation(&events, &graph, now);
    let chosen = store.select_automatic_offer(now).unwrap();
    assert_eq!(
        store.offers[&chosen.offer_key].offer.seller_npub,
        cheap.public_key().to_bech32().unwrap()
    );
    store
        .record_exit_rating(&viewer, &cheap.public_key().to_hex(), -100, true, now)
        .unwrap();
    assert!(
        store.select_automatic_offer(now).is_err(),
        "no eligible provider must remain blocked"
    );
}

#[test]
fn explicit_upvote_prefers_a_used_provider_but_cannot_rescue_a_failed_probe() {
    use nostr_vpn_core::paid_route_store::UpdatePaidRouteSessionProbeRequest;
    use nostr_vpn_core::paid_routes::PaidRouteQualityMetrics;
    let buyer = Keys::generate();
    let fast = Keys::generate();
    let preferred = Keys::generate();
    let now = Timestamp::now().as_secs();
    let mut store = PaidRouteStore::default();
    let fast_session = add_session(&mut store, &buyer, &fast, now);
    let preferred_session = add_session(&mut store, &buyer, &preferred, now);
    for (session, latency) in [(&fast_session, 20), (&preferred_session, 40)] {
        store
            .update_session_probe(UpdatePaidRouteSessionProbeRequest {
                session_id: session.clone(),
                realized_exit_ip: Some("203.0.113.9".into()),
                observed_country_code: None,
                observed_asn: None,
                quality: Some(PaidRouteQualityMetrics {
                    latency_ms: Some(latency),
                    packet_loss_ppm: Some(0),
                    last_seen_unix: Some(now),
                    ..Default::default()
                }),
                now_unix: now,
            })
            .unwrap();
    }
    let seller_for_choice = |store: &PaidRouteStore| {
        store.offers[&store.select_automatic_offer(now).unwrap().offer_key]
            .offer
            .seller_npub
            .clone()
    };
    assert_eq!(
        seller_for_choice(&store),
        fast.public_key().to_bech32().unwrap()
    );
    store
        .record_exit_rating(&buyer, &preferred.public_key().to_hex(), 100, true, now)
        .unwrap();
    assert_eq!(
        seller_for_choice(&store),
        preferred.public_key().to_bech32().unwrap()
    );
    store
        .update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: preferred_session,
            realized_exit_ip: None,
            observed_country_code: None,
            observed_asn: None,
            quality: Some(PaidRouteQualityMetrics {
                packet_loss_ppm: Some(1_000_000),
                last_seen_unix: Some(now),
                ..Default::default()
            }),
            now_unix: now,
        })
        .unwrap();
    assert_eq!(
        seller_for_choice(&store),
        fast.public_key().to_bech32().unwrap()
    );
}
