
#[cfg(all(test, feature = "paid-exit"))]
mod paid_exit_rating_tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, Kind, Tag, Timestamp};

    #[test]
    fn local_paid_exit_offer_includes_the_public_fips_endpoint() {
        let temp = std::env::temp_dir().join(format!(
            "nvpn-paid-offer-endpoint-{}-{}",
            std::process::id(),
            unix_timestamp()
        ));
        std::fs::create_dir_all(&temp).expect("create tempdir");
        let config_path = temp.join("config.toml");
        let mut app = AppConfig::generated();
        app.paid_exit.enabled = true;
        app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
        app.fips_advertise_public_endpoint = true;
        app.node.endpoint = "1.1.1.1:2122".to_string();

        let local = build_local_paid_exit_offer(&app, &config_path, "internet", 100)
            .expect("build local paid exit offer");

        assert_eq!(local.offer.fips_endpoints, vec!["1.1.1.1:2122"]);
        std::fs::remove_dir_all(temp).expect("remove tempdir");
    }

    #[test]
    fn seller_outputs_include_canonical_provider_link() {
        let keys = Keys::generate();
        let mut config = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        config.pricing.price_msat_per_gb = 25_000;
        config.channel.accepted_mints = vec!["https://mint.example".to_string()];
        config.normalize();
        let signed = signed_paid_exit_offer_from_config_with_receiver(
            "internet", &keys, &config, None, None, 100,
        )
        .expect("signed offer");
        let offer = signed.offer().expect("offer");
        let provider_link = paid_exit_provider_link_for_offer(&offer).expect("provider link");
        let result = PaidExitRunResult {
            config_path: PathBuf::from("config.toml"),
            store_path: PathBuf::from("paid-routes.json"),
            offer,
            provider_link: provider_link.clone(),
            event_id: signed.event.id.to_string(),
            stored: true,
            publish: None,
            daemon_reload_attempted: false,
            status: json!({}),
        };

        assert_eq!(
            paid_exit_run_result_json(&result)["provider_link"],
            provider_link
        );
        let parsed = ManualPaidExitProvider::parse(&provider_link).expect("parse provider link");
        assert_eq!(parsed.npub, result.offer.seller_npub);
        assert_eq!(parsed.max_price_msat_per_gb, Some(25_000));
        assert_eq!(parsed.mint, "https://mint.example");
    }

    #[test]
    fn rating_scores_use_scope_and_newest_record() {
        let ratings = json!({
            "ratings": [
                {
                    "id": "old",
                    "rater": "npub1local",
                    "subject": "npub1peer",
                    "scope": "fips.peer",
                    "rating": 90,
                    "min_rating": 0,
                    "max_rating": 100,
                    "created_at": 10
                },
                {
                    "id": "other-scope",
                    "rater": "npub1local",
                    "subject": "npub1ignored",
                    "scope": "other",
                    "rating": 100,
                    "min_rating": 0,
                    "max_rating": 100,
                    "created_at": 20
                },
                {
                    "id": "new",
                    "rater": "npub1local",
                    "subject": "npub1peer",
                    "scope": "fips.peer",
                    "rating": 20,
                    "min_rating": 0,
                    "max_rating": 100,
                    "created_at": 30
                }
            ]
        });

        let scores =
            paid_exit_rating_scores_from_value(&ratings, "fips.peer", &HashSet::new()).unwrap();

        assert_eq!(
            scores.get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: -60,
                created_at: 30,
            })
        );
        assert!(!scores.contains_key("npub1ignored"));
    }

    #[test]
    fn merge_rating_scores_keeps_newest_per_subject() {
        let mut scores = Some(HashMap::from([(
            "npub1peer".to_string(),
            PaidExitRatingScore {
                score: 10,
                created_at: 10,
            },
        )]));
        merge_paid_exit_rating_scores(
            &mut scores,
            HashMap::from([
                (
                    "npub1peer".to_string(),
                    PaidExitRatingScore {
                        score: 80,
                        created_at: 20,
                    },
                ),
                (
                    "npub1other".to_string(),
                    PaidExitRatingScore {
                        score: -20,
                        created_at: 15,
                    },
                ),
            ]),
        );

        let scores = scores.unwrap();
        assert_eq!(
            scores.get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: 80,
                created_at: 20,
            })
        );
        assert_eq!(
            scores.get("npub1other"),
            Some(&PaidExitRatingScore {
                score: -20,
                created_at: 15,
            })
        );
    }

    #[test]
    fn merge_rating_scores_keeps_newer_existing_score() {
        let mut scores = Some(HashMap::from([(
            "npub1peer".to_string(),
            PaidExitRatingScore {
                score: 10,
                created_at: 30,
            },
        )]));
        merge_paid_exit_rating_scores(
            &mut scores,
            HashMap::from([(
                "npub1peer".to_string(),
                PaidExitRatingScore {
                    score: 80,
                    created_at: 20,
                },
            )]),
        );

        assert_eq!(
            scores.unwrap().get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: 10,
                created_at: 30,
            })
        );
    }

    #[test]
    fn rating_scores_accept_signed_fact_events() {
        let event = sample_rating_fact_event("npub1crawler", "npub1peer", "fips.peer", 85, 20);
        let ratings = json!({"events": [event]});

        let scores =
            paid_exit_rating_scores_from_value(&ratings, "fips.peer", &HashSet::new()).unwrap();

        assert_eq!(
            scores.get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: 70,
                created_at: 20,
            })
        );
    }

    #[test]
    fn rating_fact_signer_can_differ_from_rater() {
        let crawler = Keys::generate();
        let rater = Keys::generate();
        let rater_npub = rater.public_key().to_bech32().unwrap();
        let event = sample_rating_fact_event_signed_by(
            &crawler,
            &rater_npub,
            "npub1peer",
            "fips.peer",
            75,
            21,
        );
        let signed_event: Event = serde_json::from_value(event.clone()).unwrap();
        assert_ne!(signed_event.pubkey, rater.public_key());
        let ratings = json!({"events": [event]});

        let scores =
            paid_exit_rating_scores_from_value(&ratings, "fips.peer", &HashSet::new()).unwrap();

        assert_eq!(
            scores.get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: 50,
                created_at: 21,
            })
        );
    }

    #[test]
    fn trusted_rating_authors_filter_signed_fact_event_publishers() {
        let trusted_crawler = Keys::generate();
        let untrusted_crawler = Keys::generate();
        let rater = Keys::generate();
        let rater_npub = rater.public_key().to_bech32().unwrap();
        let trusted = sample_rating_fact_event_signed_by(
            &trusted_crawler,
            &rater_npub,
            "npub1trustedpeer",
            "fips.peer",
            95,
            30,
        );
        let spam = sample_rating_fact_event_signed_by(
            &untrusted_crawler,
            &rater_npub,
            "npub1spampeer",
            "fips.peer",
            100,
            31,
        );
        let trusted_authors = paid_exit_trusted_rating_author_set(&[trusted_crawler
            .public_key()
            .to_bech32()
            .unwrap()])
        .unwrap();

        let scores = paid_exit_rating_scores_from_value(
            &json!({"events": [spam, trusted]}),
            "fips.peer",
            &trusted_authors,
        )
        .unwrap();

        assert_eq!(
            scores.get("npub1trustedpeer"),
            Some(&PaidExitRatingScore {
                score: 90,
                created_at: 30,
            })
        );
        assert!(!scores.contains_key("npub1spampeer"));
    }

    #[test]
    fn rating_event_import_skips_spoofed_trusted_pubkey_spam() {
        let trusted_crawler = Keys::generate();
        let untrusted_crawler = Keys::generate();
        let rater = Keys::generate();
        let rater_npub = rater.public_key().to_bech32().unwrap();
        let trusted_subject = Keys::generate().public_key().to_bech32().unwrap();
        let spam_subject = Keys::generate().public_key().to_bech32().unwrap();
        let trusted = sample_rating_fact_event_signed_by(
            &trusted_crawler,
            &rater_npub,
            &trusted_subject,
            "fips.peer",
            90,
            32,
        );
        let mut spoofed = sample_rating_fact_event_signed_by(
            &untrusted_crawler,
            &rater_npub,
            &spam_subject,
            "fips.peer",
            100,
            33,
        );
        spoofed["pubkey"] = json!(trusted_crawler.public_key().to_hex());
        let malformed = json!({
            "kind": RATING_FACT_KIND,
            "pubkey": trusted_crawler.public_key().to_hex(),
        });
        let trusted_authors =
            paid_exit_trusted_rating_author_set(&[trusted_crawler.public_key().to_hex()]).unwrap();

        let scores = paid_exit_rating_scores_from_value(
            &json!({"events": [spoofed, malformed, trusted]}),
            "fips.peer",
            &trusted_authors,
        )
        .unwrap();

        assert_eq!(
            scores.get(&trusted_subject),
            Some(&PaidExitRatingScore {
                score: 80,
                created_at: 32,
            })
        );
        assert!(!scores.contains_key(&spam_subject));
    }

    #[test]
    fn trusted_rating_authors_filter_record_raters() {
        let trusted = Keys::generate();
        let untrusted = Keys::generate();
        let trusted_npub = trusted.public_key().to_bech32().unwrap();
        let untrusted_npub = untrusted.public_key().to_bech32().unwrap();
        let ratings = json!({
            "ratings": [
                {
                    "id": "trusted",
                    "rater": trusted_npub,
                    "subject": "npub1trustedpeer",
                    "scope": "fips.peer",
                    "rating": 90,
                    "min_rating": 0,
                    "max_rating": 100,
                    "created_at": 30
                },
                {
                    "id": "untrusted",
                    "rater": untrusted_npub,
                    "subject": "npub1spampeer",
                    "scope": "fips.peer",
                    "rating": 100,
                    "min_rating": 0,
                    "max_rating": 100,
                    "created_at": 31
                }
            ]
        });
        let trusted_authors =
            paid_exit_trusted_rating_author_set(&[trusted.public_key().to_hex()]).unwrap();

        let scores =
            paid_exit_rating_scores_from_value(&ratings, "fips.peer", &trusted_authors).unwrap();

        assert_eq!(
            scores.get("npub1trustedpeer"),
            Some(&PaidExitRatingScore {
                score: 80,
                created_at: 30,
            })
        );
        assert!(!scores.contains_key("npub1spampeer"));
    }

    #[test]
    fn rating_scores_accept_hashtree_query_output_from_fips_fact_events() {
        let event = sample_rating_fact_event("npub1crawler", "npub1peer", "fips.peer", 15, 40);
        let ratings = json!({
            "root": "nhash1testfixture",
            "count": 1,
            "events": [event],
        });

        let scores =
            paid_exit_rating_scores_from_value(&ratings, "fips.peer", &HashSet::new()).unwrap();

        assert_eq!(
            scores.get("npub1peer"),
            Some(&PaidExitRatingScore {
                score: -70,
                created_at: 40,
            })
        );
    }

    #[test]
    fn ratings_sort_offers_good_unknown_bad() {
        let good = sample_signed_offer("good", 10);
        let unknown = sample_signed_offer("unknown", 30);
        let bad = sample_signed_offer("bad", 40);
        let good_npub = good.offer().unwrap().seller_npub;
        let bad_npub = bad.offer().unwrap().seller_npub;
        let mut scores = HashMap::new();
        scores.insert(
            good_npub.clone(),
            PaidExitRatingScore {
                score: 80,
                created_at: 1,
            },
        );
        scores.insert(
            bad_npub,
            PaidExitRatingScore {
                score: -80,
                created_at: 1,
            },
        );
        let mut offers = vec![bad, unknown, good];

        paid_exit_sort_offers_by_rating(&mut offers, &scores);

        assert_eq!(offers[0].offer().unwrap().seller_npub, good_npub);
        assert_eq!(
            paid_exit_signed_offer_rating_score(&offers[1], &scores).map(|score| score.score),
            None
        );
        assert_eq!(
            paid_exit_signed_offer_rating_score(&offers[2], &scores).map(|score| score.score),
            Some(-80)
        );
    }

    #[test]
    fn offer_results_json_includes_rating_score_when_loaded() {
        let signed = sample_signed_offer("rated", 10);
        let seller_npub = signed.offer().unwrap().seller_npub;
        let mut scores = HashMap::new();
        scores.insert(
            seller_npub,
            PaidExitRatingScore {
                score: 42,
                created_at: 1,
            },
        );

        let output = paid_exit_offer_results_json(&[signed], Some(&scores)).unwrap();

        assert_eq!(output[0]["rating_score"], 42);
    }

    #[test]
    fn discovered_offers_persist_rating_scores() {
        let store_path = temp_paid_exit_store_path("rating-score");
        let signed = sample_signed_offer("rated", 10);
        let seller_npub = signed.offer().unwrap().seller_npub;
        let mut scores = HashMap::new();
        scores.insert(
            seller_npub.clone(),
            PaidExitRatingScore {
                score: 42,
                created_at: 123,
            },
        );

        let changed = persist_paid_exit_discovered_offers(
            &store_path,
            &[signed],
            &["wss://relay.example".to_string()],
            Some(&scores),
        )
        .unwrap();

        assert_eq!(changed, 1);
        let store = load_paid_route_store(&store_path).unwrap();
        let record = store.offers.values().next().expect("stored offer");
        assert_eq!(record.offer.seller_npub, seller_npub);
        assert_eq!(record.rating_score, Some(42));
        assert_eq!(record.rating_updated_at_unix, 123);

        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn buy_best_rated_selector_uses_persisted_offer_scores() {
        let good = sample_signed_offer("good", 10);
        let newcomer = sample_signed_offer("newcomer", 20);
        let bad = sample_signed_offer("bad", 30);
        let good_offer = good.offer().unwrap();
        let newcomer_offer = newcomer.offer().unwrap();
        let bad_offer = bad.offer().unwrap();
        let good_key = nostr_vpn_core::paid_route_store::paid_route_offer_store_key(
            &good_offer.seller_npub,
            &good_offer.offer_id,
        );
        let newcomer_key = nostr_vpn_core::paid_route_store::paid_route_offer_store_key(
            &newcomer_offer.seller_npub,
            &newcomer_offer.offer_id,
        );
        let mut store = PaidRouteStore::default();
        store
            .upsert_signed_offer(good, vec!["wss://relay.example".to_string()], 100)
            .unwrap();
        store
            .upsert_signed_offer(newcomer, vec!["wss://relay.example".to_string()], 110)
            .unwrap();
        store
            .upsert_signed_offer(bad, vec!["wss://relay.example".to_string()], 120)
            .unwrap();
        assert!(store.upsert_offer_rating_score(&good_offer.seller_npub, 70, 130));
        assert!(store.upsert_offer_rating_score(&bad_offer.seller_npub, -70, 130));
        let mut args = sample_buy_args(None, true);

        assert_eq!(
            paid_exit_buy_offer_selector(&args, &store).unwrap(),
            good_key
        );

        assert!(store.upsert_offer_rating_score(&good_offer.seller_npub, -90, 140));
        assert_eq!(
            paid_exit_buy_offer_selector(&args, &store).unwrap(),
            newcomer_key
        );

        args.offer = Some("manual-offer".to_string());
        assert!(paid_exit_buy_offer_selector(&args, &store)
            .unwrap_err()
            .to_string()
            .contains("cannot be combined"));
        assert_eq!(
            paid_exit_buy_offer_selector(&sample_buy_args(Some("manual-offer"), false), &store)
                .unwrap(),
            "manual-offer"
        );
        assert!(paid_exit_buy_offer_selector(&sample_buy_args(None, false), &store)
            .unwrap_err()
            .to_string()
            .contains("required unless --best-rated"));
    }

    #[test]
    fn rating_fact_filter_targets_rating_kind_and_since() {
        let filter = paid_exit_rating_fact_filter(25, Some(100), "fips.peer");
        let value = serde_json::to_value(filter).unwrap();

        assert_eq!(value["kinds"], json!([RATING_FACT_KIND]));
        assert_eq!(value["limit"], 25);
        assert_eq!(value["since"], 100);
        assert_eq!(value["#i"], json!(["fips.peer"]));
    }

    #[test]
    fn app_relay_config_excludes_disabled_payment_fallback_relays() {
        let mut app = AppConfig::generated();
        app.nostr.relays = vec![
            "wss://relay-a.example".to_string(),
            "wss://relay-disabled.example".to_string(),
        ];
        app.nostr.disabled_relays = vec!["wss://relay-disabled.example".to_string()];
        let relays = paid_exit_relay_urls(&app, &[]);

        assert_eq!(relays, vec!["wss://relay-a.example".to_string()]);
    }

    #[test]
    fn offer_retention_policy_accepts_paid_exit_offer_events() {
        let signed = sample_signed_offer("retained", 100);
        let verified = nostr_pubsub::VerifiedEvent::try_from(signed.event.clone()).unwrap();

        let accepted = paid_exit_offer_retention_policy(25, Some(90));
        let rejected = paid_exit_offer_retention_policy(25, Some(110));

        assert_eq!(accepted.max_events, 25);
        assert!(accepted.accepts(&verified));
        assert!(!rejected.accepts(&verified));
    }

    #[test]
    fn offer_discovery_rejects_expired_nip40_events() {
        let signed = sample_signed_offer("expiring", 100);
        let policy = paid_exit_offer_retention_policy(25, None);
        let requested_seller = signed.event.pubkey;
        let other_seller = Keys::generate().public_key();

        assert!(paid_exit_offer_event_is_live(
            &signed.event,
            &policy,
            Some(&requested_seller),
            100 + nostr_vpn_core::paid_routes::PAID_ROUTE_OFFER_TTL_SECS - 1,
        ));
        assert!(!paid_exit_offer_event_is_live(
            &signed.event,
            &policy,
            Some(&other_seller),
            100,
        ));
        assert!(!paid_exit_offer_event_is_live(
            &signed.event,
            &policy,
            None,
            100 + nostr_vpn_core::paid_routes::PAID_ROUTE_OFFER_TTL_SECS,
        ));
    }

    #[tokio::test]
    async fn offer_discovery_waits_for_the_daemon_cache() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("nvpn-paid-discover-{nonce}"));
        let config_path = directory.join("config.toml");
        let store_path =
            crate::control_pubsub_runtime::control_pubsub_store_file_path(&config_path);
        let signed = sample_signed_offer("delayed", unix_timestamp());
        let event_id = signed.event.id;
        let event = signed.event;
        let write_store = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            std::fs::create_dir_all(store_path.parent().expect("store parent"))
                .expect("create store parent");
            let temporary = store_path.with_extension("tmp");
            std::fs::write(
                &temporary,
                serde_json::to_vec(&json!({ "version": 1, "events": [event] }))
                    .expect("encode cache"),
            )
            .expect("write cache");
            std::fs::rename(temporary, store_path).expect("publish cache");
        });

        let events = wait_for_paid_exit_control_events(
            &config_path,
            &paid_exit_offer_retention_policy(25, None),
            None,
            1,
        )
        .await
        .expect("wait for cached offer");
        write_store.await.expect("cache writer");

        assert!(events.iter().any(|event| event.id == event_id));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn unbounded_offer_requests_still_get_bounded_pubsub_retention() {
        let policy = paid_exit_offer_retention_policy(0, None);

        assert_eq!(policy.max_events, PAID_EXIT_OFFER_EVENT_CACHE_LIMIT);
    }

    #[test]
    fn rating_retention_policy_matches_scope_and_uses_lookup_cap() {
        let event_value = sample_rating_fact_event("npub1crawler", "npub1peer", "fips.peer", 85, 20);
        let event: Event = serde_json::from_value(event_value).unwrap();
        let verified = nostr_pubsub::VerifiedEvent::try_from(event).unwrap();

        let accepted = paid_exit_rating_retention_policy(0, None, "fips.peer");
        let rejected = paid_exit_rating_retention_policy(0, None, "other.scope");

        assert_eq!(accepted.max_events, PAID_EXIT_RATING_EVENT_LOOKUP_LIMIT);
        assert!(accepted.accepts(&verified));
        assert!(!rejected.accepts(&verified));
    }

    #[test]
    fn rating_fact_scope_filter_matches_scope_tag() {
        let event = sample_rating_fact_event("npub1crawler", "npub1peer", "fips.peer", 85, 20);

        assert!(paid_exit_rating_fact_matches_scope(&event, "fips.peer"));
        assert!(!paid_exit_rating_fact_matches_scope(&event, "other.scope"));
    }

    #[test]
    fn paid_exit_probe_quality_maps_to_integer_rating_bounds() {
        let healthy = sample_probe_record(
            Some("198.51.100.42"),
            Some(PaidRouteQualityMetrics {
                latency_ms: Some(80),
                jitter_ms: Some(20),
                packet_loss_ppm: Some(0),
                down_bps: Some(20_000_000),
                up_bps: Some(5_000_000),
                last_seen_unix: Some(123),
                ..PaidRouteQualityMetrics::default()
            }),
        );
        assert_eq!(
            paid_exit_rating_from_session_probe(&healthy, 999).unwrap(),
            (100, 123)
        );

        let degraded = sample_probe_record(
            None,
            Some(PaidRouteQualityMetrics {
                latency_ms: Some(1_500),
                jitter_ms: Some(300),
                packet_loss_ppm: Some(250_000),
                down_bps: Some(100_000),
                last_seen_unix: Some(124),
                ..PaidRouteQualityMetrics::default()
            }),
        );
        assert_eq!(
            paid_exit_rating_from_session_probe(&degraded, 999).unwrap(),
            (0, 124)
        );
        assert_eq!(
            paid_exit_normalized_rating_score(0, 0, 100).unwrap(),
            -100
        );
    }

    #[test]
    fn exported_paid_exit_rating_fact_is_accepted_by_rating_importer() {
        let rater = Keys::generate();
        let seller = Keys::generate();
        let rater_npub = rater.public_key().to_bech32().unwrap();
        let seller_npub = seller.public_key().to_bech32().unwrap();
        let event = build_paid_exit_rating_fact_event(
            &rater,
            &rater_npub,
            &seller_npub,
            "fips.peer",
            "session-1",
            90,
            456,
        )
        .unwrap();
        assert_eq!(event.kind, Kind::Custom(RATING_FACT_KIND as u16));
        assert_eq!(event.pubkey, rater.public_key());

        let value = serde_json::to_value(&event).unwrap();
        assert!(paid_exit_rating_fact_matches_scope(&value, "fips.peer"));
        assert!(paid_exit_fact_values(&value, "reason").contains(&"paid_exit_probe".to_string()));
        assert!(!paid_exit_fact_tags(&value).iter().any(|tag| {
            tag.as_array()
                .and_then(|parts| parts.first())
                .and_then(|value| value.as_str())
                == Some("context")
        }));

        let scores =
            paid_exit_rating_scores_from_value(
                &json!({"events": [value]}),
                "fips.peer",
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(
            scores.get(&seller_npub),
            Some(&PaidExitRatingScore {
                score: 80,
                created_at: 456,
            })
        );
    }

    #[test]
    fn degraded_paid_exit_probe_rating_fact_makes_best_rated_avoid_seller() {
        let degraded = sample_signed_offer("degraded", 30);
        let newcomer = sample_signed_offer("newcomer", 20);
        let degraded_offer = degraded.offer().unwrap();
        let newcomer_offer = newcomer.offer().unwrap();
        let degraded_key = nostr_vpn_core::paid_route_store::paid_route_offer_store_key(
            &degraded_offer.seller_npub,
            &degraded_offer.offer_id,
        );
        let newcomer_key = nostr_vpn_core::paid_route_store::paid_route_offer_store_key(
            &newcomer_offer.seller_npub,
            &newcomer_offer.offer_id,
        );
        let degraded_probe = sample_probe_record(
            None,
            Some(PaidRouteQualityMetrics {
                latency_ms: Some(1_500),
                jitter_ms: Some(300),
                packet_loss_ppm: Some(250_000),
                down_bps: Some(100_000),
                last_seen_unix: Some(124),
                ..PaidRouteQualityMetrics::default()
            }),
        );
        let (rating, created_at) =
            paid_exit_rating_from_session_probe(&degraded_probe, 999).unwrap();
        assert_eq!((rating, created_at), (0, 124));

        let rater = Keys::generate();
        let rater_npub = rater.public_key().to_bech32().unwrap();
        let event = build_paid_exit_rating_fact_event(
            &rater,
            &rater_npub,
            &degraded_offer.seller_npub,
            "fips.peer",
            "session-degraded",
            rating,
            created_at,
        )
        .unwrap();
        let event_value = serde_json::to_value(&event).unwrap();
        assert!(paid_exit_rating_fact_matches_scope(
            &event_value,
            "fips.peer"
        ));

        let scores =
            paid_exit_rating_scores_from_value(
                &json!({"events": [event_value]}),
                "fips.peer",
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(
            scores.get(&degraded_offer.seller_npub),
            Some(&PaidExitRatingScore {
                score: -100,
                created_at: 124,
            })
        );

        let mut ranked = vec![degraded.clone(), newcomer.clone()];
        paid_exit_sort_offers_by_rating(&mut ranked, &scores);
        assert_eq!(
            ranked[0].offer().unwrap().seller_npub,
            newcomer_offer.seller_npub
        );

        let store_path = temp_paid_exit_store_path("degraded-rating-bridge");
        let changed = persist_paid_exit_discovered_offers(
            &store_path,
            &[degraded, newcomer],
            &["wss://relay.example".to_string()],
            Some(&scores),
        )
        .unwrap();
        assert_eq!(changed, 2);

        let store = load_paid_route_store(&store_path).unwrap();
        let degraded_record = store.offers.get(&degraded_key).expect("degraded offer");
        assert_eq!(degraded_record.rating_score, Some(-100));
        assert_eq!(degraded_record.rating_updated_at_unix, 124);
        assert_eq!(
            paid_exit_buy_offer_selector(&sample_buy_args(None, true), &store).unwrap(),
            newcomer_key
        );

        let _ = std::fs::remove_file(store_path);
    }

    fn sample_signed_offer(offer_id: &str, created_at: u64) -> SignedPaidRouteOffer {
        let keys = Keys::generate();
        let config = PaidExitConfig::default();
        let offer = PaidRouteOffer::from_paid_exit_config(
            offer_id,
            keys.public_key().to_bech32().unwrap(),
            &config,
            None,
        );
        SignedPaidRouteOffer::sign(offer, &keys, created_at).unwrap()
    }

    fn temp_paid_exit_store_path(name: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nvpn-paid-exit-{name}-{}-{now}.json",
            std::process::id()
        ))
    }

    fn sample_buy_args(offer: Option<&str>, best_rated: bool) -> PaidExitBuyArgs {
        PaidExitBuyArgs {
            config: None,
            offer: offer.map(ToOwned::to_owned),
            best_rated,
            mint: None,
            channel_capacity_sat: None,
            initial_paid_msat: 0,
            no_select_exit_node: false,
            no_reload_daemon: false,
            json: false,
        }
    }

    fn sample_probe_record(
        realized_exit_ip: Option<&str>,
        quality: Option<PaidRouteQualityMetrics>,
    ) -> PaidRouteSessionRecord {
        PaidRouteSessionRecord {
            session: nostr_vpn_core::paid_routes::PaidRouteSession {
                session_id: "session-1".to_string(),
                lease_id: "lease-1".to_string(),
                usage: Default::default(),
                payment: Default::default(),
                realized_exit_ip: realized_exit_ip.map(ToOwned::to_owned),
                observed_country_code: None,
                observed_asn: None,
                quality,
            },
            created_at_unix: 100,
            updated_at_unix: 120,
        }
    }

    fn sample_rating_fact_event(
        rater: &str,
        subject: &str,
        scope: &str,
        rating: i64,
        created_at: u64,
    ) -> serde_json::Value {
        let keys = Keys::generate();
        sample_rating_fact_event_signed_by(&keys, rater, subject, scope, rating, created_at)
    }

    fn sample_rating_fact_event_signed_by(
        keys: &Keys,
        rater: &str,
        subject: &str,
        scope: &str,
        rating: i64,
        created_at: u64,
    ) -> serde_json::Value {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let rater_index = rater.to_lowercase();
        let subject_index = subject.to_lowercase();
        let scope_index = scope.to_lowercase();
        let tags = vec![
            sample_rating_fact_tag(["i", id, "subject"]),
            sample_rating_fact_tag(["i", &rater_index]),
            sample_rating_fact_tag(["i", &subject_index]),
            sample_rating_fact_tag(["i", &scope_index]),
            sample_rating_fact_tag(["type", RATING_FACT_TYPE]),
            sample_rating_fact_tag(["schema", RATING_FACT_SCHEMA]),
            sample_rating_fact_tag(["created_at", &created_at.to_string()]),
            sample_rating_fact_tag(["rater", rater]),
            sample_rating_fact_tag(["subject", subject]),
            sample_rating_fact_tag(["scope", scope]),
            sample_rating_fact_tag(["rating", &rating.to_string()]),
            sample_rating_fact_tag(["min_rating", "0"]),
            sample_rating_fact_tag(["max_rating", "100"]),
            sample_rating_fact_tag(["sample_count", "7"]),
            sample_rating_fact_tag(["tag", "fips"]),
            sample_rating_fact_tag(["tag", "peer"]),
        ];
        let event = EventBuilder::new(Kind::Custom(RATING_FACT_KIND as u16), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .unwrap();

        serde_json::to_value(event).unwrap()
    }

    fn sample_rating_fact_tag<const N: usize>(parts: [&str; N]) -> Tag {
        Tag::parse(parts).unwrap()
    }
}
