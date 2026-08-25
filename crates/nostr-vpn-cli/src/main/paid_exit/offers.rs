
async fn paid_exit_offer_command(args: PaidExitOfferArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    if args.publish {
        require_paid_exit_seller_daemon_ready(&config_path, false).await?;
    }
    let offer_id = args.offer_id.unwrap_or_else(default_paid_exit_offer_id);
    let local = build_local_paid_exit_offer(&app, &config_path, &offer_id, unix_timestamp())?;
    let provider_link = paid_exit_provider_link_for_offer(&local.offer)?;

    let publish = if args.publish {
        Some(publish_paid_exit_offer_pubsub(
            &app,
            &config_path,
            &local.signed,
        )?)
    } else {
        None
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "offer": local.offer,
                "provider_link": provider_link,
                "event": local.signed.event,
                "publish": publish,
                "store_path": local.store_path,
                "stored": local.stored,
            }))?
        );
    } else {
        println!("paid_exit_offer: {}", local.offer.offer_id);
        println!("seller: {}", local.offer.seller_npub);
        println!("provider_link: {provider_link}");
        println!(
            "price: {}",
            paid_exit_price_text(local.offer.pricing.price_msat_per_gb)
        );
        println!(
            "access: upstream={} private_vpn_access={}",
            local.offer.access.upstream.as_str(),
            local.offer.access.private_vpn_access.as_str()
        );
        println!(
            "location: country={} asn={}",
            display_or_none(&local.offer.location.country_code),
            local.offer
                .location
                .asn
                .map(|asn| asn.to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        println!("event_id: {}", local.signed.event.id);
        println!(
            "store: {} changed={}",
            local.store_path.display(),
            local.stored
        );
        if let Some(publish) = publish {
            println!(
                "published: nostr-pubsub queued={}",
                publish["nostr_pubsub_queued"].as_bool().unwrap_or_default()
            );
        } else {
            println!("published: false");
        }
    }

    Ok(())
}

struct LocalPaidExitOffer {
    signed: SignedPaidRouteOffer,
    offer: PaidRouteOffer,
    store_path: PathBuf,
    stored: bool,
}

fn build_local_paid_exit_offer(
    app: &AppConfig,
    config_path: &Path,
    offer_id: &str,
    now_unix: u64,
) -> Result<LocalPaidExitOffer> {
    let config = paid_exit_offer_config(app)?;
    let receiver_pubkey_hex = paid_exit_spilman_receiver_pubkey_hex(config_path, &config)?;
    let fips_endpoints = if app.fips_advertise_public_endpoint {
        normalize_fips_peer_endpoint_hint(&app.node.endpoint)
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let signed = signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints(
        offer_id,
        &app.nostr_keys()?,
        &config,
        receiver_pubkey_hex.as_deref(),
        &fips_endpoints,
        Some(PaidRouteQualityMetrics {
            last_seen_unix: Some(now_unix),
            ..PaidRouteQualityMetrics::default()
        }),
        now_unix,
    )?;
    let offer = signed.offer()?;
    let store_path = paid_route_store_file_path(config_path);
    let stored = persist_paid_exit_offer_snapshot(&store_path, &signed, &[], &offer, now_unix)?;
    Ok(LocalPaidExitOffer {
        signed,
        offer,
        store_path,
        stored,
    })
}

fn paid_exit_import_offer_command(args: PaidExitImportOfferArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let event_json = read_paid_exit_offer_event(args.event, args.event_stdin, args.event_file)?;
    let event: Event = serde_json::from_str(&event_json)
        .context("failed to decode paid route offer event JSON")?;
    let signed = SignedPaidRouteOffer::from_event(event)
        .context("failed to verify paid route offer event")?;
    let offer = signed.offer()?;
    let store_path = paid_route_store_file_path(&config_path);
    let changed =
        upsert_paid_route_offer(&store_path, signed.clone(), vec![], unix_timestamp())?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "offer": offer,
                "event": signed.event,
                "store_path": store_path,
                "stored": changed,
            }))?
        );
    } else {
        println!("paid_exit_offer: {}", offer.offer_id);
        println!("seller: {}", offer.seller_npub);
        println!("event_id: {}", signed.event.id);
        println!("store: {} changed={changed}", store_path.display());
    }

    Ok(())
}

fn paid_exit_offer_event_is_live(
    event: &Event,
    retention_policy: &nostr_pubsub::EventRetentionPolicy,
    seller: Option<&PublicKey>,
    now_unix: u64,
) -> bool {
    if seller.is_some_and(|seller| &event.pubkey != seller) {
        return false;
    }
    nostr_pubsub::VerifiedEvent::try_from(event.clone())
        .is_ok_and(|verified| retention_policy.accepts(&verified))
        && SignedPaidRouteOffer::from_event(event.clone())
            .is_ok_and(|signed| signed.is_live_at(now_unix))
}

async fn wait_for_paid_exit_control_events(
    config_path: &Path,
    retention_policy: &nostr_pubsub::EventRetentionPolicy,
    seller: Option<&PublicKey>,
    duration_secs: u64,
) -> Result<Vec<Event>> {
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut events = crate::control_pubsub_runtime::load_control_pubsub_events(config_path)?;
    if duration_secs == 0 {
        return Ok(events);
    }
    let initial_offer_ids = events
        .iter()
        .filter(|event| {
            paid_exit_offer_event_is_live(
                event,
                retention_policy,
                seller,
                unix_timestamp(),
            )
        })
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(events);
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
        events = crate::control_pubsub_runtime::load_control_pubsub_events(config_path)?;
        let now_unix = unix_timestamp();
        if events.iter().any(|event| {
            !initial_offer_ids.contains(&event.id)
                && paid_exit_offer_event_is_live(event, retention_policy, seller, now_unix)
        }) {
            return Ok(events);
        }
    }
}

async fn paid_exit_discover_command(args: PaidExitDiscoverArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let provider = args
        .provider
        .as_deref()
        .map(ManualPaidExitProvider::parse)
        .transpose()
        .context("invalid targeted paid exit provider")?;
    let seller = provider
        .as_ref()
        .map(|provider| PublicKey::parse(&provider.npub))
        .transpose()
        .context("invalid targeted paid exit seller npub")?;
    let trusted_rating_authors =
        paid_exit_trusted_rating_author_set(&args.trusted_rating_authors)?;
    let mut rating_scores = args
        .fips_peer_ratings
        .as_deref()
        .map(|path| load_paid_exit_rating_scores(path, &args.rating_scope, &trusted_rating_authors))
        .transpose()?;
    let since_unix = if args.since_secs == 0 {
        None
    } else {
        Some(unix_timestamp().saturating_sub(args.since_secs))
    };
    let retention_policy = paid_exit_offer_retention_policy(args.limit, since_unix);
    let cached_control_events = wait_for_paid_exit_control_events(
        &config_path,
        &retention_policy,
        seller.as_ref(),
        args.duration_secs,
    )
    .await?;
    let cached_rating_events = cached_control_events
        .iter()
        .filter(|event| event.kind == Kind::Custom(RATING_FACT_KIND as u16))
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let cached_rating_event_count = cached_rating_events.len();
    if !cached_rating_events.is_empty() {
        let cached_scores = paid_exit_rating_scores_from_value(
            &json!({ "events": cached_rating_events }),
            &args.rating_scope,
            &trusted_rating_authors,
        )?;
        merge_paid_exit_rating_scores(&mut rating_scores, cached_scores);
    }
    let now_unix = unix_timestamp();
    let cached_offers = cached_control_events
        .into_iter()
        .filter_map(|event| {
            paid_exit_offer_event_is_live(
                &event,
                &retention_policy,
                seller.as_ref(),
                now_unix,
            )
                .then(|| SignedPaidRouteOffer::from_event(event).ok())
                .flatten()
        })
        .filter(|signed| {
            provider.as_ref().is_none_or(|provider| {
                signed
                    .offer()
                    .is_ok_and(|offer| provider.accepts(&offer).is_ok())
            })
        })
        .collect::<Vec<_>>();
    let cached_offer_count = cached_offers.len();
    let mut offers = cached_offers.clone();
    offers.sort_by_key(|signed| std::cmp::Reverse(signed.event.created_at.as_secs()));
    let mut seen_offer_ids = HashSet::new();
    offers.retain(|signed| seen_offer_ids.insert(signed.event.id));
    offers.truncate(retention_policy.max_events);
    if let Some(scores) = rating_scores.as_ref() {
        paid_exit_sort_offers_by_rating(&mut offers, scores);
    }
    let store_path = paid_route_store_file_path(&config_path);
    let stored_count = persist_paid_exit_discovered_offers(
        &store_path,
        &cached_offers,
        &[],
        rating_scores.as_ref(),
    )?;

    if args.json {
        let offers_json = paid_exit_offer_results_json(&offers, rating_scores.as_ref())?;
        let ratings_json = if args.fips_peer_ratings.is_some() || cached_rating_event_count > 0 {
            Some(json!({
                "path": args.fips_peer_ratings.as_ref().map(|path| path.display().to_string()),
                "scope": args.rating_scope,
                "subject_count": rating_scores.as_ref().map_or(0, HashMap::len),
                "nostr_pubsub_cached_event_count": cached_rating_event_count,
                "trusted_author_count": trusted_rating_authors.len(),
            }))
        } else {
            None
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "count": offers_json.len(),
                "offers": offers_json,
                "store_path": store_path,
                "stored_count": stored_count,
                "nostr_pubsub_cached_offer_count": cached_offer_count,
                "nostr_pubsub_cached_rating_event_count": cached_rating_event_count,
                "ratings": ratings_json,
            }))?
        );
    } else {
        println!("paid_exit_offers: {}", offers.len());
        println!(
            "nostr_pubsub_cache: offers={} rating_events={}",
            cached_offer_count, cached_rating_event_count
        );
        println!("store: {} changed={stored_count}", store_path.display());
        if args.fips_peer_ratings.is_some() || cached_rating_event_count > 0 {
            let subject_count = rating_scores.as_ref().map_or(0, HashMap::len);
            let file = args
                .fips_peer_ratings
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "ratings: file={} scope={} subjects={} nostr_pubsub_events={} trusted_authors={}",
                file,
                args.rating_scope,
                subject_count,
                cached_rating_event_count,
                trusted_rating_authors.len()
            );
        }
        for signed in &offers {
            let offer = signed.offer()?;
            println!(
                "{}",
                paid_exit_offer_summary_line_with_rating(
                    &offer,
                    signed.event.id,
                    rating_scores.as_ref()
                )
            );
        }
    }

    Ok(())
}
