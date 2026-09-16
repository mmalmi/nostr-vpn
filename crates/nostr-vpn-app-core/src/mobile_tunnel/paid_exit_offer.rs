async fn run_mobile_paid_exit_pubsub(
    endpoint: Arc<FipsEndpoint>,
    app: AppConfig,
    store_path: PathBuf,
) -> Result<()> {
    use nostr_pubsub::{EventBus, EventSource, VerifiedEvent};
    use nostr_pubsub_fips::{FipsPubsubClient, FipsPubsubClientOptions};
    use nostr_sdk::prelude::{Event, Filter, Kind};
    use nostr_vpn_core::paid_route_ratings::{exit_rating_graph, verified_exit_rating};
    use nostr_vpn_core::paid_route_store::{load_paid_route_store, update_paid_route_store};
    use nostr_vpn_core::paid_routes::{PAID_ROUTE_OFFER_KIND, SignedPaidRouteOffer};

    let root = app.nostr_keys()?.public_key();
    let client = FipsPubsubClient::start(endpoint, FipsPubsubClientOptions::default()).await?;
    let mut subscription = client
        .subscribe(vec![
            Filter::new()
                .kind(Kind::Custom(PAID_ROUTE_OFFER_KIND))
                .limit(32),
            Filter::new().kind(Kind::Custom(7368)).limit(32),
            Filter::new()
                .author(root)
                .kinds([Kind::ContactList, Kind::MuteList])
                .limit(2),
        ])
        .await?;
    let mut accepted = std::collections::HashSet::new();
    let mut events: Vec<Event> = Vec::new();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = unix_timestamp();
                let store = load_paid_route_store(&store_path)?;
                let pending = store.pending_exit_ratings();
                accepted.retain(|id| pending.iter().any(|event| event.id == *id));
                let batch = pending.into_iter().filter(|event| !accepted.contains(&event.id) && verified_exit_rating(event, now).is_ok()).take(8).collect::<Vec<_>>();
                for event in batch {
                    let result = client.publish(VerifiedEvent::try_from(event.clone())?,
                        EventSource::local_index(root.to_hex())).await;
                    if result.is_ok_and(|report| report.accepted) { accepted.insert(event.id); }
                    // The persistent local rating remains the mobile outbox.
                    // Replay it on the next tunnel start; local acceptance alone
                    // does not prove delivery to any peer.
                }
            }
            delivery = subscription.recv() => {
                let Some(delivery) = delivery else { return Err(anyhow!("paid exit subscription closed")); };
                let event = delivery.event.into_event();
                let now = unix_timestamp();
                if u16::from(event.kind) == PAID_ROUTE_OFFER_KIND {
                    let Ok(signed) = SignedPaidRouteOffer::from_event(event) else { continue; };
                    if !signed.is_live_at(now) { continue; }
                    let offer = signed.offer()?;
                    if !app.manual_paid_exit_provider.is_default()
                        && app.manual_paid_exit_provider.accepts(&offer).is_err() { continue; }
                    let graph = exit_rating_graph(&root.to_hex(), &events, &app.paid_exit.rating_discovery.trusted_authors, now)?;
                    update_paid_route_store(&store_path, |store| {
                        store.upsert_signed_offer(signed, Vec::new(), now)?;
                        store.refresh_exit_reputation(&events, &graph, now);
                        Ok(())
                    })?;
                    continue;
                }
                if matches!(u16::from(event.kind), 3 | 10_000) && event.pubkey == root {
                    if event.created_at.as_secs() > now.saturating_add(300) { continue; }
                    if events.iter().any(|old| old.kind == event.kind && old.pubkey == root
                        && (old.created_at > event.created_at || (old.created_at == event.created_at && old.id <= event.id))) { continue; }
                    events.retain(|old| old.kind != event.kind || old.pubkey != root);
                } else {
                    let Ok(rating) = verified_exit_rating(&event, now) else { continue; };
                    let graph = exit_rating_graph(&root.to_hex(), &events, &app.paid_exit.rating_discovery.trusted_authors, now)?;
                    // Ratings may arrive before the viewer's follow list. Keep
                    // a bounded buffer, but never let unknown authors evict trusted ones.
                    let previous = events.iter().position(|old| old.pubkey == event.pubkey
                        && verified_exit_rating(old, now).is_ok_and(|r| r.subject == rating.subject));
                    if let Some(index) = previous {
                        let old = verified_exit_rating(&events[index], now)?;
                        if (old.created_at, events[index].id) >= (rating.created_at, event.id) { continue; }
                        events.remove(index);
                    }
                    if events.len() >= 256 {
                        let muted = graph.get_muted_by_user(graph.get_root());
                        let trusted = |review: &Event| graph.get_follow_distance(&review.pubkey.to_hex()) <= 1
                            && !muted.contains(&review.pubkey.to_hex());
                        let evict = events.iter().position(|old| u16::from(old.kind) == 7368 && !trusted(old))
                            .or_else(|| trusted(&event).then(|| events.iter().position(|old| u16::from(old.kind) == 7368)).flatten());
                        let Some(index) = evict else { continue; };
                        events.remove(index);
                    }
                }
                events.push(event);
                let graph = exit_rating_graph(&root.to_hex(), &events, &app.paid_exit.rating_discovery.trusted_authors, now)?;
                update_paid_route_store(&store_path, |store| {
                    store.refresh_exit_reputation(&events, &graph, now);
                    Ok(())
                })?;
            }
        }
    }
}
