async fn run_mobile_paid_exit_pubsub(
    client: ControlPubsubClient,
    app: AppConfig,
    store_path: PathBuf,
) -> Result<()> {
    use nostr_vpn_core::paid_route_ratings::verified_exit_rating;
    use nostr_vpn_core::paid_route_store::{load_paid_route_store, update_paid_route_store};
    use nostr_vpn_core::paid_routes::{PAID_ROUTE_OFFER_KIND, SignedPaidRouteOffer};

    let root = app.nostr_keys()?.public_key();
    let mut accepted = HashSet::new();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let now = unix_timestamp();
        let store = load_paid_route_store(&store_path)?;
        let pending = store.pending_exit_ratings();
        accepted.retain(|id| pending.iter().any(|event| event.id == *id));
        for event in pending
            .into_iter()
            .filter(|event| {
                !accepted.contains(&event.id) && verified_exit_rating(event, now).is_ok()
            })
            .take(8)
            .collect::<Vec<_>>()
        {
            if client
                .publish(event.clone())
                .await
                .is_ok_and(|accepted| accepted)
            {
                accepted.insert(event.id);
            }
            // The rating remains the persistent outbox and is replayed after restart.
        }
        // The shared runtime owns the live subscriptions and bounded event store.
        let events = client.events().await;
        update_paid_route_store(&store_path, |store| {
            for event in &events {
                if u16::from(event.kind) != PAID_ROUTE_OFFER_KIND {
                    continue;
                }
                let Ok(signed) = SignedPaidRouteOffer::from_event(event.clone()) else {
                    continue;
                };
                if !signed.is_live_at(now) {
                    continue;
                }
                let offer = signed.offer()?;
                if !app.manual_paid_exit_provider.is_default()
                    && app.manual_paid_exit_provider.accepts(&offer).is_err()
                {
                    continue;
                }
                store.upsert_signed_offer(signed, Vec::new(), now)?;
            }
            let graph = nostr_vpn_core::paid_route_ratings::exit_rating_graph(
                &root.to_hex(),
                &events,
                &app.paid_exit.rating_discovery.trusted_authors,
                now,
            )?;
            store.refresh_exit_reputation(&events, &graph, now);
            Ok(())
        })?;
    }
}
