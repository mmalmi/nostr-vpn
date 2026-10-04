fn exit_graph_filter(root: PublicKey) -> Filter {
    Filter::new()
        .author(root)
        .kinds([Kind::ContactList, Kind::MuteList])
        .limit(2)
}

fn control_kinds() -> Vec<Kind> {
    vec![
        #[cfg(feature = "paid-exit")]
        Kind::Custom(PAID_EXIT_OFFER_KIND),
        Kind::Custom(RATING_FACT_KIND),
    ]
}

fn relay_subscription_filters(
    update_events: &UpdateEventCache,
    target_advert_authors: &[PublicKey],
) -> Vec<Filter> {
    let mut filters = Vec::with_capacity(5);
    if !target_advert_authors.is_empty() {
        filters.push(
            Filter::new()
                .kind(Kind::Custom(FIPS_PEER_ADVERT_KIND))
                .authors(target_advert_authors.iter().copied())
                .limit(target_advert_authors.len().min(MAX_PUBSUB_PEERS)),
        );
    }
    filters.extend([
        Filter::new()
            .kind(Kind::Custom(FIPS_PEER_ADVERT_KIND))
            .limit(RELAY_REPLAY_LIMIT),
        #[cfg(feature = "paid-exit")]
        Filter::new()
            .kind(Kind::Custom(PAID_EXIT_OFFER_KIND))
            .limit(RELAY_REPLAY_LIMIT),
        Filter::new()
            .kind(Kind::Custom(RATING_FACT_KIND))
            .limit(RELAY_REPLAY_LIMIT),
        update_events.filter().clone().limit(RELAY_REPLAY_LIMIT),
    ]);
    filters
}

fn is_control_event(event: &Event, update_events: &UpdateEventCache) -> bool {
    if u16::from(event.kind) == PAID_EXIT_OFFER_KIND {
        return cfg!(feature = "paid-exit");
    }
    matches!(
        u16::from(event.kind),
        FIPS_PEER_ADVERT_KIND | RATING_FACT_KIND | 3 | 10_000
    ) || update_events
        .filter()
        .match_event(event, MatchEventOptions::new())
}
