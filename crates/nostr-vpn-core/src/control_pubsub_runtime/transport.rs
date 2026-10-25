fn fips_pubsub_options(max_event_bytes: usize, max_hops: u8) -> FipsPubsubClientOptions {
    FipsPubsubClientOptions {
        max_frame_bytes: max_event_bytes
            .saturating_add(4 * 1_024)
            .min(CONTROL_PUBSUB_MAX_WIRE_BYTES),
        max_connected_peers: MAX_PUBSUB_PEERS,
        max_replay_events: FIPS_REPLAY_LIMIT,
        receive_batch_size: 64,
        max_hops,
        ..FipsPubsubClientOptions::default()
    }
}

#[derive(Debug, Clone)]
pub struct ControlRelayStatus {
    pub url: String,
    pub status: String,
}

// Query retained control events before applying the transport's replay limit.
// A release root may be older than every event in the small live gossip cache.
struct ControlEventReplay {
    events: Arc<Mutex<ControlEventStore>>,
    policy: Arc<Mutex<FipsPubsubPolicy>>,
}

fn scoped_fips_replay(mut events: Vec<Event>, peer_ratings: &Filter) -> Vec<Event> {
    // Old caches can contain ratings collected by the former unscoped request.
    // Filter those before either replay path applies its cap.
    let rating_filters = rating_subscription_filters(peer_ratings, FIPS_REPLAY_LIMIT);
    events.retain(|event| {
        event.kind != Kind::Custom(RATING_FACT_KIND)
            || rating_filters
                .iter()
                .any(|filter| filter.match_event(event, MatchEventOptions::new()))
    });
    events
}

#[async_trait::async_trait]
impl EventBus for ControlEventReplay {
    async fn publish(
        &self,
        _event: VerifiedEvent,
        _source: EventSource,
    ) -> nostr_pubsub::Result<nostr_pubsub::PublishReport> {
        Err(nostr_pubsub::PubsubError::Storage(
            "control event replay is read-only".to_string(),
        ))
    }

    async fn query(
        &self,
        filters: Vec<Filter>,
        options: nostr_pubsub::QueryOptions,
    ) -> nostr_pubsub::Result<nostr_pubsub::QueryReport> {
        let limit = options
            .limit
            .unwrap_or(FIPS_REPLAY_LIMIT)
            .min(FIPS_REPLAY_LIMIT);
        if limit == 0 {
            return Ok(nostr_pubsub::QueryReport::default());
        }
        let peer_ratings = self.policy.lock().await.rating_filter()?;
        let mut stored = scoped_fips_replay(self.events.lock().await.snapshot(), &peer_ratings);
        stored.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let filters = if filters.is_empty() {
            vec![Filter::new()]
        } else {
            filters
        };
        let mut selected = HashSet::new();
        for filter in filters {
            for event in stored
                .iter()
                .filter(|event| filter.match_event(event, MatchEventOptions::new()))
                .take(filter.limit.unwrap_or(limit).min(limit))
            {
                selected.insert(event.id);
            }
        }
        let events = stored
            .into_iter()
            .filter(|event| selected.contains(&event.id))
            .take(limit)
            .map(|event| {
                Ok(QueryEvent {
                    event: VerifiedEvent::try_from(event)?,
                    source: EventSource::local_index("nvpn-control-events"),
                    priority: 0,
                })
            })
            .collect::<nostr_pubsub::Result<Vec<_>>>()?;
        Ok(nostr_pubsub::QueryReport { events })
    }
}
