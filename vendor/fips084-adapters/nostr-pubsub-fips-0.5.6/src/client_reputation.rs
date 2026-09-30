use super::{
    Arc, ClientInner, EventSource, FipsEndpoint, FipsPubsubClient, FipsPubsubClientOptions,
    FipsPubsubPolicy, FipsPubsubPolicyOptions, FipsPubsubSubscription, Ordering, PubsubError,
    Result, VerifiedEvent, now_ms,
};

impl FipsPubsubClient {
    /// Start with managed, bounded machine reputation. No external rater is
    /// selected by default. Ratings remain in memory and are recovered through
    /// peer replay; use the policy facade directly for application persistence.
    ///
    /// One subscription from `max_active_subscriptions` is owned by reputation.
    /// The task observes only explicit raters and publishes paced local ratings;
    /// it stops with the client and never shuts down the application endpoint.
    pub async fn start_with_reputation(
        endpoint: Arc<FipsEndpoint>,
        options: FipsPubsubClientOptions,
        reputation: FipsPubsubPolicyOptions,
    ) -> Result<Self> {
        let interval = reputation.evaluation_interval;
        let policy = FipsPubsubPolicy::new(endpoint.clone(), std::iter::empty(), reputation)?;
        let filter = policy.rating_filter()?;
        let mut client =
            Self::start_with_policies(endpoint, options, policy.client_policies()).await?;
        let subscription = client.subscribe(vec![filter]).await?;
        client.tasks.get_mut().reputation = Some(tokio::spawn(run_reputation(
            client.inner.clone(),
            subscription,
            policy,
            interval,
        )));
        Ok(client)
    }

    /// Failed managed reputation updates or publication batches. Invalid remote
    /// ratings are discarded by the normal validator without incrementing this.
    #[must_use]
    pub fn reputation_error_count(&self) -> u64 {
        self.inner.reputation_errors.load(Ordering::Relaxed)
    }
}

async fn run_reputation(
    inner: Arc<ClientInner>,
    mut subscription: FipsPubsubSubscription,
    mut policy: FipsPubsubPolicy,
    interval: std::time::Duration,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let result = tokio::select! {
            delivery = subscription.recv() => {
                let Some(delivery) = delivery else { return; };
                policy.observe_event(delivery.event.as_event()).map(|_| ())
            }
            _ = timer.tick() => maintain_reputation(&inner, &mut policy, now_ms()).await,
        };
        if result.is_err() {
            inner.reputation_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn maintain_reputation(
    inner: &ClientInner,
    policy: &mut FipsPubsubPolicy,
    now: u64,
) -> Result<()> {
    let events = policy.maintenance_events(now).await?;
    publish_ratings(inner, policy, events, now).await
}

pub(super) async fn publish_ratings(
    inner: &ClientInner,
    policy: &mut FipsPubsubPolicy,
    events: Vec<nostr::Event>,
    now: u64,
) -> Result<()> {
    let mut failure = None;
    for event in events.into_iter().take(inner.options.max_replay_events) {
        let outcome = async {
            let verified = VerifiedEvent::try_from(event.clone())?;
            let published = inner
                .publish(
                    verified,
                    EventSource::fips_endpoint(inner.endpoint.npub().to_string()),
                )
                .await;
            let accepted = published.as_ref().is_ok_and(|report| report.accepted);
            policy.complete_maintenance_event(&event, accepted, now)?;
            published?;
            if accepted {
                Ok(())
            } else {
                Err(PubsubError::Storage(
                    "local peer rating was rejected by pubsub policy".into(),
                ))
            }
        }
        .await;
        if let Err(error) = outcome {
            // A failed send must not starve later local observations in this
            // bounded batch. Keep publication due and expose the failure.
            failure = Some(error);
        }
    }
    failure.map_or(Ok(()), Err)
}
