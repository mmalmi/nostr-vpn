struct RelayProvider {
    bus: Arc<RelayEventBus>,
    notifications: mpsc::Receiver<QueryEvent>,
    queued_events: Arc<StdMutex<HashSet<(EventId, EventSource)>>>,
    _subscription: Box<dyn NostrEventSubscription>,
    #[cfg(feature = "paid-exit")]
    ingress: Arc<dyn Fn(QueryEvent) -> bool + Send + Sync>,
    #[cfg(feature = "paid-exit")]
    profile_subscription: Option<Box<dyn NostrEventSubscription>>,
    #[cfg(feature = "paid-exit")]
    profile_authors: Vec<PublicKey>,
    #[cfg(feature = "paid-exit")]
    profile_graph_authors: Vec<PublicKey>,
    #[cfg(feature = "paid-exit")]
    profile_inputs: Option<Vec<nostr_sdk::prelude::EventId>>,
    #[cfg(feature = "paid-exit")]
    profile_graph_revision: Option<u64>,
}

impl RelayProvider {
    async fn start(
        host_network: Option<Arc<dyn fips_core::host_network::HostNetwork>>,
        mode: NostrPubsubMode,
        relays: Vec<String>,
        mut filters: Vec<Filter>,
        graph_root: PublicKey,
    ) -> Result<Option<Self>> {
        if mode != NostrPubsubMode::Relay || relays.is_empty() {
            return Ok(None);
        }
        let bus = if let Some(network) = host_network {
            let client = Client::builder()
                .signer(nostr_sdk::Keys::generate())
                .websocket_transport(fips_core::host_network::NostrHostTransport(network))
                .build();
            RelayEventBus::with_client(client, relays, RELAY_QUERY_TIMEOUT).await
        } else {
            RelayEventBus::new(relays, RELAY_QUERY_TIMEOUT).await
        }
        .context("failed to start configured Nostr pubsub relay provider")?;
        let bus = Arc::new(bus);
        let (notification_tx, notifications) = mpsc::channel(RELAY_REPLAY_LIMIT * 5);
        let queued_events = Arc::new(StdMutex::new(HashSet::new()));
        let admitted_events = Arc::clone(&queued_events);
        let ingress: Arc<dyn Fn(QueryEvent) -> bool + Send + Sync> = Arc::new(move |event| {
            let key = (event.event.as_event().id, event.source.clone());
            let mut queued = admitted_events
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // Coalesce verified copies only while queued and only from the
            // same source. Later observations still reach policy and FIPS.
            if queued.contains(&key) {
                return true;
            }
            match notification_tx.try_send(event) {
                Ok(()) => {
                    queued.insert(key);
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        "control pubsub relay ingress is full; requesting retained-event replay"
                    );
                    false
                }
            }
        });
        filters.push(exit_graph_filter(graph_root));
        let subscription = bus
            .subscribe_with_admission(filters, Arc::clone(&ingress))
            .await
            .context("failed to subscribe through configured Nostr pubsub relay provider")?;
        Ok(Some(Self {
            bus,
            notifications,
            queued_events,
            _subscription: subscription,
            #[cfg(feature = "paid-exit")]
            ingress,
            #[cfg(feature = "paid-exit")]
            profile_subscription: None,
            #[cfg(feature = "paid-exit")]
            profile_authors: Vec::new(),
            #[cfg(feature = "paid-exit")]
            profile_graph_authors: Vec::new(),
            #[cfg(feature = "paid-exit")]
            profile_inputs: None,
            #[cfg(feature = "paid-exit")]
            profile_graph_revision: None,
        }))
    }
}
