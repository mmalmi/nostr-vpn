use super::{
    Arc, AtomicU64, AtomicUsize, EventId, EventPolicyContext, EventSource, Filter, FipsEndpoint,
    FipsPubsubClientOptions, FipsPubsubSubscription, FipsPubsubWireCodec, FipsPubsubWireMessage,
    HashMap, HashSet, Mutex, Ordering, PeerIdentity, PolicyDecision, PublishReport, PubsubError,
    PubsubPeerInterest, PubsubPeerSubscriptionStore, PubsubPolicy, QueryEvent, Result,
    SOURCE_PRIORITY_FIPS_ENDPOINT, SourceId, SubscriptionId, TransportCommand, VecDeque,
    VerifiedEvent, bounded_delivery_targets, event_payload_bytes, mpsc, no_connected_peers, now_ms,
    poisoned, publish_report, storage_error,
};
use crate::FIPS_NOSTR_PUBSUB_MAX_SEEN_EVENT_IDS;
use crate::pending_wants::{InventoryProvider, PendingInventory, PendingWants};
use crate::provider_behavior::{ProviderBehavior, ProviderViolation};
use crate::recent_events::{CachedEvent, RecentEvents, deliver_local};
use crate::seen_ids::ScopedSeenIds;

pub(super) struct ClientInner {
    pub(super) admission: Mutex<bool>,
    pub(super) endpoint: Arc<FipsEndpoint>,
    pub(super) codec: FipsPubsubWireCodec,
    pub(super) options: FipsPubsubClientOptions,
    pub(super) routed_peers: Mutex<Vec<String>>,
    pub(super) peer_transport: Option<&'static str>,
    pub(super) excluded_peer_transports: HashSet<String>,
    pub(super) event_policy: Option<Arc<dyn PubsubPolicy>>,
    pub(super) peer_policy: Option<Arc<dyn nostr_pubsub::MeshPeerPolicy>>,
    pub(super) unknown_peer_reserve: usize,
    pub(super) transport_tx: mpsc::Sender<TransportCommand>,
    pub(super) connected_transport_peers: AtomicUsize,
    pub(super) req_frames_received: AtomicU64,
    pub(super) close_frames_received: AtomicU64,
    pub(super) event_frames_received: AtomicU64,
    pub(super) inv_frames_received: AtomicU64,
    pub(super) want_frames_received: AtomicU64,
    pub(super) want_frames_sent: AtomicU64,
    pub(super) subscription_events_received: AtomicU64,
    pub(super) expired_wants: AtomicU64,
    pub(super) provider_cooldowns: AtomicU64,
    pub(super) tcp_receive_batches: AtomicU64,
    pub(super) tcp_datagrams_received: AtomicU64,
    pub(super) tcp_datagrams_rejected: AtomicU64,
    pub(super) tcp_poll_turns: AtomicU64,
    pub(super) transport_errors: AtomicU64,
    pub(super) reputation_errors: AtomicU64,
    pub(super) next_subscription_id: AtomicU64,
    pub(super) subscriptions: Mutex<HashMap<String, ActiveSubscription>>,
    pub(super) peer_subscriptions: Mutex<PubsubPeerSubscriptionStore>,
    pub(super) recent_events: Mutex<RecentEvents>,
    pub(super) observed_inventories: Mutex<ScopedSeenIds>,
    pub(super) observed_full_events: Mutex<ScopedSeenIds>,
    pub(super) provider_behavior: Mutex<ProviderBehavior>,
    pub(super) pending_wants: Mutex<PendingWants>,
}

impl ClientInner {
    pub(super) fn admit(&self) -> Result<std::sync::MutexGuard<'_, bool>> {
        let open = self
            .admission
            .lock()
            .map_err(|_| poisoned("FIPS admission"))?;
        if !*open {
            return Err(PubsubError::Storage(
                "FIPS pubsub client is shut down".into(),
            ));
        }
        Ok(open)
    }

    pub(super) async fn connected_peers(&self) -> Result<Vec<ConnectedPeer>> {
        self.connected_peer_links()
            .await?
            .into_iter()
            .map(|peer| {
                let identity = PeerIdentity::from_npub(&peer.npub).map_err(|error| {
                    PubsubError::Validation(format!(
                        "invalid authenticated FIPS peer {}: {error}",
                        peer.npub
                    ))
                })?;
                Ok(ConnectedPeer {
                    npub: peer.npub,
                    identity,
                })
            })
            .collect()
    }

    pub(super) async fn subscribe(
        self: &Arc<Self>,
        mut filters: Vec<Filter>,
    ) -> Result<FipsPubsubSubscription> {
        drop(self.admit()?);
        if filters.is_empty() {
            filters.push(Filter::new());
        }
        if filters.len() > self.options.max_filters_per_subscription {
            return Err(PubsubError::Validation(format!(
                "FIPS pubsub filter count {} exceeds limit {}",
                filters.len(),
                self.options.max_filters_per_subscription
            )));
        }
        for filter in &mut filters {
            filter.limit = Some(
                filter
                    .limit
                    .unwrap_or(self.options.max_replay_events)
                    .min(self.options.max_replay_events),
            );
        }

        let peers = self.connected_peers().await?;
        let _admission = self.admit()?;
        let had_peers = !peers.is_empty();
        let sequence = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let subscription_id = SubscriptionId::new(format!("fips-{sequence}"));
        let key = subscription_id.to_string();
        let frame = self.codec.encode_frame(&FipsPubsubWireMessage::req(
            subscription_id.clone(),
            filters.clone(),
        ))?;
        let (sender, receiver) = mpsc::channel(self.options.max_replay_events);
        let subscribed_peers = peers
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        {
            let mut subscriptions = self.lock_subscriptions()?;
            let subscription_capacity = self.options.max_active_subscriptions.saturating_add(1);
            if subscriptions.len() >= subscription_capacity {
                return Err(PubsubError::Storage(format!(
                    "application FIPS pubsub subscription limit is {}",
                    self.options.max_active_subscriptions
                )));
            }
            subscriptions.insert(
                key.clone(),
                ActiveSubscription {
                    filters,
                    peers: subscribed_peers,
                    recent_event_ids: HashSet::new(),
                    recent_event_order: VecDeque::new(),
                    sender,
                },
            );
        }

        self.replay_local_events(&key)?;

        let mut sent = 0usize;
        let mut last_error = None;
        for peer in peers {
            match self.send_frame(peer.identity, frame.clone()) {
                Ok(()) => sent += 1,
                Err(error) => {
                    last_error = Some(error);
                    if let Some(active) = self.lock_subscriptions()?.get_mut(&key) {
                        active.peers.remove(&peer.npub);
                    }
                }
            }
        }
        if had_peers && sent == 0 {
            self.close_subscription(&key);
            return Err(last_error.unwrap_or_else(|| no_connected_peers(self.peer_transport)));
        }

        Ok(FipsPubsubSubscription {
            subscription_id,
            key,
            receiver,
            inner: Arc::clone(self),
            closed: false,
        })
    }

    pub(super) fn send_frame(&self, peer: PeerIdentity, frame: Vec<u8>) -> Result<()> {
        self.transport_tx
            .try_send(TransportCommand::Send { peer, frame })
            .map_err(|error| storage_error("queue TCP/FIPS Nostr pubsub frame", error))
    }

    pub(super) async fn handle_frame(&self, source_peer: PeerIdentity, frame: &[u8]) {
        let Ok(message) = self.codec.decode_frame(frame) else {
            self.record_provider_violation(source_peer, ProviderViolation::MalformedFrame);
            return;
        };

        let source_npub = source_peer.npub();
        let source_id = SourceId::new(source_npub.clone());
        match message {
            FipsPubsubWireMessage::Req {
                subscription_id,
                filters,
            } => {
                self.req_frames_received.fetch_add(1, Ordering::Relaxed);
                self.handle_req(source_peer, source_id, &subscription_id, &filters);
            }
            FipsPubsubWireMessage::Close { subscription_id } => {
                self.close_frames_received.fetch_add(1, Ordering::Relaxed);
                self.handle_close(&source_id, &subscription_id);
            }
            FipsPubsubWireMessage::Event {
                subscription_id,
                event,
            } => {
                self.event_frames_received.fetch_add(1, Ordering::Relaxed);
                let subscription_key = subscription_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let event_id = event.as_event().id.to_string();
                let first_observation = self
                    .observed_full_events
                    .lock()
                    .is_ok_and(|mut seen| seen.observe(&source_npub, &subscription_key, &event_id));
                let is_subscribed =
                    self.event_matches_subscription(&source_npub, subscription_id.as_ref(), &event);
                if !is_subscribed {
                    self.record_provider_violation(
                        source_peer,
                        ProviderViolation::OutOfFilterEvent {
                            repeated: !first_observation,
                        },
                    );
                    return;
                }
                if !first_observation {
                    return;
                }
                let source = EventSource::fips_endpoint(&source_npub);
                if !self.event_is_admitted(&event, &source).await {
                    return;
                }
                self.handle_event(&source_npub, &source_id, subscription_id.as_ref(), &event);
            }
            FipsPubsubWireMessage::Inv {
                subscription_ids,
                event_id,
                event_kind,
                payload_bytes,
                hop_limit,
            } => self.handle_inv(
                source_peer,
                &source_npub,
                InventoryAdvertisement {
                    subscription_ids,
                    event_id,
                    event_kind,
                    payload_bytes,
                    hop_limit,
                },
            ),
            FipsPubsubWireMessage::Want { event_id } => {
                self.want_frames_received.fetch_add(1, Ordering::Relaxed);
                self.handle_want(source_peer, &source_id, &event_id);
            }
        }
    }

    pub(super) fn handle_req(
        &self,
        source_peer: PeerIdentity,
        source_id: SourceId,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
    ) {
        if self
            .remember_peer_subscription(source_id, subscription_id, filters.to_vec())
            .is_err()
        {
            return;
        }
        for cached in self.recent_matching_events(filters).unwrap_or_default() {
            let Ok(frame) = self.inventory_frame(
                vec![subscription_id.clone()],
                &cached.event,
                cached.hop_limit,
            ) else {
                continue;
            };
            let _ = self.send_frame(source_peer, frame);
        }
    }

    pub(super) fn handle_close(&self, source_id: &SourceId, subscription_id: &SubscriptionId) {
        if let Ok(mut subscriptions) = self.peer_subscriptions.lock() {
            subscriptions.remove(source_id, &subscription_id.to_string());
        }
    }

    pub(super) fn handle_event(
        &self,
        source_npub: &str,
        source_id: &SourceId,
        subscription_id: Option<&SubscriptionId>,
        event: &VerifiedEvent,
    ) {
        let hop_limit = match subscription_id {
            Some(subscription_id) => Some(
                self.complete_want(source_npub, subscription_id, event)
                    .unwrap_or(None)
                    .unwrap_or(0),
            ),
            None => Some(self.options.max_hops),
        };
        let Some(hop_limit) = hop_limit else {
            return;
        };
        if subscription_id.is_some() {
            self.subscription_events_received
                .fetch_add(1, Ordering::Relaxed);
        }
        if !self.deliver_local_event(source_npub, event) {
            return;
        }
        let source = EventSource::fips_endpoint(source_npub);
        if self
            .remember_event(event.clone(), source, hop_limit)
            .unwrap_or(false)
            && hop_limit > 0
        {
            let targets = self
                .peer_delivery_targets(event, Some(source_id))
                .unwrap_or_default();
            let _ = self.send_inventories(targets, event, hop_limit);
        }
    }

    pub(super) fn handle_inv(
        &self,
        source_peer: PeerIdentity,
        source_npub: &str,
        inventory: InventoryAdvertisement,
    ) {
        self.inv_frames_received.fetch_add(1, Ordering::Relaxed);
        let Ok(Some(frame)) = self.accept_inventory(source_npub, inventory) else {
            return;
        };
        if self.send_frame(source_peer, frame).is_ok() {
            self.want_frames_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn handle_want(
        &self,
        source_peer: PeerIdentity,
        source_id: &SourceId,
        event_id: &EventId,
    ) {
        let Ok(Some((subscription_id, event))) = self.event_for_want(source_id, event_id) else {
            return;
        };
        let Ok(frame) = self
            .codec
            .encode_frame(&FipsPubsubWireMessage::deliver(subscription_id, event))
        else {
            return;
        };
        let _ = self.send_frame(source_peer, frame);
    }

    pub(super) fn remember_peer_subscription(
        &self,
        peer_id: SourceId,
        subscription_id: &SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<()> {
        self.peer_subscriptions
            .lock()
            .map_err(|_| poisoned("FIPS peer subscription state"))?
            .upsert_filters(peer_id, subscription_id.to_string(), filters)?;
        Ok(())
    }

    pub(super) fn deliver_local_event(&self, source_npub: &str, event: &VerifiedEvent) -> bool {
        let event_id = event.as_event().id.to_string();
        let Ok(mut subscriptions) = self.subscriptions.lock() else {
            return false;
        };
        let mut delivered = false;
        for active in subscriptions.values_mut() {
            if !active.peers.contains(source_npub)
                || PubsubPeerInterest::from_filters(&active.filters, event)
                    != PubsubPeerInterest::Subscribed
                || active.recent_event_ids.contains(&event_id)
            {
                continue;
            }
            deliver_local(
                active,
                event.clone(),
                EventSource::fips_endpoint(source_npub),
                &event_id,
                FIPS_NOSTR_PUBSUB_MAX_SEEN_EVENT_IDS,
            );
            delivered = true;
        }
        delivered
    }

    fn event_matches_subscription(
        &self,
        source_npub: &str,
        subscription_id: Option<&SubscriptionId>,
        event: &VerifiedEvent,
    ) -> bool {
        let Ok(subscriptions) = self.subscriptions.lock() else {
            return false;
        };
        match subscription_id {
            Some(subscription_id) => {
                subscriptions
                    .get(&subscription_id.to_string())
                    .is_some_and(|active| {
                        active.peers.contains(source_npub)
                            && PubsubPeerInterest::from_filters(&active.filters, event)
                                == PubsubPeerInterest::Subscribed
                    })
            }
            None => subscriptions.values().any(|active| {
                active.peers.contains(source_npub)
                    && PubsubPeerInterest::from_filters(&active.filters, event)
                        == PubsubPeerInterest::Subscribed
            }),
        }
    }

    pub(super) fn remember_event(
        &self,
        event: VerifiedEvent,
        source: EventSource,
        hop_limit: u8,
    ) -> Result<bool> {
        self.recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))
            .map(|mut events| events.insert(event, source, hop_limit))
    }

    pub(super) async fn publish(
        &self,
        event: VerifiedEvent,
        source: EventSource,
    ) -> Result<PublishReport> {
        drop(self.admit()?);
        let decision = self.event_decision(&event, &source).await?;
        drop(self.admit()?);
        let (accepted, priority, reason) = decision_report(&decision);
        if !accepted {
            return Ok(PublishReport {
                accepted,
                priority,
                reason,
            });
        }

        let peers = self.connected_peers().await?;
        let subscribed = self.peer_delivery_targets(&event, None)?;
        let _admission = self.admit()?;
        let is_new = self
            .recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))?
            .insert_for_publish(event.clone(), source, self.options.max_hops);
        if !is_new {
            return Ok(PublishReport {
                accepted: true,
                priority,
                reason: Some("event was already published".to_string()),
            });
        }

        if !subscribed.is_empty() {
            let peer_count = subscribed.len();
            let sent = self.send_inventories(subscribed, &event, self.options.max_hops);
            let mut report = publish_report(sent, peer_count, "subscribed FIPS peers")?;
            report.priority = priority;
            if report.reason.is_none() {
                report.reason = reason;
            }
            return Ok(report);
        }

        Ok(PublishReport {
            accepted: true,
            priority,
            reason: Some(format!(
                "cached for live subscriptions from {} connected FIPS peers",
                peers.len()
            )),
        })
    }

    async fn event_is_admitted(&self, event: &VerifiedEvent, source: &EventSource) -> bool {
        self.event_decision(event, source)
            .await
            .is_ok_and(|decision| !matches!(decision, PolicyDecision::Drop { .. }))
    }

    async fn event_decision(
        &self,
        event: &VerifiedEvent,
        source: &EventSource,
    ) -> Result<PolicyDecision> {
        match &self.event_policy {
            Some(policy) => {
                policy
                    .check_event(EventPolicyContext { event, source })
                    .await
            }
            None => Ok(PolicyDecision::allow_with_priority(
                SOURCE_PRIORITY_FIPS_ENDPOINT,
            )),
        }
    }

    pub(super) fn recent_matching_events(&self, filters: &[Filter]) -> Result<Vec<CachedEvent>> {
        self.recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))
            .map(|events| events.matching(filters))
    }

    pub(super) fn replay_local_events(&self, key: &str) -> Result<()> {
        let recent = self
            .recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))?
            .entries
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut subscriptions = self.lock_subscriptions()?;
        let Some(active) = subscriptions.get_mut(key) else {
            return Ok(());
        };
        for cached in recent {
            if PubsubPeerInterest::from_filters(&active.filters, &cached.event)
                != PubsubPeerInterest::Subscribed
            {
                continue;
            }
            let event_id = cached.event.as_event().id.to_string();
            deliver_local(
                active,
                cached.event,
                cached.source,
                &event_id,
                self.options.max_replay_events,
            );
        }
        Ok(())
    }

    pub(super) fn peer_delivery_targets(
        &self,
        event: &VerifiedEvent,
        excluded_peer: Option<&SourceId>,
    ) -> Result<Vec<(String, Vec<SubscriptionId>)>> {
        let subscriptions = self
            .peer_subscriptions
            .lock()
            .map_err(|_| poisoned("FIPS peer subscription state"))?;
        let mut targets: Vec<(String, Vec<SubscriptionId>)> = Vec::new();
        for (peer, subscription) in subscriptions.matching_peer_subscriptions(event) {
            if excluded_peer == Some(peer) {
                continue;
            }
            let peer_npub = peer.as_str();
            if let Some((last_peer, subscription_ids)) = targets.last_mut()
                && last_peer == peer_npub
            {
                subscription_ids.push(SubscriptionId::new(subscription.subscription_id.clone()));
            } else {
                targets.push((
                    peer_npub.to_string(),
                    vec![SubscriptionId::new(subscription.subscription_id.clone())],
                ));
            }
        }
        drop(subscriptions);
        if let Some(policy) = self.peer_policy.as_deref() {
            let selected = crate::client_peers::select_policy_peers(
                policy,
                targets.iter().map(|(id, _)| id.clone()),
                self.options.fanout,
                self.unknown_peer_reserve,
            )?;
            let mut by_identity = targets.into_iter().collect::<HashMap<_, _>>();
            return Ok(selected
                .into_iter()
                .filter_map(|id| {
                    by_identity
                        .remove(&id)
                        .map(|subscriptions| (id, subscriptions))
                })
                .collect());
        }
        Ok(bounded_delivery_targets(
            targets,
            &event.as_event().id,
            self.options.fanout,
        ))
    }

    pub(super) fn send_inventories(
        &self,
        targets: Vec<(String, Vec<SubscriptionId>)>,
        event: &VerifiedEvent,
        hop_limit: u8,
    ) -> usize {
        if hop_limit == 0 {
            return 0;
        }
        let mut sent = 0;
        for (npub, subscription_ids) in targets {
            let Ok(peer) = PeerIdentity::from_npub(&npub) else {
                continue;
            };
            let Ok(frame) = self.inventory_frame(subscription_ids, event, hop_limit) else {
                continue;
            };
            if self.send_frame(peer, frame).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub(super) fn inventory_frame(
        &self,
        subscription_ids: Vec<SubscriptionId>,
        event: &VerifiedEvent,
        hop_limit: u8,
    ) -> Result<Vec<u8>> {
        let payload_bytes = event_payload_bytes(event)?;
        self.codec.encode_frame(&FipsPubsubWireMessage::inv(
            subscription_ids,
            event.as_event().id,
            event.as_event().kind.as_u16(),
            payload_bytes,
            hop_limit,
        ))
    }

    pub(super) fn accept_inventory(
        &self,
        source_npub: &str,
        inventory: InventoryAdvertisement,
    ) -> Result<Option<Vec<u8>>> {
        let InventoryAdvertisement {
            subscription_ids,
            event_id,
            event_kind,
            payload_bytes,
            hop_limit,
        } = inventory;
        if subscription_ids.len() > self.options.max_active_subscriptions.saturating_add(1) {
            return Ok(None);
        }
        let event_id_hex = event_id.to_hex();
        if self
            .recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))?
            .contains(&event_id_hex)
        {
            return Ok(None);
        }
        let subscriptions = self.lock_subscriptions()?;
        let candidate_subscription_ids = subscription_ids
            .into_iter()
            .filter(|subscription_id| {
                subscriptions
                    .get(&subscription_id.to_string())
                    .is_some_and(|active| {
                        active.peers.contains(source_npub)
                            && !active.recent_event_ids.contains(&event_id_hex)
                    })
            })
            .map(|subscription_id| subscription_id.to_string())
            .collect::<Vec<_>>();
        drop(subscriptions);
        let mut observed = self
            .observed_inventories
            .lock()
            .map_err(|_| poisoned("FIPS observed inventory IDs"))?;
        let valid_subscription_ids = candidate_subscription_ids
            .into_iter()
            .filter(|subscription_id| observed.observe(source_npub, subscription_id, &event_id_hex))
            .collect::<Vec<_>>();
        if valid_subscription_ids.is_empty() {
            return Ok(None);
        }
        drop(observed);

        let provider = InventoryProvider {
            peer_npub: source_npub.to_string(),
            subscription_ids: valid_subscription_ids,
        };
        let inventory = PendingInventory {
            selected: provider,
            alternatives: VecDeque::new(),
            event_kind,
            payload_bytes,
            hop_limit,
            requested_at_ms: now_ms(),
            retry_count: 0,
        };
        let should_request = self
            .pending_wants
            .lock()
            .map_err(|_| poisoned("FIPS pending WANT state"))?
            .insert(event_id_hex, inventory);
        if !should_request {
            return Ok(None);
        }
        self.codec
            .encode_frame(&FipsPubsubWireMessage::want(event_id))
            .map(Some)
    }

    pub(super) fn complete_want(
        &self,
        source_npub: &str,
        subscription_id: &SubscriptionId,
        event: &VerifiedEvent,
    ) -> Result<Option<u8>> {
        let event_id = event.as_event().id.to_string();
        let payload_bytes = event_payload_bytes(event)?;
        let subscription_key = subscription_id.to_string();
        let subscriptions = self.lock_subscriptions()?;
        let Some(active) = subscriptions.get(&subscription_key) else {
            return Ok(None);
        };
        if !active.peers.contains(source_npub)
            || PubsubPeerInterest::from_filters(&active.filters, event)
                != PubsubPeerInterest::Subscribed
        {
            return Ok(None);
        }
        drop(subscriptions);
        let pending = self
            .pending_wants
            .lock()
            .map_err(|_| poisoned("FIPS pending WANT state"))?
            .take_matching(
                &event_id,
                source_npub,
                &subscription_key,
                event.as_event().kind.as_u16(),
                payload_bytes,
            );
        let Some(pending) = pending else {
            return Ok(None);
        };
        Ok(Some(pending.hop_limit.saturating_sub(1)))
    }

    pub(super) fn retry_pending_frames(&self, now_ms: u64) -> Vec<(PeerIdentity, Vec<u8>)> {
        let retry_after_ms = self
            .options
            .query_timeout
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let due = self
            .pending_wants
            .lock()
            .map(|mut pending| pending.retry_due(now_ms, retry_after_ms))
            .unwrap_or_default();
        self.expired_wants
            .fetch_add(due.expired_event_count as u64, Ordering::Relaxed);
        for provider in due.expired_providers {
            if let Ok(peer) = PeerIdentity::from_npub(&provider.peer_npub) {
                self.record_provider_violation(peer, ProviderViolation::UnansweredInventory);
            }
        }
        due.retries
            .into_iter()
            .filter_map(|(event_id, provider)| {
                let peer = PeerIdentity::from_npub(&provider.peer_npub).ok()?;
                let event_id = EventId::from_hex(&event_id).ok()?;
                let frame = self
                    .codec
                    .encode_frame(&FipsPubsubWireMessage::want(event_id))
                    .ok()?;
                Some((peer, frame))
            })
            .collect()
    }

    pub(super) fn event_for_want(
        &self,
        source_id: &SourceId,
        event_id: &EventId,
    ) -> Result<Option<(SubscriptionId, VerifiedEvent)>> {
        let events = self
            .recent_events
            .lock()
            .map_err(|_| poisoned("FIPS recent event cache"))?;
        let Some(event) = events.event(&event_id.to_hex()).cloned() else {
            return Ok(None);
        };
        drop(events);
        let subscriptions = self
            .peer_subscriptions
            .lock()
            .map_err(|_| poisoned("FIPS peer subscription state"))?;
        let Some(subscription) = subscriptions
            .matching_subscriptions(source_id, &event)
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        Ok(Some((
            SubscriptionId::new(subscription.subscription_id.clone()),
            event,
        )))
    }

    pub(super) fn close_subscription(&self, key: &str) {
        let active = self
            .subscriptions
            .lock()
            .ok()
            .and_then(|mut subscriptions| subscriptions.remove(key));
        let Some(active) = active else {
            return;
        };
        if let Ok(mut pending) = self.pending_wants.lock() {
            pending.remove_subscription(key);
        }
        if let Ok(mut observed) = self.observed_inventories.lock() {
            observed.clear_subscription(key);
        }
        if let Ok(mut observed) = self.observed_full_events.lock() {
            observed.clear_subscription(key);
        }
        self.send_close(key, active.peers);
    }

    pub(super) fn close_all(&self) {
        if let Ok(mut open) = self.admission.lock() {
            *open = false;
        }
        let active = self
            .subscriptions
            .lock()
            .map(|mut subscriptions| subscriptions.drain().collect::<Vec<_>>())
            .unwrap_or_default();
        for (key, subscription) in active {
            self.send_close(&key, subscription.peers);
        }
        if let Ok(mut pending) = self.pending_wants.lock() {
            pending.clear();
        }
    }

    pub(super) fn send_close(&self, key: &str, peers: HashSet<String>) {
        let Ok(frame) =
            self.codec
                .encode_frame(&FipsPubsubWireMessage::close(SubscriptionId::new(
                    key.to_string(),
                )))
        else {
            return;
        };
        for npub in peers {
            let Ok(peer) = PeerIdentity::from_npub(&npub) else {
                continue;
            };
            let _ = self.transport_tx.try_send(TransportCommand::Send {
                peer,
                frame: frame.clone(),
            });
        }
    }

    pub(super) fn lock_subscriptions(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, ActiveSubscription>>> {
        self.subscriptions.lock().map_err(|_| {
            PubsubError::Storage("FIPS pubsub subscription state poisoned".to_string())
        })
    }

    pub(super) fn replay_frames_for_peer(&self, peer_npub: &str) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        if let Ok(mut subscriptions) = self.subscriptions.lock() {
            for (key, active) in subscriptions.iter_mut() {
                active.peers.insert(peer_npub.to_string());
                if let Ok(frame) = self.codec.encode_frame(&FipsPubsubWireMessage::req(
                    SubscriptionId::new(key.clone()),
                    active.filters.clone(),
                )) {
                    frames.push(frame);
                }
            }
        }
        frames
    }

    pub(super) fn reset_peer_epoch(&self, peer_npub: &str) {
        if let Ok(mut observed) = self.observed_inventories.lock() {
            observed.clear_peer(peer_npub);
        }
        if let Ok(mut observed) = self.observed_full_events.lock() {
            observed.clear_peer(peer_npub);
        }
        if let Ok(mut pending) = self.pending_wants.lock() {
            pending.remove_peer(peer_npub);
        }
    }

    pub(super) fn peer_is_in_cooldown(&self, peer_npub: &str, now_ms: u64) -> bool {
        self.provider_behavior
            .lock()
            .is_ok_and(|mut behavior| behavior.is_in_cooldown(peer_npub, now_ms))
    }

    fn record_provider_violation(&self, peer: PeerIdentity, violation: ProviderViolation) {
        let peer_npub = peer.npub();
        let cooldown = self
            .provider_behavior
            .lock()
            .ok()
            .and_then(|mut behavior| behavior.record(&peer_npub, violation, now_ms()));
        if cooldown.is_some()
            && self
                .transport_tx
                .try_send(TransportCommand::Cooldown { peer })
                .is_ok()
        {
            self.provider_cooldowns.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn decision_report(decision: &PolicyDecision) -> (bool, i32, Option<String>) {
    match decision {
        PolicyDecision::Allow { priority } => (true, *priority, None),
        PolicyDecision::Throttle { priority, reason } => (true, *priority, Some(reason.clone())),
        PolicyDecision::Drop { reason } => (false, 0, Some(reason.clone())),
    }
}

pub(super) struct ConnectedPeer {
    pub(super) npub: String,
    pub(super) identity: PeerIdentity,
}

pub(super) struct ConnectedPeerLink {
    pub(super) npub: String,
    pub(super) link_id: u64,
}

pub(super) struct ActiveSubscription {
    pub(super) filters: Vec<Filter>,
    pub(super) peers: HashSet<String>,
    pub(super) recent_event_ids: HashSet<String>,
    pub(super) recent_event_order: VecDeque<String>,
    pub(super) sender: mpsc::Sender<QueryEvent>,
}

pub(super) struct InventoryAdvertisement {
    pub(super) subscription_ids: Vec<SubscriptionId>,
    pub(super) event_id: EventId,
    pub(super) event_kind: u16,
    pub(super) payload_bytes: u32,
    pub(super) hop_limit: u8,
}
