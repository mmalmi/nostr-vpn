use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use fips_core::FipsEndpoint;
use nostr_pubsub::{
    EventBus, EventSource, MatchEventOptions, MeshPeerPolicy, NostrEventSubscriber,
    NostrEventSubscription, NostrPubsubRouter, PolicyDecision, QueryEvent, RouterPublishSource,
    SourceRoute, VerifiedEvent,
};
use nostr_pubsub_fips::{
    FipsPubsubClient, FipsPubsubClientOptions, FipsPubsubPolicy, FipsPubsubPolicyOptions,
    FipsPubsubSubscription,
};
use nostr_pubsub_relay::RelayEventBus;
use nostr_pubsub_social_graph::{PEER_RATING_MAX_AGE, PEER_RATING_MAX_FUTURE_SKEW};
#[cfg(test)]
use nostr_sdk::prelude::Keys;
use nostr_sdk::prelude::{Client, Event, Filter, Kind, PublicKey};
use nostr_social_memory::rating_from_event;
use nostr_vpn_core::config::{NostrPubsubConfig, NostrPubsubMode};
use nostr_vpn_core::control_pubsub::{
    CONTROL_PUBSUB_MAX_EVENT_BYTES, CONTROL_PUBSUB_MAX_WIRE_BYTES, FIPS_PEER_ADVERT_KIND,
    PAID_EXIT_OFFER_KIND, RATING_FACT_KIND,
};
use nostr_vpn_core::paid_routes::{PAID_ROUTE_OFFER_TTL_SECS, SignedPaidRouteOffer};
use nostr_vpn_core::updater::{UpdateEventCache, configured_update_ref};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

const STORE_VERSION: u8 = 1;
const STORE_MAX_EVENTS: usize = 1_024;
const COMMAND_CAPACITY: usize = 64;
const MAX_PUBSUB_PEERS: usize = 64;
const MAINTENANCE_TICK_INTERVAL: Duration = Duration::from_secs(1);
const OUTBOX_POLL_INTERVAL: Duration = Duration::from_secs(1);
const OUTBOX_BATCH: usize = 8;
const RELAY_REPLAY_LIMIT: usize = 32;
const FIPS_REPLAY_LIMIT: usize = 32;
const RELAY_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const FIPS_ADVERT_REFRESH_INTERVAL: Duration = Duration::from_mins(30);

struct PublishRequest {
    event: Box<Event>,
    response: oneshot::Sender<Result<bool>>,
}

enum RuntimeCommand {
    Publish(PublishRequest),
    ConnectedPeerCount(oneshot::Sender<Result<usize>>),
    PeerSubscriptionCount(oneshot::Sender<Result<usize>>),
}

include!("control_pubsub_runtime/event_store.rs");

pub struct ControlPubsubFipsRuntime {
    command_tx: mpsc::Sender<RuntimeCommand>,
    events: Arc<Mutex<ControlEventStore>>,
    relay_client: Option<Client>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ControlPubsubFipsRuntime {
    pub async fn start(
        endpoint: Arc<FipsEndpoint>,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        Self::start_for_peers(endpoint, config, relays, store_path, &[]).await
    }

    pub async fn start_for_peers(
        endpoint: Arc<FipsEndpoint>,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        target_peer_npubs: &[String],
    ) -> Result<Option<Self>> {
        if config.mode == NostrPubsubMode::Off {
            return Ok(None);
        }
        Self::start_inner(
            endpoint,
            config,
            relays,
            store_path,
            None,
            None,
            target_peer_npubs,
        )
        .await
    }

    pub async fn start_with_peer_policy(
        endpoint: Arc<FipsEndpoint>,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        peer_policy: Arc<dyn MeshPeerPolicy>,
    ) -> Result<Option<Self>> {
        Self::start_inner(
            endpoint,
            config,
            relays,
            store_path,
            Some(peer_policy),
            None,
            &[],
        )
        .await
    }

    async fn start_inner(
        endpoint: Arc<FipsEndpoint>,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        peer_policy: Option<Arc<dyn MeshPeerPolicy>>,
        update_events_override: Option<UpdateEventCache>,
        target_peer_npubs: &[String],
    ) -> Result<Option<Self>> {
        if config.mode == NostrPubsubMode::Off {
            return Ok(None);
        }
        let update_events = match update_events_override {
            Some(update_events) => update_events,
            None => configured_update_events()?,
        };
        let target_advert_authors = target_peer_npubs
            .iter()
            .filter_map(|peer| PublicKey::parse(peer).ok())
            .collect::<Vec<_>>();
        let outbox_path = store_path
            .as_deref()
            .map(control_pubsub_outbox_directory_from_store_path);
        let graph_root = PublicKey::parse(endpoint.npub())?;
        let event_store =
            ControlEventStore::load_for_owner(store_path, update_events.clone(), Some(graph_root))?;
        let stored_events = event_store.snapshot();
        let pubsub_policy = FipsPubsubPolicy::new(
            Arc::clone(&endpoint),
            stored_events.iter(),
            FipsPubsubPolicyOptions::default(),
        )?;
        let event_policy = pubsub_policy.event_policy();
        let peer_policy = peer_policy.unwrap_or_else(|| pubsub_policy.peer_policy());
        let pubsub_policy = Arc::new(Mutex::new(pubsub_policy));

        let max_event_bytes = config.max_event_bytes.min(CONTROL_PUBSUB_MAX_EVENT_BYTES);
        let fips_pubsub = Arc::new(
            FipsPubsubClient::start_with_policy(
                Arc::clone(&endpoint),
                fips_pubsub_options(max_event_bytes, config.max_hops),
                Arc::clone(&event_policy),
            )
            .await
            .context("failed to bind standard FIPS Nostr pubsub service")?,
        );
        let relay = RelayProvider::start(
            config.mode,
            relays,
            &update_events,
            &target_advert_authors,
            graph_root,
        )
        .await?;
        let relay_client = relay.as_ref().map(|provider| provider.bus.client().clone());
        let mut pubsub =
            NostrPubsubRouter::new(event_policy).with_publish_source(RouterPublishSource::new(
                SourceRoute::fips_peer_default(endpoint.npub().to_string()),
                Arc::clone(&fips_pubsub),
            ));
        if let Some(provider) = relay.as_ref() {
            pubsub = pubsub.with_publish_source(RouterPublishSource::new(
                SourceRoute::relay(provider.bus.relays().join(",")),
                Arc::clone(&provider.bus),
            ));
        }

        let events = Arc::new(Mutex::new(event_store));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task_events = Arc::clone(&events);
        let task = tokio::spawn(async move {
            run(
                PubsubRunState {
                    endpoint,
                    fips_pubsub,
                    pubsub,
                    relay,
                    events: task_events,
                    peer_policy,
                    pubsub_policy,
                    update_events,
                },
                outbox_path,
                command_rx,
                shutdown_rx,
            )
            .await;
        });
        Ok(Some(Self {
            command_tx,
            events,
            relay_client,
            shutdown: Some(shutdown_tx),
            task,
        }))
    }

    pub async fn events(&self) -> Vec<Event> {
        self.events.lock().await.snapshot()
    }

    pub async fn publish(&self, event: Event) -> Result<bool> {
        let (response, result) = oneshot::channel();
        self.command_tx
            .send(RuntimeCommand::Publish(PublishRequest {
                event: Box::new(event),
                response,
            }))
            .await
            .context("control pubsub runtime stopped before publish")?;
        result
            .await
            .context("control pubsub runtime stopped while publishing")?
    }

    pub async fn connected_peer_count(&self) -> Result<usize> {
        let (response, result) = oneshot::channel();
        self.command_tx
            .send(RuntimeCommand::ConnectedPeerCount(response))
            .await
            .context("control pubsub runtime stopped before peer query")?;
        result
            .await
            .context("control pubsub runtime stopped during peer query")?
    }

    pub async fn peer_subscription_count(&self) -> Result<usize> {
        let (response, result) = oneshot::channel();
        self.command_tx
            .send(RuntimeCommand::PeerSubscriptionCount(response))
            .await
            .context("control pubsub runtime stopped before subscription query")?;
        result
            .await
            .context("control pubsub runtime stopped during subscription query")?
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
        if let Some(client) = self.relay_client.take() {
            client.shutdown().await;
        }
    }
}

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

impl Drop for ControlPubsubFipsRuntime {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

struct RelayProvider {
    bus: Arc<RelayEventBus>,
    notifications: mpsc::Receiver<QueryEvent>,
    _subscription: Box<dyn NostrEventSubscription>,
}

impl RelayProvider {
    async fn start(
        mode: NostrPubsubMode,
        relays: Vec<String>,
        update_events: &UpdateEventCache,
        target_advert_authors: &[PublicKey],
        graph_root: PublicKey,
    ) -> Result<Option<Self>> {
        if mode != NostrPubsubMode::Relay || relays.is_empty() {
            return Ok(None);
        }
        let bus = Arc::new(
            RelayEventBus::new(relays, RELAY_QUERY_TIMEOUT)
                .await
                .context("failed to start configured Nostr pubsub relay provider")?,
        );
        let (notification_tx, notifications) = mpsc::channel(RELAY_REPLAY_LIMIT * 5);
        let subscription = NostrEventSubscriber::subscribe(
            bus.as_ref(),
            {
                let mut filters = relay_subscription_filters(update_events, target_advert_authors);
                filters.push(exit_graph_filter(graph_root));
                filters
            },
            Arc::new(move |event| {
                if notification_tx.try_send(event).is_err() {
                    tracing::warn!("dropping control pubsub relay event because the bounded ingress queue is full");
                }
            }),
        )
        .await
        .context("failed to subscribe through configured Nostr pubsub relay provider")?;
        Ok(Some(Self {
            bus,
            notifications,
            _subscription: subscription,
        }))
    }
}

struct PubsubRunState {
    endpoint: Arc<FipsEndpoint>,
    fips_pubsub: Arc<FipsPubsubClient>,
    pubsub: NostrPubsubRouter,
    relay: Option<RelayProvider>,
    events: Arc<Mutex<ControlEventStore>>,
    peer_policy: Arc<dyn MeshPeerPolicy>,
    pubsub_policy: Arc<Mutex<FipsPubsubPolicy>>,
    update_events: UpdateEventCache,
}

#[derive(Default)]
struct FipsSubscriptionState {
    subscription: Option<FipsPubsubSubscription>,
}

#[derive(Clone, Copy)]
struct PublishContext<'a> {
    endpoint: &'a FipsEndpoint,
    pubsub: &'a NostrPubsubRouter,
    events: &'a Arc<Mutex<ControlEventStore>>,
    pubsub_policy: &'a Arc<Mutex<FipsPubsubPolicy>>,
    update_events: &'a UpdateEventCache,
}

async fn run(
    state: PubsubRunState,
    outbox_path: Option<PathBuf>,
    mut command_rx: mpsc::Receiver<RuntimeCommand>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let PubsubRunState {
        endpoint,
        fips_pubsub,
        pubsub,
        mut relay,
        events,
        peer_policy,
        pubsub_policy,
        update_events,
    } = state;
    let mut maintenance_tick = tokio::time::interval(MAINTENANCE_TICK_INTERVAL);
    maintenance_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut outbox_tick = tokio::time::interval(OUTBOX_POLL_INTERVAL);
    outbox_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let advert_refresh = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(advert_refresh);
    let mut fips_subscription = FipsSubscriptionState::default();
    sync_fips_subscription(
        &endpoint,
        &fips_pubsub,
        peer_policy.as_ref(),
        &events,
        &update_events,
        &mut fips_subscription,
    )
    .await;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            command = command_rx.recv() => {
                let Some(command) = command else { break; };
                match command {
                    RuntimeCommand::Publish(PublishRequest { event, response }) => {
                        let result = publish_local(
                            PublishContext {
                                endpoint: &endpoint,
                                pubsub: &pubsub,
                                events: &events,
                                pubsub_policy: &pubsub_policy,
                                update_events: &update_events,
                            },
                            *event,
                        )
                        .await;
                        let _ = response.send(result);
                    }
                    RuntimeCommand::ConnectedPeerCount(response) => {
                        let _ = response.send(
                            fips_pubsub
                                .connected_peer_count()
                                .map_err(anyhow::Error::from),
                        );
                    }
                    RuntimeCommand::PeerSubscriptionCount(response) => {
                        let _ = response.send(
                            fips_pubsub
                                .peer_subscription_count()
                                .map_err(anyhow::Error::from),
                        );
                    }
                }
            }
            _ = outbox_tick.tick(), if outbox_path.is_some() => {
                publish_outbox_batch(
                    PublishContext {
                        endpoint: &endpoint,
                        pubsub: &pubsub,
                        events: &events,
                        pubsub_policy: &pubsub_policy,
                        update_events: &update_events,
                    },
                    outbox_path.as_deref().expect("outbox path is present"),
                )
                .await;
            }
            delivery = fips_notification(&mut fips_subscription.subscription) => {
                let Some(delivery) = delivery else { continue; };
                process_fips_delivery(
                    &endpoint,
                    relay.as_ref().map(|provider| Arc::clone(&provider.bus)),
                    &events,
                    &pubsub_policy,
                    &update_events,
                    delivery,
                )
                .await;
            }
            notification = relay_notification(&mut relay) => {
                let Some(delivery) = notification else { continue; };
                process_relay_delivery(
                    &endpoint,
                    &fips_pubsub,
                    &events,
                    &pubsub_policy,
                    &update_events,
                    delivery,
                )
                .await;
            }
            _ = &mut advert_refresh => {
                let refresh_after = publish_local_fips_advert(&endpoint, &pubsub).await;
                advert_refresh.as_mut().reset(tokio::time::Instant::now() + refresh_after);
            }
            _ = maintenance_tick.tick() => {
                let delivery = fips_pubsub.delivery_snapshot();
                tracing::debug!(
                    req_frames_received = delivery.req_frames_received,
                    close_frames_received = delivery.close_frames_received,
                    event_frames_received = delivery.event_frames_received,
                    inv_frames_received = delivery.inv_frames_received,
                    want_frames_received = delivery.want_frames_received,
                    want_frames_sent = delivery.want_frames_sent,
                    subscription_events_received = delivery.subscription_events_received,
                    expired_wants = delivery.expired_wants,
                    provider_cooldowns = delivery.provider_cooldowns,
                    tcp_receive_batches = delivery.tcp_receive_batches,
                    tcp_datagrams_received = delivery.tcp_datagrams_received,
                    tcp_datagrams_rejected = delivery.tcp_datagrams_rejected,
                    tcp_poll_turns = delivery.tcp_poll_turns,
                    "standard FIPS pubsub delivery snapshot"
                );
                sync_fips_subscription(
                    &endpoint,
                    &fips_pubsub,
                    peer_policy.as_ref(),
                    &events,
                    &update_events,
                    &mut fips_subscription,
                )
                .await;
                publish_policy_maintenance(
                    PublishContext {
                        endpoint: &endpoint,
                        pubsub: &pubsub,
                        events: &events,
                        pubsub_policy: &pubsub_policy,
                        update_events: &update_events,
                    },
                )
                .await;
            }
        }
    }
}

async fn publish_local(context: PublishContext<'_>, event: Event) -> Result<bool> {
    let verified = verify_control_event(event, context.update_events)?;
    publish_verified(context, verified).await
}

fn verify_control_event(event: Event, update_events: &UpdateEventCache) -> Result<VerifiedEvent> {
    validate_control_event_shape(&event, update_events)?;
    VerifiedEvent::try_from(event).map_err(anyhow::Error::from)
}

fn validate_control_event_shape(event: &Event, update_events: &UpdateEventCache) -> Result<()> {
    if !is_control_event(event, update_events) {
        anyhow::bail!("event is outside control pubsub subscriptions");
    }
    let event_bytes = serde_json::to_vec(&event)?;
    if event_bytes.len() > CONTROL_PUBSUB_MAX_EVENT_BYTES {
        anyhow::bail!(
            "control pubsub event is {} bytes, maximum is {}",
            event_bytes.len(),
            CONTROL_PUBSUB_MAX_EVENT_BYTES
        );
    }
    Ok(())
}

async fn publish_verified(context: PublishContext<'_>, verified: VerifiedEvent) -> Result<bool> {
    validate_control_event_shape(verified.as_event(), context.update_events)?;
    let event = verified.as_event().clone();
    let published = match context
        .pubsub
        .publish(
            verified,
            EventSource::local_index(context.endpoint.npub().to_string()),
        )
        .await
    {
        Ok(report) => {
            if let Some(reason) = report.reason.as_deref() {
                tracing::debug!(event_id = %event.id, %reason, "some Nostr pubsub publication routes were unavailable");
            }
            report.accepted
        }
        Err(error) => {
            tracing::debug!(%error, event_id = %event.id, "Nostr pubsub publication deferred");
            false
        }
    };
    tracing::debug!(event_id = %event.id, published, "publishing local control event");
    observe_policy_event(context.pubsub_policy, &event).await;
    context.events.lock().await.insert(event.clone())?;
    ingest_into_fips_discovery(context.endpoint, &event).await;
    Ok(published)
}

async fn publish_local_fips_advert(
    endpoint: &FipsEndpoint,
    pubsub: &NostrPubsubRouter,
) -> Duration {
    let event = match endpoint.local_nostr_discovery_advert_event().await {
        Ok(Some(event)) => event,
        Ok(None) => return MAINTENANCE_TICK_INTERVAL,
        Err(error) => {
            tracing::debug!(%error, "local FIPS advert is not ready for Nostr pubsub publication");
            return MAINTENANCE_TICK_INTERVAL;
        }
    };
    let refresh_after = fips_advert_refresh_delay(&event);
    let event_id = event.id;
    let Ok(event) = VerifiedEvent::try_from(event) else {
        tracing::warn!(%event_id, "FIPS produced an invalid signed local advert");
        return MAINTENANCE_TICK_INTERVAL;
    };
    match pubsub
        .publish(
            event,
            EventSource::fips_endpoint(endpoint.npub().to_string()),
        )
        .await
    {
        Ok(report) if report.accepted && report.reason.is_none() => {
            tracing::debug!(%event_id, "published local FIPS advert through Nostr pubsub providers");
            refresh_after
        }
        Ok(report) if report.accepted => {
            tracing::debug!(%event_id, reason = report.reason.as_deref().unwrap_or_default(), "local FIPS advert reached only part of the Nostr pubsub provider set");
            MAINTENANCE_TICK_INTERVAL
        }
        Ok(report) => {
            tracing::debug!(%event_id, reason = report.reason.as_deref().unwrap_or("no provider accepted the advert"), "local FIPS advert publication deferred");
            MAINTENANCE_TICK_INTERVAL
        }
        Err(error) => {
            tracing::debug!(%error, %event_id, "local FIPS advert publication deferred");
            MAINTENANCE_TICK_INTERVAL
        }
    }
}

fn fips_advert_refresh_delay(event: &Event) -> Duration {
    event
        .tags
        .expiration()
        .map(|expiration| {
            expiration
                .as_secs()
                .saturating_sub(event.created_at.as_secs())
        })
        .filter(|ttl_secs| *ttl_secs > 0)
        .map_or(FIPS_ADVERT_REFRESH_INTERVAL, |ttl_secs| {
            Duration::from_secs((ttl_secs / 2).max(1))
        })
        .min(FIPS_ADVERT_REFRESH_INTERVAL)
}

async fn publish_policy_maintenance(context: PublishContext<'_>) {
    let now = now_ms();
    if let Err(error) = context
        .events
        .lock()
        .await
        .prune_expired_events(now / 1_000)
    {
        tracing::warn!(%error, "failed to prune expired control pubsub events");
    }
    let policy_events = match context
        .pubsub_policy
        .lock()
        .await
        .maintenance_events(now)
        .await
    {
        Ok(events) => events,
        Err(error) => {
            tracing::warn!(%error, "failed to evaluate pubsub policy maintenance");
            return;
        }
    };
    for event in policy_events {
        let published = match publish_local(context, event.clone()).await {
            Ok(published) => published,
            Err(error) => {
                tracing::warn!(%error, "failed to publish pubsub policy event");
                false
            }
        };
        if let Err(error) = context
            .pubsub_policy
            .lock()
            .await
            .complete_maintenance_event(&event, published, now)
        {
            tracing::warn!(%error, "failed to complete pubsub policy maintenance");
        }
    }
}

async fn publish_outbox_batch(context: PublishContext<'_>, outbox_path: &Path) {
    for path in control_pubsub_outbox_event_paths(outbox_path) {
        let event = match fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))
            .and_then(|bytes| {
                serde_json::from_slice::<Event>(&bytes)
                    .with_context(|| format!("failed to decode {}", path.display()))
            }) {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(%error, "discarding invalid control pubsub outbox entry");
                let _ = fs::remove_file(&path);
                continue;
            }
        };
        if let Err(error) = validate_control_pubsub_event(&event) {
            tracing::warn!(%error, path = %path.display(), "discarding rejected control pubsub outbox entry");
            let _ = fs::remove_file(&path);
            continue;
        }
        match publish_local(context, event).await {
            Ok(true) => {
                if let Err(error) = fs::remove_file(&path) {
                    tracing::warn!(%error, path = %path.display(), "failed to remove published control pubsub outbox entry");
                }
            }
            Ok(false) => break,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "discarding rejected control pubsub outbox entry");
                let _ = fs::remove_file(&path);
            }
        }
    }
}

async fn process_fips_delivery(
    endpoint: &FipsEndpoint,
    relay: Option<Arc<RelayEventBus>>,
    events: &Arc<Mutex<ControlEventStore>>,
    pubsub_policy: &Arc<Mutex<FipsPubsubPolicy>>,
    update_events: &UpdateEventCache,
    delivery: QueryEvent,
) {
    let verified = delivery.event;
    if !is_control_event(verified.as_event(), update_events) {
        return;
    }
    if !verified_event_is_admitted(pubsub_policy, &verified, &delivery.source).await {
        return;
    }
    let event = verified.as_event().clone();
    observe_policy_event(pubsub_policy, &event).await;
    ingest_into_fips_discovery(endpoint, &event).await;
    let inserted = match events.lock().await.insert(event.clone()) {
        Ok(inserted) => inserted,
        Err(error) => {
            tracing::warn!(%error, event_id = %event.id, "failed to store control pubsub event");
            false
        }
    };
    if inserted {
        tracing::debug!(event_id = %event.id, "delivered new standard FIPS pubsub event");
        if let Some(relay) = relay
            && let Err(error) = relay.publish(verified, delivery.source).await
        {
            tracing::debug!(%error, event_id = %event.id, "configured Nostr pubsub relay publication deferred");
        }
    }
}

async fn process_relay_delivery(
    endpoint: &FipsEndpoint,
    fips_pubsub: &FipsPubsubClient,
    events: &Arc<Mutex<ControlEventStore>>,
    pubsub_policy: &Arc<Mutex<FipsPubsubPolicy>>,
    update_events: &UpdateEventCache,
    delivery: QueryEvent,
) {
    let verified = delivery.event;
    if !is_control_event(verified.as_event(), update_events)
        || !verified_event_is_admitted(pubsub_policy, &verified, &delivery.source).await
    {
        return;
    }
    let event = verified.as_event().clone();
    observe_policy_event(pubsub_policy, &event).await;
    ingest_into_fips_discovery(endpoint, &event).await;
    let inserted = match events.lock().await.insert(event.clone()) {
        Ok(inserted) => inserted,
        Err(error) => {
            tracing::warn!(%error, event_id = %event.id, "failed to store control pubsub event");
            false
        }
    };
    if !inserted {
        return;
    }
    if let Err(error) = fips_pubsub.publish(verified, delivery.source).await {
        tracing::debug!(%error, event_id = %event.id, "decentralized Nostr pubsub publication deferred");
    }
}

async fn observe_policy_event(policy: &Arc<Mutex<FipsPubsubPolicy>>, event: &Event) {
    if let Err(error) = policy.lock().await.observe_event(event) {
        tracing::warn!(%error, event_id = %event.id, "failed to observe pubsub policy event");
    }
}

async fn ingest_into_fips_discovery(endpoint: &FipsEndpoint, event: &Event) {
    match endpoint.ingest_nostr_discovery_event(event.clone()).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!(event_id = %event.id, "FIPS ignored non-discovery control event");
        }
        Err(error) => {
            tracing::debug!(%error, event_id = %event.id, "failed to ingest pubsub event into FIPS discovery");
        }
    }
}

async fn sync_fips_subscription(
    endpoint: &FipsEndpoint,
    fips_pubsub: &FipsPubsubClient,
    peer_policy: &dyn MeshPeerPolicy,
    events: &Arc<Mutex<ControlEventStore>>,
    update_events: &UpdateEventCache,
    state: &mut FipsSubscriptionState,
) {
    // FIPS replays an active REQ onto newly connected/replacement links.
    // Recreating it on peer churn would replay retained events to all peers.
    let subscription_exists = state.subscription.is_some();
    if subscription_exists {
        return;
    }
    let peers = connected_peers(endpoint, peer_policy).await;
    if !should_create_fips_subscription(subscription_exists, peers.len()) {
        return;
    }
    let mut filters = fips_subscription_filters(update_events);
    if let Ok(root) = PublicKey::parse(endpoint.npub()) {
        filters.push(exit_graph_filter(root));
    }
    let next = match fips_pubsub.subscribe(filters).await {
        Ok(subscription) => subscription,
        Err(error) => {
            tracing::debug!(%error, "standard FIPS pubsub subscription deferred");
            return;
        }
    };
    state.subscription = Some(next);

    for event in bounded_fips_replay(events.lock().await.snapshot()) {
        let event_id = event.id;
        let Ok(event) = VerifiedEvent::try_from(event) else {
            continue;
        };
        if let Err(error) = fips_pubsub
            .publish(event, EventSource::local_index(endpoint.npub().to_string()))
            .await
        {
            tracing::debug!(%error, %event_id, "stored FIPS pubsub replay deferred");
        }
    }
}

fn should_create_fips_subscription(subscription_exists: bool, connected_peer_count: usize) -> bool {
    !subscription_exists && connected_peer_count > 0
}

fn fips_subscription_filters(update_events: &UpdateEventCache) -> Vec<Filter> {
    let mut filters = vec![
        Filter::new()
            .kinds(control_kinds())
            .limit(FIPS_REPLAY_LIMIT),
    ];
    if update_events.filter().kinds.is_some() {
        filters.push(update_events.filter().clone().limit(FIPS_REPLAY_LIMIT));
    }
    filters
}

fn bounded_fips_replay(mut events: Vec<Event>) -> Vec<Event> {
    let drop_count = events.len().saturating_sub(FIPS_REPLAY_LIMIT);
    events.drain(..drop_count);
    events
}

async fn connected_peers(endpoint: &FipsEndpoint, peer_policy: &dyn MeshPeerPolicy) -> Vec<String> {
    let peers = endpoint
        .peers()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|peer| peer.connected)
        .filter_map(|peer| {
            peer_policy
                .select_mesh_peer(&peer.npub)
                .ok()
                .flatten()
                .map(|selected| (selected.id, peer.link_id))
        })
        .collect::<Vec<_>>();
    subscription_peer_ids(peers)
}

fn subscription_peer_ids(peers: Vec<(String, u64)>) -> Vec<String> {
    let mut peer_ids = peers
        .into_iter()
        .map(|(peer_id, _link_id)| peer_id)
        .collect::<Vec<_>>();
    peer_ids.sort();
    peer_ids.dedup();
    peer_ids
}

async fn fips_notification(
    subscription: &mut Option<FipsPubsubSubscription>,
) -> Option<QueryEvent> {
    let Some(subscription) = subscription.as_mut() else {
        return std::future::pending().await;
    };
    subscription.recv().await
}

async fn verified_event_is_admitted(
    policy: &Arc<Mutex<FipsPubsubPolicy>>,
    event: &VerifiedEvent,
    source: &EventSource,
) -> bool {
    match policy
        .lock()
        .await
        .check_verified_event(event, source)
        .await
    {
        Ok(PolicyDecision::Drop { reason }) => {
            tracing::debug!(
                event_id = %event.as_event().id,
                author = %event.as_event().pubkey,
                source = %source.id.as_str(),
                %reason,
                "dropped control pubsub event by author reputation"
            );
            false
        }
        Ok(PolicyDecision::Allow { .. } | PolicyDecision::Throttle { .. }) => true,
        Err(error) => {
            tracing::debug!(
                %error,
                event_id = %event.as_event().id,
                source = %source.id.as_str(),
                "ignored control pubsub event rejected by shared policy"
            );
            false
        }
    }
}

async fn relay_notification(relay: &mut Option<RelayProvider>) -> Option<QueryEvent> {
    let Some(relay) = relay.as_mut() else {
        return std::future::pending().await;
    };
    relay.notifications.recv().await
}

fn exit_graph_filter(root: PublicKey) -> Filter {
    Filter::new()
        .author(root)
        .kinds([Kind::ContactList, Kind::MuteList])
        .limit(2)
}

fn control_kinds() -> [Kind; 2] {
    [
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
    matches!(
        u16::from(event.kind),
        FIPS_PEER_ADVERT_KIND | PAID_EXIT_OFFER_KIND | RATING_FACT_KIND | 3 | 10_000
    ) || update_events
        .filter()
        .match_event(event, MatchEventOptions::new())
}

include!("control_pubsub_runtime/outbox.rs");
include!("control_pubsub_runtime/exit_ratings.rs");

#[cfg(test)]
#[path = "control_pubsub_runtime/tests.rs"]
mod fips_update_tests;
