#[cfg(target_os = "macos")]
use crate::macos_file_io as fs;
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(not(target_os = "macos"))]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{NostrPubsubConfig, NostrPubsubMode};
use crate::control_pubsub::{
    CONTROL_PUBSUB_MAX_EVENT_BYTES, CONTROL_PUBSUB_MAX_WIRE_BYTES, FIPS_PEER_ADVERT_KIND,
    PAID_EXIT_OFFER_KIND, RATING_FACT_KIND,
};
use crate::paid_routes::{PAID_ROUTE_OFFER_TTL_SECS, SignedPaidRouteOffer};
#[cfg(feature = "updater")]
use crate::updater::{UpdateEventCache, configured_update_ref};
use anyhow::{Context, Result, anyhow};
use fips_core::FipsEndpoint;
use nostr_pubsub::MatchEventOptions;
use nostr_pubsub::{
    EventBus, EventSource, MeshPeerPolicy, NostrEventSubscription, NostrPubsubRouter,
    PolicyDecision, QueryEvent, RouterPublishSource, SourceRoute, VerifiedEvent,
};
use nostr_pubsub_fips::{
    FipsPubsubClient, FipsPubsubClientOptions, FipsPubsubClientPolicies, FipsPubsubPolicy,
    FipsPubsubPolicyOptions, FipsPubsubSubscription,
};
use nostr_pubsub_relay::RelayEventBus;
use nostr_pubsub_social_graph::{PEER_RATING_MAX_AGE, PEER_RATING_MAX_FUTURE_SKEW};
#[cfg(test)]
use nostr_sdk::prelude::Keys;
use nostr_sdk::prelude::{Client, Event, EventId, Filter, Kind, PublicKey};
use nostr_social_memory::rating_from_event;
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
const FIPS_ADVERT_RETRY_INITIAL: Duration = Duration::from_secs(1);
const FIPS_ADVERT_RETRY_MAX: Duration = Duration::from_mins(1);

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
include!("control_pubsub_runtime/relay_provider.rs");

#[derive(Clone)]
pub struct ControlPubsubClient {
    command_tx: mpsc::Sender<RuntimeCommand>,
    events: Arc<Mutex<ControlEventStore>>,
    relay_client: Option<Client>,
}

pub struct ControlPubsubFipsRuntime {
    pub client: ControlPubsubClient,
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
            #[cfg(feature = "updater")]
            None,
            relay_advert_filters(None, target_peer_npubs),
            MAX_PUBSUB_PEERS,
        )
        .await
    }

    /// Scope relay adverts to the endpoint's configured Nostr discovery app.
    /// This is `config.node.discovery.nostr.app`, not the endpoint's LAN scope.
    pub async fn start_for_peers_with_advert_app(
        endpoint: Arc<FipsEndpoint>,
        nostr_advert_app: &str,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        target_peer_npubs: &[String],
    ) -> Result<Option<Self>> {
        Self::start_inner(
            endpoint,
            config,
            relays,
            store_path,
            None,
            #[cfg(feature = "updater")]
            None,
            relay_advert_filters(Some(nostr_advert_app), target_peer_npubs),
            MAX_PUBSUB_PEERS,
        )
        .await
    }

    /// Use the endpoint's configured peer bound, including public bootstrap
    /// listeners, instead of silently selecting only 64 of its admitted peers.
    pub async fn start_for_peers_with_endpoint_config(
        endpoint: Arc<FipsEndpoint>,
        endpoint_config: &ControlPubsubEndpointConfig,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        target_peer_npubs: &[String],
    ) -> Result<Option<Self>> {
        Self::start_inner(
            endpoint,
            config,
            relays,
            store_path,
            None,
            #[cfg(feature = "updater")]
            None,
            relay_advert_filters(Some(&endpoint_config.advert_app), target_peer_npubs),
            endpoint_config.max_connected_peers,
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
            #[cfg(feature = "updater")]
            None,
            relay_advert_filters(None, &[]),
            MAX_PUBSUB_PEERS,
        )
        .await
    }

    /// Apply peer policy and the endpoint's configured Nostr advert app.
    pub async fn start_with_peer_policy_and_advert_app(
        endpoint: Arc<FipsEndpoint>,
        nostr_advert_app: &str,
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
            #[cfg(feature = "updater")]
            None,
            relay_advert_filters(Some(nostr_advert_app), &[]),
            MAX_PUBSUB_PEERS,
        )
        .await
    }

    // The optional updater cache adds the eighth input to this private startup path.
    #[allow(clippy::too_many_arguments)]
    async fn start_inner(
        endpoint: Arc<FipsEndpoint>,
        config: NostrPubsubConfig,
        relays: Vec<String>,
        store_path: Option<PathBuf>,
        peer_policy: Option<Arc<dyn MeshPeerPolicy>>,
        #[cfg(feature = "updater")] update_events_override: Option<UpdateEventCache>,
        advert_filters: Vec<Filter>,
        max_connected_peers: usize,
    ) -> Result<Option<Self>> {
        if config.mode == NostrPubsubMode::Off {
            return Ok(None);
        }
        #[cfg(feature = "updater")]
        let update_events = match update_events_override {
            Some(update_events) => update_events,
            None => configured_update_events()?,
        };
        let outbox_path = store_path
            .as_deref()
            .map(control_pubsub_outbox_directory_from_store_path);
        let graph_root = PublicKey::parse(endpoint.npub())?;
        #[cfg(feature = "updater")]
        let store_updates = update_events.clone();
        let event_store = control_store_io(move || {
            ControlEventStore::load_for_owner(
                store_path,
                #[cfg(feature = "updater")]
                store_updates,
                Some(graph_root),
            )
        })
        .await?;
        let stored_events = event_store.snapshot();
        let pubsub_policy = FipsPubsubPolicy::new(
            Arc::clone(&endpoint),
            stored_events.iter(),
            FipsPubsubPolicyOptions::default(),
        )?;
        let rating_filter = pubsub_policy.rating_filter()?;
        let event_policy = pubsub_policy.event_policy();
        let peer_policy = peer_policy.unwrap_or_else(|| pubsub_policy.peer_policy());
        let pubsub_policy = Arc::new(Mutex::new(pubsub_policy));

        let fips_pubsub = Arc::new(
            FipsPubsubClient::start_with_policies(
                Arc::clone(&endpoint),
                fips_pubsub_options(&config, max_connected_peers),
                FipsPubsubClientPolicies {
                    peers: Some(Arc::clone(&peer_policy)),
                    events: Some(Arc::clone(&event_policy)),
                    ..FipsPubsubClientPolicies::default()
                },
            )
            .await
            .context("failed to bind standard FIPS Nostr pubsub service")?,
        );
        let relay = RelayProvider::start(
            endpoint.host_network(),
            config.mode,
            relays,
            relay_subscription_filters(
                &rating_filter,
                #[cfg(feature = "updater")]
                &update_events,
                advert_filters,
            ),
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
        fips_pubsub.set_replay_source(Some(Arc::new(ControlEventReplay {
            events: Arc::clone(&events),
            policy: Arc::clone(&pubsub_policy),
        })))?;
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
                    rating_filter,
                    #[cfg(feature = "updater")]
                    update_events,
                },
                outbox_path,
                command_rx,
                shutdown_rx,
            )
            .await;
        });
        Ok(Some(Self {
            client: ControlPubsubClient {
                command_tx,
                events,
                relay_client,
            },
            shutdown: Some(shutdown_tx),
            task,
        }))
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
        if let Some(client) = self.client.relay_client.take() {
            client.shutdown().await;
        }
    }
}

impl ControlPubsubClient {
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

    pub async fn relay_statuses(&self) -> Vec<ControlRelayStatus> {
        let Some(client) = &self.relay_client else {
            return Vec::new();
        };
        let mut states = Vec::new();
        for (url, relay) in client.relays().await {
            states.push(ControlRelayStatus {
                url: url.to_string(),
                status: relay.status().to_string().to_ascii_lowercase(),
            });
        }
        states.sort_by(|left, right| left.url.cmp(&right.url));
        states
    }
}

impl std::ops::Deref for ControlPubsubFipsRuntime {
    type Target = ControlPubsubClient;
    fn deref(&self) -> &Self::Target {
        &self.client
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

struct PubsubRunState {
    endpoint: Arc<FipsEndpoint>,
    fips_pubsub: Arc<FipsPubsubClient>,
    pubsub: NostrPubsubRouter,
    relay: Option<RelayProvider>,
    events: Arc<Mutex<ControlEventStore>>,
    peer_policy: Arc<dyn MeshPeerPolicy>,
    pubsub_policy: Arc<Mutex<FipsPubsubPolicy>>,
    rating_filter: Filter,
    #[cfg(feature = "updater")]
    update_events: UpdateEventCache,
}

#[derive(Clone, Copy)]
struct PublishContext<'a> {
    endpoint: &'a FipsEndpoint,
    pubsub: &'a NostrPubsubRouter,
    events: &'a Arc<Mutex<ControlEventStore>>,
    pubsub_policy: &'a Arc<Mutex<FipsPubsubPolicy>>,
    #[cfg(feature = "updater")]
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
        rating_filter,
        #[cfg(feature = "updater")]
        update_events,
    } = state;
    let mut maintenance_tick = tokio::time::interval(MAINTENANCE_TICK_INTERVAL);
    maintenance_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut outbox_tick = tokio::time::interval(OUTBOX_POLL_INTERVAL);
    outbox_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let advert_refresh = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(advert_refresh);
    let mut advert_retry_delay = FIPS_ADVERT_RETRY_INITIAL;
    let mut fips_subscription = FipsSubscriptionState::default();
    sync_fips_subscription(
        &endpoint,
        &fips_pubsub,
        peer_policy.as_ref(),
        &events,
        &rating_filter,
        #[cfg(feature = "updater")]
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
                                #[cfg(feature = "updater")]
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
                        #[cfg(feature = "updater")]
                        update_events: &update_events,
                    },
                    outbox_path.as_deref().expect("outbox path is present"),
                )
                .await;
            }
            delivery = fips_subscription.recv() => {
                let Some(delivery) = delivery else { continue; };
                process_fips_delivery(
                    &endpoint,
                    relay.as_ref().map(|provider| Arc::clone(&provider.bus)),
                    &events,
                    &pubsub_policy,
                    #[cfg(feature = "updater")]
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
                    #[cfg(feature = "updater")]
                    &update_events,
                    delivery,
                )
                .await;
            }
            _ = &mut advert_refresh => {
                let refresh_after = publish_local_fips_advert(&endpoint, &pubsub, &mut advert_retry_delay).await;
                advert_refresh.as_mut().reset(tokio::time::Instant::now() + refresh_after);
            }
            _ = maintenance_tick.tick() => {
                #[cfg(feature = "paid-exit")]
                sync_provider_profiles(&mut relay, &events).await;
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
                    &rating_filter,
                    #[cfg(feature = "updater")]
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
                        #[cfg(feature = "updater")]
                        update_events: &update_events,
                    },
                )
                .await;
            }
        }
    }
    // Join provider tasks and drop their service receiver before stop() returns.
    fips_pubsub.shutdown_shared().await;
    if let Err(error) = flush_control_events(&events).await {
        tracing::warn!(%error, "failed to flush control pubsub cache on shutdown");
    }
}

async fn publish_local(context: PublishContext<'_>, event: Event) -> Result<bool> {
    let verified = verify_control_event(
        event,
        #[cfg(feature = "updater")]
        context.update_events,
    )?;
    publish_verified(context, verified).await
}

fn verify_control_event(
    event: Event,
    #[cfg(feature = "updater")] update_events: &UpdateEventCache,
) -> Result<VerifiedEvent> {
    validate_control_event_shape(
        &event,
        #[cfg(feature = "updater")]
        update_events,
    )?;
    VerifiedEvent::try_from(event).map_err(anyhow::Error::from)
}

fn validate_control_event_shape(
    event: &Event,
    #[cfg(feature = "updater")] update_events: &UpdateEventCache,
) -> Result<()> {
    if !is_control_event(
        event,
        #[cfg(feature = "updater")]
        update_events,
    ) {
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
    validate_control_event_shape(
        verified.as_event(),
        #[cfg(feature = "updater")]
        context.update_events,
    )?;
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
    insert_control_event(context.events, event.clone()).await?;
    ingest_into_fips_discovery(context.endpoint, &event).await;
    Ok(published)
}

async fn publish_local_fips_advert(
    endpoint: &FipsEndpoint,
    pubsub: &NostrPubsubRouter,
    retry_delay: &mut Duration,
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
        Ok(report) if report.accepted => {
            // A partial result must not replay the advert to providers that
            // already accepted it. Resume the normal refresh after any success.
            tracing::debug!(%event_id, reason = report.reason.as_deref().unwrap_or_default(), "published local FIPS advert through Nostr pubsub providers");
            *retry_delay = FIPS_ADVERT_RETRY_INITIAL;
            return refresh_after;
        }
        Ok(report) => {
            tracing::debug!(%event_id, reason = report.reason.as_deref().unwrap_or("no provider accepted the advert"), "local FIPS advert publication deferred");
        }
        Err(error) => {
            tracing::debug!(%error, %event_id, "local FIPS advert publication deferred");
        }
    }
    let retry_after = *retry_delay;
    *retry_delay = retry_delay.saturating_mul(2).min(FIPS_ADVERT_RETRY_MAX);
    retry_after
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
    if let Err(error) = prune_control_events(context.events, now / 1_000).await {
        tracing::warn!(%error, "failed to maintain control pubsub cache");
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
    #[cfg(feature = "updater")] update_events: &UpdateEventCache,
    delivery: QueryEvent,
) {
    let verified = delivery.event;
    if !is_control_event(
        verified.as_event(),
        #[cfg(feature = "updater")]
        update_events,
    ) {
        return;
    }
    if !verified_event_is_admitted(pubsub_policy, &verified, &delivery.source).await {
        return;
    }
    let event = verified.as_event().clone();
    observe_policy_event(pubsub_policy, &event).await;
    ingest_into_fips_discovery(endpoint, &event).await;
    let inserted = events.lock().await.insert_memory(event.clone());
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
    #[cfg(feature = "updater")] update_events: &UpdateEventCache,
    delivery: QueryEvent,
) {
    let verified = delivery.event;
    if !is_control_event(
        verified.as_event(),
        #[cfg(feature = "updater")]
        update_events,
    ) || !verified_event_is_admitted(pubsub_policy, &verified, &delivery.source).await
    {
        return;
    }
    let event = verified.as_event().clone();
    observe_policy_event(pubsub_policy, &event).await;
    ingest_into_fips_discovery(endpoint, &event).await;
    let inserted = events.lock().await.insert_memory(event.clone());
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

fn should_create_fips_subscription(subscription_exists: bool, connected_peer_count: usize) -> bool {
    !subscription_exists && connected_peer_count > 0
}

include!("control_pubsub_runtime/subscriptions.rs");

fn bounded_fips_replay(events: Vec<Event>, peer_ratings: &Filter) -> Vec<Event> {
    let mut events = scoped_fips_replay(events, peer_ratings);
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
    let delivery = relay.notifications.recv().await?;
    relay
        .queued_events
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&(delivery.event.as_event().id, delivery.source.clone()));
    Some(delivery)
}

include!("control_pubsub_runtime/outbox.rs");
include!("control_pubsub_runtime/transport.rs");
include!("control_pubsub_runtime/exit_ratings.rs");
#[cfg(feature = "paid-exit")]
include!("control_pubsub_runtime/provider_profiles.rs");

#[cfg(all(test, feature = "updater"))]
#[path = "control_pubsub_runtime/tests.rs"]
mod fips_update_tests;
