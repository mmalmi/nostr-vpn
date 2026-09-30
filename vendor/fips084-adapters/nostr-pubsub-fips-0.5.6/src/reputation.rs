use std::sync::Arc;
use std::time::Duration;

use fips_core::FipsEndpoint;
use nostr::Event;
use nostr_pubsub::{
    EventSource, MeshPeerPolicy, PolicyDecision, PubsubError, PubsubPolicy, Result, VerifiedEvent,
};
use nostr_pubsub_social_graph::{
    PeerRatingPublisher, PeerRatingPublisherConfig, PeerReputation, PeerReputationConfig,
    PeerReputationPolicies,
};

use crate::storage_error;

#[derive(Debug, Clone, PartialEq)]
pub struct FipsPeerReputationOptions {
    pub evaluation_interval: Duration,
    pub reputation: PeerReputationConfig,
    pub publication: PeerRatingPublisherConfig,
}

pub type FipsPubsubPolicyOptions = FipsPeerReputationOptions;

impl Default for FipsPeerReputationOptions {
    fn default() -> Self {
        Self {
            evaluation_interval: Duration::from_mins(1),
            reputation: PeerReputationConfig::default(),
            publication: PeerRatingPublisherConfig::default(),
        }
    }
}

/// Default peer reputation for pubsub carried by a [`FipsEndpoint`].
///
/// FIPS remains the source of authenticated peer metrics and signed local
/// ratings. This adapter owns the reusable trust projection and publication
/// cadence so applications only need to transport the returned rating events.
pub struct FipsPeerReputation {
    endpoint: Arc<FipsEndpoint>,
    reputation: PeerReputation,
    policies: PeerReputationPolicies,
    publisher: PeerRatingPublisher,
    evaluation_interval: Duration,
}

/// Pubsub-facing policy facade. It hides rating parsing and cadence from the
/// application runtime; callers only observe ordinary events and periodically
/// request due maintenance events for transport.
pub struct FipsPubsubPolicy {
    reputation: FipsPeerReputation,
    next_evaluation_ms: Option<u64>,
}

impl FipsPeerReputation {
    /// Restores reputation using the wall-clock Unix time.
    pub fn new<'a>(
        endpoint: Arc<FipsEndpoint>,
        stored_events: impl IntoIterator<Item = &'a Event>,
        options: FipsPeerReputationOptions,
    ) -> Result<Self> {
        Self::new_inner(endpoint, stored_events, options, None)
    }

    /// Restores reputation at an explicit Unix timestamp in seconds.
    pub fn new_at<'a>(
        endpoint: Arc<FipsEndpoint>,
        stored_events: impl IntoIterator<Item = &'a Event>,
        options: FipsPeerReputationOptions,
        now_secs: u64,
    ) -> Result<Self> {
        Self::new_inner(endpoint, stored_events, options, Some(now_secs))
    }

    fn new_inner<'a>(
        endpoint: Arc<FipsEndpoint>,
        stored_events: impl IntoIterator<Item = &'a Event>,
        options: FipsPeerReputationOptions,
        now_secs: Option<u64>,
    ) -> Result<Self> {
        if options.evaluation_interval.is_zero() {
            return Err(PubsubError::Validation(
                "FIPS peer reputation evaluation interval must be positive".to_string(),
            ));
        }
        let stored_events = stored_events.into_iter().collect::<Vec<_>>();
        let (mut reputation, policies) = PeerReputation::new(endpoint.npub(), options.reputation)?;
        if let Some(now_secs) = now_secs {
            reputation.replay_at(stored_events.iter().copied(), now_secs)?;
        } else {
            reputation.replay(stored_events.iter().copied())?;
        }
        let publisher = if let Some(now_secs) = now_secs {
            PeerRatingPublisher::from_events_at(
                reputation.root(),
                reputation.scope(),
                options.publication,
                stored_events.iter().copied(),
                now_secs.saturating_mul(1_000),
            )?
        } else {
            PeerRatingPublisher::from_events(
                reputation.root(),
                reputation.scope(),
                options.publication,
                stored_events.iter().copied(),
            )?
        };
        Ok(Self {
            endpoint,
            reputation,
            policies,
            publisher,
            evaluation_interval: options.evaluation_interval,
        })
    }

    #[must_use]
    pub fn peer_policy(&self) -> Arc<dyn MeshPeerPolicy> {
        self.policies.mesh()
    }

    #[must_use]
    pub fn event_policy(&self) -> Arc<dyn PubsubPolicy> {
        self.policies.events()
    }

    /// Applies the shared author policy to an event from any transport.
    pub async fn check_event(&self, event: &Event, source: &EventSource) -> Result<PolicyDecision> {
        self.policies.check_event(event, source).await
    }

    /// Applies the shared author policy without repeating signature
    /// verification already completed at the transport boundary.
    pub async fn check_verified_event(
        &self,
        event: &VerifiedEvent,
        source: &EventSource,
    ) -> Result<PolicyDecision> {
        self.policies.check_verified_event(event, source).await
    }

    #[must_use]
    pub const fn evaluation_interval(&self) -> Duration {
        self.evaluation_interval
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        self.reputation.scope()
    }

    pub fn ingest_event(&mut self, event: &Event) -> Result<bool> {
        self.reputation.ingest_event(event)
    }

    /// Ingests one rating event at an explicit Unix timestamp in seconds.
    pub fn ingest_event_at(&mut self, event: &Event, now_secs: u64) -> Result<bool> {
        self.reputation.ingest_event_at(event, now_secs)
    }

    pub async fn publication_candidates(&self, now_ms: u64) -> Result<Vec<Event>> {
        let events = self
            .endpoint
            .peer_rating_events(self.reputation.scope())
            .await
            .map_err(|error| storage_error("snapshot signed FIPS peer ratings", error))?;
        Ok(events
            .into_iter()
            .filter(|event| self.publisher.should_publish_event(event, now_ms))
            .take(self.publisher.batch_size())
            .collect())
    }

    pub fn record_published_event(&mut self, event: &Event, now_ms: u64) -> bool {
        self.publisher.record_published_event(event, now_ms)
    }
}

impl FipsPubsubPolicy {
    /// Bounded subscription for the local root and explicitly configured raters.
    pub fn rating_filter(&self) -> Result<nostr::Filter> {
        self.reputation.reputation.rating_filter()
    }

    /// Apply the same configurable reputation projection to peer selection and
    /// event admission. The default trusted-rater list is empty.
    #[must_use]
    pub fn client_policies(&self) -> crate::FipsPubsubClientPolicies {
        crate::FipsPubsubClientPolicies {
            peers: Some(self.peer_policy()),
            events: Some(self.event_policy()),
            ..Default::default()
        }
    }

    /// Restores the policy using the wall-clock Unix time.
    pub fn new<'a>(
        endpoint: Arc<FipsEndpoint>,
        stored_events: impl IntoIterator<Item = &'a Event>,
        options: FipsPubsubPolicyOptions,
    ) -> Result<Self> {
        Ok(Self {
            reputation: FipsPeerReputation::new(endpoint, stored_events, options)?,
            next_evaluation_ms: None,
        })
    }

    /// Restores the policy at an explicit Unix timestamp in seconds.
    pub fn new_at<'a>(
        endpoint: Arc<FipsEndpoint>,
        stored_events: impl IntoIterator<Item = &'a Event>,
        options: FipsPubsubPolicyOptions,
        now_secs: u64,
    ) -> Result<Self> {
        Ok(Self {
            reputation: FipsPeerReputation::new_at(endpoint, stored_events, options, now_secs)?,
            next_evaluation_ms: None,
        })
    }

    #[must_use]
    pub fn peer_policy(&self) -> Arc<dyn MeshPeerPolicy> {
        self.reputation.peer_policy()
    }

    /// Shared author admission used by FIPS pubsub before cache and gossip.
    #[must_use]
    pub fn event_policy(&self) -> Arc<dyn PubsubPolicy> {
        self.reputation.event_policy()
    }

    pub fn observe_event(&mut self, event: &Event) -> Result<bool> {
        self.reputation.ingest_event(event)
    }

    /// Observes one rating event at an explicit Unix timestamp in seconds.
    pub fn observe_event_at(&mut self, event: &Event, now_secs: u64) -> Result<bool> {
        self.reputation.ingest_event_at(event, now_secs)
    }

    /// Applies transport-neutral author admission before an event enters the
    /// application cache or pubsub fanout.
    pub async fn check_event(&self, event: &Event, source: &EventSource) -> Result<PolicyDecision> {
        self.reputation.check_event(event, source).await
    }

    /// Applies transport-neutral author admission to an event whose ID and
    /// signature have already been verified by the selected pubsub carrier.
    pub async fn check_verified_event(
        &self,
        event: &VerifiedEvent,
        source: &EventSource,
    ) -> Result<PolicyDecision> {
        self.reputation.check_verified_event(event, source).await
    }

    pub async fn maintenance_events(&mut self, now_ms: u64) -> Result<Vec<Event>> {
        self.reputation.reputation.prune(now_ms / 1_000)?;
        self.reputation.publisher.prune(now_ms);
        let interval_ms = duration_ms(self.reputation.evaluation_interval());
        let Some(next_evaluation_ms) = self.next_evaluation_ms else {
            self.next_evaluation_ms = Some(now_ms.saturating_add(interval_ms));
            return Ok(Vec::new());
        };
        if now_ms < next_evaluation_ms {
            return Ok(Vec::new());
        }
        self.next_evaluation_ms = Some(now_ms.saturating_add(interval_ms));
        self.reputation.publication_candidates(now_ms).await
    }

    pub fn complete_maintenance_event(
        &mut self,
        event: &Event,
        published: bool,
        now_ms: u64,
    ) -> Result<()> {
        // Local observations remain useful while disconnected. Only the
        // publication cadence depends on successful delivery to pubsub.
        self.reputation.ingest_event_at(event, now_ms / 1_000)?;
        if published {
            let _ = self.reputation.record_published_event(event, now_ms);
        }
        Ok(())
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
