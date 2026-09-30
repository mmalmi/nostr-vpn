use std::sync::Arc;

use fips_core::FipsEndpoint;
use fips_core::config::{NostrDiscoveryConfig, NostrPeerfindingSource};
use fips_core::discovery::nostr::{ADVERT_IDENTIFIER, ADVERT_KIND};
use nostr::Kind;
use nostr_pubsub::{
    EventBus, EventRetentionPolicy, EventSource, Filter, PublishReport, PubsubError, QueryOptions,
    Result, VerifiedEvent,
};

use super::storage_error;

/// Convert FIPS's transport-neutral discovery configuration into the bounded
/// retention policy used by a pubsub cache.
#[must_use]
pub fn fips_discovery_retention_policy(
    config: &NostrDiscoveryConfig,
) -> Option<EventRetentionPolicy> {
    (config.enabled && config.peerfinding_source == NostrPeerfindingSource::External).then(|| {
        let app = config.app.trim();
        let identifier = if app.is_empty() {
            ADVERT_IDENTIFIER
        } else {
            app
        };
        EventRetentionPolicy::new(
            config.advert_cache_max_entries,
            vec![
                Filter::new()
                    .kind(Kind::Custom(ADVERT_KIND))
                    .identifier(identifier),
            ],
        )
    })
}

/// Result of one bounded peer-advert query through the selected pubsub bus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FipsPeerfindingRefresh {
    pub received: usize,
    pub accepted: usize,
}

/// Routes FIPS peer adverts through an application-selected `nostr-pubsub`
/// event bus.
///
/// The event bus owns every source decision: configured relay providers,
/// decentralized pubsub providers, local indexes, or an application-defined
/// composition. This adapter accepts no relay lists and never opens a relay
/// socket itself.
pub struct FipsPeerfinder {
    endpoint: Arc<FipsEndpoint>,
    filter: Filter,
    max_events: usize,
}

impl FipsPeerfinder {
    pub fn new(endpoint: Arc<FipsEndpoint>, config: &NostrDiscoveryConfig) -> Result<Self> {
        if !config.enabled {
            return Err(PubsubError::Validation(
                "FIPS Nostr discovery must be enabled for pubsub peerfinding".to_string(),
            ));
        }
        if config.peerfinding_source != NostrPeerfindingSource::External {
            return Err(PubsubError::Validation(
                "FIPS peerfinding_source must be external when nostr-pubsub owns peerfinding"
                    .to_string(),
            ));
        }
        let app = config.app.trim();
        let identifier = if app.is_empty() {
            ADVERT_IDENTIFIER
        } else {
            app
        };
        Ok(Self {
            endpoint,
            filter: Filter::new()
                .kind(Kind::Custom(ADVERT_KIND))
                .identifier(identifier),
            max_events: config.advert_cache_max_entries.max(1),
        })
    }

    #[must_use]
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// Publish the signed local FIPS advert through the selected pubsub bus.
    pub async fn publish_local<B>(&self, bus: &B) -> Result<Option<PublishReport>>
    where
        B: EventBus + ?Sized,
    {
        let Some(event) = self
            .endpoint
            .local_nostr_discovery_advert_event()
            .await
            .map_err(|error| storage_error("create local FIPS discovery advert", error))?
        else {
            return Ok(None);
        };
        let event = VerifiedEvent::try_from(event)?;
        bus.publish(
            event,
            EventSource::fips_endpoint(self.endpoint.npub().to_string()),
        )
        .await
        .map(Some)
    }

    /// Query the selected pubsub bus and feed every returned advert through
    /// FIPS's normal signature, namespace, freshness, and schema validation.
    pub async fn refresh<B>(&self, bus: &B) -> Result<FipsPeerfindingRefresh>
    where
        B: EventBus + ?Sized,
    {
        let report = bus
            .query(
                vec![self.filter.clone()],
                QueryOptions {
                    limit: Some(self.max_events),
                },
            )
            .await?;
        let received = report.events.len();
        let mut accepted = 0;
        for event in report.events {
            accepted += usize::from(self.ingest(event.event).await?);
        }
        Ok(FipsPeerfindingRefresh { received, accepted })
    }

    /// Ingest one event from an open pubsub subscription.
    pub async fn ingest(&self, event: VerifiedEvent) -> Result<bool> {
        ingest_fips_discovery_event(&self.endpoint, event).await
    }
}

/// Feed a verified pubsub event into FIPS's normal Nostr discovery validator.
pub async fn ingest_fips_discovery_event(
    endpoint: &FipsEndpoint,
    event: VerifiedEvent,
) -> Result<bool> {
    endpoint
        .ingest_nostr_discovery_event(event.into_event())
        .await
        .map_err(|error| storage_error("ingest FIPS Nostr discovery event", error))
}
