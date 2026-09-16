#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredEventsFile {
    version: u8,
    events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    paid_offer_watermarks: Vec<Event>,
}

#[derive(Debug)]
struct ControlEventStore {
    graph_root: Option<PublicKey>,
    path: Option<PathBuf>,
    events: HashMap<String, Event>,
    order: VecDeque<String>,
    paid_offer_watermarks: HashMap<(u16, String, String), Event>,
    rating_events: HashMap<RatingEventStoreKey, RatingEventStoreEntry>,
    update_events: UpdateEventCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RatingEventStoreKey {
    author: String,
    subject: String,
    scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RatingEventStoreEntry {
    event_id: String,
    created_at: u64,
}

fn configured_update_events() -> Result<UpdateEventCache> {
    let reference = configured_update_ref()?;
    UpdateEventCache::new(&reference).context("failed to configure update announcement cache")
}

impl ControlEventStore {
    fn load(path: Option<PathBuf>, update_events: UpdateEventCache) -> Result<Self> {
        Self::load_for_owner(path, update_events, None)
    }

    fn load_for_owner(
        path: Option<PathBuf>,
        update_events: UpdateEventCache,
        graph_root: Option<PublicKey>,
    ) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self {
                graph_root,
                path: None,
                events: HashMap::new(),
                order: VecDeque::new(),
                paid_offer_watermarks: HashMap::new(),
                rating_events: HashMap::new(),
                update_events,
            });
        };
        let mut store = Self {
            graph_root,
            path: Some(path.clone()),
            events: HashMap::new(),
            order: VecDeque::new(),
            paid_offer_watermarks: HashMap::new(),
            rating_events: HashMap::new(),
            update_events,
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(store),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let saved: StoredEventsFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode {}", path.display()))?;
        if saved.version != STORE_VERSION {
            return Err(anyhow!(
                "unsupported control pubsub store version {} in {}",
                saved.version,
                path.display()
            ));
        }
        let saved_count = saved.events.len();
        let saved_watermark_count = saved.paid_offer_watermarks.len();
        for event in saved.events {
            if event.verify().is_ok()
                && is_control_event(&event, &store.update_events)
                && control_event_is_persistent(&event)
            {
                let _ = store.insert_memory(event);
            }
        }
        for event in saved.paid_offer_watermarks {
            if event.verify().is_ok()
                && is_control_event(&event, &store.update_events)
                && u16::from(event.kind) == PAID_EXIT_OFFER_KIND
            {
                let _ = store.insert_memory(event);
            }
        }
        if store.events.len() != saved_count
            || store.paid_offer_watermarks.len() != saved_watermark_count
        {
            store.persist()?;
        }
        Ok(store)
    }

    fn insert(&mut self, event: Event) -> Result<bool> {
        let persistent = control_event_is_persistent(&event);
        if !self.insert_memory(event) {
            return Ok(false);
        }
        if persistent {
            self.persist()?;
        }
        Ok(true)
    }

    fn insert_memory(&mut self, event: Event) -> bool {
        let event_id = event.id.to_hex();
        if self.events.contains_key(&event_id) {
            return false;
        }
        let now_secs = now_ms() / 1_000;
        if matches!(u16::from(event.kind), 3 | 10_000) {
            if self.graph_root.is_some_and(|root| root != event.pubkey)
                || event.created_at.as_secs() > now_secs.saturating_add(300)
            {
                return false;
            }
            if let Some(previous) = self
                .events
                .values()
                .find(|old| old.kind == event.kind && old.pubkey == event.pubkey)
            {
                if !paid_offer_supersedes(&event, previous) {
                    return false;
                }
                let previous_id = previous.id.to_hex();
                self.remove_memory(&previous_id);
            }
        }
        let paid_offer = if u16::from(event.kind) == PAID_EXIT_OFFER_KIND {
            let Some(state) = paid_offer_state(&event, now_secs) else {
                return false;
            };
            Some(state)
        } else {
            None
        };
        if let Some((coordinate, is_live)) = paid_offer {
            if let Some(stored) = self.paid_offer_watermarks.get(&coordinate)
                && !paid_offer_supersedes(&event, stored)
            {
                return false;
            }
            if let Some(stored_id) = self.events.iter().find_map(|(stored_id, stored)| {
                (paid_offer_coordinate(stored).as_ref() == Some(&coordinate))
                    .then(|| stored_id.clone())
            }) {
                self.remove_memory(&stored_id);
            }
            self.paid_offer_watermarks.insert(coordinate, event.clone());
            if !is_live {
                return true;
            }
        }
        let rating = if u16::from(event.kind) == RATING_FACT_KIND {
            let Some((rating_key, created_at)) = retained_rating_event(&event, now_secs) else {
                return false;
            };
            if let Some(stored) = self.rating_events.get(&rating_key).cloned() {
                let stored_event = self
                    .events
                    .get(&stored.event_id)
                    .expect("rating index refers to a stored event");
                if (stored.created_at, stored_event.id) >= (created_at, event.id) {
                    return false;
                }
                self.remove_memory(&stored.event_id);
            }
            Some((rating_key, created_at))
        } else {
            None
        };
        let is_update_event = self
            .update_events
            .filter()
            .match_event(&event, MatchEventOptions::new());
        if is_update_event {
            if !self
                .update_events
                .ingest_event(event.clone())
                .unwrap_or(false)
            {
                return false;
            }
            let replaced = self
                .events
                .iter()
                .filter(|(_, stored)| {
                    self.update_events
                        .filter()
                        .match_event(stored, MatchEventOptions::new())
                })
                .map(|(event_id, _)| event_id.clone())
                .collect::<Vec<_>>();
            for stored_id in replaced {
                self.remove_memory(&stored_id);
            }
        }
        while self.events.len() >= STORE_MAX_EVENTS {
            let remove_index = self
                .order
                .iter()
                .position(|stored_id| {
                    self.events.get(stored_id).is_some_and(|stored| {
                        !matches!(u16::from(stored.kind), 3 | 10_000)
                            && !self
                                .update_events
                                .filter()
                                .match_event(stored, MatchEventOptions::new())
                    })
                })
                .unwrap_or(0);
            let Some(oldest) = self.order.remove(remove_index) else {
                break;
            };
            self.remove_memory(&oldest);
        }
        self.order.push_back(event_id.clone());
        self.events.insert(event_id.clone(), event);
        if let Some((rating_key, created_at)) = rating {
            self.rating_events.insert(
                rating_key,
                RatingEventStoreEntry {
                    event_id,
                    created_at,
                },
            );
        }
        true
    }

    fn remove_memory(&mut self, event_id: &str) -> bool {
        if self.events.remove(event_id).is_none() {
            return false;
        }
        self.order.retain(|stored_id| stored_id != event_id);
        self.rating_events
            .retain(|_, stored| stored.event_id != event_id);
        true
    }

    fn snapshot(&self) -> Vec<Event> {
        self.order
            .iter()
            .filter_map(|event_id| self.events.get(event_id).cloned())
            .collect()
    }

    fn prune_expired_events(&mut self, now_secs: u64) -> Result<usize> {
        let mut remove = self
            .rating_events
            .iter()
            .filter(|(_, stored)| {
                now_secs.saturating_sub(stored.created_at) > PEER_RATING_MAX_AGE.as_secs()
            })
            .map(|(_, stored)| stored.event_id.clone())
            .collect::<Vec<_>>();
        remove.extend(
            self.events
                .iter()
                .filter(|(_, event)| {
                    u16::from(event.kind) == PAID_EXIT_OFFER_KIND
                        && retained_paid_offer_coordinate(event, now_secs).is_none()
                })
                .map(|(event_id, _)| event_id.clone()),
        );
        remove.sort();
        remove.dedup();
        let removed_event_ids = remove.iter().cloned().collect::<HashSet<_>>();
        let expired_watermarks = self
            .paid_offer_watermarks
            .iter()
            .filter(|(_, event)| {
                now_secs
                    >= event
                        .created_at
                        .as_secs()
                        .saturating_add(PAID_ROUTE_OFFER_TTL_SECS)
            })
            .map(|(coordinate, event)| (coordinate.clone(), event.id.to_hex()))
            .collect::<Vec<_>>();
        if remove.is_empty() && expired_watermarks.is_empty() {
            return Ok(0);
        }
        for event_id in &remove {
            self.remove_memory(event_id);
        }
        let hidden_watermarks_removed = expired_watermarks
            .iter()
            .filter(|(_, event_id)| !removed_event_ids.contains(event_id))
            .count();
        for (coordinate, _) in expired_watermarks {
            self.paid_offer_watermarks.remove(&coordinate);
        }
        self.persist()?;
        Ok(remove.len() + hidden_watermarks_removed)
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut paid_offer_watermarks = self
            .paid_offer_watermarks
            .values()
            .cloned()
            .collect::<Vec<_>>();
        paid_offer_watermarks.sort_by_key(paid_offer_coordinate);
        let saved = StoredEventsFile {
            version: STORE_VERSION,
            events: self
                .snapshot()
                .into_iter()
                .filter(control_event_is_persistent)
                .collect(),
            paid_offer_watermarks,
        };
        let bytes = serde_json::to_vec(&saved).context("failed to encode control pubsub store")?;
        let temporary = temporary_store_path(path);
        fs::write(&temporary, bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to replace control pubsub store {} with {}",
                path.display(),
                temporary.display()
            )
        })?;
        Ok(())
    }
}

fn paid_offer_supersedes(candidate: &Event, stored: &Event) -> bool {
    candidate.created_at > stored.created_at
        || (candidate.created_at == stored.created_at && candidate.id < stored.id)
}

fn control_event_is_persistent(event: &Event) -> bool {
    u16::from(event.kind) != FIPS_PEER_ADVERT_KIND
}

fn paid_offer_coordinate(event: &Event) -> Option<(u16, String, String)> {
    if u16::from(event.kind) != PAID_EXIT_OFFER_KIND {
        return None;
    }
    Some((
        u16::from(event.kind),
        event.pubkey.to_hex(),
        event.tags.identifier()?.to_string(),
    ))
}

fn retained_paid_offer_coordinate(event: &Event, now_secs: u64) -> Option<(u16, String, String)> {
    let (coordinate, is_live) = paid_offer_state(event, now_secs)?;
    is_live.then_some(coordinate)
}

fn paid_offer_state(event: &Event, now_secs: u64) -> Option<((u16, String, String), bool)> {
    let signed = SignedPaidRouteOffer::from_event(event.clone()).ok()?;
    Some((
        paid_offer_coordinate(&signed.event)?,
        signed.is_live_at(now_secs),
    ))
}

fn retained_rating_event(event: &Event, now_secs: u64) -> Option<(RatingEventStoreKey, u64)> {
    let (key, created_at) = rating_event_store_key(event)?;
    if created_at > now_secs.saturating_add(PEER_RATING_MAX_FUTURE_SKEW.as_secs())
        || now_secs.saturating_sub(created_at) > PEER_RATING_MAX_AGE.as_secs()
    {
        return None;
    }
    Some((key, created_at))
}

fn rating_event_store_key(event: &Event) -> Option<(RatingEventStoreKey, u64)> {
    if u16::from(event.kind) != RATING_FACT_KIND {
        return None;
    }
    let rating = rating_from_event(event).ok()?;
    if rating.scope.as_deref() == Some("vpn.exit")
        && PublicKey::parse(&rating.rater).ok() != Some(event.pubkey)
    {
        return None;
    }
    let subject = PublicKey::parse(&rating.subject).ok()?.to_hex();
    let scope = rating.scope?.trim().to_string();
    if scope.is_empty() {
        return None;
    }
    Some((
        RatingEventStoreKey {
            author: event.pubkey.to_hex(),
            subject,
            scope,
        },
        rating.created_at,
    ))
}

#[cfg(test)]
mod tests {
    use nostr_sdk::{EventBuilder, ToBech32};
    use nostr_social_graph::Rating;
    use nostr_social_memory::RatingEventExt;
    use nostr_vpn_core::paid_routes::{
        PAID_ROUTE_OFFER_TTL_SECS, PaidExitConfig, SignedPaidRouteOffer,
        signed_paid_exit_offer_from_config,
    };

    use super::*;

    #[test]
    fn rating_events_are_coalesced_by_author_subject_and_scope() {
        let author = Keys::generate();
        let subject = Keys::generate().public_key().to_hex();
        let update_events = test_update_events();
        let now = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, update_events).expect("event store");
        let older = rating_event(&author, &subject, "fips.peer", 20, now.saturating_sub(1));
        let newer = rating_event(&author, &subject, "fips.peer", 80, now);

        assert!(store.insert(older).expect("insert older rating"));
        assert!(store.insert(newer.clone()).expect("insert newer rating"));
        assert_eq!(store.snapshot(), vec![newer]);
        assert_eq!(store.rating_events.len(), 1);
    }

    #[test]
    fn stale_or_far_future_ratings_are_not_retained() {
        let author = Keys::generate();
        let subject = Keys::generate().public_key().to_hex();
        let update_events = test_update_events();
        let now = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, update_events).expect("event store");
        let stale = rating_event(
            &author,
            &subject,
            "fips.peer",
            20,
            now.saturating_sub(PEER_RATING_MAX_AGE.as_secs() + 1),
        );
        let future = rating_event(
            &author,
            &subject,
            "fips.peer",
            80,
            now.saturating_add(PEER_RATING_MAX_FUTURE_SKEW.as_secs() + 60),
        );

        assert!(!store.insert(stale).expect("reject stale rating"));
        assert!(!store.insert(future).expect("reject future rating"));
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn maintenance_prunes_ratings_that_age_out() {
        let author = Keys::generate();
        let subject = Keys::generate().public_key().to_hex();
        let update_events = test_update_events();
        let created_at = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, update_events).expect("event store");
        let rating = rating_event(&author, &subject, "fips.peer", 20, created_at);

        assert!(store.insert(rating).expect("insert rating"));
        assert_eq!(
            store
                .prune_expired_events(created_at + PEER_RATING_MAX_AGE.as_secs() + 1)
                .expect("prune ratings"),
            1
        );
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn paid_offer_refreshes_replace_the_same_author_and_identifier() {
        let seller = Keys::generate();
        let other_seller = Keys::generate();
        let now = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, test_update_events()).expect("event store");
        let older = paid_offer_event(&seller, "internet-exit", now.saturating_sub(1));
        let newer = paid_offer_event(&seller, "internet-exit", now);
        let other = paid_offer_event(&other_seller, "internet-exit", now);

        assert!(store.insert(older.clone()).expect("insert older offer"));
        assert!(store.insert(other.clone()).expect("insert other seller"));
        assert!(store.insert(newer.clone()).expect("insert refreshed offer"));
        assert!(!store.insert(older).expect("reject stale refresh"));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.contains(&newer));
        assert!(snapshot.contains(&other));
    }

    #[test]
    fn expired_replacement_withdraws_the_previous_paid_offer() {
        let seller = Keys::generate();
        let now = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, test_update_events()).expect("event store");
        let live = paid_offer_event(&seller, "internet-exit", now.saturating_sub(1));
        let offer = SignedPaidRouteOffer::from_event(live.clone())
            .expect("live signed offer")
            .offer()
            .expect("live offer");
        let withdrawal = SignedPaidRouteOffer::sign_expiring_at(offer, &seller, now, now)
            .expect("immediate tombstone")
            .event;

        assert!(store.insert(live).expect("insert live offer"));
        assert!(store.insert(withdrawal).expect("withdraw live offer"));
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn paid_offer_tombstone_rejects_out_of_order_live_replay() {
        let seller = Keys::generate();
        let now = now_ms() / 1_000;
        let live = paid_offer_event(&seller, "internet-exit", now.saturating_sub(1));
        let offer = SignedPaidRouteOffer::from_event(live.clone())
            .expect("live signed offer")
            .offer()
            .expect("live offer");
        let tombstone = SignedPaidRouteOffer::sign_expiring_at(offer, &seller, now, now)
            .expect("immediate tombstone")
            .event;
        let mut store = ControlEventStore::load(None, test_update_events()).expect("event store");

        assert!(store.insert(tombstone).expect("insert tombstone first"));
        assert!(!store.insert(live).expect("reject older live replay"));
        assert!(store.snapshot().is_empty());
        assert_eq!(store.paid_offer_watermarks.len(), 1);
        assert_eq!(
            store
                .prune_expired_events(now + PAID_ROUTE_OFFER_TTL_SECS - 1)
                .expect("retain watermark while an older offer could be live"),
            0
        );
        assert_eq!(
            store
                .prune_expired_events(now + PAID_ROUTE_OFFER_TTL_SECS)
                .expect("prune safe watermark"),
            1
        );
    }

    #[test]
    fn paid_offer_tombstone_survives_restart_without_becoming_visible() {
        let seller = Keys::generate();
        let now = now_ms() / 1_000;
        let live = paid_offer_event(&seller, "internet-exit", now.saturating_sub(1));
        let offer = SignedPaidRouteOffer::from_event(live.clone())
            .expect("live signed offer")
            .offer()
            .expect("live offer");
        let tombstone = SignedPaidRouteOffer::sign_expiring_at(offer, &seller, now, now)
            .expect("immediate tombstone")
            .event;
        let directory = std::env::temp_dir().join(format!(
            "nvpn-paid-offer-watermark-{}-{now}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("event store directory");
        let path = directory.join("control-events.json");
        let mut store =
            ControlEventStore::load(Some(path.clone()), test_update_events()).expect("event store");

        assert!(store.insert(tombstone.clone()).expect("persist tombstone"));
        assert!(store.snapshot().is_empty());
        let saved: StoredEventsFile =
            serde_json::from_slice(&fs::read(&path).expect("persisted store"))
                .expect("decode persisted store");
        assert!(saved.events.is_empty());
        assert_eq!(saved.paid_offer_watermarks, vec![tombstone]);

        let mut reloaded =
            ControlEventStore::load(Some(path), test_update_events()).expect("reload event store");
        assert!(reloaded.snapshot().is_empty());
        assert!(!reloaded.insert(live).expect("reject replay after restart"));
        fs::remove_dir_all(directory).expect("remove event store directory");
    }

    #[test]
    fn maintenance_prunes_expired_paid_offers() {
        let seller = Keys::generate();
        let signed_at = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, test_update_events()).expect("event store");
        let offer = paid_offer_event(&seller, "internet-exit", signed_at);

        assert!(store.insert(offer).expect("insert paid offer"));
        assert_eq!(
            store
                .prune_expired_events(signed_at + PAID_ROUTE_OFFER_TTL_SECS)
                .expect("prune expired events"),
            1
        );
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn peer_adverts_remain_in_memory_but_are_not_persisted() {
        let keys = Keys::generate();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nvpn-control-event-store-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("event store directory");
        let path = directory.join("control-events.json");
        let update_events = test_update_events();
        let mut store =
            ControlEventStore::load(Some(path.clone()), update_events).expect("event store");
        let advert = EventBuilder::new(Kind::Custom(FIPS_PEER_ADVERT_KIND), "")
            .sign_with_keys(&keys)
            .expect("signed peer advert");

        assert!(store.insert(advert.clone()).expect("insert peer advert"));
        assert_eq!(store.snapshot(), vec![advert.clone()]);
        assert!(!path.exists(), "ephemeral peer advert must not hit disk");

        let rating = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now_ms() / 1_000,
        );
        assert!(store.insert(rating.clone()).expect("insert rating"));
        let saved: StoredEventsFile =
            serde_json::from_slice(&fs::read(&path).expect("persisted store"))
                .expect("decode persisted store");
        assert_eq!(saved.events, vec![rating.clone()]);

        let legacy = StoredEventsFile {
            version: STORE_VERSION,
            events: vec![advert, rating.clone()],
            paid_offer_watermarks: Vec::new(),
        };
        fs::write(
            &path,
            serde_json::to_vec(&legacy).expect("encode legacy store"),
        )
        .expect("write legacy store");
        let reloaded = ControlEventStore::load(Some(path.clone()), test_update_events())
            .expect("reload event store");
        assert_eq!(reloaded.snapshot(), vec![rating.clone()]);
        let cleaned: StoredEventsFile =
            serde_json::from_slice(&fs::read(path).expect("cleaned store"))
                .expect("decode cleaned store");
        assert_eq!(cleaned.events, vec![rating]);
        fs::remove_dir_all(directory).expect("remove event store directory");
    }

    fn test_update_events() -> UpdateEventCache {
        let keys = Keys::generate();
        let reference = nostr_vpn_core::updater::UpdateRef {
            npub: keys.public_key().to_bech32().expect("npub"),
            tree_name: "test-root".to_string(),
            path: Some("latest".to_string()),
        };
        UpdateEventCache::new(&reference).expect("update event cache")
    }

    fn rating_event(
        author: &Keys,
        subject: &str,
        scope: &str,
        value: i64,
        created_at: u64,
    ) -> Event {
        let mut rating = Rating::new(author.public_key().to_hex(), subject, value, 0, 100);
        rating.scope = Some(scope.to_string());
        rating.created_at = created_at;
        rating.to_event(author).expect("signed rating")
    }

    fn paid_offer_event(author: &Keys, offer_id: &str, signed_at: u64) -> Event {
        let config = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        signed_paid_exit_offer_from_config(offer_id, author, &config, None, signed_at)
            .expect("signed paid offer")
            .event
    }
}
