#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: Deserialize<'de>"))]
struct StoredEventsFile<E = Event> {
    version: u8,
    events: Vec<E>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    paid_offer_watermarks: Vec<E>,
}

#[derive(Debug)]
struct ControlEventStore {
    graph_root: Option<PublicKey>,
    path: Option<PathBuf>,
    dirty: bool,
    events: HashMap<String, Event>,
    order: VecDeque<String>,
    encoded_events: HashMap<nostr_sdk::prelude::EventId, Box<serde_json::value::RawValue>>,
    paid_offer_watermarks: HashMap<(u16, String, String), Event>,
    rating_events: HashMap<RatingEventStoreKey, RatingEventStoreEntry>,
    #[cfg(feature = "updater")]
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

#[cfg(feature = "updater")]
fn configured_update_events() -> Result<UpdateEventCache> {
    let reference = configured_update_ref()?;
    UpdateEventCache::new(&reference).context("failed to configure update announcement cache")
}

async fn control_store_io<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .context("control pubsub storage task failed")?
}

async fn insert_control_event(
    events: &Arc<Mutex<ControlEventStore>>,
    event: Event,
) -> Result<bool> {
    // Keep writes serialized even if the awaiting task is cancelled: the
    // blocking operation retains the owned guard until its durable write ends.
    let mut store = Arc::clone(events).lock_owned().await;
    if store.path.is_none()
        || !control_event_is_persistent(&event)
        || (!store.dirty && store.events.contains_key(&event.id.to_hex()))
    {
        return store.insert(event);
    }
    control_store_io(move || store.insert(event)).await
}

async fn prune_control_events(
    events: &Arc<Mutex<ControlEventStore>>,
    now_secs: u64,
) -> Result<usize> {
    let mut store = Arc::clone(events).lock_owned().await;
    if store.path.is_none() {
        return store.prune_expired_events(now_secs);
    }
    control_store_io(move || store.prune_expired_events(now_secs)).await
}

async fn flush_control_events(events: &Arc<Mutex<ControlEventStore>>) -> Result<()> {
    let mut store = Arc::clone(events).lock_owned().await;
    if store.path.is_none() || !store.dirty {
        return store.persist();
    }
    control_store_io(move || store.persist()).await
}

impl ControlEventStore {
    #[cfg(any(feature = "paid-exit", test))]
    fn load(
        path: Option<PathBuf>,
        #[cfg(feature = "updater")] update_events: UpdateEventCache,
    ) -> Result<Self> {
        Self::load_for_owner(
            path,
            #[cfg(feature = "updater")]
            update_events,
            None,
        )
    }

    fn load_for_owner(
        path: Option<PathBuf>,
        #[cfg(feature = "updater")] update_events: UpdateEventCache,
        graph_root: Option<PublicKey>,
    ) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self {
                graph_root,
                path: None,
                dirty: false,
                events: HashMap::new(),
                order: VecDeque::new(),
                encoded_events: HashMap::new(),
                paid_offer_watermarks: HashMap::new(),
                rating_events: HashMap::new(),
                #[cfg(feature = "updater")]
                update_events,
            });
        };
        let mut store = Self {
            graph_root,
            path: Some(path.clone()),
            dirty: false,
            events: HashMap::new(),
            order: VecDeque::new(),
            encoded_events: HashMap::new(),
            paid_offer_watermarks: HashMap::new(),
            rating_events: HashMap::new(),
            #[cfg(feature = "updater")]
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
                && is_control_event(
                    &event,
                    #[cfg(feature = "updater")]
                    &store.update_events,
                )
                && control_event_is_persistent(&event)
            {
                let _ = store.insert_memory(event);
            }
        }
        for event in saved.paid_offer_watermarks {
            if event.verify().is_ok()
                && is_control_event(
                    &event,
                    #[cfg(feature = "updater")]
                    &store.update_events,
                )
                && u16::from(event.kind) == PAID_EXIT_OFFER_KIND
            {
                let _ = store.insert_memory(event);
            }
        }
        store.dirty = store.events.len() != saved_count
            || store.paid_offer_watermarks.len() != saved_watermark_count;
        store.persist()?;
        Ok(store)
    }

    fn insert(&mut self, event: Event) -> Result<bool> {
        let persistent = control_event_is_persistent(&event);
        let inserted = self.insert_memory(event);
        if persistent {
            self.persist()?;
        }
        Ok(inserted)
    }

    fn insert_memory(&mut self, event: Event) -> bool {
        if !is_control_event(
            &event,
            #[cfg(feature = "updater")]
            &self.update_events,
        ) {
            return false;
        }
        let event_id = event.id.to_hex();
        if self.events.contains_key(&event_id) {
            return false;
        }
        let now_secs = now_ms() / 1_000;
        if matches!(u16::from(event.kind), 0 | 3 | 10_000) {
            #[cfg(not(feature = "paid-exit"))]
            if self.graph_root.is_some_and(|root| root != event.pubkey) {
                return false;
            }
            if event.created_at.as_secs() > now_secs.saturating_add(300) {
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
            self.dirty = true;
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
        #[cfg(feature = "updater")]
        let is_update_event = self
            .update_events
            .filter()
            .match_event(&event, MatchEventOptions::new());
        #[cfg(feature = "updater")]
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
            let Some(remove_index) = self
                .order
                .iter()
                .position(|stored_id| {
                    self.events.get(stored_id).is_some_and(|stored| {
                        let evictable = !matches!(u16::from(stored.kind), 3 | 10_000);
                        #[cfg(feature = "updater")]
                        let evictable = evictable
                            && !self
                                .update_events
                                .filter()
                                .match_event(stored, MatchEventOptions::new());
                        evictable
                    })
                })
            else {
                // Only pinned roster and update events remain, so the insert
                // is rejected instead of evicting a pinned entry for it.
                return false;
            };
            let oldest = self
                .order
                .remove(remove_index)
                .expect("eviction index refers to an ordered event");
            self.remove_memory(&oldest);
        }
        self.order.push_back(event_id.clone());
        self.dirty |= control_event_is_persistent(&event);
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
        let Some(event) = self.events.remove(event_id) else {
            return false;
        };
        self.dirty |= control_event_is_persistent(&event);
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
            self.persist()?;
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
            self.dirty = true;
        }
        self.persist()?;
        Ok(remove.len() + hidden_watermarks_removed)
    }

    fn persist(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let Some(path) = self.path.as_deref() else {
            self.dirty = false;
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut paid_offer_watermarks = self.paid_offer_watermarks.values().collect::<Vec<_>>();
        paid_offer_watermarks.sort_by_key(|event| paid_offer_coordinate(event));
        let events = self
            .order
            .iter()
            .filter_map(|event_id| self.events.get(event_id))
            .filter(|event| control_event_is_persistent(event))
            .collect::<Vec<_>>();
        // Signed events are immutable by ID. Encode new records once instead
        // of converting every signature, key, and tag on each snapshot write.
        // Keep only encodings referenced by this exact snapshot, including
        // hidden paid-offer watermarks retained for replay protection.
        let retained_ids = events
            .iter()
            .chain(&paid_offer_watermarks)
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        self.encoded_events
            .retain(|id, _| retained_ids.contains(id));
        for event in events.iter().chain(&paid_offer_watermarks) {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.encoded_events.entry(event.id)
            {
                entry.insert(
                    serde_json::value::to_raw_value(*event)
                        .context("failed to encode control event")?,
                );
            }
        }
        let saved = StoredEventsFile {
            version: STORE_VERSION,
            events: events
                .iter()
                .map(|event| self.encoded_events[&event.id].as_ref())
                .collect(),
            paid_offer_watermarks: paid_offer_watermarks
                .iter()
                .map(|event| self.encoded_events[&event.id].as_ref())
                .collect(),
        };
        let bytes = serde_json::to_vec(&saved).context("failed to encode control pubsub store")?;
        crate::config::write_private_file_preserving_user_owner(path, &bytes)
            .with_context(|| format!("failed to write control pubsub store {}", path.display()))?;
        self.dirty = false;
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

include!("event_store_tests.rs");
