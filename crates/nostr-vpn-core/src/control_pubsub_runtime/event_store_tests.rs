#[cfg(all(test, feature = "updater"))]
mod tests {
    #[cfg(feature = "paid-exit")]
    use crate::paid_routes::{
        PAID_ROUTE_OFFER_TTL_SECS, PaidExitConfig, SignedPaidRouteOffer,
        signed_paid_exit_offer_from_config,
    };
    use nostr_sdk::{EventBuilder, ToBech32};
    use nostr_social_graph::Rating;
    use nostr_social_memory::RatingEventExt;

    use super::*;

    fn async_store_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nvpn-control-store-async-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("store directory");
        directory
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_store_async_keeps_runtime_progress_during_durable_work() {
        let directory = async_store_directory();
        let path = directory.join("events.json");
        let keys = Keys::generate();
        let event = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now_ms() / 1_000,
        );
        let expected = event.clone();
        let stored_path = path.clone();
        let (started, ready) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let write = control_store_io(move || {
            let mut store = ControlEventStore::load(Some(stored_path), test_update_events())?;
            let _ = started.send(());
            // Model a slow filesystem operation at the production blocking
            // boundary. The async runtime must run before this work completes.
            released
                .recv_timeout(Duration::from_secs(1))
                .context("async runtime did not progress while storage was busy")?;
            store.insert(event)
        });
        let progress = async {
            ready.await.expect("storage operation started");
            release.send(()).is_ok()
        };
        let (written, progressed) = tokio::join!(write, progress);
        let reloaded = ControlEventStore::load(Some(path), test_update_events());
        fs::remove_dir_all(&directory).expect("remove store directory");
        assert!(progressed, "async runtime must run while storage is busy");
        assert!(written.expect("durable write"));
        assert_eq!(
            reloaded.expect("reload durable store").snapshot(),
            vec![expected]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_store_async_insert_preserves_durability_and_memory_only_events() {
        let directory = async_store_directory();
        let path = directory.join("events.json");
        let events = Arc::new(Mutex::new(
            ControlEventStore::load(Some(path.clone()), test_update_events()).unwrap(),
        ));
        let keys = Keys::generate();
        let rating = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now_ms() / 1_000,
        );
        assert!(insert_control_event(&events, rating.clone()).await.unwrap());
        let saved = fs::read(&path).expect("write must be complete when insert returns");
        assert!(!insert_control_event(&events, rating.clone()).await.unwrap());
        let advert = EventBuilder::new(nostr_sdk::Kind::Custom(FIPS_PEER_ADVERT_KIND), "")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(insert_control_event(&events, advert).await.unwrap());
        assert_eq!(events.lock().await.snapshot().len(), 2);
        assert_eq!(fs::read(&path).unwrap(), saved);
        let reloaded = ControlEventStore::load(Some(path), test_update_events()).unwrap();
        fs::remove_dir_all(&directory).unwrap();
        assert_eq!(reloaded.snapshot(), vec![rating]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_store_async_duplicate_local_event_flushes_received_batch() {
        let directory = async_store_directory();
        let path = directory.join("events.json");
        let events = Arc::new(Mutex::new(
            ControlEventStore::load(Some(path.clone()), test_update_events()).unwrap(),
        ));
        let keys = Keys::generate();
        let local = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now_ms() / 1_000,
        );
        assert!(insert_control_event(&events, local.clone()).await.unwrap());
        let received = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            70,
            now_ms() / 1_000,
        );
        assert!(events.lock().await.insert_memory(received.clone()));
        assert!(!insert_control_event(&events, local).await.unwrap());
        let reloaded = ControlEventStore::load(Some(path), test_update_events()).unwrap();
        fs::remove_dir_all(directory).unwrap();
        assert_eq!(reloaded.snapshot().len(), 2);
        assert!(reloaded.snapshot().contains(&received));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_store_async_reports_durable_write_errors() {
        let directory = async_store_directory();
        let blocked = directory.join("not-a-directory");
        fs::write(&blocked, b"occupied").unwrap();
        let mut store = ControlEventStore::load(None, test_update_events()).unwrap();
        store.path = Some(blocked.join("events.json"));
        let events = Arc::new(Mutex::new(store));
        let keys = Keys::generate();
        let event = rating_event(
            &keys,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now_ms() / 1_000,
        );
        let result = insert_control_event(&events, event).await;
        fs::remove_dir_all(&directory).unwrap();
        assert!(
            result.is_err(),
            "failed durable write must reach the caller"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn control_store_async_cancelled_waiter_cannot_reorder_writes() {
        let directory = async_store_directory();
        let path = directory.join("events.json");
        let events = Arc::new(Mutex::new(
            ControlEventStore::load(Some(path.clone()), test_update_events()).unwrap(),
        ));
        let keys = Keys::generate();
        let subject = Keys::generate().public_key().to_hex();
        let now = now_ms() / 1_000;
        let older = rating_event(&keys, &subject, "fips.peer", 20, now - 1);
        let newer = rating_event(&keys, &subject, "fips.peer", 80, now);
        let mut guard = Arc::clone(&events).lock_owned().await;
        let (started, ready) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let first = tokio::spawn(control_store_io(move || {
            let _ = started.send(());
            released.recv_timeout(Duration::from_secs(1))?;
            guard.insert(older)
        }));
        ready.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let second = insert_control_event(&events, newer.clone());
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "the first write must keep ownership until its durable completion"
        );
        release.send(()).unwrap();
        assert!(second.await.unwrap());
        let reloaded = ControlEventStore::load(Some(path), test_update_events()).unwrap();
        fs::remove_dir_all(&directory).unwrap();
        assert_eq!(reloaded.snapshot(), vec![newer]);
    }

    #[test]
    fn maintenance_flushes_received_events_once_and_retries_failed_writes() {
        let author = Keys::generate();
        let now = now_ms() / 1_000;
        let directory = std::env::temp_dir().join(format!(
            "nvpn-control-event-batch-{}-{}",
            std::process::id(),
            author.public_key()
        ));
        fs::create_dir_all(&directory).expect("event store directory");
        let path = directory.join("control-events.json");
        let mut store =
            ControlEventStore::load(Some(path.clone()), test_update_events()).expect("event store");
        for _ in 0..2 {
            assert!(store.insert_memory(rating_event(
                &author,
                &Keys::generate().public_key().to_hex(),
                "fips.peer",
                50,
                now,
            )));
        }
        assert!(!path.exists(), "received events wait for maintenance");
        store
            .prune_expired_events(now)
            .expect("flush received batch");
        let reloaded = ControlEventStore::load(Some(path.clone()), test_update_events())
            .expect("reload received events");
        assert_eq!(reloaded.snapshot(), store.snapshot());

        fs::rename(&path, directory.join("previous.json")).expect("move saved cache");
        fs::create_dir(&path).expect("block cache writes");
        store
            .prune_expired_events(now)
            .expect("unchanged cache must not be rewritten");
        assert!(store.insert_memory(rating_event(
            &author,
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now,
        )));
        assert!(store.prune_expired_events(now).is_err());
        fs::remove_dir(&path).expect("restore writable cache path");
        store
            .prune_expired_events(now)
            .expect("retry received batch");
        let reloaded = ControlEventStore::load(Some(path), test_update_events())
            .expect("reload retried events");
        assert_eq!(reloaded.snapshot(), store.snapshot());
        fs::remove_dir_all(directory).expect("remove event store directory");
    }

    #[test]
    fn cached_event_encoding_preserves_snapshots_and_releases_replaced_records() {
        let author = Keys::generate();
        let subject = Keys::generate().public_key().to_hex();
        let now = now_ms() / 1_000;
        let directory = std::env::temp_dir().join(format!(
            "nvpn-control-encoding-{}-{}",
            std::process::id(),
            author.public_key()
        ));
        let path = directory.join("control-events.json");
        let mut store =
            ControlEventStore::load(Some(path.clone()), test_update_events()).expect("event store");
        let older = rating_event(&author, &subject, "fips.peer", 20, now.saturating_sub(1));
        let newer = rating_event(&author, &subject, "fips.peer", 80, now);
        assert!(store.insert(older.clone()).expect("save initial rating"));
        assert!(store.insert(newer.clone()).expect("replace rating"));
        assert_eq!(store.encoded_events.len(), 1, "replaced bytes are released");
        assert!(!store.encoded_events.contains_key(&older.id));

        let expected = StoredEventsFile {
            version: STORE_VERSION,
            events: vec![newer],
            paid_offer_watermarks: vec![],
        };
        assert_eq!(
            fs::read(&path).expect("saved bytes"),
            serde_json::to_vec(&expected).expect("canonical event encoding")
        );
        let reloaded = ControlEventStore::load(Some(path.clone()), test_update_events())
            .expect("reload encoded events");
        assert_eq!(reloaded.snapshot(), store.snapshot());

        assert_eq!(
            store
                .prune_expired_events(now + PEER_RATING_MAX_AGE.as_secs() + 1)
                .expect("expire cached rating"),
            1
        );
        assert!(
            store.encoded_events.is_empty(),
            "expired bytes are released"
        );
        let reloaded =
            ControlEventStore::load(Some(path), test_update_events()).expect("reload empty cache");
        assert!(reloaded.snapshot().is_empty());
        fs::remove_dir_all(directory).expect("remove event store directory");
    }

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
    #[cfg(feature = "paid-exit")]
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
    #[cfg(feature = "paid-exit")]
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
    #[cfg(feature = "paid-exit")]
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
    #[cfg(feature = "paid-exit")]
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
    #[cfg(feature = "paid-exit")]
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

    #[test]
    fn full_store_of_pinned_events_rejects_new_events_instead_of_evicting_pins() {
        let now = now_ms() / 1_000;
        let mut store = ControlEventStore::load(None, test_update_events()).expect("event store");
        let mut pinned_ids = Vec::new();
        for _ in 0..STORE_MAX_EVENTS / 2 {
            let author = Keys::generate();
            for kind in [Kind::ContactList, Kind::Custom(10_000)] {
                let event = EventBuilder::new(kind, "")
                    .sign_with_keys(&author)
                    .expect("signed pinned event");
                assert!(store.insert_memory(event.clone()), "store pinned event");
                pinned_ids.push(event.id.to_hex());
            }
        }
        assert_eq!(store.events.len(), STORE_MAX_EVENTS);

        // Every stored entry is pinned, so a new event is rejected and the
        // pinned roster entries survive instead of being evicted for it.
        let rejected = rating_event(
            &Keys::generate(),
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now,
        );
        assert!(!store.insert_memory(rejected));
        assert_eq!(store.events.len(), STORE_MAX_EVENTS);
        assert!(pinned_ids.iter().all(|id| store.events.contains_key(id)));

        // While an evictable entry sits at the cap, insertion still evicts it
        // and leaves the pinned entries alone.
        let mut mixed = ControlEventStore::load(None, test_update_events()).expect("event store");
        for pin in 0..STORE_MAX_EVENTS - 1 {
            let author = Keys::generate();
            let kind = if pin % 2 == 0 {
                Kind::ContactList
            } else {
                Kind::Custom(10_000)
            };
            let event = EventBuilder::new(kind, "")
                .sign_with_keys(&author)
                .expect("signed pinned event");
            assert!(mixed.insert_memory(event), "store pinned event");
        }
        let oldest = rating_event(
            &Keys::generate(),
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            50,
            now,
        );
        assert!(mixed.insert_memory(oldest.clone()));
        assert_eq!(mixed.events.len(), STORE_MAX_EVENTS);
        let newest = rating_event(
            &Keys::generate(),
            &Keys::generate().public_key().to_hex(),
            "fips.peer",
            80,
            now,
        );
        assert!(mixed.insert_memory(newest.clone()));
        assert_eq!(mixed.events.len(), STORE_MAX_EVENTS);
        assert!(!mixed.events.contains_key(&oldest.id.to_hex()));
        assert!(mixed.events.contains_key(&newest.id.to_hex()));
        assert_eq!(
            mixed
                .events
                .values()
                .filter(|stored| matches!(u16::from(stored.kind), 3 | 10_000))
                .count(),
            STORE_MAX_EVENTS - 1,
            "pinned entries must outlive both rating inserts"
        );
    }

    fn test_update_events() -> UpdateEventCache {
        let keys = Keys::generate();
        let reference = crate::updater::UpdateRef {
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

    #[cfg(feature = "paid-exit")]
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
