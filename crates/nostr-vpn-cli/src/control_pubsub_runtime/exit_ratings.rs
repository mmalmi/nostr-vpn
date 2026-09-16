#[cfg(feature = "paid-exit")]
pub fn flush_exit_ratings(config_path: &Path) -> Result<usize> {
    use nostr_vpn_core::paid_route_store::{
        load_paid_route_store, paid_route_store_file_path, update_paid_route_store,
    };
    let path = paid_route_store_file_path(config_path);
    let pending = load_paid_route_store(&path)?.pending_exit_ratings();
    let mut queued = 0;
    for event in pending
        .into_iter()
        .filter(|event| {
            nostr_vpn_core::paid_route_ratings::verified_exit_rating(event, now_ms() / 1000).is_ok()
        })
        .take(8)
    {
        queue_control_pubsub_event(config_path, &event)?;
        update_paid_route_store(&path, |store| {
            store.mark_exit_rating_queued(&event.id.to_hex());
            Ok(())
        })?;
        queued += 1;
    }
    Ok(queued)
}

#[cfg(all(test, feature = "paid-exit"))]
mod exit_rating_publication_tests {
    use super::*;
    use nostr_vpn_core::paid_route_ratings::{EXIT_RATING_SCOPE, verified_exit_rating};
    use nostr_vpn_core::paid_route_store::{
        load_paid_route_store, paid_route_store_file_path, update_paid_route_store,
    };

    #[test]
    fn automatic_publication_is_durable_idempotent_and_rating_only() {
        let keys = Keys::generate();
        let seller = Keys::generate().public_key().to_hex();
        let dir = std::env::temp_dir().join(format!(
            "exit-rating-outbox-{}-{}",
            std::process::id(),
            keys.public_key()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        let path = paid_route_store_file_path(&config);
        let now = now_ms() / 1000;
        update_paid_route_store(&path, |store| {
            store.record_exit_rating(&keys, &seller, 80, false, now)?;
            store.record_exit_rating(
                &keys,
                &Keys::generate().public_key().to_hex(),
                80,
                false,
                now - nostr_vpn_core::paid_route_ratings::EXIT_RATING_MAX_AGE - 1,
            )?;
            Ok(())
        })
        .unwrap();
        assert_eq!(flush_exit_ratings(&config).unwrap(), 1);
        assert_eq!(flush_exit_ratings(&config).unwrap(), 0);
        let queued: Vec<_> = fs::read_dir(control_pubsub_outbox_directory(&config))
            .unwrap()
            .collect();
        assert_eq!(queued.len(), 1);
        let event: Event =
            serde_json::from_slice(&fs::read(queued[0].as_ref().unwrap().path()).unwrap()).unwrap();
        let rating = verified_exit_rating(&event, now).unwrap();
        assert_eq!(rating.scope.as_deref(), Some(EXIT_RATING_SCOPE));
        assert_eq!(rating.rating, 80);
        assert!(rating.evidence.is_empty());
        assert!(event.content.is_empty());
        for tag in event.tags.iter() {
            assert!(
                ![
                    "latency",
                    "jitter",
                    "packet_loss",
                    "ip",
                    "session",
                    "payment",
                    "context"
                ]
                .contains(&tag.as_slice()[0].as_str())
            );
        }
        // An acknowledgment for an older event must not lose a newer opinion.
        update_paid_route_store(&path, |store| {
            store.record_exit_rating(&keys, &seller, -100, true, now + 1)?;
            store.mark_exit_rating_queued(&event.id.to_hex());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            load_paid_route_store(&path)
                .unwrap()
                .pending_exit_ratings()
                .iter()
                .filter(|event| verified_exit_rating(event, now + 1).is_ok())
                .count(),
            1
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
