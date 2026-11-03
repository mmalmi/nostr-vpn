
fn paid_exit_offer_config(app: &AppConfig) -> Result<PaidExitConfig> {
    let mut config = app.paid_exit.clone();
    config.access.upstream = app.paid_exit_seller_egress()?.offer_upstream();
    if config.access.upstream == PaidExitUpstream::WireGuardExit {
        if !app.wireguard_exit.configured() {
            return Err(anyhow!(
                "paid exit is configured to resell a WireGuard upstream, but wireguard_exit is incomplete"
            ));
        }
        if !app.wireguard_exit.enabled {
            return Err(anyhow!(
                "paid exit is configured to resell a WireGuard upstream, but wireguard_exit is disabled"
            ));
        }
    }
    Ok(config)
}

fn set_paid_exit_upstream(app: &mut AppConfig, value: &str) -> Result<()> {
    let upstream = value
        .parse::<PaidExitUpstream>()
        .map_err(|error| anyhow!(error))?;
    app.paid_exit.access.upstream = upstream;
    app.set_internet_source(match upstream {
        PaidExitUpstream::HostDefault => InternetSource::Direct,
        PaidExitUpstream::WireGuardExit => InternetSource::WireGuard,
    });
    Ok(())
}

fn ensure_paid_exit_advertisable(app: &AppConfig) -> Result<()> {
    paid_exit_offer_config(app)?
        .channel
        .validate_seller_free_probe_budget()
}

const PAID_EXIT_SELLER_READY_TIMEOUT: Duration = Duration::from_secs(15);

async fn require_paid_exit_seller_daemon_ready(config_path: &Path, wait: bool) -> Result<()> {
    let deadline = Instant::now() + PAID_EXIT_SELLER_READY_TIMEOUT;
    loop {
        let status = daemon_status(config_path)
            .context("failed to inspect paid exit seller runtime")?;
        if !status.running {
            return Err(anyhow!(
                "cannot publish a paid exit offer: the nvpn daemon is not running"
            ));
        }
        if status
            .state
            .as_ref()
            .is_some_and(|state| state.paid_exit_seller_ready)
        {
            return Ok(());
        }
        if !wait || Instant::now() >= deadline {
            return Err(anyhow!(
                "cannot publish a paid exit offer: the FIPS listener and selected upstream are not ready"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
fn local_paid_exit_quality_hint() -> PaidRouteQualityMetrics {
    PaidRouteQualityMetrics {
        last_seen_unix: Some(unix_timestamp()),
        ..PaidRouteQualityMetrics::default()
    }
}

fn paid_exit_relay_urls(app: &AppConfig, overrides: &[String]) -> Vec<String> {
    let relays = if overrides.is_empty() {
        app.nostr.relays.clone()
    } else {
        overrides.to_vec()
    };
    let disabled = normalize_relay_urls(app.nostr.disabled_relays.clone())
        .into_iter()
        .collect::<HashSet<_>>();
    normalize_relay_urls(relays)
        .into_iter()
        .filter(|relay| !disabled.contains(relay))
        .collect()
}

fn paid_exit_retention_event_limit(requested_limit: usize, fallback_limit: usize) -> usize {
    if requested_limit == 0 {
        fallback_limit
    } else {
        requested_limit
    }
}

fn paid_exit_offer_retention_policy(
    limit: usize,
    since_unix: Option<u64>,
) -> nostr_pubsub::EventRetentionPolicy {
    nostr_pubsub::EventRetentionPolicy::new(
        paid_exit_retention_event_limit(limit, PAID_EXIT_OFFER_EVENT_CACHE_LIMIT),
        vec![paid_route_offer_filter(limit, since_unix)],
    )
}

#[cfg(test)]
fn paid_exit_rating_retention_policy(
    limit: usize,
    since_unix: Option<u64>,
    scope: &str,
) -> nostr_pubsub::EventRetentionPolicy {
    nostr_pubsub::EventRetentionPolicy::new(
        paid_exit_retention_event_limit(limit, PAID_EXIT_RATING_EVENT_LOOKUP_LIMIT),
        vec![paid_exit_rating_fact_filter(limit, since_unix, scope)],
    )
}

fn persist_paid_exit_offer_snapshot(
    store_path: &Path,
    signed: &SignedPaidRouteOffer,
    relays: &[String],
    offer: &PaidRouteOffer,
    seen_at_unix: u64,
) -> Result<bool> {
    update_paid_route_store(store_path, |store| {
        let mut changed =
            store.upsert_signed_offer(signed.clone(), relays.to_vec(), seen_at_unix)?;
        for mint in &offer.channel.accepted_mints {
            changed |= store.upsert_wallet_mint(mint, "", None, 0);
        }
        Ok(changed)
    })
}

fn persist_paid_exit_discovered_offers(
    store_path: &Path,
    offers: &[SignedPaidRouteOffer],
    relays: &[String],
    rating_scores: Option<&HashMap<String, PaidExitRatingScore>>,
) -> Result<usize> {
    update_paid_route_store(store_path, |store| {
        let mut changed_count = 0usize;
        let seen_at_unix = unix_timestamp();
        for signed in offers {
            let offer = signed.offer()?;
            let mut changed =
                store.upsert_signed_offer(signed.clone(), relays.to_vec(), seen_at_unix)?;
            if let Some(score) = rating_scores.and_then(|scores| scores.get(&offer.seller_npub)) {
                changed |= store.upsert_offer_rating_score(
                    &offer.seller_npub,
                    score.score,
                    score.created_at,
                );
            }
            if changed {
                changed_count += 1;
            }
        }
        Ok(changed_count)
    })
}

fn publish_paid_exit_control_event(
    app: &AppConfig,
    config_path: &Path,
    event: &Event,
) -> Result<serde_json::Value> {
    if !app.nostr.pubsub.enabled() {
        return Err(anyhow!(
            "nostr.pubsub.mode is off; set it to client or relay before publishing"
        ));
    }
    let queued = crate::control_pubsub_runtime::queue_control_pubsub_event(config_path, event)?;
    Ok(json!({
        "event_id": event.id.to_string(),
        "nostr_pubsub_enabled": true,
        "nostr_pubsub_queued": queued,
        "nostr_pubsub_outbox": crate::control_pubsub_runtime::control_pubsub_outbox_directory(config_path),
    }))
}

fn publish_paid_exit_offer_pubsub(
    app: &AppConfig,
    config_path: &Path,
    signed: &SignedPaidRouteOffer,
) -> Result<serde_json::Value> {
    publish_paid_exit_control_event(app, config_path, &signed.event)
}

fn publish_paid_exit_rating_event_pubsub(
    app: &AppConfig,
    config_path: &Path,
    event: &Event,
) -> Result<serde_json::Value> {
    publish_paid_exit_control_event(app, config_path, event)
}
