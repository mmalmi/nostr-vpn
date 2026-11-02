fn paid_exit_status_snapshot_json(
    app: &AppConfig,
    store_path: &Path,
    store: &PaidRouteStore,
) -> Result<serde_json::Value> {
    let now_unix = unix_timestamp();
    let offers = store
        .offers
        .iter()
        .map(|(key, record)| {
            let mut value = json!({
                "key": key,
                "offer": record.offer,
                "event_id": record.signed_offer.event.id.to_string(),
                "live": record.signed_offer.is_live_at(now_unix),
                "relays": record.relay_urls,
                "first_seen_unix": record.first_seen_unix,
                "last_seen_unix": record.last_seen_unix,
                "personal_rating": store.personal_exit_rating(&record.offer.seller_npub),
                "avoided": store.exit_provider_is_avoided(&record.offer.seller_npub),
            });
            if let Some(score) = record.rating_score {
                value["rating_score"] = json!(score);
                value["rating_updated_at_unix"] = json!(record.rating_updated_at_unix);
            }
            value
        })
        .collect::<Vec<_>>();
    let channels = store
        .channels
        .values()
        .map(paid_exit_channel_status_json)
        .collect::<Vec<_>>();
    let sessions = store
        .sessions
        .values()
        .map(|record| paid_exit_session_status_json(record, store, &app.paid_exit, now_unix))
        .collect::<Vec<_>>();
    let seller_admissions = store.seller_admissions(&app.paid_exit, now_unix);
    let seller_collection = store.seller_collection_states(&app.paid_exit, now_unix);
    let seller_summary = paid_exit_seller_cli_summary(&app.paid_exit, store);
    let pending_buyer_credit_msat =
        paid_exit_seller_pending_buyer_credit_msat(&app.paid_exit, store);
    let auto_collect_due_msat = seller_collection
        .iter()
        .filter(|state| state.auto_collect_due)
        .map(|state| state.paid_msat)
        .fold(0_u64, u64::saturating_add);
    let (seller_npub, provider_link) = paid_exit_seller_identity(app)?;

    Ok(json!({
        "seller_npub": seller_npub,
        "provider_link": provider_link,
        "config": paid_exit_status_json(app),
        "store_path": store_path.display().to_string(),
        "wallet": store.wallet,
        "seller_accounting": {
            "pending_buyer_credit_msat": pending_buyer_credit_msat,
            "pending_buyer_credit_text": paid_exit_msat_text(pending_buyer_credit_msat),
            "pending_buyer_credit_help_text": paid_exit_pending_buyer_credit_help_text(pending_buyer_credit_msat),
            "collectable_channel_count": seller_collection.iter().filter(|state| state.collectable).count(),
            "auto_collect_due_count": seller_collection.iter().filter(|state| state.auto_collect_due).count(),
            "auto_collect_due_msat": auto_collect_due_msat,
            "auto_collect_due_text": paid_exit_msat_text(auto_collect_due_msat),
            "current_connection_count": seller_summary.current_connection_count,
            "past_connection_count": seller_summary.past_connection_count,
            "total_billable_bytes": seller_summary.total_billable_bytes,
            "total_traffic_text": paid_exit_usage_text(seller_summary.total_billable_bytes),
            "total_paid_msat": seller_summary.total_paid_msat,
            "total_paid_text": paid_exit_msat_text(seller_summary.total_paid_msat),
            "total_due_msat": seller_summary.total_due_msat,
            "total_due_text": paid_exit_msat_text(seller_summary.total_due_msat),
            "total_unpaid_msat": seller_summary.total_unpaid_msat,
            "total_unpaid_text": paid_exit_msat_text(seller_summary.total_unpaid_msat),
        },
        "counts": {
            "offers": store.offers.len(),
            "quotes": store.quotes.len(),
            "leases": store.leases.len(),
            "channels": store.channels.len(),
            "sessions": store.sessions.len(),
        },
        "offers": offers,
        "channels": channels,
        "sessions": sessions,
        "seller_admissions": seller_admissions,
        "seller_collection": seller_collection.iter().map(paid_exit_seller_collection_status_json).collect::<Vec<_>>(),
    }))
}

fn paid_exit_channel_status_json(channel: &PaidRouteChannelRecord) -> serde_json::Value {
    json!({
        "channel_id": channel.channel_id,
        "offer_id": channel.offer_id,
        "role": paid_route_channel_role_text(channel.role),
        "status": paid_route_lifecycle_status_text(channel.status),
        "payment": {
            "mode": channel.payment.mode.clone().as_str(),
            "channel_id": channel.payment.channel_id,
            "cashu_unit": channel.payment.cashu_unit,
            "capacity_sat": channel.payment.capacity_sat,
            "paid_msat": channel.payment.paid_msat,
            "updated_at_unix": channel.payment.updated_at_unix,
            "cashu_spilman": paid_exit_spilman_payment_status_json(
                channel.payment.cashu_spilman_payment.as_ref()
            ),
            "cashu_token_lease": paid_exit_token_lease_status_json(
                channel.payment.cashu_token_lease.as_ref()
            ),
        },
        "mint_url": channel.mint_url,
        "counterparty_npub": channel.counterparty_npub,
        "created_at_unix": channel.created_at_unix,
        "updated_at_unix": channel.updated_at_unix,
        "expires_at_unix": channel.expires_at_unix,
        "error": channel.error,
    })
}

fn paid_exit_spilman_payment_status_json(
    payment: Option<&CashuSpilmanPayment>,
) -> serde_json::Value {
    match payment {
        Some(payment) => json!({
            "channel_id": payment.channel_id,
            "balance": payment.balance,
            "has_signature": !payment.signature.trim().is_empty(),
            "has_funding": payment.has_funding(),
        }),
        None => serde_json::Value::Null,
    }
}

fn paid_exit_spilman_receiver_mode(processing_available: bool) -> &'static str {
    if processing_available {
        "processing"
    } else {
        "claim_only"
    }
}

fn paid_exit_token_lease_status_json(
    token_lease: Option<&StreamingRouteCashuTokenLease>,
) -> serde_json::Value {
    match token_lease {
        Some(token_lease) => json!({
            "channel_id": token_lease.channel_id,
            "mint_url": token_lease.mint_url,
            "unit": token_lease.unit,
            "amount": token_lease.amount,
            "paid_msat": token_lease.paid_msat,
            "expires_unix": token_lease.expires_unix,
            "has_token": !token_lease.token.trim().is_empty(),
        }),
        None => serde_json::Value::Null,
    }
}

fn paid_exit_session_status_json(
    record: &PaidRouteSessionRecord,
    store: &PaidRouteStore,
    seller_config: &PaidExitConfig,
    now_unix: u64,
) -> serde_json::Value {
    let session = &record.session;
    let session_config = paid_exit_session_config(store, record);
    let country_claim = paid_route_country_claim(
        session_config
            .as_ref()
            .map(|config| config.location.country_code.as_str())
            .unwrap_or_default(),
        session.observed_country_code.as_deref(),
    );
    let decision = session_config.map(|config| {
        let decision = session.routing_decision(&config);
        json!({
            "state": decision.state.as_str(),
            "allow_routing": decision.allow_routing,
            "shared_internet": paid_exit_shared_internet_text(&decision),
            "delivered_units": decision.delivered_units,
            "paid_msat": decision.paid_msat,
            "amount_due_msat": decision.amount_due_msat,
            "enforced_amount_due_msat": decision.enforced_amount_due_msat,
            "unpaid_msat": decision.unpaid_msat,
            "free_probe_remaining_units": decision.free_probe_remaining_units,
            "grace_remaining_units": decision.grace_remaining_units,
        })
    });
    let collection =
        store.seller_collection_state_for_session(seller_config, now_unix, &session.session_id);

    json!({
        "session_id": session.session_id,
        "manual_auto_renew": store.manual_renewal_session_id == session.session_id,
        "lease_id": session.lease_id,
        "channel_id": session.payment.channel_id,
        "created_at_unix": record.created_at_unix,
        "updated_at_unix": record.updated_at_unix,
        "usage": session.usage,
        "payment": {
            "mode": session.payment.mode.clone().as_str(),
            "channel_id": session.payment.channel_id,
            "cashu_unit": session.payment.cashu_unit,
            "capacity_sat": session.payment.capacity_sat,
            "paid_msat": session.payment.paid_msat,
            "updated_at_unix": session.payment.updated_at_unix,
            "cashu_spilman": paid_exit_spilman_payment_status_json(
                session.payment.cashu_spilman_payment.as_ref()
            ),
            "cashu_token_lease": paid_exit_token_lease_status_json(
                session.payment.cashu_token_lease.as_ref()
            ),
        },
        "routing": decision,
        "collection": paid_exit_session_collection_status_json(collection.as_ref()),
        "realized_exit_ip": session.realized_exit_ip,
        "observed_country_code": session.observed_country_code,
        "observed_asn": session.observed_asn,
        "claimed_country_code": country_claim.claimed_country_code,
        "country_claim": {
            "claimed_country_code": country_claim.claimed_country_code,
            "observed_country_code": country_claim.observed_country_code,
            "status": country_claim.status.as_str(),
            "matches": country_claim.matches_claim(),
        },
        "quality": session.quality,
    })
}

fn paid_exit_session_collection_status_json(
    state: Option<&PaidRouteSellerCollectionState>,
) -> serde_json::Value {
    match state {
        Some(state) => paid_exit_seller_collection_status_json(state),
        None => serde_json::Value::Null,
    }
}

fn paid_exit_seller_collection_status_json(
    state: &PaidRouteSellerCollectionState,
) -> serde_json::Value {
    json!({
        "buyer_npub": state.buyer_npub,
        "session_id": state.session_id,
        "lease_id": state.lease_id,
        "channel_id": state.channel_id,
        "collectable": state.collectable,
        "manual_collect": state.manual_collect,
        "auto_collect_due": state.auto_collect_due,
        "reason": state.reason,
        "paid_msat": state.paid_msat,
        "paid_text": paid_exit_msat_text(state.paid_msat),
        "expires_at_unix": state.expires_at_unix,
        "due_at_unix": state.due_at_unix,
        "updated_at_unix": state.updated_at_unix,
    })
}

#[derive(Default)]
struct PaidExitSellerCliSummary {
    current_connection_count: u64,
    past_connection_count: u64,
    total_billable_bytes: u64,
    total_paid_msat: u64,
    total_due_msat: u64,
    total_unpaid_msat: u64,
}

fn paid_exit_seller_cli_summary(
    config: &PaidExitConfig,
    store: &PaidRouteStore,
) -> PaidExitSellerCliSummary {
    let seller_channel_ids = store
        .channels
        .values()
        .filter(|channel| channel.role == PaidRouteChannelRole::Seller)
        .map(|channel| channel.channel_id.clone())
        .collect::<HashSet<_>>();
    let mut summary = PaidExitSellerCliSummary::default();
    for record in store.sessions.values() {
        if !seller_channel_ids.contains(&record.session.payment.channel_id) {
            continue;
        }
        let decision = record.session.routing_decision(config);
        let channel_is_current = store
            .channels
            .get(&record.session.payment.channel_id)
            .is_some_and(|channel| paid_route_lifecycle_is_current(channel.status));
        if decision.allow_routing && channel_is_current {
            summary.current_connection_count = summary.current_connection_count.saturating_add(1);
        } else {
            summary.past_connection_count = summary.past_connection_count.saturating_add(1);
        }
        summary.total_billable_bytes = summary
            .total_billable_bytes
            .saturating_add(record.session.usage.total_bytes());
        summary.total_paid_msat = summary
            .total_paid_msat
            .saturating_add(record.session.payment.paid_msat);
        summary.total_due_msat = summary
            .total_due_msat
            .saturating_add(decision.amount_due_msat);
        summary.total_unpaid_msat = summary
            .total_unpaid_msat
            .saturating_add(decision.unpaid_msat);
    }
    summary
}

fn print_paid_exit_status_snapshot(
    app: &AppConfig,
    store_path: &Path,
    store: &PaidRouteStore,
) -> Result<()> {
    let now_unix = unix_timestamp();
    print_paid_exit_status(app);
    let (seller_npub, provider_link) = paid_exit_seller_identity(app)?;
    println!("paid_exit_seller: {seller_npub}");
    println!("paid_exit_provider_link: {provider_link}");
    println!("paid_exit_store: {}", store_path.display());
    println!(
        "paid_exit_store_counts: offers={} quotes={} leases={} channels={} sessions={}",
        store.offers.len(),
        store.quotes.len(),
        store.leases.len(),
        store.channels.len(),
        store.sessions.len()
    );
    print_paid_exit_wallet(store);
    let pending_buyer_credit_msat =
        paid_exit_seller_pending_buyer_credit_msat(&app.paid_exit, store);
    let seller_collection = store.seller_collection_states(&app.paid_exit, now_unix);
    let seller_summary = paid_exit_seller_cli_summary(&app.paid_exit, store);
    let auto_collect_due_msat = seller_collection
        .iter()
        .filter(|state| state.auto_collect_due)
        .map(|state| state.paid_msat)
        .fold(0_u64, u64::saturating_add);
    if app.paid_exit.enabled || pending_buyer_credit_msat > 0 {
        let help = paid_exit_pending_buyer_credit_help_text(pending_buyer_credit_msat);
        if help.is_empty() {
            println!(
                "paid_exit_pending_buyer_credit: {}",
                paid_exit_msat_text(pending_buyer_credit_msat)
            );
        } else {
            println!(
                "paid_exit_pending_buyer_credit: {} ({help})",
                paid_exit_msat_text(pending_buyer_credit_msat)
            );
        }
        if auto_collect_due_msat > 0 {
            println!(
                "paid_exit_collect_due: {} across {} channel(s)",
                paid_exit_msat_text(auto_collect_due_msat),
                seller_collection
                    .iter()
                    .filter(|state| state.auto_collect_due)
                    .count()
            );
        }
        println!(
            "paid_exit_seller_summary: connected={} past={} traffic={} paid={} due={} unpaid={}",
            seller_summary.current_connection_count,
            seller_summary.past_connection_count,
            paid_exit_usage_text(seller_summary.total_billable_bytes),
            paid_exit_msat_text(seller_summary.total_paid_msat),
            paid_exit_msat_text(seller_summary.total_due_msat),
            paid_exit_msat_text(seller_summary.total_unpaid_msat),
        );
    }

    if !store.offers.is_empty() {
        println!("paid_exit_offers:");
        for (key, record) in &store.offers {
            let offer = &record.offer;
            let rating_text = record
                .rating_score
                .map(|score| format!(" rating_score={score:+}"))
                .unwrap_or_default();
            let personal_text = match store.personal_exit_rating(&offer.seller_npub) {
                -1 => " your_rating=down avoided=true",
                1 => " your_rating=up",
                _ => "",
            };
            println!(
                "  {key} price={} country={} upstream={} live={} last_seen={}{}{}",
                paid_exit_price_text(offer.pricing.price_msat_per_gb),
                display_or_none(&offer.location.country_code),
                offer.access.upstream.as_str(),
                record.signed_offer.is_live_at(now_unix),
                record.last_seen_unix,
                rating_text,
                personal_text
            );
        }
    }

    if !store.channels.is_empty() {
        println!("paid_exit_channels:");
        for channel in store.channels.values() {
            println!(
                "  {} role={} status={} mode={} paid={} capacity={} counterparty={} mint={} expires_at={}{}",
                channel.channel_id,
                paid_route_channel_role_text(channel.role),
                paid_route_lifecycle_status_text(channel.status),
                channel.payment.mode.clone().as_str(),
                paid_exit_msat_text(channel.payment.paid_msat),
                paid_exit_sat_text(channel.payment.capacity_sat),
                display_or_none(&channel.counterparty_npub),
                display_or_none(&channel.mint_url),
                channel.expires_at_unix,
                paid_exit_error_suffix(&channel.error),
            );
        }
    }

    if !store.sessions.is_empty() {
        println!("paid_exit_sessions:");
        for record in store.sessions.values() {
            let session = &record.session;
            let session_config = paid_exit_session_config(store, record);
            let country_claim = paid_route_country_claim(
                session_config
                    .as_ref()
                    .map(|config| config.location.country_code.as_str())
                    .unwrap_or_default(),
                session.observed_country_code.as_deref(),
            );
            let decision = session_config
                .as_ref()
                .map(|config| session.routing_decision(config));
            let collection = store.seller_collection_state_for_session(
                &app.paid_exit,
                now_unix,
                &session.session_id,
            );
            let (state, allow, shared_internet, due, unpaid, delivered) = decision.as_ref().map_or(
                (
                    "unknown",
                    false,
                    "off: no matching offer".to_string(),
                    0,
                    0,
                    session.usage.total_bytes(),
                ),
                |decision| {
                    (
                        decision.state.as_str(),
                        decision.allow_routing,
                        paid_exit_shared_internet_text(decision),
                        decision.amount_due_msat,
                        decision.unpaid_msat,
                        decision.delivered_units,
                    )
                },
            );
            let bytes = session.usage.total_bytes();
            let renewal = if store.manual_renewal_session_id == session.session_id {
                " manual_auto_renew=true"
            } else {
                ""
            };
            println!(
                "  {} shared_internet=\"{}\" state={} allow={} collection={} mode={} paid={} due={} unpaid={} usage={} exit_ip={} country={} claimed_country={} country_claim={} quality={}{renewal}",
                session.session_id,
                shared_internet,
                state,
                allow,
                paid_exit_collection_state_text(collection.as_ref()),
                session.payment.mode.clone().as_str(),
                paid_exit_msat_text(session.payment.paid_msat),
                paid_exit_msat_text(due),
                paid_exit_msat_text(unpaid),
                paid_exit_usage_text(bytes.max(delivered)),
                display_or_none(session.realized_exit_ip.as_deref().unwrap_or_default()),
                display_or_none(session.observed_country_code.as_deref().unwrap_or_default()),
                display_or_none(&country_claim.claimed_country_code),
                country_claim.status.as_str(),
                paid_exit_quality_text(session.quality.as_ref()),
            );
        }
    }

    let seller_admissions = store.seller_admissions(&app.paid_exit, unix_timestamp());
    if !seller_admissions.is_empty() {
        println!("paid_exit_seller_admissions:");
        for admission in seller_admissions {
            println!(
                "  buyer={} session={} shared_internet=\"{}\" state={} allow={} paid={} due={} unpaid={} expires_at={}",
                admission.buyer_npub,
                admission.session_id,
                paid_exit_shared_internet_state_text(
                    admission.allow_routing,
                    admission.state.as_str(),
                    admission.unpaid_msat,
                ),
                admission.state.as_str(),
                admission.allow_routing,
                paid_exit_msat_text(admission.paid_msat),
                paid_exit_msat_text(admission.amount_due_msat),
                paid_exit_msat_text(admission.unpaid_msat),
                admission.expires_at_unix,
            );
        }
    }
    Ok(())
}

fn paid_exit_session_config(
    store: &PaidRouteStore,
    record: &PaidRouteSessionRecord,
) -> Option<PaidExitConfig> {
    let session = &record.session;
    store
        .channels
        .get(&session.payment.channel_id)?
        .accepted_terms
        .clone()
}

fn paid_route_channel_role_text(role: PaidRouteChannelRole) -> &'static str {
    match role {
        PaidRouteChannelRole::Buyer => "buyer",
        PaidRouteChannelRole::Seller => "seller",
    }
}

fn paid_route_lifecycle_status_text(status: PaidRouteLifecycleStatus) -> &'static str {
    match status {
        PaidRouteLifecycleStatus::Opening => "opening",
        PaidRouteLifecycleStatus::Probing => "probing",
        PaidRouteLifecycleStatus::Active => "active",
        PaidRouteLifecycleStatus::Paused => "paused",
        PaidRouteLifecycleStatus::Closing => "closing",
        PaidRouteLifecycleStatus::Closed => "closed",
        PaidRouteLifecycleStatus::Expired => "expired",
        PaidRouteLifecycleStatus::Failed => "failed",
    }
}

fn paid_route_lifecycle_is_current(status: PaidRouteLifecycleStatus) -> bool {
    matches!(
        status,
        PaidRouteLifecycleStatus::Opening
            | PaidRouteLifecycleStatus::Probing
            | PaidRouteLifecycleStatus::Active
            | PaidRouteLifecycleStatus::Paused
    )
}

fn paid_exit_seller_pending_buyer_credit_msat(
    config: &PaidExitConfig,
    store: &PaidRouteStore,
) -> u64 {
    if !config.enabled {
        return 0;
    }
    let seller_channel_ids = store
        .channels
        .values()
        .filter(|channel| {
            channel.role == PaidRouteChannelRole::Seller
                && paid_route_lifecycle_is_current(channel.status)
        })
        .map(|channel| channel.channel_id.as_str())
        .collect::<HashSet<_>>();
    store
        .sessions
        .values()
        .filter(|record| seller_channel_ids.contains(record.session.payment.channel_id.as_str()))
        .map(|record| record.session.payment.paid_msat)
        .fold(0_u64, u64::saturating_add)
}

fn paid_exit_pending_buyer_credit_help_text(pending_buyer_credit_msat: u64) -> &'static str {
    if pending_buyer_credit_msat > 0 {
        "collect to move it into wallet"
    } else {
        ""
    }
}

fn paid_exit_collection_state_text(state: Option<&PaidRouteSellerCollectionState>) -> String {
    let Some(state) = state else {
        return "none".to_string();
    };
    if state.auto_collect_due {
        format!("due: {}", paid_exit_msat_text(state.paid_msat))
    } else if state.manual_collect {
        format!("manual: {}", paid_exit_msat_text(state.paid_msat))
    } else {
        "none".to_string()
    }
}

fn paid_exit_error_suffix(error: &str) -> String {
    let error = error.trim();
    if error.is_empty() {
        String::new()
    } else {
        format!(" error={error}")
    }
}

fn paid_exit_quality_text(quality: Option<&PaidRouteQualityMetrics>) -> String {
    let Some(quality) = quality else {
        return "none".to_string();
    };
    let mut parts = Vec::new();
    if let Some(latency_ms) = quality.latency_ms {
        parts.push(format!("latency={latency_ms}ms"));
    }
    if let Some(jitter_ms) = quality.jitter_ms {
        parts.push(format!("jitter={jitter_ms}ms"));
    }
    if let Some(packet_loss_ppm) = quality.packet_loss_ppm {
        parts.push(format!(
            "loss={}",
            paid_exit_packet_loss_text(packet_loss_ppm)
        ));
    }
    if let Some(down_bps) = quality.down_bps {
        parts.push(format!("down={}", paid_exit_bitrate_text(down_bps)));
    }
    if let Some(up_bps) = quality.up_bps {
        parts.push(format!("up={}", paid_exit_bitrate_text(up_bps)));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}

pub(crate) fn paid_exit_shared_internet_text(decision: &PaidRouteRoutingDecision) -> String {
    let prefix = if decision.allow_routing { "on" } else { "off" };
    match decision.state.as_str() {
        "free_probe" => {
            if decision.free_probe_remaining_units > 0 {
                format!(
                    "{prefix}: free test, {} left",
                    paid_exit_binary_bytes_text(decision.free_probe_remaining_units)
                )
            } else {
                format!("{prefix}: free test")
            }
        }
        "paid" => format!("{prefix}: paid"),
        "grace" => {
            let mut text = if decision.grace_remaining_units > 0 {
                format!(
                    "{prefix}: grace, {} left",
                    paid_exit_binary_bytes_text(decision.grace_remaining_units)
                )
            } else {
                format!("{prefix}: grace")
            };
            if decision.unpaid_msat > 0 {
                text.push_str(&format!(
                    ", {} behind",
                    paid_exit_msat_text(decision.unpaid_msat)
                ));
            }
            text
        }
        _ => paid_exit_shared_internet_state_text(
            decision.allow_routing,
            decision.state.as_str(),
            decision.unpaid_msat,
        ),
    }
}

fn paid_exit_shared_internet_state_text(
    allow_routing: bool,
    state: &str,
    unpaid_msat: u64,
) -> String {
    let prefix = if allow_routing { "on" } else { "off" };
    if state == "suspended" && unpaid_msat > 0 {
        format!(
            "{prefix}: payment needed, {} behind",
            paid_exit_msat_text(unpaid_msat)
        )
    } else if state == "suspended" {
        format!("{prefix}: payment needed")
    } else if state.trim().is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}: {state}")
    }
}

fn paid_exit_packet_loss_text(packet_loss_ppm: u32) -> String {
    let percent = f64::from(packet_loss_ppm) / 10_000.0;
    if percent == 0.0 {
        "0%".to_string()
    } else if percent < 0.1 {
        format!("{percent:.2}%")
    } else if percent < 10.0 {
        format!("{percent:.1}%")
    } else {
        format!("{percent:.0}%")
    }
}

fn paid_exit_bitrate_text(bps: u64) -> String {
    let units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut value = bps as f64;
    let mut index = 0usize;
    while value >= 1_000.0 && index < units.len() - 1 {
        value /= 1_000.0;
        index += 1;
    }
    if index == 0 {
        format!("{bps} bps")
    } else if value.fract().abs() < 0.05 {
        format!("{value:.0} {}", units[index])
    } else {
        format!("{value:.1} {}", units[index])
    }
}

pub(crate) fn paid_exit_offer_summary_line(
    offer: &PaidRouteOffer,
    event_id: impl std::fmt::Display,
) -> String {
    format!(
        "  {} seller={} price={} country={} upstream={} channel=max={} expiry={}s free_probe={} grace={} mints={} quality={} event={}",
        offer.offer_id,
        offer.seller_npub,
        paid_exit_price_text(offer.pricing.price_msat_per_gb),
        display_or_none(&offer.location.country_code),
        offer.access.upstream.as_str(),
        paid_exit_sat_text(offer.channel.max_channel_capacity_sat),
        offer.channel.channel_expiry_secs,
        paid_exit_binary_bytes_text(offer.channel.free_probe_units),
        paid_exit_binary_bytes_text(offer.channel.grace_units),
        paid_exit_mints_text(&offer.channel.accepted_mints),
        paid_exit_quality_text(offer.quality.as_ref()),
        event_id,
    )
}

fn paid_exit_offer_summary_line_with_rating(
    offer: &PaidRouteOffer,
    event_id: impl std::fmt::Display,
    rating_scores: Option<&HashMap<String, PaidExitRatingScore>>,
) -> String {
    let mut line = paid_exit_offer_summary_line(offer, event_id);
    if let Some(score) = rating_scores
        .and_then(|scores| scores.get(&offer.seller_npub))
        .map(|score| score.score)
    {
        line.push_str(&format!(" rating_score={score:+}"));
    }
    line
}

fn paid_exit_mints_text(mints: &[String]) -> String {
    if mints.is_empty() {
        "none".to_string()
    } else {
        mints.join(",")
    }
}

fn display_or_none(value: &str) -> &str {
    if value.trim().is_empty() {
        "none"
    } else {
        value
    }
}
