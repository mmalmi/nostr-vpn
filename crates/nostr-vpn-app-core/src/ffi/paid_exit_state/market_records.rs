fn paid_route_wallet_state(
    store: &PaidRouteStore,
    last_action: &NativePaidRouteWalletActionState,
) -> NativePaidRouteWalletState {
    let wallet = &store.wallet;
    let total_balance_msat = wallet
        .mints
        .iter()
        .filter_map(|mint| mint.balance_msat)
        .sum();
    let channel_balance_msat = store
        .channels
        .values()
        .map(paid_route_buyer_channel_balance_msat)
        .sum();
    // An empty wallet has a known zero balance. Once mints exist, the total is
    // only known when every mint balance is known.
    let balance_known = wallet.mints.iter().all(|mint| mint.balance_msat.is_some());
    let mints = wallet
        .mints
        .iter()
        .map(|mint| NativePaidRouteWalletMintState {
            url: mint.url.clone(),
            label: mint.label.clone(),
            is_default: mint.url == wallet.default_mint,
            balance_known: mint.balance_msat.is_some(),
            balance_msat: mint.balance_msat.unwrap_or_default(),
            balance_text: mint
                .balance_msat
                .map_or_else(String::new, paid_route_msat_text),
            last_checked_unix: mint.last_checked_unix,
        })
        .collect();

    NativePaidRouteWalletState {
        default_mint: wallet.default_mint.clone(),
        balance_known,
        total_balance_msat,
        total_balance_text: if balance_known {
            paid_route_msat_text(total_balance_msat)
        } else {
            String::new()
        },
        channel_balance_msat,
        channel_balance_text: if channel_balance_msat > 0 {
            format!("{} in channels", paid_route_msat_text(channel_balance_msat))
        } else {
            String::new()
        },
        navigation_balance_text: if balance_known && total_balance_msat > 0 {
            compact_wallet_balance_text(total_balance_msat)
        } else {
            String::new()
        },
        fiat_currency: String::new(),
        fiat_balance_text: String::new(),
        exchange_rate_text: String::new(),
        exchange_rate_status: String::new(),
        exchange_rate_sources: String::new(),
        exchange_rate_stale: false,
        exchange_rate_updated_at_unix: 0,
        mints,
        last_action: last_action.clone(),
    }
}

fn paid_route_buyer_channel_balance_msat(channel: &PaidRouteChannelRecord) -> u64 {
    paid_route_channel_balance_msat(
        channel.role,
        channel.status,
        channel.payment.cashu_spilman_payment.is_some(),
        channel.payment.capacity_sat,
        channel.payment.paid_msat,
    )
}

fn paid_route_channel_balance_msat(
    role: PaidRouteChannelRole,
    status: PaidRouteLifecycleStatus,
    payment_channel_ready: bool,
    capacity_sat: u64,
    paid_msat: u64,
) -> u64 {
    if role != PaidRouteChannelRole::Buyer
        || status == PaidRouteLifecycleStatus::Closed
        || !payment_channel_ready
    {
        return 0;
    }
    capacity_sat.saturating_mul(1_000).saturating_sub(paid_msat)
}

include!("wallet_balance.rs");

fn paid_route_offer_state(
    key: &str,
    record: &nostr_vpn_core::paid_route_store::PaidRouteOfferRecord,
) -> NativePaidRouteOfferState {
    let offer = &record.offer;
    let quality = offer.quality.as_ref();
    NativePaidRouteOfferState {
        key: key.to_string(),
        offer_id: offer.offer_id.clone(),
        seller_npub: offer.seller_npub.clone(),
        status_text: paid_route_offer_status_text(offer, record.last_seen_unix),
        price_text: paid_route_price_text(offer.pricing.price_msat_per_gb),
        price_msat_per_gb: offer.pricing.price_msat_per_gb,
        accepted_mints: offer.channel.accepted_mints.clone(),
        max_channel_capacity_sat: offer.channel.max_channel_capacity_sat,
        channel_expiry_secs: offer.channel.channel_expiry_secs,
        free_probe_units: offer.channel.free_probe_units,
        free_probe_text: paid_route_binary_bytes_text(offer.channel.free_probe_units),
        grace_units: offer.channel.grace_units,
        grace_text: paid_route_binary_bytes_text(offer.channel.grace_units),
        country_code: normalize_paid_route_country_code(&offer.location.country_code),
        asn: offer.location.asn.unwrap_or_default(),
        ipv4: offer.ip_support.ipv4,
        ipv6: offer.ip_support.ipv6,
        has_rating: record.rating_score.is_some(),
        rating_score: record.rating_score.unwrap_or_default(),
        rating_updated_at_unix: record.rating_updated_at_unix,
        has_quality: quality.is_some(),
        quality_text: paid_route_quality_text(quality),
        bandwidth_text: paid_route_bandwidth_text(quality),
        latency_ms: quality
            .and_then(|quality| quality.latency_ms)
            .unwrap_or_default(),
        jitter_ms: quality
            .and_then(|quality| quality.jitter_ms)
            .unwrap_or_default(),
        packet_loss_ppm: quality
            .and_then(|quality| quality.packet_loss_ppm)
            .unwrap_or_default(),
        down_bps: quality
            .and_then(|quality| quality.down_bps)
            .unwrap_or_default(),
        up_bps: quality.and_then(|quality| quality.up_bps).unwrap_or_default(),
        uptime_secs: quality
            .and_then(|quality| quality.uptime_secs)
            .unwrap_or_default(),
        first_seen_unix: record.first_seen_unix,
        last_seen_unix: record.last_seen_unix,
        relay_urls: record.relay_urls.clone(),
    }
}

fn paid_route_offer_status_text(offer: &PaidRouteOffer, last_seen_unix: u64) -> String {
    let mut parts = Vec::new();
    let country_code = normalize_paid_route_country_code(&offer.location.country_code);
    if !country_code.is_empty() {
        parts.push(country_code);
    }
    if let Some(latency_ms) = offer
        .quality
        .as_ref()
        .and_then(|quality| quality.latency_ms)
    {
        parts.push(format!("{latency_ms} ms"));
    }
    if last_seen_unix > 0 {
        parts.push(format!(
            "seen {}",
            compact_age_text(age_secs_since(last_seen_unix))
        ));
    }
    if parts.is_empty() {
        "Internet seller".to_string()
    } else {
        parts.join(" - ")
    }
}

fn paid_route_channel_state(channel: &PaidRouteChannelRecord) -> NativePaidRouteChannelState {
    NativePaidRouteChannelState {
        channel_id: channel.channel_id.clone(),
        offer_id: channel.offer_id.clone(),
        role: paid_route_channel_role_text(channel.role).to_string(),
        status: paid_route_lifecycle_status_text(channel.status).to_string(),
        mint_url: channel.mint_url.clone(),
        counterparty_npub: channel.counterparty_npub.clone(),
        capacity_sat: channel.payment.capacity_sat,
        capacity_text: format!("{} sat", channel.payment.capacity_sat),
        paid_msat: channel.payment.paid_msat,
        paid_text: paid_route_paid_text(channel.payment.paid_msat),
        updated_at_unix: channel.updated_at_unix,
        expires_at_unix: channel.expires_at_unix,
        error: channel.error.clone(),
    }
}

fn paid_route_session_state(
    record: &nostr_vpn_core::paid_route_store::PaidRouteSessionRecord,
    store: &PaidRouteStore,
) -> NativePaidRouteSessionState {
    let session = &record.session;
    let channel = store.channels.get(&session.payment.channel_id);
    let accepted_terms = channel.and_then(|channel| channel.accepted_terms.as_ref());
    let offer = channel.zip(accepted_terms).map(|(channel, terms)| {
        PaidRouteOffer::from_paid_exit_config(
            channel.offer_id.clone(),
            channel.counterparty_npub.clone(),
            terms,
            None,
        )
    });
    let decision = accepted_terms.map(|terms| session.routing_decision(terms));
    let country_claim = accepted_terms.map_or_else(
        || paid_route_country_claim("", session.observed_country_code.as_deref()),
        |terms| {
            paid_route_country_claim(
                &terms.location.country_code,
                session.observed_country_code.as_deref(),
            )
        },
    );
    paid_route_session_state_with_decision(
        record,
        store,
        offer.as_ref(),
        decision.as_ref(),
        country_claim,
        None,
    )
}

fn paid_route_seller_session_state(
    record: &nostr_vpn_core::paid_route_store::PaidRouteSessionRecord,
    store: &PaidRouteStore,
    config: &PaidExitConfig,
) -> NativePaidRouteSessionState {
    let now_unix = unix_timestamp();
    let accepted_terms = store
        .channels
        .get(&record.session.payment.channel_id)
        .and_then(|channel| channel.accepted_terms.as_ref());
    let decision = accepted_terms.map(|terms| record.session.routing_decision(terms));
    let country_claim = paid_route_country_claim(
        accepted_terms
            .map(|terms| terms.location.country_code.as_str())
            .unwrap_or_default(),
        record.session.observed_country_code.as_deref(),
    );
    let collection =
        store.seller_collection_state_for_session(config, now_unix, &record.session.session_id);
    let mut state = paid_route_session_state_with_decision(
        record,
        store,
        None,
        decision.as_ref(),
        country_claim,
        collection.as_ref(),
    );
    state.title_text = paid_route_seller_session_title_text(&state);
    state
}

#[allow(clippy::too_many_lines)]
fn paid_route_session_state_with_decision(
    record: &nostr_vpn_core::paid_route_store::PaidRouteSessionRecord,
    store: &PaidRouteStore,
    offer: Option<&PaidRouteOffer>,
    decision: Option<&PaidRouteRoutingDecision>,
    country_claim: PaidRouteCountryClaim,
    collection: Option<&PaidRouteSellerCollectionState>,
) -> NativePaidRouteSessionState {
    let session = &record.session;
    let now_unix = unix_timestamp();
    let channel = store.channels.get(&session.payment.channel_id);
    let lease = store.leases.get(&session.lease_id);
    let stored_lifecycle_status = channel
        .map(|channel| channel.status)
        .or_else(|| lease.map(|lease| lease.status));
    let expires_at_unix = match (channel, lease) {
        (Some(channel), Some(lease)) => channel.expires_at_unix.min(lease.lease.expires_at_unix),
        (Some(channel), None) => channel.expires_at_unix,
        (None, Some(lease)) => lease.lease.expires_at_unix,
        (None, None) => 0,
    };
    let lifecycle_status = if expires_at_unix > 0
        && expires_at_unix <= now_unix
        && stored_lifecycle_status.is_some_and(paid_route_lifecycle_is_current)
    {
        "expired"
    } else {
        stored_lifecycle_status
            .map(paid_route_lifecycle_status_text)
            .unwrap_or_default()
    };
    let access_state = decision
        .map(|decision| decision.state.as_str())
        .unwrap_or_default();
    let quality = session.quality.as_ref();
    let status_text = paid_route_session_status_text(decision.map(|d| d.state), channel);
    let payment_channel_ready = session.payment.cashu_spilman_payment.is_some()
        || session.payment.cashu_token_lease.is_some();
    let channel_balance_msat = channel.map_or(0, paid_route_buyer_channel_balance_msat);
    let decision_allows_routing = decision.is_some_and(|decision| decision.allow_routing);
    let lifecycle_allows_routing = channel
        .is_none_or(|channel| paid_route_lifecycle_allows_routing_for_state(channel.status))
        && lease.is_none_or(|lease| paid_route_lifecycle_allows_routing_for_state(lease.status));
    let channel_role = channel.map(|channel| channel.role);
    let time_allows_routing = expires_at_unix == 0 || expires_at_unix > now_unix;
    let payment_allows_routing = channel_role != Some(PaidRouteChannelRole::Buyer)
        || offer.is_none_or(|offer| {
            !paid_route_offer_requires_payment_before_routing_for_state(offer)
                || payment_channel_ready
        });
    let allow_routing = decision_allows_routing
        && lifecycle_allows_routing
        && time_allows_routing
        && payment_allows_routing;
    let delivered_units = decision.map_or(0, |decision| decision.delivered_units);
    let amount_due_msat = decision.map_or(0, |decision| decision.amount_due_msat);
    let unpaid_msat = decision.map_or(0, |decision| decision.unpaid_msat);
    let bytes = session.usage.total_bytes();
    let packets = session.usage.total_packets();
    let usage_text = paid_route_usage_text(bytes.max(delivered_units));
    let detail_text = paid_route_session_detail_text(
        lifecycle_status,
        access_state,
        &usage_text,
        amount_due_msat,
    );
    let realized_exit_ip = session.realized_exit_ip.clone().unwrap_or_default();
    let location_text = paid_route_location_text(&realized_exit_ip, &country_claim);
    let collection_available = collection.is_some_and(|state| state.manual_collect);
    let auto_collect_due = collection.is_some_and(|state| state.auto_collect_due);

    NativePaidRouteSessionState {
        session_id: session.session_id.clone(),
        lease_id: session.lease_id.clone(),
        channel_id: session.payment.channel_id.clone(),
        status_text: status_text.clone(),
        lifecycle_status: lifecycle_status.to_string(),
        access_state: access_state.to_string(),
        title_text: paid_route_session_title_text(
            &status_text,
            lifecycle_status,
            payment_channel_ready,
            allow_routing,
            unpaid_msat,
        ),
        detail_text,
        settlement_text: paid_route_session_settlement_text(
            channel_role,
            lifecycle_status,
            expires_at_unix,
            allow_routing,
            payment_channel_ready,
            session.payment.paid_msat,
            &session.payment.channel_id,
            collection_available,
            auto_collect_due,
            now_unix,
        ),
        collect_action_text: paid_route_session_collect_action_text(
            channel_role,
            payment_channel_ready,
            allow_routing,
            session.payment.paid_msat,
            &session.payment.channel_id,
            collection_available,
            auto_collect_due,
        ),
        collect_action_help_text: paid_route_session_collect_action_help_text(
            channel_role,
            payment_channel_ready,
            allow_routing,
            session.payment.paid_msat,
            &session.payment.channel_id,
            collection_available,
            auto_collect_due,
        ),
        payment_channel_ready,
        allow_routing,
        delivered_units,
        usage_text,
        amount_due_msat,
        amount_due_text: paid_route_due_text(amount_due_msat),
        paid_msat: session.payment.paid_msat,
        paid_text: paid_route_paid_text(session.payment.paid_msat),
        channel_balance_msat,
        channel_balance_text: if channel_balance_msat > 0 {
            format!("{} in channel", paid_route_msat_text(channel_balance_msat))
        } else {
            String::new()
        },
        unpaid_msat,
        unpaid_text: paid_route_unpaid_text(unpaid_msat),
        active_millis: session.usage.active_millis,
        bytes,
        packets,
        realized_exit_ip,
        claimed_country_code: country_claim.claimed_country_code,
        observed_country_code: session.observed_country_code.clone().unwrap_or_default(),
        country_claim_status: country_claim.status.as_str().to_string(),
        location_text,
        observed_asn: session.observed_asn.unwrap_or_default(),
        has_quality: quality.is_some(),
        quality_text: paid_route_quality_text(quality),
        bandwidth_text: paid_route_bandwidth_text(quality),
        latency_ms: quality
            .and_then(|quality| quality.latency_ms)
            .unwrap_or_default(),
        jitter_ms: quality
            .and_then(|quality| quality.jitter_ms)
            .unwrap_or_default(),
        packet_loss_ppm: quality
            .and_then(|quality| quality.packet_loss_ppm)
            .unwrap_or_default(),
        down_bps: quality
            .and_then(|quality| quality.down_bps)
            .unwrap_or_default(),
        up_bps: quality.and_then(|quality| quality.up_bps).unwrap_or_default(),
        updated_at_unix: record.updated_at_unix,
        expires_at_unix,
    }
}
