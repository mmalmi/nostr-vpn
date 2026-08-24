fn selected_paid_exit_upstream(config: &AppConfig) -> Result<PaidExitUpstream> {
    config
        .paid_exit_seller_egress()
        .map(|egress| egress.offer_upstream())
}

fn paid_exit_seller_state(
    app: Option<&AppConfig>,
    daemon_state: Option<&DaemonRuntimeState>,
    port_mapping: Option<&PortMappingStatus>,
    supported: bool,
    store_path: &Path,
) -> NativePaidExitSellerState {
    let Some(app) = app else {
        return NativePaidExitSellerState {
            supported,
            status_text: if supported {
                "Config unavailable".to_string()
            } else {
                "Selling internet is not supported on this platform".to_string()
            },
            ..NativePaidExitSellerState::default()
        };
    };
    let mut config = app.paid_exit.clone();
    if let Ok(upstream) = selected_paid_exit_upstream(app) {
        config.access.upstream = upstream;
    }
    let (store_status, channels, sessions, traffic_summary) =
        paid_exit_seller_store_state(&config, supported, store_path);
    let channel_credit_msat = paid_exit_seller_channel_credit_msat(&sessions);
    let status_text = append_paid_exit_seller_store_status(
        paid_exit_seller_status_text(
            app,
            daemon_state,
            &config,
            app.wireguard_exit.configured(),
            supported,
        ),
        store_status,
    );

    NativePaidExitSellerState {
        supported,
        enabled: supported && config.enabled,
        status_text,
        provider_link: app
            .own_nostr_pubkey_hex()
            .ok()
            .and_then(|npub| ManualPaidExitProvider::seller_link(&npub, &config).ok())
            .unwrap_or_default(),
        upstream: config.access.upstream.as_str().to_string(),
        private_vpn_access: config.access.private_vpn_access.as_str().to_string(),
        internet_text: paid_exit_seller_internet_text(app),
        public_ip_text: paid_exit_public_ip_text(port_mapping),
        price_text: paid_route_price_text(config.pricing.price_msat_per_gb),
        price_msat_per_gb: config.pricing.price_msat_per_gb,
        accepted_mints: config.channel.accepted_mints.clone(),
        max_channel_capacity_sat: config.channel.max_channel_capacity_sat,
        channel_expiry_secs: config.channel.channel_expiry_secs,
        channel_expiry_text: paid_route_duration_text(config.channel.channel_expiry_secs),
        settlement_text: paid_exit_seller_settlement_text(config.channel.channel_expiry_secs),
        free_probe_units: config.channel.free_probe_units,
        free_probe_text: paid_route_binary_bytes_text(config.channel.free_probe_units),
        grace_units: config.channel.grace_units,
        grace_text: paid_route_binary_bytes_text(config.channel.grace_units),
        country_code: normalize_paid_route_country_code(&config.location.country_code),
        asn: config.location.asn.unwrap_or_default(),
        ipv4: config.ip_support.ipv4,
        ipv6: config.ip_support.ipv6,
        channel_credit_msat,
        channel_credit_text: paid_exit_seller_channel_credit_text(channel_credit_msat),
        channel_credit_title_text: paid_exit_seller_channel_credit_title_text().to_string(),
        channel_credit_help_text: paid_exit_seller_channel_credit_help_text(channel_credit_msat)
            .to_string(),
        current_connection_count: traffic_summary.current_connection_count,
        past_connection_count: traffic_summary.past_connection_count,
        total_billable_bytes: traffic_summary.total_billable_bytes,
        total_traffic_text: paid_route_usage_text(traffic_summary.total_billable_bytes),
        total_paid_msat: traffic_summary.total_paid_msat,
        total_paid_text: paid_route_paid_text(traffic_summary.total_paid_msat),
        total_due_msat: traffic_summary.total_due_msat,
        total_due_text: paid_route_due_text(traffic_summary.total_due_msat),
        total_unpaid_msat: traffic_summary.total_unpaid_msat,
        total_unpaid_text: paid_route_unpaid_text(traffic_summary.total_unpaid_msat),
        channels,
        sessions,
    }
}

fn paid_exit_seller_supported_for_current_target(mobile: bool) -> bool {
    paid_exit_seller_supported_for_target(std::env::consts::OS, mobile)
}

fn paid_exit_seller_supported_for_target(target_os: &str, mobile: bool) -> bool {
    !mobile && matches!(target_os, "macos" | "linux")
}

fn paid_exit_public_ip_text(port_mapping: Option<&PortMappingStatus>) -> String {
    let Some(endpoint) = port_mapping.and_then(|status| status.external_endpoint.as_deref()) else {
        return String::new();
    };
    public_ip_from_endpoint(endpoint)
}

fn public_ip_from_endpoint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((ip, _)) = rest.split_once(']')
    {
        return ip.to_string();
    }
    match (trimmed.matches(':').count(), trimmed.split_once(':')) {
        (1, Some((ip, _))) => ip.to_string(),
        _ => trimmed.to_string(),
    }
}

fn paid_exit_seller_store_state(
    config: &PaidExitConfig,
    supported: bool,
    store_path: &Path,
) -> (
    String,
    Vec<NativePaidRouteChannelState>,
    Vec<NativePaidRouteSessionState>,
    PaidExitSellerTrafficSummary,
) {
    if !supported {
        return (
            String::new(),
            Vec::new(),
            Vec::new(),
            PaidExitSellerTrafficSummary::default(),
        );
    }
    let store = match load_paid_route_store(store_path) {
        Ok(store) => store,
        Err(error) => {
            return (
                format!("Paid route store unavailable: {error}"),
                Vec::new(),
                Vec::new(),
                PaidExitSellerTrafficSummary::default(),
            );
        }
    };
    let all_seller_channel_ids = store
        .channels
        .values()
        .filter(|channel| channel.role == PaidRouteChannelRole::Seller)
        .map(|channel| channel.channel_id.clone())
        .collect::<HashSet<_>>();
    let traffic_summary =
        paid_exit_seller_traffic_summary(&store, config, &all_seller_channel_ids);
    let mut channels = store
        .channels
        .values()
        .filter(|channel| {
            channel.role == PaidRouteChannelRole::Seller
                && paid_route_lifecycle_is_current(channel.status)
        })
        .map(paid_route_channel_state)
        .collect::<Vec<_>>();
    channels.sort_by(|left, right| {
        right
            .updated_at_unix
            .cmp(&left.updated_at_unix)
            .then_with(|| left.channel_id.cmp(&right.channel_id))
    });

    let seller_channel_ids = channels
        .iter()
        .map(|channel| channel.channel_id.clone())
        .collect::<HashSet<_>>();
    let mut sessions = store
        .sessions
        .values()
        .filter(|record| seller_channel_ids.contains(&record.session.payment.channel_id))
        .map(|record| paid_route_seller_session_state(record, &store, config))
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| {
        right
            .updated_at_unix
            .cmp(&left.updated_at_unix)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });

    let status = match sessions.len() {
        0 => String::new(),
        1 => "1 active paid client".to_string(),
        count => format!("{count} active paid clients"),
    };
    (status, channels, sessions, traffic_summary)
}

#[derive(Default)]
struct PaidExitSellerTrafficSummary {
    current_connection_count: u64,
    past_connection_count: u64,
    total_billable_bytes: u64,
    total_paid_msat: u64,
    total_due_msat: u64,
    total_unpaid_msat: u64,
}

fn paid_exit_seller_traffic_summary(
    store: &PaidRouteStore,
    config: &PaidExitConfig,
    seller_channel_ids: &HashSet<String>,
) -> PaidExitSellerTrafficSummary {
    let mut summary = PaidExitSellerTrafficSummary::default();
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

fn paid_exit_seller_channel_credit_msat(sessions: &[NativePaidRouteSessionState]) -> u64 {
    sessions
        .iter()
        .map(|session| session.paid_msat)
        .fold(0_u64, u64::saturating_add)
}

fn paid_exit_seller_channel_credit_text(channel_credit_msat: u64) -> String {
    paid_route_msat_text(channel_credit_msat)
}

fn paid_exit_seller_channel_credit_title_text() -> &'static str {
    "Pending buyer credit"
}

fn paid_exit_seller_channel_credit_help_text(channel_credit_msat: u64) -> &'static str {
    if channel_credit_msat > 0 {
        "Collect to move it into wallet"
    } else {
        ""
    }
}

fn append_paid_exit_seller_store_status(config_status: String, store_status: String) -> String {
    if store_status.is_empty() {
        config_status
    } else if config_status.is_empty() {
        store_status
    } else {
        format!("{config_status}; {store_status}")
    }
}

pub(super) fn paid_exit_seller_status_text(
    app: &AppConfig,
    daemon_state: Option<&DaemonRuntimeState>,
    config: &PaidExitConfig,
    wireguard_exit_configured: bool,
    supported: bool,
) -> String {
    if !supported {
        "Selling internet is not supported on this platform".to_string()
    } else if !config.enabled {
        "Selling internet is off".to_string()
    } else if let Err(error) = app.paid_exit_seller_egress() {
        error.to_string()
    } else if matches!(
        app.paid_exit_seller_egress(),
        Ok(PaidExitSellerEgress::WireGuard)
    )
        && !wireguard_exit_configured
    {
        "Configure WireGuard upstream before advertising".to_string()
    } else if matches!(
        app.paid_exit_seller_egress(),
        Ok(PaidExitSellerEgress::WireGuard)
    ) && !daemon_state.is_some_and(|state| state.wireguard_exit_ready)
    {
        "Waiting for the WireGuard handshake".to_string()
    } else if let Ok(PaidExitSellerEgress::PrivatePeer { pubkey }) =
        app.paid_exit_seller_egress()
        && !daemon_state.is_some_and(|state| {
            state.peers.iter().any(|peer| {
                peer.participant_pubkey == pubkey
                    && peer.reachable
                    && peer_offers_exit_node(&peer.advertised_routes)
            })
        })
    {
        "Waiting for the selected private exit".to_string()
    } else if !daemon_state.is_some_and(|state| state.paid_exit_seller_ready) {
        "Waiting for the FIPS listener".to_string()
    } else if app.nostr_keys().is_err() {
        "Set up Nostr identity before advertising".to_string()
    } else if config.channel.accepted_mints.is_empty() {
        "Selling internet is on; add accepted mints before advertising".to_string()
    } else if config.pricing.price_msat_per_gb == 0 {
        "Selling internet is on with a free/dev price".to_string()
    } else {
        "Selling internet is ready".to_string()
    }
}

fn paid_exit_seller_internet_text(app: &AppConfig) -> String {
    match app.paid_exit_seller_egress() {
        Ok(PaidExitSellerEgress::Direct) => "Device internet".to_string(),
        Ok(PaidExitSellerEgress::WireGuard) => "WireGuard exit".to_string(),
        Ok(PaidExitSellerEgress::PrivatePeer { pubkey }) => {
            let name = app
                .magic_dns_name_for_participant(&pubkey)
                .or_else(|| app.peer_alias(&pubkey))
                .unwrap_or_else(|| short_pubkey(&pubkey));
            format!("Private exit · {name}")
        }
        Err(_) => "Unavailable".to_string(),
    }
}

fn paid_route_market_state(
    app: Option<&AppConfig>,
    store_path: &Path,
    filter: &NativePaidRouteMarketFilterState,
    wallet_last_action: &NativePaidRouteWalletActionState,
    payment_last_action: &NativePaidRoutePaymentActionState,
) -> NativePaidRouteMarketState {
    let Some(app) = app else {
        return NativePaidRouteMarketState {
            supported: false,
            status_text: "Config unavailable".to_string(),
            store_path: store_path.display().to_string(),
            ..NativePaidRouteMarketState::default()
        };
    };

    let store = match load_paid_route_store(store_path) {
        Ok(store) => store,
        Err(error) => {
            return NativePaidRouteMarketState {
                supported: true,
                status_text: format!("Paid route store unavailable: {error}"),
                store_path: store_path.display().to_string(),
                ..NativePaidRouteMarketState::default()
            };
        }
    };

    let now_unix = unix_timestamp();
    let mut offers = store
        .offers
        .iter()
        .filter(|(_, record)| record.signed_offer.is_live_at(now_unix))
        .map(|(key, record)| paid_route_offer_state(key, record))
        .collect::<Vec<_>>();
    offers.sort_by(|left, right| paid_route_offer_order(left, right, "quality"));
    let filter = normalize_paid_route_market_filter(filter);
    let country_options = paid_route_offer_country_options(&offers);
    let visible_offers = paid_route_visible_offers(&offers, &filter);
    let hidden_offer_count = offers.len().saturating_sub(visible_offers.len()) as u64;
    let manual_provider_link = app
        .manual_paid_exit_provider
        .link()
        .unwrap_or_default();
    let manual_provider_status_text = manual_paid_exit_provider_status(app, &store, &offers);

    let mut channels = store
        .channels
        .values()
        .filter(|channel| channel.role == PaidRouteChannelRole::Buyer)
        .map(paid_route_channel_state)
        .collect::<Vec<_>>();
    channels.sort_by(|left, right| {
        right
            .updated_at_unix
            .cmp(&left.updated_at_unix)
            .then_with(|| left.channel_id.cmp(&right.channel_id))
    });

    let mut sessions = store
        .sessions
        .values()
        .filter(|record| {
            store
                .channels
                .get(&record.session.payment.channel_id)
                .is_none_or(|channel| channel.role == PaidRouteChannelRole::Buyer)
        })
        .map(|record| paid_route_session_state(record, &store))
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| {
        right
            .updated_at_unix
            .cmp(&left.updated_at_unix)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });

    let status_text = if offers.is_empty() {
        "No internet sellers found".to_string()
    } else if offers.len() == 1 {
        "1 internet seller found".to_string()
    } else {
        format!("{} internet sellers found", offers.len())
    };

    NativePaidRouteMarketState {
        supported: true,
        status_text,
        manual_provider_link,
        manual_provider_status_text,
        store_path: store_path.display().to_string(),
        wallet: paid_route_wallet_state(&store.wallet, wallet_last_action),
        last_payment_action: payment_last_action.clone(),
        filter,
        offers,
        visible_offers,
        hidden_offer_count,
        country_options,
        channels,
        sessions,
    }
}

fn manual_paid_exit_provider_status(
    app: &AppConfig,
    store: &PaidRouteStore,
    offers: &[NativePaidRouteOfferState],
) -> String {
    if app.manual_paid_exit_provider.is_default() {
        return String::new();
    }
    offers
        .iter()
        .find(|offer| offer.seller_npub == app.manual_paid_exit_provider.npub)
        .and_then(|offer| store.offers.get(&offer.key))
        .map_or_else(
            || "Waiting for provider offer".to_string(),
            |record| match app.manual_paid_exit_provider.accepts(&record.offer) {
                Ok(()) => "Provider offer ready".to_string(),
                Err(error) => error.to_string(),
            },
        )
}

fn normalize_paid_route_market_filter(
    filter: &NativePaidRouteMarketFilterState,
) -> NativePaidRouteMarketFilterState {
    let country_code = normalize_paid_route_country_code(&normalize_paid_route_filter_value(
        &filter.country_code,
    ));
    let sort = match normalize_paid_route_filter_value(&filter.sort)
        .to_lowercase()
        .as_str()
    {
        "price" => "price",
        "newest" => "newest",
        _ => "quality",
    };

    NativePaidRouteMarketFilterState {
        query: filter.query.trim().to_string(),
        country_code,
        mint_url: normalize_paid_route_filter_value(&filter.mint_url),
        require_ipv4: filter.require_ipv4,
        require_ipv6: filter.require_ipv6,
        sort: sort.to_string(),
    }
}

fn normalize_paid_route_filter_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("all") || trimmed.eq_ignore_ascii_case("any") || trimmed == "*"
    {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn paid_route_visible_offers(
    offers: &[NativePaidRouteOfferState],
    filter: &NativePaidRouteMarketFilterState,
) -> Vec<NativePaidRouteOfferState> {
    let query = filter.query.trim().to_lowercase();
    let country_code = filter.country_code.trim().to_uppercase();
    let mint_url = filter.mint_url.trim();
    let mut visible = offers
        .iter()
        .filter(|offer| {
            query.is_empty()
                || paid_route_offer_search_text(offer)
                    .to_lowercase()
                    .contains(query.as_str())
        })
        .filter(|offer| {
            country_code.is_empty() || offer.country_code.trim().to_uppercase() == country_code
        })
        .filter(|offer| {
            mint_url.is_empty() || offer.accepted_mints.iter().any(|mint| mint == mint_url)
        })
        .filter(|offer| !filter.require_ipv4 || offer.ipv4)
        .filter(|offer| !filter.require_ipv6 || offer.ipv6)
        .cloned()
        .collect::<Vec<_>>();

    visible.sort_by(|left, right| paid_route_offer_order(left, right, &filter.sort));
    visible
}

fn paid_route_offer_search_text(offer: &NativePaidRouteOfferState) -> String {
    format!(
        "{} {} {} {} {}",
        offer.offer_id,
        offer.seller_npub,
        offer.status_text,
        offer.country_code,
        offer.accepted_mints.join(" ")
    )
}

fn paid_route_offer_order(
    left: &NativePaidRouteOfferState,
    right: &NativePaidRouteOfferState,
    sort: &str,
) -> std::cmp::Ordering {
    match sort {
        "price" => paid_route_offer_price_order(left, right)
            .then_with(|| paid_route_offer_rating_order(left, right))
            .then_with(|| paid_route_offer_quality_order(left, right))
            .then_with(|| paid_route_offer_newest_order(left, right))
            .then_with(|| left.key.cmp(&right.key)),
        "newest" => paid_route_offer_newest_order(left, right)
            .then_with(|| paid_route_offer_rating_order(left, right))
            .then_with(|| paid_route_offer_quality_order(left, right))
            .then_with(|| paid_route_offer_price_order(left, right))
            .then_with(|| left.key.cmp(&right.key)),
        _ => paid_route_offer_rating_order(left, right)
            .then_with(|| paid_route_offer_quality_order(left, right))
            .then_with(|| paid_route_offer_price_order(left, right))
            .then_with(|| paid_route_offer_newest_order(left, right))
            .then_with(|| left.key.cmp(&right.key)),
    }
}

fn paid_route_offer_rating_order(
    left: &NativePaidRouteOfferState,
    right: &NativePaidRouteOfferState,
) -> std::cmp::Ordering {
    right.rating_score.cmp(&left.rating_score)
}

fn paid_route_offer_price_order(
    left: &NativePaidRouteOfferState,
    right: &NativePaidRouteOfferState,
) -> std::cmp::Ordering {
    left.price_msat_per_gb.cmp(&right.price_msat_per_gb)
}

fn paid_route_offer_newest_order(
    left: &NativePaidRouteOfferState,
    right: &NativePaidRouteOfferState,
) -> std::cmp::Ordering {
    right.last_seen_unix.cmp(&left.last_seen_unix)
}

fn paid_route_offer_quality_order(
    left: &NativePaidRouteOfferState,
    right: &NativePaidRouteOfferState,
) -> std::cmp::Ordering {
    right
        .has_quality
        .cmp(&left.has_quality)
        .then_with(|| left.packet_loss_ppm.cmp(&right.packet_loss_ppm))
        .then_with(|| left.latency_ms.cmp(&right.latency_ms))
        .then_with(|| left.jitter_ms.cmp(&right.jitter_ms))
        .then_with(|| right.down_bps.cmp(&left.down_bps))
        .then_with(|| right.up_bps.cmp(&left.up_bps))
}

fn paid_route_offer_country_options(offers: &[NativePaidRouteOfferState]) -> Vec<String> {
    let mut options = offers
        .iter()
        .map(|offer| offer.country_code.trim().to_uppercase())
        .filter(|country_code| !country_code.is_empty())
        .collect::<Vec<_>>();
    options.sort();
    options.dedup();
    options
}

fn paid_route_wallet_state(
    wallet: &PaidRouteWalletState,
    last_action: &NativePaidRouteWalletActionState,
) -> NativePaidRouteWalletState {
    let total_balance_msat = wallet
        .mints
        .iter()
        .filter_map(|mint| mint.balance_msat)
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

include!("paid_exit_state/wallet_balance.rs");

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
