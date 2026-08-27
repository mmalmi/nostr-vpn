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

#[cfg(test)]
mod supported_target_tests {
    use super::paid_exit_seller_supported_for_target;

    #[test]
    fn seller_support_matches_the_shipped_gui_release_matrix() {
        assert!(paid_exit_seller_supported_for_target("linux", false));
        assert!(paid_exit_seller_supported_for_target("macos", false));
        assert!(!paid_exit_seller_supported_for_target("windows", false));
        assert!(!paid_exit_seller_supported_for_target("android", true));
        assert!(!paid_exit_seller_supported_for_target("ios", true));
    }
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
        wallet: paid_route_wallet_state(&store, wallet_last_action),
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

include!("paid_exit_state/market_records.rs");
