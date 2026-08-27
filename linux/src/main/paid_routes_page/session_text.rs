fn paid_route_session_lines(session: &NativePaidRouteSessionState) -> Vec<String> {
    let mut lines = vec![paid_route_session_detail(session)];
    if !session.location_text.is_empty() {
        lines.push(session.location_text.clone());
    } else if !session.realized_exit_ip.is_empty() {
        lines.push(format!(
            "{} · {}",
            session.realized_exit_ip,
            paid_route_country_claim_text(session),
        ));
    }
    let metric = paid_route_metric_text(
        &non_empty_or(
            &session.quality_text,
            &paid_route_quality_text(
                session.latency_ms,
                session.jitter_ms,
                session.packet_loss_ppm,
            ),
        ),
        &session.bandwidth_text,
    );
    if !metric.is_empty() {
        lines.push(metric);
    }
    if !session.settlement_text.is_empty() {
        lines.push(session.settlement_text.clone());
    }
    lines.push(format!(
        "{} · {}",
        non_empty_or(
            &session.paid_text,
            &format!("{} paid", format_paid_route_msat(session.paid_msat)),
        ),
        if session.unpaid_msat > 0 {
            non_empty_or(
                &session.unpaid_text,
                &format!("{} behind", format_paid_route_msat(session.unpaid_msat)),
            )
        } else {
            non_empty_or(
                &session.amount_due_text,
                &format!("{} due", format_paid_route_msat(session.amount_due_msat)),
            )
        }
    ));
    lines
}
fn paid_route_buyer_session_title(session: &NativePaidRouteSessionState) -> String {
    if !session.title_text.is_empty() {
        session.title_text.clone()
    } else if session.allow_routing {
        "Ready".to_string()
    } else if session.unpaid_msat > 0 {
        "Payment needed".to_string()
    } else if !session.payment_channel_ready {
        "Needs funds".to_string()
    } else {
        paid_route_plain_status(
            &non_empty_or(&session.status_text, &session.lifecycle_status),
            "Session",
        )
    }
}

fn paid_exit_seller_session_title(session: &NativePaidRouteSessionState) -> String {
    if !session.title_text.is_empty() {
        session.title_text.clone()
    } else if session.allow_routing {
        "Connected customer".to_string()
    } else if session.unpaid_msat > 0 {
        "Customer behind".to_string()
    } else {
        paid_route_plain_status(
            &non_empty_or(&session.status_text, &session.lifecycle_status),
            "Customer",
        )
    }
}

fn paid_route_session_detail(session: &NativePaidRouteSessionState) -> String {
    if !session.detail_text.is_empty() {
        return session.detail_text.clone();
    }
    let access = paid_route_access_title(
        &session.access_state,
        &non_empty_or(&session.lifecycle_status, "session"),
    );
    let units = if session.bytes > 0 {
        format!("{} used", format_bytes(session.bytes))
    } else if session.packets > 0 {
        format!("{} packets", session.packets)
    } else {
        format!("{} units", session.delivered_units)
    };
    format!(
        "{access}, {units}, {} due",
        format_paid_route_msat(session.amount_due_msat)
    )
}

fn paid_route_session_can_open_channel(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty() && !session.payment_channel_ready
}

fn paid_route_session_can_sign_payment(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty() && session.payment_channel_ready && session.unpaid_msat > 0
}

fn paid_route_session_can_close_channel(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty()
        && session.payment_channel_ready
        && !matches!(session.lifecycle_status.as_str(), "closed" | "expired")
}

fn paid_exit_seller_session_can_collect(session: &NativePaidRouteSessionState) -> bool {
    session.payment_channel_ready
        && session.paid_msat > 0
        && !session.channel_id.is_empty()
        && (!session.collect_action_text.is_empty()
            || !matches!(session.lifecycle_status.as_str(), "closed" | "expired"))
}

fn paid_route_offer_title(offer: &NativePaidRouteOfferState) -> String {
    format!(
        "{} · {}",
        non_empty_or(&offer.country_code, "Unknown country").to_uppercase(),
        &offer.price_text
    )
}

fn paid_exit_seller_status_text(seller: &NativePaidExitSellerState) -> String {
    if !seller.status_text.is_empty() {
        seller
            .status_text
            .replace("Paid exit selling", "Selling internet")
            .replace("paid exit selling", "selling internet")
    } else if seller.supported {
        "People can pay to use my internet".to_string()
    } else {
        "This platform cannot sell public internet access".to_string()
    }
}

fn paid_exit_seller_internet_text(seller: &NativePaidExitSellerState) -> String {
    if !seller.internet_text.is_empty() {
        seller.internet_text.clone()
    } else if matches!(
        seller.upstream.as_str(),
        "wireguard_exit" | "wireguard" | "wg" | "upstream_vpn" | "vpn"
    ) {
        "My internet through WireGuard".to_string()
    } else {
        "My internet".to_string()
    }
}

fn paid_exit_seller_totals_text(seller: &NativePaidExitSellerState) -> String {
    [
        format!("{} connected", seller.current_connection_count),
        format!("{} past", seller.past_connection_count),
        non_empty_or(
            &seller.total_traffic_text,
            &format!("{} routed", format_bytes(seller.total_billable_bytes)),
        ),
        format!(
            "{} paid",
            non_empty_or(
                &seller.total_paid_text,
                &format_paid_route_msat(seller.total_paid_msat),
            )
        ),
        format!(
            "{} due",
            non_empty_or(
                &seller.total_due_text,
                &format_paid_route_msat(seller.total_due_msat),
            )
        ),
    ]
    .join(" · ")
}

fn paid_route_payment_action_text(
    action: &nostr_vpn_app_core::native_state::NativePaidRoutePaymentActionState,
) -> String {
    if action.kind.is_empty() && action.status_text.is_empty() {
        String::new()
    } else {
        non_empty_or(
            &action.status_text,
            &paid_route_payment_action_title(&action.kind),
        )
    }
}

fn paid_route_wallet_action_text(
    action: &nostr_vpn_app_core::native_state::NativePaidRouteWalletActionState,
) -> String {
    if action.kind.is_empty() && action.status_text.is_empty() {
        String::new()
    } else {
        non_empty_or(
            &action.status_text,
            &paid_route_wallet_action_title(&action.kind),
        )
    }
}

fn paid_route_access_title(value: &str, fallback: &str) -> String {
    match value {
        "paid" => "Paid".to_string(),
        "free_probe" => "Free test".to_string(),
        "grace" => "Grace".to_string(),
        "suspended" => "Paused".to_string(),
        other => paid_route_plain_status(other, fallback),
    }
}

fn paid_route_plain_status(value: &str, fallback: &str) -> String {
    let raw = non_empty_or(value, fallback).replace('_', " ");
    let mut chars = raw.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn paid_route_quality_text(latency_ms: u32, jitter_ms: u32, packet_loss_ppm: u32) -> String {
    if latency_ms == 0 && jitter_ms == 0 && packet_loss_ppm == 0 {
        return "Quality unmeasured".to_string();
    }
    let loss = packet_loss_ppm as f64 / 10_000.0;
    format!("{latency_ms} ms · {jitter_ms} ms jitter · {loss:.2}% loss")
}

fn paid_route_metric_text(quality: &str, bandwidth: &str) -> String {
    [quality.trim(), bandwidth.trim()]
        .into_iter()
        .filter(|value| !value.is_empty() && *value != "Quality unmeasured")
        .collect::<Vec<_>>()
        .join(" · ")
}

fn paid_route_country_claim_text(session: &NativePaidRouteSessionState) -> String {
    match session.country_claim_status.as_str() {
        "match" => format!(
            "{} matches claim",
            non_empty_or(
                &session.observed_country_code,
                &session.claimed_country_code
            )
        ),
        "mismatch" => format!(
            "{} differs from {}",
            non_empty_or(&session.observed_country_code, "Observed country"),
            session.claimed_country_code,
        ),
        _ => non_empty_or(
            &session.observed_country_code,
            &non_empty_or(&session.claimed_country_code, "country unknown"),
        ),
    }
}

fn paid_route_traffic_unit_text(units: u64) -> String {
    format_bytes(units)
}

fn format_paid_route_msat(msat: u64) -> String {
    if msat >= 1_000 {
        let sat = msat as f64 / 1_000.0;
        if (sat.fract()).abs() < f64::EPSILON {
            format!("{sat:.0} sat")
        } else {
            format!("{sat:.3} sat")
        }
    } else {
        format!("{msat} msat")
    }
}

fn parse_positive_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok().filter(|value| *value > 0)
}
