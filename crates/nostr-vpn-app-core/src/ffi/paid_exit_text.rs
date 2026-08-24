fn paid_route_session_status_text(
    access_state: Option<PaidRouteAccessState>,
    channel: Option<&PaidRouteChannelRecord>,
) -> String {
    if let Some(channel) = channel
        && !channel.error.trim().is_empty()
    {
        return channel.error.clone();
    }
    match access_state {
        Some(PaidRouteAccessState::FreeProbe) => "Free probe".to_string(),
        Some(PaidRouteAccessState::Paid) => "Paid".to_string(),
        Some(PaidRouteAccessState::Grace) => "Awaiting payment update".to_string(),
        Some(PaidRouteAccessState::Suspended) => "Suspended until paid".to_string(),
        None => "Payment state pending".to_string(),
    }
}

fn paid_route_price_text(price_msat_per_gb: u64) -> String {
    if price_msat_per_gb == 0 {
        "free".to_string()
    } else {
        format!("{price_msat_per_gb} msat/GB")
    }
}

#[allow(clippy::cast_precision_loss)]
fn paid_route_price_text_with_fiat(
    price_msat_per_gb: u64,
    fiat_per_btc: Option<f64>,
    currency: &str,
    exchange_rate_stale: bool,
) -> String {
    let mut text = paid_route_price_text(price_msat_per_gb);
    if exchange_rate_stale {
        return text;
    }
    let Some(rate) = fiat_per_btc.filter(|rate| rate.is_finite() && *rate > 0.0) else {
        return text;
    };
    if price_msat_per_gb == 0 || currency.trim().is_empty() {
        return text;
    }
    let value = price_msat_per_gb as f64 / 100_000_000_000.0 * rate;
    let decimals = if value >= 0.01 { 2 } else { 6 };
    let mut value = format!("{value:.decimals$}");
    while value.contains('.') && value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.pop();
    }
    let _ = write!(&mut text, " · ≈ {value} {}/GB", currency.trim());
    text
}

fn paid_route_paid_text(msat: u64) -> String {
    format!("{} paid", paid_route_msat_text(msat))
}

fn paid_route_sat_text(sat: u64) -> String {
    format!("{sat} sat")
}

fn paid_route_fee_text(sat: u64) -> String {
    if sat == 0 {
        String::new()
    } else {
        format!("{sat} sat fee")
    }
}

fn paid_route_due_text(msat: u64) -> String {
    format!("{} due", paid_route_msat_text(msat))
}

fn paid_route_unpaid_text(msat: u64) -> String {
    if msat == 0 {
        String::new()
    } else {
        format!("{} behind", paid_route_msat_text(msat))
    }
}

fn paid_route_msat_text(msat: u64) -> String {
    if msat == 0 {
        return "0 sat".to_string();
    }
    let whole = msat / 1_000;
    let remainder = msat % 1_000;
    if remainder == 0 {
        format!("{whole} sat")
    } else {
        format!("{whole}.{remainder:03} sat")
    }
}

fn paid_route_session_title_text(
    status_text: &str,
    lifecycle_status: &str,
    payment_channel_ready: bool,
    allow_routing: bool,
    unpaid_msat: u64,
) -> String {
    if lifecycle_status == "expired" {
        "Ended".to_string()
    } else if lifecycle_status == "closed" {
        "Closed".to_string()
    } else if lifecycle_status == "failed" {
        "Connection failed".to_string()
    } else if allow_routing {
        "Ready".to_string()
    } else if unpaid_msat > 0 {
        "Payment needed".to_string()
    } else if !payment_channel_ready {
        "Needs funds".to_string()
    } else {
        paid_route_plain_status_text(
            if status_text.trim().is_empty() {
                lifecycle_status
            } else {
                status_text
            },
            "Session",
        )
    }
}

fn paid_route_seller_session_title_text(session: &NativePaidRouteSessionState) -> String {
    if session.allow_routing {
        "Buyer online".to_string()
    } else if session.unpaid_msat > 0 {
        "Waiting for payment".to_string()
    } else if session.payment_channel_ready && session.paid_msat > 0 {
        "Ready to collect".to_string()
    } else if !session.payment_channel_ready {
        "Waiting for channel".to_string()
    } else {
        paid_route_plain_status_text(&session.status_text, "Buyer session")
    }
}

fn paid_exit_seller_settlement_text(channel_expiry_secs: u64) -> String {
    format!(
        "Channels end after {} or when you manually collect",
        paid_route_duration_text(channel_expiry_secs)
    )
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn paid_route_session_settlement_text(
    channel_role: Option<PaidRouteChannelRole>,
    lifecycle_status: &str,
    expires_at_unix: u64,
    allow_routing: bool,
    payment_channel_ready: bool,
    paid_msat: u64,
    channel_id: &str,
    collection_available: bool,
    auto_collect_due: bool,
    now_unix: u64,
) -> String {
    if lifecycle_status == "closed" {
        return match channel_role {
            Some(PaidRouteChannelRole::Seller) => "Collected".to_string(),
            _ => "Channel closed".to_string(),
        };
    }
    if expires_at_unix == 0 {
        return String::new();
    }
    let is_collectable_seller = collection_available
        || paid_route_session_has_seller_collection(
            channel_role,
            payment_channel_ready,
            paid_msat,
            channel_id,
        );
    if expires_at_unix <= now_unix {
        return if auto_collect_due {
            "Ended; collect to move funds to wallet".to_string()
        } else if is_collectable_seller {
            "Ended; collect when ready".to_string()
        } else {
            "Ended".to_string()
        };
    }

    let remaining = paid_route_duration_text(expires_at_unix.saturating_sub(now_unix));
    match channel_role {
        Some(PaidRouteChannelRole::Seller) if is_collectable_seller && allow_routing => {
            format!("Ends in {remaining} or when you manually collect")
        }
        Some(PaidRouteChannelRole::Seller) if is_collectable_seller => {
            format!("Ready to collect; expires in {remaining}")
        }
        Some(PaidRouteChannelRole::Seller) => format!("Ends in {remaining}"),
        _ => format!("Channel ends in {remaining}"),
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn paid_route_session_collect_action_text(
    channel_role: Option<PaidRouteChannelRole>,
    payment_channel_ready: bool,
    allow_routing: bool,
    paid_msat: u64,
    channel_id: &str,
    collection_available: bool,
    auto_collect_due: bool,
) -> String {
    if !(collection_available
        || paid_route_session_has_seller_collection(
            channel_role,
            payment_channel_ready,
            paid_msat,
            channel_id,
        ))
    {
        return String::new();
    }
    if auto_collect_due {
        "Collect".to_string()
    } else if allow_routing {
        "End & Collect".to_string()
    } else {
        "Collect".to_string()
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn paid_route_session_collect_action_help_text(
    channel_role: Option<PaidRouteChannelRole>,
    payment_channel_ready: bool,
    allow_routing: bool,
    paid_msat: u64,
    channel_id: &str,
    collection_available: bool,
    auto_collect_due: bool,
) -> String {
    if paid_route_session_collect_action_text(
        channel_role,
        payment_channel_ready,
        allow_routing,
        paid_msat,
        channel_id,
        collection_available,
        auto_collect_due,
    )
    .is_empty()
    {
        return String::new();
    }
    if auto_collect_due {
        "Move ended channel funds to wallet".to_string()
    } else if allow_routing {
        "Stop routing and move paid channel funds to wallet".to_string()
    } else {
        "Move paid channel funds to wallet".to_string()
    }
}

fn paid_route_session_has_seller_collection(
    channel_role: Option<PaidRouteChannelRole>,
    payment_channel_ready: bool,
    paid_msat: u64,
    channel_id: &str,
) -> bool {
    matches!(channel_role, Some(PaidRouteChannelRole::Seller))
        && payment_channel_ready
        && paid_msat > 0
        && !channel_id.trim().is_empty()
}

fn paid_route_session_detail_text(
    lifecycle_status: &str,
    access_state: &str,
    usage_text: &str,
    amount_due_msat: u64,
) -> String {
    format!(
        "{}, {}, {}",
        paid_route_access_title_text(
            access_state,
            if lifecycle_status.trim().is_empty() {
                "session"
            } else {
                lifecycle_status
            },
        ),
        usage_text,
        paid_route_due_text(amount_due_msat)
    )
}

fn paid_route_usage_text(bytes: u64) -> String {
    format!("{} used", paid_route_binary_bytes_text(bytes))
}

fn paid_route_access_title_text(value: &str, fallback: &str) -> String {
    match value {
        "paid" => "Paid".to_string(),
        "free_probe" => "Free test".to_string(),
        "grace" => "Grace".to_string(),
        "suspended" => "Paused".to_string(),
        _ => paid_route_plain_status_text(value, fallback),
    }
}

fn paid_route_plain_status_text(value: &str, fallback: &str) -> String {
    let raw = if value.trim().is_empty() {
        fallback.trim()
    } else {
        value.trim()
    };
    match raw {
        "opening" => "Opening".to_string(),
        "probing" => "Checking quality".to_string(),
        "active" => "Active".to_string(),
        "paused" => "Paused".to_string(),
        "closed" => "Closed".to_string(),
        "session" => "Session".to_string(),
        _ => paid_route_humanize(raw),
    }
}

fn paid_route_humanize(value: &str) -> String {
    let text = value.replace('_', " ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn paid_route_location_text(
    realized_exit_ip: &str,
    country_claim: &PaidRouteCountryClaim,
) -> String {
    let claim_text = paid_route_country_claim_text(country_claim);
    if !realized_exit_ip.trim().is_empty() && !claim_text.trim().is_empty() {
        format!("{} - {}", realized_exit_ip.trim(), claim_text)
    } else if !realized_exit_ip.trim().is_empty() {
        realized_exit_ip.trim().to_string()
    } else {
        claim_text
    }
}

fn paid_route_country_claim_text(country_claim: &PaidRouteCountryClaim) -> String {
    match country_claim.status.as_str() {
        "match" => {
            let observed = if country_claim.observed_country_code.is_empty() {
                &country_claim.claimed_country_code
            } else {
                &country_claim.observed_country_code
            };
            if observed.is_empty() {
                String::new()
            } else {
                format!("{observed} matches claim")
            }
        }
        "mismatch" => {
            let observed = if country_claim.observed_country_code.is_empty() {
                "Observed country"
            } else {
                country_claim.observed_country_code.as_str()
            };
            if country_claim.claimed_country_code.is_empty() {
                "country mismatch".to_string()
            } else {
                format!(
                    "{observed} differs from {}",
                    country_claim.claimed_country_code
                )
            }
        }
        _ => {
            if !country_claim.observed_country_code.is_empty() {
                country_claim.observed_country_code.clone()
            } else if !country_claim.claimed_country_code.is_empty() {
                country_claim.claimed_country_code.clone()
            } else {
                String::new()
            }
        }
    }
}

fn paid_route_quality_text(quality: Option<&PaidRouteQualityMetrics>) -> String {
    let Some(quality) = quality else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(latency_ms) = quality.latency_ms {
        parts.push(format!("{latency_ms} ms"));
    }
    if let Some(jitter_ms) = quality.jitter_ms {
        parts.push(format!("{jitter_ms} ms jitter"));
    }
    if let Some(packet_loss_ppm) = quality.packet_loss_ppm {
        parts.push(format!(
            "{} loss",
            paid_route_packet_loss_text(packet_loss_ppm)
        ));
    }
    parts.join(" - ")
}

fn paid_route_bandwidth_text(quality: Option<&PaidRouteQualityMetrics>) -> String {
    let Some(quality) = quality else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(down_bps) = quality.down_bps.filter(|value| *value > 0) {
        parts.push(format!("{} down", paid_route_bitrate_text(down_bps)));
    }
    if let Some(up_bps) = quality.up_bps.filter(|value| *value > 0) {
        parts.push(format!("{} up", paid_route_bitrate_text(up_bps)));
    }
    parts.join(" - ")
}

fn paid_route_packet_loss_text(packet_loss_ppm: u32) -> String {
    let percent = f64::from(packet_loss_ppm) / 10_000.0;
    if percent.abs() < 0.005 {
        "0%".to_string()
    } else if percent >= 10.0 {
        format!("{percent:.1}%")
    } else {
        format!("{percent:.2}%")
    }
}

#[allow(clippy::cast_precision_loss)]
fn paid_route_bitrate_text(bps: u64) -> String {
    let units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut value = bps as f64;
    let mut unit_index = 0usize;
    while value >= 1_000.0 && unit_index < units.len() - 1 {
        value /= 1_000.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bps} bps")
    } else if value.fract().abs() < 0.05 {
        format!("{value:.0} {}", units[unit_index])
    } else {
        format!("{value:.1} {}", units[unit_index])
    }
}

fn paid_route_duration_text(seconds: u64) -> String {
    match seconds {
        0..=59 => plural_text(seconds.max(1), "sec"),
        60..=3_599 => plural_text((seconds / 60).max(1), "min"),
        3_600..=86_399 => {
            let hours = seconds / 3_600;
            let minutes = (seconds % 3_600) / 60;
            if minutes == 0 {
                plural_text(hours, "hour")
            } else {
                format!(
                    "{} {}",
                    plural_text(hours, "hour"),
                    plural_text(minutes, "min")
                )
            }
        }
        _ => {
            let days = seconds / 86_400;
            let hours = (seconds % 86_400) / 3_600;
            if hours == 0 {
                plural_text(days, "day")
            } else {
                format!(
                    "{} {}",
                    plural_text(days, "day"),
                    plural_text(hours, "hour")
                )
            }
        }
    }
}

fn plural_text(value: u64, unit: &str) -> String {
    if value == 1 || matches!(unit, "sec" | "min") {
        format!("{value} {unit}")
    } else {
        format!("{value} {unit}s")
    }
}

#[allow(clippy::cast_precision_loss)]
fn paid_route_binary_bytes_text(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;
    while value >= 1_024.0 && unit_index < units.len() - 1 {
        value /= 1_024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bytes} B")
    } else if value.fract().abs() < 0.05 {
        format!("{value:.0} {}", units[unit_index])
    } else {
        format!("{value:.1} {}", units[unit_index])
    }
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

fn paid_route_lifecycle_allows_routing_for_state(status: PaidRouteLifecycleStatus) -> bool {
    matches!(
        status,
        PaidRouteLifecycleStatus::Opening
            | PaidRouteLifecycleStatus::Probing
            | PaidRouteLifecycleStatus::Active
    )
}

fn paid_route_offer_requires_payment_before_routing_for_state(offer: &PaidRouteOffer) -> bool {
    offer.pricing.price_msat_per_gb > 0 && offer.channel.free_probe_units == 0
}

fn paid_route_lifecycle_is_current(status: PaidRouteLifecycleStatus) -> bool {
    !matches!(
        status,
        PaidRouteLifecycleStatus::Closed
            | PaidRouteLifecycleStatus::Expired
            | PaidRouteLifecycleStatus::Failed
    )
}
