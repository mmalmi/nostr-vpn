fn paid_exit_provider_link_for_offer(offer: &PaidRouteOffer) -> Result<String> {
    ManualPaidExitProvider::seller_link(
        &offer.seller_npub,
        &PaidExitConfig::from_paid_route_offer(offer),
    )
}

fn paid_exit_seller_identity(app: &AppConfig) -> Result<(String, String)> {
    let seller_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode seller npub")?;
    let provider_link = ManualPaidExitProvider::seller_link(&seller_npub, &app.paid_exit)?;
    Ok((seller_npub, provider_link))
}

fn paid_exit_status_json(app: &AppConfig) -> serde_json::Value {
    let config = &app.paid_exit;
    json!({
        "enabled": config.enabled,
        "upstream": config.access.upstream.as_str(),
        "private_vpn_access": config.access.private_vpn_access.as_str(),
        "price_msat_per_gb": config.pricing.price_msat_per_gb,
        "price_text": paid_exit_price_text(config.pricing.price_msat_per_gb),
        "accepted_mints": &config.channel.accepted_mints,
        "max_channel_capacity_sat": config.channel.max_channel_capacity_sat,
        "channel_expiry_secs": config.channel.channel_expiry_secs,
        "channel_expiry_text": paid_exit_duration_text(config.channel.channel_expiry_secs),
        "settlement_text": paid_exit_settlement_text(config.channel.channel_expiry_secs),
        "free_probe_units": config.channel.free_probe_units,
        "free_probe_text": paid_exit_binary_bytes_text(config.channel.free_probe_units),
        "grace_units": config.channel.grace_units,
        "grace_text": paid_exit_binary_bytes_text(config.channel.grace_units),
        "country_code": &config.location.country_code,
        "asn": config.location.asn,
        "ipv4": config.ip_support.ipv4,
        "ipv6": config.ip_support.ipv6,
    })
}

fn print_paid_exit_status(app: &AppConfig) {
    let config = &app.paid_exit;
    println!(
        "paid_exit: {}",
        if config.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    if !config.enabled
        && config.channel.accepted_mints.is_empty()
        && config.pricing.price_msat_per_gb == 0
    {
        return;
    }

    println!(
        "paid_exit_price: {}",
        paid_exit_price_text(config.pricing.price_msat_per_gb)
    );
    println!(
        "paid_exit_access: upstream={} private_vpn_access={}",
        config.access.upstream.as_str(),
        config.access.private_vpn_access.as_str()
    );
    println!(
        "paid_exit_channel: max={} expiry={}s free_probe={} grace={}",
        paid_exit_sat_text(config.channel.max_channel_capacity_sat),
        config.channel.channel_expiry_secs,
        paid_exit_binary_bytes_text(config.channel.free_probe_units),
        paid_exit_binary_bytes_text(config.channel.grace_units)
    );
    println!(
        "paid_exit_settlement: {}",
        paid_exit_settlement_text(config.channel.channel_expiry_secs)
    );
    if !config.channel.accepted_mints.is_empty() {
        println!(
            "paid_exit_accepted_mints: {}",
            config.channel.accepted_mints.join(", ")
        );
    }
    println!(
        "paid_exit_location: country={} asn={}",
        display_or_none(&config.location.country_code),
        config
            .location
            .asn
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "paid_exit_ip_support: ipv4={} ipv6={}",
        config.ip_support.ipv4, config.ip_support.ipv6
    );
}

fn paid_exit_price_text(price_msat_per_gb: u64) -> String {
    if price_msat_per_gb == 0 {
        return "free".to_string();
    }
    format!(
        "{price_msat_per_gb} msat/GB · {}/GB",
        paid_exit_msat_text(price_msat_per_gb)
    )
}

fn paid_exit_settlement_text(channel_expiry_secs: u64) -> String {
    format!(
        "Automatic collection after {}; buyer refunds available after {}",
        paid_exit_duration_text(
            nostr_vpn_core::paid_routes::paid_route_collection_after_secs(channel_expiry_secs)
        ),
        paid_exit_duration_text(channel_expiry_secs)
    )
}

fn paid_exit_duration_text(seconds: u64) -> String {
    match seconds {
        0..=59 => paid_exit_plural_text(seconds.max(1), "sec"),
        60..=3_599 => paid_exit_plural_text((seconds / 60).max(1), "min"),
        3_600..=86_399 => {
            let hours = seconds / 3_600;
            let minutes = (seconds % 3_600) / 60;
            if minutes == 0 {
                paid_exit_plural_text(hours, "hour")
            } else {
                format!(
                    "{} {}",
                    paid_exit_plural_text(hours, "hour"),
                    paid_exit_plural_text(minutes, "min")
                )
            }
        }
        _ => {
            let days = seconds / 86_400;
            let hours = (seconds % 86_400) / 3_600;
            if hours == 0 {
                paid_exit_plural_text(days, "day")
            } else {
                format!(
                    "{} {}",
                    paid_exit_plural_text(days, "day"),
                    paid_exit_plural_text(hours, "hour")
                )
            }
        }
    }
}

fn paid_exit_plural_text(value: u64, unit: &str) -> String {
    if value == 1 || matches!(unit, "sec" | "min") {
        format!("{value} {unit}")
    } else {
        format!("{value} {unit}s")
    }
}

fn paid_exit_parse_traffic_units_arg(value: &str, flag: &str) -> Result<u64> {
    paid_exit_parse_units_arg(value, 1_024.0, flag)
}

fn paid_exit_parse_units_arg(value: &str, byte_scale: f64, flag: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{flag} cannot be empty"));
    }
    if let Ok(units) = trimmed.parse::<u64>() {
        return Ok(units);
    }
    paid_exit_parse_byte_units_text(trimmed, byte_scale, flag)
}

fn paid_exit_parse_byte_units_text(value: &str, scale: f64, flag: &str) -> Result<u64> {
    let normalized = value.trim().to_lowercase();
    let mut characters = normalized.chars().peekable();
    let mut number_text = String::new();
    while let Some(character) = characters.peek().copied() {
        if character.is_ascii_digit() || character == '.' {
            number_text.push(character);
            characters.next();
        } else if character == ',' || character == '_' {
            characters.next();
        } else {
            break;
        }
    }
    while matches!(characters.peek(), Some(character) if character.is_whitespace()) {
        characters.next();
    }
    let unit_text = characters
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if unit_text
        .chars()
        .any(|character| character.is_ascii_digit() || matches!(character, '.' | ',' | '_'))
    {
        return Err(anyhow!("{flag} has invalid byte unit '{unit_text}'"));
    }
    let amount = number_text
        .parse::<f64>()
        .map_err(|_| anyhow!("{flag} has invalid byte amount '{value}'"))?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(anyhow!("{flag} has invalid byte amount '{value}'"));
    }
    let multiplier = match unit_text.as_str() {
        "" | "b" | "byte" | "bytes" => 1.0,
        "k" | "kb" | "kib" => scale,
        "m" | "mb" | "mib" => scale.powi(2),
        "g" | "gb" | "gib" => scale.powi(3),
        "t" | "tb" | "tib" => scale.powi(4),
        _ => return Err(anyhow!("{flag} has unsupported byte unit '{unit_text}'")),
    };
    let units = (amount * multiplier).round();
    if !units.is_finite() || units < 0.0 || units > u64::MAX as f64 {
        return Err(anyhow!("{flag} byte amount is out of range"));
    }
    Ok(units as u64)
}

fn paid_exit_msat_text(msat: u64) -> String {
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

fn paid_exit_sat_text(sat: u64) -> String {
    format!("{sat} sat")
}

fn paid_exit_usage_text(bytes: u64) -> String {
    format!("{} used", paid_exit_binary_bytes_text(bytes))
}

fn paid_exit_binary_bytes_text(bytes: u64) -> String {
    paid_exit_scaled_bytes_text(bytes, 1_024.0)
}

fn paid_exit_scaled_bytes_text(bytes: u64, threshold: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut index = 0usize;
    while value >= threshold && index < units.len() - 1 {
        value /= threshold;
        index += 1;
    }
    if index == 0 {
        format!("{bytes} B")
    } else if (value - value.round()).abs() < 0.05 {
        format!("{value:.0} {}", units[index])
    } else {
        format!("{value:.1} {}", units[index])
    }
}
