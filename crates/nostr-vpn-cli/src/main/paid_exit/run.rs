struct PaidExitRunResult {
    config_path: PathBuf,
    store_path: PathBuf,
    offer: PaidRouteOffer,
    provider_link: String,
    event_id: String,
    stored: bool,
    publish: Option<serde_json::Value>,
    daemon_reload_attempted: bool,
    status: serde_json::Value,
}

async fn paid_exit_run_command(args: PaidExitRunArgs) -> Result<()> {
    let json_output = args.json;
    let result = paid_exit_run_once(args).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_run_result_json(&result))?
        );
    } else {
        print_paid_exit_run_result(&result);
    }

    Ok(())
}

async fn paid_exit_run_once(args: PaidExitRunArgs) -> Result<PaidExitRunResult> {
    if args.publish && args.no_reload_daemon {
        return Err(anyhow!(
            "--publish requires daemon reload; remove --no-reload-daemon"
        ));
    }
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let mut app = load_or_default_config(&config_path)?;
    apply_paid_exit_run_settings(&mut app, &args)?;
    app.ensure_defaults();
    ensure_paid_exit_advertisable(&app)?;
    app.save(&config_path)?;

    let daemon_reload_attempted = !args.no_reload_daemon;
    if args.publish {
        reload_running_daemon_after_save(&config_path)?;
        require_paid_exit_seller_daemon_ready(&config_path, true).await?;
    } else if daemon_reload_attempted {
        maybe_reload_running_daemon(&config_path);
    }

    let offer_id = args.offer_id.unwrap_or_else(default_paid_exit_offer_id);
    let local = build_local_paid_exit_offer(&app, &config_path, &offer_id, unix_timestamp())?;

    let publish = if args.publish {
        Some(publish_paid_exit_offer_pubsub(
            &app,
            &config_path,
            &local.signed,
        )?)
    } else {
        None
    };
    let store = load_paid_route_store(&local.store_path)?;
    let status = paid_exit_status_snapshot_json(&app, &local.store_path, &store)?;
    let provider_link = paid_exit_provider_link_for_offer(&local.offer)?;

    Ok(PaidExitRunResult {
        config_path,
        store_path: local.store_path,
        offer: local.offer,
        provider_link,
        event_id: local.signed.event.id.to_string(),
        stored: local.stored,
        publish,
        daemon_reload_attempted,
        status,
    })
}

fn apply_paid_exit_run_settings(app: &mut AppConfig, args: &PaidExitRunArgs) -> Result<()> {
    app.set_paid_exit_seller_enabled(true);
    if let Some(value) = args.upstream.as_deref() {
        set_paid_exit_upstream(app, value)?;
    }
    if let Some(value) = args.price_msat_per_gb {
        app.paid_exit.pricing.price_msat_per_gb = value;
    }
    if let Some(mints) = paid_exit_run_accepted_mints(args)? {
        app.paid_exit.channel.accepted_mints = mints;
    }
    if let Some(value) = args.country_code.as_deref() {
        app.paid_exit.location.country_code = value.to_string();
    }
    if let Some(value) = args.network_class {
        app.paid_exit.location.network_class = value;
    }
    if let Some(value) = args.asn {
        app.paid_exit.location.asn = Some(value);
    }
    if let Some(value) = args.max_channel_capacity_sat {
        app.paid_exit.channel.max_channel_capacity_sat = value;
    }
    if let Some(value) = args.channel_expiry_secs {
        app.paid_exit.channel.channel_expiry_secs = value;
    }
    if let Some(value) = args.free_probe_units.as_deref() {
        app.paid_exit.channel.free_probe_units =
            paid_exit_parse_traffic_units_arg(value, "--free-probe-units")?;
    }
    if let Some(value) = args.grace_units.as_deref() {
        app.paid_exit.channel.grace_units =
            paid_exit_parse_traffic_units_arg(value, "--grace-units")?;
    }
    app.paid_exit.normalize();
    Ok(())
}

fn paid_exit_run_accepted_mints(args: &PaidExitRunArgs) -> Result<Option<Vec<String>>> {
    if args.accepted_mints.is_none() && args.accepted_mint.is_empty() {
        return Ok(None);
    }

    let mut values = Vec::new();
    if let Some(csv) = args.accepted_mints.as_deref() {
        values.extend(parse_csv_arg(csv));
    }
    values.extend(args.accepted_mint.iter().cloned());

    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        normalized.push(normalize_mint_url(value)?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(Some(normalized))
}

fn paid_exit_spilman_receiver_pubkey_hex(
    config_path: &Path,
    paid_exit: &PaidExitConfig,
) -> Result<Option<String>> {
    let mut paid_exit = paid_exit.clone();
    paid_exit.normalize();
    if paid_exit.channel.accepted_mints.is_empty() {
        return Ok(None);
    }
    let key = load_or_create_cashu_spilman_receiver_key(&paid_exit_wallet_data_dir(config_path))
        .map_err(|error| anyhow!("{error}"))?;
    Ok(Some(key.public_key_hex))
}

fn paid_exit_spilman_receiver_config(
    paid_exit: &PaidExitConfig,
) -> Option<FileSpilmanPaymentReceiverConfig> {
    let mut paid_exit = paid_exit.clone();
    paid_exit.normalize();
    if paid_exit.channel.accepted_mints.is_empty() {
        return None;
    }
    Some(FileSpilmanPaymentReceiverConfig {
        accepted_mints: paid_exit.channel.accepted_mints,
        units: vec!["sat".to_string()],
        min_capacity: 1,
        max_amount_per_output: 0,
        min_expiry_seconds: 0,
    })
}

async fn try_load_paid_exit_spilman_receiver(
    config_path: &Path,
    paid_exit: &PaidExitConfig,
) -> (Option<FileSpilmanPaymentReceiver>, Option<String>) {
    let Some(receiver_config) = paid_exit_spilman_receiver_config(paid_exit) else {
        return (None, Some("no accepted Cashu mints configured".to_string()));
    };
    match FileSpilmanPaymentReceiver::load_with_keyset_refresh(
        &paid_exit_wallet_data_dir(config_path),
        receiver_config,
    )
    .await
    {
        Ok(receiver) => (Some(receiver), None),
        Err(error) => (None, Some(error)),
    }
}

fn apply_paid_route_seller_payment(
    store: &mut PaidRouteStore,
    request: ApplyPaidRouteSellerPaymentRequest,
    receiver: Option<&FileSpilmanPaymentReceiver>,
    receiver_error: Option<&str>,
) -> Result<nostr_vpn_core::paid_route_store::ApplyPaidRouteSellerPaymentResult> {
    match receiver {
        Some(receiver) => {
            if let cashu_service::StreamingRoutePaymentPayload::ChannelOpen(open) =
                &request.envelope.payload
            {
                let requested_receiver = open.receiver_pubkey_hex.trim();
                let local_receiver = receiver.receiver_pubkey_hex();
                if !requested_receiver.eq_ignore_ascii_case(local_receiver) {
                    return Err(anyhow!(
                        "paid route channel receiver pubkey {} does not match local receiver {}",
                        requested_receiver,
                        local_receiver
                    ));
                }
            }
            let context = "{}".to_string();
            store.apply_seller_payment_with_spilman_receiver(request, receiver, &context)
        }
        None => {
            let detail = receiver_error
                .filter(|error| !error.trim().is_empty())
                .unwrap_or("receiver unavailable");
            Err(anyhow!(
                "paid exit Spilman receiver is unavailable ({detail}); refusing to apply unvalidated paid route payment"
            ))
        }
    }
}

fn paid_exit_run_result_json(result: &PaidExitRunResult) -> serde_json::Value {
    json!({
        "config_path": result.config_path.display().to_string(),
        "store_path": result.store_path.display().to_string(),
        "enabled": true,
        "offer": result.offer,
        "provider_link": result.provider_link,
        "event_id": result.event_id,
        "stored": result.stored,
        "published": result.publish.is_some(),
        "publish": result.publish,
        "daemon_reload_attempted": result.daemon_reload_attempted,
        "status": result.status,
    })
}

fn print_paid_exit_run_result(result: &PaidExitRunResult) {
    println!("paid_exit_seller: enabled");
    println!("config: {}", result.config_path.display());
    println!(
        "store: {} changed={}",
        result.store_path.display(),
        result.stored
    );
    println!("paid_exit_offer: {}", result.offer.offer_id);
    println!("seller: {}", result.offer.seller_npub);
    println!("provider_link: {}", result.provider_link);
    println!("event_id: {}", result.event_id);
    println!(
        "price: {}",
        paid_exit_price_text(result.offer.pricing.price_msat_per_gb)
    );
    println!(
        "access: upstream={} private_vpn_access={}",
        result.offer.access.upstream.as_str(),
        result.offer.access.private_vpn_access.as_str()
    );
    println!(
        "channel: max={} expiry={}s free_probe={} grace={} accepted_mints={}",
        paid_exit_sat_text(result.offer.channel.max_channel_capacity_sat),
        result.offer.channel.channel_expiry_secs,
        paid_exit_binary_bytes_text(result.offer.channel.free_probe_units),
        paid_exit_binary_bytes_text(result.offer.channel.grace_units),
        if result.offer.channel.accepted_mints.is_empty() {
            "none".to_string()
        } else {
            result.offer.channel.accepted_mints.join(", ")
        }
    );
    println!(
        "location: country={} asn={}",
        display_or_none(&result.offer.location.country_code),
        result
            .offer
            .location
            .asn
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    if let Some(publish) = &result.publish {
        println!(
            "published: nostr-pubsub queued={}",
            publish["nostr_pubsub_queued"].as_bool().unwrap_or_default()
        );
    } else {
        println!("published: false");
    }
    println!(
        "daemon_reload: {}",
        if result.daemon_reload_attempted {
            "attempted"
        } else {
            "skipped"
        }
    );
}
