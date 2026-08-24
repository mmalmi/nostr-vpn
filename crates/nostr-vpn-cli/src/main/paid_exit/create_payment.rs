
async fn paid_exit_create_payment_command(args: PaidExitCreatePaymentArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode buyer npub")?;
    let store_path = paid_route_store_file_path(&config_path);
    let now_unix = unix_timestamp();
    let (result, wallet_open_json, wallet_sign_json) = if args.sign_from_wallet {
        let signer = FileSpilmanPaymentSigner::load(&paid_exit_wallet_data_dir(&config_path))
            .map_err(|error| anyhow!("{error}"))?;
        let result = update_paid_route_store(&store_path, |store| {
            store.build_buyer_signed_payment_envelope(
                &signer,
                BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                    session_id: args.session.clone(),
                    buyer_npub,
                    kind: args.kind.into(),
                    delivered_units: args.delivered_units,
                    paid_msat: args.paid_msat,
                    now_unix,
                },
            )
        })?;
        (
            result,
            None,
            Some(json!({
                "source": "spilman-client-store",
                "data_dir": paid_exit_wallet_data_dir(&config_path).display().to_string(),
            })),
        )
    } else if args.open_from_wallet {
        if args.kind != PaidExitCreatePaymentKind::ChannelOpen {
            return Err(anyhow!(
                "--open-from-wallet currently creates channel_open payments; pass --kind channel-open"
            ));
        }
        let keyset_info_json =
            read_optional_paid_exit_keyset_info(args.keyset_info, args.keyset_info_file)?;
        let open_request = {
            let store = load_paid_route_store(&store_path)?;
            let session_record = store.sessions.get(&args.session).cloned().ok_or_else(|| {
                anyhow!("paid exit buyer session {} does not exist", args.session)
            })?;
            let lease_record = store
                .leases
                .get(&session_record.session.lease_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "paid exit lease {} does not exist",
                        session_record.session.lease_id
                    )
                })?;
            let channel_record = store
                .channels
                .get(&session_record.session.payment.channel_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "paid exit channel {} does not exist",
                        session_record.session.payment.channel_id
                    )
                })?;
            let quote_record = store
                .quotes
                .get(&lease_record.lease.quote_id)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "paid exit quote {} does not exist",
                        lease_record.lease.quote_id
                    )
                })?;
            let mint_url = args
                .mint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| channel_record.mint_url.clone());
            if mint_url.trim().is_empty() {
                return Err(anyhow!(
                    "paid exit session has no mint; pass --mint for --open-from-wallet"
                ));
            }
            let cashu_unit = if session_record.session.payment.cashu_unit.trim().is_empty() {
                "sat".to_string()
            } else {
                session_record.session.payment.cashu_unit.clone()
            };
            StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url,
                receiver_pubkey_hex: quote_record.quote.receiver_pubkey_hex,
                capacity_sat: session_record.session.payment.capacity_sat,
                expiry_unix: channel_record.expires_at_unix,
                max_amount_per_output: args.max_amount_per_output,
                unit: cashu_unit,
                opening_paid_msat: args
                    .paid_msat
                    .unwrap_or(session_record.session.payment.paid_msat),
                keyset_id: args.keyset_id,
                keyset_info_json,
            }
        };
        let opened: cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletResult =
            daemon_cashu_wallet_request(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::OpenSpilmanChannel {
                    request: open_request,
                },
            )
            .await?;
        let (result, attach) = update_paid_route_store(&store_path, |store| {
            let attach = store.attach_buyer_spilman_channel(
                AttachPaidRouteBuyerSpilmanChannelRequest {
                    session_id: args.session.clone(),
                    channel_id: opened.channel.channel_id.clone(),
                    cashu_unit: opened.channel.unit.clone(),
                    capacity_sat: opened.channel.capacity_sat,
                    paid_msat: Some(opened.channel.opening_paid_msat),
                    payment: opened.channel.payment.clone(),
                    now_unix,
                },
            )?;
            let result = store.build_buyer_payment_envelope(
                BuildPaidRouteBuyerPaymentEnvelopeRequest {
                    session_id: args.session.clone(),
                    buyer_npub,
                    kind: args.kind.into(),
                    payment: opened.channel.payment.clone(),
                    delivered_units: args.delivered_units,
                    paid_msat: Some(opened.channel.opening_paid_msat),
                    now_unix,
                },
            )?;
            Ok((result, attach))
        })?;
        let wallet_open_json = json!({
            "channel": opened.channel,
            "wallet_send": {
                "mint_url": opened.wallet_send.mint_url,
                "unit": opened.wallet_send.unit,
                "amount_sat": opened.wallet_send.amount_sat,
                "send_fee_sat": opened.wallet_send.send_fee_sat,
                "operation_id": opened.wallet_send.operation_id,
            },
            "attached": attach,
        });
        (result, Some(wallet_open_json), None)
    } else {
        let payment_json = read_paid_exit_spilman_payment(args.payment, args.payment_stdin)?;
        let payment: CashuSpilmanPayment = serde_json::from_str(&payment_json)
            .context("failed to decode Cashu Spilman payment JSON")?;
        let result = update_paid_route_store(&store_path, |store| {
            store.build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
                session_id: args.session.clone(),
                buyer_npub,
                kind: args.kind.into(),
                payment,
                delivered_units: args.delivered_units,
                paid_msat: args.paid_msat,
                now_unix,
            })
        })?;
        (result, None, None)
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "store_path": store_path.display().to_string(),
                "payment": result,
                "wallet_open": wallet_open_json,
                "wallet_sign": wallet_sign_json,
            }))?
        );
    } else {
        if let Some(wallet_open) = wallet_open_json.as_ref()
            && let Some(wallet_send) = wallet_open.get("wallet_send")
        {
            let amount_sat = wallet_send["amount_sat"].as_u64().unwrap_or_default();
            let fee_sat = wallet_send["send_fee_sat"].as_u64().unwrap_or_default();
            println!(
                "wallet_funding: amount={} fee={} operation={}",
                paid_exit_sat_text(amount_sat),
                paid_exit_sat_text(fee_sat),
                wallet_send["operation_id"].as_str().unwrap_or_default()
            );
        }
        if let Some(wallet_sign) = wallet_sign_json.as_ref() {
            println!(
                "wallet_sign: {}",
                wallet_sign["source"].as_str().unwrap_or_default()
            );
        }
        println!("paid_exit_payment: {}", result.payload_type);
        println!("session: {}", result.session_id);
        println!("seller: {}", result.seller_npub);
        println!("offer: {}", result.offer_id);
        println!("channel: {}", result.channel_id);
        println!(
            "routing: state={} allow={} paid={} due={} unpaid={} usage={}",
            result.state.as_str(),
            result.allow_routing,
            paid_exit_msat_text(result.paid_msat),
            paid_exit_msat_text(result.amount_due_msat),
            paid_exit_msat_text(result.unpaid_msat),
            paid_exit_usage_text(result.delivered_units)
        );
        println!("store: {} changed={}", store_path.display(), result.changed);
        println!(
            "envelope: {}",
            serde_json::to_string(&result.envelope)
                .context("failed to encode paid route payment envelope")?
        );
    }

    Ok(())
}

fn paid_exit_create_token_lease_command(args: PaidExitCreateTokenLeaseArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode buyer npub")?;
    let store_path = paid_route_store_file_path(&config_path);
    let token = read_paid_exit_wallet_token(args.token, args.token_stdin)?;
    let mint_url = args
        .mint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_mint_url)
        .transpose()?
        .unwrap_or_default();
    let result = update_paid_route_store(&store_path, |store| {
        store.build_buyer_token_lease_envelope(BuildPaidRouteBuyerTokenLeaseEnvelopeRequest {
            session_id: args.session.clone(),
            buyer_npub,
            mint_url,
            cashu_unit: args.unit,
            amount: args.amount,
            paid_msat: args.paid_msat,
            token,
            expires_at_unix: args.expires_at_unix,
            now_unix: unix_timestamp(),
        })
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "store_path": store_path.display().to_string(),
                "payment": result,
            }))?
        );
    } else {
        println!("paid_exit_payment: {}", result.payload_type);
        println!("session: {}", result.session_id);
        println!("seller: {}", result.seller_npub);
        println!("offer: {}", result.offer_id);
        println!("channel: {}", result.channel_id);
        println!(
            "routing: state={} allow={} paid={} due={} unpaid={} usage={}",
            result.state.as_str(),
            result.allow_routing,
            paid_exit_msat_text(result.paid_msat),
            paid_exit_msat_text(result.amount_due_msat),
            paid_exit_msat_text(result.unpaid_msat),
            paid_exit_usage_text(result.delivered_units)
        );
        println!("store: {} changed={}", store_path.display(), result.changed);
        println!(
            "envelope: {}",
            serde_json::to_string(&result.envelope)
                .context("failed to encode paid route token lease envelope")?
        );
    }

    Ok(())
}
