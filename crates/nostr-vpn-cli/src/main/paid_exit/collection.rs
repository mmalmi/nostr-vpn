
#[derive(Debug, Default)]
pub(crate) struct PaidExitApplyFipsPaymentsResult {
    pub(crate) received_count: usize,
    pub(crate) applied_count: usize,
    pub(crate) error_count: usize,
    pub(crate) changed: bool,
    pub(crate) spilman_receiver_processing: bool,
    pub(crate) acknowledgments: Vec<(String, String)>,
}

pub(crate) fn paid_exit_apply_fips_payments(
    app: &AppConfig,
    config_path: &Path,
    payments: Vec<(String, String, StreamingRoutePaymentEnvelope)>,
    spilman_receiver: Option<&FileSpilmanPaymentReceiver>,
    spilman_receiver_error: Option<&str>,
) -> Result<PaidExitApplyFipsPaymentsResult> {
    if payments.is_empty() {
        return Ok(PaidExitApplyFipsPaymentsResult::default());
    }
    let seller_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode seller npub")?;
    let store_path = paid_route_store_file_path(config_path);
    let spilman_receiver_processing = spilman_receiver.is_some();
    let received_count = payments.len();
    let (applied_count, error_count, changed, acknowledgments) =
        update_paid_route_store(&store_path, |store| {
            let mut applied_count = 0;
            let mut error_count = 0;
            let mut changed = false;
            let mut acknowledgments = Vec::new();
            for (sender_pubkey, id, envelope) in payments {
                if normalize_nostr_pubkey(&envelope.buyer).ok().as_deref()
                    != Some(&sender_pubkey)
                {
                    error_count += 1;
                    continue;
                }
                match apply_paid_route_seller_payment(
                    store,
                    ApplyPaidRouteSellerPaymentRequest {
                        envelope,
                        seller_npub: seller_npub.clone(),
                        config: app.paid_exit.clone(),
                        now_unix: unix_timestamp(),
                    },
                    spilman_receiver,
                    spilman_receiver_error,
                ) {
                    Ok(result) => {
                        applied_count += 1;
                        changed |= result.changed;
                        acknowledgments.push((sender_pubkey, id));
                    }
                    Err(error) => {
                        error_count += 1;
                        eprintln!(
                            "paid-exit: rejected direct FIPS payment from {sender_pubkey}: {error}"
                        );
                    }
                }
            }
            Ok((applied_count, error_count, changed, acknowledgments))
        })?;
    Ok(PaidExitApplyFipsPaymentsResult {
        received_count,
        applied_count,
        error_count,
        changed,
        spilman_receiver_processing,
        acknowledgments,
    })
}

struct PaidExitCollectChannelOutcome {
    close: CashuSpilmanReceiverCloseResult,
    wallet_collect: Option<serde_json::Value>,
    changed: bool,
}

async fn paid_exit_collect_channel_with_receiver(
    receiver: &FileSpilmanPaymentReceiver,
    config_path: &Path,
    store_path: &Path,
    channel_id: &str,
) -> Result<PaidExitCollectChannelOutcome> {
    let close = receiver
        .close_cashu_spilman_channel(channel_id)
        .await
        .map_err(|error| anyhow!("{error}"))?;

    let changed = update_paid_route_store(store_path, |store| {
        store.mark_seller_channel_closed(
            &close.channel_id,
            close.closed_amount.saturating_mul(1_000),
            unix_timestamp(),
        )
    })?;
    let wallet_collect = if close.receiver_proofs_json.trim().is_empty() {
        None
    } else {
        let imported: cashu_service::CashuReceivedPayment = daemon_cashu_wallet_request(
                config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::ImportProofs {
                    mint_url: close.mint_url.clone(),
                    unit: close.unit.clone(),
                    proofs_json: close.receiver_proofs_json.clone(),
                },
            )
            .await?;
        Some(json!(imported))
    };

    Ok(PaidExitCollectChannelOutcome {
        close,
        wallet_collect,
        changed,
    })
}

async fn paid_exit_collect_command(args: PaidExitCollectArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    let receiver_config = paid_exit_spilman_receiver_config(&app.paid_exit)
        .ok_or_else(|| anyhow!("no accepted Cashu mints configured"))?;
    let wallet_data_dir = paid_exit_wallet_data_dir(&config_path);
    let receiver =
        FileSpilmanPaymentReceiver::load_with_keyset_refresh(&wallet_data_dir, receiver_config)
            .await
            .map_err(|error| anyhow!("{error}"))?;

    let store_path = paid_route_store_file_path(&config_path);
    let outcome = paid_exit_collect_channel_with_receiver(
        &receiver,
        &config_path,
        &store_path,
        &args.channel,
    )
    .await?;
    let mut changed = outcome.changed;
    let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
        crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
        &config_path,
        crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
            refresh_quotes: false,
        },
    )
    .await?,
    )?;
    let (wallet_changed, store) = update_paid_route_store(&store_path, |store| {
        let changed = sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
        Ok((changed, store.clone()))
    })?;
    changed |= wallet_changed;
    let daemon_reload_attempted = changed && !args.no_reload_daemon;
    if daemon_reload_attempted {
        maybe_reload_running_daemon(&config_path);
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "store_path": store_path.display().to_string(),
                "wallet_data_dir": wallet_data_dir.display().to_string(),
                "spilman_close": paid_exit_spilman_close_result_json(&outcome.close),
                "wallet_collect": outcome.wallet_collect,
                "cashu": cashu_wallet_overview_json(&overview),
                "changed": changed,
                "daemon_reload_attempted": daemon_reload_attempted,
                "status": paid_exit_status_snapshot_json(&app, &store_path, &store)?,
            }))?
        );
    } else {
        println!("paid_exit_collect: {}", outcome.close.channel_id);
        println!(
            "collected: {}",
            paid_exit_sat_text(outcome.close.receiver_sum)
        );
        println!(
            "buyer_refund: {}",
            paid_exit_sat_text(outcome.close.sender_sum)
        );
        println!(
            "receiver_proofs: {}",
            if outcome.close.receiver_proofs_json.trim().is_empty() {
                "missing"
            } else {
                "saved"
            }
        );
        let wallet_collect_amount_sat =
            paid_exit_wallet_collect_amount_sat(outcome.wallet_collect.as_ref());
        match outcome.wallet_collect {
            Some(_) if wallet_collect_amount_sat > 0 => {
                println!(
                    "wallet_collected: {}",
                    paid_exit_sat_text(wallet_collect_amount_sat)
                );
            }
            Some(_) => {
                println!("wallet_collected: already imported");
            }
            None => {
                println!("wallet_collected: skipped");
            }
        }
        println!("store: {} changed={changed}", store_path.display());
        println!(
            "daemon_reload: {}",
            if daemon_reload_attempted {
                "attempted"
            } else {
                "skipped"
            }
        );
    }

    Ok(())
}

async fn paid_exit_collect_due_command(args: PaidExitCollectDueArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    let store_path = paid_route_store_file_path(&config_path);
    let wallet_data_dir = paid_exit_wallet_data_dir(&config_path);
    let mut due = load_paid_route_store(&store_path)?
        .seller_collection_states(&app.paid_exit, unix_timestamp())
        .into_iter()
        .filter(|state| state.auto_collect_due)
        .collect::<Vec<_>>();
    if args.limit > 0 {
        due.truncate(args.limit);
    }

    let mut collected = Vec::new();
    let mut errors = Vec::new();
    let mut changed = false;
    if !due.is_empty() {
        let receiver_config = paid_exit_spilman_receiver_config(&app.paid_exit)
            .ok_or_else(|| anyhow!("no accepted Cashu mints configured"))?;
        let receiver =
            FileSpilmanPaymentReceiver::load_with_keyset_refresh(&wallet_data_dir, receiver_config)
                .await
                .map_err(|error| anyhow!("{error}"))?;
        for state in &due {
            match paid_exit_collect_channel_with_receiver(
                &receiver,
                &config_path,
                &store_path,
                &state.channel_id,
            )
            .await
            {
                Ok(outcome) => {
                    changed |= outcome.changed;
                    collected.push(paid_exit_collect_channel_outcome_json(&outcome));
                }
                Err(error) => {
                    errors.push(json!({
                        "channel_id": state.channel_id,
                        "session_id": state.session_id,
                        "error": error.to_string(),
                    }));
                }
            }
        }
    }

    let cashu = if collected.is_empty() {
        serde_json::Value::Null
    } else {
        let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
            crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
            &config_path,
            crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                refresh_quotes: false,
            },
        )
        .await?,
        )?;
        changed |= update_paid_route_store(&store_path, |store| {
            Ok(sync_paid_exit_wallet_store_from_cashu(
                store,
                &overview,
                unix_timestamp(),
            ))
        })?;
        json!(cashu_wallet_overview_json(&overview))
    };
    let store = load_paid_route_store(&store_path)?;
    let daemon_reload_attempted = changed && !args.no_reload_daemon;
    if daemon_reload_attempted {
        maybe_reload_running_daemon(&config_path);
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "store_path": store_path.display().to_string(),
                "wallet_data_dir": wallet_data_dir.display().to_string(),
                "due_count": due.len(),
                "collected_count": collected.len(),
                "error_count": errors.len(),
                "collected": collected,
                "errors": errors,
                "cashu": cashu,
                "changed": changed,
                "daemon_reload_attempted": daemon_reload_attempted,
                "status": paid_exit_status_snapshot_json(&app, &store_path, &store)?,
            }))?
        );
    } else if due.is_empty() {
        println!("paid_exit_collect_due: none");
    } else {
        println!(
            "paid_exit_collect_due: collected={} errors={}",
            collected.len(),
            errors.len()
        );
        for entry in &collected {
            let close = entry
                .get("spilman_close")
                .unwrap_or(&serde_json::Value::Null);
            println!(
                "  {} collected={}",
                paid_exit_json_string(close, "channel_id"),
                paid_exit_sat_text(paid_exit_json_u64(close, "receiver_amount_sat"))
            );
        }
        for entry in &errors {
            println!(
                "  {} error={}",
                paid_exit_json_string(entry, "channel_id"),
                paid_exit_json_string(entry, "error")
            );
        }
        println!("store: {} changed={changed}", store_path.display());
        println!(
            "daemon_reload: {}",
            if daemon_reload_attempted {
                "attempted"
            } else {
                "skipped"
            }
        );
    }

    Ok(())
}

fn paid_exit_collect_channel_outcome_json(
    outcome: &PaidExitCollectChannelOutcome,
) -> serde_json::Value {
    json!({
        "spilman_close": paid_exit_spilman_close_result_json(&outcome.close),
        "wallet_collect": outcome.wallet_collect,
        "changed": outcome.changed,
    })
}

fn paid_exit_wallet_collect_amount_sat(value: Option<&serde_json::Value>) -> u64 {
    value
        .and_then(|value| value.get("amount_sat"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn paid_exit_json_string(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn paid_exit_json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn paid_exit_spilman_close_result_json(
    close: &CashuSpilmanReceiverCloseResult,
) -> serde_json::Value {
    json!({
        "channel_id": close.channel_id,
        "mint_url": close.mint_url,
        "unit": close.unit,
        "closed_amount_sat": close.closed_amount,
        "closed_amount_text": paid_exit_sat_text(close.closed_amount),
        "total_value_sat": close.total_value,
        "total_value_text": paid_exit_sat_text(close.total_value),
        "receiver_amount_sat": close.receiver_sum,
        "receiver_amount_text": paid_exit_sat_text(close.receiver_sum),
        "sender_refund_sat": close.sender_sum,
        "sender_refund_text": paid_exit_sat_text(close.sender_sum),
        "receiver_proofs_saved": !close.receiver_proofs_json.trim().is_empty(),
        "sender_proofs_saved": !close.sender_proofs_json.trim().is_empty(),
        "already_closed": close.already_closed,
    })
}
