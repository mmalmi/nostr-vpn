use super::*;

pub(super) async fn fund_automatic_paid_exit(
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    now_unix: u64,
) -> Result<StreamingRoutePaymentEnvelope> {
    if !PaidExitAutomaticBuyer::enabled(app) {
        return Err(anyhow!(
            "automatic paid exit funding cancelled by internet mode"
        ));
    }
    fund_paid_exit_session(app, config_path, session_id, now_unix).await
}

pub(crate) async fn fund_paid_exit_session(
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    now_unix: u64,
) -> Result<StreamingRoutePaymentEnvelope> {
    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    let session = store
        .sessions
        .get(session_id)
        .cloned()
        .ok_or_else(|| anyhow!("automatic paid exit session {session_id} does not exist"))?;
    let lease = store
        .leases
        .get(&session.session.lease_id)
        .cloned()
        .ok_or_else(|| anyhow!("automatic paid exit session has no lease"))?;
    let channel = store
        .channels
        .get(&session.session.payment.channel_id)
        .cloned()
        .ok_or_else(|| anyhow!("automatic paid exit session has no channel"))?;
    let quote = store
        .quotes
        .get(&lease.lease.quote_id)
        .cloned()
        .ok_or_else(|| anyhow!("automatic paid exit session has no quote"))?;
    let opened: cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletResult =
        serde_json::from_value(
            crate::cashu_wallet_daemon::request_daemon_cashu_wallet_worker(
                config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::OpenSpilmanChannel {
                    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                        mint_url: channel.mint_url,
                        receiver_pubkey_hex: quote.quote.receiver_pubkey_hex,
                        capacity_sat: session.session.payment.capacity_sat,
                        expiry_unix: channel.expires_at_unix,
                        max_amount_per_output: 0,
                        unit: "sat".to_string(),
                        opening_paid_msat: 0,
                        keyset_id: None,
                        keyset_info_json: None,
                        client_request_id: Some(session_id.to_string()),
                        route_created_at_unix: Some(channel.created_at_unix),
                    },
                },
            )
            .await?,
        )
        .context("daemon wallet returned an invalid opened Cashu channel")?;
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode automatic paid exit buyer npub")?;
    let payment = update_paid_route_store(&store_path, |store| {
        store.attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
            session_id: session_id.to_string(),
            channel_id: opened.channel.channel_id.clone(),
            cashu_unit: opened.channel.unit.clone(),
            capacity_sat: opened.channel.capacity_sat,
            paid_msat: Some(opened.channel.opening_paid_msat),
            payment: opened.channel.payment.clone(),
            now_unix,
        })?;
        store.build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
            session_id: session_id.to_string(),
            buyer_npub,
            kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
            payment: opened.channel.payment,
            delivered_units: None,
            paid_msat: Some(opened.channel.opening_paid_msat),
            now_unix,
        })
    })?;
    Ok(payment.envelope)
}

pub(crate) async fn finalize_automatic_paid_exit(
    automatic: &PaidExitAutomaticBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<()> {
    let Some(candidate) = automatic.candidate.as_ref() else {
        return Ok(());
    };
    drain_paid_exit_buyer_usage(runtime, config_path, &candidate.seller_pubkey, now_unix)?;
    if candidate.funded {
        let wallet_data_dir = paid_exit_wallet_data_dir(config_path);
        let signer = FileSpilmanPaymentSigner::try_load(&wallet_data_dir)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| anyhow!("Cashu channel storage is busy; retry finalization"))?;
        let store_path = paid_route_store_file_path(config_path);
        update_paid_route_store(&store_path, |store| {
            paid_exit_settle_with_signer(PaidExitSettleRequest {
                app,
                config_path,
                store,
                signer: &signer,
                session_id: &candidate.session_id,
                dry_run: false,
                wallet_data_dir: &wallet_data_dir,
                now_unix,
            })
        })?;
        let flushed = flush_paid_exit_payment_outbox(runtime, config_path).await;
        if flushed.errors > 0 {
            eprintln!(
                "paid-exit: automatic seller finalization queued with {} send error(s)",
                flushed.errors
            );
        }
    }
    Ok(())
}

pub(super) fn suspend_automatic_paid_exit(
    automatic: &PaidExitAutomaticBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    config_path: &Path,
    now_unix: u64,
) -> Result<()> {
    let Some(candidate) = automatic.candidate.as_ref() else {
        return Ok(());
    };
    drain_paid_exit_buyer_usage(runtime, config_path, &candidate.seller_pubkey, now_unix)?;
    Ok(())
}

pub(crate) fn queue_recovered_paid_exit_channel_open(
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    now_unix: u64,
) -> Result<()> {
    let signer = FileSpilmanPaymentSigner::try_load(&paid_exit_wallet_data_dir(config_path))
        .map_err(|error| anyhow!("{error}"))?
        .ok_or_else(|| anyhow!("Cashu channel storage is busy; retry recovery"))?;
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode automatic paid exit buyer npub")?;
    let payment = update_paid_route_store(&paid_route_store_file_path(config_path), |store| {
        store.build_buyer_signed_payment_envelope(
            &signer,
            BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                session_id: session_id.to_string(),
                buyer_npub,
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
                delivered_units: None,
                paid_msat: None,
                now_unix,
            },
        )
    })?;
    queue_paid_exit_payment(app, config_path, &payment.envelope)?;
    Ok(())
}

fn drain_paid_exit_buyer_usage(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    config_path: &Path,
    seller_pubkey: &str,
    now_unix: u64,
) -> Result<PaidRouteUsage> {
    let delta = runtime.drain_paid_route_usage(seller_pubkey)?;
    if delta.is_empty() {
        return Ok(delta);
    }
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        store.record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller_pubkey.to_string(),
            usage_delta: delta.clone(),
            now_unix,
        })?;
        Ok(())
    })?;
    Ok(delta)
}
