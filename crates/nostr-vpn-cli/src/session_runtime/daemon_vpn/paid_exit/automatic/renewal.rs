use super::*;

pub(super) async fn renew_automatic_paid_exit(
    automatic: &mut PaidExitAutomaticBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<()> {
    let Some(candidate) = automatic.candidate.as_ref() else {
        return Ok(());
    };
    if !candidate.funded || !candidate.probe_succeeded || candidate.failed {
        return Ok(());
    }
    let session_id = candidate.session_id.clone();
    let seller_pubkey = candidate.seller_pubkey.clone();
    let store_path = paid_route_store_file_path(config_path);

    // Closing may race a wallet write. Retry it without interrupting the new
    // route, and retain the intent across daemon restarts.
    let store = load_paid_route_store(&store_path)?;
    let closing = store
        .buyer_session_renewals
        .iter()
        .filter(|(_, next)| **next == session_id)
        .map(|(previous, _)| previous.clone())
        .collect::<Vec<_>>();
    if !closing.is_empty() {
        let wallet_data_dir = paid_exit_wallet_data_dir(config_path);
        if let Some(signer) = FileSpilmanPaymentSigner::try_load(&wallet_data_dir)
            .map_err(|error| anyhow!("{error}"))?
        {
            for previous in closing {
                update_paid_route_store(&store_path, |store| {
                    paid_exit_settle_with_signer(PaidExitSettleRequest {
                        app,
                        config_path,
                        store,
                        signer: &signer,
                        session_id: &previous,
                        dry_run: false,
                        wallet_data_dir: &wallet_data_dir,
                        now_unix,
                    })?;
                    store.buyer_session_renewals.remove(&previous);
                    Ok(())
                })?;
            }
        }
    }

    if automatic
        .renewal_funding
        .as_ref()
        .is_some_and(|task| task.is_finished())
    {
        let result = automatic
            .renewal_funding
            .take()
            .expect("finished renewal funding")
            .await?;
        if let Err(error) = result {
            eprintln!("paid-exit: channel renewal funding will retry: {error}");
            automatic.renewal_retry_at = now_unix.saturating_add(5);
        }
    }
    let store = load_paid_route_store(&store_path)?;
    if !store.buyer_session_renewals.contains_key(&session_id)
        && !store.buyer_session_needs_renewal(&session_id, now_unix)?
    {
        return Ok(());
    }
    let next = update_paid_route_store(&store_path, |store| {
        store.prepare_buyer_session_renewal(&session_id, now_unix)
    })?;
    let store = load_paid_route_store(&store_path)?;
    let funded = store.sessions[&next]
        .session
        .payment
        .cashu_spilman_payment
        .as_ref()
        .is_some_and(CashuSpilmanPayment::has_funding);
    if !funded {
        if automatic.renewal_funding.is_none() && now_unix >= automatic.renewal_retry_at {
            let app = app.clone();
            let config_path = config_path.to_path_buf();
            automatic.renewal_funding = Some(tokio::spawn(async move {
                let envelope =
                    fund_automatic_paid_exit(&app, &config_path, &next, now_unix).await?;
                queue_paid_exit_payment(&app, &config_path, &envelope)?;
                Ok(())
            }));
        }
        return Ok(());
    }
    if store.buyer_session_is_seller_admitted(&next)? {
        payments::drain_paid_exit_buyer_usage(runtime, config_path, &seller_pubkey, now_unix)?;
        update_paid_route_store(&store_path, |store| {
            store.activate_buyer_session_renewal(&session_id, now_unix)?;
            Ok(())
        })?;
        if let Some(candidate) = automatic.candidate.as_mut() {
            candidate.session_id = next;
            candidate.unanswered_since = None;
        }
        eprintln!("paid-exit: renewed channel with the current provider");
        return Ok(());
    }
    // Replay the durable signed open too: the process may have stopped between
    // wallet funding and queuing it. The wallet and receiver are idempotent.
    if now_unix >= automatic.renewal_retry_at {
        queue_recovered_paid_exit_channel_open(app, config_path, &next, now_unix)?;
        let keys = app.nostr_keys()?;
        let tunnel_ip =
            derive_mesh_tunnel_ip(&app.effective_network_id(), &keys.public_key().to_hex())
                .ok_or_else(|| anyhow!("failed to derive paid route buyer tunnel IP"))?;
        let open = store.build_buyer_session_open(
            &next,
            &keys.public_key().to_bech32()?,
            &tunnel_ip,
            now_unix,
        )?;
        runtime
            .send_paid_route_session_open(&seller_pubkey, open)
            .await?;
        automatic.renewal_retry_at = now_unix.saturating_add(2);
    }
    Ok(())
}
