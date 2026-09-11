use super::*;

/// Initial funding and renewal share one task. Wallet requests may outlive a
/// mode change; let them finish persisting their idempotent result.
pub(super) fn start_funding(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    now_unix: u64,
) -> Result<bool> {
    if automatic.funding.is_some() || now_unix < automatic.funding_retry_at {
        return Ok(false);
    }
    let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
    if now_unix < store.buyer_session_funding_retry_at(session_id) {
        return Ok(false);
    }
    let changed = update_paid_route_store(&paid_route_store_file_path(config_path), |store| {
        store.begin_buyer_session_funding(session_id, now_unix)
    })?;
    if changed {
        // Let the daemon withdraw the trial route before the wallet opens any
        // mint connections. Start the request on the next control tick.
        return Ok(true);
    }
    let app = app.clone();
    let config_path = config_path.to_path_buf();
    let session_id = session_id.to_string();
    automatic.funding = Some(tokio::spawn(async move {
        match fund_automatic_paid_exit(&app, &config_path, &session_id, now_unix).await {
            Ok(envelope) => queue_paid_exit_payment(&app, &config_path, &envelope).map(|_| ()),
            Err(error) => {
                update_paid_route_store(&paid_route_store_file_path(&config_path), |store| {
                    let session = store
                        .sessions
                        .get(&session_id)
                        .ok_or_else(|| anyhow!("missing funding session"))?;
                    let channel = store
                        .channels
                        .get_mut(&session.session.payment.channel_id)
                        .ok_or_else(|| anyhow!("missing funding channel"))?;
                    channel.error = format!("Payment setup failed: {error:#}");
                    channel.updated_at_unix = unix_timestamp();
                    Ok(())
                })?;
                Err(error)
            }
        }
    }));
    Ok(changed)
}

pub(super) async fn update_funding(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<bool> {
    let mut changed = false;
    if automatic
        .funding
        .as_ref()
        .is_some_and(|task| task.is_finished())
    {
        let result = automatic
            .funding
            .take()
            .expect("finished funding task")
            .await?;
        if let Err(error) = result {
            eprintln!("paid-exit: payment setup will retry with the selected provider: {error:#}");
            automatic.funding_retry_at =
                now_unix.saturating_add(state::PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS);
        } else {
            automatic.funding_retry_at = 0;
        }
        if let Some(candidate) = automatic
            .candidate
            .as_mut()
            .filter(|candidate| !candidate.funded)
        {
            let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
            if store
                .sessions
                .get(&candidate.session_id)
                .is_some_and(|session| {
                    session
                        .session
                        .payment
                        .cashu_spilman_payment
                        .as_ref()
                        .is_some_and(CashuSpilmanPayment::has_funding)
                })
            {
                candidate.funded = true;
                candidate.selected_at = now_unix;
                if !candidate.probe_succeeded {
                    candidate.probe_started_at = None;
                }
                changed = true;
            }
        }
    }
    if let Some(candidate) = automatic
        .candidate
        .as_ref()
        .filter(|candidate| candidate.ready_to_fund(now_unix))
    {
        let session_id = candidate.session_id.clone();
        let started = start_funding(automatic, app, config_path, &session_id, now_unix)?;
        changed |= started;
        if started || automatic.funding.is_some() {
            automatic
                .candidate
                .as_mut()
                .expect("funding candidate")
                .funding_attempted = true;
        }
    }
    Ok(changed)
}
