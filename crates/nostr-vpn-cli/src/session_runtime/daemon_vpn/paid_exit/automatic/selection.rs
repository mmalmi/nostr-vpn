use super::*;

pub(crate) fn reconcile_automatic_paid_exit_selection(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &mut AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<bool> {
    automatic.cancel_if_disabled(app);
    if !PaidExitAutomaticBuyer::enabled(app) {
        return Ok(false);
    }

    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    let selection = match automatic.selection(&store, now_unix) {
        Ok(selection) => selection,
        Err(_) => {
            if let Some(candidate) = automatic.candidate.as_mut() {
                candidate.failed = true;
            }
            return Ok(false);
        }
    };
    if let Some(candidate) = automatic.candidate.as_mut() {
        if candidate.selection != selection {
            candidate.failed = true;
        }
        return Ok(false);
    }

    if let Some((seller_npub, seller_pubkey, session_id, funded)) =
        recover_automatic_paid_exit_session(&store, &selection, now_unix)
    {
        update_paid_route_store(&store_path, |store| {
            store.begin_buyer_session_open_attempt(&session_id, now_unix)?;
            Ok(())
        })?;
        let route_changed =
            app.public_paid_exit_node_pubkey_hex().as_deref() != Some(seller_pubkey.as_str());
        app.select_public_paid_exit_node(&seller_npub)?;
        if !PaidExitAutomaticBuyer::enabled(app) {
            return Err(anyhow!(
                "automatic paid exit recovery changed internet mode"
            ));
        }
        if route_changed {
            app.save(config_path)?;
        }
        if funded {
            queue_recovered_paid_exit_channel_open(app, config_path, &session_id, now_unix)?;
        }
        automatic.start_candidate(selection, seller_pubkey, session_id, funded, now_unix);
        return Ok(route_changed);
    }

    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode automatic paid exit buyer npub")?;
    let session = update_paid_route_store(&store_path, |store| {
        let session = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: selection.offer_key.clone(),
            buyer_npub,
            mint_url: Some(selection.mint_url.clone()),
            channel_capacity_sat: Some(selection.channel_capacity_sat),
            initial_paid_msat: 0,
            now_unix,
        })?;
        store.begin_buyer_session_open_attempt(&session.session_id, now_unix)?;
        Ok(session)
    })?;
    let seller_pubkey = normalize_nostr_pubkey(&session.seller_npub)
        .context("invalid automatically selected paid exit seller")?;
    if !PaidExitAutomaticBuyer::enabled(app) {
        return Ok(false);
    }
    app.select_public_paid_exit_node(&session.seller_npub)?;
    if !PaidExitAutomaticBuyer::enabled(app) {
        return Err(anyhow!(
            "automatic paid exit selection changed internet mode"
        ));
    }
    app.save(config_path)?;
    automatic.start_candidate(
        selection,
        seller_pubkey,
        session.session_id,
        false,
        now_unix,
    );
    Ok(true)
}

fn recover_automatic_paid_exit_session(
    store: &PaidRouteStore,
    selection: &nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
    now_unix: u64,
) -> Option<(String, String, String, bool)> {
    let offer = &store.offers.get(&selection.offer_key)?.offer;
    let seller_pubkey = normalize_nostr_pubkey(&offer.seller_npub).ok()?;
    store
        .sessions
        .values()
        .filter_map(|session| {
            let channel = store.channels.get(&session.session.payment.channel_id)?;
            let lease = store.leases.get(&session.session.lease_id)?;
            (channel.role == PaidRouteChannelRole::Buyer
                && channel.offer_id == offer.offer_id
                && channel.counterparty_npub == offer.seller_npub
                && channel.expires_at_unix > now_unix
                && lease.lease.expires_at_unix > now_unix
                && matches!(
                    lease.status,
                    PaidRouteLifecycleStatus::Opening
                        | PaidRouteLifecycleStatus::Probing
                        | PaidRouteLifecycleStatus::Active
                        | PaidRouteLifecycleStatus::Paused
                )
                && matches!(
                    channel.status,
                    PaidRouteLifecycleStatus::Opening
                        | PaidRouteLifecycleStatus::Probing
                        | PaidRouteLifecycleStatus::Active
                        | PaidRouteLifecycleStatus::Paused
                ))
            .then_some((
                session.updated_at_unix,
                session.session.session_id.clone(),
                session.session.payment.cashu_spilman_payment.is_some(),
            ))
        })
        .max_by_key(|candidate| candidate.0)
        .map(|(_, session_id, funded)| {
            (offer.seller_npub.clone(), seller_pubkey, session_id, funded)
        })
}
