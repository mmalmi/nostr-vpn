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
    let mut store = load_paid_route_store(&store_path)?;
    let known_events = store
        .offers
        .values()
        .map(|record| record.signed_offer.event.id)
        .collect::<HashSet<_>>();
    let received_offers = crate::control_pubsub_runtime::load_control_pubsub_events(config_path)?
        .into_iter()
        .filter(|event| !known_events.contains(&event.id))
        .filter_map(|event| SignedPaidRouteOffer::from_event(event).ok())
        .collect::<Vec<_>>();
    if !received_offers.is_empty() {
        persist_paid_exit_discovered_offers(&store_path, &received_offers, &[], None)?;
        store = load_paid_route_store(&store_path)?;
    }
    let selection = match automatic.selection(&store, now_unix) {
        Ok(selection) => selection,
        Err(_) => {
            if let Some(candidate) = automatic.candidate.as_mut() {
                candidate.failed = true;
            }
            return Ok(false);
        }
    };
    let changing_mint = automatic.candidate.as_ref().is_some_and(|candidate| {
        !candidate.funded
            && candidate.selection.offer_key == selection.offer_key
            && candidate.selection.mint_url != selection.mint_url
    });
    let exhausted = automatic.candidate.as_ref().is_some_and(|candidate| {
        candidate.funded
            && !store
                .buyer_session_has_remaining_capacity(&candidate.session_id)
                .unwrap_or(false)
    });
    if changing_mint || exhausted {
        // A wallet operation may already be committing funds. Consume its
        // result before deciding whether a replacement channel is necessary.
        if automatic.funding.is_some() {
            return Ok(false);
        }
        // Keep the signed provider and its successful probe history. The old
        // session remains available for recovery; its mint/request identity
        // must never be rewritten underneath a wallet operation.
        automatic.cancel_candidate(false, now_unix);
    }
    if let Some(candidate) = automatic.candidate.as_mut() {
        candidate.reconcile_selection(selection);
        if candidate.failed {
            return Ok(false);
        }
        let changed =
            select_automatic_paid_exit_route(app, config_path, &store, &candidate.session_id)?;
        if changed {
            // Config reloads can clear the selected exit without changing the
            // automatic buyer. Restore its paid session, then prove the route
            // again instead of keeping the previous connection's health result.
            update_paid_route_store(&store_path, |store| {
                store.begin_buyer_session_open_attempt(&candidate.session_id, now_unix)?;
                Ok(())
            })?;
            if let Some(probe) = automatic.probe.take() {
                probe.task.abort();
            }
            candidate.selected_at = now_unix;
            candidate.probe_started_at = None;
            candidate.probe_succeeded = false;
            candidate.last_tx_at = None;
            candidate.last_rx_at = None;
            candidate.unanswered_since = None;
        }
        return Ok(changed);
    }

    if let Some((seller_pubkey, session_id, funded)) =
        recover_automatic_paid_exit_session(&store, &selection, now_unix)
    {
        update_paid_route_store(&store_path, |store| {
            store.begin_buyer_session_open_attempt(&session_id, now_unix)?;
            Ok(())
        })?;
        let route_changed =
            select_automatic_paid_exit_route(app, config_path, &store, &session_id)?;
        if funded {
            queue_recovered_paid_exit_channel_open(app, config_path, &session_id, now_unix)?;
        }
        let pending_funding = store.sessions[&session_id].funding_started_unix != 0;
        automatic.start_candidate(selection, seller_pubkey, session_id, funded, now_unix);
        if pending_funding {
            automatic
                .candidate
                .as_mut()
                .expect("recovered candidate")
                .funding_attempted = true;
        }
        return Ok(changing_mint || exhausted || route_changed);
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
    let endpoint_hints = store.offers[&selection.offer_key]
        .offer
        .fips_endpoints
        .clone();
    app.add_fips_peer_endpoint_hints(&session.seller_npub, &endpoint_hints)?;
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

/// Keep configuration in sync even when Automatic already has a candidate.
fn select_automatic_paid_exit_route(
    app: &mut AppConfig,
    config_path: &Path,
    store: &PaidRouteStore,
    session_id: &str,
) -> Result<bool> {
    let seller_npub = store.buyer_session_seller_npub(session_id)?;
    let seller_pubkey = normalize_nostr_pubkey(&seller_npub)?;
    let endpoint_hints = store.buyer_session_seller_fips_endpoints(session_id)?;
    let endpoints_before = app.fips_peer_endpoint_hints(&seller_npub);
    app.add_fips_peer_endpoint_hints(&seller_npub, &endpoint_hints)?;
    let changed = endpoints_before != app.fips_peer_endpoint_hints(&seller_npub)
        || app.public_paid_exit_node_pubkey_hex().as_deref() != Some(seller_pubkey.as_str());
    if changed {
        app.select_public_paid_exit_node(&seller_npub)?;
        if !PaidExitAutomaticBuyer::enabled(app) {
            return Err(anyhow!(
                "automatic paid exit selection changed internet mode"
            ));
        }
        app.save(config_path)?;
    }
    Ok(changed)
}

fn recover_automatic_paid_exit_session(
    store: &PaidRouteStore,
    selection: &nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
    now_unix: u64,
) -> Option<(String, String, bool)> {
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
                && channel.mint_url == selection.mint_url
                && channel.expires_at_unix > now_unix
                && lease.lease.expires_at_unix > now_unix
                && store
                    .buyer_session_has_remaining_capacity(&session.session.session_id)
                    .ok()?
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
                session
                    .session
                    .payment
                    .cashu_spilman_payment
                    .as_ref()
                    .is_some_and(CashuSpilmanPayment::has_funding),
            ))
        })
        .max_by_key(|candidate| candidate.0)
        .map(|(_, session_id, funded)| (seller_pubkey, session_id, funded))
}
