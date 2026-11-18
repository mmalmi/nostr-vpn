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
    let events = crate::control_pubsub_runtime::load_control_pubsub_events(config_path)?;
    let graph = nostr_vpn_core::paid_route_ratings::exit_rating_graph(
        &app.nostr_keys()?.public_key().to_hex(),
        &events,
        &app.paid_exit.rating_discovery.trusted_authors,
        now_unix,
    )?;
    let received_offers = events
        .iter()
        .filter(|event| !known_events.contains(&event.id))
        .cloned()
        .filter_map(|event| SignedPaidRouteOffer::from_event(event).ok())
        .collect::<Vec<_>>();
    if !received_offers.is_empty() {
        persist_paid_exit_discovered_offers(&store_path, &received_offers, &[], None)?;
    }
    update_paid_route_store(&store_path, |store| {
        store.refresh_exit_reputation(&events, &graph, now_unix);
        Ok(())
    })?;
    store = load_paid_route_store(&store_path)?;
    if !store.automatic_reselect_from.is_empty() {
        return reselection::stage(automatic, app, config_path, &store, now_unix);
    }
    automatic.reselection.take();
    if automatic
        .candidate
        .as_ref()
        .is_some_and(|candidate| store.exit_provider_is_avoided(&candidate.seller_pubkey))
    {
        // Finish any wallet operation before replacing its candidate. The
        // routing gate already rejects the downvoted provider immediately.
        if automatic.funding.is_some() {
            return Ok(false);
        }
        automatic.cancel_candidate(false, now_unix);
    }
    let selection = match automatic.selection(&store, now_unix) {
        Ok(selection) => selection,
        Err(_) => {
            if let Some(candidate) = automatic.candidate.as_mut() {
                // A mint outage or fee shortfall must not turn a waiting
                // session into a provider failure when no alternative can pay.
                if store.buyer_session_funding_retry_at(&candidate.session_id) <= now_unix {
                    candidate.failed = true;
                }
            }
            return Ok(false);
        }
    };
    let replacing_unfunded = automatic.candidate.as_ref().is_some_and(|candidate| {
        !candidate.funded
            && (candidate.selection.offer_key != selection.offer_key
                || candidate.selection.mint_url != selection.mint_url)
    });
    let exhausted = automatic.candidate.as_ref().is_some_and(|candidate| {
        candidate.funded
            && !store
                .buyer_session_has_remaining_capacity(&candidate.session_id)
                .unwrap_or(false)
    });
    if replacing_unfunded || exhausted {
        // A wallet operation may already be committing funds. Consume its
        // result before deciding whether a replacement channel is necessary.
        if automatic.funding.is_some() {
            return Ok(false);
        }
        // Switch immediately to a payable mint/provider. Preserve the old
        // session for wallet recovery and do not blame a seller for a mint outage.
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
        return Ok(replacing_unfunded || exhausted || route_changed);
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

pub(super) fn finish_automatic_reselection(store_path: &Path, requested: &str) -> Result<()> {
    if !requested.is_empty() {
        update_paid_route_store(store_path, |store| {
            if store.automatic_reselect_from == requested {
                store.automatic_reselect_from.clear();
                store.automatic_reselect_session_id.clear();
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Keep configuration in sync even when Automatic already has a candidate.
pub(super) fn select_automatic_paid_exit_route(
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

pub(super) fn recover_automatic_paid_exit_session(
    store: &PaidRouteStore,
    selection: &nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
    now_unix: u64,
) -> Option<(String, String, bool)> {
    store
        .sessions
        .values()
        .filter_map(|session| {
            let channel = store.channels.get(&session.session.payment.channel_id)?;
            let lease = store.leases.get(&session.session.lease_id)?;
            (channel.role == PaidRouteChannelRole::Buyer
                && nostr_vpn_core::paid_route_store::paid_route_offer_store_key(
                    &channel.counterparty_npub,
                    &channel.offer_id,
                ) == selection.offer_key
                && channel.mint_url == selection.mint_url
                && channel.routing_expires_at_unix(lease.lease.expires_at_unix) > now_unix
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
                session.session.session_id == store.selected_buyer_session_id,
                session.updated_at_unix,
                normalize_nostr_pubkey(&channel.counterparty_npub).ok()?,
                session.session.session_id.clone(),
                store
                    .funded_buyer_session_selection(&session.session.session_id, now_unix)
                    .is_some(),
            ))
        })
        .filter(|candidate| !selection.funded || candidate.4)
        .max_by_key(|candidate| (candidate.0, candidate.1))
        .map(|(_, _, seller_pubkey, session_id, funded)| (seller_pubkey, session_id, funded))
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn recovery_prefers_selected_credit_over_a_newer_pending_renewal_without_an_advert() {
        let seller = Keys::generate();
        let buyer = Keys::generate();
        let mut config = PaidExitConfig {
            enabled: true,
            ..Default::default()
        };
        config.channel.accepted_mints = vec!["https://mint.example".into()];
        let mut store = PaidRouteStore::default();
        store.upsert_wallet_mint("https://mint.example", "Mint", Some(100_000), 100);
        store
            .upsert_signed_offer(
                nostr_vpn_core::paid_routes::signed_paid_exit_offer_from_config(
                    "exit", &seller, &config, None, 100,
                )
                .unwrap(),
                vec![],
                100,
            )
            .unwrap();
        let original = store
            .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                offer_selector: "exit".into(),
                buyer_npub: buyer.public_key().to_bech32().unwrap(),
                mint_url: None,
                channel_capacity_sat: Some(10),
                initial_paid_msat: 0,
                now_unix: 100,
            })
            .unwrap();
        store
            .begin_buyer_session_open_attempt(&original.session_id, 100)
            .unwrap();
        let payment = CashuSpilmanPayment {
            channel_id: original.channel_id.clone(),
            balance: 1,
            signature: "signed".into(),
            params: Some(serde_json::json!({"unit": "sat"})),
            funding_proofs: Some(serde_json::json!({"proofs": []})),
        };
        store
            .sessions
            .get_mut(&original.session_id)
            .unwrap()
            .session
            .payment
            .cashu_spilman_payment = Some(payment.clone());
        store
            .channels
            .get_mut(&original.channel_id)
            .unwrap()
            .payment
            .cashu_spilman_payment = Some(payment);
        let next = store
            .prepare_buyer_session_renewal(&original.session_id, 110)
            .unwrap();
        store.offers.clear();
        let selection = store
            .funded_buyer_session_selection(&original.session_id, 120)
            .unwrap();
        let (_, recovered, funded) =
            recover_automatic_paid_exit_session(&store, &selection, 120).unwrap();
        assert_eq!(recovered, original.session_id);
        assert_ne!(recovered, next);
        assert!(funded);
        assert_eq!(store.sessions.len(), 2);

        // Even without a durable selection, an existing purchase must not
        // recover as the newer, unfunded renewal for the same seller/mint.
        store.selected_buyer_session_id.clear();
        let (_, recovered, funded) =
            recover_automatic_paid_exit_session(&store, &selection, 120).unwrap();
        assert_eq!(recovered, original.session_id);
        assert!(funded);
    }
}
