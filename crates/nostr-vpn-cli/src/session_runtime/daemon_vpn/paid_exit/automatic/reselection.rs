use super::*;
use nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection;

pub(super) struct Reselection {
    from: String,
    original: String,
    network: String,
    seller: String,
    session: String,
    selection: PaidRouteAutomaticOfferSelection,
    started: u64,
    last_open: Option<u64>,
    probe: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl Drop for Reselection {
    fn drop(&mut self) {
        if let Some(task) = self.probe.take() {
            task.abort();
        }
    }
}

fn still_requested(store: &PaidRouteStore, pending: &Reselection) -> bool {
    store.automatic_reselect_from == pending.from
        && store.automatic_reselect_session_id == pending.session
        && store.selected_buyer_session_id == pending.original
}

pub(super) fn stage(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &mut AppConfig,
    path: &Path,
    store: &PaidRouteStore,
    now: u64,
) -> Result<bool> {
    let store_path = paid_route_store_file_path(path);
    let from = &store.automatic_reselect_from;
    let incumbent = normalize_nostr_pubkey(from)?;
    // Older stores can have a configured, admitted provider without a saved
    // selection. Recover that provider before opening a replacement trial.
    if store.selected_buyer_session_id.is_empty() {
        update_paid_route_store(&store_path, |current| {
            if current.automatic_reselect_from == *from
                && current.selected_buyer_session_id.is_empty()
                && (app.public_paid_exit_node_pubkey_hex().as_deref() != Some(&incumbent)
                    || current
                        .begin_latest_buyer_session_open_attempt_for_seller(&incumbent, now)?
                        .is_none())
            {
                current.automatic_reselect_from.clear();
                current.automatic_reselect_session_id.clear();
            }
            Ok(())
        })?;
        return Ok(false);
    }
    if !store.automatic_reselect_session_id.is_empty()
        && store.selected_buyer_session_id == store.automatic_reselect_session_id
    {
        // The verified selection was committed just before a restart. Finish
        // installing its config before consuming the one-shot request.
        let seller = normalize_nostr_pubkey(
            &store.buyer_session_seller_npub(&store.selected_buyer_session_id)?,
        )?;
        if app
            .public_paid_exit_node_pubkey_hex()
            .is_some_and(|s| s == incumbent || s == seller)
            && store.buyer_session_allows_routing(&store.selected_buyer_session_id, now)?
            && !store.exit_provider_is_avoided(&seller)
        {
            selection::select_automatic_paid_exit_route(
                app,
                path,
                store,
                &store.selected_buyer_session_id,
            )?;
        }
        selection::finish_automatic_reselection(&store_path, from)?;
        automatic.reselection.take();
        return Ok(true);
    }
    if app.public_paid_exit_node_pubkey_hex().as_deref() != Some(&incumbent)
        || store
            .buyer_session_seller_npub(&store.selected_buyer_session_id)
            .ok()
            .as_deref()
            != Some(from)
        || store.exit_provider_is_avoided(from)
    {
        selection::finish_automatic_reselection(&store_path, from)?;
        automatic.reselection.take();
        return Ok(false);
    }
    if let Some(p) = automatic.reselection.as_ref()
        && still_requested(store, p)
        && p.network == app.effective_network_id()
    {
        let before = app.fips_peer_endpoint_hints(&p.seller);
        app.add_fips_peer_endpoint_hints(
            &p.seller,
            &store.buyer_session_seller_fips_endpoints(&p.session)?,
        )?;
        return Ok(before != app.fips_peer_endpoint_hints(&p.seller));
    }
    automatic.reselection.take();
    if automatic.funding.is_some() {
        return Ok(false);
    }
    let selection = match store.select_automatic_offer(now) {
        Ok(candidate) => candidate,
        Err(error) => {
            selection::finish_automatic_reselection(&store_path, from)?;
            eprintln!("paid-exit: keeping current provider: {error}");
            return Ok(false);
        }
    };
    let buyer = app.nostr_keys()?.public_key().to_bech32()?;
    let recovered = selection::recover_automatic_paid_exit_session(store, &selection, now);
    let session = update_paid_route_store(&store_path, |current| {
        anyhow::ensure!(
            current.automatic_reselect_from == *from
                && current.selected_buyer_session_id == store.selected_buyer_session_id,
            "paid selection changed"
        );
        let session = match recovered {
            Some((_, session, _)) => session,
            None => {
                current
                    .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                        offer_selector: selection.offer_key.clone(),
                        buyer_npub: buyer,
                        mint_url: Some(selection.mint_url.clone()),
                        channel_capacity_sat: Some(selection.channel_capacity_sat),
                        initial_paid_msat: 0,
                        now_unix: now,
                    })?
                    .session_id
            }
        };
        current.automatic_reselect_session_id = session.clone();
        Ok(session)
    })?;
    let staged = load_paid_route_store(&store_path)?;
    let seller = normalize_nostr_pubkey(&staged.buyer_session_seller_npub(&session)?)?;
    let endpoints = staged.buyer_session_seller_fips_endpoints(&session)?;
    app.add_fips_peer_endpoint_hints(&seller, &endpoints)?;
    // Rebuild the incumbent's health/payment state after a daemon restart.
    if automatic.candidate.is_none() {
        let mut active = store.clone();
        active.automatic_reselect_from.clear();
        let selected = &store.selected_buyer_session_id;
        if let Some(selection) = active.funded_buyer_session_selection(selected, now) {
            automatic.start_candidate(selection, incumbent, selected.clone(), true, now);
        }
    }
    automatic.reselection = Some(Reselection {
        from: from.clone(),
        original: store.selected_buyer_session_id.clone(),
        network: app.effective_network_id(),
        selection,
        seller,
        session,
        started: now,
        last_open: None,
        probe: None,
    });
    Ok(true)
}

pub(super) async fn advance(
    automatic: &mut PaidExitAutomaticBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    path: &Path,
    now: u64,
) -> Result<bool> {
    let pending = automatic.reselection.as_mut().expect("pending reselection");
    let store_path = paid_route_store_file_path(path);
    let store = load_paid_route_store(&store_path)?;
    if !still_requested(&store, pending) || app.effective_network_id() != pending.network {
        automatic.reselection.take();
        return Ok(false);
    }
    let result = if now.saturating_sub(pending.started) >= 30 {
        Err(anyhow!(
            "second provider did not pass its Internet check in time"
        ))
    } else if let Some(task) = pending.probe.as_mut() {
        if !task.is_finished() {
            return Ok(false);
        }
        task.await
            .context("candidate Internet check stopped")
            .and_then(|r| r)
    } else {
        let keys = app.nostr_keys()?;
        let ip = derive_mesh_tunnel_ip(&pending.network, &keys.public_key().to_hex())
            .ok_or_else(|| anyhow!("missing tunnel IP"))?;
        let lease_id = &store
            .sessions
            .get(&pending.session)
            .context("candidate session no longer exists")?
            .session
            .lease_id;
        let fresh_ack = store
            .buyer_session_admissions
            .get(lease_id)
            .is_some_and(|at| *at >= pending.started);
        if pending.last_open.is_none() || !fresh_ack {
            if pending
                .last_open
                .is_none_or(|last| now.saturating_sub(last) >= PAID_EXIT_SESSION_OPEN_RETRY_SECS)
            {
                pending.last_open = Some(now);
                let open = store.build_buyer_session_open(
                    &pending.session,
                    &keys.public_key().to_bech32()?,
                    &ip,
                    now,
                )?;
                if let Err(error) = runtime
                    .send_paid_route_session_open(&pending.seller, open)
                    .await
                {
                    eprintln!("paid-exit: candidate session open will retry: {error}");
                }
            }
            return Ok(false);
        }
        anyhow::ensure!(
            store.buyer_session_allows_routing(&pending.session, now)?,
            "candidate session has no traffic allowance"
        );
        pending.probe = Some(runtime.probe_paid_exit_candidate(
            &pending.seller,
            crate::strip_cidr(&ip).parse()?,
            app.exit_dns.resolver_config(None)?,
        )?);
        return Ok(false);
    };
    finish(automatic, app, path, result, now)
}

pub(super) fn finish(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &mut AppConfig,
    path: &Path,
    result: Result<()>,
    now: u64,
) -> Result<bool> {
    let store_path = paid_route_store_file_path(path);
    let pending = automatic.reselection.take().expect("completed reselection");
    if let Err(error) = result {
        update_paid_route_store(&store_path, |current| {
            if still_requested(current, &pending) {
                current.automatic_reselect_from.clear();
                current.automatic_reselect_session_id.clear();
            }
            Ok(())
        })?;
        eprintln!("paid-exit: keeping current provider: {error:#}");
        return Ok(true);
    }
    commit_proven_candidate(automatic, app, path, &pending, now)
}

fn commit_proven_candidate(
    automatic: &mut PaidExitAutomaticBuyer,
    app: &mut AppConfig,
    path: &Path,
    pending: &Reselection,
    now: u64,
) -> Result<bool> {
    let store_path = paid_route_store_file_path(path);
    let mut latest = AppConfig::load(path)?;
    if !PaidExitAutomaticBuyer::enabled(&latest)
        || latest.effective_network_id() != pending.network
        || latest.public_paid_exit_node_pubkey_hex() != Some(normalize_nostr_pubkey(&pending.from)?)
        || automatic.funding.is_some()
    {
        return Ok(false);
    }
    let committed = update_paid_route_store(&store_path, |store| {
        if !still_requested(store, pending)
            || store.exit_provider_is_avoided(&pending.seller)
            || !store.buyer_session_is_seller_admitted(&pending.session)?
            || !store.buyer_session_allows_routing(&pending.session, now)?
            || store.select_automatic_offer(now).ok().is_none_or(|s| {
                s.offer_key != pending.selection.offer_key
                    || s.mint_url != pending.selection.mint_url
            })
        {
            return Ok(false);
        }
        store.begin_buyer_session_open_attempt(&pending.session, now)?;
        Ok(true)
    })?;
    if !committed {
        return Ok(false);
    }
    let store = load_paid_route_store(&store_path)?;
    selection::select_automatic_paid_exit_route(&mut latest, path, &store, &pending.session)?;
    *app = latest;
    selection::finish_automatic_reselection(&store_path, &pending.from)?;
    let funded = store
        .funded_buyer_session_selection(&pending.session, now)
        .is_some();
    automatic.cancel_candidate(false, now);
    automatic.start_candidate(
        pending.selection.clone(),
        pending.seller.clone(),
        pending.session.clone(),
        funded,
        now,
    );
    Ok(true)
}
