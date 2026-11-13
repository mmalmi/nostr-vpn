use super::*;
use nostr_vpn_core::paid_route_store::paid_route_offer_store_key;

pub(super) enum PaidExitRenewalStep {
    Waiting,
    /// The replacement channel exists but still needs wallet funding.
    Fund(String),
    /// The seller admitted the replacement and it is now selected.
    Renewed(String),
}

/// Replace the selected channel with the same seller, offer, mint and capacity
/// before it runs out of credit or reaches its routing cutoff. Automatic and
/// Manual share this handover; each mode funds the replacement itself.
pub(super) async fn renew_selected_paid_exit(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    seller_pubkey: &str,
    retry_at: &mut u64,
    now_unix: u64,
) -> Result<PaidExitRenewalStep> {
    let store_path = paid_route_store_file_path(config_path);

    // Closing may race a wallet write. Retry it without interrupting the new
    // route, and retain the intent across daemon restarts.
    let store = load_paid_route_store(&store_path)?;
    let closing = store
        .buyer_session_renewals
        .iter()
        .filter(|(_, next)| *next == session_id)
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

    let store = load_paid_route_store(&store_path)?;
    if !store.buyer_session_renewals.contains_key(session_id) {
        if !store.buyer_session_needs_renewal(session_id, now_unix)? {
            return Ok(PaidExitRenewalStep::Waiting);
        }
        adopt_latest_seller_offer(config_path, &store, session_id)?;
    }
    let next = update_paid_route_store(&store_path, |store| {
        store.prepare_buyer_session_renewal(session_id, now_unix)
    })?;
    let store = load_paid_route_store(&store_path)?;
    let funded = store.sessions[&next]
        .session
        .payment
        .cashu_spilman_payment
        .as_ref()
        .is_some_and(CashuSpilmanPayment::has_funding);
    if !funded {
        return Ok(PaidExitRenewalStep::Fund(next));
    }
    if store.buyer_session_is_seller_admitted(&next)? {
        drain_paid_exit_buyer_usage(runtime, config_path, seller_pubkey, now_unix)?;
        update_paid_route_store(&store_path, |store| {
            store.activate_buyer_session_renewal(session_id, now_unix)?;
            Ok(())
        })?;
        eprintln!("paid-exit: renewed channel with the current provider");
        return Ok(PaidExitRenewalStep::Renewed(next));
    }
    if !store.buyer_session_renewal_starts.contains_key(session_id)
        && !store.buyer_session_ready_to_handover(session_id, now_unix)?
    {
        return Ok(PaidExitRenewalStep::Waiting);
    }
    // Replay the durable signed open too: the process may have stopped between
    // wallet funding and queuing it. The wallet and receiver are idempotent.
    if now_unix >= *retry_at {
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
        if !store.buyer_session_renewal_starts.contains_key(session_id) {
            drain_paid_exit_buyer_usage(runtime, config_path, seller_pubkey, now_unix)?;
            update_paid_route_store(&store_path, |store| {
                store.start_buyer_session_renewal_handover(session_id, now_unix)
            })?;
        }
        runtime
            .send_paid_route_session_open(seller_pubkey, open)
            .await?;
        *retry_at = now_unix.saturating_add(2);
    }
    Ok(PaidExitRenewalStep::Waiting)
}

/// Renewal reopens the stored seller offer, which lapses an hour after signing.
/// Only Automatic selection copies received offers into the store, so adopt the
/// seller's latest signed copy of the same offer before preparing a renewal.
fn adopt_latest_seller_offer(
    config_path: &Path,
    store: &nostr_vpn_core::paid_route_store::PaidRouteStore,
    session_id: &str,
) -> Result<()> {
    let channel = store
        .sessions
        .get(session_id)
        .and_then(|session| store.channels.get(&session.session.payment.channel_id))
        .ok_or_else(|| anyhow!("missing buyer channel"))?;
    let offer_key = paid_route_offer_store_key(&channel.counterparty_npub, &channel.offer_id);
    let offers = crate::control_pubsub_runtime::load_control_pubsub_events(config_path)?
        .into_iter()
        .filter_map(|event| SignedPaidRouteOffer::from_event(event).ok())
        .filter(|signed| {
            signed.offer().is_ok_and(|offer| {
                paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id) == offer_key
            })
        })
        .collect::<Vec<_>>();
    if !offers.is_empty() {
        persist_paid_exit_discovered_offers(
            &paid_route_store_file_path(config_path),
            &offers,
            &[],
            None,
        )?;
    }
    Ok(())
}
