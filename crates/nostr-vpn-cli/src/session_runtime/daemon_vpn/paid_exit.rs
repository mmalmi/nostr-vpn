use super::*;
use nostr_vpn_core::paid_routes::PaidRouteUsage;

#[path = "paid_exit/automatic.rs"]
mod automatic;
pub(crate) use automatic::*;
#[path = "paid_exit/refunds.rs"]
mod refunds;
pub(in crate::session_runtime) use refunds::PaidExitBuyerRefundRuntime;
#[cfg(test)]
#[path = "paid_exit/tests.rs"]
mod tests;

pub(super) const PAID_EXIT_DAEMON_STREAM_PAYMENT_MIN_INCREMENT_MSAT: u64 = 1;
pub(super) const PAID_EXIT_DAEMON_STREAM_PAYMENT_LIMIT: usize = 4;
pub(super) const PAID_EXIT_SESSION_OPEN_RETRY_SECS: u64 = 5;
pub(super) const PAID_EXIT_SESSION_OPEN_TIMEOUT_SECS: u64 = 30;
pub(super) const PAID_EXIT_OFFER_REFRESH_SECS: u64 =
    nostr_vpn_core::paid_routes::PAID_ROUTE_OFFER_TTL_SECS / 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaidExitOfferPublication {
    None,
    Published,
    Withdrawn(usize),
}

#[derive(Debug, Default)]
pub(crate) struct PaidExitOfferPublisher {
    advertised: bool,
    last_created_at: u64,
}

impl PaidExitOfferPublisher {
    pub(crate) fn load(app: &AppConfig, config_path: &Path, now_unix: u64) -> Self {
        let Ok(own_npub) = app
            .nostr_keys()
            .and_then(|keys| keys.public_key().to_bech32().map_err(anyhow::Error::from))
        else {
            return Self::default();
        };
        let Ok(store) = load_paid_route_store(&paid_route_store_file_path(config_path)) else {
            return Self::default();
        };
        let own_offers = store
            .offers
            .values()
            .filter(|record| record.offer.seller_npub == own_npub)
            .collect::<Vec<_>>();
        Self {
            advertised: own_offers
                .iter()
                .any(|record| record.signed_offer.is_live_at(now_unix)),
            last_created_at: own_offers
                .iter()
                .map(|record| record.signed_offer.event.created_at.as_secs())
                .max()
                .unwrap_or_default(),
        }
    }

    pub(crate) fn reconcile(
        &mut self,
        app: &AppConfig,
        config_path: &Path,
        now_unix: u64,
        seller_ready: bool,
        refresh: bool,
    ) -> Result<PaidExitOfferPublication> {
        let should_advertise = app.paid_exit.enabled && seller_ready;
        if should_advertise && let Err(error) = validate_paid_exit_offer_for_daemon(app, now_unix) {
            if self.advertised {
                let signed_at = now_unix.max(self.last_created_at.saturating_add(1));
                let count = withdraw_paid_exit_offers_for_daemon(app, config_path, signed_at)?;
                self.advertised = false;
                self.last_created_at = signed_at;
                return Ok(PaidExitOfferPublication::Withdrawn(count));
            }
            return Err(error);
        }
        if should_advertise && (!self.advertised || refresh) {
            let signed_at = now_unix.max(self.last_created_at.saturating_add(1));
            refresh_paid_exit_offer_for_daemon(app, config_path, signed_at)?;
            self.advertised = true;
            self.last_created_at = signed_at;
            return Ok(PaidExitOfferPublication::Published);
        }
        if !should_advertise && self.advertised {
            let signed_at = now_unix.max(self.last_created_at.saturating_add(1));
            let count = withdraw_paid_exit_offers_for_daemon(app, config_path, signed_at)?;
            self.advertised = false;
            self.last_created_at = signed_at;
            return Ok(PaidExitOfferPublication::Withdrawn(count));
        }
        Ok(PaidExitOfferPublication::None)
    }
}

fn validate_paid_exit_offer_for_daemon(app: &AppConfig, signed_at: u64) -> Result<()> {
    let config = paid_exit_offer_config(app)?;
    signed_paid_exit_offer_from_config_with_receiver(
        default_paid_exit_offer_id(),
        &app.nostr_keys()?,
        &config,
        None,
        None,
        signed_at,
    )?;
    Ok(())
}

pub(crate) fn log_paid_exit_offer_publication(result: Result<PaidExitOfferPublication>) {
    match result {
        Ok(PaidExitOfferPublication::Published) => {
            eprintln!("paid-exit: published ready public offer")
        }
        Ok(PaidExitOfferPublication::Withdrawn(count)) if count > 0 => {
            eprintln!("paid-exit: withdrew {count} unavailable public offer(s)")
        }
        Ok(_) => {}
        Err(error) => eprintln!("paid-exit: offer reconcile failed: {error}"),
    }
}

pub(crate) fn refresh_paid_exit_offer_for_daemon(
    app: &AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<bool> {
    if !app.paid_exit.enabled {
        return Ok(false);
    }
    let local =
        build_local_paid_exit_offer(app, config_path, &default_paid_exit_offer_id(), now_unix)?;
    Ok(
        publish_paid_exit_offer_pubsub(app, config_path, &local.signed)?["nostr_pubsub_queued"]
            .as_bool()
            .unwrap_or_default(),
    )
}

fn withdraw_paid_exit_offers_for_daemon(
    app: &AppConfig,
    config_path: &Path,
    signed_at: u64,
) -> Result<usize> {
    let keys = app.nostr_keys()?;
    let own_npub = keys
        .public_key()
        .to_bech32()
        .context("failed to encode paid route seller npub")?;
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        let offers = store
            .offers
            .values()
            .filter(|record| record.offer.seller_npub == own_npub)
            .map(|record| record.offer.clone())
            .collect::<Vec<_>>();
        let mut count = 0;
        for offer in offers {
            let signed =
                SignedPaidRouteOffer::sign_expiring_at(offer, &keys, signed_at, signed_at)?;
            store.upsert_signed_offer(signed.clone(), Vec::new(), signed_at)?;
            publish_paid_exit_offer_pubsub(app, config_path, &signed)?;
            count += 1;
        }
        Ok(count)
    })
}

#[derive(Debug, Default)]
pub(super) struct PaidExitApplySessionOpensResult {
    pub(super) received_count: usize,
    pub(super) applied_count: usize,
    pub(super) error_count: usize,
    pub(super) changed: bool,
    pub(super) acknowledgments: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PaidExitSessionOpenResult {
    None,
    Sent,
    FellBackDirect,
}

pub(super) async fn send_selected_paid_exit_session_open(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<PaidExitSessionOpenResult> {
    let Some(seller_pubkey) = app.public_paid_exit_node_pubkey_hex() else {
        return Ok(PaidExitSessionOpenResult::None);
    };
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode paid route buyer npub")?;
    let buyer_tunnel_ip = derive_mesh_tunnel_ip(
        &app.effective_network_id(),
        &app.nostr_keys()?.public_key().to_hex(),
    )
    .ok_or_else(|| anyhow!("failed to derive paid route buyer tunnel IP"))?;
    let reconciled =
        reconcile_selected_paid_exit_session(app, config_path, &seller_pubkey, now_unix)?;
    if reconciled.selected_session_timed_out {
        eprintln!(
            "paid-exit: seller did not acknowledge selected session {}; falling back to direct internet",
            reconciled.selected_session_id
        );
        return Ok(PaidExitSessionOpenResult::FellBackDirect);
    }
    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    let Some(open) = store.buyer_session_open_for_seller(
        &seller_pubkey,
        &buyer_npub,
        &buyer_tunnel_ip,
        now_unix,
    )?
    else {
        return Ok(PaidExitSessionOpenResult::None);
    };
    runtime
        .send_paid_route_session_open(&seller_pubkey, open)
        .await?;
    Ok(PaidExitSessionOpenResult::Sent)
}

pub(super) fn reconcile_selected_paid_exit_session(
    app: &mut AppConfig,
    config_path: &Path,
    seller_pubkey: &str,
    now_unix: u64,
) -> Result<nostr_vpn_core::paid_route_store::PaidRouteBuyerSessionLifecycleReconcile> {
    let manual = app.internet_source == nostr_vpn_core::config::InternetSource::PaidManual;
    let reconciled = update_paid_route_store(&paid_route_store_file_path(config_path), |store| {
        let reconciled = store.reconcile_buyer_session_lifecycle(
            now_unix,
            if manual {
                PAID_EXIT_SESSION_OPEN_TIMEOUT_SECS
            } else {
                0
            },
        );
        if !reconciled.selected_session_timed_out {
            store.begin_latest_buyer_session_open_attempt_for_seller(seller_pubkey, now_unix)?;
        }
        Ok(reconciled)
    })?;
    if manual && reconciled.selected_session_timed_out {
        app.set_internet_source(nostr_vpn_core::config::InternetSource::Direct);
        app.save(config_path)?;
    }
    Ok(reconciled)
}

pub(super) fn apply_paid_exit_session_opens(
    app: &AppConfig,
    config_path: &Path,
    opens: Vec<(String, PaidRouteSessionOpen)>,
) -> Result<PaidExitApplySessionOpensResult> {
    if opens.is_empty() {
        return Ok(PaidExitApplySessionOpensResult::default());
    }
    if !app.paid_exit.enabled {
        return Err(anyhow!("paid exit selling is disabled"));
    }
    let seller_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode paid route seller npub")?;
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        let mut result = PaidExitApplySessionOpensResult {
            received_count: opens.len(),
            ..PaidExitApplySessionOpensResult::default()
        };
        for (buyer_pubkey, open) in opens {
            let buyer_pubkey = match app.validate_paid_exit_seller_buyer(&buyer_pubkey) {
                Ok(buyer_pubkey) => buyer_pubkey,
                Err(error) => {
                    result.error_count += 1;
                    eprintln!(
                        "paid-exit: rejected authenticated session open from {buyer_pubkey}: {error}"
                    );
                    continue;
                }
            };
            match store.apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
                open,
                authenticated_buyer_pubkey: buyer_pubkey.clone(),
                seller_npub: seller_npub.clone(),
                config: app.paid_exit.clone(),
                now_unix: unix_timestamp(),
            }) {
                Ok(applied) => {
                    result.applied_count += 1;
                    result.changed |= applied.changed;
                    result
                        .acknowledgments
                        .push((buyer_pubkey, applied.lease_id));
                }
                Err(error) => {
                    result.error_count += 1;
                    eprintln!(
                        "paid-exit: rejected authenticated free-probe open from {buyer_pubkey}: {error}"
                    );
                }
            }
        }
        Ok(result)
    })
}

pub(super) struct PaidExitMeshEventContext<'a> {
    pub(super) runtime: &'a mut crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    pub(super) app: &'a AppConfig,
    pub(super) config_path: &'a Path,
    pub(super) network_id: &'a str,
    pub(super) underlay_interface: Option<&'a str>,
    pub(super) underlay_interface_mtu: Option<u32>,
    pub(super) own_pubkey: Option<&'a str>,
    pub(super) vpn_status: &'a mut String,
    pub(super) spilman_receiver: Option<&'a FileSpilmanPaymentReceiver>,
    pub(super) spilman_receiver_error: Option<&'a str>,
}

pub(super) async fn handle_paid_exit_mesh_events(
    context: PaidExitMeshEventContext<'_>,
    drained: &mut DrainedFipsMeshEvents,
) -> bool {
    let PaidExitMeshEventContext {
        runtime,
        app,
        config_path,
        network_id,
        underlay_interface,
        underlay_interface_mtu,
        own_pubkey,
        vpn_status,
        spilman_receiver,
        spilman_receiver_error,
    } = context;
    let mut payment_outbox_changed = false;

    let session_opens = std::mem::take(&mut drained.paid_route_session_opens);
    if !session_opens.is_empty() {
        match apply_paid_exit_session_opens(app, config_path, session_opens) {
            Ok(result) => {
                eprintln!(
                    "paid-exit: authenticated session opens received={} applied={} errors={} changed={}",
                    result.received_count, result.applied_count, result.error_count, result.changed
                );
                if result.changed
                    && let Err(error) = refresh_fips_tunnel_config(
                        runtime,
                        app,
                        config_path,
                        network_id,
                        underlay_interface,
                        underlay_interface_mtu,
                        own_pubkey,
                    )
                    .await
                {
                    *vpn_status =
                        format!("paid-exit free-probe admission refresh failed ({error})");
                }
                for (buyer_pubkey, lease_id) in result.acknowledgments {
                    if let Err(error) = runtime
                        .send_paid_route_session_open_ack(&buyer_pubkey, lease_id.clone())
                        .await
                    {
                        eprintln!(
                            "paid-exit: failed to acknowledge session open {lease_id}: {error}"
                        );
                    }
                }
            }
            Err(error) => {
                eprintln!("paid-exit: failed to apply authenticated session open: {error}")
            }
        }
    }

    for (seller_pubkey, lease_id) in std::mem::take(&mut drained.paid_route_session_open_acks) {
        match acknowledge_paid_exit_session_open(config_path, &seller_pubkey, &lease_id) {
            Ok(true) => {
                eprintln!("paid-exit: seller admitted session {lease_id}");
                if let Err(error) = refresh_fips_tunnel_config(
                    runtime,
                    app,
                    config_path,
                    network_id,
                    underlay_interface,
                    underlay_interface_mtu,
                    own_pubkey,
                )
                .await
                {
                    *vpn_status =
                        format!("paid-exit admission acknowledgment refresh failed ({error})");
                }
            }
            Ok(false) => {}
            Err(error) => eprintln!(
                "paid-exit: rejected session acknowledgment from {seller_pubkey}: {error}"
            ),
        }
    }

    for (seller_pubkey, id) in std::mem::take(&mut drained.paid_route_payment_acks) {
        match acknowledge_paid_exit_payment(config_path, &seller_pubkey, &id) {
            Ok(true) => {
                eprintln!("paid-exit: seller acknowledged direct FIPS payment {id}");
                payment_outbox_changed = true;
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("paid-exit: rejected direct FIPS payment acknowledgment: {error}")
            }
        }
    }

    let payments = std::mem::take(&mut drained.paid_route_payments);
    if payments.is_empty() {
        return payment_outbox_changed;
    }
    match paid_exit_apply_fips_payments(
        app,
        config_path,
        payments,
        spilman_receiver,
        spilman_receiver_error,
    ) {
        Ok(result) => {
            eprintln!(
                "paid-exit: direct FIPS payments received={} applied={} errors={} changed={} receiver={}",
                result.received_count,
                result.applied_count,
                result.error_count,
                result.changed,
                result.spilman_receiver_processing
            );
            if result.changed
                && let Err(error) = refresh_fips_tunnel_config(
                    runtime,
                    app,
                    config_path,
                    network_id,
                    underlay_interface,
                    underlay_interface_mtu,
                    own_pubkey,
                )
                .await
            {
                *vpn_status = format!("paid-exit payment refresh failed ({error})");
            }
            for (buyer_pubkey, id) in result.acknowledgments {
                if let Err(error) = runtime
                    .send_paid_route_payment_ack(&buyer_pubkey, id.clone())
                    .await
                {
                    eprintln!("paid-exit: failed to acknowledge direct FIPS payment {id}: {error}");
                }
            }
        }
        Err(error) => eprintln!("paid-exit: failed to apply direct FIPS payment: {error}"),
    }
    payment_outbox_changed
}

pub(super) fn acknowledge_paid_exit_session_open(
    config_path: &Path,
    seller_pubkey: &str,
    lease_id: &str,
) -> Result<bool> {
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        store.acknowledge_buyer_session_open(seller_pubkey, lease_id, unix_timestamp())
    })
}

pub(super) fn flush_fips_paid_route_usage(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    now_unix: u64,
    active_millis_delta: u64,
) -> Result<PaidExitUsageFlush> {
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        let mut changed = false;
        let seller_admission_routing_before = if app.paid_exit.enabled {
            paid_route_seller_admission_routing_signature(
                &store.seller_admissions(&app.paid_exit, now_unix),
            )
        } else {
            Vec::new()
        };

        let mut buyer_delta = PaidRouteUsage::default();
        if let Some(seller_pubkey) = app.public_paid_exit_node_pubkey_hex() {
            let mut usage_delta = runtime.drain_paid_route_usage(&seller_pubkey)?;
            usage_delta.active_millis = usage_delta
                .active_millis
                .saturating_add(active_millis_delta);
            buyer_delta = usage_delta.clone();
            if !usage_delta.is_empty() {
                changed |= store
                    .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
                        seller_pubkey,
                        usage_delta,
                        now_unix,
                    })?
                    .is_some_and(|result| result.changed);
            }
        }

        if app.paid_exit.enabled {
            for admission in store.seller_admissions(&app.paid_exit, now_unix) {
                let mut usage_delta = runtime.drain_paid_route_usage(&admission.buyer_pubkey)?;
                if admission.allow_routing {
                    usage_delta.active_millis = usage_delta
                        .active_millis
                        .saturating_add(active_millis_delta);
                }
                if usage_delta.is_empty() {
                    continue;
                }
                changed |= store
                    .record_seller_usage(RecordPaidRouteSellerUsageRequest {
                        buyer_pubkey: admission.buyer_pubkey,
                        config: app.paid_exit.clone(),
                        usage_delta,
                        now_unix,
                    })?
                    .is_some_and(|result| result.changed);
            }
        }

        let seller_admission_routing_after = if changed && app.paid_exit.enabled {
            paid_route_seller_admission_routing_signature(
                &store.seller_admissions(&app.paid_exit, now_unix),
            )
        } else {
            seller_admission_routing_before.clone()
        };
        Ok(PaidExitUsageFlush {
            seller_admission_changed: seller_admission_routing_after
                != seller_admission_routing_before,
            buyer_delta,
        })
    })
}

fn paid_route_seller_admission_routing_signature(
    admissions: &[nostr_vpn_core::paid_route_store::PaidRouteSellerAdmission],
) -> Vec<(String, String, bool)> {
    admissions
        .iter()
        .map(|admission| {
            (
                admission.buyer_pubkey.clone(),
                admission.session_id.clone(),
                admission.allow_routing,
            )
        })
        .collect()
}
