use super::*;

const PAID_EXIT_MANUAL_HEALTH_TIMEOUT_SECS: u64 = 30;
const PAID_EXIT_MANUAL_HEALTH_RETRY_SECS: u64 = 2;
const PAID_EXIT_MANUAL_FUNDING_RETRY_SECS: u64 = 5;

#[derive(Default)]
pub(crate) struct PaidExitManualBuyer {
    generation: u64,
    session_id: String,
    selected_at: u64,
    probe_succeeded: bool,
    probe_retry_after: u64,
    last_probe_error: String,
    probe: Option<PaidExitManualProbe>,
    funding_satisfied: bool,
    funding_retry_after: u64,
    funding: Option<PaidExitManualFunding>,
}

struct PaidExitManualProbe {
    generation: u64,
    task: tokio::task::JoinHandle<Result<PaidRouteProbeMeasurement>>,
}

struct PaidExitManualFunding {
    generation: u64,
    task: tokio::task::JoinHandle<Result<PaidExitManualFundingOutcome>>,
}

enum PaidExitManualFundingOutcome {
    Funded(Box<StreamingRoutePaymentEnvelope>),
    AlreadyFunded,
}

impl PaidExitManualBuyer {
    fn cancel(&mut self) {
        if let Some(probe) = self.probe.take() {
            probe.task.abort();
        }
        if let Some(funding) = self.funding.take() {
            funding.task.abort();
        }
        self.generation = self.generation.wrapping_add(1);
        self.session_id.clear();
        self.selected_at = 0;
        self.probe_succeeded = false;
        self.probe_retry_after = 0;
        self.last_probe_error.clear();
        self.funding_satisfied = false;
        self.funding_retry_after = 0;
    }

    fn select(&mut self, session_id: &str, now_unix: u64) {
        self.cancel();
        self.session_id = session_id.to_string();
        self.selected_at = now_unix;
    }

    fn schedule_probe_retry(&mut self, error: &str, now_unix: u64) {
        self.last_probe_error = error.to_string();
        self.probe_retry_after = now_unix.saturating_add(PAID_EXIT_MANUAL_HEALTH_RETRY_SECS);
    }

    fn timeout_reason(&self) -> String {
        if self.last_probe_error.is_empty() {
            "Seller Internet did not become usable within 30 seconds".to_string()
        } else {
            format!(
                "Seller Internet did not become usable within 30 seconds: {}",
                self.last_probe_error
            )
        }
    }

    fn schedule_funding_retry(&mut self, now_unix: u64) {
        self.funding_retry_after = now_unix.saturating_add(PAID_EXIT_MANUAL_FUNDING_RETRY_SECS);
    }

    fn health_deadline_expired(&self, now_unix: u64) -> bool {
        self.funding.is_none()
            && now_unix.saturating_sub(self.selected_at) >= PAID_EXIT_MANUAL_HEALTH_TIMEOUT_SECS
    }
}

async fn fund_manual_paid_exit_if_available(
    app: &AppConfig,
    config_path: &Path,
    session_id: &str,
    now_unix: u64,
) -> Result<PaidExitManualFundingOutcome> {
    let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
    let session = store
        .sessions
        .get(session_id)
        .ok_or_else(|| anyhow!("manual paid exit session {session_id} does not exist"))?;
    if !store
        .channels
        .contains_key(&session.session.payment.channel_id)
    {
        return Err(anyhow!(
            "manual paid exit session {session_id} has no channel"
        ));
    }
    if session.session.payment.cashu_spilman_payment.is_some()
        || session.session.payment.cashu_token_lease.is_some()
    {
        return Ok(PaidExitManualFundingOutcome::AlreadyFunded);
    }

    Ok(PaidExitManualFundingOutcome::Funded(Box::new(
        fund_paid_exit_session(app, config_path, session_id, now_unix).await?,
    )))
}

fn begin_or_retry_funded_manual_session(
    store: &mut nostr_vpn_core::paid_route_store::PaidRouteStore,
    session_id: &str,
    now_unix: u64,
) -> Result<()> {
    store.retry_failed_funded_buyer_session(session_id, now_unix)?;
    store.begin_buyer_session_open_attempt(session_id, now_unix)?;
    Ok(())
}

pub(crate) async fn update_manual_paid_exit(
    manual: &mut PaidExitManualBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<bool> {
    if app.internet_source != nostr_vpn_core::config::InternetSource::PaidManual {
        manual.cancel();
        return Ok(false);
    }
    let Some(seller_pubkey) = app.public_paid_exit_node_pubkey_hex() else {
        manual.cancel();
        return Ok(false);
    };
    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    let session_id = store.selected_buyer_session_id.trim().to_string();
    if session_id.is_empty() {
        manual.cancel();
        return Ok(false);
    }
    if manual.session_id != session_id {
        manual.select(&session_id, now_unix);
    }

    if manual.funding.is_none()
        && !manual.funding_satisfied
        && now_unix >= manual.funding_retry_after
    {
        let funding_app = app.clone();
        let funding_config_path = config_path.to_path_buf();
        let funding_session_id = session_id.clone();
        manual.funding = Some(PaidExitManualFunding {
            generation: manual.generation,
            task: tokio::spawn(async move {
                fund_manual_paid_exit_if_available(
                    &funding_app,
                    &funding_config_path,
                    &funding_session_id,
                    now_unix,
                )
                .await
            }),
        });
    }
    if manual
        .funding
        .as_ref()
        .is_some_and(|funding| funding.task.is_finished())
    {
        let funding = manual
            .funding
            .take()
            .expect("finished manual funding exists");
        let generation = funding.generation;
        let result = funding.task.await;
        if generation == manual.generation {
            match result {
                Ok(Ok(PaidExitManualFundingOutcome::Funded(envelope))) => {
                    queue_paid_exit_payment(app, config_path, &envelope)?;
                    update_paid_route_store(&store_path, |store| {
                        begin_or_retry_funded_manual_session(store, &session_id, now_unix)
                    })?;
                    manual.funding_satisfied = true;
                    manual.selected_at = now_unix;
                    eprintln!(
                        "paid-exit: funded selected manual session {session_id}; retrying seller admission"
                    );
                }
                Ok(Ok(PaidExitManualFundingOutcome::AlreadyFunded)) => {
                    queue_recovered_paid_exit_channel_open(
                        app,
                        config_path,
                        &session_id,
                        now_unix,
                    )?;
                    update_paid_route_store(&store_path, |store| {
                        begin_or_retry_funded_manual_session(store, &session_id, now_unix)
                    })?;
                    manual.funding_satisfied = true;
                    manual.selected_at = now_unix;
                    eprintln!(
                        "paid-exit: recovered selected manual channel open for {session_id}; retrying seller admission"
                    );
                }
                Ok(Err(error)) => {
                    manual.schedule_funding_retry(now_unix);
                    eprintln!(
                        "paid-exit: selected manual session funding failed: {error}; retrying"
                    );
                }
                Err(error) => {
                    manual.schedule_funding_retry(now_unix);
                    eprintln!(
                        "paid-exit: selected manual session funding task failed: {error}; retrying"
                    );
                }
            }
        }
    }
    if manual.probe_succeeded {
        return Ok(false);
    }

    let seller_admitted = store.buyer_session_is_seller_admitted(&session_id)?;
    let seller_authenticated = runtime.peer_statuses().iter().any(|status| {
        status.connected
            && normalize_nostr_pubkey(&status.pubkey).ok().as_deref()
                == Some(seller_pubkey.as_str())
    });
    if manual.probe.is_none()
        && now_unix >= manual.probe_retry_after
        && seller_admitted
        && seller_authenticated
    {
        let probe_app = app.clone();
        manual.probe = Some(PaidExitManualProbe {
            generation: manual.generation,
            task: tokio::spawn(async move {
                paid_exit_route_probe_measurement(&probe_app, now_unix).await
            }),
        });
        eprintln!("paid-exit: checking selected manual seller Internet egress");
    }

    if manual
        .probe
        .as_ref()
        .is_some_and(|probe| probe.task.is_finished())
    {
        let probe = manual.probe.take().expect("finished manual probe exists");
        let generation = probe.generation;
        let result = match probe.task.await {
            Ok(result) => result,
            Err(error) => {
                return fail_manual_paid_exit(
                    manual,
                    app,
                    config_path,
                    &format!("Seller Internet health-check task failed: {error}"),
                    now_unix,
                );
            }
        };
        if generation == manual.generation {
            match result {
                Ok(measurement) => {
                    record_paid_exit_probe(config_path, &session_id, measurement, now_unix)?;
                    manual.probe_succeeded = true;
                    eprintln!("paid-exit: selected manual seller Internet egress is healthy");
                    return Ok(false);
                }
                Err(error) => {
                    let error = error.to_string();
                    manual.schedule_probe_retry(&error, now_unix);
                    eprintln!(
                        "paid-exit: selected seller Internet health probe failed: {error}; retrying"
                    );
                }
            }
        }
    }

    // The health deadline starts after funding completes. The daemon wallet
    // owns the mint operation independently, so aborting this task at the
    // seller-health deadline could otherwise strand a successfully opened
    // channel before the route store observes its result.
    if manual.health_deadline_expired(now_unix) {
        let reason = manual.timeout_reason();
        return fail_manual_paid_exit(manual, app, config_path, &reason, now_unix);
    }
    Ok(false)
}

pub(super) fn fail_manual_paid_exit(
    manual: &mut PaidExitManualBuyer,
    app: &mut AppConfig,
    config_path: &Path,
    reason: &str,
    now_unix: u64,
) -> Result<bool> {
    update_paid_route_store(&paid_route_store_file_path(config_path), |store| {
        store.fail_selected_buyer_session(reason, now_unix)?;
        Ok(())
    })?;
    eprintln!("paid-exit: {reason}; falling back to direct Internet");
    app.set_internet_source(nostr_vpn_core::config::InternetSource::Direct);
    app.save(config_path)?;
    manual.cancel();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_health_failure_is_retried_before_timeout() {
        let mut manual = PaidExitManualBuyer::default();
        manual.select("funded-session", 100);

        manual.schedule_probe_retry("temporary HTTPS failure", 105);

        assert_eq!(manual.probe_retry_after, 107);
        assert_eq!(manual.last_probe_error, "temporary HTTPS failure");
        assert_eq!(
            manual.timeout_reason(),
            "Seller Internet did not become usable within 30 seconds: temporary HTTPS failure"
        );
    }

    #[test]
    fn manual_funding_retries_without_blocking_the_daemon_loop() {
        let mut manual = PaidExitManualBuyer::default();
        manual.select("unfunded-session", 100);
        manual.schedule_funding_retry(105);

        assert_eq!(manual.funding_retry_after, 110);
        assert!(!manual.funding_satisfied);
        assert!(manual.funding.is_none());
    }

    #[tokio::test]
    async fn seller_health_timeout_does_not_cancel_inflight_wallet_funding() {
        let mut manual = PaidExitManualBuyer::default();
        manual.select("funding-session", 100);
        manual.funding = Some(PaidExitManualFunding {
            generation: manual.generation,
            task: tokio::spawn(std::future::pending()),
        });

        assert!(!manual.health_deadline_expired(131));
        manual.funding.take().expect("funding task").task.abort();
        assert!(manual.health_deadline_expired(131));
    }
}
