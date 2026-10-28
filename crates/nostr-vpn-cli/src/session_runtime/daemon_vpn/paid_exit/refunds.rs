use super::*;

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};

const PAID_EXIT_BUYER_REFUND_ATTEMPT_TIMEOUT_SECS: u64 = 30;
const PAID_EXIT_BUYER_REFUND_RETRY_SECS: u64 = 60;

use cashu_service::CashuSpilmanRefundDeferred as RefundWorkDeferred;

#[derive(Debug, Default)]
pub(super) struct PaidExitBuyerRefundRecovery {
    pub(super) scanned_count: usize,
    pub(super) complete_count: usize,
    pub(super) pending_count: usize,
    pub(super) error_count: usize,
    pub(super) imported_amount_sat: u64,
    pub(super) changed: bool,
}

#[derive(Debug)]
enum PaidExitBuyerRefundOutcome {
    Complete {
        imported_amount_sat: u64,
        overview: Option<CashuWalletOverview>,
        wallet_error: Option<String>,
    },
    Pending {
        wait_until_unix: u64,
    },
    Failed(anyhow::Error),
}

#[derive(Debug)]
struct PaidExitBuyerRefundAttempt {
    channel_id: String,
    outcome: PaidExitBuyerRefundOutcome,
    contacted_mint: bool,
}

struct PaidExitBuyerRefundCommand {
    client_store_lock: SharedSpilmanClientStoreLock,
    config_path: PathBuf,
    channel_id: String,
    sync_wallet: bool,
    attempt_timeout: Duration,
}

#[derive(Debug)]
pub(in crate::session_runtime) struct PaidExitBuyerRefundRuntime {
    command_tx: SyncSender<PaidExitBuyerRefundCommand>,
    result_rx: Receiver<PaidExitBuyerRefundAttempt>,
    active_channel_id: Option<String>,
    retry_after: HashMap<String, Instant>,
    wallet_sync_pending: HashSet<String>,
    next_channel_index: usize,
    attempt_timeout: Duration,
    retry_interval: Duration,
}

impl PaidExitBuyerRefundRuntime {
    pub(in crate::session_runtime) fn new() -> Result<Self> {
        Self::with_timings(
            Duration::from_secs(PAID_EXIT_BUYER_REFUND_ATTEMPT_TIMEOUT_SECS),
            Duration::from_secs(PAID_EXIT_BUYER_REFUND_RETRY_SECS),
        )
    }

    fn with_timings(attempt_timeout: Duration, retry_interval: Duration) -> Result<Self> {
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("nvpn-paid-exit-refund".to_string())
            .spawn(move || paid_exit_buyer_refund_worker(command_rx, result_tx))
            .context("failed to start paid exit buyer refund worker")?;
        Ok(Self {
            command_tx,
            result_rx,
            active_channel_id: None,
            retry_after: HashMap::new(),
            wallet_sync_pending: HashSet::new(),
            next_channel_index: 0,
            attempt_timeout,
            retry_interval,
        })
    }

    pub(in crate::session_runtime) fn before_tick(
        &mut self,
        config_path: &Path,
        allow_background_maintenance: bool,
        foreground_funding: bool,
    ) -> Option<DaemonControlRequest> {
        // Always reap a completed bounded worker, including while network or
        // control work suppresses new background maintenance. Otherwise an
        // already-finished refund leaves active_channel_id set forever and a
        // newly arrived daemon control request can never be acknowledged.
        if let Err(error) = self.poll_and_log(config_path, false, foreground_funding) {
            eprintln!("paid-exit: buyer refund recovery failed: {error}");
        }
        let pending_control_request = take_daemon_control_request(config_path);
        if allow_background_maintenance
            && pending_control_request.is_none()
            && !daemon_control_file_path(config_path).exists()
            && let Err(error) = self.poll_and_log(config_path, true, foreground_funding)
        {
            eprintln!("paid-exit: buyer refund recovery failed: {error}");
        }
        pending_control_request
    }

    pub(in crate::session_runtime) fn poll_and_log(
        &mut self,
        config_path: &Path,
        allow_start: bool,
        foreground_funding: bool,
    ) -> Result<()> {
        // This runs before funding on the daemon tick. Give a ready payment
        // its turn before a background refund can take the shared store lock
        // and extend the mint cooldown again. Direct/VPN-off and insufficient
        // funds keep refund recovery available.
        let allow_start =
            allow_start && !(foreground_funding && paid_exit_buyer_funding_ready(config_path)?);
        let Some(recovery) = self.poll(config_path, allow_start)? else {
            return Ok(());
        };
        if recovery.imported_amount_sat > 0 || recovery.error_count > 0 {
            eprintln!(
                "paid-exit: buyer refund recovery scanned={} complete={} pending={} imported_sat={} errors={} changed={}",
                recovery.scanned_count,
                recovery.complete_count,
                recovery.pending_count,
                recovery.imported_amount_sat,
                recovery.error_count,
                recovery.changed
            );
        }
        Ok(())
    }

    fn poll(
        &mut self,
        config_path: &Path,
        allow_start: bool,
    ) -> Result<Option<PaidExitBuyerRefundRecovery>> {
        let recovery = self.take_finished(config_path)?;
        if allow_start && self.active_channel_id.is_none() {
            self.start_next(config_path)?;
        }
        Ok(recovery)
    }

    fn take_finished(&mut self, config_path: &Path) -> Result<Option<PaidExitBuyerRefundRecovery>> {
        if self.active_channel_id.is_none() {
            return Ok(None);
        }
        let attempt = match self.result_rx.try_recv() {
            Ok(attempt) => attempt,
            Err(TryRecvError::Empty) => return Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.active_channel_id.take();
                return Err(anyhow!("paid exit buyer refund worker stopped"));
            }
        };
        let active_channel_id = self
            .active_channel_id
            .take()
            .expect("checked active refund channel");
        if attempt.channel_id != active_channel_id {
            return Err(anyhow!(
                "paid exit buyer refund worker returned channel {} while {} was active",
                attempt.channel_id,
                active_channel_id
            ));
        }
        // An Expired channel already waits for its funding expiry, so a
        // pending recovery that reported that deadline retries there instead
        // of rechecking the mint every retry_interval.
        self.retry_after.insert(
            attempt.channel_id.clone(),
            Instant::now()
                + paid_exit_buyer_refund_retry_delay(
                    &attempt.outcome,
                    self.retry_interval,
                    unix_timestamp(),
                ),
        );
        self.update_wallet_sync_state(&attempt);
        apply_paid_exit_buyer_refund_attempt(config_path, attempt).map(Some)
    }

    fn update_wallet_sync_state(&mut self, attempt: &PaidExitBuyerRefundAttempt) {
        match &attempt.outcome {
            PaidExitBuyerRefundOutcome::Complete {
                overview,
                wallet_error,
                ..
            } if overview.is_none() && wallet_error.is_some() => {
                self.wallet_sync_pending.insert(attempt.channel_id.clone());
            }
            PaidExitBuyerRefundOutcome::Complete { .. } => {
                self.wallet_sync_pending.remove(&attempt.channel_id);
            }
            PaidExitBuyerRefundOutcome::Pending { .. } | PaidExitBuyerRefundOutcome::Failed(_) => {}
        }
    }

    fn start_next(&mut self, config_path: &Path) -> Result<()> {
        let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
        let channel_ids = paid_exit_buyer_refund_channel_ids(&store);
        let retained = channel_ids.iter().cloned().collect::<HashSet<_>>();
        self.retry_after
            .retain(|channel_id, _| retained.contains(channel_id));
        self.wallet_sync_pending
            .retain(|channel_id| retained.contains(channel_id));
        let Some(channel_id) = self.next_eligible_channel(&channel_ids, &store) else {
            return Ok(());
        };
        let Some(client_store_lock) = SharedSpilmanClientStoreLock::try_acquire(
            spilman_client_store_path(&paid_exit_wallet_data_dir(config_path)),
        )
        .map_err(|error| anyhow!("{error}"))?
        else {
            return Ok(());
        };
        let sync_wallet = self.wallet_sync_pending.contains(&channel_id);
        self.command_tx
            .send(PaidExitBuyerRefundCommand {
                client_store_lock,
                config_path: config_path.to_path_buf(),
                channel_id: channel_id.clone(),
                sync_wallet,
                attempt_timeout: self.attempt_timeout,
            })
            .map_err(|_| anyhow!("paid exit buyer refund worker stopped"))?;
        self.active_channel_id = Some(channel_id);
        Ok(())
    }

    fn next_eligible_channel(
        &mut self,
        channel_ids: &[String],
        store: &PaidRouteStore,
    ) -> Option<String> {
        if channel_ids.is_empty() {
            self.next_channel_index = 0;
            return None;
        }
        let now = Instant::now();
        for offset in 0..channel_ids.len() {
            let index = (self.next_channel_index + offset) % channel_ids.len();
            let channel_id = &channel_ids[index];
            let eligible = self
                .retry_after
                .get(channel_id)
                .is_none_or(|retry_after| now >= *retry_after);
            let mint_ready = store.channels.get(channel_id).is_some_and(|channel| {
                unix_timestamp() >= store.buyer_mint_retry_at(&channel.mint_url)
            });
            if eligible && mint_ready {
                self.next_channel_index = (index + 1) % channel_ids.len();
                return Some(channel_id.clone());
            }
        }
        None
    }
}

fn paid_exit_buyer_funding_ready(config_path: &Path) -> Result<bool> {
    let store = load_paid_route_store(&paid_route_store_file_path(config_path))?;
    let now = unix_timestamp();
    let selected = store.selected_buyer_session_id.as_str();
    let renewal = store
        .buyer_session_renewals
        .get(selected)
        .map(String::as_str);
    Ok([Some(selected), renewal].into_iter().flatten().any(|id| {
        store.sessions.get(id).is_some_and(|session| {
            session.funding_started_unix != 0
                && session.session.payment.cashu_spilman_payment.is_none()
                && session.session.payment.cashu_token_lease.is_none()
                && store.buyer_session_funding_retry_at(id) <= now
                && store
                    .channels
                    .get(&session.session.payment.channel_id)
                    .is_some_and(|channel| {
                        channel.routing_expires_at_unix(u64::MAX) > now
                            && matches!(
                                channel.status,
                                PaidRouteLifecycleStatus::Opening
                                    | PaidRouteLifecycleStatus::Probing
                                    | PaidRouteLifecycleStatus::Active
                            )
                    })
        })
    }))
}

fn paid_exit_buyer_refund_worker(
    command_rx: Receiver<PaidExitBuyerRefundCommand>,
    result_tx: SyncSender<PaidExitBuyerRefundAttempt>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            for command in command_rx {
                if result_tx
                    .send(PaidExitBuyerRefundAttempt {
                        channel_id: command.channel_id,
                        contacted_mint: false,
                        outcome: PaidExitBuyerRefundOutcome::Failed(anyhow!(
                            "failed to start Cashu refund runtime: {error}"
                        )),
                    })
                    .is_err()
                {
                    return;
                }
            }
            return;
        }
    };
    for command in command_rx {
        let channel_id = command.channel_id.clone();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(attempt_paid_exit_buyer_refund(command))
        }))
        .unwrap_or_else(|_| PaidExitBuyerRefundAttempt {
            channel_id,
            contacted_mint: true,
            outcome: PaidExitBuyerRefundOutcome::Failed(anyhow!("Cashu refund recovery panicked")),
        });
        if result_tx.send(attempt).is_err() {
            return;
        }
    }
}

fn paid_exit_buyer_refund_channel_ids(store: &PaidRouteStore) -> Vec<String> {
    let now = unix_timestamp();
    store
        .channels
        .values()
        .filter(|channel| {
            channel.role == PaidRouteChannelRole::Buyer
                && channel.payment.mode == PaidRoutePaymentMode::CashuSpilman
                && channel.payment.cashu_spilman_payment.is_some()
                && (matches!(
                    channel.status,
                    PaidRouteLifecycleStatus::Closing
                        | PaidRouteLifecycleStatus::Closed
                        | PaidRouteLifecycleStatus::Failed
                        | PaidRouteLifecycleStatus::Expired
                ) || channel.expires_at_unix <= now)
        })
        .map(|channel| channel.channel_id.clone())
        .collect()
}

fn paid_exit_buyer_refund_retry_delay(
    outcome: &PaidExitBuyerRefundOutcome,
    retry_interval: Duration,
    now_unix: u64,
) -> Duration {
    match outcome {
        PaidExitBuyerRefundOutcome::Pending { wait_until_unix } if *wait_until_unix > now_unix => {
            Duration::from_secs(wait_until_unix - now_unix)
        }
        _ => retry_interval,
    }
}

async fn attempt_paid_exit_buyer_refund(
    command: PaidExitBuyerRefundCommand,
) -> PaidExitBuyerRefundAttempt {
    let PaidExitBuyerRefundCommand {
        client_store_lock,
        config_path,
        channel_id,
        sync_wallet,
        attempt_timeout,
    } = command;
    let mut contacted_mint = false;
    let restore = tokio::time::timeout(
        attempt_timeout,
        restore_spilman_refund_through_daemon_wallet(
            &config_path,
            &channel_id,
            client_store_lock,
            &mut contacted_mint,
        ),
    )
    .await;
    let restore = match restore {
        Err(_) => Err(anyhow::Error::new(RefundWorkDeferred(format!(
            "Cashu refund recovery timed out after {} ms",
            attempt_timeout.as_millis()
        )))),
        Ok(result) => result,
    };
    let outcome = match restore {
        Err(error) => PaidExitBuyerRefundOutcome::Failed(error),
        Ok(result) if !result.complete => PaidExitBuyerRefundOutcome::Pending {
            wait_until_unix: result.funding_expires_at_unix,
        },
        Ok(result) => {
            let refresh_wallet = sync_wallet || result.imported_amount_sat > 0;
            let (overview, wallet_error) = if refresh_wallet {
                match tokio::time::timeout(attempt_timeout, async {
                    let value = crate::cashu_wallet_daemon::request_daemon_cashu_wallet_worker(
                        &config_path,
                        crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                            refresh_quotes: false,
                        },
                    )
                    .await?;
                    crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(value)
                })
                .await
                {
                    Ok(Ok(overview)) => (Some(overview), None),
                    Ok(Err(error)) => (None, Some(error.to_string())),
                    Err(_) => (
                        None,
                        Some(format!(
                            "Cashu wallet refresh timed out after {} ms",
                            attempt_timeout.as_millis()
                        )),
                    ),
                }
            } else {
                (None, None)
            };
            PaidExitBuyerRefundOutcome::Complete {
                imported_amount_sat: result.imported_amount_sat,
                overview,
                wallet_error,
            }
        }
    };
    PaidExitBuyerRefundAttempt {
        channel_id,
        outcome,
        contacted_mint,
    }
}

async fn restore_spilman_refund_through_daemon_wallet(
    config_path: &Path,
    channel_id: &str,
    client_store_lock: SharedSpilmanClientStoreLock,
    contacted_mint: &mut bool,
) -> Result<cashu_service::StreamingRouteRestoreCashuSpilmanRefundResult> {
    let client = crate::cashu_wallet_daemon::mint_http_client()?;
    cashu_service::restore_streaming_route_cashu_spilman_refund_with_wallet_and_client(
        &paid_exit_wallet_data_dir(config_path),
        channel_id,
        client_store_lock,
        contacted_mint,
        &client,
        |mint_url, unit, proofs_json| async move {
            let imported: cashu_service::CashuReceivedPayment = serde_json::from_value(
                crate::cashu_wallet_daemon::request_daemon_cashu_wallet_worker(
                    config_path,
                    crate::cashu_wallet_daemon::DaemonCashuWalletCommand::ImportProofs {
                        mint_url,
                        unit,
                        proofs_json,
                    },
                )
                .await?,
            )
            .context("daemon returned an invalid Cashu refund import response")?;
            Ok(imported.amount_sat)
        },
    )
    .await
}

fn apply_paid_exit_buyer_refund_attempt(
    config_path: &Path,
    attempt: PaidExitBuyerRefundAttempt,
) -> Result<PaidExitBuyerRefundRecovery> {
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        let mut recovery = PaidExitBuyerRefundRecovery {
            scanned_count: 1,
            ..PaidExitBuyerRefundRecovery::default()
        };
        let Some(channel) = store.channels.get(&attempt.channel_id) else {
            return Ok(recovery);
        };
        let mint_url = channel.mint_url.clone();
        if attempt.contacted_mint {
            let error = match &attempt.outcome {
                PaidExitBuyerRefundOutcome::Failed(error) => Some(error),
                _ => None,
            };
            store.defer_buyer_mint_retry(
                &mint_url,
                unix_timestamp(),
                // A local work deadline or busy store says nothing about the
                // mint's availability. Keep retrying the refund without
                // blocking unrelated foreground payments at the same mint.
                error
                    .filter(|error| !error.is::<RefundWorkDeferred>())
                    .map(|error| format!("{error:#}"))
                    .as_deref(),
                error
                    .and_then(|error| error.downcast_ref::<cashu_service::MintRetryAfter>())
                    .map(|delay| delay.0),
            )?;
            recovery.changed = true;
        }
        match attempt.outcome {
            PaidExitBuyerRefundOutcome::Complete {
                imported_amount_sat,
                overview,
                wallet_error,
            } => {
                recovery.complete_count = 1;
                recovery.imported_amount_sat = imported_amount_sat;
                recovery.changed |=
                    store.mark_buyer_channel_closed(&attempt.channel_id, unix_timestamp())?;
                if let Some(overview) = overview {
                    recovery.changed |=
                        sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
                }
                if let Some(error) = wallet_error {
                    recovery.error_count = 1;
                    recovery.changed |= set_paid_exit_buyer_refund_error(
                        store,
                        &attempt.channel_id,
                        format!("Cashu wallet balance refresh failed: {error}"),
                    );
                }
            }
            PaidExitBuyerRefundOutcome::Pending { .. } => {
                recovery.pending_count = 1;
                recovery.changed |= clear_paid_exit_buyer_refund_error(store, &attempt.channel_id);
            }
            PaidExitBuyerRefundOutcome::Failed(error) => {
                recovery.error_count = 1;
                recovery.changed |= set_paid_exit_buyer_refund_error(
                    store,
                    &attempt.channel_id,
                    format!("Cashu refund recovery failed: {error}"),
                );
            }
        }
        Ok(recovery)
    })
}

fn clear_paid_exit_buyer_refund_error(store: &mut PaidRouteStore, channel_id: &str) -> bool {
    let Some(channel) = store.channels.get_mut(channel_id) else {
        return false;
    };
    if channel.error.is_empty() {
        return false;
    }
    channel.error.clear();
    channel.updated_at_unix = unix_timestamp();
    true
}

fn set_paid_exit_buyer_refund_error(
    store: &mut PaidRouteStore,
    channel_id: &str,
    message: String,
) -> bool {
    let Some(channel) = store.channels.get_mut(channel_id) else {
        return false;
    };
    if channel.error == message {
        return false;
    }
    channel.error = message;
    channel.updated_at_unix = unix_timestamp();
    true
}

#[cfg(test)]
mod tests {
    include!("refunds/tests.rs");
}
