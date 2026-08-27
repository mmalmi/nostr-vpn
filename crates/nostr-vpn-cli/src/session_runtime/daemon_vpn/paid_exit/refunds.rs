use super::*;

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};

use cashu::nuts::{Proof, SecretKey};
use cdk_spilman::ClientStorage;
use serde::Serialize;

const PAID_EXIT_BUYER_REFUND_ATTEMPT_TIMEOUT_SECS: u64 = 3;
const PAID_EXIT_BUYER_REFUND_RETRY_SECS: u64 = 10;

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
    Pending,
    Failed(String),
}

#[derive(Debug)]
struct PaidExitBuyerRefundAttempt {
    channel_id: String,
    outcome: PaidExitBuyerRefundOutcome,
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
    ) -> Option<DaemonControlRequest> {
        // Always reap a completed bounded worker, including while network or
        // control work suppresses new background maintenance. Otherwise an
        // already-finished refund leaves active_channel_id set forever and a
        // newly arrived daemon control request can never be acknowledged.
        if let Err(error) = self.poll_and_log(config_path, false) {
            eprintln!("paid-exit: buyer refund recovery failed: {error}");
        }
        let pending_control_request = if self.active_channel_id.is_some() {
            None
        } else {
            take_daemon_control_request(config_path)
        };
        if allow_background_maintenance
            && pending_control_request.is_none()
            && !daemon_control_file_path(config_path).exists()
            && let Err(error) = self.poll_and_log(config_path, true)
        {
            eprintln!("paid-exit: buyer refund recovery failed: {error}");
        }
        pending_control_request
    }

    pub(in crate::session_runtime) fn poll_and_log(
        &mut self,
        config_path: &Path,
        allow_start: bool,
    ) -> Result<()> {
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
        self.retry_after.insert(
            attempt.channel_id.clone(),
            Instant::now() + self.retry_interval,
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
            PaidExitBuyerRefundOutcome::Pending | PaidExitBuyerRefundOutcome::Failed(_) => {}
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
        let Some(channel_id) = self.next_eligible_channel(&channel_ids) else {
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

    fn next_eligible_channel(&mut self, channel_ids: &[String]) -> Option<String> {
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
            if eligible {
                self.next_channel_index = (index + 1) % channel_ids.len();
                return Some(channel_id.clone());
            }
        }
        None
    }
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
                        outcome: PaidExitBuyerRefundOutcome::Failed(format!(
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
            outcome: PaidExitBuyerRefundOutcome::Failed(
                "Cashu refund recovery panicked".to_string(),
            ),
        });
        if result_tx.send(attempt).is_err() {
            return;
        }
    }
}

fn paid_exit_buyer_refund_channel_ids(store: &PaidRouteStore) -> Vec<String> {
    store
        .channels
        .values()
        .filter(|channel| {
            channel.role == PaidRouteChannelRole::Buyer
                && channel.payment.mode == PaidRoutePaymentMode::CashuSpilman
                && channel.payment.cashu_spilman_payment.is_some()
                && matches!(
                    channel.status,
                    PaidRouteLifecycleStatus::Closing | PaidRouteLifecycleStatus::Closed
                )
        })
        .map(|channel| channel.channel_id.clone())
        .collect()
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
    let restore = tokio::time::timeout(
        attempt_timeout,
        restore_spilman_refund_through_daemon_wallet(&config_path, &channel_id, client_store_lock),
    )
    .await;
    let restore = match restore {
        Err(_) => Err(anyhow!(
            "Cashu refund recovery timed out after {} ms",
            attempt_timeout.as_millis()
        )),
        Ok(result) => result,
    };
    let outcome = match restore {
        Err(error) => PaidExitBuyerRefundOutcome::Failed(error.to_string()),
        Ok(result) if !result.complete => PaidExitBuyerRefundOutcome::Pending,
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
    }
}

#[derive(Debug, Clone)]
struct RefundMintConnection {
    client: reqwest::Client,
    mint_url: String,
}

impl RefundMintConnection {
    fn new(mint_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            mint_url: mint_url.trim_end_matches('/').to_string(),
        }
    }

    async fn post_json<T, R>(&self, path: &str, request: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(format!("{}{path}", self.mint_url))
            .json(request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "Cashu mint request to {path} failed with {status}: {body}"
            ));
        }
        serde_json::from_str(&body).map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl cdk_spilman::MintConnection for RefundMintConnection {
    async fn process_swap(
        &self,
        request: cashu::nuts::SwapRequest,
    ) -> Result<cashu::nuts::SwapResponse> {
        self.post_json("/v1/swap", &request).await
    }

    async fn post_restore(
        &self,
        request: cashu::nuts::RestoreRequest,
    ) -> Result<cashu::nuts::RestoreResponse> {
        self.post_json("/v1/restore", &request).await
    }

    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> Result<cashu::nuts::CheckStateResponse> {
        self.post_json("/v1/checkstate", &cashu::nuts::CheckStateRequest { ys })
            .await
    }
}

async fn restore_spilman_refund_through_daemon_wallet(
    config_path: &Path,
    channel_id: &str,
    client_store_lock: SharedSpilmanClientStoreLock,
) -> Result<cashu_service::StreamingRouteRestoreCashuSpilmanRefundResult> {
    let channel_id = channel_id.trim();
    if channel_id.is_empty() {
        return Err(anyhow!("missing Cashu Spilman channel id"));
    }
    let data_dir = paid_exit_wallet_data_dir(config_path);
    let (mut storage, storage_errors) =
        cashu_service::FileSpilmanClientStorage::load_with_lock(client_store_lock)
            .map_err(|error| anyhow!(error))?;
    let funding = storage
        .get_funding(channel_id)
        .cloned()
        .ok_or_else(|| anyhow!("Cashu Spilman channel not found: {channel_id}"))?;
    let unit = serde_json::from_str::<serde_json::Value>(&funding.params_json)?
        .get("unit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("sat")
        .to_string();
    if storage.get_state(channel_id) == cdk_spilman::ClientChannelState::Closed
        && storage.refund_proofs_repaired(channel_id)
    {
        return Ok(completed_refund_result(
            channel_id,
            funding.mint_url,
            unit,
            0,
            0,
            0,
        ));
    }

    let original_keyset = cdk_spilman::parse_keyset_info_from_json(&funding.keyset_info_json)
        .map_err(|error| anyhow!(error))?;
    let channel_secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)?
        .try_into()
        .map_err(|_| anyhow!("invalid Cashu Spilman channel secret length"))?;
    let params = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
        &funding.params_json,
        original_keyset,
        channel_secret,
    )?;
    let funding_proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)?;
    let channel = cdk_spilman::EstablishedChannel::new(params, funding_proofs)?;
    let sender_key = cashu_service::load_or_create_cashu_spilman_sender_key(&data_dir)
        .map_err(|error| anyhow!(error))?;
    if sender_key.public_key_hex != funding.sender_pubkey_hex {
        return Err(anyhow!(
            "Cashu Spilman channel sender key does not match local wallet key"
        ));
    }
    let sender_secret = SecretKey::from_hex(&sender_key.secret_hex)?;
    let output_keyset_json =
        cashu_service::fetch_spilman_keyset_info_json(&funding.mint_url, &unit, None)
            .await
            .map_err(|error| anyhow!(error))?;
    let output_keyset = cdk_spilman::parse_keyset_info_from_json(&output_keyset_json)
        .map_err(|error| anyhow!(error))?;
    let mint = RefundMintConnection::new(&funding.mint_url);
    let funding_state = channel.check_funding_token_state(&mint).await?;
    if funding_state.state != cashu::nuts::State::Spent {
        return Ok(
            cashu_service::StreamingRouteRestoreCashuSpilmanRefundResult {
                channel_id: channel_id.to_string(),
                mint_url: funding.mint_url,
                unit,
                complete: false,
                recovered_amount_sat: 0,
                imported_amount_sat: 0,
                proof_count: 0,
            },
        );
    }

    let sender = cdk_spilman::SpilmanChannelSender::new(sender_secret, channel);
    let mut proofs = cashu_service::restore_sender_proofs_from_issued_keyset(
        &sender,
        &mint,
        &funding.mint_url,
        &unit,
        &output_keyset,
    )
    .await?;
    cashu_service::sign_restored_sender_proofs(
        &sender.channel.params,
        &sender.alice_secret,
        &mut proofs,
    )?;
    let recovered_amount_sat = proofs
        .iter()
        .map(|proof| u64::from(proof.amount))
        .sum::<u64>();
    let proof_count = proofs.len();
    let imported_amount_sat = if proofs.is_empty() {
        0
    } else {
        let imported: cashu_service::CashuReceivedPayment = serde_json::from_value(
            crate::cashu_wallet_daemon::request_daemon_cashu_wallet_worker(
                config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::ImportProofs {
                    mint_url: funding.mint_url.clone(),
                    unit: unit.clone(),
                    proofs_json: serde_json::to_string(&proofs)?,
                },
            )
            .await?,
        )
        .context("daemon returned an invalid Cashu refund import response")?;
        imported.amount_sat
    };
    storage.set_closed(channel_id);
    storage.mark_refund_witnesses_persisted(channel_id);
    storage.mark_refund_proofs_validated(channel_id);
    storage.mark_refund_proofs_repaired(channel_id);
    storage_errors.ensure_ok().map_err(|error| anyhow!(error))?;

    Ok(completed_refund_result(
        channel_id,
        funding.mint_url,
        unit,
        recovered_amount_sat,
        imported_amount_sat,
        proof_count,
    ))
}

fn completed_refund_result(
    channel_id: &str,
    mint_url: String,
    unit: String,
    recovered_amount_sat: u64,
    imported_amount_sat: u64,
    proof_count: usize,
) -> cashu_service::StreamingRouteRestoreCashuSpilmanRefundResult {
    cashu_service::StreamingRouteRestoreCashuSpilmanRefundResult {
        channel_id: channel_id.to_string(),
        mint_url,
        unit,
        complete: true,
        recovered_amount_sat,
        imported_amount_sat,
        proof_count,
    }
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
        if !store.channels.contains_key(&attempt.channel_id) {
            return Ok(recovery);
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
            PaidExitBuyerRefundOutcome::Pending => {
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
