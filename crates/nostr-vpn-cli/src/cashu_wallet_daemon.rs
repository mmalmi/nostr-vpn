use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use cashu_service::{CashuWalletService, StreamingRouteOpenCashuSpilmanChannelFromWalletRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{daemon_status, paid_exit_wallet_data_dir, wait_for_running_daemon_control_ready};

const CASHU_WALLET_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const LEGACY_CHANNEL_SEND_MATCH_WINDOW_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingCashuSend {
    mint_url: String,
    operation_id: String,
    amount_sat: u64,
    created_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonCashuWalletOverview {
    totals: Vec<DaemonCashuUnitTotal>,
    entries: Vec<DaemonCashuWalletEntry>,
    warnings: Vec<String>,
    legacy_state_detected: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonCashuUnitTotal {
    unit: String,
    balance: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonCashuWalletEntry {
    mint_url: String,
    unit: String,
    balance: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DaemonCashuTopupQuote {
    pub(crate) mint_url: String,
    pub(crate) unit: String,
    pub(crate) amount: u64,
    pub(crate) quote_id: String,
    pub(crate) payment_request: String,
    pub(crate) expiry_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum DaemonCashuWalletCommand {
    Overview {
        refresh_quotes: bool,
    },
    Activity,
    CreateTopupQuote {
        mint_url: String,
        amount_sat: u64,
    },
    ReceiveToken {
        token: String,
    },
    SendToken {
        mint_url: String,
        amount_sat: u64,
    },
    PayLightning {
        mint_url: String,
        invoice: String,
    },
    OpenSpilmanChannel {
        request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    },
    ImportProofs {
        mint_url: String,
        unit: String,
        proofs_json: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonCashuWalletRequest {
    id: String,
    command: DaemonCashuWalletCommand,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonCashuWalletResponse {
    id: String,
    result: Option<Value>,
    error: Option<String>,
}

pub(crate) struct DaemonCashuWallet {
    service: CashuWalletService,
}

impl DaemonCashuWallet {
    pub(crate) async fn open(config_path: &Path) -> Result<Self> {
        let data_dir = paid_exit_wallet_data_dir(config_path);
        let service = CashuWalletService::open_with_seed_store(
            &data_dir,
            Arc::new(nostr_vpn_core::PlatformCashuWalletSeedStore::new(
                config_path,
            )),
        )
        .await
        .context("failed to open the daemon-owned CDK SQLite Cashu wallet")?;
        let recovery = service.recover_startup_state().await;
        for warning in recovery.warnings {
            eprintln!("cashu-wallet: startup recovery incomplete: {warning}");
        }
        match recover_legacy_opened_route_channels(config_path, cashu_wallet_now_unix()) {
            Ok(recovered) if recovered > 0 => eprintln!(
                "cashu-wallet: reattached {recovered} committed channel(s) to paid routes"
            ),
            Ok(_) => {}
            Err(error) => {
                eprintln!("cashu-wallet: paid route channel recovery incomplete: {error:#}")
            }
        }
        match reclaim_legacy_orphaned_channel_sends(&service, config_path, cashu_wallet_now_unix())
            .await
        {
            Ok(reclaimed) if reclaimed > 0 => eprintln!(
                "cashu-wallet: returned {reclaimed} sat from expired channel opening attempts"
            ),
            Ok(_) => {}
            Err(error) => {
                eprintln!("cashu-wallet: legacy channel wallet recovery incomplete: {error:#}")
            }
        }
        prepare_ipc_directories(config_path)?;
        Ok(Self { service })
    }

    pub(crate) async fn handle_pending_requests(&self, config_path: &Path) -> Result<usize> {
        let request_dir = cashu_wallet_request_dir(config_path);
        let mut requests = fs::read_dir(&request_dir)
            .with_context(|| format!("failed to read {}", request_dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        requests.sort();

        let mut handled = 0;
        for request_path in requests {
            let raw = match fs::read(&request_path) {
                Ok(raw) => raw,
                Err(error) => {
                    eprintln!(
                        "cashu-wallet: failed to read request {}: {error}",
                        request_path.display()
                    );
                    continue;
                }
            };
            let request = match serde_json::from_slice::<DaemonCashuWalletRequest>(&raw) {
                Ok(request) => request,
                Err(error) => {
                    eprintln!(
                        "cashu-wallet: rejected malformed request {}: {error}",
                        request_path.display()
                    );
                    let _ = fs::remove_file(&request_path);
                    continue;
                }
            };
            if uuid::Uuid::parse_str(&request.id).is_err() {
                eprintln!(
                    "cashu-wallet: rejected request with invalid id in {}",
                    request_path.display()
                );
                let _ = fs::remove_file(&request_path);
                continue;
            }
            let response = match self.execute(request.command).await {
                Ok(result) => DaemonCashuWalletResponse {
                    id: request.id.clone(),
                    result: Some(result),
                    error: None,
                },
                Err(error) => DaemonCashuWalletResponse {
                    id: request.id.clone(),
                    result: None,
                    error: Some(format!("{error:#}")),
                },
            };
            write_wallet_response(config_path, &response)?;
            let _ = fs::remove_file(&request_path);
            handled += 1;
        }
        Ok(handled)
    }

    async fn execute(&self, command: DaemonCashuWalletCommand) -> Result<Value> {
        let value = match command {
            DaemonCashuWalletCommand::Overview { refresh_quotes } => {
                let overview = self.service.load_wallet_overview(refresh_quotes).await?;
                serde_json::to_value(DaemonCashuWalletOverview {
                    totals: overview
                        .totals
                        .into_iter()
                        .map(|total| DaemonCashuUnitTotal {
                            unit: total.unit,
                            balance: total.balance,
                        })
                        .collect(),
                    entries: overview
                        .entries
                        .into_iter()
                        .map(|entry| DaemonCashuWalletEntry {
                            mint_url: entry.mint_url,
                            unit: entry.unit,
                            balance: entry.balance,
                        })
                        .collect(),
                    warnings: overview.warnings,
                    legacy_state_detected: overview.legacy_state_detected,
                })?
            }
            DaemonCashuWalletCommand::Activity => {
                serde_json::to_value(self.service.load_wallet_activity().await?)?
            }
            DaemonCashuWalletCommand::CreateTopupQuote {
                mint_url,
                amount_sat,
            } => {
                let quote = self
                    .service
                    .create_topup_quote(&mint_url, amount_sat)
                    .await?;
                serde_json::to_value(DaemonCashuTopupQuote {
                    mint_url: quote.mint_url,
                    unit: quote.unit,
                    amount: quote.amount,
                    quote_id: quote.quote_id,
                    payment_request: quote.payment_request,
                    expiry_unix: quote.expiry_unix,
                })?
            }
            DaemonCashuWalletCommand::ReceiveToken { token } => {
                serde_json::to_value(self.service.receive_payment_token(&token).await?)?
            }
            DaemonCashuWalletCommand::SendToken {
                mint_url,
                amount_sat,
            } => serde_json::to_value(
                self.service
                    .send_payment_token(&mint_url, amount_sat)
                    .await?,
            )?,
            DaemonCashuWalletCommand::PayLightning { mint_url, invoice } => serde_json::to_value(
                self.service
                    .send_lightning_payment(&mint_url, &invoice)
                    .await?,
            )?,
            DaemonCashuWalletCommand::OpenSpilmanChannel { request } => {
                let pending_before =
                    pending_cashu_sends(&self.service.load_wallet_activity().await?);
                let pending_before = pending_before
                    .into_iter()
                    .map(|send| send.operation_id)
                    .collect::<BTreeSet<_>>();
                match self
                    .service
                    .open_streaming_route_cashu_spilman_channel(request)
                    .await
                {
                    Ok(opened) => serde_json::to_value(opened)?,
                    Err(open_error) => {
                        let activity_after = self.service.load_wallet_activity().await?;
                        let created = newly_pending_cashu_sends(&pending_before, &activity_after);
                        let mut reclaimed_sat = 0_u64;
                        let mut rollback_errors = Vec::new();
                        for send in created {
                            match self
                                .service
                                .revoke_pending_payment(&send.mint_url, &send.operation_id)
                                .await
                            {
                                Ok(amount) => reclaimed_sat = reclaimed_sat.saturating_add(amount),
                                Err(error) => rollback_errors.push(format!("{error:#}")),
                            }
                        }
                        if rollback_errors.is_empty() && reclaimed_sat > 0 {
                            return Err(open_error).context(format!(
                                "channel opening failed; returned {reclaimed_sat} sat to the wallet"
                            ));
                        }
                        if !rollback_errors.is_empty() {
                            return Err(open_error).context(format!(
                                "channel opening failed and wallet rollback needs retry: {}",
                                rollback_errors.join("; ")
                            ));
                        }
                        return Err(open_error);
                    }
                }
            }
            DaemonCashuWalletCommand::ImportProofs {
                mint_url,
                unit,
                proofs_json,
            } => serde_json::to_value(
                self.service
                    .import_payment_proofs(&mint_url, &unit, &proofs_json)
                    .await?,
            )?,
        };
        Ok(value)
    }
}

fn cashu_wallet_now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalized_mint_for_match(value: &str) -> &str {
    value.trim().trim_end_matches('/')
}

fn legacy_route_open_recovery_requests(
    store: &nostr_vpn_core::paid_route_store::PaidRouteStore,
    now_unix: u64,
) -> Vec<(
    String,
    cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
)> {
    let mut requests = store
        .sessions
        .iter()
        .filter_map(|(session_id, session)| {
            if session
                .session
                .payment
                .cashu_spilman_payment
                .as_ref()
                .is_some_and(cashu_service::CashuSpilmanPayment::has_funding)
                || session.session.payment.cashu_token_lease.is_some()
            {
                return None;
            }
            let lease = store.leases.get(&session.session.lease_id)?;
            let channel = store.channels.get(&session.session.payment.channel_id)?;
            let quote = store.quotes.get(&lease.lease.quote_id)?;
            if channel.role != nostr_vpn_core::paid_route_store::PaidRouteChannelRole::Buyer
                || lease.lease.expires_at_unix.min(channel.expires_at_unix) <= now_unix
                || channel.mint_url.trim().is_empty()
                || quote.quote.receiver_pubkey_hex.trim().is_empty()
                || session.session.payment.capacity_sat == 0
            {
                return None;
            }
            let unit = if session.session.payment.cashu_unit.trim().is_empty() {
                "sat".to_string()
            } else {
                session.session.payment.cashu_unit.clone()
            };
            Some((
                session_id.clone(),
                cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                    mint_url: channel.mint_url.clone(),
                    receiver_pubkey_hex: quote.quote.receiver_pubkey_hex.clone(),
                    capacity_sat: session.session.payment.capacity_sat,
                    expiry_unix: channel.expires_at_unix,
                    max_amount_per_output: 0,
                    unit,
                    opening_paid_msat: session.session.payment.paid_msat,
                    keyset_id: None,
                    keyset_info_json: None,
                    client_request_id: Some(session_id.clone()),
                    route_created_at_unix: Some(channel.created_at_unix),
                },
            ))
        })
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.0.cmp(&right.0));
    requests
}

fn recover_legacy_opened_route_channels(config_path: &Path, now_unix: u64) -> Result<usize> {
    let store_path = nostr_vpn_core::paid_route_store::paid_route_store_file_path(config_path);
    let store = nostr_vpn_core::paid_route_store::load_paid_route_store(&store_path)?;
    let requests = legacy_route_open_recovery_requests(&store, now_unix);
    let wallet_data_dir = paid_exit_wallet_data_dir(config_path);
    let mut recovered_count = 0;
    for (session_id, request) in requests {
        let Some(opened) =
            cashu_service::recover_streaming_route_cashu_spilman_channel_from_wallet_request(
                &wallet_data_dir,
                &request,
            )?
        else {
            continue;
        };
        nostr_vpn_core::paid_route_store::update_paid_route_store(&store_path, |store| {
            store.attach_buyer_spilman_channel(
                nostr_vpn_core::paid_route_store::AttachPaidRouteBuyerSpilmanChannelRequest {
                    session_id: session_id.clone(),
                    channel_id: opened.channel_id.clone(),
                    cashu_unit: opened.unit.clone(),
                    capacity_sat: opened.capacity_sat,
                    paid_msat: Some(opened.opening_paid_msat),
                    payment: opened.payment.clone(),
                    now_unix,
                },
            )?;
            Ok(())
        })?;
        recovered_count += 1;
    }
    Ok(recovered_count)
}

fn pending_cashu_sends(
    activity: &[cashu_service::CashuWalletActivityEntry],
) -> Vec<PendingCashuSend> {
    activity
        .iter()
        .filter(|entry| {
            entry.kind == cashu_service::CashuWalletActivityKind::TokenSend
                && entry.status == cashu_service::CashuWalletActivityStatus::Pending
        })
        .filter_map(|entry| {
            Some(PendingCashuSend {
                mint_url: entry.mint_url.clone(),
                operation_id: entry.operation_id.clone()?,
                amount_sat: entry.amount_sat,
                created_at_unix: entry.created_at_unix,
            })
        })
        .collect()
}

fn newly_pending_cashu_sends(
    pending_before: &BTreeSet<String>,
    activity_after: &[cashu_service::CashuWalletActivityEntry],
) -> Vec<PendingCashuSend> {
    pending_cashu_sends(activity_after)
        .into_iter()
        .filter(|send| !pending_before.contains(&send.operation_id))
        .collect()
}

fn legacy_orphaned_channel_sends(
    store: &nostr_vpn_core::paid_route_store::PaidRouteStore,
    activity: &[cashu_service::CashuWalletActivityEntry],
    now_unix: u64,
) -> Vec<PendingCashuSend> {
    let pending = pending_cashu_sends(activity);
    pending
        .into_iter()
        .filter(|send| {
            store.channels.values().any(|channel| {
                channel.role == nostr_vpn_core::paid_route_store::PaidRouteChannelRole::Buyer
                    && channel.status
                        == nostr_vpn_core::paid_route_store::PaidRouteLifecycleStatus::Probing
                    && channel.payment.cashu_spilman_payment.is_none()
                    && channel.expires_at_unix <= now_unix
                    && channel.payment.capacity_sat == send.amount_sat
                    && normalized_mint_for_match(&channel.mint_url)
                        == normalized_mint_for_match(&send.mint_url)
                    && send.created_at_unix >= channel.created_at_unix
                    && send.created_at_unix - channel.created_at_unix
                        <= LEGACY_CHANNEL_SEND_MATCH_WINDOW_SECS
            })
        })
        .collect()
}

async fn reclaim_legacy_orphaned_channel_sends(
    service: &CashuWalletService,
    config_path: &Path,
    now_unix: u64,
) -> Result<u64> {
    let store_path = nostr_vpn_core::paid_route_store::paid_route_store_file_path(config_path);
    let store = nostr_vpn_core::paid_route_store::load_paid_route_store(&store_path)?;
    let activity = service.load_wallet_activity().await?;
    let candidates = legacy_orphaned_channel_sends(&store, &activity, now_unix);
    let mut reclaimed_sat = 0_u64;
    let mut failures = Vec::new();
    for send in candidates {
        match service
            .revoke_pending_payment(&send.mint_url, &send.operation_id)
            .await
        {
            Ok(amount) => reclaimed_sat = reclaimed_sat.saturating_add(amount),
            Err(error) => failures.push(format!("{error:#}")),
        }
    }
    if !failures.is_empty() {
        return Err(anyhow!(
            "failed to reclaim one or more expired channel wallet tokens: {}",
            failures.join("; ")
        ));
    }
    Ok(reclaimed_sat)
}

pub(crate) struct DaemonCashuWalletWorker {
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    finished: Option<std::sync::mpsc::Receiver<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl DaemonCashuWalletWorker {
    pub(crate) fn start(config_path: PathBuf) -> Result<Self> {
        let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = std::sync::mpsc::channel();
        let (finished_sender, finished_receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("nvpn-cashu-wallet".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to create the daemon Cashu wallet runtime")
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_sender.send(Err(error));
                        let _ = finished_sender.send(());
                        return;
                    }
                };
                runtime.block_on(async move {
                    let wallet = match DaemonCashuWallet::open(&config_path).await {
                        Ok(wallet) => wallet,
                        Err(error) => {
                            let _ = startup_sender.send(Err(error));
                            return;
                        }
                    };
                    if startup_sender.send(Ok(())).is_err() {
                        return;
                    }
                    let mut interval = tokio::time::interval(Duration::from_millis(100));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        match shutdown_receiver.try_recv() {
                            Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                            Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        }
                        if !daemon_cashu_wallet_requests_pending(&config_path) {
                            continue;
                        }
                        if let Err(error) = wallet.handle_pending_requests(&config_path).await {
                            eprintln!("cashu-wallet: request handling failed: {error:#}");
                        }
                    }
                });
                let _ = finished_sender.send(());
            })
            .context("failed to start the daemon Cashu wallet worker")?;

        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                shutdown: Some(shutdown_sender),
                finished: Some(finished_receiver),
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(anyhow!("daemon Cashu wallet worker stopped during startup"))
            }
        }
    }

    pub(crate) fn stop(mut self) {
        self.request_shutdown();
    }

    fn request_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(finished) = self.finished.take()
            && finished.recv_timeout(Duration::from_millis(250)).is_ok()
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
        // Detach a worker that is inside an unresponsive mint request so daemon
        // shutdown can finish. Process exit terminates the detached thread.
    }
}

impl Drop for DaemonCashuWalletWorker {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

pub(crate) fn decode_daemon_cashu_wallet_overview(
    value: Value,
) -> Result<cashu_service::CashuWalletOverview> {
    let overview: DaemonCashuWalletOverview = serde_json::from_value(value)
        .context("daemon returned an invalid Cashu wallet overview")?;
    Ok(cashu_service::CashuWalletOverview {
        totals: overview
            .totals
            .into_iter()
            .map(|total| cashu_service::CashuUnitTotal {
                unit: total.unit,
                balance: total.balance,
            })
            .collect(),
        entries: overview
            .entries
            .into_iter()
            .map(|entry| cashu_service::CashuWalletEntry {
                mint_url: entry.mint_url,
                unit: entry.unit,
                balance: entry.balance,
            })
            .collect(),
        warnings: overview.warnings,
        legacy_state_detected: overview.legacy_state_detected,
    })
}

pub(crate) async fn request_daemon_cashu_wallet(
    config_path: &Path,
    command: DaemonCashuWalletCommand,
) -> Result<Value> {
    let status = daemon_status(config_path)?;
    if !status.running {
        return Err(anyhow!(
            "Cashu wallet requires the nvpn daemon; start or reinstall the Nostr VPN service"
        ));
    }
    wait_for_running_daemon_control_ready(config_path, &status)?;
    request_daemon_cashu_wallet_worker(config_path, command).await
}

/// Submit work directly to the wallet worker owned by the current daemon.
///
/// `request_daemon_cashu_wallet` intentionally searches for a *different*
/// daemon process, so calling it from the daemon itself reports that the
/// service is stopped. Background paid-exit maintenance already runs beside
/// the single wallet worker and must use this entry point instead.
pub(crate) async fn request_daemon_cashu_wallet_worker(
    config_path: &Path,
    command: DaemonCashuWalletCommand,
) -> Result<Value> {
    prepare_ipc_directories(config_path)?;

    let id = uuid::Uuid::new_v4().simple().to_string();
    let request = DaemonCashuWalletRequest {
        id: id.clone(),
        command,
    };
    let request_path = cashu_wallet_request_dir(config_path).join(format!("{id}.json"));
    let response_path = cashu_wallet_response_dir(config_path).join(format!("{id}.json"));
    nostr_vpn_core::config::write_private_file_preserving_user_owner(
        &request_path,
        &serde_json::to_vec(&request)?,
    )?;

    let started = Instant::now();
    while started.elapsed() < CASHU_WALLET_REQUEST_TIMEOUT {
        if response_path.exists() {
            let raw = fs::read(&response_path)
                .with_context(|| format!("failed to read {}", response_path.display()))?;
            let _ = fs::remove_file(&response_path);
            let response: DaemonCashuWalletResponse = serde_json::from_slice(&raw)
                .with_context(|| format!("failed to decode {}", response_path.display()))?;
            if response.id != id {
                return Err(anyhow!(
                    "Cashu wallet daemon response id did not match request"
                ));
            }
            return match (response.result, response.error) {
                (Some(result), None) => Ok(result),
                (_, Some(error)) => Err(anyhow!(error)),
                _ => Err(anyhow!("Cashu wallet daemon returned an empty response")),
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = fs::remove_file(&request_path);
    Err(anyhow!(
        "Cashu wallet daemon did not respond within {} seconds",
        CASHU_WALLET_REQUEST_TIMEOUT.as_secs()
    ))
}

fn cashu_wallet_ipc_dir(config_path: &Path) -> PathBuf {
    paid_exit_wallet_data_dir(config_path)
        .join("cashu")
        .join("daemon-ipc")
}

fn cashu_wallet_request_dir(config_path: &Path) -> PathBuf {
    cashu_wallet_ipc_dir(config_path).join("requests")
}

pub(crate) fn daemon_cashu_wallet_requests_pending(config_path: &Path) -> bool {
    fs::read_dir(cashu_wallet_request_dir(config_path))
        .ok()
        .is_some_and(|requests| {
            requests.filter_map(|entry| entry.ok()).any(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
        })
}

fn cashu_wallet_response_dir(config_path: &Path) -> PathBuf {
    cashu_wallet_ipc_dir(config_path).join("responses")
}

fn prepare_ipc_directories(config_path: &Path) -> Result<()> {
    #[cfg(unix)]
    let desired_owner = {
        use std::os::unix::fs::MetadataExt as _;
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let metadata = fs::metadata(parent)
            .with_context(|| format!("failed to inspect {}", parent.display()))?;
        (metadata.uid(), metadata.gid())
    };
    for directory in [
        cashu_wallet_ipc_dir(config_path),
        cashu_wallet_request_dir(config_path),
        cashu_wallet_response_dir(config_path),
    ] {
        fs::create_dir_all(&directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let metadata = fs::metadata(&directory)
                .with_context(|| format!("failed to inspect {}", directory.display()))?;
            if metadata.uid() == 0 && desired_owner.0 != 0 {
                std::os::unix::fs::chown(&directory, Some(desired_owner.0), Some(desired_owner.1))
                    .with_context(|| {
                        format!("failed to preserve owner of {}", directory.display())
                    })?;
            }
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to protect {}", directory.display()))?;
        }
    }
    Ok(())
}

fn write_wallet_response(config_path: &Path, response: &DaemonCashuWalletResponse) -> Result<()> {
    let response_path =
        cashu_wallet_response_dir(config_path).join(format!("{}.json", response.id));
    nostr_vpn_core::config::write_private_file_preserving_user_owner(
        &response_path,
        &serde_json::to_vec(response)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("cashu_wallet_daemon/tests.rs");
}
