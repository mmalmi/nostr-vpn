//! Reviewed, idempotent sends reuse CDK's persisted operation and proof authority.
//! No bearer material is exposed by a preview or included in Debug output.
use super::*;
use cdk::wallet::types::{OperationData, SendSagaState, WalletSagaState};
use cdk::wallet::SendOptions;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PRIMARY: &str = "iris_wallet";
const SECONDARY: &str = "reviewed_send";
const KEY: &str = "v1";
const MAX_REQUESTS: usize = 512;
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CashuSendReview {
    pub request_id: String,
    pub mint_url: String,
    /// Exact face amount of the token, before recipient redemption fees.
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub max_total_sat: u64,
    pub existing: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct Plan {
    mint_url: String,
    amount_sat: u64,
    fee_sat: u64,
    operation_id: Uuid,
    proofs_to_swap: Vec<Proof>,
    proofs_to_send: Vec<Proof>,
    swap_fee: Amount,
    send_fee: Amount,
    token: Option<String>,
    #[serde(default)]
    reclaiming: bool,
    #[serde(default)]
    fee_schedule: Option<FeeSchedule>,
}
impl Plan {
    fn review(&self, id: &str) -> Result<CashuSendReview> {
        Ok(CashuSendReview {
            request_id: id.into(),
            mint_url: self.mint_url.clone(),
            amount_sat: self.amount_sat,
            fee_sat: self.fee_sat,
            max_total_sat: self
                .amount_sat
                .checked_add(self.fee_sat)
                .context("Payment amount overflow")?,
            existing: true,
        })
    }
    fn matches(&self, mint: &str, amount: u64) -> Result<()> {
        anyhow::ensure!(
            self.mint_url == mint && self.amount_sat == amount,
            "Payment request has different terms"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct FeeSchedule {
    active: String,
    fees: BTreeMap<String, u64>,
}
pub(super) async fn fee_schedule(wallet: &cdk::Wallet, proofs: &[Proof]) -> Result<FeeSchedule> {
    let active = wallet
        .active_keyset_with_policy(cdk::wallet::types::KeysetLoadPolicy::CacheOnly)
        .await?
        .id
        .to_string();
    let mut required: std::collections::BTreeSet<_> = proofs
        .iter()
        .map(|proof| proof.keyset_id.to_string())
        .collect();
    required.insert(active.clone());
    let available: BTreeMap<_, _> = wallet
        .keysets(cdk::wallet::types::KeysetLoadPolicy::CacheOnly)
        .await?
        .into_iter()
        .map(|keyset| (keyset.id.to_string(), keyset.input_fee_ppk))
        .collect();
    let mut fees = BTreeMap::new();
    for id in required {
        fees.insert(
            id.clone(),
            *available
                .get(&id)
                .context("Mint input fee metadata is unavailable")?,
        );
    }
    Ok(FeeSchedule { active, fees })
}
pub(super) async fn validate_fee_schedule(
    wallet: &cdk::Wallet,
    proofs: &[Proof],
    approved: &FeeSchedule,
) -> Result<()> {
    super::send::refresh_active_keyset_id(wallet).await?;
    check_fee_schedule(approved, &fee_schedule(wallet, proofs).await?)
}
fn check_fee_schedule(approved: &FeeSchedule, current: &FeeSchedule) -> Result<()> {
    anyhow::ensure!(current == approved, "Mint fee schedule changed; recover or cancel the original operation before reviewing again");
    Ok(())
}
type Journal = BTreeMap<String, Plan>;
fn validate_request(id: &str, amount: u64) -> Result<()> {
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control),
        "Invalid payment request identifier"
    );
    anyhow::ensure!(amount > 0, "Enter a positive payment amount");
    Ok(())
}
async fn load(service: &CashuWalletService) -> Result<Journal> {
    let value = service
        .localstore()
        .kv_read(PRIMARY, SECONDARY, KEY)
        .await?;
    match value {
        Some(value) => {
            anyhow::ensure!(
                value.len() <= MAX_JOURNAL_BYTES,
                "Payment journal exceeds its limit"
            );
            let journal: Journal = serde_json::from_slice(&value)?;
            anyhow::ensure!(journal.len() <= MAX_REQUESTS, "Too many payment requests");
            Ok(journal)
        }
        None => Ok(BTreeMap::new()),
    }
}
async fn save(service: &CashuWalletService, value: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(
        value.len() <= MAX_REQUESTS && bytes.len() <= MAX_JOURNAL_BYTES,
        "Payment journal is full"
    );
    service
        .localstore()
        .kv_write(PRIMARY, SECONDARY, KEY, &bytes)
        .await?;
    Ok(())
}
impl CashuWalletService {
    /// Reads metadata, reserves a CDK preview and releases it; never confirms a mint swap.
    pub async fn preview_payment_token_reviewed(
        &self,
        mint: &str,
        amount: u64,
        request_id: &str,
    ) -> Result<CashuSendReview> {
        validate_request(request_id, amount)?;
        let _guard = self.lock_operation().await;
        self.require_restored_review()?;
        let mint = normalize_mint_url(mint)?;
        let journal = load(self).await?;
        if let Some(plan) = journal.get(request_id) {
            plan.matches(&mint, amount)?;
            anyhow::ensure!(
                !plan.reclaiming,
                "The original payment is reclaiming or reclaimed"
            );
            return plan.review(request_id);
        }
        anyhow::ensure!(journal.len() < MAX_REQUESTS, "Payment history is full");
        let wallet = ensure_sat_wallet(self.repository(), &MintUrl::from_str(&mint)?).await?;
        super::send::refresh_active_keyset_id(&wallet).await?;
        let prepared = wallet
            .prepare_send(
                amount.into(),
                SendOptions {
                    include_fee: false,
                    ..Default::default()
                },
            )
            .await?;
        let fee = prepared.fee().to_u64();
        prepared.cancel().await?;
        Ok(CashuSendReview {
            request_id: request_id.into(),
            mint_url: mint,
            amount_sat: amount,
            fee_sat: fee,
            max_total_sat: amount.checked_add(fee).context("Payment amount overflow")?,
            existing: false,
        })
    }
    /// The request binds to one exact CDK operation before confirmation. Uncertain
    /// or cancelled operations never silently become replacement sends.
    pub async fn send_payment_token_reviewed(
        &self,
        mint: &str,
        amount: u64,
        max_fee: u64,
        request_id: &str,
    ) -> Result<crate::helper::CashuSentPayment> {
        validate_request(request_id, amount)?;
        let _guard = self.lock_operation().await;
        self.require_restored_review()?;
        let mint = normalize_mint_url(mint)?;
        let wallet = ensure_sat_wallet(self.repository(), &MintUrl::from_str(&mint)?).await?;
        let mut journal = load(self).await?;
        if let Some(plan) = journal.get(request_id) {
            plan.matches(&mint, amount)?;
        } else {
            anyhow::ensure!(journal.len() < MAX_REQUESTS, "Payment history is full");
            super::send::refresh_active_keyset_id(&wallet).await?;
            let prepared = wallet
                .prepare_send(
                    amount.into(),
                    SendOptions {
                        include_fee: false,
                        ..Default::default()
                    },
                )
                .await?;
            let fee = prepared.fee().to_u64();
            if fee > max_fee {
                prepared.cancel().await?;
                anyhow::bail!("The fee changed; review this transfer again");
            }
            let schedule = match fee_schedule(&wallet, &prepared.proofs()).await {
                Ok(value) => value,
                Err(error) => {
                    prepared.cancel().await?;
                    return Err(error);
                }
            };
            let plan = Plan {
                mint_url: mint.clone(),
                amount_sat: amount,
                fee_sat: fee,
                operation_id: prepared.operation_id(),
                proofs_to_swap: prepared.proofs_to_swap().clone(),
                proofs_to_send: prepared.proofs_to_send().clone(),
                swap_fee: prepared.swap_fee(),
                send_fee: prepared.send_fee(),
                token: None,
                reclaiming: false,
                fee_schedule: Some(schedule),
            };
            journal.insert(request_id.into(), plan);
            if let Err(error) = save(self, &journal).await {
                prepared.cancel().await?;
                return Err(error);
            }
            drop(prepared);
        }
        let mut plan = journal
            .get(request_id)
            .context("Payment request is unavailable")?
            .clone();
        anyhow::ensure!(
            !plan.reclaiming,
            "The original payment is reclaiming or reclaimed"
        );
        anyhow::ensure!(
            plan.fee_sat <= max_fee,
            "Saved payment exceeds the approved fee"
        );
        let entries = load_wallet_activity_entries_from_store(self.localstore()).await?;
        anyhow::ensure!(
            !entries.iter().any(|entry| entry.operation_id.as_deref()
                == Some(&plan.operation_id.to_string())
                && entry.status == CashuWalletActivityStatus::Reclaimed),
            "The original payment was reclaimed"
        );
        if plan.token.is_none() {
            let saga = wallet
                .localstore
                .get_saga(&plan.operation_id)
                .await?
                .context(
                    "Original payment was cancelled or requires recovery; no replacement was sent",
                )?;
            anyhow::ensure!(
                saga.mint_url.to_string() == mint
                    && saga.unit == CurrencyUnit::Sat
                    && saga.amount.to_u64() == amount,
                "Payment operation identity changed"
            );
            let token = match saga.state {
                WalletSagaState::Send(SendSagaState::ProofsReserved) => {
                    let mut proofs = plan.proofs_to_swap.clone();
                    proofs.extend(plan.proofs_to_send.clone());
                    validate_fee_schedule(
                        &wallet,
                        &proofs,
                        plan.fee_schedule
                            .as_ref()
                            .context("Saved payment needs a fee review")?,
                    )
                    .await?;
                    wallet
                        .confirm_send(
                            plan.operation_id,
                            amount.into(),
                            SendOptions {
                                include_fee: false,
                                ..Default::default()
                            },
                            plan.proofs_to_swap.clone(),
                            plan.proofs_to_send.clone(),
                            plan.swap_fee,
                            plan.send_fee,
                            None,
                        )
                        .await?
                        .to_string()
                }
                WalletSagaState::Send(SendSagaState::TokenCreated) => match saga.data {
                    OperationData::Send(data) => data
                        .token
                        .context("Saved payment token requires recovery")?,
                    _ => anyhow::bail!("Invalid payment operation"),
                },
                _ => anyhow::bail!(
                    "The original payment is pending recovery; no replacement was sent"
                ),
            };
            let decoded = Token::from_str(&token)?;
            anyhow::ensure!(
                decoded.mint_url()?.to_string() == mint
                    && decoded.unit().unwrap_or_default() == CurrencyUnit::Sat
                    && decoded.value()?.to_u64() == amount,
                "Saved payment token does not match the approved amount"
            );
            plan.token = Some(token);
            journal.insert(request_id.into(), plan.clone());
            save(self, &journal).await?;
        }
        let payment = crate::helper::CashuSentPayment {
            mint_url: mint,
            unit: "sat".into(),
            amount_sat: amount,
            send_fee_sat: plan.fee_sat,
            operation_id: plan.operation_id.to_string(),
            token: plan.token.context("Payment token is unavailable")?,
        };
        if !entries
            .iter()
            .any(|entry| entry.operation_id.as_deref() == Some(&payment.operation_id))
        {
            append_wallet_activity_entry(
                self.localstore(),
                CashuWalletActivityEntry {
                    id: wallet_activity_id(),
                    kind: CashuWalletActivityKind::TokenSend,
                    status: CashuWalletActivityStatus::Pending,
                    mint_url: payment.mint_url.clone(),
                    unit: "sat".into(),
                    amount_sat: amount,
                    fee_sat: Some(plan.fee_sat),
                    created_at_unix: wallet_activity_now_unix(),
                    expires_at_unix: None,
                    operation_id: Some(payment.operation_id.clone()),
                    quote_id: None,
                    payment_request: None,
                    token: Some(payment.token.clone()),
                },
            )
            .await?;
        }
        Ok(payment)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_fee_schedule_rejects_changed_input_fee_and_keyset() {
        let approved = FeeSchedule {
            active: "key-one".into(),
            fees: BTreeMap::from([("key-one".into(), 1000)]),
        };
        let saved: FeeSchedule =
            serde_json::from_slice(&serde_json::to_vec(&approved).unwrap()).unwrap();
        assert!(check_fee_schedule(&saved, &approved).is_ok());
        let mut changed = approved.clone();
        changed.fees.insert("key-one".into(), 2000);
        assert!(check_fee_schedule(&saved, &changed).is_err());
        changed = approved.clone();
        changed.active = "key-two".into();
        assert!(check_fee_schedule(&saved, &changed).is_err());
    }
    #[tokio::test]
    async fn reviewed_reservation_survives_refresh_and_connection_reset() {
        use cdk::wallet::types::{SendOperationData, WalletSaga};
        let directory = tempfile::tempdir().unwrap();
        let operation = Uuid::new_v4();
        let mint: MintUrl = "https://mint.example".parse().unwrap();
        {
            let service = CashuWalletService::open_file_backed(directory.path())
                .await
                .unwrap();
            let wallet = ensure_sat_wallet(service.repository(), &mint)
                .await
                .unwrap();
            let saga = WalletSaga::new(
                operation,
                WalletSagaState::Send(SendSagaState::ProofsReserved),
                7.into(),
                mint.clone(),
                CurrencyUnit::Sat,
                OperationData::Send(SendOperationData {
                    amount: 7.into(),
                    memo: None,
                    counter_start: None,
                    counter_end: None,
                    token: None,
                    proofs: None,
                }),
            );
            wallet.localstore.add_saga(saga).await.unwrap();
            let plan = Plan {
                mint_url: mint.to_string(),
                amount_sat: 7,
                fee_sat: 1,
                operation_id: operation,
                proofs_to_swap: vec![],
                proofs_to_send: vec![],
                swap_fee: 0.into(),
                send_fee: 0.into(),
                token: None,
                reclaiming: false,
                fee_schedule: None,
            };
            save(&service, &BTreeMap::from([("order:reserved".into(), plan)]))
                .await
                .unwrap();
        }
        let service = CashuWalletService::open_file_backed(directory.path())
            .await
            .unwrap();
        service.refresh_network_connections().await.unwrap();
        let overview = service.load_wallet_overview(true).await.unwrap();
        assert!(overview
            .warnings
            .iter()
            .any(|w| w.contains("reservation was preserved")));
        let wallet = ensure_sat_wallet(service.repository(), &mint)
            .await
            .unwrap();
        assert!(matches!(
            wallet
                .localstore
                .get_saga(&operation)
                .await
                .unwrap()
                .unwrap()
                .state,
            WalletSagaState::Send(SendSagaState::ProofsReserved)
        ));
        assert_eq!(
            service
                .preview_payment_token_reviewed(&mint.to_string(), 7, "order:reserved")
                .await
                .unwrap()
                .request_id,
            "order:reserved"
        );
    }
    #[tokio::test]
    async fn reclaim_marker_survives_reopen_before_history_update() {
        let directory = tempfile::tempdir().unwrap();
        let operation = Uuid::new_v4();
        {
            let service = CashuWalletService::open_file_backed(directory.path())
                .await
                .unwrap();
            let plan = Plan {
                mint_url: "https://mint.example".into(),
                amount_sat: 7,
                fee_sat: 1,
                operation_id: operation,
                proofs_to_swap: vec![],
                proofs_to_send: vec![],
                swap_fee: 0.into(),
                send_fee: 0.into(),
                token: None,
                reclaiming: false,
                fee_schedule: None,
            };
            save(&service, &BTreeMap::from([("order:one".into(), plan)]))
                .await
                .unwrap();
            begin_reclaim(&service, "https://mint.example", &operation.to_string())
                .await
                .unwrap();
        }
        let service = CashuWalletService::open_file_backed(directory.path())
            .await
            .unwrap();
        assert!(service
            .payment_token_is_reclaiming(&operation.to_string())
            .await
            .unwrap());
        assert!(service
            .preview_payment_token_reviewed("https://mint.example", 7, "order:one")
            .await
            .is_err());
    }
    #[test]
    fn request_identifiers_and_amounts_are_bounded() {
        assert!(validate_request("order:one", 1).is_ok());
        for id in ["".to_string(), "x".repeat(257), "line\nbreak".into()] {
            assert!(validate_request(&id, 1).is_err());
        }
        assert!(validate_request("order:one", 0).is_err());
    }
}

/// Called with the service operation lock before submitting any revoke request.
pub(super) async fn begin_reclaim(
    service: &CashuWalletService,
    mint: &str,
    operation_id: &str,
) -> Result<()> {
    let mut journal = load(service).await?;
    let mut changed = false;
    for plan in journal
        .values_mut()
        .filter(|plan| plan.operation_id.to_string() == operation_id)
    {
        anyhow::ensure!(
            plan.mint_url == mint,
            "Reclaim does not match the original mint"
        );
        plan.reclaiming = true;
        changed = true;
    }
    if changed {
        save(service, &journal).await?;
    }
    Ok(())
}
impl CashuWalletService {
    pub async fn payment_token_is_reclaiming(&self, operation_id: &str) -> Result<bool> {
        let _guard = self.lock_operation().await;
        Ok(load(self)
            .await?
            .values()
            .any(|plan| plan.operation_id.to_string() == operation_id && plan.reclaiming))
    }
}

impl CashuWalletService {
    /// Generic CDK recovery compensates reservations; a reviewed request owns
    /// its original reservation until the caller explicitly confirms it.
    pub(super) async fn recover_wallet_sagas(
        &self,
        wallet: &cdk::Wallet,
    ) -> Result<cdk::wallet::RecoveryReport> {
        let mut ids: Vec<Uuid> = load(self)
            .await?
            .values()
            .filter(|plan| {
                plan.mint_url == wallet.mint_url.to_string()
                    && plan.token.is_none()
                    && !plan.reclaiming
            })
            .map(|plan| plan.operation_id)
            .collect();
        ids.extend(
            super::reviewed_lightning::reserved_intents(self, &wallet.mint_url.to_string()).await?,
        );
        for id in ids {
            let saga =
                wallet.localstore.get_saga(&id).await?.context(
                    "Reviewed payment needs recovery; original reservation is unavailable",
                )?;
            anyhow::ensure!(
                saga.mint_url == wallet.mint_url && saga.unit == CurrencyUnit::Sat,
                "Reviewed operation identity changed"
            );
            if matches!(
                saga.state,
                WalletSagaState::Send(SendSagaState::ProofsReserved)
                    | WalletSagaState::Melt(cdk::wallet::types::MeltSagaState::ProofsReserved)
            ) {
                return Ok(cdk::wallet::RecoveryReport {
                    skipped: 1,
                    ..Default::default()
                });
            }
        }
        Ok(wallet.recover_incomplete_sagas().await?)
    }
}
