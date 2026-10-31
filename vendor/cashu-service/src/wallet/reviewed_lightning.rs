//! Explicit quote review and fee-capped confirmation of one durable melt.
use super::*;
use cdk::wallet::types::{MeltQuote, MeltSagaState, WalletSagaState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const PRIMARY: &str = "iris_wallet";
const SECONDARY: &str = "reviewed_lightning";
const KEY: &str = "v1";
const LIMIT: usize = 512;
#[derive(Clone, Serialize, Deserialize)]
pub struct CashuLightningReview {
    pub mint_url: String,
    pub quote_id: String,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub max_total_sat: u64,
    pub expiry_unix: u64,
    pub state: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CashuLightningResult {
    pub mint_url: String,
    pub quote_id: String,
    pub operation_id: Option<String>,
    pub amount_sat: u64,
    pub fee_sat: Option<u64>,
    pub state: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Intent {
    operation_id: Uuid,
    quote: MeltQuote,
    proofs: Vec<Proof>,
    proofs_to_swap: Vec<Proof>,
    input_fee: Amount,
    input_fee_without_swap: Amount,
    swap_fee: u64,
    #[serde(default)]
    fee_schedule: Option<super::reviewed::FeeSchedule>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    review: CashuLightningReview,
    invoice: String,
    intent: Option<Intent>,
    result: Option<CashuLightningResult>,
}
type Journal = BTreeMap<String, Record>;
async fn load(service: &CashuWalletService) -> Result<Journal> {
    let bytes = service
        .localstore()
        .kv_read(PRIMARY, SECONDARY, KEY)
        .await?;
    match bytes {
        None => Ok(BTreeMap::new()),
        Some(bytes) => {
            anyhow::ensure!(
                bytes.len() <= 16 * 1024 * 1024,
                "Lightning history exceeds its limit"
            );
            let records: Journal = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(records.len() <= LIMIT, "Lightning history is full");
            Ok(records)
        }
    }
}
async fn save(service: &CashuWalletService, records: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec(records)?;
    anyhow::ensure!(
        records.len() <= LIMIT && bytes.len() <= 16 * 1024 * 1024,
        "Lightning history is full"
    );
    service
        .localstore()
        .kv_write(PRIMARY, SECONDARY, KEY, &bytes)
        .await?;
    Ok(())
}
impl CashuWalletService {
    /// Called only after the user supplies an invoice and requests fee review.
    /// Preparation is cancelled without submitting a melt or a swap.
    pub async fn preview_lightning_payment_reviewed(
        &self,
        mint: &str,
        invoice: &str,
    ) -> Result<CashuLightningReview> {
        anyhow::ensure!(
            invoice.len() <= 16_384
                && invoice.to_ascii_lowercase().starts_with("lnbc")
                && invoice.bytes().all(|b| b.is_ascii_alphanumeric()),
            "Enter a mainnet Lightning invoice"
        );
        let _guard = self.lock_operation().await;
        self.require_restored_review()?;
        let mint = normalize_mint_url(mint)?;
        let wallet = ensure_sat_wallet(self.repository(), &MintUrl::from_str(&mint)?).await?;
        let mut journal = load(self).await?;
        if let Some(saved) = journal.values().find(|entry| {
            entry.review.mint_url == mint
                && entry.invoice.eq_ignore_ascii_case(invoice)
                && (entry.intent.is_some() || entry.result.is_some())
        }) {
            let mut review = saved.review.clone();
            review.state = saved
                .result
                .as_ref()
                .map(|r| r.state.clone())
                .unwrap_or_else(|| "pending".into());
            return Ok(review);
        }
        anyhow::ensure!(journal.len() < LIMIT, "Lightning history is full");
        let quote = wallet
            .melt_quote(PaymentMethod::BOLT11, invoice, None, None)
            .await?;
        anyhow::ensure!(
            quote.unit == CurrencyUnit::Sat
                && quote.request.eq_ignore_ascii_case(invoice)
                && quote.state == MeltQuoteState::Unpaid
                && quote.amount.to_u64() > 0
                && quote.expiry > wallet_activity_now_unix(),
            "The mint returned an unsupported Lightning quote"
        );
        let prepared = wallet.prepare_melt(&quote.id, HashMap::new()).await?;
        let fee = quote
            .fee_reserve
            .to_u64()
            .checked_add(prepared.total_fee().to_u64())
            .context("Lightning fee overflow")?;
        prepared.cancel().await?;
        let review = CashuLightningReview {
            mint_url: mint,
            quote_id: quote.id.clone(),
            amount_sat: quote.amount.to_u64(),
            fee_sat: fee,
            max_total_sat: quote
                .amount
                .to_u64()
                .checked_add(fee)
                .context("Lightning amount overflow")?,
            expiry_unix: quote.expiry,
            state: "review".into(),
        };
        journal.insert(
            quote.id,
            Record {
                review: review.clone(),
                invoice: invoice.into(),
                intent: None,
                result: None,
            },
        );
        save(self, &journal).await?;
        Ok(review)
    }
    /// Never creates a new quote. Retries confirm/recover only the saved operation.
    pub async fn confirm_lightning_payment_reviewed(
        &self,
        mint: &str,
        quote_id: &str,
        max_fee: u64,
    ) -> Result<CashuLightningResult> {
        let _guard = self.lock_operation().await;
        self.require_restored_review()?;
        let mint = normalize_mint_url(mint)?;
        let wallet = ensure_sat_wallet(self.repository(), &MintUrl::from_str(&mint)?).await?;
        let mut journal = load(self).await?;
        let mut record = journal
            .get(quote_id)
            .context("Review this Lightning invoice first")?
            .clone();
        anyhow::ensure!(
            record.review.mint_url == mint && record.review.fee_sat <= max_fee,
            "Lightning payment does not match the approved mint and fee"
        );
        if let Some(result) = record.result {
            reconcile_activity(self, &result).await?;
            check_actual_fee(&result, max_fee)?;
            return Ok(result);
        }
        if record.intent.is_none() {
            anyhow::ensure!(
                record.review.expiry_unix > wallet_activity_now_unix(),
                "This Lightning quote expired; review the invoice again"
            );
            super::send::refresh_active_keyset_id(&wallet).await?;
            let prepared = wallet.prepare_melt(quote_id, HashMap::new()).await?;
            let fee = prepared
                .quote()
                .fee_reserve
                .to_u64()
                .checked_add(prepared.total_fee().to_u64())
                .context("Lightning fee overflow")?;
            if fee > max_fee {
                prepared.cancel().await?;
                anyhow::bail!("The Lightning fee changed; review the invoice again");
            }
            let schedule = match super::reviewed::fee_schedule(&wallet, &prepared.proofs()).await {
                Ok(value) => value,
                Err(error) => {
                    prepared.cancel().await?;
                    return Err(error);
                }
            };
            let intent = Intent {
                operation_id: prepared.operation_id(),
                quote: prepared.quote().clone(),
                proofs: prepared.proofs().clone(),
                proofs_to_swap: prepared.proofs_to_swap().clone(),
                input_fee: prepared.input_fee(),
                input_fee_without_swap: prepared.input_fee_without_swap(),
                swap_fee: prepared.swap_fee().to_u64(),
                fee_schedule: Some(schedule),
            };
            record.intent = Some(intent);
            journal.insert(quote_id.into(), record.clone());
            if let Err(error) = save(self, &journal).await {
                prepared.cancel().await?;
                return Err(error);
            }
            drop(prepared);
        }
        let intent = record
            .intent
            .clone()
            .context("Lightning operation is unavailable")?;
        // CDK check_melt_quote_status resumes/compensates ProofsReserved sagas.
        // Read local quote authority here: confirming the exact saved operation
        // (or waiting for its pending result) performs the necessary remote work.
        let quote = wallet
            .localstore
            .get_melt_quote(quote_id)
            .await?
            .context("The original Lightning quote is unavailable")?;
        let (paid, actual_fee) = if quote.state == MeltQuoteState::Paid {
            (true, None)
        } else {
            let saga = wallet
                .localstore
                .get_saga(&intent.operation_id)
                .await?
                .context(
                    "The original Lightning payment needs recovery; no replacement was sent",
                )?;
            anyhow::ensure!(
                saga.mint_url.to_string() == mint
                    && saga.unit == CurrencyUnit::Sat
                    && saga.amount.to_u64() == record.review.amount_sat
                    && saga.quote_id.as_deref() == Some(quote_id),
                "Lightning operation identity changed"
            );
            if matches!(
                saga.state,
                WalletSagaState::Melt(MeltSagaState::ProofsReserved)
            ) {
                let mut proofs = intent.proofs.clone();
                proofs.extend(intent.proofs_to_swap.clone());
                super::reviewed::validate_fee_schedule(
                    &wallet,
                    &proofs,
                    intent
                        .fee_schedule
                        .as_ref()
                        .context("Saved Lightning payment needs a fee review")?,
                )
                .await?;
            }
            let future = async {
                match saga.state {
                    WalletSagaState::Melt(MeltSagaState::ProofsReserved) => {
                        wallet
                            .confirm_prepared_melt(
                                intent.operation_id,
                                intent.quote.clone(),
                                intent.proofs.clone(),
                                intent.proofs_to_swap.clone(),
                                intent.input_fee,
                                intent.input_fee_without_swap,
                                HashMap::new(),
                            )
                            .await
                    }
                    WalletSagaState::Melt(
                        MeltSagaState::MeltRequested | MeltSagaState::PaymentPending,
                    ) => {
                        wallet
                            .wait_pending_melt(intent.operation_id, quote_id, PaymentMethod::BOLT11)
                            .await
                    }
                    _ => Err(cdk::Error::Custom(
                        "The original Lightning payment needs recovery".into(),
                    )),
                }
            };
            let finalized = tokio::time::timeout(std::time::Duration::from_secs(30), future)
                .await
                .context("Lightning payment is pending; refresh before retrying")??;
            (
                finalized.state() == MeltQuoteState::Paid,
                Some(
                    finalized
                        .fee_paid()
                        .to_u64()
                        .checked_add(intent.swap_fee)
                        .context("Lightning fee overflow")?,
                ),
            )
        };
        anyhow::ensure!(
            paid,
            "Lightning payment is pending; no replacement was sent"
        );
        let result = CashuLightningResult {
            mint_url: mint.clone(),
            quote_id: quote_id.into(),
            operation_id: Some(intent.operation_id.to_string()),
            amount_sat: record.review.amount_sat,
            fee_sat: actual_fee,
            state: "paid".into(),
        };
        record.result = Some(result.clone());
        journal.insert(quote_id.into(), record);
        save(self, &journal).await?;
        reconcile_activity(self, &result).await?;
        check_actual_fee(&result, max_fee)?;
        Ok(result)
    }
}
fn check_actual_fee(result: &CashuLightningResult, max_fee: u64) -> Result<()> {
    anyhow::ensure!(result.fee_sat.map_or(true, |fee| fee <= max_fee), "Lightning payment completed but its reported fee exceeded the approved bound; inspect payment history before any further action");
    Ok(())
}
async fn reconcile_activity(
    service: &CashuWalletService,
    result: &CashuLightningResult,
) -> Result<()> {
    let entries = load_wallet_activity_entries_from_store(service.localstore()).await?;
    if !entries
        .iter()
        .any(|entry| entry.quote_id.as_deref() == Some(&result.quote_id))
    {
        append_wallet_activity_entry(
            service.localstore(),
            CashuWalletActivityEntry {
                id: wallet_activity_id(),
                kind: CashuWalletActivityKind::LightningPayment,
                status: CashuWalletActivityStatus::Complete,
                mint_url: result.mint_url.clone(),
                unit: "sat".into(),
                amount_sat: result.amount_sat,
                fee_sat: result.fee_sat,
                created_at_unix: wallet_activity_now_unix(),
                expires_at_unix: None,
                operation_id: result.operation_id.clone(),
                quote_id: Some(result.quote_id.clone()),
                payment_request: None,
                token: None,
            },
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn saved_result_repairs_history_after_restart_without_duplicate() {
        let directory = tempfile::tempdir().unwrap();
        let result = CashuLightningResult {
            mint_url: "https://mint.example".into(),
            quote_id: "quote-one".into(),
            operation_id: Some(Uuid::new_v4().to_string()),
            amount_sat: 100,
            fee_sat: Some(2),
            state: "paid".into(),
        };
        {
            let service = CashuWalletService::open_file_backed(directory.path())
                .await
                .unwrap();
            let record = Record {
                review: CashuLightningReview {
                    mint_url: result.mint_url.clone(),
                    quote_id: result.quote_id.clone(),
                    amount_sat: 100,
                    fee_sat: 2,
                    max_total_sat: 102,
                    expiry_unix: 0,
                    state: "review".into(),
                },
                invoice: "lnbcfixture".into(),
                intent: None,
                result: Some(result.clone()),
            };
            save(
                &service,
                &BTreeMap::from([(result.quote_id.clone(), record)]),
            )
            .await
            .unwrap();
        }
        let service = CashuWalletService::open_file_backed(directory.path())
            .await
            .unwrap();
        let saved = load(&service)
            .await
            .unwrap()
            .remove(&result.quote_id)
            .unwrap()
            .result
            .unwrap();
        reconcile_activity(&service, &saved).await.unwrap();
        reconcile_activity(&service, &saved).await.unwrap();
        let entries = load_wallet_activity_entries_from_store(service.localstore())
            .await
            .unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.quote_id.as_deref() == Some("quote-one"))
                .count(),
            1
        );
        assert!(check_actual_fee(&saved, 2).is_ok());
        assert!(check_actual_fee(&saved, 1).is_err());
    }
}

pub(super) async fn reserved_intents(
    service: &CashuWalletService,
    mint: &str,
) -> Result<Vec<Uuid>> {
    Ok(load(service)
        .await?
        .values()
        .filter(|record| record.review.mint_url == mint && record.result.is_none())
        .filter_map(|record| record.intent.as_ref().map(|intent| intent.operation_id))
        .collect())
}
