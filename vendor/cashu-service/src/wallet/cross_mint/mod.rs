use anyhow::{bail, Context, Result};
use cdk::lightning_invoice::Bolt11Invoice;
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MeltQuoteState, MintQuoteState, PaymentMethod};
use cdk::Amount;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use super::{ensure_sat_wallet, normalize_mint_url, CashuWalletService};

const K_WALLET_NAMESPACE: &str = "iris_wallet";
const K_CROSS_MINT_TRANSFER_NAMESPACE: &str = "cross_mint_transfer";
const K_CROSS_MINT_TRANSFER_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CashuCrossMintTransferRequest {
    /// Caller-owned idempotency key. Reusing it resumes or returns the same transfer.
    pub transfer_id: String,
    /// Caller-selected and caller-approved source mint.
    pub source_mint_url: String,
    /// Caller-selected and caller-approved destination mint.
    pub destination_mint_url: String,
    pub amount_sat: u64,
    /// Maximum total source-side fee, including the melt reserve and wallet input fees.
    pub max_fee_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CashuCrossMintTransfer {
    pub transfer_id: String,
    pub source_mint_url: String,
    pub destination_mint_url: String,
    pub unit: String,
    pub amount_sat: u64,
    pub max_fee_sat: u64,
    pub melt_fee_reserve_sat: u64,
    pub wallet_fee_sat: u64,
    pub fee_paid_sat: u64,
    pub source_melt_quote_id: String,
    pub destination_mint_quote_id: String,
    /// Informational whole-wallet balance observed before this transfer.
    pub destination_balance_before_sat: u64,
    /// Informational whole-wallet balance observed after this transfer. Other
    /// wallet activity may contribute to the difference between these fields.
    pub destination_balance_after_sat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CashuCrossMintTransferSaga {
    version: u32,
    request: CashuCrossMintTransferRequest,
    destination_balance_before_sat: u64,
    destination_mint_quote_id: Option<String>,
    destination_payment_request: Option<String>,
    source_melt_quote_id: Option<String>,
    melt_fee_reserve_sat: Option<u64>,
    wallet_fee_sat: Option<u64>,
    fee_paid_sat: Option<u64>,
    result: Option<CashuCrossMintTransfer>,
}

/// Move sat-denominated wallet balance between two caller-selected, approved mints.
///
/// `transfer_id` is an idempotency key: retries recover the stored CDK sagas and
/// resume the same destination mint quote and source melt quote. This function
/// deliberately performs no mint selection or trust inference.
///
/// The saga mutex is process-local. Run exactly one wallet writer process per
/// `data_dir`; separate processes can otherwise start different quotes before
/// either persists the shared transfer ID.
///
/// This converts liquidity into the caller's destination-mint wallet; it does
/// not prove that a counterparty was paid. A payout application must durably
/// journal `settlement_id -> exact bearer token -> authenticated receiver ACK`
/// and replay that journal rather than creating another token after a crash.
pub async fn transfer_between_mints(
    data_dir: &Path,
    request: CashuCrossMintTransferRequest,
) -> Result<CashuCrossMintTransfer> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .transfer_between_mints(request)
        .await
}

/// Resume an already durable saga without permitting a new payment to start.
#[allow(dead_code)]
pub(crate) async fn resume_transfer_between_mints(
    data_dir: &Path,
    request: CashuCrossMintTransferRequest,
) -> Result<CashuCrossMintTransfer> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .resume_transfer_between_mints(request)
        .await
}

impl CashuWalletService {
    pub async fn transfer_between_mints(
        &self,
        request: CashuCrossMintTransferRequest,
    ) -> Result<CashuCrossMintTransfer> {
        self.transfer_between_mints_with_start(request, true).await
    }

    #[allow(dead_code)]
    pub(crate) async fn resume_transfer_between_mints(
        &self,
        request: CashuCrossMintTransferRequest,
    ) -> Result<CashuCrossMintTransfer> {
        self.transfer_between_mints_with_start(request, false).await
    }

    async fn transfer_between_mints_with_start(
        &self,
        request: CashuCrossMintTransferRequest,
        allow_new: bool,
    ) -> Result<CashuCrossMintTransfer> {
        let _guard = self.lock_operation().await;
        let request = normalize_cross_mint_transfer_request(request)?;
        let source_mint = MintUrl::from_str(&request.source_mint_url)
            .context("Failed to parse normalized source mint URL")?;
        let destination_mint = MintUrl::from_str(&request.destination_mint_url)
            .context("Failed to parse normalized destination mint URL")?;
        let source_wallet = ensure_sat_wallet(self.repository(), &source_mint).await?;
        let destination_wallet = ensure_sat_wallet(self.repository(), &destination_mint).await?;

        transfer_between_wallets_with_start(&source_wallet, &destination_wallet, request, allow_new)
            .await
    }
}

fn normalize_cross_mint_transfer_request(
    mut request: CashuCrossMintTransferRequest,
) -> Result<CashuCrossMintTransferRequest> {
    request.transfer_id = request.transfer_id.trim().to_string();
    if request.transfer_id.is_empty()
        || request.transfer_id.len() > 128
        || !request
            .transfer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("Cashu cross-mint transfer id must be 1-128 ASCII letters, digits, '-' or '_'");
    }
    if request.amount_sat == 0 {
        bail!("Cashu cross-mint transfer amount must be greater than zero");
    }
    request
        .amount_sat
        .checked_mul(1_000)
        .context("Cashu cross-mint transfer amount is too large")?;
    request.source_mint_url = normalize_mint_url(&request.source_mint_url)?;
    request.destination_mint_url = normalize_mint_url(&request.destination_mint_url)?;
    if request.source_mint_url == request.destination_mint_url {
        bail!("Cashu cross-mint transfer requires two different mints");
    }
    Ok(request)
}

async fn load_cross_mint_transfer_saga(
    wallet: &cdk::wallet::Wallet,
    transfer_id: &str,
) -> Result<Option<CashuCrossMintTransferSaga>> {
    let stored = wallet
        .localstore
        .kv_read(
            K_WALLET_NAMESPACE,
            K_CROSS_MINT_TRANSFER_NAMESPACE,
            transfer_id,
        )
        .await
        .context("Failed to read Cashu cross-mint transfer saga")?;
    stored
        .map(|bytes| {
            serde_json::from_slice(&bytes).context("Failed to parse Cashu cross-mint transfer saga")
        })
        .transpose()
}

async fn save_cross_mint_transfer_saga(
    wallet: &cdk::wallet::Wallet,
    saga: &CashuCrossMintTransferSaga,
) -> Result<()> {
    let encoded =
        serde_json::to_vec(saga).context("Failed to encode Cashu cross-mint transfer saga")?;
    wallet
        .localstore
        .kv_write(
            K_WALLET_NAMESPACE,
            K_CROSS_MINT_TRANSFER_NAMESPACE,
            &saga.request.transfer_id,
            &encoded,
        )
        .await
        .context("Failed to write Cashu cross-mint transfer saga")
}

fn validate_exact_bolt11_amount(payment_request: &str, amount_sat: u64) -> Result<()> {
    let invoice = Bolt11Invoice::from_str(payment_request)
        .context("Destination mint returned an invalid BOLT11 invoice")?;
    let expected_msat = amount_sat
        .checked_mul(1_000)
        .context("Cashu cross-mint transfer amount is too large")?;
    let invoice_msat = invoice
        .amount_milli_satoshis()
        .context("Destination mint returned an amountless BOLT11 invoice")?;
    if invoice_msat != expected_msat {
        bail!(
            "Destination mint invoice amount {invoice_msat} msat does not match requested amount {expected_msat} msat"
        );
    }
    Ok(())
}

#[cfg(test)]
async fn transfer_between_wallets(
    source_wallet: &cdk::wallet::Wallet,
    destination_wallet: &cdk::wallet::Wallet,
    request: CashuCrossMintTransferRequest,
) -> Result<CashuCrossMintTransfer> {
    transfer_between_wallets_with_start(source_wallet, destination_wallet, request, true).await
}

async fn transfer_between_wallets_with_start(
    source_wallet: &cdk::wallet::Wallet,
    destination_wallet: &cdk::wallet::Wallet,
    request: CashuCrossMintTransferRequest,
    allow_new: bool,
) -> Result<CashuCrossMintTransfer> {
    let recovered_melts = source_wallet
        .finalize_pending_melts()
        .await
        .context("Failed to finalize pending source mint payments")?;
    source_wallet
        .recover_incomplete_sagas()
        .await
        .context("Failed to recover source mint wallet state")?;
    destination_wallet
        .recover_incomplete_sagas()
        .await
        .context("Failed to recover destination mint wallet state")?;

    let mut saga = match load_cross_mint_transfer_saga(source_wallet, &request.transfer_id).await? {
        Some(saga) => {
            if saga.version != K_CROSS_MINT_TRANSFER_VERSION || saga.request != request {
                bail!(
                    "Cashu cross-mint transfer id {} is already bound to a different request",
                    request.transfer_id
                );
            }
            if let Some(result) = saga.result {
                return Ok(result);
            }
            saga
        }
        None => {
            if !allow_new {
                bail!(
                    "Cashu cross-mint transfer id {} has no durable saga to resume",
                    request.transfer_id
                );
            }
            let saga = CashuCrossMintTransferSaga {
                version: K_CROSS_MINT_TRANSFER_VERSION,
                request: request.clone(),
                destination_balance_before_sat: destination_wallet
                    .total_balance()
                    .await
                    .context("Failed to load destination mint balance before transfer")?
                    .to_u64(),
                destination_mint_quote_id: None,
                destination_payment_request: None,
                source_melt_quote_id: None,
                melt_fee_reserve_sat: None,
                wallet_fee_sat: None,
                fee_paid_sat: None,
                result: None,
            };
            save_cross_mint_transfer_saga(source_wallet, &saga).await?;
            saga
        }
    };

    if saga.destination_mint_quote_id.is_none() {
        let quote = destination_wallet
            .mint_quote(
                PaymentMethod::BOLT11,
                Some(Amount::from(request.amount_sat)),
                None,
                None,
            )
            .await
            .context("Failed to create exact destination mint quote")?;
        if quote.amount != Some(Amount::from(request.amount_sat)) {
            bail!("Destination mint returned an incorrect mint quote amount");
        }
        validate_exact_bolt11_amount(&quote.request, request.amount_sat)?;
        saga.destination_mint_quote_id = Some(quote.id);
        saga.destination_payment_request = Some(quote.request);
        save_cross_mint_transfer_saga(source_wallet, &saga).await?;
    }

    let destination_quote_id = saga
        .destination_mint_quote_id
        .clone()
        .context("Cashu cross-mint saga has no destination quote id")?;
    let payment_request = saga
        .destination_payment_request
        .clone()
        .context("Cashu cross-mint saga has no destination invoice")?;
    validate_exact_bolt11_amount(&payment_request, request.amount_sat)?;

    if saga.source_melt_quote_id.is_none() {
        let quote = source_wallet
            .melt_quote(PaymentMethod::BOLT11, &payment_request, None, None)
            .await
            .context("Failed to preflight source mint melt quote")?;
        if quote.amount != Amount::from(request.amount_sat) {
            bail!("Source mint returned an incorrect melt quote amount");
        }
        let fee_reserve_sat = quote.fee_reserve.to_u64();
        if fee_reserve_sat > request.max_fee_sat {
            bail!(
                "Source mint melt fee reserve {fee_reserve_sat} sat exceeds caller maximum {} sat",
                request.max_fee_sat
            );
        }
        saga.source_melt_quote_id = Some(quote.id);
        saga.melt_fee_reserve_sat = Some(fee_reserve_sat);
        save_cross_mint_transfer_saga(source_wallet, &saga).await?;
    }

    let source_quote_id = saga
        .source_melt_quote_id
        .clone()
        .context("Cashu cross-mint saga has no source quote id")?;
    let source_quote = source_wallet
        .localstore
        .get_melt_quote(&source_quote_id)
        .await
        .context("Failed to load source mint melt quote")?
        .context("Stored source mint melt quote is missing")?;
    if source_quote.request != payment_request
        || source_quote.amount != Amount::from(request.amount_sat)
        || source_quote.fee_reserve.to_u64()
            != saga
                .melt_fee_reserve_sat
                .context("Cashu cross-mint saga has no melt fee reserve")?
    {
        bail!("Stored source mint melt quote does not match the cross-mint transfer");
    }

    let mut paid_transaction = source_wallet
        .list_transactions(Some(cdk::wallet::types::TransactionDirection::Outgoing))
        .await
        .context("Failed to load source mint transactions")?
        .into_iter()
        .find(|transaction| transaction.quote_id.as_deref() == Some(source_quote_id.as_str()));

    if paid_transaction.is_none() {
        if let Some(finalized) = recovered_melts
            .into_iter()
            .find(|melt| melt.quote_id() == source_quote_id)
        {
            if finalized.state() != MeltQuoteState::Paid {
                bail!(
                    "Recovered source mint payment finished in unexpected state {}",
                    finalized.state()
                );
            }
            saga.fee_paid_sat = Some(finalized.fee_paid().to_u64());
        }

        match source_quote.state {
            MeltQuoteState::Unpaid => {
                if !allow_new {
                    bail!(
                        "Cashu cross-mint transfer id {} has not started a source payment",
                        request.transfer_id
                    );
                }
                let prepared = source_wallet
                    .prepare_melt(&source_quote_id, HashMap::new())
                    .await
                    .context("Failed to prepare source mint payment")?;
                let wallet_fee_sat = prepared.total_fee_with_swap().to_u64();
                let preflight_fee_sat = source_quote
                    .fee_reserve
                    .to_u64()
                    .checked_add(wallet_fee_sat)
                    .context("Cashu cross-mint fee overflow")?;
                if preflight_fee_sat > request.max_fee_sat {
                    prepared
                        .cancel()
                        .await
                        .context("Failed to cancel over-limit source mint payment")?;
                    bail!(
                        "Source mint preflight fee {preflight_fee_sat} sat exceeds caller maximum {} sat",
                        request.max_fee_sat
                    );
                }
                saga.wallet_fee_sat = Some(wallet_fee_sat);
                save_cross_mint_transfer_saga(source_wallet, &saga).await?;
                let finalized = prepared
                    .confirm()
                    .await
                    .context("Failed to execute source mint payment")?;
                if finalized.state() != MeltQuoteState::Paid {
                    bail!(
                        "Source mint payment finished in unexpected state {}",
                        finalized.state()
                    );
                }
                saga.fee_paid_sat = Some(finalized.fee_paid().to_u64());
                save_cross_mint_transfer_saga(source_wallet, &saga).await?;
            }
            MeltQuoteState::Paid => {}
            state => bail!("Source mint payment is not recoverable from state {state}"),
        }

        paid_transaction = source_wallet
            .list_transactions(Some(cdk::wallet::types::TransactionDirection::Outgoing))
            .await
            .context("Failed to reload source mint transactions")?
            .into_iter()
            .find(|transaction| transaction.quote_id.as_deref() == Some(source_quote_id.as_str()));
    }

    let paid_transaction =
        paid_transaction.context("Paid source mint transfer has no durable wallet transaction")?;
    let fee_paid_sat = paid_transaction.fee.to_u64();
    saga.fee_paid_sat = Some(fee_paid_sat);
    save_cross_mint_transfer_saga(source_wallet, &saga).await?;

    let destination_quote = destination_wallet
        .check_mint_quote_status(&destination_quote_id)
        .await
        .context("Failed to refresh destination mint quote")?;
    if destination_quote.amount != Some(Amount::from(request.amount_sat)) {
        bail!("Destination mint quote amount changed during transfer");
    }
    if destination_quote.state == MintQuoteState::Paid {
        destination_wallet
            .mint(
                &destination_quote_id,
                cdk::amount::SplitTarget::default(),
                None,
            )
            .await
            .context("Failed to issue paid destination mint quote")?;
    } else if destination_quote.state != MintQuoteState::Issued {
        bail!(
            "Paid source transfer has destination mint quote in unexpected state {}",
            destination_quote.state
        );
    }

    let issued_quote = destination_wallet
        .localstore
        .get_mint_quote(&destination_quote_id)
        .await
        .context("Failed to load issued destination mint quote")?
        .context("Issued destination mint quote is missing")?;
    if issued_quote.id != destination_quote_id
        || issued_quote.mint_url != destination_wallet.mint_url
        || issued_quote.payment_method != PaymentMethod::BOLT11
        || issued_quote.unit != CurrencyUnit::Sat
        || issued_quote.amount != Some(Amount::from(request.amount_sat))
        || issued_quote.request != payment_request
        || issued_quote.state != MintQuoteState::Issued
        || issued_quote.amount_issued != Amount::from(request.amount_sat)
    {
        bail!("Issued destination mint quote does not match the cross-mint transfer");
    }

    let destination_balance_after_sat = destination_wallet
        .total_balance()
        .await
        .context("Failed to load destination mint balance after transfer")?
        .to_u64();
    if fee_paid_sat > request.max_fee_sat {
        bail!(
            "Source mint charged {fee_paid_sat} sat after a maximum {} sat preflight",
            request.max_fee_sat
        );
    }

    let result = CashuCrossMintTransfer {
        transfer_id: request.transfer_id.clone(),
        source_mint_url: request.source_mint_url.clone(),
        destination_mint_url: request.destination_mint_url.clone(),
        unit: CurrencyUnit::Sat.to_string(),
        amount_sat: request.amount_sat,
        max_fee_sat: request.max_fee_sat,
        melt_fee_reserve_sat: saga.melt_fee_reserve_sat.unwrap_or_default(),
        wallet_fee_sat: saga.wallet_fee_sat.unwrap_or_default(),
        fee_paid_sat,
        source_melt_quote_id: source_quote_id,
        destination_mint_quote_id: destination_quote_id,
        destination_balance_before_sat: saga.destination_balance_before_sat,
        destination_balance_after_sat,
    };
    saga.result = Some(result.clone());
    save_cross_mint_transfer_saga(source_wallet, &saga).await?;
    Ok(result)
}

#[cfg(test)]
mod tests;
