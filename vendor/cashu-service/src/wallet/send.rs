use anyhow::{bail, Context, Result};
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, Id, Proof, State};
use cdk::wallet::SendOptions;
use cdk::Amount;
use std::path::Path;
use std::str::FromStr;

use super::{
    append_wallet_activity_entry, ensure_sat_wallet, normalize_mint_url, wallet_activity_id,
    wallet_activity_now_unix, CashuWalletActivityEntry, CashuWalletActivityKind,
    CashuWalletActivityStatus, CashuWalletService,
};
use crate::helper::CashuSentPayment;

/// A local funding shortfall, distinct from a mint/network failure. The required
/// amount is a lower bound when CDK cannot select proofs including all fees.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CashuInsufficientFunds {
    pub available_sat: u64,
    pub required_sat: u64,
}

impl std::fmt::Display for CashuInsufficientFunds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Insufficient funds including mint fees: {} sat available, at least {} sat required",
            self.available_sat, self.required_sat
        )
    }
}

impl std::error::Error for CashuInsufficientFunds {}

pub async fn send_payment_token(
    data_dir: &Path,
    mint_url: &str,
    amount_sat: u64,
) -> Result<CashuSentPayment> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .send_payment_token(mint_url, amount_sat)
        .await
}

impl CashuWalletService {
    pub async fn send_payment_token(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<CashuSentPayment> {
        self.send_payment_token_with_keyset(mint_url, amount_sat, None)
            .await
    }

    pub(crate) async fn send_payment_token_for_keyset(
        &self,
        mint_url: &str,
        amount_sat: u64,
        keyset_id: Id,
    ) -> Result<CashuSentPayment> {
        self.send_payment_token_with_keyset(mint_url, amount_sat, Some(keyset_id))
            .await
    }

    async fn send_payment_token_with_keyset(
        &self,
        mint_url: &str,
        amount_sat: u64,
        required_keyset_id: Option<Id>,
    ) -> Result<CashuSentPayment> {
        if amount_sat == 0 {
            bail!("Cashu payment amount must be greater than zero");
        }

        let _guard = self.lock_operation().await;
        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;

        wallet
            .recover_incomplete_sagas()
            .await
            .context("Failed to recover Cashu wallet state before sending payment")?;

        let available_sat = wallet.total_balance().await?.to_u64();
        if available_sat < amount_sat {
            return Err(CashuInsufficientFunds {
                available_sat,
                required_sat: amount_sat,
            }
            .into());
        }

        if let Some(required_keyset_id) = required_keyset_id {
            // The Spilman keyset was fetched directly from the mint immediately
            // before this call. Refresh the wallet metadata too: a cached active
            // keyset can legitimately predate a mint rotation and must not block
            // consolidation of old proofs into the selected current keyset.
            let active_keyset_id = refresh_active_keyset_id(&wallet)
                .await
                .context("Failed to refresh the active Cashu keyset")?;
            if active_keyset_id != required_keyset_id {
                bail!(
                    "Cashu mint active keyset changed from {required_keyset_id} to {active_keyset_id}"
                );
            }

            let available_proofs = wallet
                .get_proofs_with(Some(vec![State::Unspent]), None)
                .await
                .context("Failed to load Cashu proofs before payment")?;
            if proofs_require_keyset_consolidation(&available_proofs, required_keyset_id) {
                wallet
                    .swap(
                        None,
                        SplitTarget::None,
                        available_proofs,
                        None,
                        false,
                        false,
                    )
                    .await
                    .context("Failed to consolidate Cashu proofs into the active keyset")?;
            }
        }

        let available_sat = wallet.total_balance().await?.to_u64();
        let (prepared, send_fee_sat) =
            prepare_payment_token(&wallet, amount_sat, available_sat).await?;
        if let Some(required_keyset_id) = required_keyset_id {
            if proofs_require_keyset_consolidation(&prepared.proofs(), required_keyset_id) {
                prepared
                    .cancel()
                    .await
                    .context("Failed to release mixed-keyset Cashu payment proofs")?;
                bail!("Cashu payment proofs are not all from keyset {required_keyset_id}");
            }
        }
        let operation_id = prepared.operation_id().to_string();
        let token = prepared
            .confirm(None)
            .await
            .context("Failed to create Cashu payment token")?;

        let payment = CashuSentPayment {
            mint_url: normalized_mint,
            unit: CurrencyUnit::Sat.to_string(),
            amount_sat,
            send_fee_sat,
            operation_id,
            token: token.to_string(),
        };

        append_wallet_activity_entry(
            self.localstore().as_ref(),
            CashuWalletActivityEntry {
                id: wallet_activity_id(),
                kind: CashuWalletActivityKind::TokenSend,
                status: CashuWalletActivityStatus::Pending,
                mint_url: payment.mint_url.clone(),
                unit: payment.unit.clone(),
                amount_sat: payment.amount_sat,
                fee_sat: Some(payment.send_fee_sat),
                created_at_unix: wallet_activity_now_unix(),
                expires_at_unix: None,
                quote_id: None,
                operation_id: Some(payment.operation_id.clone()),
                payment_request: None,
                token: Some(payment.token.clone()),
            },
        )
        .await
        .context("Failed to record Cashu token activity")?;

        Ok(payment)
    }
}

pub(super) async fn refresh_active_keyset_id(wallet: &cdk::Wallet) -> Result<Id> {
    // CDK 0.18 keysets(Refresh) silently falls back to cached metadata on
    // network errors. Funding needs a successful refresh of all mint metadata;
    // fetch_mint_info propagates those errors and updates the same keyset cache.
    wallet
        .fetch_mint_info()
        .await
        .context("Failed to refresh Cashu mint keysets")?;
    wallet
        .active_keyset_with_policy(cdk::wallet::types::KeysetLoadPolicy::CacheOnly)
        .await
        .map(|keyset| keyset.id)
        .context("Refreshed Cashu mint has no active keyset for the wallet unit")
}

pub(super) fn proofs_require_keyset_consolidation(
    proofs: &[Proof],
    required_keyset_id: Id,
) -> bool {
    proofs
        .iter()
        .any(|proof| proof.keyset_id != required_keyset_id)
}

/// CDK's include_fee estimate can describe an optimal split rather than the
/// proofs its partial-swap path actually returns. Check that exact final split
/// before confirming; adjusting a reservation never spends or reclaims tokens.
pub(super) async fn prepare_payment_token(
    wallet: &cdk::wallet::Wallet,
    amount_sat: u64,
    available_sat: u64,
) -> Result<(cdk::wallet::PreparedSend<'_>, u64)> {
    let mut requested = amount_sat;
    loop {
        let prepared = wallet
            .prepare_send(
                Amount::from(requested),
                SendOptions {
                    include_fee: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| {
                if matches!(error, cdk::Error::InsufficientFunds) {
                    anyhow::Error::new(CashuInsufficientFunds {
                        available_sat,
                        required_sat: requested.max(available_sat.saturating_add(1)),
                    })
                } else {
                    anyhow::Error::new(error)
                }
            })
            .context("Failed to prepare Cashu payment token")?;
        let estimate = async {
            let mut counts = std::collections::HashMap::new();
            let mut nominal = 0_u64;
            for proof in prepared.proofs_to_send() {
                *counts.entry(proof.keyset_id).or_insert(0_u64) += 1;
                nominal += proof.amount.to_u64();
            }
            if !prepared.proofs_to_swap().is_empty() {
                let keyset = wallet.get_active_keyset().await?.id;
                let fees_and_amounts = wallet.get_keyset_fees_and_amounts_by_id(keyset).await?;
                let swap_amount = requested
                    .saturating_add(prepared.send_fee().to_u64())
                    .saturating_sub(nominal);
                *counts.entry(keyset).or_insert(0) +=
                    Amount::from(swap_amount).split(&fees_and_amounts)?.len() as u64;
                nominal += swap_amount;
            }
            let recipient_fee = wallet.get_proofs_fee_by_count(counts).await?.total.to_u64();
            Ok::<_, anyhow::Error>((nominal, recipient_fee))
        }
        .await;
        let (nominal, recipient_fee) = match estimate {
            Ok(value) => value,
            Err(error) => {
                prepared
                    .cancel()
                    .await
                    .context("Failed to release Cashu payment reservation")?;
                return Err(error);
            }
        };
        let spendable = nominal.saturating_sub(recipient_fee);
        if spendable >= amount_sat {
            return Ok((prepared, recipient_fee));
        }
        prepared
            .cancel()
            .await
            .context("Failed to release underfunded Cashu payment reservation")?;
        requested = requested
            .checked_add(amount_sat - spendable)
            .context("Cashu payment fee overflow")?;
        if requested > available_sat {
            return Err(CashuInsufficientFunds {
                available_sat,
                required_sat: requested,
            }
            .into());
        }
    }
}
