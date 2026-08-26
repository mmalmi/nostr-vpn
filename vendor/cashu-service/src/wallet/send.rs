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

        let prepared = wallet
            .prepare_send(
                Amount::from(amount_sat),
                SendOptions {
                    include_fee: true,
                    ..Default::default()
                },
            )
            .await
            .context("Failed to prepare Cashu payment token")?;
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
        let send_fee_sat = prepared.send_fee().to_u64();
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
    wallet
        .refresh_keysets()
        .await
        .context("Failed to refresh Cashu mint keysets")?
        .into_iter()
        .min_by_key(|keyset| keyset.input_fee_ppk)
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
