use super::*;
use cdk::amount::SplitTarget;
use cdk::wallet::Wallet;

const POLL_INTERVAL_SECS: u64 = 15;
const EXPIRED_QUOTE_INTERVAL_SECS: u64 = 24 * 3600;

#[derive(Default, Serialize, Deserialize)]
struct MintPoll {
    next_poll_unix: u64,
    failures: u32,
    quote_checks: HashMap<String, u64>,
}

impl CashuWalletService {
    // The operation lock and database belong to the service. Persist admission
    // before I/O so CLI invocations, restarts and cancelled requests share it.
    pub(super) async fn refresh_pending_wallet(
        &self,
        wallet: &Wallet,
    ) -> Result<CashuWalletStartupRecoveryReport> {
        let mut polls: HashMap<String, MintPoll> = self
            .localstore()
            .kv_read("nvpn_wallet", "", "mint_polls")
            .await?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?
            .unwrap_or_default();
        let key = format!("{} {}", wallet.mint_url, wallet.unit);
        let poll = polls.entry(key.clone()).or_default();
        let now = wallet_activity_now_unix();
        let mut report = CashuWalletStartupRecoveryReport::default();
        if now < poll.next_poll_unix {
            return Ok(report);
        }
        poll.next_poll_unix = now.saturating_add(POLL_INTERVAL_SECS + 1);
        self.localstore()
            .kv_write(
                "nvpn_wallet",
                "",
                "mint_polls",
                &serde_json::to_vec(&polls)?,
            )
            .await?;

        let poll = polls.get_mut(&key).expect("poll was inserted");
        let result: Result<()> = async {
            report.finalized_melts = wallet.finalize_pending_melts().await?.len();
            let recovery = self.recover_wallet_sagas(wallet).await?;
            if recovery.skipped > 0 { report.warnings.push("A reviewed payment is awaiting confirmation; its original reservation was preserved".into()); }
            report.recovered_sagas = recovery.recovered;
            report.compensated_sagas = recovery.compensated;
            report.pending_sagas = recovery.skipped;
            report.failed_sagas = recovery.failed;
            anyhow::ensure!(
                recovery.failed == 0,
                "Cashu wallet recovery has pending failures"
            );

            let quotes = wallet.get_unissued_mint_quotes().await?;
            poll.quote_checks
                .retain(|id, _| quotes.iter().any(|quote| quote.id == *id));
            // One quote per wallet per pass; a backlog of abandoned invoices must
            // not turn one refresh into a burst. Live invoices take priority.
            let quote = quotes
                .iter()
                .filter(|quote| poll.quote_checks.get(&quote.id).copied().unwrap_or(0) <= now)
                .min_by_key(|quote| {
                    (
                        quote.expiry > 0 && quote.expiry <= now,
                        poll.quote_checks.get(&quote.id).copied().unwrap_or(0),
                        &quote.id,
                    )
                });
            if let Some(quote) = quote {
                // Unlike mint_unissued_quotes, this propagates a failed status
                // check instead of swallowing it and continuing through all quotes.
                let refreshed = wallet.check_mint_quote_status(&quote.id).await?;
                if refreshed.amount_mintable() > Amount::ZERO {
                    let proofs = wallet.mint(&quote.id, SplitTarget::default(), None).await?;
                    report.minted_amount = proofs.iter().map(|proof| proof.amount.to_u64()).sum();
                }
                let delay = if refreshed.expiry > 0 && refreshed.expiry <= now {
                    EXPIRED_QUOTE_INTERVAL_SECS
                } else {
                    POLL_INTERVAL_SECS
                };
                poll.quote_checks
                    .insert(quote.id.clone(), now.saturating_add(delay + 1));
            }
            Ok(())
        }
        .await;

        let completed = wallet_activity_now_unix();
        if let Err(error) = result {
            poll.failures = poll.failures.saturating_add(1);
            let mut delay = (60_u64 << poll.failures.saturating_sub(1).min(6)).min(3600);
            if matches!(
                error.downcast_ref::<cdk::Error>(),
                Some(cdk::Error::HttpError(Some(403 | 429), _))
            ) {
                delay = delay.max(15 * 60);
            }
            poll.next_poll_unix = completed.saturating_add(delay + 1);
            report.warnings.push(format!(
                "Failed to refresh Cashu wallet {} ({}): {error:#}",
                wallet.mint_url, wallet.unit
            ));
        } else {
            poll.failures = 0;
            poll.next_poll_unix = completed.saturating_add(POLL_INTERVAL_SECS + 1);
        }
        self.localstore()
            .kv_write(
                "nvpn_wallet",
                "",
                "mint_polls",
                &serde_json::to_vec(&polls)?,
            )
            .await?;
        Ok(report)
    }
}
