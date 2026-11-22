//! Local receiving-wallet connection and operator-approved periodic cash out.
use super::*;
use peer_payments::redemption::ClnWallet;
use std::{os::unix::fs::FileTypeExt, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectedWallet {
    pub rpc_socket: PathBuf,
    pub network: String,
    pub node_id: String,
}
/// Only probe the selected socket or conventional, local Lightning directories.
/// Ambiguous networks/wallets require an explicit selection.
pub fn detect_wallet(path: Option<&Path>) -> Result<ConnectedWallet, String> {
    let selected = path
        .map(Path::to_owned)
        .or_else(|| std::env::var_os("LIGHTNING_RPC").map(PathBuf::from));
    let paths = if let Some(path) = selected {
        vec![path]
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("choose the local Lightning RPC socket")?;
        let base = std::env::var_os("LIGHTNING_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".lightning"));
        ["bitcoin", "signet", "testnet", "regtest"]
            .map(|n| base.join(n).join("lightning-rpc"))
            .into_iter()
            .collect()
    };
    let mut sockets: Vec<_> = paths
        .into_iter()
        .filter(|p| {
            p.is_absolute() && std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
        })
        .collect();
    if sockets.len() > 1 {
        return Err("multiple local Lightning sockets found; choose a receiving wallet".into());
    }
    let rpc_socket = sockets
        .pop()
        .ok_or("choose a running node’s local Lightning RPC socket")?;
    let (network, node_id) = ClnWallet::new(&rpc_socket).node_info().map_err(err)?;
    Ok(ConnectedWallet {
        rpc_socket,
        network,
        node_id,
    })
}

impl CreditLink {
    /// Resume an already approved own-wallet payment before starting another.
    /// A wallet-issued label scoped to account and time window also survives a
    /// restart between local invoice creation and reserving the signed debt.
    pub async fn auto_cashout_once(
        &self,
        rpc: &Path,
        policy: &AutoCashout,
    ) -> Result<Option<PaymentState>, String> {
        policy.validate()?;
        let (pending, available) = {
            let store = self.store.try_lock().map_err(|_| "credit account busy")?;
            let a = store.book();
            (
                a.pending_cashouts().next().map(|r| r.payment_hash.clone()),
                a.available_claims().map(|(_, v)| v).max().unwrap_or(0),
            )
        };
        if let Some(hash) = pending {
            return self.resume_cashout(&hash, rpc).await.map(Some);
        }
        if available < policy.min_sat {
            return Ok(None);
        }
        // A ceiling is not a charge. A small claim can still buy the minimum
        // payout when an actual quoted fee fits below the user's maximum.
        let amount = policy.max_sat.min(
            available
                .saturating_sub(policy.max_fee_sat)
                .max(policy.min_sat),
        );
        let time = now()?;
        let q = Query {
            nonce: rand::random(),
            agreement_id: String::new(),
            amount_sat: amount,
            max_fee_sat: policy.max_fee_sat,
            hops: MAX_HOPS,
            probes: BUDGET,
        };
        let (debtor, agreement_id, fee_sat) = self.find(&q, "").await?;
        let owner = self.key.x_only_public_key().0;
        let label = format!("peer-credit/auto/{owner}/{}", time / policy.interval_secs);
        let path = rpc.to_owned();
        let invoice = match tokio::task::spawn_blocking(move || {
            ClnWallet::new(path).receiving_invoice(&label, amount, time)
        })
        .await
        .map_err(err)?
        {
            Ok(invoice) => invoice,
            // This interval's label has already been used or a different amount
            // was approved before a restart. Wait for the next interval.
            Err(peer_payments::Error::Conflict) => return Ok(None),
            Err(error) => return Err(err(error)),
        };
        let (actual, payment_hash) =
            peer_payments::redemption::invoice_terms(&invoice, now()?).map_err(err)?;
        if actual != amount {
            return Err("receiving wallet returned a different amount".into());
        }
        let quote = InvoiceQuote {
            amount_sat: amount,
            fee_sat,
            debtor,
            agreement_id,
            payment_hash,
            expires_at: time + 30,
        };
        self.confirm_with_wallet(&invoice, &quote, Some(rpc.to_owned()), policy.max_fee_sat)
            .await
            .map(Some)
    }
    pub fn start_auto_cashout(
        self: &Arc<Self>,
        receive_rpc: PathBuf,
        policy: AutoCashout,
    ) -> Result<tokio::task::JoinHandle<()>, String> {
        policy.validate()?;
        if !receive_rpc.is_absolute() {
            return Err("choose an absolute receiving wallet socket".into());
        }
        let weak = Arc::downgrade(self);
        Ok(tokio::spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_secs(policy.interval_secs));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let Some(link) = weak.upgrade() else { break };
                // Transient disconnection leaves signed requests in the journal.
                // The next tick resumes them on the same wallet and agreement.
                let _ = link.auto_cashout_once(&receive_rpc, &policy).await;
            }
        }))
    }
}
