use super::*;
use cdk::nuts::CheckStateRequest;
use std::collections::HashSet;

// Run under the service's operation lock after durable saga recovery. Exported
// tokens use PendingSpent, and active operations retain used_by_operation.
pub(super) async fn recover_orphaned_reservations(wallet: &cdk::Wallet) -> Result<u64> {
    let mut proofs = wallet
        .localstore
        .get_proofs(
            Some(wallet.mint_url.clone()),
            Some(wallet.unit.clone()),
            Some(vec![State::Reserved]),
            None,
        )
        .await?
        .into_iter()
        .filter(|proof| proof.used_by_operation.is_none() && !is_legacy_refund(&proof.proof))
        .collect::<Vec<_>>();
    if proofs.is_empty() {
        return Ok(0);
    }

    // Use the connector directly: CDK's check_proofs_spent mutates storage
    // before callers can reject missing, duplicate or unrelated response Ys.
    let states = wallet
        .mint_connector()
        .post_check_state(CheckStateRequest {
            ys: proofs.iter().map(|proof| proof.y).collect(),
        })
        .await
        .context("Failed to check abandoned Cashu reservations with the mint")?
        .states;
    let expected: HashSet<_> = proofs.iter().map(|proof| proof.y).collect();
    let mut by_y = HashMap::new();
    for state in states {
        anyhow::ensure!(
            expected.contains(&state.y),
            "Mint returned an unrelated proof state"
        );
        anyhow::ensure!(
            matches!(state.state, State::Unspent | State::Pending | State::Spent),
            "Mint returned an invalid proof state"
        );
        anyhow::ensure!(
            by_y.insert(state.y, state.state).is_none(),
            "Mint returned duplicate proof states"
        );
    }
    anyhow::ensure!(
        by_y.len() == expected.len(),
        "Mint omitted requested proof states"
    );

    let mut recovered = 0_u64;
    proofs.retain_mut(|proof| match by_y[&proof.y] {
        State::Unspent => {
            recovered = recovered.saturating_add(proof.proof.amount.to_u64());
            proof.state = State::Unspent;
            true
        }
        State::Spent => {
            // Retain the proof record for audit, but never return it to balance.
            proof.state = State::Spent;
            true
        }
        _ => false,
    });
    if !proofs.is_empty() {
        wallet
            .localstore
            .update_proofs(proofs, vec![])
            .await
            .context("Failed to persist recovered Cashu reservations")?;
    }
    Ok(recovered)
}
