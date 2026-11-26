use super::*;
use crate::spilman_client::{ExpiryRefund, ExpiryRefundOutput};
use anyhow::{ensure, Context};
use cashu::{
    dhke,
    nuts::{BlindSignature, BlindedMessage, RestoreRequest, State, SwapRequest},
    secret::Secret,
    Amount,
};
use cdk_spilman::{EstablishedChannel, MintConnection, OrderedListOfAmounts};

/// Check every funding input and its identity before choosing a refund path.
pub(super) async fn funding_state<M: MintConnection>(
    channel: &EstablishedChannel,
    mint: &M,
) -> anyhow::Result<State> {
    let ys = channel
        .funding_proofs
        .iter()
        .map(Proof::y)
        .collect::<Result<Vec<_>, _>>()?;
    let response = mint.check_state(ys.clone()).await?;
    ensure!(
        !ys.is_empty() && response.states.len() == ys.len(),
        "incomplete funding state response"
    );
    let mut states = Vec::with_capacity(ys.len());
    for y in ys {
        let matches = response
            .states
            .iter()
            .filter(|entry| entry.y == y)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "funding state response does not match requested proofs"
        );
        states.push(matches[0].state);
    }
    Ok(if states.iter().all(|state| *state == State::Unspent) {
        State::Unspent
    } else if states.iter().all(|state| *state == State::Spent) {
        State::Spent
    } else {
        // A pending or mixed response must never trigger another spend.
        State::Pending
    })
}

/// `Unexpired` carries the funding expiry so callers can wait out the
/// finished-but-unexpired window instead of rechecking the mint every minute.
pub(super) enum ExpiredFundingRecovery {
    Recovered(Vec<Proof>),
    Unexpired(u64),
    Unavailable,
}

pub(super) async fn recover_expired_funding<M: MintConnection>(
    data_dir: &Path,
    saved_refund: Option<ExpiryRefund>,
    channel_id: &str,
    channel: &EstablishedChannel,
    sender_secret: &SecretKey,
    mint: &M,
    client: &reqwest::Client,
    state: State,
) -> anyhow::Result<ExpiredFundingRecovery> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if now <= channel.params.expiry_timestamp {
        return Ok(if state == State::Unspent {
            ExpiredFundingRecovery::Unexpired(channel.params.expiry_timestamp)
        } else {
            ExpiredFundingRecovery::Unavailable
        });
    }
    if state == State::Pending {
        return Ok(ExpiredFundingRecovery::Unavailable);
    }
    let refund = match saved_refund {
        Some(refund) => refund,
        None if state == State::Spent => {
            return Ok(ExpiredFundingRecovery::Unavailable); // Seller settled first.
        }
        None => {
            let keyset_json = fetch_spilman_keyset_info_json_with_client(
                client,
                &channel.params.mint,
                &channel.params.unit.to_string(),
                None,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            let keyset = cdk_spilman::parse_keyset_info_from_json(&keyset_json)
                .map_err(anyhow::Error::msg)?;
            let input_amount = channel
                .funding_proofs
                .iter()
                .try_fold(0_u64, |sum, proof| sum.checked_add(u64::from(proof.amount)))
                .context("funding amount overflow")?;
            let fee = (channel.funding_proofs.len() as u64)
                .checked_mul(channel.params.keyset_info.input_fee_ppk)
                .context("funding fee overflow")?
                .div_ceil(1000);
            let amount = input_amount
                .checked_sub(fee)
                .filter(|amount| *amount > 0)
                .context("expired funding cannot cover the mint input fee")?;
            let amounts = OrderedListOfAmounts::from_target(amount, 0, &keyset)?;
            let mut outputs = Vec::new();
            for (amount, count) in amounts.count_by_amount {
                for _ in 0..count {
                    outputs.push(ExpiryRefundOutput {
                        amount,
                        secret: Secret::generate().to_string(),
                        blinding_factor: SecretKey::generate().to_secret_hex(),
                    });
                }
            }
            let refund = ExpiryRefund { keyset, outputs };
            // Recheck under a short lock so concurrent recovery uses the same
            // durable outputs. Never hold this lock during mint or wallet I/O.
            let (mut storage, _) =
                FileSpilmanClientStorage::try_load(spilman_client_store_path(data_dir))
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| {
                        CashuSpilmanRefundDeferred("Cashu refund waiting for channel store".into())
                    })?;
            if let Some(saved) = storage.expiry_refund(channel_id) {
                saved.clone()
            } else {
                storage
                    .save_expiry_refund(channel_id, refund.clone())
                    .map_err(anyhow::Error::msg)?;
                refund
            }
        }
    };
    let outputs = refund
        .outputs
        .iter()
        .map(|output| {
            let secret = Secret::new(output.secret.clone());
            let (blinded, _) = dhke::blind_message(
                secret.as_bytes(),
                Some(SecretKey::from_hex(&output.blinding_factor)?),
            )?;
            Ok(BlindedMessage::new(
                Amount::from(output.amount),
                refund.keyset.keyset_id,
                blinded,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let signatures = if state == State::Unspent {
        let mut request = SwapRequest::new(channel.funding_proofs.clone(), outputs.clone());
        request.sign_sig_all(
            channel
                .params
                .get_sender_blinded_secret_key_for_stage1_refund(sender_secret)?,
        )?;
        mint.process_swap(request).await?.signatures
    } else {
        let response = mint
            .post_restore(RestoreRequest {
                outputs: outputs.clone(),
            })
            .await?;
        ensure!(
            response.outputs.len() == response.signatures.len(),
            "invalid expiry refund restore counts"
        );
        if response.outputs.is_empty() {
            // A seller may have won the race after we persisted our intent.
            return Ok(ExpiredFundingRecovery::Unavailable);
        }
        ensure!(
            response.outputs.len() == outputs.len(),
            "incomplete expiry refund restore"
        );
        let mut issued = response
            .outputs
            .into_iter()
            .zip(response.signatures)
            .collect::<Vec<_>>();
        let mut signatures = Vec::with_capacity(outputs.len());
        for output in &outputs {
            let index = issued
                .iter()
                .position(|(saved, _)| saved == output)
                .context("expiry refund restore returned an unexpected output")?;
            signatures.push(issued.swap_remove(index).1);
        }
        signatures
    };
    unblind_refund(&refund, &outputs, signatures).map(ExpiredFundingRecovery::Recovered)
}

fn unblind_refund(
    refund: &ExpiryRefund,
    outputs: &[BlindedMessage],
    signatures: Vec<BlindSignature>,
) -> anyhow::Result<Vec<Proof>> {
    ensure!(
        signatures.len() == outputs.len(),
        "invalid expiry refund signature count"
    );
    for (signature, output) in signatures.iter().zip(outputs) {
        ensure!(
            signature.amount == output.amount && signature.keyset_id == output.keyset_id,
            "expiry refund signature does not match requested amount/keyset"
        );
        if signature.dleq.is_some() {
            let key = refund
                .keyset
                .active_keys
                .amount_key(signature.amount)
                .context("missing expiry refund mint key")?;
            signature.verify_dleq(key, output.blinded_secret)?;
        }
    }
    dhke::construct_proofs(
        signatures,
        refund
            .outputs
            .iter()
            .map(|output| SecretKey::from_hex(&output.blinding_factor))
            .collect::<Result<Vec<_>, _>>()?,
        refund
            .outputs
            .iter()
            .map(|output| Secret::new(output.secret.clone()))
            .collect(),
        &refund.keyset.active_keys,
    )
    .map_err(Into::into)
}
