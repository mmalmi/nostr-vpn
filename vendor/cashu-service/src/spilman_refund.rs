//! Buyer-side recovery for settled Cashu Spilman channels.

use std::{collections::HashMap, path::Path};

use cashu::nuts::{Proof, SecretKey};
use cdk_spilman::ClientStorage;
use serde::{Deserialize, Serialize};

use crate::{
    fetch_spilman_keyset_info_json, load_or_create_cashu_spilman_sender_key,
    require_lock_for_data_dir, spilman_client_store_path, FileSpilmanClientStorage,
    SharedSpilmanClientStoreLock,
};

#[derive(Debug, Clone)]
struct HttpSpilmanMintConnection {
    client: reqwest::Client,
    mint_url: String,
}

impl HttpSpilmanMintConnection {
    fn new(mint_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            mint_url: mint_url.trim_end_matches('/').to_string(),
        }
    }

    async fn post_json<T, R>(&self, path: &str, request: &T) -> anyhow::Result<R>
    where
        T: Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(format!("{}{path}", self.mint_url))
            .json(request)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            anyhow::bail!("Cashu mint request to {path} failed with {status}: {body}");
        }
        serde_json::from_str(&body).map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl cdk_spilman::MintConnection for HttpSpilmanMintConnection {
    async fn process_swap(
        &self,
        request: cashu::nuts::SwapRequest,
    ) -> anyhow::Result<cashu::nuts::SwapResponse> {
        self.post_json("/v1/swap", &request).await
    }

    async fn post_restore(
        &self,
        request: cashu::nuts::RestoreRequest,
    ) -> anyhow::Result<cashu::nuts::RestoreResponse> {
        self.post_json("/v1/restore", &request).await
    }

    async fn check_state(
        &self,
        ys: Vec<cashu::nuts::PublicKey>,
    ) -> anyhow::Result<cashu::nuts::CheckStateResponse> {
        self.post_json("/v1/checkstate", &cashu::nuts::CheckStateRequest { ys })
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteRestoreCashuSpilmanRefundResult {
    pub channel_id: String,
    pub mint_url: String,
    pub unit: String,
    pub complete: bool,
    pub recovered_amount_sat: u64,
    pub imported_amount_sat: u64,
    pub proof_count: usize,
}

pub fn sign_restored_sender_proofs(
    params: &cdk_spilman::ChannelParameters,
    sender_secret: &SecretKey,
    proofs: &mut [Proof],
) -> anyhow::Result<()> {
    let mut next_index_by_amount = HashMap::<u64, usize>::new();
    for proof in proofs {
        let amount = u64::from(proof.amount);
        let index = next_index_by_amount.entry(amount).or_default();
        let signing_key = params.get_sender_blinded_secret_key_for_stage2_output(
            sender_secret,
            amount,
            *index,
        )?;
        proof.sign_p2pk(signing_key)?;
        proof
            .verify_p2pk()
            .map_err(|error| anyhow::anyhow!(error))?;
        *index += 1;
    }
    Ok(())
}

pub async fn restore_streaming_route_cashu_spilman_refund(
    data_dir: &Path,
    channel_id: &str,
) -> anyhow::Result<StreamingRouteRestoreCashuSpilmanRefundResult> {
    let lock = SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(data_dir))
        .map_err(|error| anyhow::anyhow!(error))?;
    restore_streaming_route_cashu_spilman_refund_with_lock(data_dir, channel_id, lock).await
}

pub async fn restore_streaming_route_cashu_spilman_refund_with_lock(
    data_dir: &Path,
    channel_id: &str,
    lock: SharedSpilmanClientStoreLock,
) -> anyhow::Result<StreamingRouteRestoreCashuSpilmanRefundResult> {
    let channel_id = channel_id.trim();
    if channel_id.is_empty() {
        anyhow::bail!("missing Cashu Spilman channel id");
    }
    let lock = require_lock_for_data_dir(data_dir, lock).map_err(|error| anyhow::anyhow!(error))?;
    let (mut storage, storage_errors) =
        FileSpilmanClientStorage::load_with_lock(lock).map_err(|error| anyhow::anyhow!(error))?;
    let funding = storage
        .get_funding(channel_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Cashu Spilman channel not found: {channel_id}"))?;
    let unit = serde_json::from_str::<serde_json::Value>(&funding.params_json)?
        .get("unit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("sat")
        .to_string();
    if storage.get_state(channel_id) == cdk_spilman::ClientChannelState::Closed
        && storage.refund_witnesses_persisted(channel_id)
    {
        return Ok(complete_result(channel_id, funding.mint_url, unit, 0, 0, 0));
    }

    let original_keyset = cdk_spilman::parse_keyset_info_from_json(&funding.keyset_info_json)
        .map_err(|error| anyhow::anyhow!(error))?;
    let channel_secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Cashu Spilman channel secret length"))?;
    let params = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
        &funding.params_json,
        original_keyset,
        channel_secret,
    )?;
    let funding_proofs: Vec<Proof> = serde_json::from_str(&funding.funding_proofs_json)?;
    let channel = cdk_spilman::EstablishedChannel::new(params, funding_proofs)?;
    let sender_key = load_or_create_cashu_spilman_sender_key(data_dir)
        .map_err(|error| anyhow::anyhow!(error))?;
    if sender_key.public_key_hex != funding.sender_pubkey_hex {
        anyhow::bail!("Cashu Spilman channel sender key does not match local wallet key");
    }
    let sender_secret = SecretKey::from_hex(&sender_key.secret_hex)?;
    let output_keyset_json = fetch_spilman_keyset_info_json(&funding.mint_url, &unit, None)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    let output_keyset = cdk_spilman::parse_keyset_info_from_json(&output_keyset_json)
        .map_err(|error| anyhow::anyhow!(error))?;
    let mint = HttpSpilmanMintConnection::new(&funding.mint_url);
    let funding_state = channel.check_funding_token_state(&mint).await?;
    if funding_state.state != cashu::nuts::State::Spent {
        return Ok(StreamingRouteRestoreCashuSpilmanRefundResult {
            channel_id: channel_id.to_string(),
            mint_url: funding.mint_url,
            unit,
            complete: false,
            recovered_amount_sat: 0,
            imported_amount_sat: 0,
            proof_count: 0,
        });
    }

    let sender = cdk_spilman::SpilmanChannelSender::new(sender_secret, channel);
    let mut proofs = sender
        .restore_sender_proofs_with_keyset(&mint, &output_keyset)
        .await?;
    sign_restored_sender_proofs(&sender.channel.params, &sender.alice_secret, &mut proofs)?;
    let recovered_amount_sat = proofs
        .iter()
        .map(|proof| u64::from(proof.amount))
        .sum::<u64>();
    let proof_count = proofs.len();
    let imported_amount_sat = if proofs.is_empty() {
        0
    } else {
        let proofs_json = serde_json::to_string(&proofs)?;
        crate::import_payment_proofs(data_dir, &funding.mint_url, &unit, &proofs_json)
            .await?
            .amount_sat
    };
    storage.set_closed(channel_id);
    storage.mark_refund_witnesses_persisted(channel_id);
    storage_errors
        .ensure_ok()
        .map_err(|error| anyhow::anyhow!(error))?;

    Ok(complete_result(
        channel_id,
        funding.mint_url,
        unit,
        recovered_amount_sat,
        imported_amount_sat,
        proof_count,
    ))
}

fn complete_result(
    channel_id: &str,
    mint_url: String,
    unit: String,
    recovered_amount_sat: u64,
    imported_amount_sat: u64,
    proof_count: usize,
) -> StreamingRouteRestoreCashuSpilmanRefundResult {
    StreamingRouteRestoreCashuSpilmanRefundResult {
        channel_id: channel_id.to_string(),
        mint_url,
        unit,
        complete: true,
        recovered_amount_sat,
        imported_amount_sat,
        proof_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::{
        nuts::{CurrencyUnit, Id, Keys},
        Amount,
    };
    use std::collections::BTreeMap;

    fn test_funding() -> cdk_spilman::ClientChannelFunding {
        cdk_spilman::ClientChannelFunding {
            params_json: r#"{"capacity":100}"#.to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".repeat(32),
            keyset_info_json: "{}".to_string(),
            sender_pubkey_hex: format!("02{}", "bb".repeat(32)),
            capacity: 100,
            funding_token_amount: 100,
            mint_url: "https://mint.example".to_string(),
            created_at: 123,
        }
    }

    #[tokio::test]
    async fn refund_restore_rejects_unknown_channel_before_networking() {
        let temp = tempfile::tempdir().unwrap();
        let error = restore_streaming_route_cashu_spilman_refund(temp.path(), "missing-channel")
            .await
            .expect_err("an unknown channel should fail before contacting a mint");

        assert!(error
            .to_string()
            .contains("Cashu Spilman channel not found: missing-channel"));
    }

    #[tokio::test]
    async fn completed_refund_restore_does_not_contact_the_mint_again() {
        let temp = tempfile::tempdir().unwrap();
        let (mut storage, errors) =
            FileSpilmanClientStorage::load(spilman_client_store_path(temp.path())).unwrap();
        storage.save_funding("channel-1", test_funding());
        storage.set_closed("channel-1");
        storage.mark_refund_witnesses_persisted("channel-1");
        errors.ensure_ok().unwrap();
        drop(storage);

        let result = restore_streaming_route_cashu_spilman_refund(temp.path(), "channel-1")
            .await
            .expect("a recovered channel should complete without networking");

        assert!(result.complete);
        assert_eq!(result.recovered_amount_sat, 0);
        assert_eq!(result.imported_amount_sat, 0);
        assert_eq!(result.proof_count, 0);
    }

    #[test]
    fn restored_sender_refunds_are_signed_for_generic_wallet_spending() {
        let alice_secret = SecretKey::generate();
        let charlie_secret = SecretKey::generate();
        let mut keys = BTreeMap::new();
        for amount in [1_u64, 2, 4, 8, 16] {
            keys.insert(Amount::from(amount), SecretKey::generate().public_key());
        }
        let keys = Keys::new(keys);
        let keyset_id = Id::v1_from_keys(&keys);
        let keyset = cdk_spilman::KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keys, 0, None);
        let funding_token_amount =
            cdk_spilman::ChannelParameters::get_minimum_funding_token_amount(8, &keyset, 0)
                .unwrap();
        let params = cdk_spilman::ChannelParameters::new_with_secret_key(
            alice_secret.public_key(),
            charlie_secret.public_key(),
            "https://mint.example".to_string(),
            CurrencyUnit::Sat,
            8,
            funding_token_amount,
            1_000,
            1,
            keyset,
            0,
            &alice_secret,
        )
        .unwrap();
        let deterministic = params
            .create_deterministic_output_with_blinding("sender", 2, 0)
            .unwrap();
        let mut proofs = vec![Proof::new(
            Amount::from(2_u64),
            keyset_id,
            deterministic.secret,
            SecretKey::generate().public_key(),
        )];

        sign_restored_sender_proofs(&params, &alice_secret, &mut proofs).unwrap();

        assert!(proofs[0].witness.is_some());
        proofs[0].verify_p2pk().unwrap();
    }
}
