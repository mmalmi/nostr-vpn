//! Buyer-side recovery for settled Cashu Spilman channels.

use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    path::Path,
};

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

async fn restore_sender_proofs_from_issued_keyset_with_resolver<M, R, F>(
    sender: &cdk_spilman::SpilmanChannelSender,
    mint: &M,
    requested_keyset: &cdk_spilman::KeysetInfo,
    fallback_keyset_ids: &[cashu::nuts::Id],
    mut resolve_keyset: R,
) -> anyhow::Result<Vec<Proof>>
where
    M: cdk_spilman::MintConnection + ?Sized,
    R: FnMut(cashu::nuts::Id) -> F,
    F: Future<Output = anyhow::Result<cdk_spilman::KeysetInfo>>,
{
    let mut candidates = vec![requested_keyset.keyset_id];
    candidates.extend_from_slice(fallback_keyset_ids);
    let mut seen_candidates = BTreeSet::new();
    candidates.retain(|keyset_id| seen_candidates.insert(*keyset_id));
    for candidate_id in candidates {
        let candidate = if candidate_id == requested_keyset.keyset_id {
            requested_keyset.clone()
        } else {
            resolve_keyset(candidate_id).await?
        };
        if candidate.keyset_id != candidate_id {
            anyhow::bail!(
                "resolved Cashu keyset {} instead of requested keyset {}",
                candidate.keyset_id,
                candidate_id
            );
        }
        let proofs = sender
            .restore_sender_proofs_with_keyset(mint, &candidate)
            .await?;
        if proofs.is_empty() {
            continue;
        }
        let issued_keysets = proofs
            .iter()
            .map(|proof| proof.keyset_id)
            .collect::<BTreeSet<_>>();
        if issued_keysets.len() != 1 {
            anyhow::bail!("Cashu restore returned proofs from multiple keysets");
        }
        let issued_keyset_id = *issued_keysets.iter().next().expect("one issued keyset");
        if issued_keyset_id == candidate_id {
            return Ok(proofs);
        }
        let issued_keyset = resolve_keyset(issued_keyset_id).await?;
        if issued_keyset.keyset_id != issued_keyset_id {
            anyhow::bail!(
                "resolved Cashu keyset {} instead of restored keyset {}",
                issued_keyset.keyset_id,
                issued_keyset_id
            );
        }
        let proofs = sender
            .restore_sender_proofs_with_keyset(mint, &issued_keyset)
            .await?;
        if proofs.is_empty() {
            anyhow::bail!(
                "Cashu restore reported keyset {issued_keyset_id} but returned no proofs when retried with that keyset"
            );
        }
        if proofs
            .iter()
            .any(|proof| proof.keyset_id != issued_keyset_id)
        {
            anyhow::bail!("Cashu restore response keyset changed while recovering channel refund");
        }
        return Ok(proofs);
    }
    Ok(Vec::new())
}

pub async fn restore_sender_proofs_from_issued_keyset<M>(
    sender: &cdk_spilman::SpilmanChannelSender,
    mint: &M,
    mint_url: &str,
    unit: &str,
    requested_keyset: &cdk_spilman::KeysetInfo,
) -> anyhow::Result<Vec<Proof>>
where
    M: cdk_spilman::MintConnection + ?Sized,
{
    let mint_url = mint_url.to_string();
    let unit = unit.to_string();
    let fallback_keyset_ids = crate::fetch_spilman_keyset_ids(&mint_url, &unit)
        .await
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .map(|keyset_id| keyset_id.parse())
        .collect::<Result<Vec<cashu::nuts::Id>, _>>()?;
    restore_sender_proofs_from_issued_keyset_with_resolver(
        sender,
        mint,
        requested_keyset,
        &fallback_keyset_ids,
        move |keyset_id| {
            let mint_url = mint_url.clone();
            let unit = unit.clone();
            async move {
                let keyset_id = keyset_id.to_string();
                let json =
                    fetch_spilman_keyset_info_json(&mint_url, &unit, Some(keyset_id.as_str()))
                        .await
                        .map_err(anyhow::Error::msg)?;
                cdk_spilman::parse_keyset_info_from_json(&json).map_err(anyhow::Error::msg)
            }
        },
    )
    .await
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
        && storage.refund_proofs_repaired(channel_id)
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
    let mut proofs = restore_sender_proofs_from_issued_keyset(
        &sender,
        &mint,
        &funding.mint_url,
        &unit,
        &output_keyset,
    )
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
    storage.mark_refund_proofs_validated(channel_id);
    storage.mark_refund_proofs_repaired(channel_id);
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
    use async_trait::async_trait;
    use cashu::{
        nuts::{
            BlindSignature, CheckStateResponse, CurrencyUnit, Id, Keys, RestoreRequest,
            RestoreResponse, SwapRequest, SwapResponse,
        },
        Amount,
    };
    use std::{collections::BTreeMap, sync::Mutex};

    struct RotatedRestoreMint {
        issued_keyset_id: Id,
        issued_secret: SecretKey,
        restorable_blinded_secret: cashu::nuts::PublicKey,
        require_issued_keyset_request: bool,
        requested_keysets: Mutex<Vec<Id>>,
    }

    #[async_trait]
    impl cdk_spilman::MintConnection for RotatedRestoreMint {
        async fn process_swap(&self, _request: SwapRequest) -> anyhow::Result<SwapResponse> {
            unreachable!("refund restore does not process swaps")
        }

        async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
            let output = request.outputs.first().expect("one restore output");
            self.requested_keysets
                .lock()
                .unwrap()
                .push(output.keyset_id);
            let signatures = if output.blinded_secret == self.restorable_blinded_secret
                && (!self.require_issued_keyset_request
                    || output.keyset_id == self.issued_keyset_id)
            {
                vec![BlindSignature {
                    amount: output.amount,
                    keyset_id: self.issued_keyset_id,
                    c: cashu::dhke::sign_message(&self.issued_secret, &output.blinded_secret)?,
                    dleq: None,
                }]
            } else {
                Vec::new()
            };
            Ok(RestoreResponse {
                outputs: request.outputs,
                signatures,
            })
        }

        async fn check_state(
            &self,
            _ys: Vec<cashu::nuts::PublicKey>,
        ) -> anyhow::Result<CheckStateResponse> {
            unreachable!("refund restore test does not check funding state")
        }
    }

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
        storage.mark_refund_proofs_validated("channel-1");
        storage.mark_refund_proofs_repaired("channel-1");
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

    #[tokio::test]
    async fn restored_refund_uses_the_keyset_that_actually_issued_the_signature() {
        let alice_secret = SecretKey::generate();
        let charlie_secret = SecretKey::generate();
        let issued_secret = SecretKey::generate();
        let active_secret = SecretKey::generate();
        let issued_keys = Keys::new(BTreeMap::from([(
            Amount::from(2_u64),
            issued_secret.public_key(),
        )]));
        let active_keys = Keys::new(BTreeMap::from([(
            Amount::from(2_u64),
            active_secret.public_key(),
        )]));
        let issued_keyset = cdk_spilman::KeysetInfo::new(
            Id::v1_from_keys(&issued_keys),
            CurrencyUnit::Sat,
            issued_keys,
            0,
            None,
        );
        let active_keyset = cdk_spilman::KeysetInfo::new(
            Id::v1_from_keys(&active_keys),
            CurrencyUnit::Sat,
            active_keys,
            0,
            None,
        );
        let params = cdk_spilman::ChannelParameters::new_with_secret_key(
            alice_secret.public_key(),
            charlie_secret.public_key(),
            "https://mint.example".to_string(),
            CurrencyUnit::Sat,
            2,
            2,
            1_000,
            1,
            issued_keyset.clone(),
            2,
            &alice_secret,
        )
        .unwrap();
        let restorable = params
            .create_deterministic_output_with_blinding("sender", 2, 0)
            .unwrap();
        let mint = RotatedRestoreMint {
            issued_keyset_id: issued_keyset.keyset_id,
            issued_secret: issued_secret.clone(),
            restorable_blinded_secret: restorable
                .to_blinded_message(Amount::from(2_u64), active_keyset.keyset_id)
                .unwrap()
                .blinded_secret,
            require_issued_keyset_request: false,
            requested_keysets: Mutex::new(Vec::new()),
        };
        let funding_proof = Proof::new(
            Amount::from(2_u64),
            issued_keyset.keyset_id,
            cashu::secret::Secret::generate(),
            SecretKey::generate().public_key(),
        );
        let channel = cdk_spilman::EstablishedChannel::new(params, vec![funding_proof]).unwrap();
        let sender = cdk_spilman::SpilmanChannelSender::new(alice_secret, channel);

        let proofs = restore_sender_proofs_from_issued_keyset_with_resolver(
            &sender,
            &mint,
            &active_keyset,
            &[issued_keyset.keyset_id],
            |keyset_id| {
                let issued_keyset = issued_keyset.clone();
                async move {
                    assert_eq!(keyset_id, issued_keyset.keyset_id);
                    Ok(issued_keyset)
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].keyset_id, issued_keyset.keyset_id);
        cashu::dhke::verify_message(&issued_secret, proofs[0].c, proofs[0].secret.as_bytes())
            .unwrap();
        let requested = mint.requested_keysets.lock().unwrap();
        assert!(requested.contains(&active_keyset.keyset_id));
        assert!(requested.contains(&issued_keyset.keyset_id));
    }

    #[tokio::test]
    async fn restored_refund_probes_inactive_keysets_when_active_restore_is_empty() {
        let alice_secret = SecretKey::generate();
        let charlie_secret = SecretKey::generate();
        let issued_secret = SecretKey::generate();
        let active_secret = SecretKey::generate();
        let issued_keys = Keys::new(BTreeMap::from([(
            Amount::from(2_u64),
            issued_secret.public_key(),
        )]));
        let active_keys = Keys::new(BTreeMap::from([(
            Amount::from(2_u64),
            active_secret.public_key(),
        )]));
        let issued_keyset = cdk_spilman::KeysetInfo::new(
            Id::v1_from_keys(&issued_keys),
            CurrencyUnit::Sat,
            issued_keys,
            0,
            None,
        );
        let active_keyset = cdk_spilman::KeysetInfo::new(
            Id::v1_from_keys(&active_keys),
            CurrencyUnit::Sat,
            active_keys,
            0,
            None,
        );
        let params = cdk_spilman::ChannelParameters::new_with_secret_key(
            alice_secret.public_key(),
            charlie_secret.public_key(),
            "https://mint.example".to_string(),
            CurrencyUnit::Sat,
            2,
            2,
            1_000,
            1,
            issued_keyset.clone(),
            2,
            &alice_secret,
        )
        .unwrap();
        let restorable = params
            .create_deterministic_output_with_blinding("sender", 2, 0)
            .unwrap();
        let mint = RotatedRestoreMint {
            issued_keyset_id: issued_keyset.keyset_id,
            issued_secret: issued_secret.clone(),
            restorable_blinded_secret: restorable
                .to_blinded_message(Amount::from(2_u64), active_keyset.keyset_id)
                .unwrap()
                .blinded_secret,
            require_issued_keyset_request: true,
            requested_keysets: Mutex::new(Vec::new()),
        };
        let funding_proof = Proof::new(
            Amount::from(2_u64),
            issued_keyset.keyset_id,
            cashu::secret::Secret::generate(),
            SecretKey::generate().public_key(),
        );
        let channel = cdk_spilman::EstablishedChannel::new(params, vec![funding_proof]).unwrap();
        let sender = cdk_spilman::SpilmanChannelSender::new(alice_secret, channel);

        let proofs = restore_sender_proofs_from_issued_keyset_with_resolver(
            &sender,
            &mint,
            &active_keyset,
            &[issued_keyset.keyset_id],
            |keyset_id| {
                let issued_keyset = issued_keyset.clone();
                async move {
                    assert_eq!(keyset_id, issued_keyset.keyset_id);
                    Ok(issued_keyset)
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(proofs.len(), 1);
        cashu::dhke::verify_message(&issued_secret, proofs[0].c, proofs[0].secret.as_bytes())
            .unwrap();
    }
}
