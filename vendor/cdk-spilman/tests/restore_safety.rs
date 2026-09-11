//! Regression coverage for untrusted NUT-09 restore responses.

use std::collections::BTreeMap;

use async_trait::async_trait;
use cashu::nuts::{
    BlindSignature, CheckStateResponse, CurrencyUnit, Id, Keys, PublicKey, RestoreRequest,
    RestoreResponse, SecretKey, SwapRequest, SwapResponse,
};
use cashu::Amount;
use cdk_spilman::{
    ChannelParameters, EstablishedChannel, KeysetInfo, MintConnection, SpilmanChannelSender,
};

#[derive(Clone, Copy)]
enum ResponseKind {
    Valid,
    DuplicateSignature,
    MissingOutput,
    UnrelatedOutput,
    WrongAmount,
    TransportFailure,
}

struct RestoreMint {
    secret: SecretKey,
    issued_keyset: KeysetInfo,
    restorable: PublicKey,
    response: ResponseKind,
}

#[async_trait]
impl MintConnection for RestoreMint {
    async fn process_swap(&self, _: SwapRequest) -> anyhow::Result<SwapResponse> {
        anyhow::bail!("unexpected swap during restore")
    }

    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        if matches!(self.response, ResponseKind::TransportFailure) {
            anyhow::bail!("restore transport failed")
        }
        let output = &request.outputs[0];
        if output.blinded_secret != self.restorable {
            return Ok(RestoreResponse {
                outputs: vec![],
                signatures: vec![],
            });
        }
        let signature = BlindSignature {
            amount: output.amount,
            keyset_id: self.issued_keyset.keyset_id,
            c: cashu::dhke::sign_message(&self.secret, &output.blinded_secret)?,
            dleq: None,
        };
        let mut response = RestoreResponse {
            outputs: request.outputs,
            signatures: vec![signature],
        };
        match self.response {
            ResponseKind::DuplicateSignature => {
                response.signatures.push(response.signatures[0].clone());
            }
            ResponseKind::MissingOutput => response.outputs.clear(),
            ResponseKind::UnrelatedOutput => {
                response.outputs[0].blinded_secret = self.secret.public_key();
            }
            ResponseKind::WrongAmount => response.signatures[0].amount = Amount::from(2_u64),
            ResponseKind::Valid | ResponseKind::TransportFailure => {}
        }
        Ok(response)
    }

    async fn check_state(&self, _: Vec<PublicKey>) -> anyhow::Result<CheckStateResponse> {
        anyhow::bail!("unexpected state check during restore")
    }
}

fn keyset(secret: &SecretKey) -> KeysetInfo {
    let keys = Keys::new(BTreeMap::from([
        (Amount::from(1_u64), secret.public_key()),
        (Amount::from(2_u64), secret.public_key()),
    ]));
    KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, 0, None)
}

fn fixture(response: ResponseKind) -> (SpilmanChannelSender, RestoreMint) {
    let alice = SecretKey::from_hex(&"01".repeat(32)).expect("sender key");
    let receiver = SecretKey::from_hex(&"02".repeat(32)).expect("receiver key");
    let mint_secret = SecretKey::from_hex(&"03".repeat(32)).expect("mint key");
    let issued_keyset = keyset(&mint_secret);
    let params = ChannelParameters::new_with_secret_key(
        alice.public_key(),
        receiver.public_key(),
        "https://mint.example".to_string(),
        CurrencyUnit::Sat,
        2,
        2,
        2_000_000_000,
        1_999_999_000,
        issued_keyset.clone(),
        0,
        &alice,
    )
    .expect("channel parameters");
    let restorable = params
        .create_deterministic_output_with_blinding("sender", 1, 0)
        .expect("deterministic output")
        .to_blinded_message(Amount::from(1_u64), issued_keyset.keyset_id)
        .expect("blinded output")
        .blinded_secret;
    let sender = SpilmanChannelSender::new(
        alice,
        EstablishedChannel {
            params,
            funding_proofs: vec![],
        },
    );
    let mint = RestoreMint {
        secret: mint_secret,
        issued_keyset,
        restorable,
        response,
    };
    (sender, mint)
}

async fn assert_rejected(response: ResponseKind) {
    let (sender, mint) = fixture(response);
    let error = sender
        .restore_sender_proofs(&mint)
        .await
        .expect_err("malformed mint response must not become a refund proof");
    assert!(error.to_string().contains("restore"), "{error}");
}

#[tokio::test]
async fn restore_rejects_multiple_signatures_for_one_requested_output() {
    assert_rejected(ResponseKind::DuplicateSignature).await;
}

#[tokio::test]
async fn restore_requires_a_corresponding_output() {
    assert_rejected(ResponseKind::MissingOutput).await;
    assert_rejected(ResponseKind::UnrelatedOutput).await;
}

#[tokio::test]
async fn restore_rejects_a_different_denomination() {
    assert_rejected(ResponseKind::WrongAmount).await;
}

#[tokio::test]
async fn restore_preserves_transport_failures() {
    assert_rejected(ResponseKind::TransportFailure).await;
}

#[tokio::test]
async fn restore_preserves_issued_keyset_discovery_after_rotation() {
    let (sender, mint) = fixture(ResponseKind::Valid);
    let active_secret = SecretKey::from_hex(&"04".repeat(32)).expect("rotated mint key");
    let active_keyset = keyset(&active_secret);
    let discovered = sender
        .restore_sender_proofs_with_keyset(&mint, &active_keyset)
        .await
        .expect("restore discovers the actual issued keyset");
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].keyset_id, mint.issued_keyset.keyset_id);
    assert_ne!(discovered[0].keyset_id, active_keyset.keyset_id);

    let proofs = sender
        .restore_sender_proofs_with_keyset(&mint, &mint.issued_keyset)
        .await
        .expect("restore with the issued keyset");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].amount, Amount::from(1_u64));
    cashu::dhke::verify_message(&mint.secret, proofs[0].c, &proofs[0].secret.to_bytes())
        .expect("the restored proof must verify under its actual issuing key");
}
