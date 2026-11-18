#![cfg(feature = "spilman-wallet")]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use cashu_service::{
    open_streaming_route_cashu_spilman_channel_from_token_with_networking,
    StreamingRouteOpenCashuSpilmanChannelFromTokenRequest,
};
use cdk::nuts::{BlindSignature, CurrencyUnit, Id, Keys, Proof, SecretKey, Token};
use cdk::{secret::Secret, Amount};
use cdk_spilman::{KeysetInfo, SpilmanClientAsyncNetworking};

struct Mint {
    secret: SecretKey,
    swaps: AtomicUsize,
}

#[async_trait::async_trait]
impl SpilmanClientAsyncNetworking for Mint {
    async fn call_mint_swap(&self, _: &str, request: &str) -> Result<String, String> {
        self.swaps.fetch_add(1, Ordering::SeqCst);
        let request: cdk::nuts::nut03::SwapRequest = serde_json::from_str(request).unwrap();
        let signatures: Vec<_> = request
            .outputs()
            .iter()
            .map(|message| {
                let mut signature = BlindSignature {
                    amount: message.amount,
                    keyset_id: message.keyset_id,
                    c: cdk::dhke::sign_message(&self.secret, &message.blinded_secret).unwrap(),
                    dleq: None,
                };
                signature
                    .add_dleq_proof(&message.blinded_secret, &self.secret)
                    .unwrap();
                signature
            })
            .collect();
        Ok(serde_json::json!({"signatures": signatures}).to_string())
    }
}

#[tokio::test]
async fn funding_preserves_requested_capacity_and_recovers_the_same_channel() {
    funding_preserves_capacity_and_agreed_format(1).await;
}

#[tokio::test]
async fn funding_and_retry_preserve_negotiated_nut10_output_format() {
    funding_preserves_capacity_and_agreed_format(2).await;
}

async fn funding_preserves_capacity_and_agreed_format(output_version: u8) {
    let mint = Mint {
        secret: SecretKey::generate(),
        swaps: AtomicUsize::new(0),
    };
    let keys = Keys::new(BTreeMap::from_iter(
        [1, 2, 4, 8, 16].map(|amount| (Amount::from(amount), mint.secret.public_key())),
    ));
    let keyset = KeysetInfo::new(Id::v1_from_keys(&keys), CurrencyUnit::Sat, keys, 0, None);
    // A token can contain more spendable value than the requested channel.
    // That must not increase the seller's agreed maximum or the next renewal.
    let token = Token::new(
        "https://mint.example".parse().unwrap(),
        [1, 2, 8]
            .map(|amount| {
                Proof::new(
                    Amount::from(amount),
                    keyset.keyset_id,
                    Secret::new(format!("input-{amount}")),
                    mint.secret.public_key(),
                )
            })
            .to_vec(),
        None,
        CurrencyUnit::Sat,
    );
    let request = StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
        output_version: Default::default(),
        token: token.to_string(),
        receiver_pubkey_hex: SecretKey::generate().public_key().to_hex(),
        sender_secret_hex: Some(SecretKey::generate().to_secret_hex()),
        expiry_unix: 2_000_000_000,
        keyset_info_json: serde_json::to_string(&keyset).unwrap(),
        max_amount_per_output: 16,
        unit: "sat".into(),
        opening_paid_msat: 1_000,
        route_mint_url: Some("https://mint.example".into()),
        route_capacity_sat: Some(10),
        client_request_id: Some("route-session".into()),
        route_created_at_unix: Some(1_999_999_000),
    };
    let mut request_json = serde_json::to_value(&request).unwrap();
    // Legacy clients omitted the field. New clients must select it before the
    // mint signs anything, and retries must preserve that exact selection.
    if output_version == 1 {
        request_json
            .as_object_mut()
            .unwrap()
            .remove("output_version");
    } else {
        request_json["output_version"] = serde_json::json!(output_version);
    }
    let request: StreamingRouteOpenCashuSpilmanChannelFromTokenRequest =
        serde_json::from_value(request_json).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let opened = open_streaming_route_cashu_spilman_channel_from_token_with_networking(
        directory.path(),
        request.clone(),
        &mint,
    )
    .await
    .unwrap();
    assert_eq!(opened.capacity_sat, 10);
    assert_eq!(opened.funding_token_amount, 11);
    assert!(opened.payment.has_funding());
    let secret = cdk_spilman::compute_channel_secret_from_hex(
        request.sender_secret_hex.as_ref().unwrap(),
        &request.receiver_pubkey_hex,
    )
    .unwrap();
    let params = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
        &opened.payment.params.as_ref().unwrap().to_string(),
        keyset,
        cdk::util::hex::decode(secret).unwrap().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(u8::from(params.output_version), output_version);
    let allocation = cdk_spilman::CommitmentOutputs::for_balance(10, &params).unwrap();
    let refund: u64 = allocation
        .sender_outputs
        .get_secrets_with_blinding()
        .unwrap()
        .iter()
        .map(|output| output.amount)
        .sum();
    assert_eq!(refund, 1, "extra funding remains the sender's change");
    assert_eq!(mint.swaps.load(Ordering::SeqCst), 1);

    #[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
    {
        let recovered = cashu_service::open_streaming_route_cashu_spilman_channel_from_wallet(
            directory.path(),
            cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                output_version: request.output_version,
                mint_url: opened.mint_url.clone(),
                receiver_pubkey_hex: request.receiver_pubkey_hex.clone(),
                capacity_sat: 10,
                expiry_unix: request.expiry_unix,
                max_amount_per_output: request.max_amount_per_output,
                unit: "sat".into(),
                opening_paid_msat: request.opening_paid_msat,
                keyset_id: None,
                keyset_info_json: Some("not consulted during recovery".into()),
                client_request_id: request.client_request_id.clone(),
                route_created_at_unix: request.route_created_at_unix,
            },
        )
        .await
        .unwrap();
        assert_eq!(recovered.channel, opened);
        assert!(recovered.wallet_send.token.is_empty());
        assert_eq!(mint.swaps.load(Ordering::SeqCst), 1);
    }

    let mut changed_format = serde_json::to_value(&request).unwrap();
    changed_format["token"] = serde_json::json!("");
    changed_format["output_version"] = serde_json::json!(if output_version == 1 { 2 } else { 1 });
    let error = open_streaming_route_cashu_spilman_channel_from_token_with_networking(
        directory.path(),
        serde_json::from_value(changed_format).unwrap(),
        &mint,
    )
    .await
    .unwrap_err();
    assert!(error.contains("different terms"), "{error}");
    assert_eq!(
        mint.swaps.load(Ordering::SeqCst),
        1,
        "a format mismatch must not spend again"
    );

    let mut retry = request.clone();
    retry.token.clear();
    let recovered = open_streaming_route_cashu_spilman_channel_from_token_with_networking(
        directory.path(),
        retry,
        &mint,
    )
    .await
    .unwrap();
    assert_eq!(recovered.channel_id, opened.channel_id);
    assert_eq!(recovered.capacity_sat, 10);
    assert_eq!(mint.swaps.load(Ordering::SeqCst), 1);

    let mut underfunded = request;
    underfunded.route_capacity_sat = Some(12);
    underfunded.client_request_id = Some("underfunded".into());
    let other_directory = tempfile::tempdir().unwrap();
    assert!(
        open_streaming_route_cashu_spilman_channel_from_token_with_networking(
            other_directory.path(),
            underfunded,
            &mint
        )
        .await
        .is_err()
    );
    assert_eq!(
        mint.swaps.load(Ordering::SeqCst),
        1,
        "reject before spending the token"
    );
}
