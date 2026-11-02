//! Real CDK mint transactions with simulated Lightning and a strict NUT-10
//! tags boundary. Every wallet, mint key and coin exists only in this test.
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::StatusCode,
    response::IntoResponse,
    Router,
};
use cashu_service::{simulation::*, *};
use cdk::nuts::{CurrencyUnit, Proof, Token};
use cdk_spilman::ChannelOutputVersion;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

struct StrictMint {
    url: String,
    swaps: Arc<AtomicUsize>,
    rejected_tags: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl StrictMint {
    async fn start(mint: &LocalMint) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upstream = mint.url().to_string();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let swaps = Arc::new(AtomicUsize::new(0));
        let rejected_tags = Arc::new(AtomicUsize::new(0));
        let counts = (swaps.clone(), rejected_tags.clone());
        let router = Router::new().fallback(move |request: Request| {
            let (upstream, client, counts) = (upstream.clone(), client.clone(), counts.clone());
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, 1024 * 1024).await.unwrap();
                if parts.uri.path() == "/v1/swap" {
                    counts.0.fetch_add(1, Ordering::SeqCst);
                    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    for proof in request["inputs"].as_array().unwrap() {
                        if let Ok(secret) = serde_json::from_str::<serde_json::Value>(
                            proof["secret"].as_str().unwrap(),
                        ) {
                            if let Some(tags) = secret.get(1).and_then(|fields| fields.get("tags"))
                            {
                                if !tags.as_array().is_some_and(|tags| {
                                    tags.iter().all(|tag| {
                                        tag.as_array().is_some_and(|values| {
                                            !values.is_empty()
                                                && values.iter().all(|v| {
                                                    v.as_str().is_some_and(|s| !s.is_empty())
                                                })
                                        })
                                    })
                                }) {
                                    counts.1.fetch_add(1, Ordering::SeqCst);
                                    return (StatusCode::BAD_REQUEST, "malformed NUT-10 tags")
                                        .into_response();
                                }
                            }
                        }
                    }
                }
                let response = client
                    .request(parts.method, format!("{upstream}{}", parts.uri))
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .unwrap();
                let status = response.status();
                (
                    status,
                    [("content-type", "application/json")],
                    Body::from(response.bytes().await.unwrap()),
                )
                    .into_response()
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            swaps,
            rejected_tags,
            server,
        }
    }
}

impl Drop for StrictMint {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buyer_refund_and_seller_payout_can_be_spent_once_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(42, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        network.clone(),
        "payout",
        IssuerMode::Withdrawable,
    )
    .await
    .unwrap();
    let strict = StrictMint::start(&mint).await;
    let buyer_dir = root.path().join("buyer");
    let seller_dir = root.path().join("seller");
    let quote = create_topup_quote(&buyer_dir, &strict.url, 64)
        .await
        .unwrap();
    network
        .orchestrator_funding()
        .settle_external(&quote.payment_request)
        .unwrap();
    let buyer = CashuWalletService::open_file_backed(&buyer_dir)
        .await
        .unwrap();
    assert!(buyer
        .load_wallet_overview(true)
        .await
        .unwrap()
        .warnings
        .is_empty());
    assert_eq!(
        buyer
            .load_mint_balance(&strict.url)
            .await
            .unwrap()
            .balance_sat,
        64
    );
    let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
        &seller_dir,
        FileSpilmanPaymentReceiverConfig::new([strict.url.clone()]),
    )
    .await
    .unwrap();
    let request = StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
        output_version: ChannelOutputVersion::Nut10,
        mint_url: strict.url.clone(),
        receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
        capacity_sat: 64,
        expiry_unix: now + 3600,
        max_amount_per_output: 0,
        unit: "sat".into(),
        opening_paid_msat: 0,
        keyset_id: None,
        keyset_info_json: None,
        client_request_id: Some("payout-roundtrip".into()),
        route_created_at_unix: Some(now),
    };
    let mut legacy = request.clone();
    legacy.output_version = ChannelOutputVersion::Legacy;
    assert!(buyer
        .open_streaming_route_cashu_spilman_channel(legacy)
        .await
        .is_err());
    assert_eq!(
        strict.swaps.load(Ordering::SeqCst),
        0,
        "legacy refusal must precede spending"
    );
    let opened = buyer
        .open_streaming_route_cashu_spilman_channel(request.clone())
        .await
        .unwrap()
        .channel;
    receiver
        .process_cashu_spilman_payment(&opened.payment, &"payout".into())
        .unwrap();
    let swaps = strict.swaps.load(Ordering::SeqCst);
    drop(buyer);
    let buyer = CashuWalletService::open_file_backed(&buyer_dir)
        .await
        .unwrap();
    let recovered = buyer
        .open_streaming_route_cashu_spilman_channel(request)
        .await
        .unwrap();
    assert_eq!(recovered.channel, opened);
    assert!(recovered.wallet_send.token.is_empty());
    assert_eq!(
        strict.swaps.load(Ordering::SeqCst),
        swaps,
        "restart must not fund twice"
    );
    let signer = FileSpilmanPaymentSigner::load(&buyer_dir).unwrap();
    let payment = signer
        .sign_cashu_spilman_payment(&opened.channel_id, 20, false)
        .unwrap();
    drop(signer);
    receiver
        .process_cashu_spilman_payment(&payment, &"payout".into())
        .unwrap();
    let closed = receiver
        .close_cashu_spilman_channel(&opened.channel_id)
        .await
        .unwrap();
    assert_eq!((closed.sender_sum, closed.receiver_sum), (44, 20));
    let proofs: Vec<Proof> = serde_json::from_str(&closed.receiver_proofs_json).unwrap();
    assert!(proofs.iter().all(|proof| {
        let secret: serde_json::Value = serde_json::from_str(&proof.secret.to_string()).unwrap();
        secret[1]["tags"] == serde_json::json!([])
    }));

    // Establish that the boundary rejects null tags rather than relying on
    // CDK's permissive Option<tags> parser. This altered probe is never imported.
    let mut malformed = proofs.clone();
    for proof in &mut malformed {
        let mut secret: serde_json::Value =
            serde_json::from_str(&proof.secret.to_string()).unwrap();
        secret[1]["tags"] = serde_json::Value::Null;
        proof.secret = cdk::secret::Secret::new(secret.to_string());
    }
    // A wallet may reject the altered proof's DLEQ before networking. Exercise
    // the mint boundary directly so this negative control reaches that parser.
    let rejected = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/swap", strict.url))
        .json(&serde_json::json!({"inputs": malformed, "outputs": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(strict.rejected_tags.load(Ordering::SeqCst), 1);
    let mut unsigned = proofs.clone();
    for proof in &mut unsigned {
        proof.witness = None;
    }
    let token = Token::new(
        strict.url.parse().unwrap(),
        unsigned,
        None,
        CurrencyUnit::Sat,
    );
    assert!(
        receive_payment_token(&root.path().join("unsigned-probe"), &token.to_string())
            .await
            .is_err()
    );

    import_payment_proofs(
        &seller_dir,
        &strict.url,
        "sat",
        &closed.receiver_proofs_json,
    )
    .await
    .unwrap();
    drop(buyer);
    let refund = restore_streaming_route_cashu_spilman_refund(&buyer_dir, &opened.channel_id)
        .await
        .unwrap();
    assert!(refund.complete);
    assert_eq!(refund.imported_amount_sat, 44);
    let retry = restore_streaming_route_cashu_spilman_refund(&buyer_dir, &opened.channel_id)
        .await
        .unwrap();
    assert!(retry.complete);
    assert_eq!(retry.imported_amount_sat, 0);
    assert!(
        receiver
            .close_cashu_spilman_channel(&opened.channel_id)
            .await
            .unwrap()
            .already_closed
    );
    let recipient = root.path().join("recipient");
    for (directory, amount) in [(&buyer_dir, 44), (&seller_dir, 20)] {
        assert_eq!(
            load_mint_balance(directory, &strict.url)
                .await
                .unwrap()
                .balance_sat,
            amount
        );
        let token = send_payment_token(directory, &strict.url, amount)
            .await
            .unwrap();
        assert_eq!(
            receive_payment_token(&recipient, &token.token)
                .await
                .unwrap()
                .amount_sat,
            amount
        );
        assert!(
            receive_payment_token(&root.path().join(format!("replay-{amount}")), &token.token)
                .await
                .is_err()
        );
        assert_eq!(
            load_mint_balance(directory, &strict.url)
                .await
                .unwrap()
                .balance_sat,
            0
        );
    }
    assert_eq!(
        load_mint_balance(&recipient, &strict.url)
            .await
            .unwrap()
            .balance_sat,
        64
    );
    assert_eq!(
        strict.rejected_tags.load(Ordering::SeqCst),
        1,
        "real payouts must pass the strict boundary"
    );
    assert!(network.accounting().unwrap().is_conserved());
}
