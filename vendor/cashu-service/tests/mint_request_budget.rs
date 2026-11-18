#![cfg(feature = "wallet")]

use std::sync::{Arc, Mutex};

use cashu_service::CashuWalletService;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::{CurrencyUnit, PaymentMethod};
use cashu_service::sqlite::WalletSqliteDatabase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Mint {
    url: cdk::mint_url::MintUrl,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Mint {
    async fn new(status: u16) -> Self {
        Self::serve(status, false).await
    }

    async fn serve(status: u16, paid: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let task = tokio::spawn(async move {
            let secret = cdk::nuts::SecretKey::generate();
            let keys = cdk::nuts::Keys::new(std::collections::BTreeMap::from_iter(
                [1_u64, 2, 4, 8].map(|amount| (cdk::Amount::from(amount), secret.public_key())),
            ));
            let id = cdk::nuts::Id::v1_from_keys(&keys);
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(request).unwrap();
                let path = headers.split_whitespace().nth(1).unwrap().to_owned();
                seen.lock().unwrap().push(path.clone());
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut payload = vec![0; length];
                socket.read_exact(&mut payload).await.unwrap();
                let body = if path == "/v1/info" {
                    serde_json::to_string(&cdk::nuts::MintInfo::new()).unwrap()
                } else if paid && path == "/v1/keysets" {
                    serde_json::json!({"keysets": [{"id": id, "unit": "sat", "active": true, "input_fee_ppk": 0}]}).to_string()
                } else if paid && path.starts_with("/v1/keys") {
                    serde_json::json!({"keysets": [{"id": id, "unit": "sat", "keys": keys}]})
                        .to_string()
                } else if paid && (path == "/v1/mint/bolt11" || path == "/v1/swap") {
                    let request: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                    if path == "/v1/swap" {
                        for proof in request["inputs"].as_array().unwrap() {
                            let secret = proof["secret"].as_str().unwrap();
                            if let Ok(condition) = serde_json::from_str::<serde_json::Value>(secret)
                            {
                                assert_ne!(
                                    condition[1].get("tags"),
                                    Some(&serde_json::Value::Null),
                                    "wallet sent a malformed legacy refund to the mint"
                                );
                            }
                        }
                    }
                    let outputs: Vec<cdk::nuts::BlindedMessage> =
                        serde_json::from_value(request["outputs"].clone()).unwrap();
                    let signatures: Vec<_> = outputs
                        .iter()
                        .map(|output| {
                            let mut signature = cdk::nuts::BlindSignature {
                                amount: output.amount,
                                keyset_id: output.keyset_id,
                                c: cdk::dhke::sign_message(&secret, &output.blinded_secret)
                                    .unwrap(),
                                dleq: None,
                            };
                            signature
                                .add_dleq_proof(&output.blinded_secret, &secret)
                                .unwrap();
                            signature
                        })
                        .collect();
                    serde_json::json!({"signatures": signatures}).to_string()
                } else {
                    serde_json::json!({"quote": path.rsplit('/').next().unwrap(), "request": "lnbc-test", "state": if paid { "PAID" } else { "UNPAID" }, "expiry": 1}).to_string()
                };
                socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    async fn seed(&self, directory: &std::path::Path, quotes: usize) {
        // Open once to create the seed and database, then seed only local state.
        drop(
            CashuWalletService::open_file_backed(directory)
                .await
                .unwrap(),
        );
        let db = WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(directory))
            .await
            .unwrap();
        db.add_mint(self.url.clone(), None).await.unwrap();
        for index in 0..quotes {
            db.add_mint_quote(cdk::wallet::MintQuote::new(
                format!("quote-{index}"),
                self.url.clone(),
                PaymentMethod::BOLT11,
                Some(cdk::Amount::from(5_u64)),
                CurrencyUnit::Sat,
                "lnbc-test".into(),
                1,
                None,
            ))
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn late_paid_quote_is_minted_and_wallet_balance_survives_restart() {
    let mint = Mint::serve(200, true).await;
    let directory = tempfile::tempdir().unwrap();
    mint.seed(directory.path(), 1).await;
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    let overview = service.load_wallet_overview(true).await.unwrap();
    assert!(overview.warnings.is_empty(), "{:?}", overview.warnings);
    assert_eq!(overview.totals[0].balance, 5);
    let request_count = mint.requests.lock().unwrap().len();
    drop(service);
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    service.recover_startup_state().await;
    assert_eq!(
        service.load_wallet_overview(false).await.unwrap().totals[0].balance,
        5
    );
    assert_eq!(mint.requests.lock().unwrap().len(), request_count);
}

impl Drop for Mint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn idle_wallet_refresh_and_startup_make_no_mint_requests() {
    let mint = Mint::new(200).await;
    let directory = tempfile::tempdir().unwrap();
    mint.seed(directory.path(), 0).await;
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    service.recover_startup_state().await;
    for _ in 0..3 {
        service.refresh_network_connections().await.unwrap();
        service.load_wallet_overview(true).await.unwrap();
    }
    assert!(
        mint.requests.lock().unwrap().is_empty(),
        "idle refresh contacted a mint"
    );
}

#[tokio::test]
async fn quote_polling_is_bounded_across_refreshes_and_restarts() {
    let mint = Mint::new(200).await;
    let directory = tempfile::tempdir().unwrap();
    mint.seed(directory.path(), 8).await;
    for _ in 0..3 {
        let service = CashuWalletService::open_file_backed(directory.path())
            .await
            .unwrap();
        service.recover_startup_state().await;
        for _ in 0..3 {
            service.refresh_network_connections().await.unwrap();
            service.load_wallet_overview(true).await.unwrap();
        }
    }
    let requests = mint.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "repeated refreshes swept pending quotes: {requests:?}"
    );
    assert!(requests[0].starts_with("/v1/mint/quote/bolt11/"));
}

#[tokio::test]
async fn failed_quote_check_stops_the_sweep_and_persists_backoff() {
    let mint = Mint::new(403).await;
    let directory = tempfile::tempdir().unwrap();
    mint.seed(directory.path(), 8).await;
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    let report = service.recover_startup_state().await;
    assert_eq!(
        report.warnings.len(),
        1,
        "mint failures must remain visible"
    );
    drop(service);
    let db = WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(directory.path()))
        .await
        .unwrap();
    let polls: serde_json::Value = serde_json::from_slice(
        &db.kv_read("nvpn_wallet", "", "mint_polls")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        polls[format!("{} sat", mint.url)]["next_poll_unix"]
            .as_u64()
            .unwrap()
            >= now + 890
    );
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    service.recover_startup_state().await;
    service.load_wallet_overview(true).await.unwrap();
    assert_eq!(mint.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn expired_unpaid_quote_is_not_rechecked_on_every_poll() {
    let mint = Mint::new(200).await;
    let directory = tempfile::tempdir().unwrap();
    mint.seed(directory.path(), 1).await;
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    service.load_wallet_overview(true).await.unwrap();
    let db = WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(directory.path()))
        .await
        .unwrap();
    let mut polls: serde_json::Value = serde_json::from_slice(
        &db.kv_read("nvpn_wallet", "", "mint_polls")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let poll = &mut polls[format!("{} sat", mint.url)];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(poll["quote_checks"]["quote-0"].as_u64().unwrap() >= now + 86_390);
    // Advance only the mint's admission deadline, as on a later routine poll.
    poll["next_poll_unix"] = 0.into();
    db.kv_write(
        "nvpn_wallet",
        "",
        "mint_polls",
        &serde_json::to_vec(&polls).unwrap(),
    )
    .await
    .unwrap();
    service.load_wallet_overview(true).await.unwrap();
    assert_eq!(mint.requests.lock().unwrap().len(), 1);
}

#[cfg(feature = "spilman-wallet-http")]
#[tokio::test]
async fn direct_mint_failures_share_a_cooldown_across_paths_and_clients() {
    for status in [403, 429, 503] {
        let mint = Mint::new(status).await;
        let response = cashu_service::send_mint_request(
            reqwest::Client::new().get(format!("{}/v1/keysets", mint.url)),
        )
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), status);
        for path in [
            "/v1/swap",
            "/v1/restore",
            "/v1/checkstate",
            "/Bitcoin/v1/keys",
        ] {
            let error = cashu_service::send_mint_request(
                reqwest::Client::new().post(format!("{}{path}", mint.url)),
            )
            .await
            .unwrap_err();
            let delay = error
                .downcast_ref::<cashu_service::MintRetryAfter>()
                .unwrap()
                .0;
            assert!(delay >= if status == 503 { 59 } else { 899 });
        }
        let error =
            cashu_service::fetch_spilman_keyset_info_json(&mint.url.to_string(), "sat", None)
                .await
                .unwrap_err();
        assert!(
            error
                .downcast_ref::<cashu_service::MintRetryAfter>()
                .is_some(),
            "keyset helper lost structured cooldown: {error:#}"
        );
        #[cfg(feature = "spilman-configurable-host-reqwest")]
        assert!(
            cdk_spilman::configurable_networking::fetch_all_keysets_from_mint(
                &mint.url.to_string()
            )
            .await
            .is_err()
        );
        assert_eq!(mint.requests.lock().unwrap().len(), 1);
        let healthy = Mint::new(200).await;
        cashu_service::send_mint_request(
            reqwest::Client::new().get(format!("{}/v1/info", healthy.url)),
        )
        .await
        .unwrap();
    }
}

#[cfg(feature = "spilman-wallet-http")]
#[tokio::test]
async fn direct_mint_requests_are_paced_across_concurrent_clients() {
    let mint = Mint::new(200).await;
    let started = std::time::Instant::now();
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let url = format!("{}/v1/info", mint.url);
        requests.spawn(async move {
            cashu_service::send_mint_request(reqwest::Client::new().get(url))
                .await
                .unwrap();
        });
    }
    while let Some(result) = requests.join_next().await {
        result.unwrap();
    }
    assert!(started.elapsed() >= std::time::Duration::from_secs(4));
    assert_eq!(mint.requests.lock().unwrap().len(), 3);
}

mod wallet_refunds;

#[cfg(feature = "spilman-wallet-http")]
mod expiry_refunds;
