use cashu_service::{
    load_or_create_cashu_spilman_sender_key, restore_streaming_route_cashu_spilman_refund,
    spilman_client_store_path, FileSpilmanClientStorage,
};
use cdk::nuts::nut10::SpendingConditionVerification;
use cdk::nuts::{
    BlindSignature, BlindedMessage, CurrencyUnit, Id, Keys, Proof, SecretKey, SwapRequest,
};
use cdk_spilman::{ChannelParameters, ClientStorage, KeysetInfo, OrderedListOfAmounts};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct State {
    spent: bool,
    pending: bool,
    drop_swap_response: bool,
    swaps: usize,
    malformed_state: bool,
    mixed_state: bool,
    corrupt_signature: bool,
    incomplete_restore: bool,
    signatures: Vec<(BlindedMessage, BlindSignature)>,
    requests: Vec<String>,
}

struct Mint {
    url: String,
    secret: SecretKey,
    keyset: KeysetInfo,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Mint {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let secret = SecretKey::generate();
        let keys = Keys::new(BTreeMap::from_iter(
            [1_u64, 2, 4, 8, 16, 32].map(|amount| (cdk::Amount::from(amount), secret.public_key())),
        ));
        let keyset = KeysetInfo::new(
            Id::v1_from_keys(&keys),
            CurrencyUnit::Sat,
            keys.clone(),
            150,
            None,
        );
        let id = keyset.keyset_id;
        let signer = secret.clone();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap();
                let path = header.split_whitespace().nth(1).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                socket.read_exact(&mut body).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let (status, response, drop_response) = {
                    let mut state = shared.lock().unwrap();
                    state.requests.push(path.to_owned());
                    let mut status = 200;
                    let mut drop_response = false;
                    let response = match path {
                        "/v1/info" => serde_json::to_value(cdk::nuts::MintInfo::new()).unwrap(),
                        "/v1/keysets" => {
                            serde_json::json!({"keysets":[{"id":id,"unit":"sat","active":true,"input_fee_ppk":150}]})
                        }
                        path if path.starts_with("/v1/keys") => {
                            serde_json::json!({"keysets":[{"id":id,"unit":"sat","keys":keys}]})
                        }
                        "/v1/checkstate" => {
                            let mut states: Vec<_> = request["Ys"].as_array().unwrap().iter().enumerate().map(|(index, y)|
                                serde_json::json!({"Y":y,"state":if state.pending || (state.mixed_state && index == 0) { "PENDING" } else if state.spent { "SPENT" } else { "UNSPENT" }})).collect();
                            if state.malformed_state {
                                states.pop();
                            }
                            serde_json::json!({"states":states})
                        }
                        "/v1/swap" => {
                            state.swaps += 1;
                            let swap: SwapRequest = serde_json::from_value(request).unwrap();
                            swap.verify_spending_conditions()
                                .expect("refund must satisfy the full SIG_ALL expiry condition");
                            let input: u64 =
                                swap.inputs().iter().map(|p| u64::from(p.amount)).sum();
                            let output: u64 =
                                swap.outputs().iter().map(|p| u64::from(p.amount)).sum();
                            assert_eq!(
                                input - output,
                                (swap.inputs().len() as u64 * 150).div_ceil(1000)
                            );
                            if state.spent {
                                status = 400;
                                serde_json::json!({"code":11001,"detail":"already spent"})
                            } else {
                                state.signatures = swap
                                    .outputs()
                                    .iter()
                                    .map(|output| {
                                        let mut signature = BlindSignature {
                                            amount: output.amount,
                                            keyset_id: output.keyset_id,
                                            c: cdk::dhke::sign_message(
                                                &signer,
                                                &output.blinded_secret,
                                            )
                                            .unwrap(),
                                            dleq: None,
                                        };
                                        signature
                                            .add_dleq_proof(&output.blinded_secret, &signer)
                                            .unwrap();
                                        (output.clone(), signature)
                                    })
                                    .collect();
                                state.spent = true;
                                drop_response = std::mem::take(&mut state.drop_swap_response);
                                let mut signatures: Vec<_> =
                                    state.signatures.iter().map(|(_, s)| s.clone()).collect();
                                if state.corrupt_signature {
                                    signatures[0].c = SecretKey::generate().public_key();
                                }
                                serde_json::json!({"signatures":signatures})
                            }
                        }
                        "/v1/restore" => {
                            let requested: Vec<BlindedMessage> =
                                serde_json::from_value(request["outputs"].clone()).unwrap();
                            let mut matches: Vec<_> = requested
                                .iter()
                                .filter_map(|out| {
                                    state.signatures.iter().find(|(saved, _)| {
                                        saved.blinded_secret == out.blinded_secret
                                    })
                                })
                                .collect();
                            if state.incomplete_restore {
                                matches.pop();
                            }
                            serde_json::json!({"outputs":matches.iter().map(|(o,_)|o).collect::<Vec<_>>(),
                                "signatures":matches.iter().map(|(_,s)|s).collect::<Vec<_>>()})
                        }
                        _ => panic!("unexpected mint path {path}"),
                    };
                    (status, response.to_string(), drop_response)
                };
                if !drop_response {
                    socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{response}",response.len()).as_bytes()).await.unwrap();
                }
            }
        });
        Self {
            url,
            secret,
            keyset,
            state,
            task,
        }
    }

    async fn fund_expired(&self, directory: &std::path::Path) -> (String, u64) {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2;
        let result = self.fund(directory, expiry);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        result
    }

    fn fund(&self, directory: &std::path::Path, expiry: u64) -> (String, u64) {
        self.fund_for_receiver(directory, expiry, SecretKey::generate().public_key())
    }

    fn fund_for_receiver(
        &self,
        directory: &std::path::Path,
        expiry: u64,
        receiver: cdk::nuts::PublicKey,
    ) -> (String, u64) {
        let sender = load_or_create_cashu_spilman_sender_key(directory).unwrap();
        let key = SecretKey::from_hex(&sender.secret_hex).unwrap();
        let total =
            ChannelParameters::get_minimum_funding_token_amount(8, &self.keyset, 0).unwrap();
        let params = ChannelParameters::new_with_secret_key(
            key.public_key(),
            receiver,
            self.url.clone(),
            CurrencyUnit::Sat,
            8,
            total,
            expiry,
            1,
            self.keyset.clone(),
            0,
            &key,
        )
        .unwrap();
        let amounts = OrderedListOfAmounts::from_target(total, 0, &self.keyset).unwrap();
        let mut proofs = Vec::new();
        for (amount, count) in amounts.count_by_amount {
            for index in 0..count {
                let output = params
                    .create_deterministic_output_with_blinding("funding", amount, index)
                    .unwrap();
                let message = output
                    .to_blinded_message(cdk::Amount::from(amount), self.keyset.keyset_id)
                    .unwrap();
                let mut signature = BlindSignature {
                    amount: message.amount,
                    keyset_id: message.keyset_id,
                    c: cdk::dhke::sign_message(&self.secret, &message.blinded_secret).unwrap(),
                    dleq: None,
                };
                signature
                    .add_dleq_proof(&message.blinded_secret, &self.secret)
                    .unwrap();
                proofs.extend(
                    cdk::dhke::construct_proofs(
                        vec![signature],
                        vec![output.blinding_factor],
                        vec![output.secret],
                        &self.keyset.active_keys,
                    )
                    .unwrap(),
                );
            }
        }
        let recovered = total - (proofs.len() as u64 * 150).div_ceil(1000);
        let id = params.get_channel_id();
        let (mut storage, errors) =
            FileSpilmanClientStorage::load(spilman_client_store_path(directory)).unwrap();
        storage.save_funding(
            &id,
            cdk_spilman::ClientChannelFunding {
                params_json: params.get_channel_id_params_json(),
                funding_proofs_json: serde_json::to_string(&proofs).unwrap(),
                channel_secret_hex: cdk::util::hex::encode(params.channel_secret),
                keyset_info_json: serde_json::to_string(&self.keyset).unwrap(),
                sender_pubkey_hex: sender.public_key_hex,
                capacity: 8,
                funding_token_amount: total,
                mint_url: self.url.clone(),
                created_at: 1,
            },
        );
        errors.ensure_ok().unwrap();
        (id, recovered)
    }
}

async fn assert_wallet_refund(mint: &Mint, directory: &std::path::Path, expected: u64) {
    use cdk::cdk_database::WalletDatabase;
    let db = cashu_service::sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(directory))
        .await
        .unwrap();
    let proofs = db
        .get_proofs(
            Some(mint.url.parse().unwrap()),
            Some(CurrencyUnit::Sat),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        proofs
            .iter()
            .map(|p| u64::from(p.proof.amount))
            .sum::<u64>(),
        expected
    );
    for info in proofs {
        assert_eq!(info.state, cdk::nuts::State::Unspent);
        let y = info.proof.y().unwrap();
        assert_eq!(
            info.proof.c,
            cdk::dhke::sign_message(&mint.secret, &y).unwrap(),
            "wallet coins must have valid mint signatures"
        );
        assert!(
            info.proof.witness.is_none(),
            "refund outputs are ordinary spendable coins"
        );
        info.proof.verify_dleq(mint.secret.public_key()).unwrap();
    }
}

impl Drop for Mint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn expiry_refund_uses_existing_wallet_owner_without_holding_channel_store() {
    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    let interrupted_lock = cashu_service::SharedSpilmanClientStoreLock::acquire(
        spilman_client_store_path(directory.path()),
    )
    .unwrap();
    let failed_import = cashu_service::restore_streaming_route_cashu_spilman_refund_with_wallet(
        directory.path(),
        &id,
        interrupted_lock,
        &mut false,
        |_, _, _| async { anyhow::bail!("wallet import interrupted") },
    )
    .await;
    assert!(failed_import.is_err());
    let (storage, _) =
        FileSpilmanClientStorage::load(spilman_client_store_path(directory.path())).unwrap();
    assert_ne!(
        storage.get_state(&id),
        cdk_spilman::ClientChannelState::Closed
    );
    drop(storage);
    let wallet = cashu_service::CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    let lock = cashu_service::SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(
        directory.path(),
    ))
    .unwrap();
    let mut contacted = false;
    let wallet_owner = &wallet;
    let path = directory.path();
    let result = cashu_service::restore_streaming_route_cashu_spilman_refund_with_wallet(
        directory.path(),
        &id,
        lock,
        &mut contacted,
        |mint_url, unit, proofs| async move {
            let lock = cashu_service::SharedSpilmanClientStoreLock::try_acquire(
                spilman_client_store_path(path),
            )
            .unwrap()
            .expect("wallet import must not hold the channel store");
            drop(lock);
            Ok(wallet_owner
                .import_payment_proofs(&mint_url, &unit, &proofs)
                .await?
                .amount_sat)
        },
    )
    .await
    .unwrap();
    assert!(result.complete && contacted);
    assert_eq!(result.imported_amount_sat, expected);
    assert_wallet_refund(&mint, directory.path(), expected).await;
}

#[tokio::test]
async fn expiry_refund_reclaims_unspent_funding_once_with_input_fees() {
    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    let refund = restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
        .await
        .unwrap();
    assert!(
        refund.complete,
        "expired unspent funding must return to the buyer"
    );
    assert_eq!(refund.imported_amount_sat, expected);
    assert_wallet_refund(&mint, directory.path(), expected).await;
    assert_eq!(mint.state.lock().unwrap().swaps, 1);
    let again = restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
        .await
        .unwrap();
    assert!(again.complete);
    assert_eq!(again.imported_amount_sat, 0);
    assert_eq!(mint.state.lock().unwrap().swaps, 1);
}

#[tokio::test]
async fn expiry_refund_waits_before_expiry_and_while_mint_is_pending() {
    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, _) = mint.fund(directory.path(), u64::MAX / 2);
    assert!(
        !restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .unwrap()
            .complete
    );
    let expired = tempfile::tempdir().unwrap();
    let (id, _) = mint.fund_expired(expired.path()).await;
    mint.state.lock().unwrap().pending = true;
    assert!(
        !restore_streaming_route_cashu_spilman_refund(expired.path(), &id)
            .await
            .unwrap()
            .complete
    );
    assert_eq!(mint.state.lock().unwrap().swaps, 0);
}

#[tokio::test]
async fn expiry_refund_restores_after_lost_swap_response_and_restart() {
    if let Some(directory) = std::env::var_os("NVPN_TEST_REFUND_DIRECTORY") {
        let id = std::env::var("NVPN_TEST_REFUND_CHANNEL").unwrap();
        let expected: u64 = std::env::var("NVPN_TEST_REFUND_AMOUNT")
            .unwrap()
            .parse()
            .unwrap();
        let refund =
            restore_streaming_route_cashu_spilman_refund(std::path::Path::new(&directory), &id)
                .await
                .unwrap();
        assert!(refund.complete);
        assert_eq!(refund.imported_amount_sat, expected);
        return;
    }

    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    mint.state.lock().unwrap().drop_swap_response = true;
    assert!(
        restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .is_err()
    );
    assert!(mint.state.lock().unwrap().spent);
    // A new process reloads durable intent without inheriting the failed
    // connection's shared mint cooldown, exactly as a restarted daemon does.
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "expiry_refunds::expiry_refund_restores_after_lost_swap_response_and_restart",
            "--nocapture",
        ])
        .env("NVPN_TEST_REFUND_DIRECTORY", directory.path())
        .env("NVPN_TEST_REFUND_CHANNEL", &id)
        .env("NVPN_TEST_REFUND_AMOUNT", expected.to_string())
        .output()
        .await
        .unwrap();
    assert!(
        child.status.success(),
        "restarted recovery failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(
        mint.state.lock().unwrap().swaps,
        1,
        "recovery restores the exact original outputs"
    );
}

#[tokio::test]
async fn expiry_refund_preserves_recovery_after_bad_signature_or_partial_restore() {
    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    mint.state.lock().unwrap().corrupt_signature = true;
    assert!(
        restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .is_err()
    );
    let (storage, _) =
        FileSpilmanClientStorage::load(spilman_client_store_path(directory.path())).unwrap();
    assert_ne!(
        storage.get_state(&id),
        cdk_spilman::ClientChannelState::Closed
    );
    drop(storage);
    mint.state.lock().unwrap().incomplete_restore = true;
    assert!(
        restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .is_err()
    );
    let (storage, _) =
        FileSpilmanClientStorage::load(spilman_client_store_path(directory.path())).unwrap();
    assert_ne!(
        storage.get_state(&id),
        cdk_spilman::ClientChannelState::Closed
    );
    drop(storage);
    mint.state.lock().unwrap().incomplete_restore = false;
    let result = restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
        .await
        .unwrap();
    assert_eq!(result.imported_amount_sat, expected);
    assert_wallet_refund(&mint, directory.path(), expected).await;
    assert_eq!(mint.state.lock().unwrap().swaps, 1);
}

#[tokio::test]
async fn expiry_refund_requires_complete_unspent_funding_state() {
    let mint = Mint::new().await;
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    mint.state.lock().unwrap().malformed_state = true;
    assert!(
        restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .is_err()
    );
    {
        let mut state = mint.state.lock().unwrap();
        state.malformed_state = false;
        state.mixed_state = true;
    }
    assert!(
        !restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
            .await
            .unwrap()
            .complete
    );
    assert_eq!(mint.state.lock().unwrap().swaps, 0);
    mint.state.lock().unwrap().mixed_state = false;
    let result = restore_streaming_route_cashu_spilman_refund(directory.path(), &id)
        .await
        .unwrap();
    assert_eq!(result.imported_amount_sat, expected);
    assert_wallet_refund(&mint, directory.path(), expected).await;
}

#[tokio::test]
async fn explicit_mint_client_covers_expiry_swap_and_interrupted_import_restore() {
    let mut mint = Mint::new().await;
    let address: std::net::SocketAddr = mint.url.strip_prefix("http://").unwrap().parse().unwrap();
    mint.url = "http://refund-mint.invalid".to_owned();
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("refund-mint.invalid", address)
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (id, expected) = mint.fund_expired(directory.path()).await;
    let lock = || {
        cashu_service::SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(
            directory.path(),
        ))
        .unwrap()
    };
    let failed =
        cashu_service::restore_streaming_route_cashu_spilman_refund_with_wallet_and_client(
            directory.path(),
            &id,
            lock(),
            &mut false,
            &client,
            |_, _, _| async { anyhow::bail!("wallet import interrupted") },
        )
        .await;
    assert!(failed
        .unwrap_err()
        .to_string()
        .contains("wallet import interrupted"));
    let public_key = mint.secret.public_key();
    let result =
        cashu_service::restore_streaming_route_cashu_spilman_refund_with_wallet_and_client(
            directory.path(),
            &id,
            lock(),
            &mut false,
            &client,
            move |url, unit, json| async move {
                assert_eq!(url, "http://refund-mint.invalid");
                assert_eq!(unit, "sat");
                let proofs: Vec<Proof> = serde_json::from_str(&json)?;
                for proof in &proofs {
                    proof.verify_dleq(public_key)?;
                }
                let amount: u64 = proofs.iter().map(|proof| u64::from(proof.amount)).sum();
                assert_eq!(amount, expected);
                Ok(amount)
            },
        )
        .await
        .unwrap();
    assert!(result.complete);
    assert_eq!(result.imported_amount_sat, expected);
    let state = mint.state.lock().unwrap();
    assert_eq!(state.swaps, 1);
    for path in ["/v1/checkstate", "/v1/keysets", "/v1/swap", "/v1/restore"] {
        assert!(
            state.requests.iter().any(|request| request == path),
            "missing {path}"
        );
    }
    assert!(state
        .requests
        .iter()
        .any(|path| path.starts_with("/v1/keys/")));
}

#[cfg(feature = "spilman-configurable-host-reqwest")]
#[tokio::test]
async fn receiver_uses_explicit_mint_client_for_keysets_and_settlement() {
    use cashu_service::{
        CashuSpilmanPaymentReceiver, CashuSpilmanPaymentSigner, FileSpilmanPaymentReceiver,
        FileSpilmanPaymentReceiverConfig, FileSpilmanPaymentSigner,
    };

    let mut mint = Mint::new().await;
    let address = mint.url.strip_prefix("http://").unwrap().parse().unwrap();
    mint.url = "http://seller-mint.invalid".to_owned();
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("seller-mint.invalid", address)
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let seller = tempfile::tempdir().unwrap();
    let sender = tempfile::tempdir().unwrap();
    let mut config = FileSpilmanPaymentReceiverConfig::new([mint.url.clone()]);
    config.min_capacity = 1;
    let receiver = FileSpilmanPaymentReceiver::load(seller.path(), config)
        .unwrap()
        .with_http_client(client);
    receiver.refresh_keysets().await.unwrap();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let (channel, _) = mint.fund_for_receiver(
        sender.path(),
        expiry,
        cdk::nuts::PublicKey::from_hex(receiver.receiver_pubkey_hex()).unwrap(),
    );
    let signer = FileSpilmanPaymentSigner::load(sender.path()).unwrap();
    let payment = signer
        .sign_cashu_spilman_payment(&channel, 2, true)
        .unwrap();
    receiver
        .process_cashu_spilman_payment(&payment, &"{}".to_owned())
        .unwrap();
    let closed = receiver
        .close_cashu_spilman_channel(&channel)
        .await
        .unwrap();
    assert_eq!(closed.closed_amount, 2);
    // Nominal proofs include one sat to cover their later redemption fee.
    assert_eq!(closed.receiver_sum, 3);
    let proofs: Vec<Proof> = serde_json::from_str(&closed.receiver_proofs_json).unwrap();
    assert_eq!(proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(), 3);
    for proof in proofs {
        proof.verify_dleq(mint.secret.public_key()).unwrap();
    }
    assert!(
        receiver
            .close_cashu_spilman_channel(&channel)
            .await
            .unwrap()
            .already_closed
    );
    let state = mint.state.lock().unwrap();
    assert_eq!(state.swaps, 1);
    assert!(state.requests.iter().any(|path| path == "/v1/keysets"));
    assert!(state
        .requests
        .iter()
        .any(|path| path.starts_with("/v1/keys/")));
}
