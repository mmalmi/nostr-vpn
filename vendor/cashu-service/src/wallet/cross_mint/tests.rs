use super::*;
use async_trait::async_trait;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, BlindSignature, CheckStateRequest,
    CheckStateResponse, CurrencyUnit, Id, KeySet, KeySetInfo, Keys, KeysetResponse,
    MeltQuoteBolt11Response, MeltRequest, MintInfo, MintQuoteBolt11Response, MintRequest,
    MintResponse, PaymentMethod, Proof, RestoreRequest, RestoreResponse, SecretKey, State,
    SwapRequest, SwapResponse,
};
use cdk::secret::Secret;
use cdk::wallet::{types::ProofInfo, MintConnector, WalletBuilder};
use cdk::{Amount, Error};
use cdk_common::{
    MeltQuoteCreateResponse, MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest,
    MintQuoteResponse,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

const K_VALID_BOLT11_INVOICE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const K_TEST_EXPIRY_UNIX: u64 = 4_102_444_800;

#[derive(Debug, Default)]
struct CrossMintTestState {
    paid: AtomicBool,
    destination_amount_sat: AtomicU64,
    delay_destination_once: AtomicBool,
    mint_quote_calls: AtomicUsize,
    melt_calls: AtomicUsize,
    mint_calls: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestMintRole {
    Source,
    Destination,
}

#[derive(Debug, Clone)]
struct LightningMockMintConnector {
    keyset: KeySet,
    quote_id: String,
    preimage: String,
    role: TestMintRole,
    fee_reserve_sat: u64,
    state: Arc<CrossMintTestState>,
}

impl LightningMockMintConnector {
    fn cross_mint_source(
        keyset: KeySet,
        state: Arc<CrossMintTestState>,
        fee_reserve_sat: u64,
    ) -> Self {
        Self {
            keyset,
            quote_id: "source-melt-quote".to_string(),
            preimage: "00ff".to_string(),
            role: TestMintRole::Source,
            fee_reserve_sat,
            state,
        }
    }

    fn cross_mint_destination(keyset: KeySet, state: Arc<CrossMintTestState>) -> Self {
        Self {
            keyset,
            quote_id: "destination-mint-quote".to_string(),
            preimage: String::new(),
            role: TestMintRole::Destination,
            fee_reserve_sat: 0,
            state,
        }
    }

    fn keyset_info(&self) -> KeySetInfo {
        KeySetInfo {
            id: self.keyset.id,
            unit: self.keyset.unit.clone(),
            active: self.keyset.active.unwrap_or(true),
            input_fee_ppk: self.keyset.input_fee_ppk,
            final_expiry: self.keyset.final_expiry,
        }
    }
}

#[async_trait]
impl MintConnector for LightningMockMintConnector {
    async fn fetch_lnurl_pay_request(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn fetch_lnurl_invoice(
        &self,
        _url: &str,
    ) -> Result<cdk::wallet::LnurlPayInvoiceResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn get_mint_keys(&self) -> Result<Vec<KeySet>, Error> {
        Ok(vec![self.keyset.clone()])
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        if keyset_id == self.keyset.id {
            Ok(self.keyset.clone())
        } else {
            Err(Error::UnknownKeySet)
        }
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        Ok(KeysetResponse {
            keysets: vec![self.keyset_info()],
        })
    }

    async fn post_mint_quote(
        &self,
        request: MintQuoteRequest,
    ) -> Result<MintQuoteResponse<String>, Error> {
        if self.role != TestMintRole::Destination {
            unreachable!("unused in Cashu Lightning payment test")
        }
        let MintQuoteRequest::Bolt11(request) = request else {
            unreachable!("unused payment method in cross-mint test")
        };
        self.state
            .destination_amount_sat
            .store(request.amount.to_u64(), Ordering::SeqCst);
        self.state.mint_quote_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MintQuoteResponse::Bolt11(MintQuoteBolt11Response {
            quote: self.quote_id.clone(),
            request: K_VALID_BOLT11_INVOICE.to_string(),
            amount: Some(request.amount),
            unit: Some(CurrencyUnit::Sat),
            state: MintQuoteState::Unpaid,
            expiry: Some(K_TEST_EXPIRY_UNIX),
            pubkey: request.pubkey,
        }))
    }

    async fn get_mint_quote_status(
        &self,
        _method: PaymentMethod,
        quote_id: &str,
    ) -> Result<MintQuoteResponse<String>, Error> {
        if self.role != TestMintRole::Destination || quote_id != self.quote_id {
            unreachable!("unused in Cashu Lightning payment test")
        }
        let paid = self.state.paid.load(Ordering::SeqCst);
        let delayed = paid
            && self
                .state
                .delay_destination_once
                .swap(false, Ordering::SeqCst);
        Ok(MintQuoteResponse::Bolt11(MintQuoteBolt11Response {
            quote: self.quote_id.clone(),
            request: K_VALID_BOLT11_INVOICE.to_string(),
            amount: Some(Amount::from(
                self.state.destination_amount_sat.load(Ordering::SeqCst),
            )),
            unit: Some(CurrencyUnit::Sat),
            state: if paid && !delayed {
                MintQuoteState::Paid
            } else {
                MintQuoteState::Unpaid
            },
            expiry: Some(K_TEST_EXPIRY_UNIX),
            pubkey: None,
        }))
    }

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        request: MintRequest<String>,
    ) -> Result<MintResponse, Error> {
        if self.role != TestMintRole::Destination || request.quote != self.quote_id {
            unreachable!("unused in Cashu Lightning payment test")
        }
        self.state.mint_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MintResponse {
            signatures: request
                .outputs
                .into_iter()
                .map(|output| BlindSignature {
                    amount: output.amount,
                    keyset_id: output.keyset_id,
                    c: SecretKey::generate().public_key(),
                    dleq: None,
                })
                .collect(),
        })
    }

    async fn post_melt_quote(
        &self,
        request: MeltQuoteRequest,
    ) -> Result<MeltQuoteCreateResponse<String>, Error> {
        let MeltQuoteRequest::Bolt11(request) = request else {
            unreachable!("unused payment method in Cashu Lightning payment test")
        };
        let amount_msat = request
            .request
            .amount_milli_satoshis()
            .ok_or(Error::InvoiceAmountUndefined)?;
        Ok(MeltQuoteCreateResponse::Bolt11(MeltQuoteBolt11Response {
            quote: self.quote_id.clone(),
            amount: Amount::from(amount_msat / 1000),
            fee_reserve: Amount::from(self.fee_reserve_sat),
            state: MeltQuoteState::Unpaid,
            expiry: K_TEST_EXPIRY_UNIX,
            payment_preimage: None,
            change: None,
            request: Some(request.request.to_string()),
            unit: Some(CurrencyUnit::Sat),
        }))
    }

    async fn get_melt_quote_status(
        &self,
        _method: PaymentMethod,
        quote_id: &str,
    ) -> Result<MeltQuoteResponse<String>, Error> {
        if self.role != TestMintRole::Source || quote_id != self.quote_id {
            unreachable!("unused in Cashu Lightning payment test")
        }
        Ok(MeltQuoteResponse::Bolt11(MeltQuoteBolt11Response {
            quote: self.quote_id.clone(),
            amount: Amount::from(
                Bolt11Invoice::from_str(K_VALID_BOLT11_INVOICE)
                    .unwrap()
                    .amount_milli_satoshis()
                    .unwrap()
                    / 1_000,
            ),
            fee_reserve: Amount::from(self.fee_reserve_sat),
            state: if self.state.paid.load(Ordering::SeqCst) {
                MeltQuoteState::Paid
            } else {
                MeltQuoteState::Unpaid
            },
            expiry: K_TEST_EXPIRY_UNIX,
            payment_preimage: self
                .state
                .paid
                .load(Ordering::SeqCst)
                .then(|| self.preimage.clone()),
            change: None,
            request: None,
            unit: Some(CurrencyUnit::Sat),
        }))
    }

    async fn post_melt(
        &self,
        _method: &PaymentMethod,
        request: MeltRequest<String>,
    ) -> Result<MeltQuoteResponse<String>, Error> {
        if request.quote_id() != &self.quote_id {
            return Err(Error::Custom("unexpected quote id".to_string()));
        }
        self.state.melt_calls.fetch_add(1, Ordering::SeqCst);
        self.state.paid.store(true, Ordering::SeqCst);
        Ok(MeltQuoteResponse::Bolt11(MeltQuoteBolt11Response {
            quote: self.quote_id.clone(),
            amount: Amount::from(250_000_u64),
            fee_reserve: Amount::from(self.fee_reserve_sat),
            state: MeltQuoteState::Paid,
            expiry: K_TEST_EXPIRY_UNIX,
            payment_preimage: Some(self.preimage.clone()),
            change: None,
            request: None,
            unit: Some(CurrencyUnit::Sat),
        }))
    }

    async fn post_swap(&self, _request: SwapRequest) -> Result<SwapResponse, Error> {
        unreachable!("exact proofs avoid the swap path in this test")
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        Ok(MintInfo::new())
    }

    async fn post_check_state(
        &self,
        _request: CheckStateRequest,
    ) -> Result<CheckStateResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn post_restore(&self, _request: RestoreRequest) -> Result<RestoreResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn get_auth_wallet(&self) -> Option<cdk::wallet::AuthWallet> {
        None
    }

    async fn set_auth_wallet(&self, _wallet: Option<cdk::wallet::AuthWallet>) {}

    async fn post_batch_check_mint_quote_status(
        &self,
        _method: &PaymentMethod,
        _request: BatchCheckMintQuoteRequest<String>,
    ) -> Result<Vec<MintQuoteResponse<String>>, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn post_batch_mint(
        &self,
        _method: &PaymentMethod,
        _request: BatchMintRequest<String>,
    ) -> Result<MintResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }
}

fn build_test_keyset(max_amount_sat: u64) -> KeySet {
    let mut keys_map = BTreeMap::new();
    let mut current = 1_u64;
    let mut seed_byte = 1_u8;
    while current <= max_amount_sat {
        let secret_key = SecretKey::from_slice(&[seed_byte; 32]).unwrap();
        keys_map.insert(Amount::from(current), secret_key.public_key());
        current <<= 1;
        seed_byte = seed_byte.saturating_add(1);
    }

    let keys = Keys::new(keys_map);
    KeySet {
        id: Id::v1_from_keys(&keys),
        unit: CurrencyUnit::Sat,
        active: Some(true),
        keys,
        input_fee_ppk: 0,
        final_expiry: None,
    }
}

fn make_test_proof(keyset_id: Id, amount: u64) -> Proof {
    Proof::new(
        Amount::from(amount),
        keyset_id,
        Secret::generate(),
        SecretKey::generate().public_key(),
    )
}

fn make_proof_info(keyset_id: Id, amount: u64, mint_url: MintUrl) -> ProofInfo {
    let proof = make_test_proof(keyset_id, amount);
    ProofInfo::new(proof, mint_url, State::Unspent, CurrencyUnit::Sat).unwrap()
}

fn binary_proof_infos(mint_url: MintUrl, keyset_id: Id, amount_sat: u64) -> Vec<ProofInfo> {
    let mut proofs = Vec::new();
    let mut remaining = amount_sat;
    let mut bit = 1_u64 << (63 - remaining.leading_zeros() as u64);
    while bit > 0 {
        if remaining >= bit {
            proofs.push(make_proof_info(keyset_id, bit, mint_url.clone()));
            remaining -= bit;
        }
        bit >>= 1;
    }
    proofs
}

async fn cross_mint_test_wallets(
    fee_reserve_sat: u64,
    state: Arc<CrossMintTestState>,
) -> (cdk::wallet::Wallet, cdk::wallet::Wallet) {
    let keyset = build_test_keyset(250_002);
    let source_mint: MintUrl = "https://source.example".parse().unwrap();
    let destination_mint: MintUrl = "https://destination.example".parse().unwrap();
    let db = cdk_sqlite::wallet::memory::empty().await.unwrap();
    db.update_proofs(
        binary_proof_infos(source_mint.clone(), keyset.id, 250_002),
        vec![],
    )
    .await
    .unwrap();
    let db = Arc::new(db);
    let source = WalletBuilder::new()
        .mint_url(source_mint)
        .unit(CurrencyUnit::Sat)
        .localstore(db.clone())
        .seed([11_u8; 64])
        .shared_client(Arc::new(LightningMockMintConnector::cross_mint_source(
            keyset.clone(),
            state.clone(),
            fee_reserve_sat,
        )))
        .build()
        .unwrap();
    let destination = WalletBuilder::new()
        .mint_url(destination_mint)
        .unit(CurrencyUnit::Sat)
        .localstore(db)
        .seed([12_u8; 64])
        .shared_client(Arc::new(
            LightningMockMintConnector::cross_mint_destination(keyset, state),
        ))
        .build()
        .unwrap();
    (source, destination)
}

fn cross_mint_request(transfer_id: &str) -> CashuCrossMintTransferRequest {
    CashuCrossMintTransferRequest {
        transfer_id: transfer_id.to_string(),
        source_mint_url: "https://source.example".to_string(),
        destination_mint_url: "https://destination.example".to_string(),
        amount_sat: 250_000,
        max_fee_sat: 2,
    }
}
#[tokio::test]
async fn test_cross_mint_transfer_pays_and_issues_exact_destination_quote_once() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;
    let request = cross_mint_request("transfer_1");

    let first = transfer_between_wallets(&source, &destination, request.clone())
        .await
        .unwrap();
    let retry = transfer_between_wallets(&source, &destination, request)
        .await
        .unwrap();

    assert_eq!(retry, first);
    assert_eq!(first.amount_sat, 250_000);
    assert_eq!(first.melt_fee_reserve_sat, 2);
    assert_eq!(first.wallet_fee_sat, 0);
    assert_eq!(first.fee_paid_sat, 2);
    assert_eq!(first.source_melt_quote_id, "source-melt-quote");
    assert_eq!(first.destination_mint_quote_id, "destination-mint-quote");
    assert_eq!(first.destination_balance_before_sat, 0);
    assert_eq!(first.destination_balance_after_sat, 250_000);
    assert_eq!(state.mint_quote_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_cross_mint_transfer_recovers_after_payment_before_destination_refresh() {
    let state = Arc::new(CrossMintTestState::default());
    state.delay_destination_once.store(true, Ordering::SeqCst);
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;
    let request = cross_mint_request("transfer_recovery");

    let interrupted = transfer_between_wallets(&source, &destination, request.clone())
        .await
        .unwrap_err();
    assert!(interrupted.to_string().contains("unexpected state"));
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(destination.total_balance().await.unwrap().to_u64(), 0);

    // Completion must be tied to this transfer's mint quote, not to an exact
    // whole-wallet balance delta. Other wallet activity may happen while a
    // paid transfer is being recovered.
    let keyset = build_test_keyset(250_002);
    destination
        .localstore
        .update_proofs(
            vec![make_proof_info(keyset.id, 1, destination.mint_url.clone())],
            vec![],
        )
        .await
        .unwrap();

    let recovered = transfer_between_wallets(&source, &destination, request)
        .await
        .unwrap();
    assert_eq!(recovered.destination_balance_after_sat, 250_001);
    assert_eq!(state.mint_quote_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_cross_mint_transfer_rejects_fee_before_payment() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(3, state.clone()).await;
    let request = cross_mint_request("transfer_fee_limit");

    let error = transfer_between_wallets(&source, &destination, request)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("exceeds caller maximum"));
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 0);
    assert_eq!(destination.total_balance().await.unwrap().to_u64(), 0);
}

#[tokio::test]
async fn test_cross_mint_resume_never_starts_a_new_payment() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;

    let error = transfer_between_wallets_with_start(
        &source,
        &destination,
        cross_mint_request("missing_saga"),
        false,
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("no durable saga to resume"));
    assert_eq!(state.mint_quote_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_cross_mint_resume_does_not_pay_a_preflight_only_saga() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;
    let request = cross_mint_request("preflight_only");
    save_cross_mint_transfer_saga(
        &source,
        &CashuCrossMintTransferSaga {
            version: K_CROSS_MINT_TRANSFER_VERSION,
            request: request.clone(),
            destination_balance_before_sat: 0,
            destination_mint_quote_id: None,
            destination_payment_request: None,
            source_melt_quote_id: None,
            melt_fee_reserve_sat: None,
            wallet_fee_sat: None,
            fee_paid_sat: None,
            result: None,
        },
    )
    .await
    .unwrap();

    let error = transfer_between_wallets_with_start(&source, &destination, request, false)
        .await
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("has not started a source payment"));
    assert_eq!(state.mint_quote_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_cross_mint_transfer_rejects_wrong_invoice_amount_before_payment() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;
    let mut request = cross_mint_request("transfer_wrong_amount");
    request.amount_sat = 249_999;

    let error = transfer_between_wallets(&source, &destination, request)
        .await
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("does not match requested amount"));
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.mint_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_cross_mint_transfer_id_cannot_be_rebound() {
    let state = Arc::new(CrossMintTestState::default());
    let (source, destination) = cross_mint_test_wallets(2, state.clone()).await;
    let request = cross_mint_request("transfer_bound");
    transfer_between_wallets(&source, &destination, request.clone())
        .await
        .unwrap();
    let mut changed = request;
    changed.max_fee_sat = 3;

    let error = transfer_between_wallets(&source, &destination, changed)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("bound to a different request"));
    assert_eq!(state.melt_calls.load(Ordering::SeqCst), 1);
}
