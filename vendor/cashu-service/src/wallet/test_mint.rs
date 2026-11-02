use super::*;
use async_trait::async_trait;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::{
    BatchCheckMintQuoteRequest, BatchMintRequest, CheckStateRequest, CheckStateResponse,
    CurrencyUnit, Id, KeySet, KeySetInfo, Keys, KeysetResponse, MeltQuoteBolt11Response,
    MeltRequest, MintInfo, MintRequest, MintResponse, P2PKWitness, PaymentMethod, Proof,
    RestoreRequest, RestoreResponse, SecretKey, State, SwapRequest, SwapResponse, Witness,
};
use cdk::secret::Secret;
use cdk::wallet::{
    types::{KeysetLoadPolicy, ProofInfo},
    MintConnector, WalletBuilder,
};
use cdk::{Amount, Error};
use cdk_common::{
    MeltQuoteCreateResponse, MeltQuoteRequest, MeltQuoteResponse, MintQuoteRequest,
    MintQuoteResponse,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const K_VALID_BOLT11_INVOICE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const K_TEST_EXPIRY_UNIX: u64 = 4_102_444_800;

#[derive(Debug, Clone)]
struct LightningMockMintConnector {
    keyset: Arc<Mutex<KeySet>>,
    additional_keysets: Arc<Mutex<Vec<KeySet>>>,
    fail_keysets: Arc<std::sync::atomic::AtomicBool>,
    quote_id: String,
    preimage: String,
    melt_fee_reserve: u64,
    melt_amount: Arc<Mutex<u64>>,
    melt_inputs: Arc<Mutex<Vec<Proof>>>,
    spent: Arc<Mutex<std::collections::HashSet<cdk::nuts::PublicKey>>>,
    swap_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl LightningMockMintConnector {
    fn new(keyset: KeySet, quote_id: &str, preimage: &str) -> Self {
        Self {
            keyset: Arc::new(Mutex::new(keyset)),
            additional_keysets: Arc::new(Mutex::new(Vec::new())),
            fail_keysets: Default::default(),
            quote_id: quote_id.to_string(),
            preimage: preimage.to_string(),
            melt_fee_reserve: 0,
            melt_amount: Default::default(),
            melt_inputs: Default::default(),
            spent: Default::default(),
            swap_calls: Default::default(),
        }
    }

    fn keyset_info(&self) -> KeySetInfo {
        let keyset = self.keyset.lock().unwrap();
        KeySetInfo {
            id: keyset.id,
            unit: keyset.unit.clone(),
            active: keyset.active.unwrap_or(true),
            input_fee_ppk: keyset.input_fee_ppk,
            final_expiry: keyset.final_expiry,
        }
    }

    fn rotate_keyset(&self, keyset: KeySet) {
        let mut current = self.keyset.lock().unwrap();
        current.active = Some(false);
        self.additional_keysets
            .lock()
            .unwrap()
            .push(current.clone());
        *current = keyset;
    }

    fn add_keyset(&self, keyset: KeySet) {
        self.additional_keysets.lock().unwrap().push(keyset);
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
        let mut keysets = vec![self.keyset.lock().unwrap().clone()];
        keysets.extend(self.additional_keysets.lock().unwrap().clone());
        Ok(keysets)
    }

    async fn get_mint_keyset(&self, keyset_id: Id) -> Result<KeySet, Error> {
        let keyset = self.keyset.lock().unwrap();
        if keyset_id == keyset.id {
            Ok(keyset.clone())
        } else {
            self.additional_keysets
                .lock()
                .unwrap()
                .iter()
                .find(|candidate| candidate.id == keyset_id)
                .cloned()
                .ok_or(Error::UnknownKeySet)
        }
    }

    async fn get_mint_keysets(&self) -> Result<KeysetResponse, Error> {
        if self.fail_keysets.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::UnknownKeySet);
        }
        let mut keysets = vec![self.keyset_info()];
        keysets.extend(
            self.additional_keysets
                .lock()
                .unwrap()
                .iter()
                .map(|keyset| KeySetInfo {
                    id: keyset.id,
                    unit: keyset.unit.clone(),
                    active: keyset.active.unwrap_or(true),
                    input_fee_ppk: keyset.input_fee_ppk,
                    final_expiry: keyset.final_expiry,
                }),
        );
        Ok(KeysetResponse { keysets })
    }

    async fn post_mint_quote(
        &self,
        _request: MintQuoteRequest,
    ) -> Result<MintQuoteResponse<String>, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn get_mint_quote_status(
        &self,
        _method: PaymentMethod,
        _quote_id: &str,
    ) -> Result<MintQuoteResponse<String>, Error> {
        unreachable!("unused in Cashu Lightning payment test")
    }

    async fn post_mint(
        &self,
        _method: &PaymentMethod,
        _request: MintRequest<String>,
    ) -> Result<MintResponse, Error> {
        unreachable!("unused in Cashu Lightning payment test")
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
        *self.melt_amount.lock().unwrap() = amount_msat / 1000;
        Ok(MeltQuoteCreateResponse::Bolt11(MeltQuoteBolt11Response {
            method: PaymentMethod::Known(cdk_common::nut00::KnownMethod::Bolt11),
            quote: self.quote_id.clone(),
            amount: Amount::from(amount_msat / 1000),
            fee_reserve: Amount::from(self.melt_fee_reserve),
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
        assert_eq!(quote_id, self.quote_id);
        Ok(MeltQuoteResponse::Bolt11(MeltQuoteBolt11Response {
            method: PaymentMethod::Known(cdk_common::nut00::KnownMethod::Bolt11),
            quote: self.quote_id.clone(),
            amount: Amount::from(*self.melt_amount.lock().unwrap()),
            fee_reserve: Amount::from(self.melt_fee_reserve),
            state: if self.melt_inputs.lock().unwrap().is_empty() {
                MeltQuoteState::Unpaid
            } else {
                MeltQuoteState::Paid
            },
            expiry: K_TEST_EXPIRY_UNIX,
            payment_preimage: None,
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
        let amount = *self.melt_amount.lock().unwrap();
        let input_total: u64 = request.inputs().iter().map(|p| p.amount.to_u64()).sum();
        let input_fee =
            (request.inputs().len() as u64 * self.keyset_info().input_fee_ppk).div_ceil(1000);
        let change_amount = input_total
            .checked_sub(amount + self.melt_fee_reserve + input_fee)
            .ok_or(Error::InsufficientFunds)?;
        let outputs = request.outputs().as_deref().unwrap_or_default();
        let amounts: Vec<_> = (0..64)
            .filter_map(|bit| {
                let denomination = 1_u64 << bit;
                (change_amount & denomination != 0).then_some(Amount::from(denomination))
            })
            .collect();
        assert!(
            amounts.len() <= outputs.len(),
            "wallet must provide enough change outputs"
        );
        let change = amounts
            .into_iter()
            .zip(outputs)
            .map(|(amount, output)| sign_test_output(amount, output))
            .collect::<Vec<_>>();
        *self.melt_inputs.lock().unwrap() = request.inputs().clone();
        self.spent
            .lock()
            .unwrap()
            .extend(request.inputs().iter().map(|proof| proof.y().unwrap()));
        Ok(MeltQuoteResponse::Bolt11(MeltQuoteBolt11Response {
            method: PaymentMethod::Known(cdk_common::nut00::KnownMethod::Bolt11),
            quote: self.quote_id.clone(),
            amount: Amount::from(amount),
            fee_reserve: Amount::from(self.melt_fee_reserve),
            state: MeltQuoteState::Paid,
            expiry: K_TEST_EXPIRY_UNIX,
            payment_preimage: Some(self.preimage.clone()),
            change: (!change.is_empty()).then_some(change),
            request: None,
            unit: Some(CurrencyUnit::Sat),
        }))
    }

    async fn post_swap(&self, request: SwapRequest) -> Result<SwapResponse, Error> {
        self.swap_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let fee = (request.inputs().len() as u64 * self.keyset_info().input_fee_ppk).div_ceil(1000);
        let input: u64 = request.inputs().iter().map(|p| p.amount.to_u64()).sum();
        let output: u64 = request.outputs().iter().map(|p| p.amount.to_u64()).sum();
        assert_eq!(
            input - fee,
            output,
            "mint swap must cover its actual input fees"
        );
        self.spent
            .lock()
            .unwrap()
            .extend(request.inputs().iter().map(|proof| proof.y().unwrap()));
        let signatures = request
            .outputs()
            .iter()
            .map(|message| sign_test_output(message.amount, message))
            .collect();
        Ok(SwapResponse { signatures })
    }

    async fn get_mint_info(&self) -> Result<MintInfo, Error> {
        Ok(MintInfo::new())
    }

    async fn post_check_state(
        &self,
        request: CheckStateRequest,
    ) -> Result<CheckStateResponse, Error> {
        let spent = self.spent.lock().unwrap();
        Ok(CheckStateResponse {
            states: request
                .ys
                .into_iter()
                .map(|y| cdk::nuts::ProofState {
                    y,
                    state: if spent.contains(&y) {
                        State::Spent
                    } else {
                        State::Unspent
                    },
                    witness: None,
                })
                .collect(),
        })
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

fn sign_test_output(
    amount: Amount,
    message: &cdk::nuts::BlindedMessage,
) -> cdk::nuts::BlindSignature {
    let index = amount.to_u64().trailing_zeros() as u8 + 1;
    let secret = SecretKey::from_slice(&[index; 32]).unwrap();
    let mut signature = cdk::nuts::BlindSignature {
        amount,
        keyset_id: message.keyset_id,
        c: cdk::dhke::sign_message(&secret, &message.blinded_secret).unwrap(),
        dleq: None,
    };
    signature
        .add_dleq_proof(&message.blinded_secret, &secret)
        .unwrap();
    signature
}
