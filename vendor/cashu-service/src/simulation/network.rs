use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use cdk::cdk_payment::{
    self, Bolt11Settings, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions,
    MakePaymentResponse, MintPayment, OutgoingPaymentOptions, PaymentIdentifier,
    PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk::lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use cdk::nuts::{CurrencyUnit, MeltQuoteState};
use cdk::{Amount, Stream};
use cdk_common::bitcoin::hashes::{sha256, Hash};
use cdk_common::bitcoin::secp256k1::{Secp256k1, SecretKey};
use futures::stream;
use tokio::sync::broadcast;

use super::MonotonicClock;

const DEFAULT_INVOICE_LIFETIME_SECS: u64 = 3_600;
const EVENT_CAPACITY: usize = 256;

/// Whether a mint may send value outside its own proof set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerMode {
    /// Deposit-backed proofs can circulate and buy services, but cannot melt.
    ClosedLoop,
    /// Deposit-backed proofs may also melt through the simulated payment network.
    Withdrawable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceStatus {
    Unpaid,
    Paid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceSnapshot {
    pub recipient_mint: String,
    pub amount_sat: u64,
    pub expires_at: u64,
    pub status: InvoiceStatus,
    pub paid_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintReserveSnapshot {
    pub mint_id: String,
    pub mode: IssuerMode,
    /// Lightning-side sats available to settle this mint's withdrawals.
    pub reserve_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAccountingSnapshot {
    pub mints: Vec<MintReserveSnapshot>,
    pub total_reserve_sat: u64,
    pub fee_sink_sat: u64,
    pub total_accounted_sat: u64,
    pub external_funding_sat: u64,
}

impl SettlementAccountingSnapshot {
    pub fn is_conserved(&self) -> bool {
        self.total_accounted_sat == self.external_funding_sat
    }

    pub fn mint_reserve(&self, mint_id: &str) -> Option<u64> {
        self.mints
            .iter()
            .find(|mint| mint.mint_id == mint_id)
            .map(|mint| mint.reserve_sat)
    }
}

#[derive(Clone)]
pub struct PaymentNetwork {
    inner: Arc<NetworkInner>,
}

struct NetworkInner {
    seed: u64,
    fee_sat: u64,
    clock: Arc<dyn MonotonicClock>,
    state: Mutex<NetworkState>,
}

#[derive(Default)]
struct NetworkState {
    next_invoice: u64,
    invoices: HashMap<[u8; 32], InvoiceRecord>,
    modes: HashMap<String, IssuerMode>,
    online: HashMap<String, bool>,
    reserves: HashMap<String, u64>,
    external_funding_sat: u64,
    fee_sink_sat: u64,
    events: HashMap<String, broadcast::Sender<WaitPaymentResponse>>,
}

struct InvoiceRecord {
    recipient_mint: String,
    amount_sat: u64,
    expires_at: u64,
    preimage: [u8; 32],
    paid_by: Option<String>,
    fee_sat: u64,
}

impl fmt::Debug for PaymentNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentNetwork")
            .field("seed", &self.inner.seed)
            .field("fee_sat", &self.inner.fee_sat)
            .field("now", &self.inner.clock.now())
            .finish_non_exhaustive()
    }
}

/// Capability held by the simulation orchestrator, never by a participant.
///
/// It is the only API that creates value inside the isolated payment network.
/// Giving this to a simulated node would let that node counterfeit funding.
#[derive(Debug, Clone)]
pub struct OrchestratorFunding {
    network: PaymentNetwork,
}

impl OrchestratorFunding {
    pub fn settle_external(&self, payment_request: &str) -> Result<String, cdk_payment::Error> {
        self.network.settle_external(payment_request)
    }
}

impl PaymentNetwork {
    pub fn new(seed: u64, fee_sat: u64, clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            inner: Arc::new(NetworkInner {
                seed,
                fee_sat,
                clock,
                state: Mutex::new(NetworkState::default()),
            }),
        }
    }

    pub fn payment_backend(
        &self,
        mint_id: impl Into<String>,
        mode: IssuerMode,
    ) -> Result<SimMintPayment, cdk_payment::Error> {
        let mint_id = mint_id.into();
        if mint_id.is_empty() {
            return Err(custom_error("mint id cannot be empty"));
        }

        let mut state = self.state()?;
        if let Some(existing) = state.modes.get(&mint_id) {
            if *existing != mode {
                return Err(custom_error("mint id already has a different issuer mode"));
            }
        } else {
            state.modes.insert(mint_id.clone(), mode);
            state.online.insert(mint_id.clone(), true);
            state.reserves.insert(mint_id.clone(), 0);
            let (sender, _) = broadcast::channel(EVENT_CAPACITY);
            state.events.insert(mint_id.clone(), sender);
        }
        drop(state);

        Ok(SimMintPayment {
            mint_id,
            mode,
            network: self.clone(),
            wait_active: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Mint external value only from the simulation's trusted orchestrator.
    /// Participant/node objects should receive `SimMintPayment`, never this capability.
    pub fn orchestrator_funding(&self) -> OrchestratorFunding {
        OrchestratorFunding {
            network: self.clone(),
        }
    }

    pub fn set_online(&self, mint_id: &str, online: bool) -> Result<(), cdk_payment::Error> {
        let mut state = self.state()?;
        let entry = state
            .online
            .get_mut(mint_id)
            .ok_or_else(|| custom_error("unknown mint"))?;
        *entry = online;
        Ok(())
    }

    fn settle_external(&self, payment_request: &str) -> Result<String, cdk_payment::Error> {
        let invoice = parse_invoice(payment_request)?;
        let payment_hash = invoice_hash(&invoice);
        let (event, sender, preimage) = {
            let mut state = self.state()?;
            let now = self.inner.clock.now();
            let (recipient, amount_sat, preimage) = {
                let record = state
                    .invoices
                    .get(&payment_hash)
                    .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
                ensure_invoice_payable(record, &invoice, now)?;
                (
                    record.recipient_mint.clone(),
                    record.amount_sat,
                    record.preimage,
                )
            };
            if !state.online.get(&recipient).copied().unwrap_or(false) {
                return Err(custom_error("destination mint is offline"));
            }
            let funded_reserve = state
                .reserves
                .get(&recipient)
                .copied()
                .ok_or_else(|| custom_error("destination mint has no reserve account"))?
                .checked_add(amount_sat)
                .ok_or_else(|| custom_error("destination reserve overflow"))?;
            let external_funding_sat = state
                .external_funding_sat
                .checked_add(amount_sat)
                .ok_or_else(|| custom_error("external funding total overflow"))?;

            let event = {
                let record = state
                    .invoices
                    .get_mut(&payment_hash)
                    .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
                record.paid_by = Some("external".to_string());
                record.fee_sat = 0;
                incoming_response(payment_hash, record)
            };
            state.reserves.insert(recipient.clone(), funded_reserve);
            state.external_funding_sat = external_funding_sat;
            let sender = state.events.get(&recipient).cloned();
            (event, sender, preimage)
        };
        if let Some(sender) = sender {
            let _ = sender.send(event);
        }
        Ok(hex::encode(preimage))
    }

    pub fn accounting(&self) -> Result<SettlementAccountingSnapshot, cdk_payment::Error> {
        let state = self.state()?;
        if state.reserves.len() != state.modes.len() {
            return Err(custom_error("mint reserve accounts are inconsistent"));
        }
        let mut mints = state
            .modes
            .iter()
            .map(|(mint_id, mode)| {
                Ok(MintReserveSnapshot {
                    mint_id: mint_id.clone(),
                    mode: *mode,
                    reserve_sat: state
                        .reserves
                        .get(mint_id)
                        .copied()
                        .ok_or_else(|| custom_error("mint has no reserve account"))?,
                })
            })
            .collect::<Result<Vec<_>, cdk_payment::Error>>()?;
        mints.sort_by(|left, right| left.mint_id.cmp(&right.mint_id));
        let total_reserve_sat = mints.iter().try_fold(0_u64, |total, mint| {
            total
                .checked_add(mint.reserve_sat)
                .ok_or_else(|| custom_error("total reserve overflow"))
        })?;
        let total_accounted_sat = total_reserve_sat
            .checked_add(state.fee_sink_sat)
            .ok_or_else(|| custom_error("accounted value overflow"))?;
        Ok(SettlementAccountingSnapshot {
            mints,
            total_reserve_sat,
            fee_sink_sat: state.fee_sink_sat,
            total_accounted_sat,
            external_funding_sat: state.external_funding_sat,
        })
    }

    pub fn invoice(&self, payment_request: &str) -> Result<InvoiceSnapshot, cdk_payment::Error> {
        let invoice = parse_invoice(payment_request)?;
        let state = self.state()?;
        let record = state
            .invoices
            .get(&invoice_hash(&invoice))
            .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
        Ok(InvoiceSnapshot {
            recipient_mint: record.recipient_mint.clone(),
            amount_sat: record.amount_sat,
            expires_at: record.expires_at,
            status: if record.paid_by.is_some() {
                InvoiceStatus::Paid
            } else {
                InvoiceStatus::Unpaid
            },
            paid_by: record.paid_by.clone(),
        })
    }

    pub fn derive_seed(&self, mint_id: &str) -> [u8; 64] {
        let first = derive32(self.inner.seed, b"mint-seed-0", 0, mint_id);
        let second = derive32(self.inner.seed, b"mint-seed-1", 0, mint_id);
        let mut seed = [0_u8; 64];
        seed[..32].copy_from_slice(&first);
        seed[32..].copy_from_slice(&second);
        seed
    }

    fn create_invoice(
        &self,
        mint_id: &str,
        amount_sat: u64,
        description: String,
        requested_expiry: Option<u64>,
    ) -> Result<CreateIncomingPaymentResponse, cdk_payment::Error> {
        if amount_sat == 0 {
            return Err(cdk_payment::Error::AmountMismatch);
        }
        let now = self.inner.clock.now();
        let expires_at =
            requested_expiry.unwrap_or_else(|| now.saturating_add(DEFAULT_INVOICE_LIFETIME_SECS));
        if expires_at <= now {
            return Err(custom_error("invoice expiry is not in the future"));
        }

        let (invoice, payment_hash) = {
            let mut state = self.state()?;
            if !state.modes.contains_key(mint_id) {
                return Err(custom_error("unknown mint"));
            }
            let serial = state.next_invoice;
            state.next_invoice = state
                .next_invoice
                .checked_add(1)
                .ok_or_else(|| custom_error("invoice sequence overflow"))?;
            let preimage = derive32(self.inner.seed, b"preimage", serial, mint_id);
            let payment_hash = sha256::Hash::hash(&preimage).to_byte_array();
            let payment_secret = derive32(self.inner.seed, b"payment-secret", serial, mint_id);
            let signing_key = signing_key(self.inner.seed, mint_id)?;
            let invoice = InvoiceBuilder::new(Currency::Bitcoin)
                .description(description)
                .payment_hash(sha256::Hash::from_byte_array(payment_hash))
                .payment_secret(PaymentSecret(payment_secret))
                .amount_milli_satoshis(
                    amount_sat
                        .checked_mul(1_000)
                        .ok_or(cdk_payment::Error::AmountMismatch)?,
                )
                .duration_since_epoch(Duration::from_secs(now))
                .expiry_time(Duration::from_secs(expires_at - now))
                .min_final_cltv_expiry_delta(18)
                .build_signed(|message| {
                    Secp256k1::new().sign_ecdsa_recoverable(message, &signing_key)
                })
                .map_err(|error| custom_error(error.to_string()))?;
            state.invoices.insert(
                payment_hash,
                InvoiceRecord {
                    recipient_mint: mint_id.to_string(),
                    amount_sat,
                    expires_at,
                    preimage,
                    paid_by: None,
                    fee_sat: 0,
                },
            );
            (invoice, payment_hash)
        };

        Ok(CreateIncomingPaymentResponse {
            request_lookup_id: PaymentIdentifier::PaymentHash(payment_hash),
            request: invoice.to_string(),
            expiry: Some(expires_at),
            extra_json: None,
        })
    }

    fn quote(
        &self,
        mode: IssuerMode,
        unit: &CurrencyUnit,
        options: &OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, cdk_payment::Error> {
        ensure_withdrawable(mode)?;
        ensure_sat(unit)?;
        let (invoice, amount_sat, _) = outgoing_invoice(options)?;
        let state = self.state()?;
        let record = state
            .invoices
            .get(&invoice_hash(&invoice))
            .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
        ensure_invoice_payable(record, &invoice, self.inner.clock.now())?;
        ensure_amount(record, amount_sat)?;
        Ok(PaymentQuoteResponse {
            request_lookup_id: Some(PaymentIdentifier::PaymentHash(invoice_hash(&invoice))),
            amount: Amount::new(amount_sat, CurrencyUnit::Sat),
            fee: Amount::new(self.inner.fee_sat, CurrencyUnit::Sat),
            state: MeltQuoteState::Unpaid,
            extra_json: None,
            estimated_blocks: None,
            fee_options: None,
        })
    }

    fn pay(
        &self,
        payer: &str,
        mode: IssuerMode,
        unit: &CurrencyUnit,
        options: &OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, cdk_payment::Error> {
        ensure_withdrawable(mode)?;
        ensure_sat(unit)?;
        let (invoice, amount_sat, max_fee_sat) = outgoing_invoice(options)?;
        if max_fee_sat.is_some_and(|maximum| self.inner.fee_sat > maximum) {
            return Err(custom_error("payment fee exceeds maximum"));
        }
        let total_spent_sat = amount_sat
            .checked_add(self.inner.fee_sat)
            .ok_or(cdk_payment::Error::AmountMismatch)?;
        let payment_hash = invoice_hash(&invoice);
        let (event, sender, preimage) = {
            let mut state = self.state()?;
            let now = self.inner.clock.now();
            if !state.online.get(payer).copied().unwrap_or(false) {
                return Err(custom_error("source mint is offline"));
            }
            let (recipient, preimage) = {
                let record = state
                    .invoices
                    .get(&payment_hash)
                    .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
                ensure_invoice_payable(record, &invoice, now)?;
                ensure_amount(record, amount_sat)?;
                (record.recipient_mint.clone(), record.preimage)
            };
            if !state.online.get(&recipient).copied().unwrap_or(false) {
                return Err(custom_error("destination mint is offline"));
            }
            let payer_reserve = state
                .reserves
                .get(payer)
                .copied()
                .ok_or_else(|| custom_error("source mint has no reserve account"))?;
            let payer_after_debit = payer_reserve
                .checked_sub(total_spent_sat)
                .ok_or_else(|| custom_error("source mint has insufficient liquidity"))?;
            let recipient_reserve = state
                .reserves
                .get(&recipient)
                .copied()
                .ok_or_else(|| custom_error("destination mint has no reserve account"))?;
            let recipient_after_credit = if payer == recipient {
                payer_after_debit
                    .checked_add(amount_sat)
                    .ok_or_else(|| custom_error("mint reserve overflow"))?
            } else {
                recipient_reserve
                    .checked_add(amount_sat)
                    .ok_or_else(|| custom_error("destination reserve overflow"))?
            };
            let fee_sink_sat = state
                .fee_sink_sat
                .checked_add(self.inner.fee_sat)
                .ok_or_else(|| custom_error("fee sink overflow"))?;

            let event = {
                let record = state
                    .invoices
                    .get_mut(&payment_hash)
                    .ok_or_else(|| custom_error("invoice is not registered on this network"))?;
                record.paid_by = Some(payer.to_string());
                record.fee_sat = self.inner.fee_sat;
                incoming_response(payment_hash, record)
            };
            if payer == recipient {
                state
                    .reserves
                    .insert(payer.to_string(), recipient_after_credit);
            } else {
                state.reserves.insert(payer.to_string(), payer_after_debit);
                state
                    .reserves
                    .insert(recipient.clone(), recipient_after_credit);
            }
            state.fee_sink_sat = fee_sink_sat;
            let sender = state.events.get(&recipient).cloned();
            (event, sender, preimage)
        };
        if let Some(sender) = sender {
            let _ = sender.send(event);
        }
        Ok(MakePaymentResponse {
            payment_lookup_id: PaymentIdentifier::PaymentHash(payment_hash),
            payment_proof: Some(hex::encode(preimage)),
            status: MeltQuoteState::Paid,
            total_spent: Amount::new(total_spent_sat, CurrencyUnit::Sat),
        })
    }

    fn incoming_status(
        &self,
        mint_id: &str,
        identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, cdk_payment::Error> {
        let Some(payment_hash) = identifier_hash(identifier) else {
            return Ok(Vec::new());
        };
        let state = self.state()?;
        let Some(record) = state.invoices.get(&payment_hash) else {
            return Ok(Vec::new());
        };
        if record.recipient_mint != mint_id || record.paid_by.is_none() {
            return Ok(Vec::new());
        }
        Ok(vec![incoming_response(payment_hash, record)])
    }

    fn outgoing_status(
        &self,
        payer: &str,
        identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, cdk_payment::Error> {
        let payment_hash =
            identifier_hash(identifier).ok_or(cdk_payment::Error::UnknownPaymentState)?;
        let state = self.state()?;
        let record = state
            .invoices
            .get(&payment_hash)
            .ok_or(cdk_payment::Error::UnknownPaymentState)?;
        let paid = record.paid_by.as_deref() == Some(payer);
        Ok(MakePaymentResponse {
            payment_lookup_id: identifier.clone(),
            payment_proof: paid.then(|| hex::encode(record.preimage)),
            status: if paid {
                MeltQuoteState::Paid
            } else {
                MeltQuoteState::Unpaid
            },
            total_spent: Amount::new(
                if paid {
                    record.amount_sat.saturating_add(record.fee_sat)
                } else {
                    0
                },
                CurrencyUnit::Sat,
            ),
        })
    }

    fn subscribe(
        &self,
        mint_id: &str,
    ) -> Result<broadcast::Receiver<WaitPaymentResponse>, cdk_payment::Error> {
        self.state()?
            .events
            .get(mint_id)
            .map(broadcast::Sender::subscribe)
            .ok_or_else(|| custom_error("unknown mint"))
    }

    fn state(&self) -> Result<MutexGuard<'_, NetworkState>, cdk_payment::Error> {
        self.inner
            .state
            .lock()
            .map_err(|_| custom_error("payment network state poisoned"))
    }
}

#[derive(Clone)]
pub struct SimMintPayment {
    mint_id: String,
    mode: IssuerMode,
    network: PaymentNetwork,
    wait_active: Arc<AtomicBool>,
}

impl fmt::Debug for SimMintPayment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SimMintPayment")
            .field("mint_id", &self.mint_id)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl SimMintPayment {
    pub fn mint_id(&self) -> &str {
        &self.mint_id
    }

    pub fn mode(&self) -> IssuerMode {
        self.mode
    }
}

#[async_trait]
impl MintPayment for SimMintPayment {
    type Err = cdk_payment::Error;

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        Ok(SettingsResponse {
            unit: CurrencyUnit::Sat.to_string(),
            bolt11: Some(Bolt11Settings {
                mpp: false,
                amountless: false,
                invoice_description: true,
            }),
            bolt12: None,
            onchain: None,
            custom: HashMap::new(),
        })
    }

    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        let IncomingPaymentOptions::Bolt11(options) = options else {
            return Err(cdk_payment::Error::UnsupportedPaymentOption);
        };
        ensure_sat(options.amount.unit())?;
        self.network.create_invoice(
            &self.mint_id,
            options.amount.value(),
            options.description.unwrap_or_default(),
            options.unix_expiry,
        )
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        self.network.quote(self.mode, unit, &options)
    }

    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.network.pay(&self.mint_id, self.mode, unit, &options)
    }

    async fn wait_payment_event(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let receiver = self.network.subscribe(&self.mint_id)?;
        self.wait_active.store(true, Ordering::SeqCst);
        let active = Arc::clone(&self.wait_active);
        let events = stream::unfold((receiver, active), |(mut receiver, active)| async move {
            loop {
                if !active.load(Ordering::SeqCst) {
                    return None;
                }
                match receiver.recv().await {
                    Ok(response) => {
                        return Some((Event::PaymentReceived(response), (receiver, active)))
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(Box::pin(events))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.wait_active.load(Ordering::SeqCst)
    }

    fn cancel_payment_event_stream(&self) {
        self.wait_active.store(false, Ordering::SeqCst);
    }

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        self.network
            .incoming_status(&self.mint_id, payment_identifier)
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.network
            .outgoing_status(&self.mint_id, payment_identifier)
    }
}

fn outgoing_invoice(
    options: &OutgoingPaymentOptions,
) -> Result<(Bolt11Invoice, u64, Option<u64>), cdk_payment::Error> {
    let OutgoingPaymentOptions::Bolt11(options) = options else {
        return Err(cdk_payment::Error::UnsupportedPaymentOption);
    };
    let invoice_msat = options
        .bolt11
        .amount_milli_satoshis()
        .ok_or(cdk_payment::Error::AmountMismatch)?;
    let requested_msat = options
        .melt_options
        .as_ref()
        .map(|options| u64::from(options.amount_msat()))
        .unwrap_or(invoice_msat);
    if requested_msat != invoice_msat || requested_msat % 1_000 != 0 {
        return Err(cdk_payment::Error::AmountMismatch);
    }
    let max_fee_sat = options
        .max_fee_amount
        .as_ref()
        .map(|amount| {
            ensure_sat(amount.unit())?;
            Ok::<u64, cdk_payment::Error>(amount.value())
        })
        .transpose()?;
    Ok((options.bolt11.clone(), requested_msat / 1_000, max_fee_sat))
}

fn ensure_invoice_payable(
    record: &InvoiceRecord,
    invoice: &Bolt11Invoice,
    now: u64,
) -> Result<(), cdk_payment::Error> {
    if record.paid_by.is_some() {
        return Err(cdk_payment::Error::InvoiceAlreadyPaid);
    }
    if now >= record.expires_at {
        return Err(custom_error("invoice expired"));
    }
    let invoice_amount = invoice
        .amount_milli_satoshis()
        .ok_or(cdk_payment::Error::AmountMismatch)?;
    if invoice_amount != record.amount_sat.saturating_mul(1_000) {
        return Err(cdk_payment::Error::AmountMismatch);
    }
    Ok(())
}

fn ensure_amount(record: &InvoiceRecord, amount_sat: u64) -> Result<(), cdk_payment::Error> {
    if amount_sat != record.amount_sat {
        return Err(cdk_payment::Error::AmountMismatch);
    }
    Ok(())
}

fn ensure_withdrawable(mode: IssuerMode) -> Result<(), cdk_payment::Error> {
    if mode == IssuerMode::ClosedLoop {
        return Err(custom_error("closed-loop mint does not allow withdrawals"));
    }
    Ok(())
}

fn ensure_sat(unit: &CurrencyUnit) -> Result<(), cdk_payment::Error> {
    if unit != &CurrencyUnit::Sat {
        return Err(cdk_payment::Error::UnsupportedUnit);
    }
    Ok(())
}

fn incoming_response(payment_hash: [u8; 32], record: &InvoiceRecord) -> WaitPaymentResponse {
    WaitPaymentResponse {
        payment_identifier: PaymentIdentifier::PaymentHash(payment_hash),
        payment_amount: Amount::new(record.amount_sat, CurrencyUnit::Sat),
        payment_id: hex::encode(payment_hash),
    }
}

fn parse_invoice(payment_request: &str) -> Result<Bolt11Invoice, cdk_payment::Error> {
    Bolt11Invoice::from_str(payment_request).map_err(cdk_payment::Error::from)
}

fn invoice_hash(invoice: &Bolt11Invoice) -> [u8; 32] {
    *invoice.payment_hash().as_ref()
}

fn identifier_hash(identifier: &PaymentIdentifier) -> Option<[u8; 32]> {
    match identifier {
        PaymentIdentifier::PaymentHash(hash) => Some(*hash),
        _ => None,
    }
}

fn derive32(seed: u64, domain: &[u8], serial: u64, mint_id: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(16 + domain.len() + mint_id.len());
    material.extend_from_slice(&seed.to_be_bytes());
    material.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    material.extend_from_slice(domain);
    material.extend_from_slice(&serial.to_be_bytes());
    material.extend_from_slice(mint_id.as_bytes());
    sha256::Hash::hash(&material).to_byte_array()
}

fn signing_key(seed: u64, mint_id: &str) -> Result<SecretKey, cdk_payment::Error> {
    for counter in 0..u64::MAX {
        let candidate = derive32(seed, b"invoice-signing-key", counter, mint_id);
        if let Ok(key) = SecretKey::from_slice(&candidate) {
            return Ok(key);
        }
    }
    Err(custom_error("could not derive invoice signing key"))
}

fn custom_error(message: impl Into<String>) -> cdk_payment::Error {
    cdk_payment::Error::Custom(message.into())
}
