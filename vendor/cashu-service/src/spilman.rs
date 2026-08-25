//! Experimental Cashu Spilman channel support for streaming paid routes.
//!
//! The upstream protocol and APIs are early-alpha. This module deliberately
//! exposes route-payment concepts and selected upstream primitives so consumers
//! can depend on `cashu-service` rather than coupling directly to the
//! implementation crate.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Upstream base revision for the local experimental Spilman checkout.
pub const CASHU_SPILMAN_CHANNELS_REV: &str = "d3032af0096a8db9770dbfc59db63e8a45dfde23";

/// Git repository containing the experimental Spilman implementation.
pub const CASHU_SPILMAN_CHANNELS_REPO: &str =
    "https://github.com/SatsAndSports/cashu_spilman_channels.git";

/// Unit used by a metered paid route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingRouteMeter {
    /// Charge by wall-clock time while a route lease is active.
    Milliseconds,
    /// Charge by tunneled bytes.
    Bytes,
    /// Charge by packets.
    Packets,
}

/// Seller-side policy for a metered route backed by a Cashu Spilman channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRoutePolicy {
    /// Meter used to compute the amount due.
    pub meter: StreamingRouteMeter,
    /// Price numerator in millisats.
    pub price_msat: u64,
    /// Price denominator in metered units.
    pub per_units: u64,
    /// Maximum buyer-funded channel capacity accepted for one route.
    pub max_channel_capacity_sat: u64,
    /// Expiry applied to newly opened channels.
    pub channel_expiry_secs: u64,
    /// Free probe budget before streaming payments are required.
    pub free_probe_units: u64,
    /// Small risk window allowed after the last valid balance update.
    pub grace_units: u64,
}

/// Seller routing state implied by route usage and the latest signed balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingRouteAccessState {
    /// Usage is still inside the seller's free probe allowance.
    FreeProbe,
    /// The latest signed balance fully covers current usage.
    Paid,
    /// Routing may continue, but only because the grace window still covers
    /// unpaid usage while the buyer sends a fresh balance update.
    Grace,
    /// Routing should stop until the buyer provides a larger signed balance.
    Suspended,
}

/// Route gating decision for a metered Spilman-backed route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteDecision {
    pub state: StreamingRouteAccessState,
    pub allow_routing: bool,
    pub delivered_units: u64,
    pub paid_msat: u64,
    pub amount_due_msat: u64,
    pub enforced_amount_due_msat: u64,
    pub unpaid_msat: u64,
    pub free_probe_remaining_units: u64,
    pub grace_remaining_units: u64,
}

/// Wire protocol version for Cashu-Spilman paid-route payment messages.
pub const STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION: u16 = 1;

/// Serializable snapshot of an upstream Spilman payment.
///
/// `balance` is denominated in the Cashu channel unit (`unit` in the route
/// envelope), while route accounting can additionally carry `paid_msat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSpilmanPayment {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_proofs: Option<Value>,
}

impl CashuSpilmanPayment {
    pub fn has_funding(&self) -> bool {
        self.params.is_some() && self.funding_proofs.is_some()
    }
}

/// Cashu denomination used by the Spilman channel balance.
///
/// Route accounting is denominated in millisats, while the underlying Cashu
/// channel may be funded in whole sats. Whole-sat channels round required
/// balances up so a signed update never underpays a metered route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingRouteCashuUnit {
    Sat,
    Msat,
}

impl StreamingRouteCashuUnit {
    pub fn parse(unit: &str) -> Result<Self, String> {
        match unit.trim().to_ascii_lowercase().as_str() {
            "" | "sat" | "sats" => Ok(Self::Sat),
            "msat" | "msats" => Ok(Self::Msat),
            other => Err(format!("unsupported Cashu channel unit '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sat => "sat",
            Self::Msat => "msat",
        }
    }

    pub fn balance_to_msat(self, balance: u64) -> u64 {
        match self {
            Self::Sat => balance.saturating_mul(1_000),
            Self::Msat => balance,
        }
    }

    pub fn balance_from_msat(self, paid_msat: u64) -> u64 {
        match self {
            Self::Sat => paid_msat.div_ceil(1_000),
            Self::Msat => paid_msat,
        }
    }

    pub fn capacity_from_sat(self, capacity_sat: u64) -> u64 {
        match self {
            Self::Sat => capacity_sat,
            Self::Msat => capacity_sat.saturating_mul(1_000),
        }
    }

    pub fn capacity_to_sat(self, capacity: u64) -> u64 {
        match self {
            Self::Sat => capacity,
            Self::Msat => capacity.div_ceil(1_000),
        }
    }
}

pub fn streaming_route_cashu_balance_msat(unit: &str, balance: u64) -> Result<u64, String> {
    Ok(StreamingRouteCashuUnit::parse(unit)?.balance_to_msat(balance))
}

pub fn streaming_route_cashu_balance_for_msat(unit: &str, paid_msat: u64) -> Result<u64, String> {
    Ok(StreamingRouteCashuUnit::parse(unit)?.balance_from_msat(paid_msat))
}

pub fn streaming_route_cashu_capacity_for_sat(
    unit: &str,
    capacity_sat: u64,
) -> Result<u64, String> {
    Ok(StreamingRouteCashuUnit::parse(unit)?.capacity_from_sat(capacity_sat))
}

pub fn streaming_route_cashu_capacity_sat(unit: &str, capacity: u64) -> Result<u64, String> {
    Ok(StreamingRouteCashuUnit::parse(unit)?.capacity_to_sat(capacity))
}

pub fn streaming_route_cashu_capacity_msat(unit: &str, capacity: u64) -> Result<u64, String> {
    Ok(StreamingRouteCashuUnit::parse(unit)?.balance_to_msat(capacity))
}

/// Kind of signed Spilman payment a buyer needs for route streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingRouteCashuPaymentKind {
    ChannelOpen,
    BalanceUpdate,
    CooperativeClose,
}

impl StreamingRouteCashuPaymentKind {
    pub fn include_funding(self) -> bool {
        matches!(self, Self::ChannelOpen)
    }
}

/// Request for creating a signed Cashu-Spilman payment for a paid route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuPaymentRequest {
    pub kind: StreamingRouteCashuPaymentKind,
    pub channel_id: String,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    pub paid_msat: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub previous_paid_msat: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub capacity_sat: u64,
}

/// Signed payment plus the route-accounting values that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuPaymentResult {
    pub payment: CashuSpilmanPayment,
    pub unit: String,
    pub balance: u64,
    pub paid_msat: u64,
    pub include_funding: bool,
}

/// Normalized result of validating a route-payment state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuPaymentProgressValidation {
    pub paid_msat: u64,
    pub previous_paid_msat: u64,
    pub capacity_msat: u64,
}

/// Normalized result of checking a route-payment claim against a signed
/// Cashu-Spilman payment snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuPaymentClaimValidation {
    pub channel_id: String,
    pub unit: String,
    pub balance: u64,
    pub paid_msat: u64,
    pub capacity_msat: u64,
    pub has_funding: bool,
}

/// Normalized result of receiver-side Cashu-Spilman payment validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSpilmanPaymentReceiverValidation {
    pub channel_id: String,
    pub balance: u64,
    pub amount_due: u64,
    pub capacity: u64,
}

/// Combined application-layer route claim and receiver-side Spilman result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuPaymentReceiverValidation {
    pub claim: StreamingRouteCashuPaymentClaimValidation,
    pub receiver: CashuSpilmanPaymentReceiverValidation,
}

/// Request for a fixed Cashu-token lease payment.
///
/// This is a fallback/dev mode for callers that cannot open a streaming
/// Spilman channel yet. The token is opaque to this crate; higher-level code
/// should redeem or verify it with the configured Cashu wallet before treating
/// the lease as settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuTokenLeaseRequest {
    pub channel_id: String,
    pub mint_url: String,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    /// Token amount in `unit`.
    pub amount: u64,
    /// Optional route-credit amount. Defaults to the token amount converted to
    /// millisats and must not exceed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_msat: Option<u64>,
    pub expires_unix: u64,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCashuTokenLease {
    pub channel_id: String,
    pub mint_url: String,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    pub amount: u64,
    pub paid_msat: u64,
    pub expires_unix: u64,
    pub token: String,
}

/// Small signer facade implemented by the local upstream Spilman client bridge.
///
/// Tests and app code can depend on this trait without coupling storage,
/// networking, or key management to `cashu-service`.
pub trait CashuSpilmanPaymentSigner {
    fn sign_cashu_spilman_payment(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<CashuSpilmanPayment, String>;

    fn sign_cashu_spilman_close(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<CashuSpilmanPayment, String> {
        self.sign_cashu_spilman_payment(channel_id, final_balance, false)
    }
}

/// Small receiver facade implemented by the upstream Spilman bridge.
///
/// Services can depend on this trait and the serializable payment snapshot
/// instead of coupling directly to `cdk-spilman` request/response types.
pub trait CashuSpilmanPaymentReceiver<C = String> {
    fn validate_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &C,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String>;

    fn process_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &C,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String>;
}

pub fn create_streaming_route_cashu_payment<S: CashuSpilmanPaymentSigner>(
    signer: &S,
    request: StreamingRouteCashuPaymentRequest,
) -> Result<StreamingRouteCashuPaymentResult, String> {
    let channel_id = request.channel_id.trim();
    if channel_id.is_empty() {
        return Err("missing Cashu Spilman channel id".to_string());
    }
    let unit = StreamingRouteCashuUnit::parse(&request.unit)?;
    validate_streaming_route_cashu_payment_progress(
        "paid route payment",
        request.paid_msat,
        request.previous_paid_msat,
        request.capacity_sat,
    )?;

    let balance = unit.balance_from_msat(request.paid_msat);
    let include_funding = request.kind.include_funding();
    let payment = if request.kind == StreamingRouteCashuPaymentKind::CooperativeClose {
        signer.sign_cashu_spilman_close(channel_id, balance)?
    } else {
        signer.sign_cashu_spilman_payment(channel_id, balance, include_funding)?
    };
    if payment.channel_id.trim() != channel_id {
        return Err(format!(
            "signed Cashu Spilman payment channel {} does not match requested channel {}",
            payment.channel_id, channel_id
        ));
    }
    if payment.balance != balance {
        return Err(format!(
            "signed Cashu Spilman payment balance {} does not match requested balance {}",
            payment.balance, balance
        ));
    }
    if include_funding && !payment.has_funding() {
        return Err("opening Cashu Spilman payment is missing funding data".to_string());
    }

    Ok(StreamingRouteCashuPaymentResult {
        payment,
        unit: unit.as_str().to_string(),
        balance,
        paid_msat: unit.balance_to_msat(balance),
        include_funding,
    })
}

/// Validate the monotonic paid-balance transition for a streaming route channel.
///
/// This helper is intentionally deterministic and transport-neutral so buyers,
/// sellers, CLIs, and native surfaces can reject stale/replayed balance updates
/// without duplicating capacity and regression checks.
pub fn validate_streaming_route_cashu_payment_progress(
    label: &str,
    paid_msat: u64,
    previous_paid_msat: u64,
    capacity_sat: u64,
) -> Result<StreamingRouteCashuPaymentProgressValidation, String> {
    let label = if label.trim().is_empty() {
        "paid route payment"
    } else {
        label.trim()
    };
    if paid_msat < previous_paid_msat {
        return Err(format!(
            "{label} amount regressed: {paid_msat} msat < {previous_paid_msat} msat"
        ));
    }
    let capacity_msat = capacity_sat.saturating_mul(1_000);
    if capacity_msat > 0 && paid_msat > capacity_msat {
        return Err(format!(
            "{label} {paid_msat} msat exceeds channel capacity {capacity_msat} msat"
        ));
    }

    Ok(StreamingRouteCashuPaymentProgressValidation {
        paid_msat,
        previous_paid_msat,
        capacity_msat,
    })
}

/// Verify transport-neutral route accounting fields against the signed Cashu
/// Spilman payment snapshot.
///
/// This does not replace upstream cryptographic validation by the receiver-side
/// Spilman bridge. It catches application-layer mismatches before a service
/// trusts `paid_msat`, such as a balance update claiming more route credit than
/// the included channel balance can represent.
pub fn validate_streaming_route_cashu_payment_claim(
    payment: &CashuSpilmanPayment,
    expected_channel_id: &str,
    unit: &str,
    claimed_paid_msat: u64,
    capacity_sat: u64,
    require_funding: bool,
) -> Result<StreamingRouteCashuPaymentClaimValidation, String> {
    let expected_channel_id = expected_channel_id.trim();
    if expected_channel_id.is_empty() {
        return Err("missing Cashu Spilman channel id".to_string());
    }
    let channel_id = payment.channel_id.trim();
    if channel_id != expected_channel_id {
        return Err(format!(
            "Cashu Spilman payment channel {channel_id} does not match expected channel {expected_channel_id}"
        ));
    }
    if payment.signature.trim().is_empty() {
        return Err("Cashu Spilman payment signature is empty".to_string());
    }
    if require_funding && !payment.has_funding() {
        return Err("opening Cashu Spilman payment is missing funding data".to_string());
    }

    let unit = StreamingRouteCashuUnit::parse(unit)?;
    let paid_msat = unit.balance_to_msat(payment.balance);
    if paid_msat != claimed_paid_msat {
        return Err(format!(
            "paid route payment claim {claimed_paid_msat} msat does not match Cashu Spilman balance {} {} ({} msat)",
            payment.balance,
            unit.as_str(),
            paid_msat
        ));
    }
    let capacity_msat = capacity_sat.saturating_mul(1_000);
    if capacity_msat > 0 && paid_msat > capacity_msat {
        return Err(format!(
            "paid route payment {paid_msat} msat exceeds channel capacity {capacity_msat} msat"
        ));
    }

    Ok(StreamingRouteCashuPaymentClaimValidation {
        channel_id: channel_id.to_string(),
        unit: unit.as_str().to_string(),
        balance: payment.balance,
        paid_msat,
        capacity_msat,
        has_funding: payment.has_funding(),
    })
}

// Kept flat for the public nVPN adapter API; grouping these established claim
// fields would add a second compatibility path without reducing protocol state.
#[allow(clippy::too_many_arguments)]
pub fn validate_streaming_route_cashu_payment_with_receiver<R, C>(
    receiver: &R,
    payment: &CashuSpilmanPayment,
    expected_channel_id: &str,
    unit: &str,
    claimed_paid_msat: u64,
    capacity_sat: u64,
    require_funding: bool,
    context: &C,
) -> Result<StreamingRouteCashuPaymentReceiverValidation, String>
where
    R: CashuSpilmanPaymentReceiver<C>,
{
    let claim = validate_streaming_route_cashu_payment_claim(
        payment,
        expected_channel_id,
        unit,
        claimed_paid_msat,
        capacity_sat,
        require_funding,
    )?;
    let receiver_validation = receiver.validate_cashu_spilman_payment(payment, context)?;
    streaming_route_receiver_validation_from_parts(claim, receiver_validation)
}

#[allow(clippy::too_many_arguments)]
pub fn process_streaming_route_cashu_payment_with_receiver<R, C>(
    receiver: &R,
    payment: &CashuSpilmanPayment,
    expected_channel_id: &str,
    unit: &str,
    claimed_paid_msat: u64,
    capacity_sat: u64,
    require_funding: bool,
    context: &C,
) -> Result<StreamingRouteCashuPaymentReceiverValidation, String>
where
    R: CashuSpilmanPaymentReceiver<C>,
{
    let claim = validate_streaming_route_cashu_payment_claim(
        payment,
        expected_channel_id,
        unit,
        claimed_paid_msat,
        capacity_sat,
        require_funding,
    )?;
    let receiver_validation = receiver.process_cashu_spilman_payment(payment, context)?;
    streaming_route_receiver_validation_from_parts(claim, receiver_validation)
}

fn streaming_route_receiver_validation_from_parts(
    claim: StreamingRouteCashuPaymentClaimValidation,
    receiver: CashuSpilmanPaymentReceiverValidation,
) -> Result<StreamingRouteCashuPaymentReceiverValidation, String> {
    if receiver.channel_id.trim() != claim.channel_id {
        return Err(format!(
            "Cashu Spilman receiver validated channel {} but route claim expected {}",
            receiver.channel_id, claim.channel_id
        ));
    }
    if receiver.balance != claim.balance {
        return Err(format!(
            "Cashu Spilman receiver validated balance {} but route claim expected {}",
            receiver.balance, claim.balance
        ));
    }
    Ok(StreamingRouteCashuPaymentReceiverValidation { claim, receiver })
}

pub fn create_streaming_route_cashu_token_lease(
    request: StreamingRouteCashuTokenLeaseRequest,
) -> Result<StreamingRouteCashuTokenLease, String> {
    let channel_id = request.channel_id.trim();
    if channel_id.is_empty() {
        return Err("missing Cashu token lease id".to_string());
    }
    let mint_url = request.mint_url.trim();
    if mint_url.is_empty() {
        return Err("missing Cashu token mint URL".to_string());
    }
    let token = request.token.trim();
    if token.is_empty() {
        return Err("missing Cashu token".to_string());
    }
    let unit = StreamingRouteCashuUnit::parse(&request.unit)?;
    let max_paid_msat = unit.balance_to_msat(request.amount);
    let paid_msat = request.paid_msat.unwrap_or(max_paid_msat);
    if paid_msat > max_paid_msat {
        return Err(format!(
            "paid route token lease credit {} msat exceeds token amount {} msat",
            paid_msat, max_paid_msat
        ));
    }

    Ok(StreamingRouteCashuTokenLease {
        channel_id: channel_id.to_string(),
        mint_url: mint_url.to_string(),
        unit: unit.as_str().to_string(),
        amount: request.amount,
        paid_msat,
        expires_unix: request.expires_unix,
        token: token.to_string(),
    })
}

/// Transport-neutral payment message for a metered route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRoutePaymentEnvelope {
    #[serde(default = "default_streaming_route_payment_protocol_version")]
    pub version: u16,
    /// Stable service/offer id in the seller's namespace.
    pub service_id: String,
    pub lease_id: String,
    pub buyer: String,
    pub seller: String,
    pub sent_at_unix: u64,
    pub payload: StreamingRoutePaymentPayload,
}

impl StreamingRoutePaymentEnvelope {
    pub fn new(
        service_id: impl Into<String>,
        lease_id: impl Into<String>,
        buyer: impl Into<String>,
        seller: impl Into<String>,
        sent_at_unix: u64,
        payload: StreamingRoutePaymentPayload,
    ) -> Self {
        Self {
            version: STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION,
            service_id: service_id.into(),
            lease_id: lease_id.into(),
            buyer: buyer.into(),
            seller: seller.into(),
            sent_at_unix,
            payload,
        }
    }

    pub fn channel_id(&self) -> &str {
        self.payload.channel_id()
    }
}

/// Route payment payloads exchanged between buyer and seller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamingRoutePaymentPayload {
    /// First payment for a channel, usually containing funding parameters and
    /// proofs so the seller can register the channel before charging traffic.
    ChannelOpen(StreamingRouteChannelOpen),
    /// Monotonic balance update as usage grows.
    BalanceUpdate(StreamingRouteBalanceUpdate),
    /// Buyer asks the seller to cooperatively close at a final balance.
    CooperativeClose(StreamingRouteCooperativeClose),
    /// Seller acknowledges close processing. Settlement receipt format is
    /// deliberately opaque while the upstream protocol is experimental.
    CooperativeCloseAck(StreamingRouteCooperativeCloseAck),
    /// Fixed Cashu token payment for a prepaid lease. This is a fallback/dev
    /// path; streaming Spilman channels remain the default for metered usage.
    CashuTokenLease(StreamingRouteCashuTokenLease),
}

impl StreamingRoutePaymentPayload {
    pub fn channel_id(&self) -> &str {
        match self {
            Self::ChannelOpen(open) => &open.payment.channel_id,
            Self::BalanceUpdate(update) => &update.payment.channel_id,
            Self::CooperativeClose(close) => &close.payment.channel_id,
            Self::CooperativeCloseAck(ack) => &ack.channel_id,
            Self::CashuTokenLease(lease) => &lease.channel_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteChannelOpen {
    pub mint_url: String,
    /// Cashu unit for `capacity` and `payment.balance`, for example `sat` or
    /// `msat`.
    pub unit: String,
    pub capacity: u64,
    pub expires_unix: u64,
    pub receiver_pubkey_hex: String,
    pub paid_msat: u64,
    pub payment: CashuSpilmanPayment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteBalanceUpdate {
    pub delivered_units: u64,
    pub amount_due_msat: u64,
    pub paid_msat: u64,
    pub payment: CashuSpilmanPayment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCooperativeClose {
    pub final_paid_msat: u64,
    pub payment: CashuSpilmanPayment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteCooperativeCloseAck {
    pub channel_id: String,
    pub accepted_balance: u64,
    pub accepted_paid_msat: u64,
    pub closed_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
}

impl StreamingRoutePolicy {
    /// Computes the millisats due for delivered route usage.
    pub fn amount_due_msat(&self, delivered_units: u64) -> u64 {
        let billable = delivered_units.saturating_sub(self.free_probe_units);
        if billable == 0 || self.price_msat == 0 {
            return 0;
        }

        let per_units = self.per_units.max(1) as u128;
        let total = billable as u128 * self.price_msat as u128;
        total.div_ceil(per_units) as u64
    }

    /// Returns true when a signed balance is sufficient to keep routing.
    pub fn is_balance_sufficient(&self, delivered_units: u64, paid_msat: u64) -> bool {
        self.routing_decision(delivered_units, paid_msat)
            .allow_routing
    }

    /// Computes the current route-gating decision from delivered usage and the
    /// latest signed Spilman balance.
    pub fn routing_decision(&self, delivered_units: u64, paid_msat: u64) -> StreamingRouteDecision {
        let amount_due_msat = self.amount_due_msat(delivered_units);
        let free_probe_remaining_units = self.free_probe_units.saturating_sub(delivered_units);
        let grace_limit_units = self.free_probe_units.saturating_add(self.grace_units);
        let grace_remaining_units = grace_limit_units.saturating_sub(delivered_units);
        let enforced_units = delivered_units.saturating_sub(self.grace_units);
        let enforced_amount_due_msat = self.amount_due_msat(enforced_units);
        let allow_routing =
            delivered_units <= grace_limit_units || paid_msat >= enforced_amount_due_msat;
        let unpaid_msat = amount_due_msat.saturating_sub(paid_msat);
        let state = if delivered_units <= self.free_probe_units {
            StreamingRouteAccessState::FreeProbe
        } else if paid_msat >= amount_due_msat {
            StreamingRouteAccessState::Paid
        } else if allow_routing {
            StreamingRouteAccessState::Grace
        } else {
            StreamingRouteAccessState::Suspended
        };

        StreamingRouteDecision {
            state,
            allow_routing,
            delivered_units,
            paid_msat,
            amount_due_msat,
            enforced_amount_due_msat,
            unpaid_msat,
            free_probe_remaining_units,
            grace_remaining_units,
        }
    }
}

fn default_streaming_route_payment_protocol_version() -> u16 {
    STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION
}

fn default_streaming_route_cashu_unit() -> String {
    StreamingRouteCashuUnit::Sat.as_str().to_string()
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(feature = "spilman")]
impl From<upstream::Payment> for CashuSpilmanPayment {
    fn from(payment: upstream::Payment) -> Self {
        Self {
            channel_id: payment.channel_id,
            balance: payment.balance,
            signature: payment.signature,
            params: payment.params,
            funding_proofs: payment
                .funding_proofs
                .map(|proofs| serde_json::to_value(proofs).expect("serialize funding proofs")),
        }
    }
}

#[cfg(feature = "spilman")]
impl TryFrom<CashuSpilmanPayment> for upstream::Payment {
    type Error = String;

    fn try_from(payment: CashuSpilmanPayment) -> Result<Self, Self::Error> {
        Ok(Self {
            channel_id: payment.channel_id,
            balance: payment.balance,
            signature: payment.signature,
            params: payment.params,
            funding_proofs: payment
                .funding_proofs
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| format!("invalid Spilman funding proofs: {error}"))?,
        })
    }
}

#[cfg(feature = "spilman")]
impl<H, N> CashuSpilmanPaymentSigner for upstream::SpilmanClientBridge<H, N>
where
    H: upstream::SpilmanClientHost,
    N: upstream::SpilmanClientNetworking,
{
    fn sign_cashu_spilman_payment(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        let payment = if include_funding {
            self.create_payment_with_funding(channel_id, balance)?
        } else {
            self.create_payment(channel_id, balance)?
        };
        Ok(payment.into())
    }

    fn sign_cashu_spilman_close(
        &self,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<CashuSpilmanPayment, String> {
        self.create_cooperative_close_request(channel_id, final_balance)
            .map(Into::into)
    }
}

#[cfg(feature = "spilman")]
impl<H, C> CashuSpilmanPaymentReceiver<C> for upstream::SpilmanBridge<H, C>
where
    H: upstream::SpilmanHost<C>,
{
    fn validate_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &C,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        let payment = upstream::Payment::try_from(payment.clone())?;
        let validated = self
            .validate_payment(
                &payment.channel_id,
                payment.balance,
                &payment.signature,
                payment.params.as_ref(),
                payment.funding_proofs.as_deref(),
                context,
            )
            .map_err(|error| error.to_string())?;
        Ok(CashuSpilmanPaymentReceiverValidation {
            channel_id: validated.channel_id,
            balance: validated.balance,
            amount_due: validated.amount_due,
            capacity: validated.capacity,
        })
    }

    fn process_cashu_spilman_payment(
        &self,
        payment: &CashuSpilmanPayment,
        context: &C,
    ) -> Result<CashuSpilmanPaymentReceiverValidation, String> {
        let payment = upstream::Payment::try_from(payment.clone())?;
        let processed = self
            .process_payment(
                &payment.channel_id,
                payment.balance,
                &payment.signature,
                payment.params.as_ref(),
                payment.funding_proofs.as_deref(),
                context,
            )
            .map_err(|error| error.to_string())?;
        Ok(CashuSpilmanPaymentReceiverValidation {
            channel_id: processed.channel_id,
            balance: processed.balance,
            amount_due: processed.amount_due,
            capacity: processed.capacity,
        })
    }
}

/// Re-exports of the pinned implementation crate for callers that need the
/// channel protocol while this crate grows higher-level route-payment APIs.
pub mod upstream {
    pub use cdk_spilman::{
        BalanceUpdateMessage, BridgeError, BridgeErrorResponse, ChannelFunding, ChannelId,
        ChannelParameters, ChannelPolicy, ChannelState, ClientChannelInfo, ClientChannelState,
        ClientPaymentState, ClientStorage, CloseData, CloseError, ClosePreparationError,
        CloseSuccess, ClosingData, EstablishedChannel, FundChannelResult, KeysetInfo,
        MemoryClientStorage, OpenChannelResult, Payment, PaymentProof, PaymentSuccess,
        PaymentValidationResult, PreparedClose, SpilmanBridge, SpilmanClientBridge,
        SpilmanClientHost, SpilmanClientNetworking, SpilmanHost, SpilmanNetworking, UnblindResult,
    };

    #[cfg(feature = "spilman-configurable-host")]
    pub use cdk_spilman::configurable_host;

    #[cfg(feature = "spilman-axum")]
    pub use cdk_spilman::axum;
}

#[cfg(test)]
mod tests;
