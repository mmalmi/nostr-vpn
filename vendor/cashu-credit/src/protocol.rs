use serde::{Deserialize, Serialize};

/// The backing and redemption capability of value issued for useful service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueClass {
    /// Relationship-local, unbacked credit. It is never externally redeemable.
    PeerCredit,
    /// Deposit-backed value usable inside the issuer's economy, without cashout.
    ClosedLoopDeposit,
    /// Reserve-backed sats that may authorize an external Cashu or LN settlement.
    ReserveBackedWithdrawable,
}

/// Whether accepting a claim required live issuer/proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptanceMode {
    Online,
    OfflineDeferred,
}

/// An unsigned, application-neutral acknowledgement of useful service.
///
/// The issuer is the transfer initiator or sponsor and the peer-credit payer;
/// it need not be the packet sender or recipient. The counterparty is the
/// provider being paid. The caller signs and verifies the serialized claim;
/// signatures stay outside it so applications can reuse their identity scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReceiptClaim {
    /// Globally unique idempotency key chosen by the issuer.
    pub receipt_id: String,
    /// Authenticated requester/sponsor and peer-credit issuer.
    pub issuer: String,
    /// Peer that supplied the useful service and accepts the value.
    pub counterparty: String,
    /// Application-defined meter, such as `pubsub_delivery` or `nvpn_tcp_acked`.
    pub service: String,
    /// Canonical application scope, such as an FSP destination/service/budget,
    /// a pubsub subscription, an nVPN route, or a Hashtree object.
    pub resource: String,
    /// Application-defined useful quantity (bytes, packets, or lease ticks).
    pub useful_service_units: u64,
    /// Sat-denominated value issued in the explicitly named class.
    pub amount_sat: u64,
    pub value_class: ValueClass,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

/// Per-issuer limits selected by the counterparty accepting value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerPolicy {
    pub issuer: String,
    pub max_peer_credit_sat: u64,
    pub max_offline_peer_credit_sat: u64,
    pub max_closed_loop_sat: u64,
    pub max_withdrawable_sat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
}

/// Counterparty-local trust policy across all accepted issuers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    pub counterparty: String,
    /// Aggregate cap for unbacked peer credit across every trusted issuer.
    pub max_total_peer_credit_sat: u64,
    pub issuers: Vec<IssuerPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptApplication {
    Applied,
    AlreadyApplied,
}

/// Shift an existing unbacked liability to another trusted peer issuer.
///
/// The caller must verify value from `to_issuer`. Novation never creates
/// withdrawable value and never reduces aggregate peer-credit exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreditNovation {
    pub novation_id: String,
    pub counterparty: String,
    pub from_issuer: String,
    pub to_issuer: String,
    pub amount_sat: u64,
    pub expires_at_unix: u64,
}

/// The holder voluntarily extinguishes an existing unbacked claim, for example
/// after a separately verified reciprocal service settlement. This never credits
/// a reserve or authorizes withdrawal. The holder must durably bind the external
/// evidence to this cancellation before publishing an acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCreditCancellation {
    pub cancellation_id: String,
    pub counterparty: String,
    pub issuer: String,
    pub amount_sat: u64,
}

/// A deposit already verified by the Cashu or Lightning adapter.
///
/// `deposit_id` must be the adapter's stable quote, payment, or operation ID.
/// Replaying the same deposit is harmless; changing its contents is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackingDeposit {
    pub deposit_id: String,
    pub issuer: String,
    pub amount_sat: u64,
    pub value_class: ValueClass,
}

/// Replace peer credit with a verified backed liability from an accepted issuer.
///
/// A third-party mint is represented by `backing_issuer` differing from the
/// service consumer in `from_issuer`. Closed-loop settlement clears the IOU
/// without creating cashout authority; withdrawable settlement may later be
/// consumed by an [`ExternalSettlementRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackedCreditSettlement {
    pub settlement_id: String,
    pub counterparty: String,
    pub from_issuer: String,
    pub backing_issuer: String,
    pub amount_sat: u64,
    pub value_class: ValueClass,
    pub expires_at_unix: u64,
}

/// Idempotent spend of closed-loop value for a named issuer service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedLoopConsumption {
    pub consumption_id: String,
    pub issuer: String,
    pub counterparty: String,
    pub resource: String,
    pub amount_sat: u64,
}

/// Unsigned request by the counterparty to consume withdrawable backing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSettlementRequest {
    pub settlement_id: String,
    pub issuer: String,
    pub counterparty: String,
    /// Canonical adapter destination: a normalized mint URL or exact invoice.
    pub payout_destination: String,
    pub amount_sat: u64,
    /// Maximum fee the counterparty permits the backend to spend.
    pub max_fee_sat: u64,
    pub expires_at_unix: u64,
}

/// Idempotent authority for an external settlement backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSettlementAuthorization {
    pub settlement_id: String,
    pub issuer: String,
    pub counterparty: String,
    pub payout_destination: String,
    pub amount_sat: u64,
    pub max_fee_sat: u64,
    /// Principal plus the fee ceiling reserved before backend execution.
    pub reserved_sat: u64,
    pub authorized_at_unix: u64,
    pub expires_at_unix: u64,
}
