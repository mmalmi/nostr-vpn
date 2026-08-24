use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use cashu_service::{
    CashuSpilmanPayment, CashuSpilmanPaymentReceiver, CashuSpilmanPaymentSigner,
    STREAMING_ROUTE_PAYMENT_PROTOCOL_VERSION, StreamingRouteBalanceUpdate,
    StreamingRouteCashuPaymentKind, StreamingRouteCashuPaymentRequest,
    StreamingRouteCashuTokenLease, StreamingRouteCashuTokenLeaseRequest, StreamingRouteChannelOpen,
    StreamingRouteCooperativeClose, StreamingRoutePaymentEnvelope, StreamingRoutePaymentPayload,
    create_streaming_route_cashu_payment, create_streaming_route_cashu_token_lease,
    process_streaming_route_cashu_payment_with_receiver, streaming_route_cashu_balance_for_msat,
    streaming_route_cashu_balance_msat, streaming_route_cashu_capacity_for_sat,
    streaming_route_cashu_capacity_sat, validate_streaming_route_cashu_payment_claim,
    validate_streaming_route_cashu_payment_progress,
};
use nostr_sdk::prelude::{PublicKey, ToBech32, Url};
use serde::{Deserialize, Serialize};

use crate::config::normalize_nostr_pubkey;
use crate::paid_routes::{
    PaidExitConfig, PaidRouteAccessState, PaidRouteLease, PaidRouteOffer, PaidRoutePaymentMode,
    PaidRoutePaymentState, PaidRouteQualityMetrics, PaidRouteQuote, PaidRouteSession,
    PaidRouteSessionOpen, PaidRouteUsage, SignedPaidRouteOffer,
};

const CURRENT_VERSION: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteStore {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub wallet: PaidRouteWalletState,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub offers: BTreeMap<String, PaidRouteOfferRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quotes: BTreeMap<String, PaidRouteQuoteRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub leases: BTreeMap<String, PaidRouteLeaseRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, PaidRouteChannelRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sessions: BTreeMap<String, PaidRouteSessionRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub buyer_session_admissions: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selected_buyer_session_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub buyer_session_open_attempts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seller_session_tunnel_ips: BTreeMap<String, String>,
}

impl Default for PaidRouteStore {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            wallet: PaidRouteWalletState::default(),
            offers: BTreeMap::new(),
            quotes: BTreeMap::new(),
            leases: BTreeMap::new(),
            channels: BTreeMap::new(),
            sessions: BTreeMap::new(),
            buyer_session_admissions: BTreeMap::new(),
            selected_buyer_session_id: String::new(),
            buyer_session_open_attempts: BTreeMap::new(),
            seller_session_tunnel_ips: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteWalletState {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_mint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mints: Vec<PaidRouteWalletMint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteWalletMint {
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_msat: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_checked_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteOfferRecord {
    pub signed_offer: SignedPaidRouteOffer,
    pub offer: PaidRouteOffer,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating_score: Option<i64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rating_updated_at_unix: u64,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteQuoteRecord {
    pub quote: PaidRouteQuote,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteLeaseRecord {
    pub lease: PaidRouteLease,
    pub status: PaidRouteLifecycleStatus,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteChannelRecord {
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub offer_id: String,
    pub role: PaidRouteChannelRole,
    pub status: PaidRouteLifecycleStatus,
    #[serde(default)]
    pub payment: PaidRoutePaymentState,
    /// Immutable pricing and routing terms accepted when this channel opened.
    ///
    /// Legacy records without a snapshot fail closed instead of inheriting a
    /// later offer or seller configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_terms: Option<PaidExitConfig>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mint_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub counterparty_npub: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at_unix: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaidRouteChannelRole {
    Buyer,
    Seller,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaidRouteLifecycleStatus {
    Opening,
    Probing,
    Active,
    Paused,
    Closing,
    Closed,
    Expired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteSessionRecord {
    pub session: PaidRouteSession,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePaidRouteSessionProbeRequest {
    pub session_id: String,
    pub realized_exit_ip: Option<String>,
    pub observed_country_code: Option<String>,
    pub observed_asn: Option<u32>,
    pub quality: Option<PaidRouteQualityMetrics>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePaidRouteSessionProbeResult {
    pub session_id: String,
    pub changed: bool,
    pub realized_exit_ip: Option<String>,
    pub observed_country_code: Option<String>,
    pub observed_asn: Option<u32>,
    pub quality: Option<PaidRouteQualityMetrics>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaidRouteBuyerSessionLifecycleReconcile {
    pub changed: bool,
    pub selected_session_timed_out: bool,
    pub selected_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPaidRouteBuyerSessionRequest {
    pub offer_selector: String,
    pub buyer_npub: String,
    pub mint_url: Option<String>,
    pub channel_capacity_sat: Option<u64>,
    pub initial_paid_msat: u64,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPaidRouteBuyerSessionResult {
    pub offer_key: String,
    pub offer_id: String,
    pub seller_npub: String,
    pub mint_url: String,
    pub quote_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub session_id: String,
    pub channel_capacity_sat: u64,
    pub expires_at_unix: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteAutomaticOfferSelection {
    pub offer_key: String,
    pub mint_url: String,
    pub channel_capacity_sat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPaidRouteBuyerPaymentEnvelopeKind {
    ChannelOpen,
    BalanceUpdate,
    CooperativeClose,
}

impl BuildPaidRouteBuyerPaymentEnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelOpen => "channel_open",
            Self::BalanceUpdate => "balance_update",
            Self::CooperativeClose => "cooperative_close",
        }
    }
}

impl From<BuildPaidRouteBuyerPaymentEnvelopeKind> for StreamingRouteCashuPaymentKind {
    fn from(kind: BuildPaidRouteBuyerPaymentEnvelopeKind) -> Self {
        match kind {
            BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen => Self::ChannelOpen,
            BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate => Self::BalanceUpdate,
            BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose => Self::CooperativeClose,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPaidRouteBuyerPaymentEnvelopeRequest {
    pub session_id: String,
    pub buyer_npub: String,
    pub kind: BuildPaidRouteBuyerPaymentEnvelopeKind,
    pub payment: CashuSpilmanPayment,
    pub delivered_units: Option<u64>,
    pub paid_msat: Option<u64>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPaidRouteBuyerTokenLeaseEnvelopeRequest {
    pub session_id: String,
    pub buyer_npub: String,
    pub mint_url: String,
    pub cashu_unit: String,
    pub amount: u64,
    pub paid_msat: Option<u64>,
    pub token: String,
    pub expires_at_unix: Option<u64>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPaidRouteBuyerSpilmanChannelRequest {
    pub session_id: String,
    pub channel_id: String,
    pub cashu_unit: String,
    pub capacity_sat: u64,
    pub paid_msat: Option<u64>,
    pub payment: CashuSpilmanPayment,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachPaidRouteBuyerSpilmanChannelResult {
    pub previous_channel_id: String,
    pub channel_id: String,
    pub session_id: String,
    pub lease_id: String,
    pub paid_msat: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
    pub session_id: String,
    pub buyer_npub: String,
    pub kind: BuildPaidRouteBuyerPaymentEnvelopeKind,
    pub delivered_units: Option<u64>,
    pub paid_msat: Option<u64>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaidRouteBuyerPaymentSigningPlan {
    channel_id: String,
    unit: String,
    previous_paid_msat: u64,
    capacity_sat: u64,
    delivered_units: u64,
    paid_msat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaidRouteBuyerUsageSession {
    seller_pubkey: String,
    seller_npub: String,
    session_id: String,
    lease_id: String,
    channel_id: String,
    config: PaidExitConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPaidRouteBuyerPaymentEnvelopeResult {
    pub envelope: StreamingRoutePaymentEnvelope,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub offer_id: String,
    pub buyer_npub: String,
    pub seller_npub: String,
    pub payload_type: String,
    pub paid_msat: u64,
    pub delivered_units: u64,
    pub amount_due_msat: u64,
    pub unpaid_msat: u64,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPaidRouteBuyerSignedPaymentEnvelopeForDueResult {
    pub due: PaidRouteBuyerPaymentUpdateDue,
    pub payment: BuildPaidRouteBuyerPaymentEnvelopeResult,
    pub store: PaidRouteStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPaidRouteSellerPaymentRequest {
    pub envelope: StreamingRoutePaymentEnvelope,
    pub seller_npub: String,
    pub config: PaidExitConfig,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPaidRouteSellerPaymentResult {
    pub service_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub session_id: String,
    pub buyer_npub: String,
    pub seller_npub: String,
    pub payload_type: String,
    pub paid_msat: u64,
    pub delivered_units: u64,
    pub amount_due_msat: u64,
    pub unpaid_msat: u64,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPaidRouteSellerSessionOpenRequest {
    pub open: PaidRouteSessionOpen,
    pub authenticated_buyer_pubkey: String,
    pub seller_npub: String,
    pub config: PaidExitConfig,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPaidRouteSellerSessionOpenResult {
    pub service_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub session_id: String,
    pub buyer_npub: String,
    pub seller_npub: String,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy)]
struct SellerPaymentApplyContext<'a> {
    config: &'a PaidExitConfig,
    service_id: &'a str,
    lease_id: &'a str,
    channel_id: &'a str,
    buyer_npub: &'a str,
    now_unix: u64,
}

#[derive(Debug, Clone, Copy)]
struct BuyerPaymentApplyContext<'a> {
    session_id: &'a str,
    channel_id: &'a str,
    lease_id: &'a str,
    kind: BuildPaidRouteBuyerPaymentEnvelopeKind,
    delivered_units: u64,
    paid_msat: u64,
    unit: &'a str,
    now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPaidRouteSellerUsageRequest {
    pub buyer_pubkey: String,
    pub config: PaidExitConfig,
    pub usage_delta: PaidRouteUsage,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPaidRouteSellerUsageResult {
    pub buyer_pubkey: String,
    pub buyer_npub: String,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub usage: PaidRouteUsage,
    pub paid_msat: u64,
    pub amount_due_msat: u64,
    pub unpaid_msat: u64,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPaidRouteBuyerUsageRequest {
    pub seller_pubkey: String,
    pub usage_delta: PaidRouteUsage,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPaidRouteBuyerUsageResult {
    pub seller_pubkey: String,
    pub seller_npub: String,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub usage: PaidRouteUsage,
    pub paid_msat: u64,
    pub amount_due_msat: u64,
    pub unpaid_msat: u64,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidRouteBuyerPaymentUpdatesDueRequest {
    pub now_unix: u64,
    pub min_increment_msat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteBuyerPaymentUpdateDue {
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub offer_id: String,
    pub seller_npub: String,
    pub delivered_units: u64,
    pub paid_msat: u64,
    pub amount_due_msat: u64,
    pub target_paid_msat: u64,
    pub payment_increment_msat: u64,
    pub unpaid_msat: u64,
    pub remaining_unpaid_msat: u64,
    pub capacity_msat: u64,
    pub capacity_exhausted: bool,
    pub allow_routing: bool,
    pub state: PaidRouteAccessState,
    pub expires_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteSellerAdmission {
    pub buyer_pubkey: String,
    pub buyer_npub: String,
    pub buyer_tunnel_ip: String,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_allowed_ips: Vec<String>,
    pub state: PaidRouteAccessState,
    pub allow_routing: bool,
    pub amount_due_msat: u64,
    pub paid_msat: u64,
    pub unpaid_msat: u64,
    pub expires_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteSellerCollectionState {
    pub buyer_npub: String,
    pub session_id: String,
    pub lease_id: String,
    pub channel_id: String,
    pub collectable: bool,
    pub manual_collect: bool,
    pub auto_collect_due: bool,
    pub reason: String,
    pub paid_msat: u64,
    pub expires_at_unix: u64,
    pub due_at_unix: u64,
    pub updated_at_unix: u64,
}

mod automatic_selection;
mod buyer_payment;
mod buyer_session;
mod persistence;
mod seller_payment;
mod seller_state;
mod session_open;
mod wallet_offers;

pub use wallet_offers::normalize_paid_route_mint_url;

pub use automatic_selection::{
    PAID_ROUTE_AUTO_MAX_CHANNEL_CAPACITY_SAT, PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB,
    PAID_ROUTE_AUTO_MIN_FREE_PROBE_BYTES,
};
pub use persistence::{
    acknowledge_paid_route_payment_outbox, apply_paid_route_seller_payment_file,
    load_paid_route_store, paid_route_offer_store_key, paid_route_payment_id,
    paid_route_payment_outbox_directory, paid_route_store_file_path, update_paid_route_store,
    upsert_paid_route_offer,
};
use persistence::{default_version, is_zero};
#[cfg(test)]
mod tests;
