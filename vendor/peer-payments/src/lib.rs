//! Shared service-credit agreements. Amounts are sats of issuer-local credit,
//! never a promise of bitcoin redemption. No mint, wallet or transport is needed.
//!
//! Adapters verify signatures and service evidence before accounting. Durable
//! reservations precede admission; uncertain delivery never releases exposure.

#[cfg(feature = "social-graph")]
pub mod discovery;

mod account;
mod book;
mod buyer;
mod controller;
mod protocol;
mod signature;
mod store;

pub use account::Account;
pub use book::{Allowance, Book, Exposure, Grant, Limits};
pub use buyer::{Buyer, SpendingLimits};
pub use controller::{ControlMessage, Controller, Opened, PurchaseIntent};
pub use protocol::{Agreement, Netting, Receipt, Signed, Verifier, WireMessage, WIRE_VERSION};
pub use secp256k1::Keypair;
pub use signature::{sign_message, SchnorrVerifier};
pub use store::{AccountStore, BuyerStore, DurableState, PaymentStore};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid payment record: {0}")]
    Invalid(&'static str),
    #[error("signature or authenticated identity does not match")]
    Authentication,
    #[error("operation ID was reused with different terms")]
    Conflict,
    #[error("peer credit is disabled or this issuer is not accepted")]
    NotAccepted,
    #[error("payment record is expired")]
    Expired,
    #[error("credit, spending or retained-history limit reached")]
    Limit,
    #[error("unknown agreement")]
    Unknown,
    #[error("agreement is closed")]
    Closed,
    #[error("stale cumulative receipt")]
    Regressed,
    #[error("payment store owner or revision does not match")]
    StoreConflict,
    #[error(transparent)]
    Credit(#[from] cashu_credit::CreditError),
    #[error(transparent)]
    Snapshot(#[from] cashu_credit::SnapshotError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
