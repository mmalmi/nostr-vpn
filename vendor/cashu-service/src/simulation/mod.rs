//! Deterministic, isolated Cashu settlement support for adversarial simulations.
//!
//! CDK still handles mint quotes, proofs, swaps, melts, and SQLite persistence.
//! Only the Lightning payment backend is simulated.

mod clock;
mod mint;
mod network;

pub use clock::{ClockError, MonotonicClock, VirtualClock};
pub use mint::LocalMint;
pub use network::{
    InvoiceSnapshot, InvoiceStatus, IssuerMode, MintReserveSnapshot, OrchestratorFunding,
    PaymentNetwork, SettlementAccountingSnapshot, SimMintPayment,
};

#[cfg(test)]
mod tests;
