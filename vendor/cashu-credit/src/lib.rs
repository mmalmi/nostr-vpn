//! Transport-neutral accounting for peer-issued Cashu and service receipts.
//!
//! Cryptography and Cashu proof validation deliberately live outside this
//! crate. Callers must verify receipt signatures and mint proofs before
//! passing the authenticated issuer identity to [`CreditAccount`].

mod account;
mod error;
mod ledger;
mod protocol;
mod snapshot;

pub use account::CreditAccount;
pub use error::CreditError;
pub use ledger::{ClosedLoopLedger, PeerCreditLedger, WithdrawableReserveLedger};
pub use protocol::{
    AcceptanceMode, AccountPolicy, BackedCreditSettlement, BackingDeposit, ClosedLoopConsumption,
    CreditNovation, ExternalSettlementAuthorization, ExternalSettlementRequest, IssuerPolicy,
    PeerCreditCancellation, ReceiptApplication, ServiceReceiptClaim, ValueClass,
};
pub use snapshot::{CreditAccountSnapshotV1, SnapshotError};
