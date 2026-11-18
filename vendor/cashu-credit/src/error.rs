#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CreditError {
    #[error("invalid peer-credit cancellation or reused cancellation id")]
    InvalidCancellation,
    #[error("account has no trusted issuer with this identity")]
    WrongIssuer,
    #[error("claim is for a different counterparty")]
    WrongCounterparty,
    #[error("the supplied authenticated identity does not match the issuer")]
    UnauthenticatedIssuer,
    #[error("the supplied authenticated identity does not match the counterparty")]
    UnauthenticatedCounterparty,
    #[error("issuer policy has expired")]
    PolicyExpired,
    #[error("receipt has expired")]
    ReceiptExpired,
    #[error("receipt was issued in the future")]
    ReceiptNotYetValid,
    #[error("receipt id is empty")]
    MissingReceiptId,
    #[error("receipt id was reused with different contents")]
    ReceiptConflict,
    #[error("backing deposit id is empty")]
    MissingDepositId,
    #[error("backing deposit id was reused with different contents")]
    DepositConflict,
    #[error("backed settlement id is empty")]
    MissingBackedSettlementId,
    #[error("backed settlement has expired")]
    BackedSettlementExpired,
    #[error("backed settlement id was reused with different contents")]
    BackedSettlementConflict,
    #[error("closed-loop consumption id is empty")]
    MissingClosedLoopConsumptionId,
    #[error("closed-loop consumption id was reused with different contents")]
    ClosedLoopConsumptionConflict,
    #[error("peer credit is not a backed settlement class")]
    UnsupportedBackingClass,
    #[error("receipt does not describe useful service")]
    NoUsefulService,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("credit account revision overflow")]
    RevisionOverflow,
    #[error("issuer peer-credit exposure exceeded")]
    IssuerExposureExceeded,
    #[error("aggregate peer-credit exposure exceeded")]
    TotalExposureExceeded,
    #[error("offline peer-credit exposure exceeded")]
    OfflineExposureExceeded,
    #[error("deposit- or reserve-backed value requires live proof verification")]
    BackingVerificationRequired,
    #[error("issuer does not have enough available closed-loop backing")]
    InsufficientClosedLoopBacking,
    #[error("issuer does not have enough available withdrawable reserve")]
    InsufficientAvailableReserve,
    #[error("issuer does not have enough externally redeemable reserve")]
    InsufficientRedeemableReserve,
    #[error("issuer closed-loop exposure exceeded")]
    ClosedLoopExposureExceeded,
    #[error("issuer withdrawable exposure exceeded")]
    WithdrawableExposureExceeded,
    #[error("peer-credit balance is insufficient")]
    InsufficientPeerCredit,
    #[error("novation has expired")]
    NovationExpired,
    #[error("novation id is empty")]
    MissingNovationId,
    #[error("novation id was reused with different contents")]
    NovationConflict,
    #[error("novation must change issuer")]
    SameIssuerNovation,
    #[error("settlement has expired")]
    SettlementExpired,
    #[error("settlement id is empty")]
    MissingSettlementId,
    #[error("settlement payout destination is empty")]
    MissingPayoutDestination,
    #[error("settlement id was reused with different contents")]
    SettlementConflict,
    #[error("settlement completion conflicts with the recorded fee")]
    SettlementCompletionConflict,
    #[error("settlement backend fee exceeded its authorized maximum")]
    SettlementFeeExceeded,
    #[error("settlement was already cancelled")]
    SettlementCancelled,
    #[error("settlement was already completed")]
    SettlementCompleted,
    #[error("unknown settlement id")]
    UnknownSettlement,
    #[error("account policy lists an issuer more than once")]
    DuplicateIssuer,
    #[error("account has no issuers")]
    NoIssuers,
    #[error("account policy is invalid")]
    InvalidPolicy,
    #[error("unsupported credit account snapshot version")]
    UnsupportedSnapshotVersion,
    #[error("credit account snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    #[error("an internal conservation invariant was violated")]
    ConservationViolation,
}
