use crate::{
    AcceptanceMode, AccountPolicy, BackedCreditSettlement, BackingDeposit, ClosedLoopConsumption,
    ClosedLoopLedger, CreditError, CreditNovation, ExternalSettlementAuthorization,
    ExternalSettlementRequest, IssuerPolicy, PeerCreditCancellation, PeerCreditLedger,
    ReceiptApplication, ServiceReceiptClaim, ValueClass, WithdrawableReserveLedger,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PeerCreditEvent {
    Cancellation {
        revision: u64,
        cancellation_id: String,
    },
    Receipt {
        revision: u64,
        receipt_id: String,
        mode: AcceptanceMode,
    },
    Novation {
        revision: u64,
        novation_id: String,
    },
    BackedSettlement {
        revision: u64,
        settlement_id: String,
    },
}

impl PeerCreditEvent {
    pub(crate) fn revision(&self) -> u64 {
        match self {
            Self::Receipt { revision, .. }
            | Self::Cancellation { revision, .. }
            | Self::Novation { revision, .. }
            | Self::BackedSettlement { revision, .. } => *revision,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuerState {
    pub(crate) policy: IssuerPolicy,
    pub(crate) peer_credit: PeerCreditLedger,
    pub(crate) closed_loop: ClosedLoopLedger,
    pub(crate) withdrawable: WithdrawableReserveLedger,
}

impl IssuerState {
    fn new(policy: IssuerPolicy) -> Self {
        Self {
            policy,
            peer_credit: PeerCreditLedger::default(),
            closed_loop: ClosedLoopLedger::default(),
            withdrawable: WithdrawableReserveLedger::default(),
        }
    }

    fn ensure_active(&self, now_unix: u64) -> Result<(), CreditError> {
        if self
            .policy
            .expires_at_unix
            .is_some_and(|expires| expires <= now_unix)
        {
            return Err(CreditError::PolicyExpired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettlementState {
    Pending,
    Completed { fee_sat: u64 },
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SettlementRecord {
    pub(crate) request: ExternalSettlementRequest,
    pub(crate) authorization: ExternalSettlementAuthorization,
    pub(crate) state: SettlementState,
}

/// Counterparty-local accounting across a bounded set of trusted issuers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditAccount {
    pub(crate) revision: u64,
    pub(crate) counterparty: String,
    pub(crate) max_total_peer_credit_sat: u64,
    pub(crate) total_peer_credit_sat: u64,
    pub(crate) issuers: BTreeMap<String, IssuerState>,
    pub(crate) applied_receipts: BTreeMap<String, ServiceReceiptClaim>,
    pub(crate) peer_credit_events: Vec<PeerCreditEvent>,
    pub(crate) novations: BTreeMap<String, CreditNovation>,
    pub(crate) cancellations: BTreeMap<String, PeerCreditCancellation>,
    pub(crate) backing_deposits: BTreeMap<(String, String), BackingDeposit>,
    pub(crate) backed_settlements: BTreeMap<String, BackedCreditSettlement>,
    pub(crate) closed_loop_consumptions: BTreeMap<String, ClosedLoopConsumption>,
    pub(crate) settlements: BTreeMap<String, SettlementRecord>,
}

impl CreditAccount {
    pub fn new(policy: AccountPolicy) -> Result<Self, CreditError> {
        if policy.counterparty.trim().is_empty() {
            return Err(CreditError::InvalidPolicy);
        }
        if policy.issuers.is_empty() {
            return Err(CreditError::NoIssuers);
        }
        let mut issuers = BTreeMap::new();
        for issuer in policy.issuers {
            if issuer.issuer.trim().is_empty()
                || issuer.max_offline_peer_credit_sat > issuer.max_peer_credit_sat
            {
                return Err(CreditError::InvalidPolicy);
            }
            let id = issuer.issuer.clone();
            if issuers.insert(id, IssuerState::new(issuer)).is_some() {
                return Err(CreditError::DuplicateIssuer);
            }
        }
        Ok(Self {
            revision: 0,
            counterparty: policy.counterparty,
            max_total_peer_credit_sat: policy.max_total_peer_credit_sat,
            total_peer_credit_sat: 0,
            issuers,
            applied_receipts: BTreeMap::new(),
            peer_credit_events: Vec::new(),
            novations: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            backing_deposits: BTreeMap::new(),
            backed_settlements: BTreeMap::new(),
            closed_loop_consumptions: BTreeMap::new(),
            settlements: BTreeMap::new(),
        })
    }

    pub fn counterparty(&self) -> &str {
        &self.counterparty
    }

    pub fn cancel_peer_credit(
        &mut self,
        cancellation: &PeerCreditCancellation,
        authenticated_counterparty: &str,
    ) -> Result<ReceiptApplication, CreditError> {
        if authenticated_counterparty != self.counterparty {
            return Err(CreditError::UnauthenticatedCounterparty);
        }
        if cancellation.counterparty != self.counterparty
            || cancellation.cancellation_id.trim().is_empty()
            || cancellation.amount_sat == 0
        {
            return Err(CreditError::InvalidCancellation);
        }
        if let Some(old) = self.cancellations.get(&cancellation.cancellation_id) {
            return if old == cancellation {
                Ok(ReceiptApplication::AlreadyApplied)
            } else {
                Err(CreditError::InvalidCancellation)
            };
        }
        let revision = self.next_revision()?;
        let mut ledger = self.issuer(&cancellation.issuer)?.peer_credit.clone();
        ledger.debit(cancellation.amount_sat)?;
        let total = self
            .total_peer_credit_sat
            .checked_sub(cancellation.amount_sat)
            .ok_or(CreditError::ConservationViolation)?;
        self.issuer_mut(&cancellation.issuer)?.peer_credit = ledger;
        self.total_peer_credit_sat = total;
        self.cancellations
            .insert(cancellation.cancellation_id.clone(), cancellation.clone());
        self.peer_credit_events.push(PeerCreditEvent::Cancellation {
            revision,
            cancellation_id: cancellation.cancellation_id.clone(),
        });
        self.revision = revision;
        Ok(ReceiptApplication::Applied)
    }

    /// Monotonic state revision. Each newly applied mutation advances it once.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn total_peer_credit_sat(&self) -> u64 {
        self.total_peer_credit_sat
    }

    pub fn peer_credit(&self, issuer: &str) -> Result<&PeerCreditLedger, CreditError> {
        Ok(&self.issuer(issuer)?.peer_credit)
    }

    pub fn closed_loop(&self, issuer: &str) -> Result<&ClosedLoopLedger, CreditError> {
        Ok(&self.issuer(issuer)?.closed_loop)
    }

    pub fn sat_reserve(&self, issuer: &str) -> Result<&WithdrawableReserveLedger, CreditError> {
        Ok(&self.issuer(issuer)?.withdrawable)
    }

    pub fn applied_receipt_count(&self) -> usize {
        self.applied_receipts.len()
    }

    /// Verified backing operations retained by this account, in stable ID order.
    ///
    /// Persistent adapters use this to atomically bind each issuer operation to
    /// one account. The account-local idempotency map alone cannot prevent the
    /// same proof, quote, or payment from backing another account.
    pub fn backing_deposits(&self) -> impl Iterator<Item = &BackingDeposit> {
        self.backing_deposits.values()
    }

    /// Record verified backing exactly once using the adapter's stable operation ID.
    pub fn record_backing_deposit(
        &mut self,
        deposit: &BackingDeposit,
        authenticated_issuer: &str,
    ) -> Result<ReceiptApplication, CreditError> {
        self.validate_backing_deposit(deposit, authenticated_issuer)?;
        let operation_key = (deposit.issuer.clone(), deposit.deposit_id.clone());
        if let Some(existing) = self.backing_deposits.get(&operation_key) {
            return if existing == deposit {
                Ok(ReceiptApplication::AlreadyApplied)
            } else {
                Err(CreditError::DepositConflict)
            };
        }
        let revision = self.next_revision()?;
        match deposit.value_class {
            ValueClass::ClosedLoopDeposit => self
                .issuer_mut(&deposit.issuer)?
                .closed_loop
                .deposit(deposit.amount_sat)?,
            ValueClass::ReserveBackedWithdrawable => self
                .issuer_mut(&deposit.issuer)?
                .withdrawable
                .deposit(deposit.amount_sat)?,
            ValueClass::PeerCredit => return Err(CreditError::UnsupportedBackingClass),
        }
        self.backing_deposits.insert(operation_key, deposit.clone());
        self.revision = revision;
        Ok(ReceiptApplication::Applied)
    }

    /// Apply a receipt after the caller verified its signature and supplies the signer identity.
    pub fn apply_receipt(
        &mut self,
        claim: &ServiceReceiptClaim,
        authenticated_issuer: &str,
        mode: AcceptanceMode,
        now_unix: u64,
    ) -> Result<ReceiptApplication, CreditError> {
        self.validate_receipt_identity(claim, authenticated_issuer)?;
        if let Some(existing) = self.applied_receipts.get(&claim.receipt_id) {
            return if existing == claim {
                Ok(ReceiptApplication::AlreadyApplied)
            } else {
                Err(CreditError::ReceiptConflict)
            };
        }
        self.validate_receipt(claim, authenticated_issuer, now_unix)?;
        let revision = self.next_revision()?;

        match claim.value_class {
            ValueClass::PeerCredit => self.apply_peer_credit(claim, mode)?,
            ValueClass::ClosedLoopDeposit => {
                self.require_online(mode)?;
                self.apply_closed_loop(claim)?;
            }
            ValueClass::ReserveBackedWithdrawable => {
                self.require_online(mode)?;
                self.apply_withdrawable(claim)?;
            }
        }
        if claim.value_class == ValueClass::PeerCredit {
            self.peer_credit_events.push(PeerCreditEvent::Receipt {
                revision,
                receipt_id: claim.receipt_id.clone(),
                mode,
            });
        }
        self.applied_receipts
            .insert(claim.receipt_id.clone(), claim.clone());
        self.revision = revision;
        Ok(ReceiptApplication::Applied)
    }

    /// Move unbacked exposure to another verified peer issuer without reducing it.
    pub fn novate_peer_credit(
        &mut self,
        novation: &CreditNovation,
        authenticated_to_issuer: &str,
        now_unix: u64,
    ) -> Result<(), CreditError> {
        self.validate_novation_identity(novation, authenticated_to_issuer)?;
        if let Some(existing) = self.novations.get(&novation.novation_id) {
            return if existing == novation {
                Ok(())
            } else {
                Err(CreditError::NovationConflict)
            };
        }
        self.validate_novation(novation, authenticated_to_issuer, now_unix)?;
        let revision = self.next_revision()?;

        let mut source = self.issuer(&novation.from_issuer)?.peer_credit.clone();
        let mut target = self.issuer(&novation.to_issuer)?.peer_credit.clone();
        source.debit(novation.amount_sat)?;
        target.credit(novation.amount_sat, false)?;
        if target.outstanding_sat() > self.issuer(&novation.to_issuer)?.policy.max_peer_credit_sat {
            return Err(CreditError::IssuerExposureExceeded);
        }

        self.issuer_mut(&novation.from_issuer)?.peer_credit = source;
        self.issuer_mut(&novation.to_issuer)?.peer_credit = target;
        self.peer_credit_events.push(PeerCreditEvent::Novation {
            revision,
            novation_id: novation.novation_id.clone(),
        });
        self.novations
            .insert(novation.novation_id.clone(), novation.clone());
        self.revision = revision;
        Ok(())
    }

    /// Replace peer credit with a verified, issuer-authenticated backed liability.
    pub fn settle_peer_credit_with_backing(
        &mut self,
        settlement: &BackedCreditSettlement,
        authenticated_backing_issuer: &str,
        now_unix: u64,
    ) -> Result<ReceiptApplication, CreditError> {
        self.validate_backed_settlement_identity(settlement, authenticated_backing_issuer)?;
        if let Some(existing) = self.backed_settlements.get(&settlement.settlement_id) {
            return if existing == settlement {
                Ok(ReceiptApplication::AlreadyApplied)
            } else {
                Err(CreditError::BackedSettlementConflict)
            };
        }
        self.validate_backed_settlement(settlement, authenticated_backing_issuer, now_unix)?;
        let revision = self.next_revision()?;
        let mut source = self.issuer(&settlement.from_issuer)?.peer_credit.clone();
        source.debit(settlement.amount_sat)?;
        let remaining_peer_credit = self
            .total_peer_credit_sat
            .checked_sub(settlement.amount_sat)
            .ok_or(CreditError::ConservationViolation)?;
        match settlement.value_class {
            ValueClass::ClosedLoopDeposit => {
                let mut backing = self.issuer(&settlement.backing_issuer)?.closed_loop.clone();
                let exposure = backing
                    .claimable_sat()
                    .checked_add(settlement.amount_sat)
                    .ok_or(CreditError::ArithmeticOverflow)?;
                if exposure
                    > self
                        .issuer(&settlement.backing_issuer)?
                        .policy
                        .max_closed_loop_sat
                {
                    return Err(CreditError::ClosedLoopExposureExceeded);
                }
                backing.allocate(settlement.amount_sat)?;
                self.issuer_mut(&settlement.backing_issuer)?.closed_loop = backing;
            }
            ValueClass::ReserveBackedWithdrawable => {
                let mut backing = self
                    .issuer(&settlement.backing_issuer)?
                    .withdrawable
                    .clone();
                self.ensure_withdrawable_capacity(
                    &settlement.backing_issuer,
                    &backing,
                    settlement.amount_sat,
                )?;
                backing.allocate(settlement.amount_sat)?;
                self.issuer_mut(&settlement.backing_issuer)?.withdrawable = backing;
            }
            ValueClass::PeerCredit => return Err(CreditError::UnsupportedBackingClass),
        }
        self.issuer_mut(&settlement.from_issuer)?.peer_credit = source;
        self.total_peer_credit_sat = remaining_peer_credit;
        self.peer_credit_events
            .push(PeerCreditEvent::BackedSettlement {
                revision,
                settlement_id: settlement.settlement_id.clone(),
            });
        self.backed_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        self.revision = revision;
        Ok(ReceiptApplication::Applied)
    }

    /// Consume closed-loop value once for a named issuer service.
    pub fn consume_closed_loop(
        &mut self,
        consumption: &ClosedLoopConsumption,
        authenticated_counterparty: &str,
    ) -> Result<ReceiptApplication, CreditError> {
        self.validate_closed_loop_consumption(consumption, authenticated_counterparty)?;
        if let Some(existing) = self
            .closed_loop_consumptions
            .get(&consumption.consumption_id)
        {
            return if existing == consumption {
                Ok(ReceiptApplication::AlreadyApplied)
            } else {
                Err(CreditError::ClosedLoopConsumptionConflict)
            };
        }
        let revision = self.next_revision()?;
        self.issuer_mut(&consumption.issuer)?
            .closed_loop
            .consume(consumption.amount_sat)?;
        self.closed_loop_consumptions
            .insert(consumption.consumption_id.clone(), consumption.clone());
        self.revision = revision;
        Ok(ReceiptApplication::Applied)
    }

    /// Reserve externally redeemable sats under an authenticated, idempotent request.
    pub fn authorize_external_settlement(
        &mut self,
        request: &ExternalSettlementRequest,
        authenticated_counterparty: &str,
        now_unix: u64,
    ) -> Result<ExternalSettlementAuthorization, CreditError> {
        self.validate_settlement_identity(request, authenticated_counterparty)?;
        if let Some(existing) = self.settlements.get(&request.settlement_id) {
            if existing.request != *request {
                return Err(CreditError::SettlementConflict);
            }
            return match existing.state {
                SettlementState::Pending => Ok(existing.authorization.clone()),
                SettlementState::Completed { .. } => Err(CreditError::SettlementCompleted),
                SettlementState::Cancelled => Err(CreditError::SettlementCancelled),
            };
        }
        self.validate_settlement(request, authenticated_counterparty, now_unix)?;
        let revision = self.next_revision()?;

        let reserved_sat = request
            .amount_sat
            .checked_add(request.max_fee_sat)
            .ok_or(CreditError::ArithmeticOverflow)?;
        self.issuer_mut(&request.issuer)?
            .withdrawable
            .authorize(reserved_sat)?;
        let authorization = ExternalSettlementAuthorization {
            settlement_id: request.settlement_id.clone(),
            issuer: request.issuer.clone(),
            counterparty: request.counterparty.clone(),
            payout_destination: request.payout_destination.clone(),
            amount_sat: request.amount_sat,
            max_fee_sat: request.max_fee_sat,
            reserved_sat,
            authorized_at_unix: now_unix,
            expires_at_unix: request.expires_at_unix,
        };
        self.settlements.insert(
            request.settlement_id.clone(),
            SettlementRecord {
                request: request.clone(),
                authorization: authorization.clone(),
                state: SettlementState::Pending,
            },
        );
        self.revision = revision;
        Ok(authorization)
    }

    /// Enumerate durable authorizations that still require backend recovery.
    ///
    /// Results are owned clones ordered by `settlement_id`, allowing a restored
    /// worker to resume the exact saved operations and then mutate the account.
    pub fn pending_external_settlement_authorizations(
        &self,
    ) -> Vec<ExternalSettlementAuthorization> {
        self.settlements
            .values()
            .filter_map(|record| {
                matches!(record.state, SettlementState::Pending)
                    .then_some(record.authorization.clone())
            })
            .collect()
    }

    pub fn complete_external_settlement(
        &mut self,
        settlement_id: &str,
        actual_fee_sat: u64,
    ) -> Result<(), CreditError> {
        let record = self
            .settlements
            .get(settlement_id)
            .cloned()
            .ok_or(CreditError::UnknownSettlement)?;
        match record.state {
            SettlementState::Completed { fee_sat } => {
                return if fee_sat == actual_fee_sat {
                    Ok(())
                } else {
                    Err(CreditError::SettlementCompletionConflict)
                };
            }
            SettlementState::Cancelled => return Err(CreditError::SettlementCancelled),
            SettlementState::Pending => {}
        }
        if actual_fee_sat > record.request.max_fee_sat {
            return Err(CreditError::SettlementFeeExceeded);
        }
        let revision = self.next_revision()?;
        let spent_sat = record
            .request
            .amount_sat
            .checked_add(actual_fee_sat)
            .ok_or(CreditError::ArithmeticOverflow)?;
        let unused_fee_sat = record.request.max_fee_sat - actual_fee_sat;
        let mut ledger = self.issuer(&record.request.issuer)?.withdrawable.clone();
        ledger.complete(spent_sat)?;
        if unused_fee_sat > 0 {
            ledger.cancel(unused_fee_sat)?;
        }
        self.issuer_mut(&record.request.issuer)?.withdrawable = ledger;
        self.settlements
            .get_mut(settlement_id)
            .expect("record checked above")
            .state = SettlementState::Completed {
            fee_sat: actual_fee_sat,
        };
        self.revision = revision;
        Ok(())
    }

    /// Release a reservation only after the backend proves no irreversible
    /// payment was attempted. An unknown or in-flight backend result must be
    /// recovered and completed instead; cancelling it could release backing
    /// after value already left the wallet.
    pub fn cancel_external_settlement(&mut self, settlement_id: &str) -> Result<(), CreditError> {
        let record = self
            .settlements
            .get(settlement_id)
            .cloned()
            .ok_or(CreditError::UnknownSettlement)?;
        match record.state {
            SettlementState::Cancelled => return Ok(()),
            SettlementState::Completed { .. } => return Err(CreditError::SettlementCompleted),
            SettlementState::Pending => {}
        }
        let revision = self.next_revision()?;
        self.issuer_mut(&record.request.issuer)?
            .withdrawable
            .cancel(record.authorization.reserved_sat)?;
        self.settlements
            .get_mut(settlement_id)
            .expect("record checked above")
            .state = SettlementState::Cancelled;
        self.revision = revision;
        Ok(())
    }

    fn issuer(&self, issuer: &str) -> Result<&IssuerState, CreditError> {
        self.issuers.get(issuer).ok_or(CreditError::WrongIssuer)
    }

    fn issuer_mut(&mut self, issuer: &str) -> Result<&mut IssuerState, CreditError> {
        self.issuers.get_mut(issuer).ok_or(CreditError::WrongIssuer)
    }

    fn next_revision(&self) -> Result<u64, CreditError> {
        self.revision
            .checked_add(1)
            .ok_or(CreditError::RevisionOverflow)
    }

    fn validate_receipt(
        &self,
        claim: &ServiceReceiptClaim,
        authenticated_issuer: &str,
        now_unix: u64,
    ) -> Result<(), CreditError> {
        self.validate_receipt_identity(claim, authenticated_issuer)?;
        self.issuer(&claim.issuer)?.ensure_active(now_unix)?;
        if claim.expires_at_unix <= now_unix {
            return Err(CreditError::ReceiptExpired);
        }
        if claim.issued_at_unix > now_unix {
            return Err(CreditError::ReceiptNotYetValid);
        }
        if claim.service.trim().is_empty()
            || claim.resource.trim().is_empty()
            || claim.useful_service_units == 0
        {
            return Err(CreditError::NoUsefulService);
        }
        if claim.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        Ok(())
    }

    fn validate_receipt_identity(
        &self,
        claim: &ServiceReceiptClaim,
        authenticated_issuer: &str,
    ) -> Result<(), CreditError> {
        if claim.counterparty != self.counterparty {
            return Err(CreditError::WrongCounterparty);
        }
        if claim.issuer != authenticated_issuer {
            return Err(CreditError::UnauthenticatedIssuer);
        }
        self.issuer(&claim.issuer)?;
        if claim.receipt_id.trim().is_empty() {
            return Err(CreditError::MissingReceiptId);
        }
        Ok(())
    }

    fn apply_peer_credit(
        &mut self,
        claim: &ServiceReceiptClaim,
        mode: AcceptanceMode,
    ) -> Result<(), CreditError> {
        let mut ledger = self.issuer(&claim.issuer)?.peer_credit.clone();
        ledger.credit(claim.amount_sat, mode == AcceptanceMode::OfflineDeferred)?;
        let issuer_policy = &self.issuer(&claim.issuer)?.policy;
        if ledger.outstanding_sat() > issuer_policy.max_peer_credit_sat {
            return Err(CreditError::IssuerExposureExceeded);
        }
        if ledger.offline_outstanding_sat() > issuer_policy.max_offline_peer_credit_sat {
            return Err(CreditError::OfflineExposureExceeded);
        }
        let total = self
            .total_peer_credit_sat
            .checked_add(claim.amount_sat)
            .ok_or(CreditError::ArithmeticOverflow)?;
        if total > self.max_total_peer_credit_sat {
            return Err(CreditError::TotalExposureExceeded);
        }
        self.issuer_mut(&claim.issuer)?.peer_credit = ledger;
        self.total_peer_credit_sat = total;
        Ok(())
    }

    fn apply_closed_loop(&mut self, claim: &ServiceReceiptClaim) -> Result<(), CreditError> {
        let mut ledger = self.issuer(&claim.issuer)?.closed_loop.clone();
        let resulting = ledger
            .claimable_sat()
            .checked_add(claim.amount_sat)
            .ok_or(CreditError::ArithmeticOverflow)?;
        if resulting > self.issuer(&claim.issuer)?.policy.max_closed_loop_sat {
            return Err(CreditError::ClosedLoopExposureExceeded);
        }
        ledger.allocate(claim.amount_sat)?;
        self.issuer_mut(&claim.issuer)?.closed_loop = ledger;
        Ok(())
    }

    fn apply_withdrawable(&mut self, claim: &ServiceReceiptClaim) -> Result<(), CreditError> {
        let mut ledger = self.issuer(&claim.issuer)?.withdrawable.clone();
        self.ensure_withdrawable_capacity(&claim.issuer, &ledger, claim.amount_sat)?;
        ledger.allocate(claim.amount_sat)?;
        self.issuer_mut(&claim.issuer)?.withdrawable = ledger;
        Ok(())
    }

    fn ensure_withdrawable_capacity(
        &self,
        issuer: &str,
        ledger: &WithdrawableReserveLedger,
        additional_sat: u64,
    ) -> Result<(), CreditError> {
        let exposure = ledger
            .redeemable_sat()
            .checked_add(ledger.pending_external_sat())
            .and_then(|value| value.checked_add(additional_sat))
            .ok_or(CreditError::ArithmeticOverflow)?;
        if exposure > self.issuer(issuer)?.policy.max_withdrawable_sat {
            return Err(CreditError::WithdrawableExposureExceeded);
        }
        Ok(())
    }

    fn require_online(&self, mode: AcceptanceMode) -> Result<(), CreditError> {
        if mode == AcceptanceMode::OfflineDeferred {
            return Err(CreditError::BackingVerificationRequired);
        }
        Ok(())
    }

    fn validate_novation(
        &self,
        novation: &CreditNovation,
        authenticated_to_issuer: &str,
        now_unix: u64,
    ) -> Result<(), CreditError> {
        self.validate_novation_identity(novation, authenticated_to_issuer)?;
        if novation.expires_at_unix <= now_unix {
            return Err(CreditError::NovationExpired);
        }
        if novation.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        self.issuer(&novation.from_issuer)?
            .ensure_active(now_unix)?;
        self.issuer(&novation.to_issuer)?.ensure_active(now_unix)?;
        Ok(())
    }

    fn validate_novation_identity(
        &self,
        novation: &CreditNovation,
        authenticated_to_issuer: &str,
    ) -> Result<(), CreditError> {
        if novation.counterparty != self.counterparty {
            return Err(CreditError::WrongCounterparty);
        }
        if novation.to_issuer != authenticated_to_issuer {
            return Err(CreditError::UnauthenticatedIssuer);
        }
        if novation.from_issuer == novation.to_issuer {
            return Err(CreditError::SameIssuerNovation);
        }
        if novation.novation_id.trim().is_empty() {
            return Err(CreditError::MissingNovationId);
        }
        self.issuer(&novation.from_issuer)?;
        self.issuer(&novation.to_issuer)?;
        Ok(())
    }

    fn validate_backing_deposit(
        &self,
        deposit: &BackingDeposit,
        authenticated_issuer: &str,
    ) -> Result<(), CreditError> {
        if deposit.issuer != authenticated_issuer {
            return Err(CreditError::UnauthenticatedIssuer);
        }
        self.issuer(&deposit.issuer)?;
        if deposit.deposit_id.trim().is_empty() {
            return Err(CreditError::MissingDepositId);
        }
        if deposit.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        if deposit.value_class == ValueClass::PeerCredit {
            return Err(CreditError::UnsupportedBackingClass);
        }
        Ok(())
    }

    fn validate_backed_settlement(
        &self,
        settlement: &BackedCreditSettlement,
        authenticated_backing_issuer: &str,
        now_unix: u64,
    ) -> Result<(), CreditError> {
        self.validate_backed_settlement_identity(settlement, authenticated_backing_issuer)?;
        self.issuer(&settlement.from_issuer)?
            .ensure_active(now_unix)?;
        self.issuer(&settlement.backing_issuer)?
            .ensure_active(now_unix)?;
        if settlement.expires_at_unix <= now_unix {
            return Err(CreditError::BackedSettlementExpired);
        }
        if settlement.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        if settlement.value_class == ValueClass::PeerCredit {
            return Err(CreditError::UnsupportedBackingClass);
        }
        Ok(())
    }

    fn validate_backed_settlement_identity(
        &self,
        settlement: &BackedCreditSettlement,
        authenticated_backing_issuer: &str,
    ) -> Result<(), CreditError> {
        if settlement.counterparty != self.counterparty {
            return Err(CreditError::WrongCounterparty);
        }
        if settlement.backing_issuer != authenticated_backing_issuer {
            return Err(CreditError::UnauthenticatedIssuer);
        }
        self.issuer(&settlement.from_issuer)?;
        self.issuer(&settlement.backing_issuer)?;
        if settlement.settlement_id.trim().is_empty() {
            return Err(CreditError::MissingBackedSettlementId);
        }
        Ok(())
    }

    fn validate_settlement(
        &self,
        request: &ExternalSettlementRequest,
        authenticated_counterparty: &str,
        now_unix: u64,
    ) -> Result<(), CreditError> {
        self.validate_settlement_identity(request, authenticated_counterparty)?;
        self.issuer(&request.issuer)?.ensure_active(now_unix)?;
        if request.expires_at_unix <= now_unix {
            return Err(CreditError::SettlementExpired);
        }
        if request.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        if request.payout_destination.trim().is_empty() {
            return Err(CreditError::MissingPayoutDestination);
        }
        Ok(())
    }

    fn validate_closed_loop_consumption(
        &self,
        consumption: &ClosedLoopConsumption,
        authenticated_counterparty: &str,
    ) -> Result<(), CreditError> {
        if consumption.counterparty != self.counterparty {
            return Err(CreditError::WrongCounterparty);
        }
        if consumption.counterparty != authenticated_counterparty {
            return Err(CreditError::UnauthenticatedCounterparty);
        }
        self.issuer(&consumption.issuer)?;
        if consumption.consumption_id.trim().is_empty() {
            return Err(CreditError::MissingClosedLoopConsumptionId);
        }
        if consumption.resource.trim().is_empty() {
            return Err(CreditError::NoUsefulService);
        }
        if consumption.amount_sat == 0 {
            return Err(CreditError::ZeroAmount);
        }
        Ok(())
    }

    fn validate_settlement_identity(
        &self,
        request: &ExternalSettlementRequest,
        authenticated_counterparty: &str,
    ) -> Result<(), CreditError> {
        if request.counterparty != self.counterparty {
            return Err(CreditError::WrongCounterparty);
        }
        if request.counterparty != authenticated_counterparty {
            return Err(CreditError::UnauthenticatedCounterparty);
        }
        self.issuer(&request.issuer)?;
        if request.settlement_id.trim().is_empty() {
            return Err(CreditError::MissingSettlementId);
        }
        Ok(())
    }
}
