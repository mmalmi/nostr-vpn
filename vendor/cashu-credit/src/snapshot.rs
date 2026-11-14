use crate::account::{
    CreditAccount, IssuerState, PeerCreditEvent, SettlementRecord, SettlementState,
};
use crate::{
    BackedCreditSettlement, BackingDeposit, ClosedLoopConsumption, ClosedLoopLedger, CreditError,
    CreditNovation, ExternalSettlementAuthorization, ExternalSettlementRequest, IssuerPolicy,
    PeerCreditCancellation, PeerCreditLedger, ServiceReceiptClaim, ValueClass,
    WithdrawableReserveLedger,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SNAPSHOT_VERSION: u32 = 1;

/// Authoritative, versioned representation of one validated credit account.
///
/// Fields stay private so restoration always passes through
/// [`CreditAccount::from_snapshot`]. [`Self::encode_json`] is deterministic for
/// this Rust schema and crate version, but is not an RFC 8785/JCS or
/// cross-language canonical-byte contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreditAccountSnapshotV1 {
    version: u32,
    revision: u64,
    counterparty: String,
    max_total_peer_credit_sat: u64,
    total_peer_credit_sat: u64,
    issuers: BTreeMap<String, IssuerSnapshotV1>,
    applied_receipts: BTreeMap<String, ServiceReceiptClaim>,
    peer_credit_events: Vec<PeerCreditEvent>,
    novations: BTreeMap<String, CreditNovation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    cancellations: BTreeMap<String, PeerCreditCancellation>,
    backing_deposits: Vec<BackingDeposit>,
    backed_settlements: BTreeMap<String, BackedCreditSettlement>,
    closed_loop_consumptions: BTreeMap<String, ClosedLoopConsumption>,
    settlements: BTreeMap<String, SettlementRecordSnapshotV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerSnapshotV1 {
    policy: IssuerPolicy,
    peer_credit: PeerCreditSnapshotV1,
    closed_loop: ClosedLoopSnapshotV1,
    withdrawable: WithdrawableSnapshotV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerCreditSnapshotV1 {
    outstanding_sat: u64,
    offline_outstanding_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedLoopSnapshotV1 {
    total_deposited_sat: u64,
    available_backing_sat: u64,
    claimable_sat: u64,
    consumed_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawableSnapshotV1 {
    total_deposited_sat: u64,
    available_sat: u64,
    redeemable_sat: u64,
    pending_external_sat: u64,
    settled_external_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementRecordSnapshotV1 {
    request: ExternalSettlementRequest,
    authorization: ExternalSettlementAuthorization,
    state: SettlementStateSnapshotV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum SettlementStateSnapshotV1 {
    Pending,
    Completed { fee_sat: u64 },
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("invalid credit account snapshot JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Credit(#[from] CreditError),
}

#[derive(Debug, Default)]
struct ExpectedIssuerState {
    peer_credits_sat: u64,
    peer_debits_sat: u64,
    closed_deposits_sat: u64,
    withdrawable_deposits_sat: u64,
    closed_allocations_sat: u64,
    withdrawable_allocations_sat: u64,
    closed_consumptions_sat: u64,
    pending_external_sat: u64,
    settled_external_sat: u64,
}

impl CreditAccountSnapshotV1 {
    pub const fn version(&self) -> u32 {
        self.version
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn counterparty(&self) -> &str {
        &self.counterparty
    }

    /// Encode deterministic JSON for this Rust schema and crate version.
    pub fn encode_json(&self) -> Result<String, SnapshotError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse and structurally validate the authoritative snapshot representation.
    ///
    /// This does not re-authenticate historical signatures, proofs, or payments.
    pub fn decode_json(encoded: &str) -> Result<Self, SnapshotError> {
        let snapshot: Self = serde_json::from_str(encoded)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), CreditError> {
        if self.version != SNAPSHOT_VERSION {
            return Err(CreditError::UnsupportedSnapshotVersion);
        }
        if self.counterparty.trim().is_empty() || self.issuers.is_empty() {
            return invalid("account identity or issuer set");
        }

        let mut expected = BTreeMap::new();
        for (issuer_id, issuer) in &self.issuers {
            validate_issuer(issuer_id, issuer)?;
            expected.insert(issuer_id.clone(), ExpectedIssuerState::default());
        }
        self.validate_receipts(&mut expected)?;
        self.validate_novations(&mut expected)?;
        for (key, c) in &self.cancellations {
            if key != &c.cancellation_id
                || key.trim().is_empty()
                || c.counterparty != self.counterparty
                || c.amount_sat == 0
            {
                return invalid("cancellation record");
            }
            add(
                &mut expected_state(&mut expected, &c.issuer)?.peer_debits_sat,
                c.amount_sat,
                "cancellation debit total",
            )?;
        }
        self.validate_deposits(&mut expected)?;
        self.validate_backed_settlements(&mut expected)?;
        self.validate_peer_credit_events()?;
        self.validate_consumptions(&mut expected)?;
        self.validate_external_settlements(&mut expected)?;
        self.validate_totals(&expected)?;
        self.validate_revision()?;
        Ok(())
    }

    fn validate_receipts(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        for (key, receipt) in &self.applied_receipts {
            if key != &receipt.receipt_id
                || key.trim().is_empty()
                || receipt.counterparty != self.counterparty
                || receipt.service.trim().is_empty()
                || receipt.resource.trim().is_empty()
                || receipt.useful_service_units == 0
                || receipt.amount_sat == 0
                || receipt.issued_at_unix >= receipt.expires_at_unix
            {
                return invalid("receipt record");
            }
            let totals = expected_state(expected, &receipt.issuer)?;
            match receipt.value_class {
                ValueClass::PeerCredit => add(
                    &mut totals.peer_credits_sat,
                    receipt.amount_sat,
                    "peer receipt total",
                )?,
                ValueClass::ClosedLoopDeposit => add(
                    &mut totals.closed_allocations_sat,
                    receipt.amount_sat,
                    "closed-loop receipt total",
                )?,
                ValueClass::ReserveBackedWithdrawable => add(
                    &mut totals.withdrawable_allocations_sat,
                    receipt.amount_sat,
                    "withdrawable receipt total",
                )?,
            }
        }
        Ok(())
    }

    fn validate_peer_credit_events(&self) -> Result<(), CreditError> {
        let mut ledgers = self
            .issuers
            .keys()
            .map(|issuer| (issuer.clone(), PeerCreditLedger::default()))
            .collect::<BTreeMap<_, _>>();
        let mut seen_receipts = BTreeSet::new();
        let mut seen_novations = BTreeSet::new();
        let mut seen_cancellations = BTreeSet::new();
        let mut seen_settlements = BTreeSet::new();
        let mut previous_revision = 0;

        for event in &self.peer_credit_events {
            let revision = event.revision();
            if revision == 0 || revision <= previous_revision || revision > self.revision {
                return invalid("peer-credit event revision");
            }
            previous_revision = revision;
            match event {
                PeerCreditEvent::Cancellation {
                    cancellation_id, ..
                } => {
                    if !seen_cancellations.insert(cancellation_id) {
                        return invalid("duplicate cancellation event");
                    }
                    let c = self
                        .cancellations
                        .get(cancellation_id)
                        .ok_or_else(|| invalid_error("missing cancellation"))?;
                    event_ledger(&mut ledgers, &c.issuer)?
                        .debit(c.amount_sat)
                        .map_err(|_| invalid_error("cancellation cannot debit"))?;
                }
                PeerCreditEvent::Receipt {
                    receipt_id, mode, ..
                } => {
                    if !seen_receipts.insert(receipt_id) {
                        return invalid("duplicate peer-credit receipt event");
                    }
                    let receipt = self
                        .applied_receipts
                        .get(receipt_id)
                        .ok_or_else(|| invalid_error("peer-credit receipt event is missing"))?;
                    if receipt.value_class != ValueClass::PeerCredit {
                        return invalid("peer-credit receipt event has wrong value class");
                    }
                    event_ledger(&mut ledgers, &receipt.issuer)?
                        .credit(
                            receipt.amount_sat,
                            *mode == crate::AcceptanceMode::OfflineDeferred,
                        )
                        .map_err(|_| invalid_error("peer-credit receipt event cannot apply"))?;
                }
                PeerCreditEvent::Novation { novation_id, .. } => {
                    if !seen_novations.insert(novation_id) {
                        return invalid("duplicate peer-credit novation event");
                    }
                    let novation = self
                        .novations
                        .get(novation_id)
                        .ok_or_else(|| invalid_error("peer-credit novation event is missing"))?;
                    event_ledger(&mut ledgers, &novation.from_issuer)?
                        .debit(novation.amount_sat)
                        .map_err(|_| invalid_error("peer-credit novation event cannot debit"))?;
                    event_ledger(&mut ledgers, &novation.to_issuer)?
                        .credit(novation.amount_sat, false)
                        .map_err(|_| invalid_error("peer-credit novation event cannot credit"))?;
                }
                PeerCreditEvent::BackedSettlement { settlement_id, .. } => {
                    if !seen_settlements.insert(settlement_id) {
                        return invalid("duplicate backed-settlement event");
                    }
                    let settlement =
                        self.backed_settlements.get(settlement_id).ok_or_else(|| {
                            invalid_error("peer-credit backed-settlement event is missing")
                        })?;
                    event_ledger(&mut ledgers, &settlement.from_issuer)?
                        .debit(settlement.amount_sat)
                        .map_err(|_| {
                            invalid_error("peer-credit backed-settlement event cannot debit")
                        })?;
                }
            }
        }

        if seen_receipts.len()
            != self
                .applied_receipts
                .values()
                .filter(|receipt| receipt.value_class == ValueClass::PeerCredit)
                .count()
            || seen_cancellations.len() != self.cancellations.len()
            || seen_novations.len() != self.novations.len()
            || seen_settlements.len() != self.backed_settlements.len()
        {
            return invalid("peer-credit event coverage");
        }
        for (issuer, ledger) in ledgers {
            let stored = &self.issuers[&issuer].peer_credit;
            if ledger.outstanding_sat() != stored.outstanding_sat
                || ledger.offline_outstanding_sat() != stored.offline_outstanding_sat
            {
                return invalid("peer-credit event replay");
            }
        }
        Ok(())
    }

    fn validate_novations(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        for (key, novation) in &self.novations {
            if key != &novation.novation_id
                || key.trim().is_empty()
                || novation.counterparty != self.counterparty
                || novation.from_issuer == novation.to_issuer
                || novation.amount_sat == 0
            {
                return invalid("novation record");
            }
            add(
                &mut expected_state(expected, &novation.from_issuer)?.peer_debits_sat,
                novation.amount_sat,
                "novation debit total",
            )?;
            add(
                &mut expected_state(expected, &novation.to_issuer)?.peer_credits_sat,
                novation.amount_sat,
                "novation credit total",
            )?;
        }
        Ok(())
    }

    fn validate_deposits(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        let mut previous_key: Option<(&str, &str)> = None;
        for deposit in &self.backing_deposits {
            let key = (deposit.issuer.as_str(), deposit.deposit_id.as_str());
            if previous_key.is_some_and(|previous| previous >= key)
                || deposit.deposit_id.trim().is_empty()
                || deposit.amount_sat == 0
            {
                return invalid("backing deposit record");
            }
            previous_key = Some(key);
            let totals = expected_state(expected, &deposit.issuer)?;
            match deposit.value_class {
                ValueClass::PeerCredit => return invalid("peer-credit backing deposit"),
                ValueClass::ClosedLoopDeposit => add(
                    &mut totals.closed_deposits_sat,
                    deposit.amount_sat,
                    "closed-loop deposit total",
                )?,
                ValueClass::ReserveBackedWithdrawable => add(
                    &mut totals.withdrawable_deposits_sat,
                    deposit.amount_sat,
                    "withdrawable deposit total",
                )?,
            }
        }
        Ok(())
    }

    fn validate_backed_settlements(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        for (key, settlement) in &self.backed_settlements {
            if key != &settlement.settlement_id
                || key.trim().is_empty()
                || settlement.counterparty != self.counterparty
                || settlement.amount_sat == 0
            {
                return invalid("backed settlement record");
            }
            add(
                &mut expected_state(expected, &settlement.from_issuer)?.peer_debits_sat,
                settlement.amount_sat,
                "backed settlement debit total",
            )?;
            let backing = expected_state(expected, &settlement.backing_issuer)?;
            match settlement.value_class {
                ValueClass::PeerCredit => return invalid("peer-credit backed settlement"),
                ValueClass::ClosedLoopDeposit => add(
                    &mut backing.closed_allocations_sat,
                    settlement.amount_sat,
                    "backed closed-loop allocation total",
                )?,
                ValueClass::ReserveBackedWithdrawable => add(
                    &mut backing.withdrawable_allocations_sat,
                    settlement.amount_sat,
                    "backed withdrawable allocation total",
                )?,
            }
        }
        Ok(())
    }

    fn validate_consumptions(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        for (key, consumption) in &self.closed_loop_consumptions {
            if key != &consumption.consumption_id
                || key.trim().is_empty()
                || consumption.counterparty != self.counterparty
                || consumption.resource.trim().is_empty()
                || consumption.amount_sat == 0
            {
                return invalid("closed-loop consumption record");
            }
            add(
                &mut expected_state(expected, &consumption.issuer)?.closed_consumptions_sat,
                consumption.amount_sat,
                "closed-loop consumption total",
            )?;
        }
        Ok(())
    }

    fn validate_external_settlements(
        &self,
        expected: &mut BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        for (key, record) in &self.settlements {
            let request = &record.request;
            let authorization = &record.authorization;
            let reserved_sat = request
                .amount_sat
                .checked_add(request.max_fee_sat)
                .ok_or_else(|| invalid_error("external reservation overflow"))?;
            let expected_authorization = ExternalSettlementAuthorization {
                settlement_id: request.settlement_id.clone(),
                issuer: request.issuer.clone(),
                counterparty: request.counterparty.clone(),
                payout_destination: request.payout_destination.clone(),
                amount_sat: request.amount_sat,
                max_fee_sat: request.max_fee_sat,
                reserved_sat,
                authorized_at_unix: authorization.authorized_at_unix,
                expires_at_unix: request.expires_at_unix,
            };
            if key != &request.settlement_id
                || key.trim().is_empty()
                || request.counterparty != self.counterparty
                || request.payout_destination.trim().is_empty()
                || request.amount_sat == 0
                || authorization != &expected_authorization
                || authorization.authorized_at_unix >= authorization.expires_at_unix
            {
                return invalid("external settlement record");
            }
            let totals = expected_state(expected, &request.issuer)?;
            match record.state {
                SettlementStateSnapshotV1::Pending => add(
                    &mut totals.pending_external_sat,
                    reserved_sat,
                    "pending settlement total",
                )?,
                SettlementStateSnapshotV1::Completed { fee_sat } => {
                    if fee_sat > request.max_fee_sat {
                        return invalid("completed settlement fee");
                    }
                    let spent_sat = request
                        .amount_sat
                        .checked_add(fee_sat)
                        .ok_or_else(|| invalid_error("completed settlement overflow"))?;
                    add(
                        &mut totals.settled_external_sat,
                        spent_sat,
                        "completed settlement total",
                    )?;
                }
                SettlementStateSnapshotV1::Cancelled => {}
            }
        }
        Ok(())
    }

    fn validate_totals(
        &self,
        expected: &BTreeMap<String, ExpectedIssuerState>,
    ) -> Result<(), CreditError> {
        let mut total_peer_credit_sat = 0_u64;
        for (issuer_id, issuer) in &self.issuers {
            let totals = expected
                .get(issuer_id)
                .ok_or_else(|| invalid_error("missing expected issuer state"))?;
            if totals.closed_deposits_sat != issuer.closed_loop.total_deposited_sat
                || totals.withdrawable_deposits_sat != issuer.withdrawable.total_deposited_sat
            {
                return invalid("backing deposit totals");
            }
            let expected_peer = totals
                .peer_credits_sat
                .checked_sub(totals.peer_debits_sat)
                .ok_or_else(|| invalid_error("peer-credit operation totals"))?;
            if expected_peer != issuer.peer_credit.outstanding_sat {
                return invalid("peer-credit ledger total");
            }
            let closed_allocated = issuer
                .closed_loop
                .claimable_sat
                .checked_add(issuer.closed_loop.consumed_sat)
                .ok_or_else(|| invalid_error("closed-loop allocation overflow"))?;
            if totals.closed_allocations_sat != closed_allocated
                || totals.closed_consumptions_sat != issuer.closed_loop.consumed_sat
            {
                return invalid("closed-loop allocation totals");
            }
            let withdrawable_allocated = issuer
                .withdrawable
                .redeemable_sat
                .checked_add(issuer.withdrawable.pending_external_sat)
                .and_then(|value| value.checked_add(issuer.withdrawable.settled_external_sat))
                .ok_or_else(|| invalid_error("withdrawable allocation overflow"))?;
            if totals.withdrawable_allocations_sat != withdrawable_allocated
                || totals.pending_external_sat != issuer.withdrawable.pending_external_sat
                || totals.settled_external_sat != issuer.withdrawable.settled_external_sat
            {
                return invalid("withdrawable allocation or settlement totals");
            }
            add(
                &mut total_peer_credit_sat,
                issuer.peer_credit.outstanding_sat,
                "total peer credit",
            )?;
        }
        if total_peer_credit_sat != self.total_peer_credit_sat
            || total_peer_credit_sat > self.max_total_peer_credit_sat
        {
            return invalid("aggregate peer-credit total");
        }
        Ok(())
    }

    fn validate_revision(&self) -> Result<(), CreditError> {
        let mut expected_revision = count(self.applied_receipts.len())?;
        expected_revision = checked_count_add(expected_revision, self.cancellations.len())?;
        expected_revision = checked_count_add(expected_revision, self.novations.len())?;
        expected_revision = checked_count_add(expected_revision, self.backing_deposits.len())?;
        expected_revision = checked_count_add(expected_revision, self.backed_settlements.len())?;
        expected_revision =
            checked_count_add(expected_revision, self.closed_loop_consumptions.len())?;
        expected_revision = checked_count_add(expected_revision, self.settlements.len())?;
        for record in self.settlements.values() {
            if !matches!(record.state, SettlementStateSnapshotV1::Pending) {
                expected_revision = expected_revision
                    .checked_add(1)
                    .ok_or_else(|| invalid_error("revision operation count overflow"))?;
            }
        }
        if self.revision != expected_revision {
            return invalid("revision does not match applied operations");
        }
        Ok(())
    }
}

impl CreditAccount {
    pub fn snapshot(&self) -> CreditAccountSnapshotV1 {
        CreditAccountSnapshotV1 {
            version: SNAPSHOT_VERSION,
            revision: self.revision,
            counterparty: self.counterparty.clone(),
            max_total_peer_credit_sat: self.max_total_peer_credit_sat,
            total_peer_credit_sat: self.total_peer_credit_sat,
            issuers: self
                .issuers
                .iter()
                .map(|(id, issuer)| (id.clone(), issuer.into()))
                .collect(),
            applied_receipts: self.applied_receipts.clone(),
            peer_credit_events: self.peer_credit_events.clone(),
            novations: self.novations.clone(),
            cancellations: self.cancellations.clone(),
            backing_deposits: self.backing_deposits.values().cloned().collect(),
            backed_settlements: self.backed_settlements.clone(),
            closed_loop_consumptions: self.closed_loop_consumptions.clone(),
            settlements: self
                .settlements
                .iter()
                .map(|(id, record)| (id.clone(), record.into()))
                .collect(),
        }
    }

    pub fn from_snapshot(snapshot: CreditAccountSnapshotV1) -> Result<Self, CreditError> {
        snapshot.validate()?;
        Ok(Self {
            revision: snapshot.revision,
            counterparty: snapshot.counterparty,
            max_total_peer_credit_sat: snapshot.max_total_peer_credit_sat,
            total_peer_credit_sat: snapshot.total_peer_credit_sat,
            issuers: snapshot
                .issuers
                .into_iter()
                .map(|(id, issuer)| (id, issuer.into()))
                .collect(),
            applied_receipts: snapshot.applied_receipts,
            peer_credit_events: snapshot.peer_credit_events,
            novations: snapshot.novations,
            cancellations: snapshot.cancellations,
            backing_deposits: snapshot
                .backing_deposits
                .into_iter()
                .map(|deposit| {
                    (
                        (deposit.issuer.clone(), deposit.deposit_id.clone()),
                        deposit,
                    )
                })
                .collect(),
            backed_settlements: snapshot.backed_settlements,
            closed_loop_consumptions: snapshot.closed_loop_consumptions,
            settlements: snapshot
                .settlements
                .into_iter()
                .map(|(id, record)| (id, record.into()))
                .collect(),
        })
    }
}

impl From<&IssuerState> for IssuerSnapshotV1 {
    fn from(issuer: &IssuerState) -> Self {
        Self {
            policy: issuer.policy.clone(),
            peer_credit: PeerCreditSnapshotV1 {
                outstanding_sat: issuer.peer_credit.outstanding_sat,
                offline_outstanding_sat: issuer.peer_credit.offline_outstanding_sat,
            },
            closed_loop: ClosedLoopSnapshotV1 {
                total_deposited_sat: issuer.closed_loop.total_deposited_sat,
                available_backing_sat: issuer.closed_loop.available_backing_sat,
                claimable_sat: issuer.closed_loop.claimable_sat,
                consumed_sat: issuer.closed_loop.consumed_sat,
            },
            withdrawable: WithdrawableSnapshotV1 {
                total_deposited_sat: issuer.withdrawable.total_deposited_sat,
                available_sat: issuer.withdrawable.available_sat,
                redeemable_sat: issuer.withdrawable.redeemable_sat,
                pending_external_sat: issuer.withdrawable.pending_external_sat,
                settled_external_sat: issuer.withdrawable.settled_external_sat,
            },
        }
    }
}

impl From<IssuerSnapshotV1> for IssuerState {
    fn from(issuer: IssuerSnapshotV1) -> Self {
        Self {
            policy: issuer.policy,
            peer_credit: PeerCreditLedger {
                outstanding_sat: issuer.peer_credit.outstanding_sat,
                offline_outstanding_sat: issuer.peer_credit.offline_outstanding_sat,
            },
            closed_loop: ClosedLoopLedger {
                total_deposited_sat: issuer.closed_loop.total_deposited_sat,
                available_backing_sat: issuer.closed_loop.available_backing_sat,
                claimable_sat: issuer.closed_loop.claimable_sat,
                consumed_sat: issuer.closed_loop.consumed_sat,
            },
            withdrawable: WithdrawableReserveLedger {
                total_deposited_sat: issuer.withdrawable.total_deposited_sat,
                available_sat: issuer.withdrawable.available_sat,
                redeemable_sat: issuer.withdrawable.redeemable_sat,
                pending_external_sat: issuer.withdrawable.pending_external_sat,
                settled_external_sat: issuer.withdrawable.settled_external_sat,
            },
        }
    }
}

impl From<&SettlementRecord> for SettlementRecordSnapshotV1 {
    fn from(record: &SettlementRecord) -> Self {
        Self {
            request: record.request.clone(),
            authorization: record.authorization.clone(),
            state: match record.state {
                SettlementState::Pending => SettlementStateSnapshotV1::Pending,
                SettlementState::Completed { fee_sat } => {
                    SettlementStateSnapshotV1::Completed { fee_sat }
                }
                SettlementState::Cancelled => SettlementStateSnapshotV1::Cancelled,
            },
        }
    }
}

impl From<SettlementRecordSnapshotV1> for SettlementRecord {
    fn from(record: SettlementRecordSnapshotV1) -> Self {
        Self {
            request: record.request,
            authorization: record.authorization,
            state: match record.state {
                SettlementStateSnapshotV1::Pending => SettlementState::Pending,
                SettlementStateSnapshotV1::Completed { fee_sat } => {
                    SettlementState::Completed { fee_sat }
                }
                SettlementStateSnapshotV1::Cancelled => SettlementState::Cancelled,
            },
        }
    }
}

fn validate_issuer(id: &str, issuer: &IssuerSnapshotV1) -> Result<(), CreditError> {
    if id.trim().is_empty()
        || issuer.policy.issuer != id
        || issuer.policy.max_offline_peer_credit_sat > issuer.policy.max_peer_credit_sat
        || issuer.peer_credit.offline_outstanding_sat > issuer.peer_credit.outstanding_sat
        || issuer.peer_credit.outstanding_sat > issuer.policy.max_peer_credit_sat
        || issuer.peer_credit.offline_outstanding_sat > issuer.policy.max_offline_peer_credit_sat
        || issuer.closed_loop.claimable_sat > issuer.policy.max_closed_loop_sat
    {
        return invalid("issuer policy or peer-credit caps");
    }
    let withdrawable_exposure = issuer
        .withdrawable
        .redeemable_sat
        .checked_add(issuer.withdrawable.pending_external_sat)
        .ok_or_else(|| invalid_error("withdrawable exposure overflow"))?;
    if withdrawable_exposure > issuer.policy.max_withdrawable_sat {
        return invalid("withdrawable exposure cap");
    }
    let closed_conserved = issuer
        .closed_loop
        .available_backing_sat
        .checked_add(issuer.closed_loop.claimable_sat)
        .and_then(|value| value.checked_add(issuer.closed_loop.consumed_sat))
        .ok_or_else(|| invalid_error("closed-loop conservation overflow"))?;
    if closed_conserved != issuer.closed_loop.total_deposited_sat {
        return invalid("closed-loop conservation");
    }
    let withdrawable_conserved = issuer
        .withdrawable
        .available_sat
        .checked_add(issuer.withdrawable.redeemable_sat)
        .and_then(|value| value.checked_add(issuer.withdrawable.pending_external_sat))
        .and_then(|value| value.checked_add(issuer.withdrawable.settled_external_sat))
        .ok_or_else(|| invalid_error("withdrawable conservation overflow"))?;
    if withdrawable_conserved != issuer.withdrawable.total_deposited_sat {
        return invalid("withdrawable conservation");
    }
    Ok(())
}

fn expected_state<'a>(
    expected: &'a mut BTreeMap<String, ExpectedIssuerState>,
    issuer: &str,
) -> Result<&'a mut ExpectedIssuerState, CreditError> {
    expected
        .get_mut(issuer)
        .ok_or_else(|| invalid_error("operation references unknown issuer"))
}

fn event_ledger<'a>(
    ledgers: &'a mut BTreeMap<String, PeerCreditLedger>,
    issuer: &str,
) -> Result<&'a mut PeerCreditLedger, CreditError> {
    ledgers
        .get_mut(issuer)
        .ok_or_else(|| invalid_error("peer-credit event references unknown issuer"))
}

fn add(target: &mut u64, amount: u64, reason: &'static str) -> Result<(), CreditError> {
    *target = target
        .checked_add(amount)
        .ok_or_else(|| invalid_error(reason))?;
    Ok(())
}

fn count(value: usize) -> Result<u64, CreditError> {
    u64::try_from(value).map_err(|_| invalid_error("operation count overflow"))
}

fn checked_count_add(total: u64, value: usize) -> Result<u64, CreditError> {
    total
        .checked_add(count(value)?)
        .ok_or_else(|| invalid_error("operation count overflow"))
}

fn invalid<T>(reason: &'static str) -> Result<T, CreditError> {
    Err(invalid_error(reason))
}

fn invalid_error(reason: &'static str) -> CreditError {
    CreditError::InvalidSnapshot(reason)
}
