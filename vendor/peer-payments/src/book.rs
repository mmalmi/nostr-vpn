use crate::{
    protocol::{authenticate, identifier},
    Agreement, Error, Receipt, Signed, Verifier, WireMessage,
};
use cashu_credit::{
    AcceptanceMode, AccountPolicy, CreditAccount, CreditAccountSnapshotV1, IssuerPolicy,
    ServiceReceiptClaim, ValueClass,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub(crate) const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub enabled: bool,
    pub max_total_exposure_sat: u64,
    pub max_peer_exposure_sat: u64,
    pub max_agreements: usize,
    pub max_receipts: usize,
    pub max_peers: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_total_exposure_sat: 1_000,
            max_peer_exposure_sat: 100,
            max_agreements: 256,
            max_receipts: 4_096,
            max_peers: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub outstanding_sat: u64,
    pub reserved_sat: u64,
    pub total_sat: u64,
}

/// An authorization ceiling, not proof of payment or delivery. The service must
/// meter its use monotonically and durably reserve any volatile admission window.
/// Re-reading this grant never renews its quota or authorizes replaying work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub agreement: Agreement,
    pub acknowledged_units: u64,
    pub acknowledged_sat: u64,
    pub reserved_units: u64,
    pub closed: bool,
}

/// A single-owner volatile allowance obtained only by durably increasing an
/// agreement's ceiling. Never serialize or reconstruct it from a saved grant.
/// Losing it consumes that window's capacity without inventing a payment claim.
#[derive(Debug)]
pub struct Allowance {
    agreement: Agreement,
    remaining: u64,
    revoked: Arc<AtomicBool>,
}
impl Allowance {
    pub fn agreement(&self) -> &Agreement {
        &self.agreement
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// A scheduling hint only; admission still consumes the window atomically
    /// under its adapter's lock. This cannot reserve or recreate authority.
    pub fn can_admit(&self, units: u64, now: u64) -> bool {
        units > 0
            && now >= self.agreement.created_at
            && now < self.agreement.expires_at
            && !self.revoked.load(Ordering::Acquire)
            && units <= self.remaining
    }

    pub fn admit(&mut self, units: u64, now: u64) -> bool {
        if now >= self.agreement.expires_at {
            self.revoked.store(true, Ordering::Release);
        }
        if !self.can_admit(units, now) {
            return false;
        }
        self.remaining -= units;
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    agreement: Agreement,
    payer_signature: String,
    provider_signature: String,
    receipt: Option<Signed<Receipt>>,
    reserved_units: u64,
    cleared_sat: u64,
    #[serde(skip)]
    revoked: Arc<AtomicBool>,
}
impl Record {
    fn units(&self) -> u64 {
        self.receipt
            .as_ref()
            .map_or(0, |r| r.payload.cumulative_units)
    }
    fn closed(&self) -> bool {
        self.receipt
            .as_ref()
            .is_some_and(|r| r.payload.final_receipt)
    }
    fn amount(&self) -> Result<u64, Error> {
        self.agreement.amount_for(self.units())
    }
    fn grant(&self) -> Result<Grant, Error> {
        Ok(Grant {
            agreement: self.agreement.clone(),
            acknowledged_units: self.units(),
            acknowledged_sat: self.amount()?,
            reserved_units: self.reserved_units,
            closed: self.closed(),
        })
    }
}

/// One provider's authoritative account across *all* its services. The accepted
/// set is supplied by local policy, never copied from an untrusted offer. The
/// default policy enables automation but grants strangers no credit.
#[derive(Debug, Clone)]
pub struct Book {
    provider: String,
    limits: Limits,
    accepted: BTreeSet<String>,
    records: BTreeMap<String, Record>,
    accounts: BTreeMap<String, CreditAccount>,
    revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u16,
    provider: String,
    limits: Limits,
    accepted: BTreeSet<String>,
    records: BTreeMap<String, Record>,
    accounts: BTreeMap<String, CreditAccountSnapshotV1>,
    revision: u64,
}

impl Book {
    pub(crate) fn revoke_all(&self) {
        for record in self.records.values() {
            record.revoked.store(true, Ordering::Release);
        }
    }
    pub fn new(
        provider: &str,
        limits: Limits,
        accepted: impl IntoIterator<Item = String>,
    ) -> Result<Self, Error> {
        identifier(provider)?;
        if limits.max_peers == 0
            || limits.max_peers > 128
            || limits.max_agreements == 0
            || limits.max_agreements > 4_096
            || limits.max_receipts == 0
            || limits.max_receipts > 16_384
            || limits.max_peer_exposure_sat > limits.max_total_exposure_sat
        {
            return Err(Error::Invalid("limits"));
        }
        let mut peers = BTreeSet::new();
        for peer in accepted {
            identifier(&peer)?;
            if peer == provider || peers.len() >= limits.max_peers || !peers.insert(peer) {
                return Err(Error::Invalid("accepted issuers"));
            }
        }
        Ok(Self {
            provider: provider.into(),
            limits,
            accepted: peers,
            records: BTreeMap::new(),
            accounts: BTreeMap::new(),
            revision: 0,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn enabled(&self) -> bool {
        self.limits.enabled
    }

    pub fn accepts(&self, peer: &str) -> bool {
        self.limits.enabled && self.accepted.contains(peer)
    }

    /// Disabling stops new grants and revokes every installed window. Re-enabling
    /// never revives a window already handed to a service adapter.
    pub(crate) fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        if self.limits.enabled != enabled {
            self.revision = add(self.revision, 1)?;
            self.limits.enabled = enabled;
        }
        if !enabled {
            self.revoke_all();
        }
        Ok(())
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = (&str, u64)> {
        self.records
            .iter()
            .map(|(id, record)| (id.as_str(), record.cleared_sat))
    }

    pub fn outstanding_sat(&self, peer: &str) -> Result<u64, Error> {
        Ok(self
            .accounts
            .get(peer)
            .map_or(0, CreditAccount::total_peer_credit_sat))
    }

    pub fn exposure(&self) -> Result<Exposure, Error> {
        self.exposure_for(None)
    }

    fn exposure_for(&self, peer: Option<&str>) -> Result<Exposure, Error> {
        let mut result = Exposure {
            outstanding_sat: 0,
            reserved_sat: 0,
            total_sat: 0,
        };
        for record in self
            .records
            .values()
            .filter(|r| peer.is_none_or(|p| r.agreement.payer == p))
        {
            let amount = record.amount()?;
            result.outstanding_sat = add(
                result.outstanding_sat,
                amount
                    .checked_sub(record.cleared_sat)
                    .ok_or(Error::Invalid("cleared amount"))?,
            )?;
            if !record.closed() {
                result.reserved_sat = add(
                    result.reserved_sat,
                    record
                        .agreement
                        .max_amount_sat
                        .checked_sub(amount)
                        .ok_or(Error::Invalid("reservation"))?,
                )?;
            }
        }
        result.total_sat = add(result.outstanding_sat, result.reserved_sat)?;
        Ok(result)
    }

    /// Verify both signatures before reserving the entire possible obligation.
    /// Persist the returned book before publishing this grant (PaymentStore does
    /// this atomically). Repeat IDs return the existing grant, including closure.
    pub fn accept(
        &mut self,
        agreement: &Agreement,
        payer_signature: &str,
        provider_signature: &str,
        verifier: &impl Verifier,
        now: u64,
    ) -> Result<Grant, Error> {
        agreement.validate()?;
        if agreement.provider != self.provider {
            return Err(Error::Authentication);
        }
        let message = WireMessage::Agreement(agreement.clone());
        authenticate(verifier, &agreement.payer, message.clone(), payer_signature)?;
        authenticate(verifier, &self.provider, message, provider_signature)?;
        if let Some(old) = self.records.get(&agreement.id) {
            if old.agreement != *agreement {
                return Err(Error::Conflict);
            }
            return old.grant();
        }
        if !self.limits.enabled || !self.accepted.contains(&agreement.payer) {
            return Err(Error::NotAccepted);
        }
        if agreement.expires_at <= now || agreement.created_at > now {
            return Err(Error::Expired);
        }
        if self.records.len() >= self.limits.max_agreements
            || add(self.exposure()?.total_sat, agreement.max_amount_sat)?
                > self.limits.max_total_exposure_sat
            || add(
                self.exposure_for(Some(&agreement.payer))?.total_sat,
                agreement.max_amount_sat,
            )? > self.limits.max_peer_exposure_sat
        {
            return Err(Error::Limit);
        }
        let next = add(self.revision, 1)?;
        let record = Record {
            agreement: agreement.clone(),
            payer_signature: payer_signature.into(),
            provider_signature: provider_signature.into(),
            receipt: None,
            reserved_units: 0,
            cleared_sat: 0,
            revoked: Arc::new(AtomicBool::new(false)),
        };
        let grant = record.grant()?;
        self.records.insert(agreement.id.clone(), record);
        self.revision = next;
        Ok(grant)
    }

    pub fn grant(&self, id: &str, now: u64) -> Result<Grant, Error> {
        let record = self.records.get(id).ok_or(Error::Unknown)?;
        if record.closed() {
            return Err(Error::Closed);
        }
        if record.agreement.expires_at <= now {
            return Err(Error::Expired);
        }
        record.grant()
    }

    /// Compare-and-increase the service ceiling before forwarding any packets.
    /// Replaying the same expected ceiling cannot obtain the allowance twice.
    pub fn reserve_window(
        &mut self,
        id: &str,
        expected_ceiling: u64,
        units: u64,
        now: u64,
    ) -> Result<Allowance, Error> {
        let grant = self.grant(id, now)?;
        if !self.accepts(&grant.agreement.payer) {
            return Err(Error::NotAccepted);
        }
        if grant.reserved_units != expected_ceiling {
            return Err(Error::Conflict);
        }
        let ceiling = add(expected_ceiling, units)?;
        if units == 0 || ceiling > grant.agreement.max_units {
            return Err(Error::Limit);
        }
        let revision = add(self.revision, 1)?;
        self.records
            .get_mut(id)
            .ok_or(Error::Unknown)?
            .reserved_units = ceiling;
        self.revision = revision;
        Ok(Allowance {
            agreement: grant.agreement,
            remaining: units,
            revoked: Arc::clone(&self.records.get(id).ok_or(Error::Unknown)?.revoked),
        })
    }

    /// `verified_units` comes from the provider's existing service meter, never
    /// from an untrusted network field. A final receipt must reconcile that meter
    /// exactly; it cannot discard delivered but still unsigned service.
    /// Receipt recovery is allowed after expiry, but grants are not reactivated.
    pub fn apply_receipt(
        &mut self,
        signed: &Signed<Receipt>,
        verifier: &impl Verifier,
        verified_units: u64,
    ) -> Result<Grant, Error> {
        let r = &signed.payload;
        identifier(&r.agreement_id)?;
        let old = self.records.get(&r.agreement_id).ok_or(Error::Unknown)?;
        if r.payer != old.agreement.payer || r.provider != self.provider {
            return Err(Error::Authentication);
        }
        if r.agreement_commitment != old.agreement.commitment()? {
            return Err(Error::Conflict);
        }
        authenticate(
            verifier,
            &r.payer,
            WireMessage::Receipt(r.clone()),
            &signed.signature,
        )?;
        if old.receipt.as_ref().is_some_and(|old| old.payload == *r) {
            return old.grant();
        }
        if old.closed() {
            return Err(Error::Closed);
        }
        if r.cumulative_units < old.units() {
            return Err(Error::Regressed);
        }
        if r.cumulative_units > verified_units
            || verified_units > old.reserved_units
            || (r.final_receipt && r.cumulative_units != verified_units)
        {
            return Err(Error::Invalid("service evidence"));
        }
        let amount = old.agreement.amount_for(r.cumulative_units)?;
        let delta = amount.checked_sub(old.amount()?).ok_or(Error::Regressed)?;
        if delta == 0 && r.cumulative_units == old.units() && !r.final_receipt {
            return old.grant();
        }
        let next = add(self.revision, 1)?;
        let mut account = match self.accounts.get(&r.payer) {
            Some(account) => account.clone(),
            None => self.new_account(&r.payer)?,
        };
        if delta > 0 {
            if self
                .accounts
                .values()
                .map(CreditAccount::applied_receipt_count)
                .sum::<usize>()
                >= self.limits.max_receipts
            {
                return Err(Error::Limit);
            }
            let claim = ServiceReceiptClaim {
                receipt_id: serde_json::to_string(&(&r.agreement_id, r.cumulative_units))?,
                issuer: r.payer.clone(),
                counterparty: self.provider.clone(),
                service: old.agreement.service.clone(),
                resource: old.agreement.resource.clone(),
                useful_service_units: r.cumulative_units - old.units(),
                amount_sat: delta,
                value_class: ValueClass::PeerCredit,
                issued_at_unix: old.agreement.created_at,
                expires_at_unix: old.agreement.expires_at,
            };
            // The saved bilateral authorization governs late reconciliation.
            // Evaluating at its creation time does not renew service permission.
            account.apply_receipt(
                &claim,
                &r.payer,
                AcceptanceMode::OfflineDeferred,
                old.agreement.created_at,
            )?;
        }
        let record = self
            .records
            .get_mut(&r.agreement_id)
            .ok_or(Error::Unknown)?;
        record.receipt = Some(signed.clone());
        if r.final_receipt {
            record.revoked.store(true, Ordering::Release);
        }
        let grant = record.grant()?;
        self.accounts.insert(r.payer.clone(), account);
        self.revision = next;
        Ok(grant)
    }

    pub(crate) fn settlement_terms(&self, id: &str) -> Result<(&Agreement, u64, u64), Error> {
        let record = self.records.get(id).ok_or(Error::Unknown)?;
        if !record.closed() {
            return Err(Error::Invalid("unfinished service"));
        }
        Ok((&record.agreement, record.amount()?, record.cleared_sat))
    }

    pub(crate) fn clear(
        &mut self,
        id: &str,
        cancellation_id: &str,
        amount: u64,
        previous: u64,
    ) -> Result<(), Error> {
        let (agreement, total, cleared) = self.settlement_terms(id)?;
        if cleared != previous || amount == 0 || add(cleared, amount)? > total {
            return Err(Error::Conflict);
        }
        let peer = agreement.payer.clone();
        let revision = add(self.revision, 1)?;
        let mut account = self.accounts.get(&peer).ok_or(Error::Unknown)?.clone();
        account.cancel_peer_credit(
            &cashu_credit::PeerCreditCancellation {
                cancellation_id: cancellation_id.into(),
                counterparty: self.provider.clone(),
                issuer: peer.clone(),
                amount_sat: amount,
            },
            &self.provider,
        )?;
        self.accounts.insert(peer, account);
        self.records.get_mut(id).ok_or(Error::Unknown)?.cleared_sat = add(cleared, amount)?;
        self.revision = revision;
        Ok(())
    }

    fn new_account(&self, peer: &str) -> Result<CreditAccount, Error> {
        Ok(CreditAccount::new(AccountPolicy {
            counterparty: self.provider.clone(),
            max_total_peer_credit_sat: self.limits.max_peer_exposure_sat,
            issuers: vec![IssuerPolicy {
                issuer: peer.into(),
                max_peer_credit_sat: self.limits.max_peer_exposure_sat,
                max_offline_peer_credit_sat: self.limits.max_peer_exposure_sat,
                max_closed_loop_sat: 0,
                max_withdrawable_sat: 0,
                expires_at_unix: None,
            }],
        })?)
    }

    pub fn encode(&self) -> Result<String, Error> {
        let snapshot = Snapshot {
            version: 1,
            provider: self.provider.clone(),
            limits: self.limits.clone(),
            accepted: self.accepted.clone(),
            records: self.records.clone(),
            revision: self.revision,
            accounts: self
                .accounts
                .iter()
                .map(|(id, a)| (id.clone(), a.snapshot()))
                .collect(),
        };
        let json = serde_json::to_string(&snapshot)?;
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        Ok(json)
    }

    /// Restore trusted local state. Signatures and external evidence must be
    /// integrity-protected with the database; JSON validation is not a MAC.
    pub fn decode(json: &str) -> Result<Self, Error> {
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        let snapshot: Snapshot = serde_json::from_str(json)?;
        if snapshot.version != 1 {
            return Err(Error::Invalid("snapshot version"));
        }
        let mut book = Self::new(&snapshot.provider, snapshot.limits, snapshot.accepted)?;
        book.records = snapshot.records;
        book.revision = snapshot.revision;
        for (id, snapshot) in snapshot.accounts {
            if !book.accepted.contains(&id) || snapshot.counterparty() != book.provider {
                return Err(Error::Invalid("account identity"));
            }
            let account = CreditAccount::from_snapshot(snapshot)?;
            if account.total_peer_credit_sat() != account.peer_credit(&id)?.outstanding_sat()
                || account.closed_loop(&id)?.total_deposited_sat() != 0
                || account.sat_reserve(&id)?.total_deposited_sat() != 0
            {
                return Err(Error::Invalid("account value class"));
            }
            book.accounts.insert(id, account);
        }
        if book.records.len() > book.limits.max_agreements
            || book.records.len() as u64 > book.revision
            || book
                .accounts
                .values()
                .map(CreditAccount::applied_receipt_count)
                .sum::<usize>()
                > book.limits.max_receipts
            || book.exposure()?.total_sat > book.limits.max_total_exposure_sat
        {
            return Err(Error::Limit);
        }
        for (id, record) in &book.records {
            record.agreement.validate()?;
            if *id != record.agreement.id
                || record.agreement.provider != book.provider
                || !book.accepted.contains(&record.agreement.payer)
                || record.reserved_units > record.agreement.max_units
                || record.units() > record.reserved_units
                || record.cleared_sat > record.amount()?
                || (record.cleared_sat > 0 && !record.closed())
                || record.payer_signature.is_empty()
                || record.provider_signature.is_empty()
            {
                return Err(Error::Invalid("stored agreement"));
            }
            if let Some(signed) = &record.receipt {
                let r = &signed.payload;
                if r.agreement_id != *id
                    || r.agreement_commitment != record.agreement.commitment()?
                    || r.payer != record.agreement.payer
                    || r.provider != book.provider
                    || r.cumulative_units > record.agreement.max_units
                    || signed.signature.is_empty()
                {
                    return Err(Error::Invalid("stored receipt"));
                }
            }
        }
        for peer in &book.accepted {
            let exposure = book.exposure_for(Some(peer))?;
            if exposure.total_sat > book.limits.max_peer_exposure_sat
                || exposure.outstanding_sat != book.outstanding_sat(peer)?
            {
                return Err(Error::Invalid("stored exposure"));
            }
        }
        Ok(book)
    }
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Invalid("amount overflow"))
}
