use super::*;
use crate::redemption::{
    Completion, ConversionEarnings, Redemption, RedemptionApproval, RedemptionProof, Role,
};
use std::collections::BTreeSet;

const MAX_REDEMPTIONS: usize = 128;

impl Account {
    /// Realized fees in discharged service credit and Lightning routing costs
    /// in millisats. Each completed invoice contributes once across retries.
    pub fn conversion_earnings(&self) -> Result<ConversionEarnings, Error> {
        let mut earned = ConversionEarnings::default();
        for (role, done) in self
            .redemptions
            .values()
            .filter_map(|r| Some((&r.role, r.done.as_ref()?)))
        {
            match role {
                Role::Forward { incoming, outgoing } => {
                    let spread = incoming
                        .payload
                        .fee_sat
                        .checked_sub(outgoing.fee_sat)
                        .ok_or(Error::Conflict)?;
                    earned.forwarding_fee_sat = earned
                        .forwarding_fee_sat
                        .checked_add(spread)
                        .ok_or(Error::Limit)?;
                }
                Role::Payer { incoming, .. } => {
                    earned.terminal_fee_sat = earned
                        .terminal_fee_sat
                        .checked_add(incoming.payload.fee_sat)
                        .ok_or(Error::Limit)?;
                    earned.network_fee_msat = earned
                        .network_fee_msat
                        .checked_add(done.fee_msat)
                        .ok_or(Error::Limit)?;
                }
                Role::Holder { .. } => {}
            }
        }
        Ok(earned)
    }
    pub fn outgoing_redemption(&self, hash: &str) -> Option<&Redemption> {
        self.redemptions.get(hash)?.role.outgoing()
    }
    pub fn pending_cashouts(&self) -> impl Iterator<Item = &Redemption> {
        self.redemptions
            .values()
            .filter_map(|record| match &record.role {
                Role::Holder {
                    outgoing,
                    wallet: Some(_),
                } if record.done.is_none() => Some(outgoing),
                _ => None,
            })
    }
    pub fn incoming_redemption(&self, hash: &str) -> Option<&Redemption> {
        Some(&self.redemptions.get(hash)?.role.incoming()?.payload)
    }
    pub fn redemption_paid(&self, hash: &str) -> bool {
        self.redemptions.get(hash).is_some_and(|r| r.done.is_some())
    }
    pub fn redemption_proof(&self, hash: &str) -> Result<Option<RedemptionProof>, Error> {
        let Some(terms) = self.incoming_redemption(hash) else {
            return Ok(None);
        };
        let Some(done) = self.redemptions[hash].done.as_ref() else {
            return Ok(None);
        };
        Ok(Some(RedemptionProof {
            request_id: terms.id()?,
            payment_hash: hash.into(),
            preimage: done.preimage.clone(),
        }))
    }
    pub(crate) fn redemption_record(&self, hash: &str) -> Option<&Record> {
        self.redemptions.get(hash)
    }

    pub fn available_claims(&self) -> impl Iterator<Item = (&Agreement, u64)> {
        let available = self.accepts_new_redemption();
        self.seller
            .records()
            .filter(move |(id, _)| available && !self.debt_locked(id))
            .filter_map(|(id, _)| self.seller.settlement_terms(id).ok())
            .filter(|(_, total, cleared)| total > cleared)
            .map(|(a, total, cleared)| (a, total - cleared))
    }
    pub fn available_debts(&self) -> impl Iterator<Item = (&Agreement, u64)> {
        let available = self.accepts_new_redemption();
        self.buyer
            .records()
            .filter(move |(id, _)| available && !self.debt_locked(id))
            .filter_map(|(id, _)| self.buyer.settlement_terms(id).ok())
            .filter(|(_, total, cleared)| total > cleared)
            .map(|(a, total, cleared)| (a, total - cleared))
    }

    fn accepts_new_redemption(&self) -> bool {
        self.buyer.enabled() && self.seller.enabled() && self.redemptions.len() < MAX_REDEMPTIONS
    }

    /// Nonbinding availability for a new wallet payout. Journaled obligations
    /// and pending fee ceilings count immediately, including after restart.
    pub fn can_reserve_payout(
        &self,
        amount_sat: u64,
        fee_msat: u64,
        lifetime_payout_sat: u64,
        lifetime_fee_msat: u64,
    ) -> bool {
        amount_sat != 0
            && self.accepts_new_redemption()
            && self
                .check_payout_budget(lifetime_payout_sat, lifetime_fee_msat, amount_sat, fee_msat)
                .is_ok()
    }
    fn debt_locked(&self, id: &str) -> bool {
        self.redemption_locks(id)
            || self
                .pending_nettings()
                .any(|n| n.left_sale == id || n.right_sale == id)
    }
    pub(super) fn redemption_locks(&self, id: &str) -> bool {
        self.redemptions
            .values()
            .filter(|r| r.done.is_none())
            .any(|r| r.role.legs().any(|t| t.agreement_id == id))
    }

    pub(crate) fn reserve_redemption(
        &mut self,
        role: Role,
        approval: Option<&RedemptionApproval>,
    ) -> Result<(), Error> {
        let hash = role
            .legs()
            .next()
            .ok_or(Error::Unknown)?
            .payment_hash
            .clone();
        if let Some(r) = self.redemptions.get(&hash) {
            return if r.role == role {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if !self.seller.enabled() || !self.buyer.enabled() {
            return Err(Error::NotAccepted);
        }
        if self.redemptions.len() >= MAX_REDEMPTIONS {
            return Err(Error::Limit);
        }
        self.check_role(&hash, &role)?;
        for t in role.legs() {
            self.check_debt(t, false)?;
            if self.debt_locked(&t.agreement_id) {
                return Err(Error::Conflict);
            }
        }
        if let Role::Payer {
            incoming,
            max_fee_msat,
            ..
        } = &role
        {
            let a = approval.ok_or(Error::NotAccepted)?;
            self.check_payout_budget(
                a.max_lifetime_payout_sat,
                a.max_lifetime_fees_msat,
                incoming.payload.amount_sat,
                *max_fee_msat,
            )?;
        }
        self.update(|a| {
            a.redemptions.insert(hash, Record { role, done: None });
            Ok(())
        })
    }

    pub(crate) fn check_payout_budget(
        &self,
        lifetime_payout_sat: u64,
        lifetime_fee_msat: u64,
        mut payouts: u64,
        mut fees: u64,
    ) -> Result<(), Error> {
        for r in self.redemptions.values() {
            if let Role::Payer {
                incoming,
                max_fee_msat,
                ..
            } = &r.role
            {
                payouts = payouts
                    .checked_add(incoming.payload.amount_sat)
                    .ok_or(Error::Limit)?;
                fees = fees
                    .checked_add(r.done.as_ref().map_or(*max_fee_msat, |d| d.fee_msat))
                    .ok_or(Error::Limit)?;
            }
        }
        if payouts > lifetime_payout_sat || fees > lifetime_fee_msat {
            return Err(Error::Limit);
        }
        Ok(())
    }

    fn check_role(&self, hash: &str, role: &Role) -> Result<(), Error> {
        for t in role.legs() {
            t.validate()?;
            if t.payment_hash != hash {
                return Err(Error::Conflict);
            }
        }
        if let Some(s) = role.incoming() {
            if s.payload.debtor != self.owner() || s.signature.len() != 128 {
                return Err(Error::Authentication);
            }
        }
        if let Some(t) = role.outgoing() {
            if t.creditor != self.owner() {
                return Err(Error::Authentication);
            }
        }
        match role {
            Role::Holder { outgoing, wallet } => {
                if outgoing.parent.is_some() {
                    return Err(Error::Conflict);
                }
                if let Some(id) = wallet {
                    identifier(id)?;
                }
            }
            Role::Payer { wallet, .. } => identifier(wallet)?,
            Role::Forward { incoming, outgoing } => {
                let t = &incoming.payload;
                if outgoing.parent.as_deref() != Some(&t.id()?)
                    || outgoing.depth != t.depth + 1
                    || outgoing.amount_sat != t.amount_sat
                    || outgoing.fee_sat > t.fee_sat
                    || outgoing.bolt11 != t.bolt11
                    || outgoing.agreement_id == t.agreement_id
                    || outgoing.debtor == t.creditor
                {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn check_new_redemption_debt(&self, t: &Redemption) -> Result<(), Error> {
        if !self.buyer.enabled() || !self.seller.enabled() {
            return Err(Error::NotAccepted);
        }
        if self.debt_locked(&t.agreement_id) {
            return Err(Error::Conflict);
        }
        self.check_debt(t, false)
    }

    fn check_debt(&self, t: &Redemption, committed: bool) -> Result<(), Error> {
        let (a, total, cleared) = if self.owner() == t.creditor {
            self.seller.settlement_terms(&t.agreement_id)?
        } else {
            self.buyer.settlement_terms(&t.agreement_id)?
        };
        if a.payer != t.debtor
            || a.provider != t.creditor
            || a.commitment()? != t.agreement_commitment
        {
            return Err(Error::Authentication);
        }
        let end = t
            .previous_sat
            .checked_add(t.debit_sat()?)
            .ok_or(Error::Limit)?;
        if end > total || (committed && end > cleared) || (!committed && t.previous_sat != cleared)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn complete_redemption(
        &mut self,
        hash: &str,
        done: Completion,
    ) -> Result<(), Error> {
        let r = self.redemptions.get(hash).ok_or(Error::Unknown)?;
        if let Some(old) = &r.done {
            return if old.preimage == done.preimage && old.fee_msat == done.fee_msat {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.check_completion(&r.role, &done)?;
        let role = r.role.clone();
        self.update(|a| {
            for t in role.legs() {
                a.check_debt(t, false)?;
                if t.creditor == a.owner() {
                    // Separate namespace from all arbitrary legacy netting IDs.
                    let cancel = format!("ln/{}", t.id()?);
                    if a.nettings.contains_key(&cancel) {
                        return Err(Error::Conflict);
                    }
                    a.seller
                        .clear(&t.agreement_id, &cancel, t.debit_sat()?, t.previous_sat)?;
                } else {
                    a.buyer
                        .clear(&t.agreement_id, t.debit_sat()?, t.previous_sat)?;
                }
            }
            if let Role::Holder {
                outgoing,
                wallet: Some(_),
            } = &role
            {
                a.seller
                    .record_wallet_repayment(&outgoing.debtor, outgoing.amount_sat);
            }
            a.redemptions.get_mut(hash).ok_or(Error::Unknown)?.done = Some(done);
            Ok(())
        })
    }

    fn check_completion(&self, role: &Role, done: &Completion) -> Result<(), Error> {
        let t = role
            .outgoing()
            .or_else(|| role.incoming().map(|s| &s.payload))
            .ok_or(Error::Unknown)?;
        let proof = RedemptionProof {
            request_id: t.id()?,
            payment_hash: t.payment_hash.clone(),
            preimage: done.preimage.clone(),
        };
        proof.check(t)?;
        match role {
            Role::Payer { max_fee_msat, .. }
                if done.fee_msat <= *max_fee_msat && done.downstream_signature.is_none() =>
            {
                Ok(())
            }
            Role::Holder { .. } | Role::Forward { .. }
                if done.fee_msat == 0
                    && done
                        .downstream_signature
                        .as_ref()
                        .is_some_and(|s| s.len() == 128) =>
            {
                Ok(())
            }
            _ => Err(Error::Conflict),
        }
    }

    pub(super) fn validate_redemptions<'a>(
        &'a self,
        offsets: &mut BTreeMap<String, Vec<(u64, u64)>>,
        locked: &mut BTreeSet<&'a str>,
    ) -> Result<(), Error> {
        if self.redemptions.len() > MAX_REDEMPTIONS {
            return Err(Error::Limit);
        }
        for (hash, r) in &self.redemptions {
            self.check_role(hash, &r.role)?;
            if let Some(done) = &r.done {
                self.check_completion(&r.role, done)?;
            }
            for t in r.role.legs() {
                self.check_debt(t, r.done.is_some())?;
                if r.done.is_some() {
                    offsets
                        .entry(t.agreement_id.clone())
                        .or_default()
                        .push((t.previous_sat, t.debit_sat()?));
                } else if !locked.insert(&t.agreement_id) {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }
}
