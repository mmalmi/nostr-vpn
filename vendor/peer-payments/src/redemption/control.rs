use super::*;
use crate::{protocol::authenticate, sign_message, Controller, DurableState, SchnorrVerifier};

impl Controller<'_> {
    /// Pay a third-party invoice using an existing claim. The holder explicitly
    /// accepts a matching preimage and its selected debtor's signed confirmation.
    pub fn request_invoice_payment(
        &mut self,
        agreement_id: &str,
        bolt11: &str,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.request_invoice_payment_with_fee(agreement_id, bolt11, 0, 0, now)
    }
    /// Exchange the quoted fee only within the holder's independent local cap.
    pub fn request_invoice_payment_with_fee(
        &mut self,
        agreement_id: &str,
        bolt11: &str,
        fee_sat: u64,
        max_fee_sat: u64,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.request_redemption_inner(agreement_id, bolt11, fee_sat, max_fee_sat, None, now)
    }
    /// Cash out to an unpaid invoice owned by this local wallet. The creditor
    /// verifies its own wallet's receipt again before clearing the claim.
    pub fn request_redemption(
        &mut self,
        agreement_id: &str,
        bolt11: &str,
        wallet: &mut impl RedemptionWallet,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.request_redemption_with_fee(agreement_id, bolt11, 0, 0, wallet, now)
    }
    pub fn request_redemption_with_fee(
        &mut self,
        agreement_id: &str,
        bolt11: &str,
        fee_sat: u64,
        max_fee_sat: u64,
        wallet: &mut impl RedemptionWallet,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.request_redemption_inner(
            agreement_id,
            bolt11,
            fee_sat,
            max_fee_sat,
            Some(wallet),
            now,
        )
    }
    fn request_redemption_inner(
        &mut self,
        id: &str,
        bolt11: &str,
        fee_sat: u64,
        max_fee_sat: u64,
        wallet: Option<&mut dyn RedemptionWallet>,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        if fee_sat > max_fee_sat {
            return Err(Error::Limit);
        }
        let parsed = decode_invoice(bolt11)?;
        let hash = parsed.payment_hash().to_string();
        let mut wallet = wallet;
        let wallet_id = match &mut wallet {
            Some(w) => Some(w.identity(parsed.currency())?),
            None => None,
        };
        if let Some(r) = self.store.book().redemption_record(&hash) {
            match &r.role {
                Role::Holder { outgoing, wallet }
                    if outgoing.bolt11 == bolt11
                        && outgoing.fee_sat == fee_sat
                        && outgoing.agreement_id == id
                        && wallet == &wallet_id =>
                {
                    return self.sign_terms(outgoing)
                }
                _ => return Err(Error::Conflict),
            }
        }
        let (amount_sat, hash) = invoice_terms(bolt11, now)?;
        let terms = self.sale(id, bolt11, hash, amount_sat, fee_sat, None)?;
        if let Some(w) = wallet {
            if !matches!(w.received(&terms)?, InvoiceState::Unpaid) {
                return Err(Error::Conflict);
            }
        }
        self.store.transact(|a| {
            a.reserve_redemption(
                Role::Holder {
                    outgoing: terms.clone(),
                    wallet: wallet_id,
                },
                None,
            )
        })?;
        self.sign_terms(&terms)
    }

    fn sale(
        &self,
        id: &str,
        bolt11: &str,
        hash: String,
        amount_sat: u64,
        fee_sat: u64,
        parent: Option<&Redemption>,
    ) -> Result<Redemption, Error> {
        let (a, total, cleared) = self.store.book().seller().settlement_terms(id)?;
        if total.checked_sub(cleared).ok_or(Error::Conflict)?
            < amount_sat.checked_add(fee_sat).ok_or(Error::Limit)?
        {
            return Err(Error::Limit);
        }
        let terms = Redemption {
            creditor: a.provider.clone(),
            debtor: a.payer.clone(),
            agreement_id: id.into(),
            agreement_commitment: a.commitment()?,
            previous_sat: cleared,
            amount_sat,
            fee_sat,
            bolt11: bolt11.into(),
            payment_hash: hash,
            parent: parent.map(Redemption::id).transpose()?,
            depth: parent.map_or(1, |p| p.depth.saturating_add(1)),
        };
        terms.validate()?;
        Ok(terms)
    }
    fn sign_terms(&self, t: &Redemption) -> Result<Signed<Redemption>, Error> {
        Ok(Signed {
            payload: t.clone(),
            signature: sign_message(self.key, &WireMessage::Redemption(t.clone()))?,
        })
    }
    fn authorize_incoming(
        &self,
        s: &Signed<Redemption>,
        approval: &RedemptionApproval,
    ) -> Result<(), Error> {
        approval.check(&s.payload)?;
        if s.payload.debtor != self.store.book().owner() {
            return Err(Error::Authentication);
        }
        s.payload.validate()?;
        authenticate(
            &SchnorrVerifier,
            &s.payload.creditor,
            WireMessage::Redemption(s.payload.clone()),
            &s.signature,
        )
    }
    fn sign_paid(&self, hash: &str) -> Result<Signed<RedemptionProof>, Error> {
        let proof = self
            .store
            .book()
            .redemption_proof(hash)?
            .ok_or(Error::Pending)?;
        Ok(Signed {
            signature: sign_message(self.key, &WireMessage::RedemptionPaid(proof.clone()))?,
            payload: proof,
        })
    }

    /// Relay an invoice along an independently approved matured claim. Both the
    /// incoming debt and outgoing claim are locked together before the quote is sent.
    pub fn forward_redemption(
        &mut self,
        incoming: &Signed<Redemption>,
        approval: &RedemptionApproval,
        onward_agreement: &str,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.forward_redemption_with_fee(incoming, approval, onward_agreement, 0, now)
    }
    pub fn forward_redemption_with_fee(
        &mut self,
        incoming: &Signed<Redemption>,
        approval: &RedemptionApproval,
        onward_agreement: &str,
        onward_fee_sat: u64,
        now: u64,
    ) -> Result<Signed<Redemption>, Error> {
        self.authorize_incoming(incoming, approval)?;
        let t = &incoming.payload;
        if onward_fee_sat > t.fee_sat {
            return Err(Error::Limit);
        }
        if let Some(r) = self.store.book().redemption_record(&t.payment_hash) {
            return match &r.role {
                Role::Forward {
                    incoming: s,
                    outgoing,
                } if s == incoming
                    && outgoing.agreement_id == onward_agreement
                    && outgoing.fee_sat == onward_fee_sat =>
                {
                    self.sign_terms(outgoing)
                }
                _ => Err(Error::Conflict),
            };
        }
        t.validate_invoice(now)?;
        let outgoing = self.sale(
            onward_agreement,
            &t.bolt11,
            t.payment_hash.clone(),
            t.amount_sat,
            onward_fee_sat,
            Some(t),
        )?;
        self.store.transact(|a| {
            a.reserve_redemption(
                Role::Forward {
                    incoming: incoming.clone(),
                    outgoing: outgoing.clone(),
                },
                None,
            )
        })?;
        self.sign_terms(&outgoing)
    }

    /// Authorize exactly one outgoing Lightning payment. The caller provides
    /// local per-intent and aggregate lifetime spending limits. Recover an
    /// interrupted wallet call with the exact same invoice and wallet.
    pub fn pay_redemption(
        &mut self,
        incoming: &Signed<Redemption>,
        approval: &RedemptionApproval,
        wallet: &mut impl RedemptionWallet,
        now: u64,
    ) -> Result<Signed<RedemptionProof>, Error> {
        let t = &incoming.payload;
        let hash = &t.payment_hash;
        let (state, fee_limit, fresh) = if let Some(r) = self.store.book().redemption_record(hash) {
            approval.check_binding(t)?;
            let Role::Payer {
                incoming: signed,
                wallet: bound,
                max_fee_msat,
            } = &r.role
            else {
                return Err(Error::Conflict);
            };
            // Only an exact copy of the authenticated, journaled signature and
            // payload can use this shortcut. It never authorizes a new payment.
            if signed != incoming {
                return Err(Error::Conflict);
            }
            if r.done.is_some() {
                return self.sign_paid(hash);
            }
            if &wallet.identity(decode_invoice(&t.bolt11)?.currency())? != bound {
                return Err(Error::Authentication);
            }
            (
                wallet.payment(t)?,
                approval.max_fee_msat.min(*max_fee_msat),
                false,
            )
        } else {
            self.authorize_incoming(incoming, approval)?;
            let currency = t.validate_invoice(now)?;
            self.store.book().check_new_redemption_debt(t)?;
            let wallet_id = wallet.identity(currency)?;
            if !matches!(wallet.payment(t)?, PaymentState::Missing) {
                return Err(Error::Conflict);
            }
            self.store.transact(|a| {
                a.reserve_redemption(
                    Role::Payer {
                        incoming: incoming.clone(),
                        wallet: wallet_id,
                        max_fee_msat: approval.max_fee_msat,
                    },
                    Some(approval),
                )
            })?;
            (PaymentState::Missing, approval.max_fee_msat, true)
        };
        let state = match state {
            PaymentState::Missing | PaymentState::Failed => {
                if !self.store.book().buyer().enabled() {
                    return Err(Error::NotAccepted);
                }
                if !fresh {
                    approval.check(t)?;
                    t.validate_invoice(now)?;
                    self.store.book().check_payout_budget(
                        approval.max_lifetime_payout_sat,
                        approval.max_lifetime_fees_msat,
                        0,
                        0,
                    )?;
                }
                wallet.submit(t, fee_limit)?;
                wallet.payment(t)?
            }
            state => state,
        };
        let PaymentState::Paid { preimage, fee_msat } = state else {
            return Err(Error::Pending);
        };
        self.store.transact(|a| {
            a.complete_redemption(
                hash,
                Completion {
                    preimage,
                    fee_msat,
                    downstream_signature: None,
                },
            )
        })?;
        self.sign_paid(hash)
    }

    fn verified_downstream(
        &self,
        s: &Signed<RedemptionProof>,
    ) -> Result<(&Record, &Redemption), Error> {
        let r = self
            .store
            .book()
            .redemption_record(&s.payload.payment_hash)
            .ok_or(Error::Unknown)?;
        let t = r.role.outgoing().ok_or(Error::Conflict)?;
        s.payload.check(t)?;
        authenticate(
            &SchnorrVerifier,
            &t.debtor,
            WireMessage::RedemptionPaid(s.payload.clone()),
            &s.signature,
        )?;
        Ok((r, t))
    }
    fn finish(&mut self, s: &Signed<RedemptionProof>) -> Result<(), Error> {
        self.store.transact(|a| {
            a.complete_redemption(
                &s.payload.payment_hash,
                Completion {
                    preimage: s.payload.preimage.clone(),
                    fee_msat: 0,
                    downstream_signature: Some(s.signature.clone()),
                },
            )
        })
    }
    pub fn finish_forwarded_redemption(
        &mut self,
        s: &Signed<RedemptionProof>,
    ) -> Result<Signed<RedemptionProof>, Error> {
        let (r, _) = self.verified_downstream(s)?;
        if !matches!(r.role, Role::Forward { .. }) {
            return Err(Error::Conflict);
        }
        if r.done.is_none() {
            self.finish(s)?;
        }
        self.sign_paid(&s.payload.payment_hash)
    }
    pub fn finish_invoice_payment(&mut self, s: &Signed<RedemptionProof>) -> Result<(), Error> {
        let (r, _) = self.verified_downstream(s)?;
        if !matches!(r.role, Role::Holder { wallet: None, .. }) {
            return Err(Error::Conflict);
        }
        if r.done.is_some() {
            return Ok(());
        }
        self.finish(s)
    }
    pub fn finish_redemption(
        &mut self,
        s: &Signed<RedemptionProof>,
        wallet: &mut impl RedemptionWallet,
    ) -> Result<(), Error> {
        let (r, t) = self.verified_downstream(s)?;
        let Role::Holder {
            wallet: Some(id), ..
        } = &r.role
        else {
            return Err(Error::Conflict);
        };
        if r.done.is_some() {
            return Ok(());
        }
        if &wallet.identity(decode_invoice(&t.bolt11)?.currency())? != id {
            return Err(Error::Authentication);
        }
        match wallet.received(t)? {
            InvoiceState::Paid { preimage } if preimage == s.payload.preimage => self.finish(s),
            _ => Err(Error::Pending),
        }
    }
}
