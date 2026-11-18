use crate::{
    book::MAX_STATE_BYTES,
    protocol::{authenticate, identifier},
    Agreement, Error, Receipt, Signed, Verifier, WireMessage,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendingLimits {
    pub enabled: bool,
    /// All unresolved agreements reserve their full capacity across services.
    pub max_reserved_sat: u64,
    /// Cumulative obligations, including closed agreements. Closing cannot
    /// replenish this budget; a separate, explicit policy update is required.
    pub max_lifetime_sat: u64,
    pub max_agreements: usize,
}
impl Default for SpendingLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_reserved_sat: 100,
            max_lifetime_sat: 1_000,
            max_agreements: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Purchase {
    agreement: Agreement,
    provider_signature: String,
    authorized_receipt: Option<Receipt>,
    completion: Option<Signed<Receipt>>,
    cleared_sat: u64,
}

/// A payer's durable signing authority shared by every service. Call prepare
/// through BuyerStore *before* signing/sending the agreement, and authorize_receipt
/// through BuyerStore before signing/sending any cumulative payment.
#[derive(Debug, Clone)]
pub struct Buyer {
    version: u16,
    payer: String,
    limits: SpendingLimits,
    purchases: BTreeMap<String, Purchase>,
    revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuyerSnapshot {
    version: u16,
    payer: String,
    limits: SpendingLimits,
    purchases: BTreeMap<String, Purchase>,
    revision: u64,
}

impl Buyer {
    pub fn new(payer: &str, limits: SpendingLimits) -> Result<Self, Error> {
        identifier(payer)?;
        if limits.max_agreements == 0
            || limits.max_agreements > 4_096
            || limits.max_reserved_sat > limits.max_lifetime_sat
        {
            return Err(Error::Invalid("spending limits"));
        }
        Ok(Self {
            version: 1,
            payer: payer.into(),
            limits,
            purchases: BTreeMap::new(),
            revision: 0,
        })
    }
    pub fn payer(&self) -> &str {
        &self.payer
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn enabled(&self) -> bool {
        self.limits.enabled
    }

    pub(crate) fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        if self.limits.enabled != enabled {
            self.revision = add(self.revision, 1)?;
            self.limits.enabled = enabled;
        }
        Ok(())
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = (&str, u64)> {
        self.purchases
            .iter()
            .map(|(id, p)| (id.as_str(), p.cleared_sat))
    }

    pub fn exposure(&self) -> Result<(u64, u64), Error> {
        let mut reserved = 0u64;
        let mut lifetime = 0u64;
        for p in self.purchases.values() {
            let amount = if let Some(done) = &p.completion {
                p.agreement.amount_for(done.payload.cumulative_units)?
            } else {
                reserved = add(reserved, p.agreement.max_amount_sat)?;
                p.agreement.max_amount_sat
            };
            lifetime = add(lifetime, amount)?;
        }
        Ok((reserved, lifetime))
    }

    pub(crate) fn settlement_terms(&self, id: &str) -> Result<(&Agreement, u64, u64), Error> {
        let p = self.purchases.get(id).ok_or(Error::Unknown)?;
        let done = p
            .completion
            .as_ref()
            .ok_or(Error::Invalid("unfinished purchase"))?;
        Ok((
            &p.agreement,
            p.agreement.amount_for(done.payload.cumulative_units)?,
            p.cleared_sat,
        ))
    }

    pub(crate) fn clear(&mut self, id: &str, amount: u64, previous: u64) -> Result<(), Error> {
        let (_, total, cleared) = self.settlement_terms(id)?;
        if cleared != previous || amount == 0 || add(cleared, amount)? > total {
            return Err(Error::Conflict);
        }
        let revision = add(self.revision, 1)?;
        self.purchases
            .get_mut(id)
            .ok_or(Error::Unknown)?
            .cleared_sat = add(cleared, amount)?;
        self.revision = revision;
        Ok(())
    }

    pub fn prepare(
        &mut self,
        offer: &Signed<Agreement>,
        verifier: &impl Verifier,
        now: u64,
    ) -> Result<Agreement, Error> {
        let a = &offer.payload;
        a.validate()?;
        if a.payer != self.payer {
            return Err(Error::Authentication);
        }
        authenticate(
            verifier,
            &a.provider,
            WireMessage::Agreement(a.clone()),
            &offer.signature,
        )?;
        if !self.limits.enabled {
            return Err(Error::NotAccepted);
        }
        if let Some(old) = self.purchases.get(&a.id) {
            if old.agreement != *a {
                return Err(Error::Conflict);
            }
            if old.completion.is_some() {
                return Err(Error::Closed);
            }
            return Ok(old.agreement.clone());
        }
        if a.expires_at <= now || a.created_at > now {
            return Err(Error::Expired);
        }
        let (reserved, lifetime) = self.exposure()?;
        if self.purchases.len() >= self.limits.max_agreements
            || add(reserved, a.max_amount_sat)? > self.limits.max_reserved_sat
            || add(lifetime, a.max_amount_sat)? > self.limits.max_lifetime_sat
        {
            return Err(Error::Limit);
        }
        let next = add(self.revision, 1)?;
        self.purchases.insert(
            a.id.clone(),
            Purchase {
                agreement: a.clone(),
                provider_signature: offer.signature.clone(),
                authorized_receipt: None,
                completion: None,
                cleared_sat: 0,
            },
        );
        self.revision = next;
        Ok(a.clone())
    }

    /// Called with cumulative units verified by the payer's service adapter,
    /// never a provider's unverified usage report. It cannot exceed the original
    /// signed terms, regress, or undo a final authorization.
    pub fn authorize_receipt(
        &mut self,
        id: &str,
        verified_units: u64,
        final_receipt: bool,
    ) -> Result<Receipt, Error> {
        let p = self.purchases.get(id).ok_or(Error::Unknown)?;
        p.agreement.amount_for(verified_units)?;
        let receipt = Receipt {
            agreement_id: id.into(),
            agreement_commitment: p.agreement.commitment()?,
            payer: self.payer.clone(),
            provider: p.agreement.provider.clone(),
            cumulative_units: verified_units,
            final_receipt,
        };
        if let Some(old) = &p.authorized_receipt {
            if *old == receipt {
                return Ok(old.clone());
            }
            if old.final_receipt {
                return Err(Error::Closed);
            }
            if old.cumulative_units > verified_units {
                return Err(Error::Regressed);
            }
        }
        let next = add(self.revision, 1)?;
        self.purchases
            .get_mut(id)
            .ok_or(Error::Unknown)?
            .authorized_receipt = Some(receipt.clone());
        self.revision = next;
        Ok(receipt)
    }

    /// Release only unused capacity after the provider acknowledges the exact
    /// final receipt. Lost replies and expired grants keep their reservation.
    pub fn acknowledge(
        &mut self,
        ack: &Signed<Receipt>,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        let p = self
            .purchases
            .get(&ack.payload.agreement_id)
            .ok_or(Error::Unknown)?;
        if p.authorized_receipt.as_ref() != Some(&ack.payload) || !ack.payload.final_receipt {
            return Err(Error::Conflict);
        }
        authenticate(
            verifier,
            &p.agreement.provider,
            WireMessage::Receipt(ack.payload.clone()),
            &ack.signature,
        )?;
        if p.completion.is_some() {
            return Ok(());
        }
        let next = add(self.revision, 1)?;
        self.purchases
            .get_mut(&ack.payload.agreement_id)
            .ok_or(Error::Unknown)?
            .completion = Some(ack.clone());
        self.revision = next;
        Ok(())
    }

    pub fn encode(&self) -> Result<String, Error> {
        let json = serde_json::to_string(&BuyerSnapshot {
            version: self.version,
            payer: self.payer.clone(),
            limits: self.limits.clone(),
            purchases: self.purchases.clone(),
            revision: self.revision,
        })?;
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        Ok(json)
    }

    pub fn decode(json: &str) -> Result<Self, Error> {
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        let snapshot: BuyerSnapshot = serde_json::from_str(json)?;
        let book = Self {
            version: snapshot.version,
            payer: snapshot.payer,
            limits: snapshot.limits,
            purchases: snapshot.purchases,
            revision: snapshot.revision,
        };
        Self::new(&book.payer, book.limits.clone())?;
        let (reserved, lifetime) = book.exposure()?;
        if book.version != 1
            || book.purchases.len() > book.limits.max_agreements
            || book.purchases.len() as u64 > book.revision
            || reserved > book.limits.max_reserved_sat
            || lifetime > book.limits.max_lifetime_sat
        {
            return Err(Error::Invalid("buyer snapshot"));
        }
        for (id, p) in &book.purchases {
            p.agreement.validate()?;
            if *id != p.agreement.id
                || p.agreement.payer != book.payer
                || p.provider_signature.is_empty()
                || p.cleared_sat
                    > p.completion.as_ref().map_or(Ok(0), |r| {
                        p.agreement.amount_for(r.payload.cumulative_units)
                    })?
            {
                return Err(Error::Invalid("buyer agreement"));
            }
            if let Some(r) = &p.authorized_receipt {
                if r.agreement_id != *id
                    || r.agreement_commitment != p.agreement.commitment()?
                    || r.payer != book.payer
                    || r.provider != p.agreement.provider
                {
                    return Err(Error::Invalid("buyer receipt"));
                }
                p.agreement.amount_for(r.cumulative_units)?;
            }
            if let Some(done) = &p.completion {
                if p.authorized_receipt.as_ref() != Some(&done.payload)
                    || !done.payload.final_receipt
                    || done.signature.is_empty()
                {
                    return Err(Error::Invalid("buyer completion"));
                }
            }
        }
        Ok(book)
    }
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Invalid("spending overflow"))
}
