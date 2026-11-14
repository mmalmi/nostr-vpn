//! Deterministic control transitions. Applications choose the peer and service,
//! supply independently measured usage, and carry bounded records over an
//! authenticated transport. No discovery, network task or signing key is owned here.
use crate::{
    protocol::{authenticate, MAX_WIRE_BYTES},
    sign_message, AccountStore, Agreement, Allowance, DurableState, Error, Grant, Keypair, Netting,
    Receipt, SchnorrVerifier, Signed, WireMessage,
};
use serde::{Deserialize, Serialize};

/// Local purchase intent, never copied from an unsolicited network offer.
/// Rational prices are compared without rounding; total obligations are still
/// rounded upwards by Agreement::amount_for and bounded by max_amount_sat.
pub struct PurchaseIntent<'a> {
    pub provider: &'a str,
    pub service: &'a str,
    pub resource: &'a str,
    pub units: u64,
    pub max_price_sat: u64,
    pub price_per_units: u64,
    pub max_amount_sat: u64,
    pub max_duration_secs: u64,
}

impl PurchaseIntent<'_> {
    pub(crate) fn check(&self, a: &Agreement, now: u64) -> Result<(), Error> {
        a.validate()?;
        if a.provider != self.provider || a.service != self.service || a.resource != self.resource {
            return Err(Error::Authentication);
        }
        if a.created_at > now || a.expires_at <= now {
            return Err(Error::Expired);
        }
        if self.price_per_units == 0
            || a.max_units != self.units
            || a.max_amount_sat > self.max_amount_sat
            || a.expires_at - a.created_at > self.max_duration_secs
            || u128::from(a.price_sat) * u128::from(self.price_per_units)
                > u128::from(self.max_price_sat) * u128::from(a.price_per_units)
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
}

/// Replays return the same grant, but never another admission window. A lost
/// window remains reserved across restart; neither an ACK nor a timeout renews it.
pub struct Opened {
    pub grant: Grant,
    pub allowance: Option<Allowance>,
}

/// Borrow one durable account and its existing Nostr-compatible identity for a
/// control operation. Every outgoing obligation follows a successful commit.
pub struct Controller<'a> {
    store: &'a mut AccountStore,
    key: &'a Keypair,
}

impl<'a> Controller<'a> {
    pub fn new(store: &'a mut AccountStore, key: &'a Keypair) -> Result<Self, Error> {
        if store.book().owner() != key.x_only_public_key().0.to_string() {
            return Err(Error::Authentication);
        }
        Ok(Self { store, key })
    }

    /// A quote is not a service grant. The provider still checks its aggregate
    /// exposure atomically when both signatures arrive at open().
    pub fn offer(&self, terms: Agreement, now: u64) -> Result<Signed<Agreement>, Error> {
        terms.validate()?;
        if terms.provider != self.store.book().owner() {
            return Err(Error::Authentication);
        }
        if !self.store.book().seller().accepts(&terms.payer) {
            return Err(Error::NotAccepted);
        }
        if terms.created_at > now || terms.expires_at <= now {
            return Err(Error::Expired);
        }
        let signature = sign_message(self.key, &WireMessage::Agreement(terms.clone()))?;
        Ok(Signed {
            payload: terms,
            signature,
        })
    }

    pub fn accept_offer(
        &mut self,
        offer: &Signed<Agreement>,
        intent: &PurchaseIntent<'_>,
        now: u64,
    ) -> Result<Signed<Agreement>, Error> {
        intent.check(&offer.payload, now)?;
        let terms = self
            .store
            .transact(|a| a.prepare_purchase(offer, &SchnorrVerifier, now))?;
        let signature = sign_message(self.key, &WireMessage::Agreement(terms.clone()))?;
        Ok(Signed {
            payload: terms,
            signature,
        })
    }

    pub fn open(
        &mut self,
        offer: &Signed<Agreement>,
        acceptance: &Signed<Agreement>,
        now: u64,
    ) -> Result<Opened, Error> {
        if offer.payload != acceptance.payload {
            return Err(Error::Conflict);
        }
        self.store.transact(|account| {
            let a = &offer.payload;
            let mut grant = account.accept(
                a,
                &acceptance.signature,
                &offer.signature,
                &SchnorrVerifier,
                now,
            )?;
            let allowance = if grant.reserved_units == 0 && !grant.closed {
                let allowance = account.reserve_window(&a.id, 0, a.max_units, now)?;
                grant.reserved_units = a.max_units;
                Some(allowance)
            } else {
                None
            };
            Ok(Opened { grant, allowance })
        })
    }

    pub fn receipt(
        &mut self,
        id: &str,
        verified_units: u64,
        final_receipt: bool,
    ) -> Result<Signed<Receipt>, Error> {
        let payload = self
            .store
            .transact(|a| a.authorize_receipt(id, verified_units, final_receipt))?;
        let signature = sign_message(self.key, &WireMessage::Receipt(payload.clone()))?;
        Ok(Signed { payload, signature })
    }

    pub fn receive_receipt(
        &mut self,
        receipt: &Signed<Receipt>,
        verified_units: u64,
    ) -> Result<Signed<Receipt>, Error> {
        self.store
            .transact(|a| a.apply_receipt(receipt, &SchnorrVerifier, verified_units))?;
        let payload = receipt.payload.clone();
        let signature = sign_message(self.key, &WireMessage::Receipt(payload.clone()))?;
        Ok(Signed { payload, signature })
    }

    pub fn acknowledge(&mut self, ack: &Signed<Receipt>) -> Result<(), Error> {
        self.store
            .transact(|a| a.acknowledge(ack, &SchnorrVerifier))
    }

    /// Only the lexicographically smaller identity initiates automatic netting.
    /// This avoids competing proposals locking different pairs of debts. The
    /// prepared proposal is recovered verbatim after disconnect or restart.
    pub fn propose_netting(&mut self, peer: &str) -> Result<Option<Signed<Netting>>, Error> {
        if self.store.book().owner() >= peer {
            return Ok(None);
        }
        let Some(payload) = self.store.transact(|a| a.prepare_reciprocal(peer))? else {
            return Ok(None);
        };
        let signature = sign_message(self.key, &WireMessage::Netting(payload.clone()))?;
        Ok(Some(Signed { payload, signature }))
    }

    pub fn accept_netting(&mut self, proposal: &Signed<Netting>) -> Result<Signed<Netting>, Error> {
        let terms = &proposal.payload;
        if terms.right != self.store.book().owner() {
            return Err(Error::Authentication);
        }
        authenticate(
            &SchnorrVerifier,
            &terms.left,
            WireMessage::Netting(terms.clone()),
            &proposal.signature,
        )?;
        self.store.transact(|a| a.prepare_netting(terms))?;
        let signature = sign_message(self.key, &WireMessage::Netting(terms.clone()))?;
        self.store.transact(|a| {
            a.commit_netting(terms, &proposal.signature, &signature, &SchnorrVerifier)
        })?;
        Ok(Signed {
            payload: terms.clone(),
            signature,
        })
    }

    pub fn finish_netting(&mut self, ack: &Signed<Netting>) -> Result<(), Error> {
        let terms = &ack.payload;
        if terms.left != self.store.book().owner() {
            return Err(Error::Authentication);
        }
        if self.store.book().netting(&terms.id) != Some(terms) {
            return Err(Error::Conflict);
        }
        let signature = sign_message(self.key, &WireMessage::Netting(terms.clone()))?;
        self.store
            .transact(|a| a.commit_netting(terms, &signature, &ack.signature, &SchnorrVerifier))
    }

    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        self.store.transact(|a| a.set_enabled(enabled))
    }
}

/// Application-level records, independent of FIPS wire formats. Authenticate
/// the transport peer, check the expected response variant and then call the
/// corresponding controller transition; decoding alone grants no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ControlMessage {
    Offer(Signed<Agreement>),
    Acceptance(Signed<Agreement>),
    Receipt(Signed<Receipt>),
    Acknowledgement(Signed<Receipt>),
    NettingProposal(Signed<Netting>),
    NettingAcknowledgement(Signed<Netting>),
}

impl ControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let bytes = serde_json::to_vec(&("peer-payments/control", 1u16, self))?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }

    /// The carrier must enforce the same bound before allocating a frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::Limit);
        }
        let (domain, version, message): (String, u16, Self) = serde_json::from_slice(bytes)?;
        if domain != "peer-payments/control" || version != 1 {
            return Err(Error::Invalid("control version"));
        }
        Ok(message)
    }
}
