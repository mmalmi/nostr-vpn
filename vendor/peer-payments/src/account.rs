use crate::{
    book::MAX_STATE_BYTES,
    protocol::{authenticate, identifier},
    Agreement, Allowance, Book, Buyer, DurableState, Error, Grant, Netting, Receipt, Signed,
    Verifier, WireMessage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A node's buying, selling and reciprocal settlement share one atomic journal.
/// Never run separate stores for services that share this node's risk budget.
#[derive(Debug, Clone)]
pub struct Account {
    seller: Book,
    buyer: Buyer,
    nettings: BTreeMap<String, NettingRecord>,
    revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NettingRecord {
    terms: Netting,
    signatures: Option<(String, String)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u16,
    seller: String,
    buyer: String,
    nettings: BTreeMap<String, NettingRecord>,
    revision: u64,
}

impl Account {
    pub fn new(seller: Book, buyer: Buyer) -> Result<Self, Error> {
        if seller.provider() != buyer.payer() {
            return Err(Error::Authentication);
        }
        Ok(Self {
            seller,
            buyer,
            nettings: BTreeMap::new(),
            revision: 0,
        })
    }

    pub fn seller(&self) -> &Book {
        &self.seller
    }
    pub fn buyer(&self) -> &Buyer {
        &self.buyer
    }

    /// Persist the opt-out in the same account shared by every service. Existing
    /// obligations can still be reconciled while new buying/selling is disabled.
    /// Revocation is fail-closed, including when a later database write fails.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        self.update(|s| {
            s.seller.set_enabled(enabled)?;
            s.buyer.set_enabled(enabled)
        })
    }

    pub fn netting(&self, id: &str) -> Option<&Netting> {
        self.nettings.get(id).map(|record| &record.terms)
    }

    // Clone first so even direct use is atomic when a later validation fails.
    fn update<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        let mut candidate = self.clone();
        candidate.revision = candidate.revision.checked_add(1).ok_or(Error::Limit)?;
        let result = f(&mut candidate)?;
        *self = candidate;
        Ok(result)
    }

    pub fn accept(
        &mut self,
        a: &Agreement,
        payer_signature: &str,
        provider_signature: &str,
        verifier: &impl Verifier,
        now: u64,
    ) -> Result<Grant, Error> {
        if self.buyer.records().any(|(id, _)| id == a.id) {
            return Err(Error::Conflict);
        }
        self.update(|s| {
            s.seller
                .accept(a, payer_signature, provider_signature, verifier, now)
        })
    }
    pub fn reserve_window(
        &mut self,
        id: &str,
        expected: u64,
        units: u64,
        now: u64,
    ) -> Result<Allowance, Error> {
        self.update(|s| s.seller.reserve_window(id, expected, units, now))
    }
    pub fn apply_receipt(
        &mut self,
        r: &Signed<Receipt>,
        verifier: &impl Verifier,
        verified_units: u64,
    ) -> Result<Grant, Error> {
        self.update(|s| s.seller.apply_receipt(r, verifier, verified_units))
    }
    pub fn prepare_purchase(
        &mut self,
        offer: &Signed<Agreement>,
        verifier: &impl Verifier,
        now: u64,
    ) -> Result<Agreement, Error> {
        if self.seller.records().any(|(id, _)| id == offer.payload.id) {
            return Err(Error::Conflict);
        }
        self.update(|s| s.buyer.prepare(offer, verifier, now))
    }
    pub fn authorize_receipt(
        &mut self,
        id: &str,
        units: u64,
        final_receipt: bool,
    ) -> Result<Receipt, Error> {
        self.update(|s| s.buyer.authorize_receipt(id, units, final_receipt))
    }
    pub fn acknowledge(
        &mut self,
        receipt: &Signed<Receipt>,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        self.update(|s| s.buyer.acknowledge(receipt, verifier))
    }

    /// Deterministically select the oldest IDs with reciprocal completed debt.
    /// Repeated calls return the same pending terms for automatic reconnect retry.
    pub fn prepare_reciprocal(&mut self, peer: &str) -> Result<Option<Netting>, Error> {
        if let Some(pending) = self
            .pending_nettings()
            .find(|n| n.left == peer || n.right == peer)
        {
            return Ok(Some(pending.clone()));
        }
        let sale = self.seller.records().find_map(|(id, _)| {
            self.seller
                .settlement_terms(id)
                .ok()
                .filter(|(a, total, cleared)| a.payer == peer && total > cleared)
        });
        let purchase = self.buyer.records().find_map(|(id, _)| {
            self.buyer
                .settlement_terms(id)
                .ok()
                .filter(|(a, total, cleared)| a.provider == peer && total > cleared)
        });
        let (Some(sale), Some(purchase)) = (sale, purchase) else {
            return Ok(None);
        };
        let (left, right) = if self.owner() < peer {
            (sale, purchase)
        } else {
            (purchase, sale)
        };
        let mut n = Netting {
            id: String::new(),
            left: left.0.provider.clone(),
            right: right.0.provider.clone(),
            left_sale: left.0.id.clone(),
            left_commitment: left.0.commitment()?,
            left_previous_sat: left.2,
            right_sale: right.0.id.clone(),
            right_commitment: right.0.commitment()?,
            right_previous_sat: right.2,
            amount_sat: (left.1 - left.2).min(right.1 - right.2),
        };
        n.id = format!(
            "{:x}",
            Sha256::digest(WireMessage::Netting(n.clone()).signing_bytes()?)
        );
        self.prepare_netting(&n)?;
        Ok(Some(n))
    }

    /// Persist before signing. A pending proposal locks both referenced debts.
    /// A disconnected peer can delay clearing, but cannot make us sign conflicting
    /// proposals. Reconnect resends these exact terms; timeouts never unlock them.
    pub fn prepare_netting(&mut self, terms: &Netting) -> Result<(), Error> {
        if let Some(old) = self.nettings.get(&terms.id) {
            return if old.terms == *terms {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.validate_netting(terms, false)?;
        if self.nettings.len() >= 256 {
            return Err(Error::Limit);
        }
        for record in self.nettings.values().filter(|r| r.signatures.is_none()) {
            if record.terms.left_sale == terms.left_sale
                || record.terms.left_sale == terms.right_sale
                || record.terms.right_sale == terms.left_sale
                || record.terms.right_sale == terms.right_sale
            {
                return Err(Error::Conflict);
            }
        }
        self.update(|s| {
            s.nettings.insert(
                terms.id.clone(),
                NettingRecord {
                    terms: terms.clone(),
                    signatures: None,
                },
            );
            Ok(())
        })
    }

    /// Both signatures clear equal service debts, with no mint or withdrawable
    /// asset. Local debit and credit settle in the same durable transaction.
    /// The other peer can recover the signed commit independently after a crash.
    pub fn commit_netting(
        &mut self,
        terms: &Netting,
        left_signature: &str,
        right_signature: &str,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        authenticate(
            verifier,
            &terms.left,
            WireMessage::Netting(terms.clone()),
            left_signature,
        )?;
        authenticate(
            verifier,
            &terms.right,
            WireMessage::Netting(terms.clone()),
            right_signature,
        )?;
        let record = self.nettings.get(&terms.id).ok_or(Error::Unknown)?;
        if record.terms != *terms {
            return Err(Error::Conflict);
        }
        if record.signatures.is_some() {
            return Ok(());
        }
        self.validate_netting(terms, false)?;
        self.update(|s| {
            let (sale, sale_previous, purchase, purchase_previous) = s.sides(terms);
            s.seller
                .clear(sale, &terms.id, terms.amount_sat, sale_previous)?;
            s.buyer
                .clear(purchase, terms.amount_sat, purchase_previous)?;
            s.nettings
                .get_mut(&terms.id)
                .ok_or(Error::Unknown)?
                .signatures = Some((left_signature.into(), right_signature.into()));
            Ok(())
        })
    }

    pub fn pending_nettings(&self) -> impl Iterator<Item = &Netting> {
        self.nettings
            .values()
            .filter(|r| r.signatures.is_none())
            .map(|r| &r.terms)
    }

    fn sides<'a>(&self, n: &'a Netting) -> (&'a str, u64, &'a str, u64) {
        if self.seller.provider() == n.left {
            (
                &n.left_sale,
                n.left_previous_sat,
                &n.right_sale,
                n.right_previous_sat,
            )
        } else {
            (
                &n.right_sale,
                n.right_previous_sat,
                &n.left_sale,
                n.left_previous_sat,
            )
        }
    }

    fn validate_netting(&self, n: &Netting, committed: bool) -> Result<(), Error> {
        for id in [&n.id, &n.left, &n.right, &n.left_sale, &n.right_sale] {
            identifier(id)?;
        }
        if n.left >= n.right
            || n.left_sale == n.right_sale
            || n.amount_sat == 0
            || (self.seller.provider() != n.left && self.seller.provider() != n.right)
        {
            return Err(Error::Invalid("netting parties"));
        }
        let (sale, sale_previous, purchase, purchase_previous) = self.sides(n);
        let (a, total_a, cleared_a) = self.seller.settlement_terms(sale)?;
        let (b, total_b, cleared_b) = self.buyer.settlement_terms(purchase)?;
        let (left, right) = if self.seller.provider() == n.left {
            (a, b)
        } else {
            (b, a)
        };
        if left.provider != n.left
            || left.payer != n.right
            || right.provider != n.right
            || right.payer != n.left
            || left.commitment()? != n.left_commitment
            || right.commitment()? != n.right_commitment
        {
            return Err(Error::Authentication);
        }
        let end_a = sale_previous
            .checked_add(n.amount_sat)
            .ok_or(Error::Limit)?;
        let end_b = purchase_previous
            .checked_add(n.amount_sat)
            .ok_or(Error::Limit)?;
        if end_a > total_a
            || end_b > total_b
            || if committed {
                end_a > cleared_a || end_b > cleared_b
            } else {
                sale_previous != cleared_a || purchase_previous != cleared_b
            }
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

impl DurableState for Account {
    fn revoke_allowances(&self) {
        self.seller.revoke_all();
    }
    fn owner(&self) -> &str {
        self.seller.provider()
    }
    fn revision(&self) -> u64 {
        self.revision
    }
    fn encode(&self) -> Result<String, Error> {
        let json = serde_json::to_string(&Snapshot {
            version: 1,
            seller: self.seller.encode()?,
            buyer: self.buyer.encode()?,
            nettings: self.nettings.clone(),
            revision: self.revision,
        })?;
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        Ok(json)
    }
    fn decode(json: &str) -> Result<Self, Error> {
        if json.len() > MAX_STATE_BYTES {
            return Err(Error::Limit);
        }
        let snapshot: Snapshot = serde_json::from_str(json)?;
        if snapshot.version != 1 || snapshot.nettings.len() > 256 {
            return Err(Error::Invalid("account snapshot"));
        }
        let mut account = Self::new(
            Book::decode(&snapshot.seller)?,
            Buyer::decode(&snapshot.buyer)?,
        )?;
        account.revision = snapshot.revision;
        account.nettings = snapshot.nettings;
        let mut offsets: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
        let mut locked = std::collections::BTreeSet::new();
        for (id, record) in &account.nettings {
            if *id != record.terms.id {
                return Err(Error::Conflict);
            }
            account.validate_netting(&record.terms, record.signatures.is_some())?;
            let (sale, sp, purchase, pp) = account.sides(&record.terms);
            if let Some((left, right)) = &record.signatures {
                if left.is_empty() || right.is_empty() {
                    return Err(Error::Authentication);
                }
                for (key, previous) in [(sale, sp), (purchase, pp)] {
                    offsets
                        .entry(key.into())
                        .or_default()
                        .push((previous, record.terms.amount_sat));
                }
            } else if !locked.insert(sale) || !locked.insert(purchase) {
                return Err(Error::Conflict);
            }
        }
        for (id, cleared) in account.seller.records().chain(account.buyer.records()) {
            if cleared > 0 && !offsets.contains_key(id) {
                return Err(Error::Conflict);
            }
        }
        if account.seller.records().any(|(sale, _)| {
            account
                .buyer
                .records()
                .any(|(purchase, _)| sale == purchase)
        }) {
            return Err(Error::Conflict);
        }
        for (id, mut intervals) in offsets {
            intervals.sort_unstable();
            let mut end = 0u64;
            for (start, amount) in intervals {
                if start != end {
                    return Err(Error::Conflict);
                }
                end = end.checked_add(amount).ok_or(Error::Limit)?;
            }
            let cleared = account
                .seller
                .settlement_terms(&id)
                .or_else(|_| account.buyer.settlement_terms(&id))?
                .2;
            if cleared != end {
                return Err(Error::Conflict);
            }
        }
        Ok(account)
    }
}
