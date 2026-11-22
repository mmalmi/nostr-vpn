use super::*;
use peer_payments::{
    Controller, WireMessage,
    redemption::{RedemptionApproval, invoice_terms},
    sign_message,
};
use std::collections::HashMap;

#[derive(Clone)]
enum Choice {
    Wallet,
    Forward { agreement: String, onward_fee: u64 },
}
#[derive(Default)]
pub(super) struct Hints {
    searches: HashMap<u64, Instant>,
    quotes: BTreeMap<(String, String, u64, u64), (Instant, Choice)>,
    successes: BTreeMap<String, Instant>,
    offers: BTreeMap<String, (Instant, u64)>,
    declined: BTreeMap<String, Instant>,
}
impl Hints {
    fn begin(&mut self, nonce: u64) -> bool {
        let now = Instant::now();
        self.searches.retain(|_, t| *t > now);
        if self.searches.len() >= 256 || self.searches.contains_key(&nonce) {
            return false;
        }
        self.searches.insert(nonce, now + Duration::from_secs(12));
        true
    }
    fn remember(
        &mut self,
        peer: &str,
        query: &Query,
        fee_sat: u64,
        choice: Choice,
    ) -> Result<(), String> {
        let now = Instant::now();
        self.quotes.retain(|_, (t, _)| *t > now);
        let key = (
            peer.into(),
            query.agreement_id.clone(),
            query.amount_sat,
            fee_sat,
        );
        if self.quotes.len() >= 256 && !self.quotes.contains_key(&key) {
            return Err("quote table full".into());
        }
        self.quotes
            .insert(key, (now + Duration::from_secs(30), choice));
        Ok(())
    }
    fn back_off(&mut self, peer: &str) {
        let now = Instant::now();
        self.declined.retain(|_, t| *t > now);
        if self.declined.len() < 128 || self.declined.contains_key(peer) {
            self.declined
                .insert(peer.into(), now + Duration::from_secs(5));
        }
    }
    fn success(&mut self, peer: String) {
        self.declined.remove(&peer);
        let now = Instant::now();
        self.successes.retain(|_, t| *t > now);
        if self.successes.len() < 128 || self.successes.contains_key(&peer) {
            self.successes.insert(peer, now + Duration::from_secs(120));
        }
    }
}

impl CreditLink {
    /// Send a two-minute, non-binding offer to one creditor. The peer learns
    /// the flat payout fee. Probing and signed settlement are still required.
    pub async fn offer_payout(&self, peer: &str) -> Result<(), String> {
        {
            let store = self.store.try_lock().map_err(|_| "credit account busy")?;
            let account = store.book();
            if !self.terminal(account, 1)
                || !account.available_debts().any(|(a, _)| a.provider == peer)
            {
                return Err("no eligible payout for this peer".into());
            }
        }
        let fee_sat = self.policy.market.payout_fee_sat;
        let offer = if fee_sat == 0 {
            Call::PayoutOffer
        } else {
            Call::PayoutAt { fee_sat }
        };
        match self.call(peer, offer).await? {
            Reply::Available => Ok(()),
            _ => Err("payout offer declined".into()),
        }
    }
    /// Refresh a bounded rotating group of directly connected creditors. Losing
    /// a hint costs no money and never triggers a payment or retry storm.
    pub(super) async fn refresh_offers(&self, cursor: usize) -> Result<usize, String> {
        let peers = {
            let neighbors = self.neighbors().await?;
            let s = self.store.try_lock().map_err(|_| "credit account busy")?;
            let a = s.book();
            if !self.terminal(a, 1) {
                return Ok(cursor);
            }
            a.available_debts()
                .map(|(a, _)| a.provider.as_str())
                .filter(|p| neighbors.1.contains_key(*p))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        if peers.is_empty() {
            return Ok(0);
        }
        let count = peers.len().min(16);
        for index in 0..count {
            let _ = self
                .offer_payout(&peers[(cursor + index) % peers.len()])
                .await;
        }
        Ok((cursor + count) % peers.len())
    }
    pub(super) fn receive_payout_offer(&self, peer: &str, fee_sat: u64) -> Result<Reply, String> {
        if !self
            .store
            .try_lock()
            .map_err(|_| "credit account busy")?
            .book()
            .available_claims()
            .any(|(a, _)| a.payer == peer)
        {
            return Err("no eligible claim".into());
        }
        let mut hints = self.routes.lock().map_err(|_| "credit link unavailable")?;
        let now = Instant::now();
        hints.offers.retain(|_, (end, _)| *end > now);
        if hints.offers.len() >= 128 && !hints.offers.contains_key(peer) {
            return Err("offer table full".into());
        }
        hints
            .offers
            .insert(peer.into(), (now + Duration::from_secs(120), fee_sat));
        Ok(Reply::Available)
    }
    fn claims(
        &self,
        amount: u64,
        exclude: &str,
        fee_limit: u64,
        connected: &BTreeMap<String, PeerIdentity>,
    ) -> Result<Vec<(String, (String, u64))>, String> {
        let store = self.store.try_lock().map_err(|_| "credit account busy")?;
        let hints = self.routes.lock().map_err(|_| "credit link unavailable")?;
        let mut eligible = BTreeMap::new();
        for (a, cap) in store.book().available_claims().filter(|(a, cap)| {
            *cap >= amount && a.payer != exclude && connected.contains_key(&a.payer)
        }) {
            let entry = eligible
                .entry(a.payer.clone())
                .or_insert((a.id.clone(), cap));
            if cap > entry.1 {
                *entry = (a.id.clone(), cap);
            }
        }
        let now = Instant::now();
        let mut claims: Vec<_> = eligible.into_iter().collect();
        if !claims.is_empty() {
            let offset = (rand::random::<u64>() % claims.len() as u64) as usize;
            claims.rotate_left(offset);
        }
        claims.sort_by_key(|(p, _)| {
            (
                hints.declined.get(p).is_some_and(|t| *t > now),
                !hints.successes.get(p).is_some_and(|t| *t > now),
                hints
                    .offers
                    .get(p)
                    .filter(|(t, fee)| *t > now && *fee <= fee_limit)
                    .map_or((true, 0), |(_, fee)| (false, *fee)),
            )
        });
        Ok(claims)
    }

    // Nodes split the remaining message budget before sending. A missing or
    // dishonest reply cannot replenish it. Each peer learns just its own debt.
    pub(super) async fn find(
        &self,
        query: &Query,
        exclude: &str,
    ) -> Result<(String, String, u64), String> {
        if query.hops == 0 || query.probes == 0 {
            return Err("no private quote".into());
        }
        let claims = {
            let neighbors = self.neighbors().await?;
            self.claims(query.amount_sat, exclude, query.max_fee_sat, &neighbors.1)?
        };
        let candidates = claims.len().min(3).min(query.probes as usize);
        let mut remaining = query.probes;
        for (index, (peer, (agreement, cap))) in claims.into_iter().take(candidates).enumerate() {
            let budget = remaining.div_ceil((candidates - index) as u8);
            remaining -= budget;
            let child = Query {
                nonce: query.nonce,
                agreement_id: agreement.clone(),
                amount_sat: query.amount_sat,
                max_fee_sat: query.max_fee_sat.min(cap - query.amount_sat),
                hops: query.hops,
                probes: budget,
            };
            let limit = child.max_fee_sat;
            let fee = match self.call(&peer, Call::Query(child)).await {
                Ok(Reply::Available) => Some(0),
                Ok(Reply::Priced { fee_sat }) if fee_sat <= limit => Some(fee_sat),
                _ => None,
            };
            if let Some(fee) = fee {
                return Ok((peer, agreement, fee));
            }
            self.routes
                .lock()
                .map_err(|_| "credit link unavailable")?
                .back_off(&peer);
        }
        Err("no connected peer quoted this invoice amount".into())
    }

    fn terminal(&self, account: &peer_payments::Account, amount: u64) -> bool {
        self.policy.lightning.as_ref().is_some_and(|p| {
            amount > 0
                && amount <= p.max_amount_sat
                && account.can_reserve_payout(
                    amount,
                    p.max_fee_msat,
                    p.max_lifetime_payout_sat,
                    p.max_lifetime_fees_msat,
                )
        })
    }

    pub(super) async fn answer_query(&self, peer: &str, q: Query) -> Result<Reply, String> {
        if q.amount_sat == 0
            || q.agreement_id.len() > 256
            || !(1..=MAX_HOPS).contains(&q.hops)
            || !(1..=BUDGET).contains(&q.probes)
        {
            return Err("invalid request".into());
        }
        let (can_pay, fee_ceiling) = {
            let store = self.store.try_lock().map_err(|_| "credit account busy")?;
            let account = store.book();
            let cap = account
                .available_debts()
                .find(|(a, _)| a.provider == peer && a.id == q.agreement_id)
                .and_then(|(_, v)| v.checked_sub(q.amount_sat))
                .ok_or("no eligible debt")?;
            (self.terminal(account, q.amount_sat), q.max_fee_sat.min(cap))
        };
        if !self
            .routes
            .lock()
            .map_err(|_| "credit link unavailable")?
            .begin(q.nonce)
        {
            return Err("repeat request".into());
        }
        let market = &self.policy.market;
        let (choice, fee) = if can_pay && market.payout_fee_sat <= fee_ceiling {
            (Choice::Wallet, market.payout_fee_sat)
        } else if self.policy.forward_existing_credit && q.hops > 1 && q.probes > 1 {
            let max_fee_sat = fee_ceiling
                .checked_sub(market.forward_fee_sat)
                .ok_or("conversion price over limit")?;
            let child = Query {
                max_fee_sat,
                hops: q.hops - 1,
                probes: q.probes - 1,
                agreement_id: String::new(),
                ..q
            };
            let (_, agreement, onward_fee) = self.find(&child, peer).await?;
            (
                Choice::Forward {
                    agreement,
                    onward_fee,
                },
                market
                    .forward_fee_sat
                    .checked_add(onward_fee)
                    .ok_or("conversion price overflow")?,
            )
        } else {
            return Err("no conversion available".into());
        };
        self.routes
            .lock()
            .map_err(|_| "credit link unavailable")?
            .remember(peer, &q, fee, choice)?;
        Ok(if fee == 0 {
            Reply::Available
        } else {
            Reply::Priced { fee_sat: fee }
        })
    }

    pub async fn quote_invoice(&self, invoice: &str) -> Result<InvoiceQuote, String> {
        self.quote_with_limit(invoice, self.policy.market.max_invoice_fee_sat)
            .await
    }
    pub(super) async fn quote_with_limit(
        &self,
        invoice: &str,
        max_fee_sat: u64,
    ) -> Result<InvoiceQuote, String> {
        let time = now()?;
        let (amount_sat, payment_hash) = invoice_terms(invoice, time).map_err(err)?;
        {
            let store = self.store.try_lock().map_err(|_| "credit account busy")?;
            if store.book().outgoing_redemption(&payment_hash).is_some()
                || store.book().incoming_redemption(&payment_hash).is_some()
            {
                return Err("invoice already has a payment; check its status".into());
            }
        }
        let q = Query {
            nonce: rand::random(),
            agreement_id: String::new(),
            amount_sat,
            max_fee_sat,
            hops: MAX_HOPS,
            probes: BUDGET,
        };
        let (debtor, agreement_id, fee_sat) = self.find(&q, "").await?;
        Ok(InvoiceQuote {
            agreement_id,
            debtor,
            amount_sat,
            payment_hash,
            fee_sat,
            expires_at: time + 30,
        })
    }

    pub async fn confirm_invoice(
        &self,
        invoice: &str,
        quote: &InvoiceQuote,
    ) -> Result<PaymentState, String> {
        self.confirm_with_wallet(invoice, quote, None, self.policy.market.max_invoice_fee_sat)
            .await
    }

    /// Cash out to a locally owned receiving wallet. Use the same wallet on recovery.
    #[cfg(unix)]
    pub async fn confirm_cashout(
        &self,
        invoice: &str,
        quote: &InvoiceQuote,
        local_rpc: &std::path::Path,
    ) -> Result<PaymentState, String> {
        self.confirm_with_wallet(
            invoice,
            quote,
            Some(local_rpc.to_owned()),
            self.policy.market.max_invoice_fee_sat,
        )
        .await
    }
    pub(super) async fn confirm_with_wallet(
        &self,
        invoice: &str,
        quote: &InvoiceQuote,
        local: Option<PathBuf>,
        limit: u64,
    ) -> Result<PaymentState, String> {
        let time = now()?;
        let (amount, hash) = invoice_terms(invoice, time).map_err(err)?;
        let debit = quote.debit_sat()?;
        let fee = quote.fee_sat;
        if fee > limit {
            return Err("quote exceeds configured fee limit".into());
        }
        if quote.expires_at <= time || (amount, &hash) != (quote.amount_sat, &quote.payment_hash) {
            return Err("invoice quote has changed or expired".into());
        }
        {
            let store = self.store.try_lock().map_err(|_| "credit account busy")?;
            if !store
                .book()
                .available_claims()
                .any(|(a, v)| a.id == quote.agreement_id && a.payer == quote.debtor && v >= debit)
                && !store.book().outgoing_redemption(&hash).is_some_and(|r| {
                    r.agreement_id == quote.agreement_id
                        && r.debtor == quote.debtor
                        && r.fee_sat == fee
                        && r.bolt11 == invoice
                })
            {
                return Err("earned credit is unavailable".into());
            }
        }
        let store = self.store.clone();
        let key = self.key;
        let id = quote.agreement_id.clone();
        let invoice = invoice.to_owned();
        let receive_wallet = local.clone();
        tokio::task::spawn_blocking(move || {
            let mut s = store.lock().map_err(|_| "credit account unavailable")?;
            let mut c = Controller::new(&mut s, &key).map_err(err)?;
            #[cfg(unix)]
            if let Some(path) = receive_wallet {
                return c
                    .request_redemption_with_fee(
                        &id,
                        &invoice,
                        fee,
                        limit,
                        &mut peer_payments::redemption::ClnWallet::new(path),
                        time,
                    )
                    .map_err(err);
            }
            c.request_invoice_payment_with_fee(&id, &invoice, fee, limit, time)
                .map_err(err)
        })
        .await
        .map_err(err)??;
        self.resume_with_wallet(&hash, local).await
    }

    pub async fn resume_invoice(&self, hash: &str) -> Result<PaymentState, String> {
        self.resume_with_wallet(hash, None).await
    }
    #[cfg(unix)]
    pub async fn resume_cashout(
        &self,
        hash: &str,
        local_rpc: &std::path::Path,
    ) -> Result<PaymentState, String> {
        self.resume_with_wallet(hash, Some(local_rpc.to_owned()))
            .await
    }
    async fn resume_with_wallet(
        &self,
        hash: &str,
        local: Option<PathBuf>,
    ) -> Result<PaymentState, String> {
        let request = {
            let s = self.store.try_lock().map_err(|_| "credit account busy")?;
            let r = s
                .book()
                .outgoing_redemption(hash)
                .filter(|_| s.book().incoming_redemption(hash).is_none())
                .ok_or("unknown outgoing invoice")?;
            if s.book().redemption_paid(hash) {
                return Ok(PaymentState::Paid);
            }
            self.sign(r)?
        };
        let debtor = request.payload.debtor.clone();
        let Some(proof) = self.send_reserved(request).await else {
            if let Ok(mut hints) = self.routes.lock() {
                hints.back_off(&debtor)
            }
            return Ok(PaymentState::Pending);
        };
        let store = self.store.clone();
        let key = self.key;
        let result = tokio::task::spawn_blocking(move || {
            let mut s = store.lock().map_err(|_| "credit account unavailable")?;
            let mut c = Controller::new(&mut s, &key).map_err(err)?;
            #[cfg(unix)]
            if let Some(path) = local {
                return c
                    .finish_redemption(&proof, &mut peer_payments::redemption::ClnWallet::new(path))
                    .map_err(err);
            }
            c.finish_invoice_payment(&proof).map_err(err)
        })
        .await
        .map_err(err)?;
        Ok(if result.is_ok() {
            if let Ok(mut hints) = self.routes.lock() {
                hints.success(debtor)
            }
            PaymentState::Paid
        } else {
            PaymentState::Pending
        })
    }

    fn sign(&self, r: &Redemption) -> Result<Signed<Redemption>, String> {
        Ok(Signed {
            signature: sign_message(&self.key, &WireMessage::Redemption(r.clone())).map_err(err)?,
            payload: r.clone(),
        })
    }

    pub(super) async fn redeem(
        &self,
        peer: &str,
        incoming: Signed<Redemption>,
    ) -> Result<Reply, String> {
        let r = &incoming.payload;
        if r.creditor != peer || r.debtor != self.key.x_only_public_key().0.to_string() {
            return Err("identity mismatch".into());
        }
        let time = now()?;
        let prior = {
            let s = self.store.try_lock().map_err(|_| "credit account busy")?;
            if let Some(accepted) = s.book().incoming_redemption(&r.payment_hash) {
                if accepted != r {
                    return Err("conflicting payment".into());
                }
                // Never release a proof, even on replay, without verifying this peer's signed terms.
                use peer_payments::{SchnorrVerifier, Verifier};
                if !SchnorrVerifier.verify(
                    peer,
                    &WireMessage::Redemption(r.clone())
                        .signing_bytes()
                        .map_err(err)?,
                    &incoming.signature,
                ) {
                    return Err("invalid signature".into());
                }
                if let Some(proof) = s.book().redemption_proof(&r.payment_hash).map_err(err)? {
                    return Ok(Reply::Paid(Signed {
                        signature: sign_message(
                            &self.key,
                            &WireMessage::RedemptionPaid(proof.clone()),
                        )
                        .map_err(err)?,
                        payload: proof,
                    }));
                }
                Some(
                    s.book()
                        .outgoing_redemption(&r.payment_hash)
                        .map(|t| Choice::Forward {
                            agreement: t.agreement_id.clone(),
                            onward_fee: t.fee_sat,
                        })
                        .unwrap_or(Choice::Wallet),
                )
            } else {
                Redemption::verify(&incoming, time).map_err(err)?;
                None
            }
        };
        let choice = if let Some(choice) = prior {
            choice
        } else {
            let hints = self.routes.lock().map_err(|_| "credit link unavailable")?;
            hints
                .quotes
                .get(&(peer.into(), r.agreement_id.clone(), r.amount_sat, r.fee_sat))
                .filter(|(t, _)| *t > Instant::now())
                .map(|(_, c)| c.clone())
                .ok_or("fresh quote required")?
        };
        let mut approval = RedemptionApproval {
            creditor: peer.into(),
            agreement_id: r.agreement_id.clone(),
            payment_hash: r.payment_hash.clone(),
            max_amount_sat: r.amount_sat,
            max_fee_msat: 0,
            max_lifetime_payout_sat: 0,
            max_lifetime_fees_msat: 0,
        };
        let store = self.store.clone();
        let key = self.key;
        match choice {
            Choice::Wallet => {
                let p = self
                    .policy
                    .lightning
                    .clone()
                    .ok_or("Lightning payout is disabled")?;
                approval.max_amount_sat = p.max_amount_sat;
                approval.max_fee_msat = p.max_fee_msat;
                approval.max_lifetime_payout_sat = p.max_lifetime_payout_sat;
                approval.max_lifetime_fees_msat = p.max_lifetime_fees_msat;
                #[cfg(unix)]
                return tokio::task::spawn_blocking(move || {
                    let mut s = store.lock().map_err(|_| "credit account unavailable")?;
                    let mut wallet = peer_payments::redemption::ClnWallet::new(p.rpc_socket);
                    Controller::new(&mut s, &key)
                        .map_err(err)?
                        .pay_redemption(&incoming, &approval, &mut wallet, time)
                        .map(Reply::Paid)
                        .map_err(err)
                })
                .await
                .map_err(err)?;
                #[cfg(not(unix))]
                Err("Lightning payout is unavailable".into())
            }
            Choice::Forward {
                agreement,
                onward_fee,
            } => {
                if !self.policy.forward_existing_credit {
                    return Err("credit forwarding disabled".into());
                }
                let onward = tokio::task::spawn_blocking(move || {
                    let mut s = store.lock().map_err(|_| "credit account unavailable")?;
                    Controller::new(&mut s, &key)
                        .map_err(err)?
                        .forward_redemption_with_fee(
                            &incoming, &approval, &agreement, onward_fee, time,
                        )
                        .map_err(err)
                })
                .await
                .map_err(err)??;
                let debtor = onward.payload.debtor.clone();
                let Some(proof) = self.send_reserved(onward).await else {
                    if let Ok(mut hints) = self.routes.lock() {
                        hints.back_off(&debtor)
                    }
                    return Err("payment pending".into());
                };
                let store = self.store.clone();
                let reply = tokio::task::spawn_blocking(move || {
                    let mut s = store.lock().map_err(|_| "credit account unavailable")?;
                    Controller::new(&mut s, &key)
                        .map_err(err)?
                        .finish_forwarded_redemption(&proof)
                        .map(Reply::Paid)
                        .map_err(err)
                })
                .await
                .map_err(err)??;
                if let Ok(mut hints) = self.routes.lock() {
                    hints.success(debtor)
                }
                Ok(reply)
            }
        }
    }

    async fn send_reserved(&self, request: Signed<Redemption>) -> Option<Signed<RedemptionProof>> {
        let r = &request.payload;
        let peer = r.debtor.clone();
        let request_id = r.id().ok()?;
        let hash = r.payment_hash.clone();
        let proof = match self.call(&peer, Call::Redeem(request.clone())).await {
            Ok(Reply::Paid(proof)) => proof,
            Ok(Reply::Declined) => {
                // Recover a volatile quote only on the originally reserved agreement.
                // A missing response leaves the original payment pending.
                let query = Query {
                    nonce: rand::random(),
                    agreement_id: r.agreement_id.clone(),
                    amount_sat: r.amount_sat,
                    max_fee_sat: r.fee_sat,
                    hops: MAX_HOPS.checked_sub(r.depth)?.checked_add(1)?,
                    probes: BUDGET,
                };
                let recovered = match self.call(&peer, Call::Query(query)).await {
                    Ok(Reply::Available) => r.fee_sat == 0,
                    Ok(Reply::Priced { fee_sat }) => r.fee_sat == fee_sat,
                    _ => false,
                };
                if !recovered {
                    return None;
                }
                let Ok(Reply::Paid(proof)) = self.call(&peer, Call::Redeem(request)).await else {
                    return None;
                };
                proof
            }
            _ => return None,
        };
        // A peer could have other legitimate pending payments with this node.
        (proof.payload.request_id == request_id && proof.payload.payment_hash == hash)
            .then_some(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_requires_room_and_a_replayed_nonce_spends_no_new_budget() {
        let mut h = Hints::default();
        assert!(h.begin(100));
        assert!(!h.begin(100));
        for i in 0..=256 {
            let q = Query {
                nonce: i,
                amount_sat: i + 1,
                agreement_id: "agreement".into(),
                max_fee_sat: 0,
                hops: 1,
                probes: 1,
            };
            assert_eq!(h.remember("issuer", &q, 0, Choice::Wallet).is_ok(), i < 256);
        }
        let existing = Query {
            nonce: 555,
            amount_sat: 1,
            agreement_id: "agreement".into(),
            max_fee_sat: 0,
            hops: 1,
            probes: 1,
        };
        assert!(h.remember("issuer", &existing, 0, Choice::Wallet).is_ok());
    }
}
