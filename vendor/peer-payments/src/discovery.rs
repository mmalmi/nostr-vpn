//! Read-only counterparty discovery from the user's verified Nostr graph.
//! A relationship can nominate a peer for a quote. It cannot add an issuer to
//! an account, allocate funds or change any bilateral spending limit.
use crate::{
    protocol::authenticate, Agreement, Error, PurchaseIntent, SchnorrVerifier, Signed, WireMessage,
};
use nostr_social_graph::SocialGraph;
use std::collections::HashSet;

pub struct QuotePeers<'a> {
    graph: &'a SocialGraph,
    muted: HashSet<String>,
    direct: HashSet<String>,
}

impl<'a> QuotePeers<'a> {
    /// Supply a graph built from signature-checked contact and mute events.
    pub fn new(graph: &'a SocialGraph, local_pubkey: &str) -> Result<Self, Error> {
        if graph.get_root() != local_pubkey
            || local_pubkey.parse::<secp256k1::XOnlyPublicKey>().is_err()
        {
            return Err(Error::Authentication);
        }
        let muted: HashSet<_> = graph.get_muted_by_user(local_pubkey).into_iter().collect();
        let direct = graph
            .get_followed_by_user(local_pubkey)
            .into_iter()
            .filter(|p| !muted.contains(p))
            .collect();
        Ok(Self {
            graph,
            muted,
            direct,
        })
    }

    /// Local identity whose verified relationships define this view.
    pub fn root(&self) -> &str {
        self.graph.get_root()
    }

    /// Lower distances take precedence when otherwise eligible quotes cost the same.
    pub fn distance(&self, peer: &str) -> Option<u32> {
        if peer == self.graph.get_root() || self.muted.contains(peer) {
            return None;
        }
        if self.direct.contains(peer) {
            return Some(1);
        }
        self.direct
            .iter()
            .any(|friend| self.graph.is_following(friend, peer))
            .then_some(2)
    }

    /// Compare signed quotes against local per-provider purchase intents for the
    /// same job. Price is the total sats for those exact units. The caller can
    /// persist a selected commitment before accepting it with the controller.
    pub fn select_credit_offer<'b>(
        &self,
        offers: &'b [Signed<Agreement>],
        intents: &[PurchaseIntent<'_>],
        now: u64,
    ) -> Result<Option<&'b Signed<Agreement>>, Error> {
        if offers.len() > 128 || intents.len() > 128 {
            return Err(Error::Limit);
        }
        let Some(job) = intents.first() else {
            return Ok(None);
        };
        if intents
            .iter()
            .any(|i| (i.service, i.resource, i.units) != (job.service, job.resource, job.units))
        {
            return Err(Error::Invalid("incomparable purchase intents"));
        }
        let eligible = offers.iter().filter_map(|offer| {
            let a = &offer.payload;
            let distance = self.distance(&a.provider)?;
            if a.payer != self.graph.get_root() || !intents.iter().any(|i| i.check(a, now).is_ok())
            {
                return None;
            }
            authenticate(
                &SchnorrVerifier,
                &a.provider,
                WireMessage::Agreement(a.clone()),
                &offer.signature,
            )
            .ok()?;
            Some((
                (
                    a.max_amount_sat,
                    distance,
                    &a.provider,
                    a.commitment().ok()?,
                ),
                offer,
            ))
        });
        Ok(eligible
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, offer)| offer))
    }
}
