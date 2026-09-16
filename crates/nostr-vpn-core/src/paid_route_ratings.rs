//! Exit feedback uses the shared social-memory Rating wire format. Only the
//! publication state and local service policy belong to the VPN.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, anyhow};
use nostr_sdk::prelude::{Event, Keys, PublicKey, ToBech32};
use nostr_social_graph::SocialGraph;
use nostr_social_memory::{Rating, RatingEventExt, rating_from_event};
use serde::{Deserialize, Serialize};

use crate::paid_route_store::{PaidRouteSessionRecord, PaidRouteStore};

pub const EXIT_RATING_SCOPE: &str = "vpn.exit";
pub const EXIT_RATING_MIN_INTERVAL: u64 = 60 * 60;
pub const EXIT_RATING_REFRESH_INTERVAL: u64 = 24 * 60 * 60;
pub const EXIT_RATING_MAX_AGE: u64 = 30 * 24 * 60 * 60;
const MAX_FUTURE_SKEW: u64 = 5 * 60;
const USER_REASON: &str = "user";
const PROBE_REASON: &str = "paid_exit_probe";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalExitRating {
    pub event: Event,
    #[serde(default)]
    pub queued_event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitRatingScore {
    pub score: i64,
    pub authors: usize,
    pub created_at: u64,
}

pub fn exit_rating_event(
    keys: &Keys,
    seller: &str,
    score: i64,
    manual: bool,
    now: u64,
) -> Result<Event> {
    let mut rating = Rating::new(
        keys.public_key().to_hex(),
        PublicKey::parse(seller)?.to_hex(),
        score,
        -100,
        100,
    );
    rating.scope = Some(EXIT_RATING_SCOPE.into());
    rating.reason = Some(if manual { USER_REASON } else { PROBE_REASON }.into());
    rating.created_at = now;
    // No probe values, session identifiers, IPs, or payment data are published.
    rating.to_event(keys)
}

/// Direct feedback must be authored by its signer. Social memory also supports
/// crawled third-party reviews; those are not authenticated exit feedback.
pub fn verified_exit_rating(event: &Event, now: u64) -> Result<Rating> {
    event.verify()?;
    let rating = rating_from_event(event)?;
    if rating.scope.as_deref() != Some(EXIT_RATING_SCOPE)
        || PublicKey::parse(&rating.rater)? != event.pubkey
        || rating.created_at > now.saturating_add(MAX_FUTURE_SKEW)
        || event.created_at.as_secs() > now.saturating_add(MAX_FUTURE_SKEW)
        || now.saturating_sub(rating.created_at) > EXIT_RATING_MAX_AGE
    {
        return Err(anyhow!("invalid or expired exit rating"));
    }
    PublicKey::parse(&rating.subject)?;
    Ok(rating)
}

/// Explicit local trusted authors augment the user's follow graph, without
/// allowing a positive exit review to delegate rating authority.
pub fn trust_exit_rating_authors(graph: &mut SocialGraph, authors: &[String]) -> Result<()> {
    let root = graph.get_root().to_owned();
    for author in authors {
        graph.add_positive_relation(&root, &PublicKey::parse(author)?.to_hex(), 0)?;
    }
    graph.recalculate_follow_distances();
    Ok(())
}

pub fn exit_rating_graph(
    root: &str,
    events: &[Event],
    trusted_authors: &[String],
    now: u64,
) -> Result<SocialGraph> {
    let root = PublicKey::parse(root)?;
    let mut graph = SocialGraph::new(&root.to_hex());
    let mut latest: BTreeMap<u16, &Event> = BTreeMap::new();
    for event in events {
        let kind = u16::from(event.kind);
        if event.pubkey != root
            || !matches!(kind, 3 | 10_000)
            || event.created_at.as_secs() > now.saturating_add(MAX_FUTURE_SKEW)
            || event.verify().is_err()
        {
            continue;
        }
        if latest.get(&kind).is_none_or(|old| {
            event.created_at > old.created_at
                || (event.created_at == old.created_at && event.id < old.id)
        }) {
            latest.insert(kind, event);
        }
    }
    for event in latest.values() {
        graph.handle_event(
            &nostr_social_graph::NostrEvent {
                created_at: event.created_at.as_secs(),
                content: event.content.clone(),
                tags: event
                    .tags
                    .iter()
                    .map(|tag| tag.as_slice().to_vec())
                    .collect(),
                kind: u16::from(event.kind).into(),
                pubkey: event.pubkey.to_hex(),
                id: event.id.to_hex(),
                sig: event.sig.to_string(),
            },
            true,
            1.0,
        );
    }
    trust_exit_rating_authors(&mut graph, trusted_authors)?;
    Ok(graph)
}

/// Root and direct-follow ratings are admitted. Limiting admission to this
/// explicit trust boundary prevents one followed actor minting unlimited
/// follow-of-follow identities. Service reviews never mutate this graph.
pub fn exit_rating_scores<'a>(
    events: impl IntoIterator<Item = &'a Event>,
    graph: &SocialGraph,
    now: u64,
) -> BTreeMap<String, ExitRatingScore> {
    let muted: HashSet<_> = graph
        .get_muted_by_user(graph.get_root())
        .into_iter()
        .collect();
    let mut latest: BTreeMap<(String, String), (&Event, Rating)> = BTreeMap::new();
    for event in events {
        let author = event.pubkey.to_hex();
        if graph.get_follow_distance(&author) > 1 || muted.contains(&author) {
            continue;
        }
        let Ok(rating) = verified_exit_rating(event, now) else {
            continue;
        };
        let Some(subject) = PublicKey::parse(&rating.subject)
            .ok()
            .and_then(|key| key.to_bech32().ok())
        else {
            continue;
        };
        // Provider self-reviews must not improve its own reputation.
        if PublicKey::parse(&rating.subject).ok() == Some(event.pubkey) {
            continue;
        }
        let key = (author, subject);
        let replace = latest.get(&key).is_none_or(|(old_event, old)| {
            (rating.created_at, event.id.to_hex()) > (old.created_at, old_event.id.to_hex())
        });
        if replace {
            latest.insert(key, (event, rating));
        }
    }
    let mut totals: BTreeMap<String, (i64, usize, u64)> = BTreeMap::new();
    for ((_, subject), (_, rating)) in latest {
        let Ok(score) = rating.normalized_score() else {
            continue;
        };
        // A withdrawal supersedes the previous opinion, without a neutral vote
        // diluting everyone else's score.
        if score == 0 {
            continue;
        }
        let total = totals.entry(subject).or_default();
        total.0 += score;
        total.1 += 1;
        total.2 = total.2.max(rating.created_at);
    }
    totals
        .into_iter()
        .map(|(subject, (total, count, created_at))| {
            (
                subject,
                ExitRatingScore {
                    score: total / count as i64,
                    authors: count,
                    created_at,
                },
            )
        })
        .collect()
}

impl PaidRouteStore {
    pub fn rate_exit(
        &mut self,
        app: &mut crate::config::AppConfig,
        seller: &str,
        vote: i64,
        now: u64,
    ) -> Result<()> {
        if !(-1..=1).contains(&vote) {
            return Err(anyhow!("invalid exit opinion"));
        }
        if !self.can_rate_exit(seller) {
            return Err(anyhow!("connect through this provider before rating it"));
        }
        self.record_exit_rating(&app.nostr_keys()?, seller, vote * 100, true, now)?;
        if vote < 0
            && app.exit_node_public_paid_exit
            && PublicKey::parse(&app.exit_node).ok() == PublicKey::parse(seller).ok()
        {
            app.exit_node_leak_protection = true;
            app.exit_node.clear();
            app.exit_node_public_paid_exit = false;
            if app.internet_source == crate::config::InternetSource::PaidManual {
                app.clear_manual_paid_exit_provider();
            }
        }
        Ok(())
    }

    pub fn request_exit_reselection(
        &mut self,
        app: &crate::config::AppConfig,
        now: u64,
    ) -> Result<()> {
        if app.internet_source != crate::config::InternetSource::PaidAutomatic
            || !app.exit_node_public_paid_exit
            || app.exit_node.is_empty()
        {
            return Err(anyhow!("select an automatic provider first"));
        }
        let seller = PublicKey::parse(&app.exit_node)?.to_bech32()?;
        let previous = std::mem::replace(&mut self.automatic_reselect_from, seller);
        if self.select_automatic_offer(now).is_err() {
            self.automatic_reselect_from = previous;
            return Err(anyhow!("no other eligible provider is available yet"));
        }
        Ok(())
    }

    pub fn can_rate_exit(&self, seller: &str) -> bool {
        let Ok(seller) = PublicKey::parse(seller) else {
            return false;
        };
        self.sessions.values().any(|record| {
            record.successful_probe_unix() > 0
                && self
                    .channels
                    .get(&record.session.payment.channel_id)
                    .is_some_and(|channel| {
                        channel.role == crate::paid_route_store::PaidRouteChannelRole::Buyer
                            && PublicKey::parse(&channel.counterparty_npub).ok() == Some(seller)
                    })
        })
    }

    pub fn record_exit_probe_rating(
        &mut self,
        keys: &Keys,
        session_id: &str,
        now: u64,
    ) -> Result<bool> {
        let seller = self.buyer_session_seller_npub(session_id)?;
        let record = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("unknown exit session"))?;
        let Some(score) = exit_probe_rating(record) else {
            return Ok(false);
        };
        // A standalone probe cannot attribute a negative result to the exit.
        // The live feedback window can do so using a healthy alternative.
        if score < 0 {
            return Ok(false);
        }
        self.record_exit_rating(keys, &seller, score, false, now)
    }

    pub fn refresh_exit_reputation(&mut self, events: &[Event], graph: &SocialGraph, now: u64) {
        let scores = exit_rating_scores(
            events
                .iter()
                .chain(self.exit_ratings.values().map(|r| &r.event)),
            graph,
            now,
        );
        for record in self.offers.values_mut() {
            let score = scores.get(&record.offer.seller_npub);
            record.rating_score = score.map(|s| s.score);
            record.rating_updated_at_unix = score.map_or(0, |s| s.created_at);
        }
    }
    pub fn record_exit_rating(
        &mut self,
        keys: &Keys,
        seller: &str,
        score: i64,
        manual: bool,
        now: u64,
    ) -> Result<bool> {
        if !(-100..=100).contains(&score) {
            return Err(anyhow!("exit rating is out of range"));
        }
        let seller = PublicKey::parse(seller)?.to_bech32()?;
        let mut created_at = now;
        if let Some(previous) = self.exit_ratings.get(&seller)
            && previous.event.pubkey == keys.public_key()
            && let Ok(rating) = rating_from_event(&previous.event)
        {
            let age = now.saturating_sub(rating.created_at);
            if !manual
                && ((rating.reason.as_deref() == Some(USER_REASON) && rating.rating != 0)
                    || age < 60
                    || (age < EXIT_RATING_MIN_INTERVAL && score.signum() == rating.rating.signum())
                    || ((score - rating.rating).abs() < 10 && age < EXIT_RATING_REFRESH_INTERVAL))
            {
                return Ok(false);
            }
            if manual && rating.reason.as_deref() == Some(USER_REASON) && rating.rating == score {
                return Ok(false);
            }
            // Make rapid vote changes ordered even within one clock second.
            created_at = now.max(rating.created_at.saturating_add(1));
            if created_at > now.saturating_add(MAX_FUTURE_SKEW) {
                return Err(anyhow!("exit rating changes are too frequent"));
            }
        }
        let event = exit_rating_event(keys, &seller, score, manual, created_at)?;
        self.exit_ratings.insert(
            seller,
            LocalExitRating {
                event,
                queued_event_id: String::new(),
            },
        );
        Ok(true)
    }

    pub fn personal_exit_rating(&self, seller: &str) -> i64 {
        let Some(seller) = PublicKey::parse(seller)
            .ok()
            .and_then(|key| key.to_bech32().ok())
        else {
            return 0;
        };
        let Some(local) = self.exit_ratings.get(&seller) else {
            return 0;
        };
        if local.event.verify().is_err() {
            return 0;
        }
        rating_from_event(&local.event)
            .ok()
            .filter(|rating| {
                rating.reason.as_deref() == Some(USER_REASON)
                    && rating.scope.as_deref() == Some(EXIT_RATING_SCOPE)
                    && PublicKey::parse(&rating.subject).ok() == PublicKey::parse(&seller).ok()
                    && PublicKey::parse(&rating.rater).ok() == Some(local.event.pubkey)
            })
            .map_or(0, |rating| rating.rating.signum())
    }

    pub fn exit_provider_is_avoided(&self, seller: &str) -> bool {
        self.personal_exit_rating(seller) < 0
    }

    pub fn pending_exit_ratings(&self) -> Vec<Event> {
        self.exit_ratings
            .values()
            .filter(|local| local.queued_event_id != local.event.id.to_hex())
            .map(|local| local.event.clone())
            .collect()
    }

    pub fn mark_exit_rating_queued(&mut self, event_id: &str) {
        for local in self.exit_ratings.values_mut() {
            if local.event.id.to_hex() == event_id {
                local.queued_event_id = event_id.to_owned();
            }
        }
    }
}

/// Conservative summary of a real local probe. Missing metrics are neutral.
pub fn exit_probe_rating(record: &PaidRouteSessionRecord) -> Option<i64> {
    let session = &record.session;
    let quality = session.quality.as_ref();
    if session.realized_exit_ip.is_none() && quality.is_none_or(|q| q.is_empty()) {
        return None;
    }
    let mut rating = if session.realized_exit_ip.is_some() {
        70_i64
    } else {
        20
    };
    if let Some(q) = quality {
        if let Some(loss) = q.packet_loss_ppm {
            rating += match loss {
                0 => 10,
                1..=10_000 => 5,
                10_001..=50_000 => 0,
                50_001..=200_000 => -20,
                _ => -40,
            };
        }
        if let Some(latency) = q.latency_ms {
            rating += match latency {
                0..=100 => 10,
                101..=300 => 5,
                301..=500 => 0,
                501..=1_000 => -10,
                _ => -20,
            };
        }
        if let Some(jitter) = q.jitter_ms {
            rating += match jitter {
                0..=30 => 5,
                31..=100 => 0,
                101..=200 => -5,
                _ => -10,
            };
        }
        if let Some(bps) = q.down_bps.into_iter().chain(q.up_bps).max() {
            rating += match bps {
                0..=249_999 => -10,
                250_000..=999_999 => 0,
                1_000_000..=9_999_999 => 5,
                _ => 10,
            };
        }
    }
    Some(rating.clamp(0, 100) * 2 - 100)
}

/// Short-lived local evidence. Dropped on link changes, reconnects, or process
/// restart; it is neither persisted nor included in public ratings.
#[derive(Default)]
pub struct ExitProbeFeedback {
    generation: u64,
    observations: BTreeMap<String, (u64, i64)>,
}

impl ExitProbeFeedback {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.observations.clear();
    }

    pub fn observe(
        &mut self,
        store: &mut PaidRouteStore,
        keys: &Keys,
        session_id: &str,
        score: i64,
        observed_at: u64,
        generation: u64,
    ) -> Result<()> {
        if generation != self.generation {
            return Ok(());
        }
        let seller = store.buyer_session_seller_npub(session_id)?;
        self.observations
            .retain(|_, (at, _)| *at <= observed_at && observed_at - *at <= 60);
        self.observations
            .insert(seller.clone(), (observed_at, score));
        let healthy_alternative = self
            .observations
            .iter()
            .any(|(other, (_, rating))| other != &seller && *rating >= 50);
        if score >= 0 || healthy_alternative {
            store.record_exit_rating(keys, &seller, score, false, observed_at)?;
        }
        if score >= 50 {
            // Revisit a recent failed provider when the same connection works
            // through a different provider. Each author still has one vote.
            for (other, (_, rating)) in &self.observations {
                if other != &seller && *rating < 0 {
                    store.record_exit_rating(keys, other, *rating, false, observed_at)?;
                }
            }
        }
        Ok(())
    }
}
