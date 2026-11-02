use std::cmp::Ordering;

use super::{persistence::*, *};
use crate::paid_routes::PAID_ROUTE_PRICE_BYTES_PER_GB;

pub const PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB: u64 = 100_000;
pub const PAID_ROUTE_AUTO_MIN_FREE_PROBE_BYTES: u64 = 1024 * 1024;
pub const PAID_ROUTE_AUTO_MAX_CHANNEL_CAPACITY_SAT: u64 = 1_000;

const FUTURE_CLOCK_SKEW_SECS: u64 = 5 * 60;
const CHANNEL_TARGET_BYTES: u64 = 100 * 1024 * 1024;
const CHANNEL_TARGET_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    offer_key: String,
    mint_url: String,
    capacity_sat: u64,
    funded: bool,
    payment_available: bool,
    local_probe: Option<LocalProbeRank>,
    local_probe_count: u32,
    previously_verified: bool,
    personal_rating: i64,
    rating_score: i64,
    price_msat_per_gb: u64,
    signed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LocalProbeRank {
    usable: bool,
    retained_packets_ppm: u32,
    inverse_latency_ms: u32,
    inverse_jitter_ms: u32,
    down_bps: u64,
    up_bps: u64,
}

impl PaidRouteStore {
    pub fn select_automatic_offer(
        &self,
        now_unix: u64,
    ) -> Result<PaidRouteAutomaticOfferSelection> {
        let candidate = self
            .offers
            .iter()
            .filter_map(|(key, record)| self.candidate(key, record, now_unix))
            .max_by(compare_candidates)
            .ok_or_else(|| {
                anyhow!(
                    "No eligible automatic exit at or below {} sat/GB",
                    PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB / 1_000
                )
            })?;
        // Keep blocked candidates in the ranking to explain why selection is
        // waiting, but never return one as a new purchase. Existing funded
        // channels remain usable without reaching their mint.
        if !candidate.payment_available {
            let mint = Url::parse(&candidate.mint_url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .unwrap_or_else(|| candidate.mint_url.clone());
            if self.buyer_mint_needs_funds(&candidate.mint_url, candidate.capacity_sat) {
                return Err(anyhow!("More funds needed · {mint}"));
            }
            let cause = normalize_paid_route_mint_url(&candidate.mint_url)
                .ok()
                .and_then(|url| self.buyer_mint_retries.get(&url))
                .filter(|retry| !retry.error.is_empty())
                .map_or_else(String::new, |retry| format!(" · {}", retry.error));
            return Err(anyhow!(
                "Payment unavailable · {mint}{cause} · No payable alternative · Retrying in {} s",
                self.buyer_mint_failure_retry_at(&candidate.mint_url)
                    .saturating_sub(now_unix)
            ));
        }
        Ok(PaidRouteAutomaticOfferSelection {
            funded: candidate.funded,
            previously_verified: candidate.previously_verified,
            offer_key: candidate.offer_key,
            mint_url: candidate.mint_url,
            channel_capacity_sat: candidate.capacity_sat,
        })
    }

    fn candidate(
        &self,
        key: &str,
        record: &PaidRouteOfferRecord,
        now_unix: u64,
    ) -> Option<Candidate> {
        record.signed_offer.verify().ok()?;
        let offer = record.signed_offer.offer().ok()?;
        let signed_at_unix = record.signed_offer.event.created_at.as_secs();
        if offer != record.offer
            || self.exit_provider_is_avoided(&offer.seller_npub)
            || offer.seller_npub == self.automatic_reselect_from
            || paid_route_offer_store_key(&offer.seller_npub, &offer.offer_id) != key
            || !record.signed_offer.is_live_at(now_unix)
            || !offer.ip_support.ipv4
        {
            return None;
        }

        let previously_verified = self.sessions.values().any(|session| {
            let Some(channel) = self.channels.get(&session.session.payment.channel_id) else {
                return false;
            };
            let successful_at = session.successful_probe_unix();
            channel.role == PaidRouteChannelRole::Buyer
                && channel.offer_id == offer.offer_id
                && channel.counterparty_npub == offer.seller_npub
                && successful_at > 0
                && successful_at <= now_unix.saturating_add(FUTURE_CLOCK_SKEW_SECS)
        });
        if !previously_verified
            && offer.channel.free_probe_units < PAID_ROUTE_AUTO_MIN_FREE_PROBE_BYTES
        {
            return None;
        }

        if offer.pricing.price_msat_per_gb > PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB {
            return None;
        }
        let (mint_url, capacity_sat, funded) = self.trusted_mint_and_capacity(&offer, now_unix)?;
        if !funded
            && record.signed_offer.output_version().ok()?
                != crate::paid_routes::PAID_ROUTE_OUTPUT_VERSION
        {
            return None;
        }
        let (local_probe, local_probe_count) = self.local_probe_history(&offer, now_unix);
        Some(Candidate {
            offer_key: key.to_string(),
            capacity_sat,
            funded,
            payment_available: funded
                || (self.buyer_mint_failure_retry_at(&mint_url) <= now_unix
                    && !self.buyer_mint_needs_funds(&mint_url, capacity_sat)),
            mint_url,
            local_probe,
            local_probe_count,
            previously_verified,
            personal_rating: self.personal_exit_rating(&offer.seller_npub),
            rating_score: record.rating_score.unwrap_or_default(),
            price_msat_per_gb: offer.pricing.price_msat_per_gb,
            signed_at_unix,
        })
    }

    fn trusted_mint_and_capacity(
        &self,
        offer: &PaidRouteOffer,
        now_unix: u64,
    ) -> Option<(String, u64, bool)> {
        let accepted = normalize_mint_list(&offer.channel.accepted_mints);
        if let Some(existing) = self
            .sessions
            .values()
            .filter_map(|session| {
                let lease = self.leases.get(&session.session.lease_id)?;
                let channel = self.channels.get(&session.session.payment.channel_id)?;
                let mint = channel.mint_url.trim();
                (channel.role == PaidRouteChannelRole::Buyer
                    && channel.offer_id == offer.offer_id
                    && channel.counterparty_npub == offer.seller_npub
                    && accepted.iter().any(|url| url == mint)
                    && channel.routing_expires_at_unix(lease.lease.expires_at_unix) > now_unix
                    && paid_route_lifecycle_allows_routing(lease.status)
                    && paid_route_lifecycle_allows_routing(channel.status)
                    && self
                        .buyer_session_has_remaining_capacity(&session.session.session_id)
                        .ok()?
                    && paid_route_session_has_payment_material(&session.session, channel))
                .then_some((
                    session.updated_at_unix,
                    mint.to_string(),
                    session.session.payment.capacity_sat,
                ))
            })
            .max_by_key(|(updated_at, _, _)| *updated_at)
        {
            return Some((existing.1, existing.2, true));
        }
        let default = self.wallet.default_mint.trim();
        let target = self.recommended_capacity_sat(offer, None, now_unix)?;
        let mut wallet_mints = self
            .wallet
            .mints
            .iter()
            .filter(|mint| accepted.iter().any(|url| url == mint.url.trim()))
            .filter_map(|mint| {
                let capacity =
                    target.min(mint.balance_msat.map_or(target, |balance| balance / 1_000));
                (capacity > 0).then_some((mint, capacity))
            })
            .collect::<Vec<_>>();
        wallet_mints.sort_by_key(|(mint, capacity)| {
            (
                self.buyer_mint_needs_funds(&mint.url, *capacity),
                self.buyer_mint_failure_retry_at(&mint.url) > now_unix,
                mint.balance_msat
                    .is_none_or(|balance| balance / 1_000 < target),
                mint.url.trim() != default,
                mint.url.trim(),
            )
        });
        wallet_mints
            .into_iter()
            .next()
            .map(|(mint, capacity)| (mint.url.trim().to_string(), capacity, false))
    }

    fn local_probe_history(
        &self,
        offer: &PaidRouteOffer,
        now_unix: u64,
    ) -> (Option<LocalProbeRank>, u32) {
        let mut probes = self.sessions.values().filter_map(|session| {
            let channel = self.channels.get(&session.session.payment.channel_id)?;
            let quality = session.session.quality.as_ref()?;
            (channel.role == PaidRouteChannelRole::Buyer
                && channel.offer_id == offer.offer_id
                && channel.counterparty_npub == offer.seller_npub
                && quality.last_seen_unix.unwrap_or_default()
                    <= now_unix.saturating_add(FUTURE_CLOCK_SKEW_SECS))
            .then_some((
                quality.last_seen_unix.unwrap_or_default(),
                probe_rank(quality)?,
            ))
        });
        let Some(mut latest) = probes.next() else {
            return (None, 0);
        };
        let mut count = 1_u32;
        for probe in probes {
            count = count.saturating_add(1);
            latest = latest.max(probe);
        }
        (Some(latest.1), count)
    }
}

impl PaidRouteSessionRecord {
    pub(crate) fn successful_probe_unix(&self) -> u64 {
        // Backfill legacy stores from locally observed exit IP and successful
        // measurements, never from an advert or another buyer's rating.
        let observed = if self
            .session
            .realized_exit_ip
            .as_ref()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            && self
                .session
                .quality
                .as_ref()
                .is_none_or(|quality| quality.packet_loss_ppm != Some(1_000_000))
        {
            self.session
                .quality
                .as_ref()
                .and_then(|quality| quality.last_seen_unix)
                .unwrap_or(self.updated_at_unix)
        } else {
            0
        };
        self.last_successful_probe_unix.max(observed)
    }
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    // A known failed probe cannot be rescued by a vote. Within the same
    // health class, explicit preference wins, then local measurements and
    // trusted reputation, before price and announcement recency.
    let health = |candidate: &Candidate| {
        candidate
            .local_probe
            .map_or(1, |probe| if probe.usable { 2 } else { 0 })
    };
    left.payment_available
        .cmp(&right.payment_available)
        .then_with(|| health(left).cmp(&health(right)))
        .then_with(|| left.personal_rating.cmp(&right.personal_rating))
        .then_with(|| left.local_probe.cmp(&right.local_probe))
        .then_with(|| left.rating_score.cmp(&right.rating_score))
        .then_with(|| left.local_probe_count.cmp(&right.local_probe_count))
        .then_with(|| right.price_msat_per_gb.cmp(&left.price_msat_per_gb))
        .then_with(|| left.signed_at_unix.cmp(&right.signed_at_unix))
        .then_with(|| right.offer_key.cmp(&left.offer_key))
}

fn probe_rank(quality: &PaidRouteQualityMetrics) -> Option<LocalProbeRank> {
    (quality.latency_ms.is_some()
        || quality.jitter_ms.is_some()
        || quality.packet_loss_ppm.is_some()
        || quality.down_bps.is_some()
        || quality.up_bps.is_some())
    .then(|| LocalProbeRank {
        usable: quality.packet_loss_ppm != Some(1_000_000),
        retained_packets_ppm: 1_000_000_u32
            .saturating_sub(quality.packet_loss_ppm.unwrap_or(1_000_000).min(1_000_000)),
        inverse_latency_ms: u32::MAX.saturating_sub(quality.latency_ms.unwrap_or(u32::MAX)),
        inverse_jitter_ms: u32::MAX.saturating_sub(quality.jitter_ms.unwrap_or(u32::MAX)),
        down_bps: quality.down_bps.unwrap_or_default(),
        up_bps: quality.up_bps.unwrap_or_default(),
    })
}

impl PaidRouteStore {
    pub(super) fn recommended_capacity_sat(
        &self,
        offer: &PaidRouteOffer,
        balance_msat: Option<u64>,
        now_unix: u64,
    ) -> Option<u64> {
        let matches_offer = |channel: &PaidRouteChannelRecord| {
            channel.role == PaidRouteChannelRole::Buyer
                && channel.offer_id == offer.offer_id
                && channel.counterparty_npub == offer.seller_npub
        };
        // Start small. Once traffic has been observed locally, budget an hour
        // at the most recently used channel's average rate, bounded by its
        // usable lifetime. A one-minute denominator limits short probe bursts.
        let horizon = CHANNEL_TARGET_SECS.min(
            crate::paid_routes::paid_route_collection_after_secs(offer.channel.channel_expiry_secs),
        );
        let measured = self.sessions.values().filter(|session| {
            session.usage_started_at_unix >= session.created_at_unix
                && session.last_usage_at_unix >= session.usage_started_at_unix
                && session.last_usage_at_unix > 0
                && session.last_usage_at_unix <= now_unix
                && session.session.usage.billable_bytes > 0
                && self
                    .channels
                    .get(&session.session.payment.channel_id)
                    .is_some_and(matches_offer)
        });
        let newest_used_channel = measured
            .clone()
            .map(|session| session.created_at_unix)
            .max()
            .unwrap_or(0);
        let traffic_bytes = measured
            .filter(|session| now_unix - session.last_usage_at_unix <= CHANNEL_TARGET_SECS)
            .max_by_key(|session| session.last_usage_at_unix)
            .map_or(0, |session| {
                u128::from(session.session.usage.billable_bytes) * u128::from(horizon)
                    / u128::from(
                        (session.last_usage_at_unix - session.usage_started_at_unix).max(60),
                    )
            })
            .max(u128::from(CHANNEL_TARGET_BYTES));
        let target_sat = u128::from(offer.pricing.price_msat_per_gb)
            .saturating_mul(traffic_bytes)
            .div_ceil(u128::from(PAID_ROUTE_PRICE_BYTES_PER_GB) * 1_000)
            .max(1);
        // The prepared quote survives wallet failures and process restarts.
        // Retain that target when reselection must open a replacement, even
        // after the traffic sample ages out during a mint outage.
        let pending_capacity = self
            .buyer_session_renewals
            .values()
            .filter_map(|id| self.sessions.get(id))
            .filter_map(|session| {
                let channel = self.channels.get(&session.session.payment.channel_id)?;
                (matches_offer(channel)
                    && session.created_at_unix <= now_unix
                    && session.created_at_unix >= newest_used_channel
                    && !paid_route_session_has_payment_material(&session.session, channel))
                .then_some(channel.payment.capacity_sat)
            })
            .max()
            .unwrap_or(0);
        let mut capacity = target_sat
            .max(u128::from(pending_capacity))
            .min(u128::from(offer.channel.max_channel_capacity_sat))
            .min(u128::from(PAID_ROUTE_AUTO_MAX_CHANNEL_CAPACITY_SAT))
            as u64;
        if let Some(balance_msat) = balance_msat {
            capacity = capacity.min(balance_msat / 1_000);
        }
        (capacity > 0).then_some(capacity)
    }
}
