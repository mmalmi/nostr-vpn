use std::cmp::Ordering;

use super::{persistence::*, *};
use crate::paid_routes::PAID_ROUTE_PRICE_BYTES_PER_GB;

pub const PAID_ROUTE_AUTO_MAX_PRICE_MSAT_PER_GB: u64 = 100_000;
pub const PAID_ROUTE_AUTO_MIN_FREE_PROBE_BYTES: u64 = 1024 * 1024;
pub const PAID_ROUTE_AUTO_MAX_CHANNEL_CAPACITY_SAT: u64 = 1_000;

const FUTURE_CLOCK_SKEW_SECS: u64 = 5 * 60;
const CHANNEL_TARGET_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    offer_key: String,
    mint_url: String,
    capacity_sat: u64,
    funded: bool,
    local_probe: Option<LocalProbeRank>,
    local_probe_count: u32,
    previously_verified: bool,
    rating_score: i64,
    price_msat_per_gb: u64,
    signed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LocalProbeRank {
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
        self.offers
            .iter()
            .filter_map(|(key, record)| self.candidate(key, record, now_unix))
            .max_by(compare_candidates)
            .map(|candidate| PaidRouteAutomaticOfferSelection {
                funded: candidate.funded,
                previously_verified: candidate.previously_verified,
                offer_key: candidate.offer_key,
                mint_url: candidate.mint_url,
                channel_capacity_sat: candidate.capacity_sat,
            })
            .ok_or_else(|| {
                anyhow!("no eligible paid route offer is available for automatic selection")
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
        let (local_probe, local_probe_count) = self.local_probe_history(&offer, now_unix);
        Some(Candidate {
            offer_key: key.to_string(),
            mint_url,
            capacity_sat,
            funded,
            local_probe,
            local_probe_count,
            previously_verified,
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
                    && lease.lease.expires_at_unix.min(channel.expires_at_unix) > now_unix
                    && paid_route_lifecycle_allows_routing(lease.status)
                    && paid_route_lifecycle_allows_routing(channel.status)
                    && self.buyer_session_has_remaining_capacity(&session.session.session_id).ok()?
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
        let mut wallet_mints = self
            .wallet
            .mints
            .iter()
            .filter(|mint| accepted.iter().any(|url| url == mint.url.trim()))
            .collect::<Vec<_>>();
        let target = recommended_capacity_sat(offer, None)?;
        wallet_mints.sort_by_key(|mint| {
            (
                self.buyer_mint_needs_funds(
                    &mint.url,
                    recommended_capacity_sat(offer, mint.balance_msat).unwrap_or(target),
                ),
                self.buyer_mint_failure_retry_at(&mint.url) > now_unix,
                mint.balance_msat
                    .is_none_or(|balance| balance / 1_000 < target),
                mint.url.trim() != default,
                mint.url.trim(),
            )
        });
        wallet_mints.into_iter().find_map(|mint| {
            recommended_capacity_sat(offer, mint.balance_msat)
                .map(|capacity| (mint.url.trim().to_string(), capacity, false))
        })
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
    pub(super) fn successful_probe_unix(&self) -> u64 {
        // Backfill legacy stores from locally observed exit IP and successful
        // measurements, never from an advert or another buyer's rating.
        let observed = self
            .session
            .quality
            .as_ref()
            .filter(|quality| {
                self.session
                    .realized_exit_ip
                    .as_ref()
                    .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                    && quality.packet_loss_ppm.unwrap_or(0) < 1_000_000
                    && (quality.latency_ms.is_some() || quality.packet_loss_ppm.is_some())
            })
            .and_then(|quality| quality.last_seen_unix)
            .unwrap_or(0);
        self.last_successful_probe_unix.max(observed)
    }
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    left.local_probe
        .cmp(&right.local_probe)
        .then_with(|| left.local_probe_count.cmp(&right.local_probe_count))
        .then_with(|| right.price_msat_per_gb.cmp(&left.price_msat_per_gb))
        .then_with(|| left.signed_at_unix.cmp(&right.signed_at_unix))
        .then_with(|| left.rating_score.cmp(&right.rating_score))
        .then_with(|| right.offer_key.cmp(&left.offer_key))
}

fn probe_rank(quality: &PaidRouteQualityMetrics) -> Option<LocalProbeRank> {
    (quality.latency_ms.is_some()
        || quality.jitter_ms.is_some()
        || quality.packet_loss_ppm.is_some()
        || quality.down_bps.is_some()
        || quality.up_bps.is_some())
    .then(|| LocalProbeRank {
        retained_packets_ppm: 1_000_000_u32
            .saturating_sub(quality.packet_loss_ppm.unwrap_or(1_000_000).min(1_000_000)),
        inverse_latency_ms: u32::MAX.saturating_sub(quality.latency_ms.unwrap_or(u32::MAX)),
        inverse_jitter_ms: u32::MAX.saturating_sub(quality.jitter_ms.unwrap_or(u32::MAX)),
        down_bps: quality.down_bps.unwrap_or_default(),
        up_bps: quality.up_bps.unwrap_or_default(),
    })
}

fn recommended_capacity_sat(offer: &PaidRouteOffer, balance_msat: Option<u64>) -> Option<u64> {
    let traffic_msat = u64::try_from(
        u128::from(offer.pricing.price_msat_per_gb)
            .saturating_mul(u128::from(CHANNEL_TARGET_BYTES))
            .div_ceil(u128::from(PAID_ROUTE_PRICE_BYTES_PER_GB)),
    )
    .ok()?;
    let target_sat = traffic_msat
        .saturating_add(999)
        .saturating_div(1_000)
        .max(1);
    let mut capacity = target_sat
        .min(offer.channel.max_channel_capacity_sat)
        .min(PAID_ROUTE_AUTO_MAX_CHANNEL_CAPACITY_SAT);
    if let Some(balance_msat) = balance_msat {
        capacity = capacity.min(balance_msat / 1_000);
    }
    (capacity > 0).then_some(capacity)
}
