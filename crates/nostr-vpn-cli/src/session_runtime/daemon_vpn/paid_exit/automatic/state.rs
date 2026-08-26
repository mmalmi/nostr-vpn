use super::*;

pub(super) const PAID_EXIT_AUTO_HEALTH_TTL_SECS: u64 = 15;
pub(super) const PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS: u64 = 30;
const PAID_EXIT_AUTO_PROBE_TIMEOUT_SECS: u64 = 30;
const PAID_EXIT_AUTO_FAILOVER_SECS: u64 = 60;

#[derive(Default)]
pub(crate) struct PaidExitAutomaticBuyer {
    pub(super) generation: u64,
    pub(super) candidate: Option<PaidExitAutomaticCandidate>,
    pub(super) rejected_offers: HashMap<String, u64>,
    pub(super) probe: Option<PaidExitAutomaticProbe>,
}

pub(super) struct PaidExitAutomaticProbe {
    pub(super) generation: u64,
    pub(super) task: tokio::task::JoinHandle<Result<PaidRouteProbeMeasurement>>,
}

pub(super) struct PaidExitAutomaticCandidate {
    pub(super) selection: nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
    pub(super) seller_pubkey: String,
    pub(super) session_id: String,
    pub(super) selected_at: u64,
    pub(super) probe_started_at: Option<u64>,
    pub(super) probe_succeeded: bool,
    pub(super) funding_attempted: bool,
    pub(super) funded: bool,
    pub(super) last_authenticated_at: Option<u64>,
    pub(super) last_tx_at: Option<u64>,
    pub(super) last_rx_at: Option<u64>,
    pub(super) last_healthy_at: Option<u64>,
    pub(super) failed: bool,
}

#[derive(Default)]
pub(crate) struct PaidExitUsageFlush {
    pub(crate) seller_admission_changed: bool,
    pub(crate) buyer_delta: PaidRouteUsage,
}

impl PaidExitAutomaticCandidate {
    pub(super) fn reconcile_selection(
        &mut self,
        selection: nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
    ) {
        if self.selection.offer_key != selection.offer_key
            || self.selection.mint_url != selection.mint_url
        {
            self.failed = true;
            return;
        }
        // Funding makes the actual channel capacity authoritative, so the
        // derived selection can legitimately change while it still refers to
        // the same signed seller offer. Keep that route and remember the
        // updated channel details instead of treating it as a failover.
        self.selection = selection;
    }

    pub(super) fn observe_presence(&mut self, statuses: &[MeshPeerStatus], now_unix: u64) {
        let authenticated = statuses.iter().any(|status| {
            status.connected
                && normalize_nostr_pubkey(&status.pubkey).ok().as_deref()
                    == Some(self.seller_pubkey.as_str())
                && status.last_seen_at.is_some_and(|seen| {
                    now_unix.saturating_sub(seen) <= PAID_EXIT_AUTO_HEALTH_TTL_SECS
                })
        });
        if authenticated {
            self.last_authenticated_at = Some(now_unix);
        }
    }

    pub(super) fn observe_usage(&mut self, delta: &PaidRouteUsage, now_unix: u64) {
        if delta.tx_bytes > 0 {
            self.last_tx_at = Some(now_unix);
        }
        if delta.rx_bytes > 0 {
            self.last_rx_at = Some(now_unix);
        }
        if self.health_evidence_fresh(now_unix) {
            self.last_healthy_at = Some(now_unix);
        }
    }

    pub(super) fn health_evidence_fresh(&self, now_unix: u64) -> bool {
        self.probe_succeeded
            && [self.last_authenticated_at, self.last_tx_at, self.last_rx_at]
                .into_iter()
                .all(|observed| {
                    observed.is_some_and(|observed| {
                        now_unix.saturating_sub(observed) <= PAID_EXIT_AUTO_HEALTH_TTL_SECS
                    })
                })
    }

    pub(super) fn should_failover(&self, now_unix: u64) -> bool {
        if self.failed {
            return true;
        }
        if !self.probe_succeeded
            && now_unix.saturating_sub(self.probe_started_at.unwrap_or(self.selected_at))
                >= PAID_EXIT_AUTO_PROBE_TIMEOUT_SECS
        {
            return true;
        }
        self.funded
            && self.last_healthy_at.is_some_and(|healthy| {
                now_unix.saturating_sub(healthy) >= PAID_EXIT_AUTO_FAILOVER_SECS
            })
    }
}

impl PaidExitAutomaticBuyer {
    pub(crate) fn enabled(app: &AppConfig) -> bool {
        app.internet_source == nostr_vpn_core::config::InternetSource::PaidAutomatic
    }

    pub(crate) fn payments_allowed(&self, app: &AppConfig, now_unix: u64) -> bool {
        if !Self::enabled(app) {
            return true;
        }
        self.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.funded && candidate.health_evidence_fresh(now_unix))
    }

    pub(crate) fn cancel_if_disabled(&mut self, app: &AppConfig) {
        if Self::enabled(app) {
            return;
        }
        if let Some(probe) = self.probe.take() {
            probe.task.abort();
        }
        self.generation = self.generation.wrapping_add(1);
        self.candidate = None;
        self.rejected_offers.clear();
    }

    pub(super) fn selection(
        &mut self,
        store: &PaidRouteStore,
        now_unix: u64,
    ) -> Result<nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection> {
        self.expire_rejected_offers(now_unix);
        let mut candidates = store.clone();
        for offer in self.rejected_offers.keys() {
            candidates.offers.remove(offer);
        }
        candidates.select_automatic_offer(now_unix)
    }

    pub(super) fn expire_rejected_offers(&mut self, now_unix: u64) {
        self.rejected_offers
            .retain(|_, retry_at| *retry_at > now_unix);
    }

    pub(super) fn start_candidate(
        &mut self,
        selection: nostr_vpn_core::paid_route_store::PaidRouteAutomaticOfferSelection,
        seller_pubkey: String,
        session_id: String,
        funded: bool,
        now_unix: u64,
    ) {
        self.generation = self.generation.wrapping_add(1);
        self.candidate = Some(PaidExitAutomaticCandidate {
            selection,
            seller_pubkey,
            session_id,
            selected_at: now_unix,
            probe_started_at: None,
            probe_succeeded: false,
            funding_attempted: funded,
            funded,
            last_authenticated_at: None,
            last_tx_at: None,
            last_rx_at: None,
            last_healthy_at: None,
            failed: false,
        });
    }

    pub(super) fn cancel_candidate(&mut self, reject: bool, now_unix: u64) {
        if let Some(probe) = self.probe.take() {
            probe.task.abort();
        }
        if reject && let Some(candidate) = self.candidate.as_ref() {
            self.rejected_offers.insert(
                candidate.selection.offer_key.clone(),
                now_unix.saturating_add(PAID_EXIT_AUTO_RETRY_COOLDOWN_SECS),
            );
        }
        self.generation = self.generation.wrapping_add(1);
        self.candidate = None;
    }
}
