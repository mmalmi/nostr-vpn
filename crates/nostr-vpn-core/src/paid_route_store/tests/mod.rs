use super::{persistence::*, *};
use crate::paid_routes::{
    PAID_ROUTE_OFFER_VERSION, PaidExitConfig, PaidRouteAccessPolicy, PaidRouteChannelTerms,
    PaidRouteIpSupport, PaidRouteLocationHint, PaidRoutePaymentMode, PaidRoutePaymentState,
    PaidRoutePricing, PaidRoutePrivateVpnAccess, PaidRouteQualityMetrics, PaidRouteSessionOpen,
    PaidRouteUsage, signed_paid_exit_offer_from_config,
    signed_paid_exit_offer_from_config_with_receiver,
};
use cashu_service::{
    CashuSpilmanPayment, CashuSpilmanPaymentReceiver, CashuSpilmanPaymentReceiverValidation,
    CashuSpilmanPaymentSigner, StreamingRouteBalanceUpdate, StreamingRouteChannelOpen,
    StreamingRouteCooperativeClose, StreamingRoutePaymentEnvelope, StreamingRoutePaymentPayload,
};
use nostr_sdk::prelude::{Keys, ToBech32};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nvpn-paid-route-store-{name}-{now}-{seq}"));
        fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

mod buyer;
mod buyer_funding;
mod closing_store;
mod credit_window;
mod renewal;
mod returning_and_trial_limits;
mod seller_open;
mod updates;

fn sample_config() -> PaidExitConfig {
    PaidExitConfig {
        enabled: true,
        access: PaidRouteAccessPolicy {
            upstream: crate::paid_routes::PaidExitUpstream::HostDefault,
            private_vpn_access: PaidRoutePrivateVpnAccess::Denied,
        },
        pricing: PaidRoutePricing {
            price_msat_per_gb: 2_500_000,
        },
        channel: PaidRouteChannelTerms {
            accepted_mints: vec!["https://mint.minibits.cash/Bitcoin".to_string()],
            max_channel_capacity_sat: 100,
            channel_expiry_secs: 600,
            free_probe_units: 1_048_576,
            grace_units: 262_144,
        },
        location: PaidRouteLocationHint::default(),
        ip_support: PaidRouteIpSupport::default(),
        rating_discovery: Default::default(),
    }
}

fn seller_store_with_open_channel(
    seller: &Keys,
    buyer: &Keys,
    config: &PaidExitConfig,
) -> PaidRouteStore {
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut store = PaidRouteStore::default();
    store
        .apply_seller_payment(ApplyPaidRouteSellerPaymentRequest {
            envelope: seller_payment_envelope(
                "internet-exit",
                "lease-1",
                &buyer_npub,
                &seller_npub,
                100,
                StreamingRoutePaymentPayload::ChannelOpen(StreamingRouteChannelOpen {
                    mint_url: "https://mint.minibits.cash/Bitcoin".to_string(),
                    unit: "sat".to_string(),
                    capacity: 10,
                    expires_unix: 500,
                    receiver_pubkey_hex: seller.public_key().to_hex(),
                    paid_msat: 0,
                    payment: sample_spilman_payment("channel-1", 0),
                }),
            ),
            seller_npub,
            config: config.clone(),
            now_unix: 100,
        })
        .expect("apply open");
    store
        .apply_seller_session_open(ApplyPaidRouteSellerSessionOpenRequest {
            authenticated_source_ip: Some("203.0.113.9".parse().unwrap()),
            open: crate::paid_routes::PaidRouteSessionOpen {
                version: crate::paid_routes::PAID_ROUTE_OFFER_VERSION.to_string(),
                service_id: "internet-exit".to_string(),
                lease_id: "lease-1".to_string(),
                channel_id: "channel-1".to_string(),
                seller_npub: seller.public_key().to_bech32().expect("seller npub"),
                buyer_tunnel_ip: "10.44.201.17/32".to_string(),
                expires_at_unix: 500,
            },
            authenticated_buyer_pubkey: buyer.public_key().to_hex(),
            seller_npub: seller.public_key().to_bech32().expect("seller npub"),
            config: config.clone(),
            now_unix: 100,
        })
        .expect("bind buyer tunnel IP");
    store
}

fn buyer_store_with_session(
    seller: &Keys,
    buyer: &Keys,
    config: &PaidExitConfig,
) -> (PaidRouteStore, String, String) {
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", seller, config, None, 100)
            .expect("signed offer");
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.minibits.cash/Bitcoin", "Minibits", None, 99);
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 101)
        .expect("store offer");
    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.minibits.cash/Bitcoin".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: 120,
        })
        .expect("open buyer session");
    (store, result.session_id, result.channel_id)
}

fn seller_payment_envelope(
    service_id: &str,
    lease_id: &str,
    buyer_npub: &str,
    seller_npub: &str,
    sent_at_unix: u64,
    mut payload: StreamingRoutePaymentPayload,
) -> StreamingRoutePaymentEnvelope {
    if let StreamingRoutePaymentPayload::ChannelOpen(open) = &mut payload
        && let Some(params) = open
            .payment
            .params
            .as_mut()
            .and_then(|value| value.as_object_mut())
    {
        for (field, value) in [
            ("mint", json!(open.mint_url)),
            ("capacity", json!(open.capacity)),
            ("expiry_timestamp", json!(open.expires_unix)),
            ("receiver_pubkey", json!(open.receiver_pubkey_hex)),
        ] {
            params.entry(field).or_insert(value);
        }
    }
    StreamingRoutePaymentEnvelope::new(
        service_id,
        lease_id,
        buyer_npub,
        seller_npub,
        sent_at_unix,
        payload,
    )
}

fn sample_spilman_payment(channel_id: &str, balance: u64) -> CashuSpilmanPayment {
    CashuSpilmanPayment {
        channel_id: channel_id.to_string(),
        balance,
        signature: format!("signature-{channel_id}-{balance}"),
        params: Some(json!({"channel": channel_id, "unit": "sat"})),
        funding_proofs: Some(json!({"proofs": []})),
    }
}

struct FakePaymentSigner;

impl CashuSpilmanPaymentSigner for FakePaymentSigner {
    fn sign_cashu_spilman_payment(
        &self,
        channel_id: &str,
        balance: u64,
        include_funding: bool,
    ) -> std::result::Result<CashuSpilmanPayment, String> {
        Ok(CashuSpilmanPayment {
            channel_id: channel_id.to_string(),
            balance,
            signature: format!(
                "signed-{channel_id}-{}",
                if include_funding { "funding" } else { "update" }
            ),
            params: include_funding.then(|| json!({"channel": channel_id, "unit": "sat"})),
            funding_proofs: include_funding.then(|| json!({"proofs": []})),
        })
    }
}

struct FakeSpilmanReceiver {
    channel_id: String,
    balance: u64,
    validate_calls: std::cell::Cell<u32>,
    process_calls: std::cell::Cell<u32>,
}

impl FakeSpilmanReceiver {
    fn new(channel_id: &str, balance: u64) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            balance,
            validate_calls: std::cell::Cell::new(0),
            process_calls: std::cell::Cell::new(0),
        }
    }

    fn validation(&self) -> CashuSpilmanPaymentReceiverValidation {
        CashuSpilmanPaymentReceiverValidation {
            channel_id: self.channel_id.clone(),
            balance: self.balance,
            amount_due: 0,
            capacity: 10,
        }
    }
}

impl CashuSpilmanPaymentReceiver<()> for FakeSpilmanReceiver {
    fn validate_cashu_spilman_payment(
        &self,
        _payment: &CashuSpilmanPayment,
        _context: &(),
    ) -> std::result::Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.validate_calls.set(self.validate_calls.get() + 1);
        Ok(self.validation())
    }

    fn process_cashu_spilman_payment(
        &self,
        _payment: &CashuSpilmanPayment,
        _context: &(),
    ) -> std::result::Result<CashuSpilmanPaymentReceiverValidation, String> {
        self.process_calls.set(self.process_calls.get() + 1);
        Ok(self.validation())
    }
}
