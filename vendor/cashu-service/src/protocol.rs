use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// High-level service class offered by a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// Forward opaque traffic or datagrams between participants.
    Forwarding,
    /// Observe the caller's externally visible address.
    AddressObservation,
    /// Allocate relay/stateful resources on behalf of the caller.
    Allocation,
    /// Accept an initial connection into a larger network or mesh.
    Entry,
    /// Match peers or facilitate rendezvous/signaling.
    Rendezvous,
    /// Service kind unknown to this version of the crate.
    Custom(String),
}

/// Network or link layer a service is willing to speak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Udp,
    Tcp,
    Quic,
    Websocket,
    Tor,
    Ethernet,
    Bluetooth,
    Serial,
    Radio,
    Other(String),
}

/// Resource unit used for pricing, quoting, and lease grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterUnit {
    Flat,
    BytesIn,
    BytesOut,
    BytesTotal,
    Seconds,
    Sessions,
    Allocations,
    Packets,
    AirtimeMs,
    Other(String),
}

/// Concrete amount in one metered unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterAmount {
    pub unit: MeterUnit,
    pub quantity: u64,
}

/// A pricing rule such as "2 sat per 1 MiB" or "10 sat flat".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceRate {
    pub unit: MeterUnit,
    pub quantity: u64,
    pub price_sat: u64,
}

impl PriceRate {
    pub fn new(unit: MeterUnit, quantity: u64, price_sat: u64) -> Self {
        Self {
            unit,
            quantity: quantity.max(1),
            price_sat,
        }
    }
}

/// Publicly advertised pricing guidance used for peer selection.
///
/// This is intentionally non-authoritative. Operators may change real pricing
/// at quote time based on load, policy, or service availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndicativePricing {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rates: Vec<PriceRate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_total_price_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_ttl_secs: Option<u32>,
}

/// Resource limits and caps a service is willing to expose publicly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceLimits {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub max_per_lease: Vec<MeterAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_leases: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_secs: Option<u32>,
}

/// Public advertisement used in discovery channels such as Nostr or in-mesh
/// service directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAdvertisement {
    /// Stable identifier for this service offer within the operator's namespace.
    pub service_id: String,
    pub kind: ServiceKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<TransportKind>,
    /// Optional feature flags such as "relay", "nat_assist", "paid_only".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Public pricing hint for discovery and rough ranking. Real billing is
    /// determined by a subsequent quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicative_pricing: Option<IndicativePricing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<ServiceLimits>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_mints: Vec<String>,
    /// If true, clients must request a fresh quote before paying or using.
    #[serde(default)]
    pub quote_required: bool,
    /// Free-form metadata for operator hints that do not affect correctness.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl ServiceAdvertisement {
    pub fn should_request_quote(&self) -> bool {
        self.quote_required || self.indicative_pricing.is_some()
    }
}

/// Client request for a priced service lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub service_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested: Vec<MeterAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_mint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_total_price_sat: Option<u64>,
}

/// Authoritative operator response to a quote request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteResponse {
    pub service_id: String,
    pub quote_id: String,
    /// Unix timestamp after which the quote is invalid.
    pub expires_unix: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted: Vec<MeterAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pricing: Vec<PriceRate>,
    pub total_price_sat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint_url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Signed or otherwise authenticated lease token returned after payment.
///
/// The actual signature format is transport/application specific; this struct
/// only models the claims that should be encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseToken {
    pub service_id: String,
    pub quote_id: String,
    pub lease_id: String,
    pub issued_unix: u64,
    pub expires_unix: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted: Vec<MeterAmount>,
    pub amount_paid_sat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint_url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_advertisement_roundtrip_with_indicative_pricing() {
        let ad = ServiceAdvertisement {
            service_id: "relay-eu-1".to_string(),
            kind: ServiceKind::Forwarding,
            transports: vec![TransportKind::Udp, TransportKind::Quic],
            features: vec!["relay".to_string(), "paid_only".to_string()],
            indicative_pricing: Some(IndicativePricing {
                rates: vec![
                    PriceRate::new(MeterUnit::BytesTotal, 1_048_576, 3),
                    PriceRate::new(MeterUnit::Seconds, 60, 1),
                ],
                min_total_price_sat: Some(5),
                quote_ttl_secs: Some(30),
            }),
            limits: Some(ServiceLimits {
                max_per_lease: vec![
                    MeterAmount {
                        unit: MeterUnit::BytesTotal,
                        quantity: 16 * 1_048_576,
                    },
                    MeterAmount {
                        unit: MeterUnit::Seconds,
                        quantity: 3_600,
                    },
                ],
                max_concurrent_leases: Some(64),
                max_idle_secs: Some(120),
            }),
            accepted_mints: vec!["https://mint.example".to_string()],
            quote_required: true,
            metadata: BTreeMap::from([
                ("region".to_string(), "eu".to_string()),
                ("operator".to_string(), "nostr:npub1...".to_string()),
            ]),
        };

        let json = serde_json::to_string(&ad).unwrap();
        let decoded: ServiceAdvertisement = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ad);
        assert!(decoded.should_request_quote());
    }

    #[test]
    fn test_quote_and_lease_roundtrip() {
        let req = QuoteRequest {
            service_id: "relay-eu-1".to_string(),
            requested: vec![
                MeterAmount {
                    unit: MeterUnit::BytesTotal,
                    quantity: 2_097_152,
                },
                MeterAmount {
                    unit: MeterUnit::Seconds,
                    quantity: 600,
                },
            ],
            preferred_mint: Some("https://mint.example".to_string()),
            max_total_price_sat: Some(21),
        };

        let req_json = serde_json::to_string(&req).unwrap();
        let decoded_req: QuoteRequest = serde_json::from_str(&req_json).unwrap();
        assert_eq!(decoded_req, req);

        let quote = QuoteResponse {
            service_id: req.service_id.clone(),
            quote_id: "q-123".to_string(),
            expires_unix: 1_750_000_000,
            granted: req.requested.clone(),
            pricing: vec![PriceRate::new(MeterUnit::BytesTotal, 1_048_576, 3)],
            total_price_sat: 6,
            mint_url: Some("https://mint.example".to_string()),
            metadata: BTreeMap::from([("quote_class".to_string(), "spot".to_string())]),
        };

        let quote_json = serde_json::to_string(&quote).unwrap();
        let decoded_quote: QuoteResponse = serde_json::from_str(&quote_json).unwrap();
        assert_eq!(decoded_quote, quote);

        let lease = LeaseToken {
            service_id: quote.service_id.clone(),
            quote_id: quote.quote_id.clone(),
            lease_id: "lease-abc".to_string(),
            issued_unix: 1_749_999_900,
            expires_unix: 1_750_000_500,
            granted: quote.granted.clone(),
            amount_paid_sat: quote.total_price_sat,
            mint_url: quote.mint_url.clone(),
            metadata: BTreeMap::from([("session".to_string(), "relay-session-1".to_string())]),
        };

        let lease_json = serde_json::to_string(&lease).unwrap();
        let decoded_lease: LeaseToken = serde_json::from_str(&lease_json).unwrap();
        assert_eq!(decoded_lease, lease);
    }

    #[test]
    fn test_price_rate_normalizes_zero_quantity() {
        let rate = PriceRate::new(MeterUnit::Flat, 0, 7);
        assert_eq!(rate.quantity, 1);
        assert_eq!(rate.price_sat, 7);
    }
}
