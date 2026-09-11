//! Async networking for [`ConfigurableHost`] using `reqwest`.
//!
//! Provides a ready-made [`SpilmanAsyncNetworking`] implementation and keyset
//! fetching helpers so that Rust service providers don't need to write any
//! mint-communication boilerplate.
//!
//! Gated behind the `configurable-host-reqwest` feature.

use async_trait::async_trait;
use std::sync::Arc;

use crate::configurable_host::{ConfigurableHost, KeysetCacheEntry};
use crate::SpilmanAsyncNetworking;
use cashu::nuts::{CurrencyUnit, Id};

/// Keyset with full key data, as fetched from a mint.
#[derive(Debug, Clone)]
pub struct MintKeysetWithKeys {
    /// Mint-assigned keyset identifier.
    pub id: Id,
    /// Currency unit supported by this keyset.
    pub unit: CurrencyUnit,
    /// Whether the mint reports this keyset as active.
    pub active: bool,
    /// Input fee rate in parts per thousand.
    pub input_fee_ppk: u64,
    /// Raw key map payload returned by the mint.
    pub keys: serde_json::Value,
}

#[derive(Debug, Clone)]
struct ListedMintKeyset {
    id: Id,
    unit: CurrencyUnit,
    active: bool,
    input_fee_ppk: u64,
}

fn parse_listed_keysets(response: &serde_json::Value) -> Result<Vec<ListedMintKeyset>, String> {
    let keysets = response
        .get("keysets")
        .and_then(|keysets| keysets.as_array())
        .ok_or("Invalid keysets response")?;

    let mut result = Vec::new();
    for keyset in keysets {
        let Some(id_text) = keyset.get("id").and_then(|value| value.as_str()) else {
            tracing::warn!("Ignoring mint keyset without an id");
            continue;
        };
        let id = match id_text.parse::<Id>() {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(id = id_text, %error, "Ignoring mint keyset with an invalid id");
                continue;
            }
        };
        let Some(unit_text) = keyset.get("unit").and_then(|value| value.as_str()) else {
            tracing::warn!(id = id_text, "Ignoring mint keyset without a unit");
            continue;
        };
        let unit = match unit_text.parse::<CurrencyUnit>() {
            Ok(unit) => unit,
            Err(error) => {
                tracing::warn!(id = id_text, unit = unit_text, %error, "Ignoring mint keyset with an invalid unit");
                continue;
            }
        };

        result.push(ListedMintKeyset {
            id,
            unit,
            active: keyset
                .get("active")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            input_fee_ppk: keyset
                .get("input_fee_ppk")
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
        });
    }

    if result.is_empty() {
        return Err("Mint returned no valid keysets".to_owned());
    }

    Ok(result)
}

/// Fetch all keysets (with full keys) from a mint.
///
/// Calls `GET /v1/keysets` to list keysets, then `GET /v1/keys/{id}` for each
/// one to retrieve the full key material.
pub async fn fetch_all_keysets_from_mint(
    mint_url: &str,
) -> Result<Vec<MintKeysetWithKeys>, String> {
    let client = reqwest::Client::new();

    let keysets_url = format!("{mint_url}/v1/keysets");
    let keysets_resp: serde_json::Value = client
        .get(&keysets_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch keysets: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse keysets response: {e}"))?;

    let keysets = parse_listed_keysets(&keysets_resp)?;

    let mut result = Vec::new();
    for keyset in keysets {
        let keys_url = format!("{mint_url}/v1/keys/{}", keyset.id);
        let keys_resp: serde_json::Value = client
            .get(&keys_url)
            .send()
            .await
            .map_err(|error| format!("Failed to fetch keys for {}: {error}", keyset.id))?
            .json()
            .await
            .map_err(|error| format!("Failed to parse keys response for {}: {error}", keyset.id))?;

        let keys = keys_resp
            .get("keysets")
            .and_then(|k| k.as_array())
            .and_then(|arr| arr.first())
            .and_then(|k| k.get("keys"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        result.push(MintKeysetWithKeys {
            id: keyset.id,
            unit: keyset.unit,
            active: keyset.active,
            input_fee_ppk: keyset.input_fee_ppk,
            keys,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::parse_listed_keysets;

    #[test]
    fn malformed_advertised_keysets_do_not_hide_a_valid_active_keyset() {
        let response = serde_json::json!({
            "keysets": [
                {
                    "id": "ctv28hTYzQwr",
                    "unit": "sat",
                    "active": false,
                    "input_fee_ppk": 0
                },
                {
                    "id": "00107937db0cc865",
                    "unit": "sat",
                    "active": true,
                    "input_fee_ppk": 0
                }
            ]
        });

        let keysets = parse_listed_keysets(&response).expect("valid keyset remains usable");

        assert_eq!(keysets.len(), 1);
        assert_eq!(keysets[0].id.to_string(), "00107937db0cc865");
        assert!(keysets[0].active);
    }

    #[test]
    fn an_entirely_malformed_keyset_list_is_rejected() {
        let response = serde_json::json!({
            "keysets": [{
                "id": "ctv28hTYzQwr",
                "unit": "sat",
                "active": false
            }]
        });

        let error = parse_listed_keysets(&response).expect_err("no usable keyset remains");

        assert_eq!(error, "Mint returned no valid keysets");
    }
}

/// Build the keyset info JSON blob expected by the bridge.
///
/// This produces the format consumed by [`parse_keyset_info_from_json`](crate::parse_keyset_info_from_json).
pub fn build_keyset_info_json(
    keyset_id: &Id,
    unit: &CurrencyUnit,
    keys: &serde_json::Value,
    input_fee_ppk: u64,
) -> String {
    serde_json::json!({
        "keysetId": keyset_id.to_string(),
        "unit": unit.to_string(),
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    })
    .to_string()
}

/// Fetch keysets from a mint and populate the host's keyset cache.
pub async fn fetch_and_cache_keysets(
    host: &ConfigurableHost,
    mint_url: &str,
) -> Result<(), String> {
    let keysets = fetch_all_keysets_from_mint(mint_url).await?;
    for ks in keysets {
        let info_json = build_keyset_info_json(&ks.id, &ks.unit, &ks.keys, ks.input_fee_ppk);
        host.set_keyset(
            mint_url,
            ks.id,
            KeysetCacheEntry {
                info_json,
                active: ks.active,
                unit: ks.unit,
            },
        )?;
    }
    Ok(())
}

/// Ready-made [`SpilmanAsyncNetworking`] implementation using `reqwest`.
///
/// Wraps a shared [`ConfigurableHost`] and provides:
/// - `call_mint_swap` — POST to `/v1/swap`
/// - `refresh_all_keysets` — re-fetches and caches all keysets
///
/// # Example
///
/// ```ignore
/// let host = Arc::new(ConfigurableHost::from_yaml(&yaml, &key)?);
/// host.initialize_keysets().await?;
/// let networking = Arc::new(ReqwestNetworking::new(host.clone()));
/// ```
#[derive(Debug)]
pub struct ReqwestNetworking {
    host: Arc<ConfigurableHost>,
}

impl ReqwestNetworking {
    /// Create a new `ReqwestNetworking` wrapping the given host.
    pub fn new(host: Arc<ConfigurableHost>) -> Self {
        Self { host }
    }
}

#[async_trait]
impl SpilmanAsyncNetworking for ReqwestNetworking {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let client = reqwest::Client::new();
        let url = format!("{mint_url}/v1/swap");

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|e| format!("Swap request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Try to parse the body as a NUT-00 error: {"detail": "...", "code": ...}
            // Mints may also include an "error" field (e.g. nutmix).
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                let code = parsed.get("code").and_then(|v| v.as_u64());
                let detail = parsed
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                tracing::warn!(
                    %status,
                    nut00_code = ?code,
                    detail,
                    "Mint rejected swap (NUT-00 error)"
                );
                // Return the raw JSON body so callers can deserialize it.
                return Err(body);
            }

            return Err(format!("Swap failed: {status} - {body}"));
        }

        resp.text()
            .await
            .map_err(|e| format!("Failed to read swap response: {e}"))
    }

    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String> {
        tracing::info!("Refreshing keysets from {mint}...");
        fetch_and_cache_keysets(&self.host, mint).await?;
        tracing::info!("Keyset refresh complete for {mint}");
        Ok(())
    }
}
