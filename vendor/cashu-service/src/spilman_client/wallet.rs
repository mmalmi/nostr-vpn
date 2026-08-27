#[cfg(feature = "spilman-wallet-http")]
#[derive(Debug, Clone)]
pub struct HttpSpilmanClientNetworking {
    client: reqwest::Client,
}
#[cfg(feature = "spilman-wallet-http")]
impl Default for HttpSpilmanClientNetworking {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "spilman-wallet-http")]
impl HttpSpilmanClientNetworking {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "spilman-wallet-http")]
#[async_trait::async_trait]
impl cdk_spilman::SpilmanClientAsyncNetworking for HttpSpilmanClientNetworking {
    async fn call_mint_swap(
        &self,
        mint_url: &str,
        swap_request_json: &str,
    ) -> Result<String, String> {
        let url = format!("{}/v1/swap", mint_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(swap_request_json.to_string())
            .send()
            .await
            .map_err(|error| format!("Cashu mint swap request failed: {error}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("failed to read Cashu mint swap response: {error}"))?;
        if !status.is_success() {
            return Err(format!("Cashu mint swap failed with {status}: {body}"));
        }
        Ok(body)
    }
}

#[cfg(feature = "spilman-wallet-http")]
pub async fn fetch_spilman_keyset_ids(mint_url: &str, unit: &str) -> Result<Vec<String>, String> {
    let mint_url = mint_url.trim_end_matches('/');
    let response: serde_json::Value = reqwest::Client::new()
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keysets: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keysets: {error}"))?;
    let unit = unit.trim().to_ascii_lowercase();
    let mut ids = response
        .get("keysets")
        .and_then(|value| value.as_array())
        .ok_or("Cashu mint keysets response is missing keysets")?
        .iter()
        .filter(|entry| {
            entry
                .get("unit")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(&unit))
        })
        .filter_map(|entry| entry.get("id").and_then(|value| value.as_str()))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

#[cfg(feature = "spilman-wallet-http")]
pub async fn fetch_spilman_keyset_info_json(
    mint_url: &str,
    unit: &str,
    keyset_id: Option<&str>,
) -> Result<String, String> {
    let mint_url = mint_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let keysets_url = format!("{mint_url}/v1/keysets");
    let keysets_response: serde_json::Value = client
        .get(keysets_url)
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keysets: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keysets: {error}"))?;
    let keysets = keysets_response
        .get("keysets")
        .and_then(|value| value.as_array())
        .ok_or("Cashu mint keysets response is missing keysets")?;
    let unit = unit.trim().to_ascii_lowercase();
    let selected = select_spilman_keyset(keysets, &unit, keyset_id).ok_or_else(|| {
        keyset_id.map_or_else(
            || format!("Cashu mint has no active {unit} keyset"),
            |id| format!("Cashu mint has no {unit} keyset {id}"),
        )
    })?;
    let selected_id = selected
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or("selected Cashu mint keyset is missing id")?;
    let input_fee_ppk = selected
        .get("input_fee_ppk")
        .and_then(|value| value.as_u64())
        .unwrap_or_default();
    let final_expiry = selected
        .get("final_expiry")
        .and_then(|value| value.as_u64());
    let keys_url = format!("{mint_url}/v1/keys/{selected_id}");
    let keys_response: serde_json::Value = client
        .get(keys_url)
        .send()
        .await
        .map_err(|error| format!("failed to fetch Cashu mint keys: {error}"))?
        .json()
        .await
        .map_err(|error| format!("failed to decode Cashu mint keys: {error}"))?;
    let keys = keys_response
        .get("keysets")
        .and_then(|value| value.as_array())
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("keys"))
        .cloned()
        .ok_or("Cashu mint keys response is missing keys")?;
    let mut keyset_info = serde_json::json!({
        "keysetId": selected_id,
        "unit": unit,
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
    });
    if let Some(final_expiry) = final_expiry {
        keyset_info["finalExpiry"] = serde_json::json!(final_expiry);
    }
    Ok(keyset_info.to_string())
}

#[cfg(feature = "spilman-wallet-http")]
fn select_spilman_keyset<'a>(
    keysets: &'a [serde_json::Value],
    unit: &str,
    keyset_id: Option<&str>,
) -> Option<&'a serde_json::Value> {
    keysets
        .iter()
        .filter(|entry| {
            let entry_id = entry.get("id").and_then(|value| value.as_str());
            let entry_unit = entry
                .get("unit")
                .and_then(|value| value.as_str())
                .map(|value| value.to_ascii_lowercase());
            let active = entry
                .get("active")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            entry_unit.as_deref() == Some(unit)
                && keyset_id.map_or(active, |expected| entry_id == Some(expected))
        })
        .min_by_key(|entry| {
            entry
                .get("input_fee_ppk")
                .and_then(|value| value.as_u64())
                .unwrap_or_default()
        })
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
    pub mint_url: String,
    pub receiver_pubkey_hex: String,
    pub capacity_sat: u64,
    pub expiry_unix: u64,
    #[serde(default)]
    pub max_amount_per_output: u64,
    #[serde(default = "default_streaming_route_cashu_unit")]
    pub unit: String,
    #[serde(default)]
    pub opening_paid_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset_info_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_created_at_unix: Option<u64>,
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingRouteOpenCashuSpilmanChannelFromWalletResult {
    pub channel: StreamingRouteOpenCashuSpilmanChannelResult,
    pub wallet_send: crate::CashuSentPayment,
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
fn wallet_open_recovery_request(
    request: &StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    unit: StreamingRouteCashuUnit,
) -> StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
    StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
        token: String::new(),
        receiver_pubkey_hex: request.receiver_pubkey_hex.clone(),
        sender_secret_hex: None,
        expiry_unix: request.expiry_unix,
        keyset_info_json: String::new(),
        max_amount_per_output: request.max_amount_per_output,
        unit: unit.as_str().to_string(),
        opening_paid_msat: request.opening_paid_msat,
        client_request_id: request.client_request_id.clone(),
        route_created_at_unix: request.route_created_at_unix,
        route_mint_url: Some(request.mint_url.clone()),
        route_capacity_sat: Some(request.capacity_sat),
    }
}

/// Recover a channel already committed for this wallet request without
/// contacting the mint or spending another token.
#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
pub fn recover_streaming_route_cashu_spilman_channel_from_wallet_request(
    data_dir: &Path,
    request: &StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
) -> anyhow::Result<Option<StreamingRouteOpenCashuSpilmanChannelResult>> {
    if request.capacity_sat == 0 {
        anyhow::bail!("Cashu Spilman channel capacity must be greater than zero");
    }
    let unit =
        StreamingRouteCashuUnit::parse(&request.unit).map_err(|error| anyhow::anyhow!(error))?;
    if unit != StreamingRouteCashuUnit::Sat {
        anyhow::bail!("wallet-backed Cashu Spilman channel recovery supports sat only");
    }
    let lock = SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(data_dir))
        .map_err(|error| anyhow::anyhow!(error))?;
    let (mut storage, _) =
        FileSpilmanClientStorage::load_with_lock(lock).map_err(|error| anyhow::anyhow!(error))?;
    recover_opened_channel_from_storage(&mut storage, &wallet_open_recovery_request(request, unit))
        .map_err(|error| anyhow::anyhow!(error))
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
pub async fn open_streaming_route_cashu_spilman_channel_from_wallet(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
    let lock = SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(data_dir))
        .map_err(|error| anyhow::anyhow!(error))?;
    open_streaming_route_cashu_spilman_channel_from_wallet_with_lock(data_dir, request, lock).await
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
pub async fn open_streaming_route_cashu_spilman_channel_from_wallet_with_lock(
    data_dir: &Path,
    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    lock: SharedSpilmanClientStoreLock,
) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
    let lock = require_lock_for_data_dir(data_dir, lock).map_err(|error| anyhow::anyhow!(error))?;
    crate::wallet::CashuWalletService::open_file_backed(data_dir)
        .await?
        .open_streaming_route_cashu_spilman_channel_with_lock(request, lock)
        .await
}

#[cfg(all(feature = "wallet", feature = "spilman-wallet-http"))]
impl crate::wallet::CashuWalletService {
    pub async fn open_streaming_route_cashu_spilman_channel(
        &self,
        request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    ) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        let lock =
            SharedSpilmanClientStoreLock::acquire(spilman_client_store_path(self.data_dir()))
                .map_err(|error| anyhow::anyhow!(error))?;
        self.open_streaming_route_cashu_spilman_channel_with_lock(request, lock)
            .await
    }

    pub async fn open_streaming_route_cashu_spilman_channel_with_lock(
        &self,
        request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
        lock: SharedSpilmanClientStoreLock,
    ) -> anyhow::Result<StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        let lock = require_lock_for_data_dir(self.data_dir(), lock)
            .map_err(|error| anyhow::anyhow!(error))?;
        if request.capacity_sat == 0 {
            anyhow::bail!("Cashu Spilman channel capacity must be greater than zero");
        }
        let unit = StreamingRouteCashuUnit::parse(&request.unit)
            .map_err(|error| anyhow::anyhow!(error))?;
        if unit != StreamingRouteCashuUnit::Sat {
            anyhow::bail!(
                "wallet-backed Cashu Spilman channel opening currently supports sat only"
            );
        }
        let (mut storage, storage_errors) = FileSpilmanClientStorage::load_with_lock(lock)
            .map_err(|error| anyhow::anyhow!(error))?;
        let token_request = wallet_open_recovery_request(&request, unit);
        if let Some(channel) = recover_opened_channel_from_storage(&mut storage, &token_request)
            .map_err(|error| anyhow::anyhow!(error))?
        {
            return Ok(StreamingRouteOpenCashuSpilmanChannelFromWalletResult {
                wallet_send: crate::CashuSentPayment {
                    mint_url: channel.mint_url.clone(),
                    unit: channel.unit.clone(),
                    amount_sat: channel.funding_token_amount,
                    send_fee_sat: 0,
                    operation_id: format!("recovered-spilman-channel:{}", channel.channel_id),
                    token: String::new(),
                },
                channel,
            });
        }
        storage
            .begin_open_request(request.client_request_id.as_deref())
            .map_err(|error| anyhow::anyhow!(error))?;
        let keyset_info_json = match request.keyset_info_json {
            Some(json) => json,
            None => fetch_spilman_keyset_info_json(
                &request.mint_url,
                unit.as_str(),
                request.keyset_id.as_deref(),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))?,
        };
        let funding_token_amount = cdk_spilman::compute_funding_token_amount(
            request.capacity_sat,
            &keyset_info_json,
            request.max_amount_per_output,
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        let funding_keyset_id = cdk_spilman::parse_keyset_info_from_json(&keyset_info_json)
            .map_err(|error| anyhow::anyhow!(error))?
            .keyset_id;
        let wallet_send = self
            .send_payment_token_for_keyset(
                &request.mint_url,
                funding_token_amount,
                funding_keyset_id,
            )
            .await?;
        let networking = HttpSpilmanClientNetworking::new();
        let channel =
            open_streaming_route_cashu_spilman_channel_from_token_with_networking_and_storage(
                self.data_dir(),
                StreamingRouteOpenCashuSpilmanChannelFromTokenRequest {
                    token: wallet_send.token.clone(),
                    receiver_pubkey_hex: request.receiver_pubkey_hex,
                    sender_secret_hex: None,
                    expiry_unix: request.expiry_unix,
                    keyset_info_json,
                    max_amount_per_output: request.max_amount_per_output,
                    unit: unit.as_str().to_string(),
                    opening_paid_msat: request.opening_paid_msat,
                    route_mint_url: Some(request.mint_url.clone()),
                    route_capacity_sat: Some(request.capacity_sat),
                    client_request_id: request.client_request_id,
                    route_created_at_unix: request.route_created_at_unix,
                },
                &networking,
                storage,
                storage_errors,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(StreamingRouteOpenCashuSpilmanChannelFromWalletResult {
            channel,
            wallet_send,
        })
    }
}

#[cfg(feature = "spilman-wallet")]
#[derive(Debug, Clone, Copy)]
struct NoopSpilmanClientNetworking;

#[cfg(feature = "spilman-wallet")]
impl cdk_spilman::SpilmanClientNetworking for NoopSpilmanClientNetworking {
    fn call_mint_swap(&self, _mint_url: &str, _swap_request_json: &str) -> Result<String, String> {
        Err("synchronous Cashu Spilman client networking is not configured".to_string())
    }
}

#[cfg(feature = "spilman-wallet")]
fn default_streaming_route_cashu_unit() -> String {
    StreamingRouteCashuUnit::Sat.as_str().to_string()
}
