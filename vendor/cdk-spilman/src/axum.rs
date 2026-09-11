//! Axum management router for Spilman channels.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use super::configurable_host::ConfigurableHost;
use super::{
    BridgeError, ChannelState, ClosePreparationError, SpilmanAsyncNetworking, SpilmanBridge,
    SpilmanHost,
};

/// Shared state required by the Spilman management routes.
pub struct SpilmanState<H: SpilmanHost<C>, N, C = String> {
    /// The payment bridge for processing payments and closes.
    pub bridge: Arc<SpilmanBridge<H, C>>,
    /// The host implementation for storage and pricing.
    pub host: Arc<H>,
    /// The networking implementation for mint communication.
    pub networking: Arc<N>,
}

impl<H: SpilmanHost<C>, N, C> std::fmt::Debug for SpilmanState<H, N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpilmanState").finish_non_exhaustive()
    }
}

impl<H: SpilmanHost<C>, N, C> Clone for SpilmanState<H, N, C> {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.clone(),
            host: self.host.clone(),
            networking: self.networking.clone(),
        }
    }
}

/// Create a router with the standard Spilman management endpoints for [`ConfigurableHost`].
///
/// Merging this into your application (usually via `.nest("/channel", ...)` if using a different state)
/// adds:
/// - `GET /params`
/// - `POST /register`
/// - `GET /{id}/status`
/// - `POST /{id}/close`
/// - `POST /{id}/unilateral-close`
///
/// Note: this router installs its own [`SpilmanState`] via `.with_state(...)`. When nesting into an
/// app that uses its own state, attach your app state after the `.nest()` call.
pub fn configurable_management_router<S, N>(
    state: SpilmanState<ConfigurableHost, N, String>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
{
    Router::new()
        .route("/params", get(get_configurable_params::<N>))
        .route(
            "/register",
            post(post_channel_register::<ConfigurableHost, N, String>),
        )
        .route("/{id}/status", get(get_configurable_status_handler::<N>))
        .route("/{id}/close", post(post_configurable_channel_close::<N>))
        .route(
            "/{id}/unilateral-close",
            post(post_configurable_unilateral_close::<N>),
        )
        .with_state(state)
}

async fn post_configurable_channel_close<N>(
    State(s): State<SpilmanState<ConfigurableHost, N, String>>,
    Path(channel_id): Path<String>,
    Json(body): Json<CloseRequest>,
) -> Response
where
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
{
    if let Some(closed_data) = s.host.get_closed_data(&channel_id) {
        if body.balance == closed_data.closed_amount {
            return Json(serde_json::json!({
                "success": true,
                "channel_id": channel_id,
                "total_value": closed_data.value_after_stage1,
                "receiver_sum": closed_data.receiver_sum,
                "sender_sum": closed_data.sender_sum,
                "sender_proofs": parse_sender_proofs(&closed_data.sender_proofs_json),
                "already_closed": true
            }))
            .into_response();
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "channel already closed with a different amount",
                    "closed_amount": closed_data.closed_amount,
                    "requested_amount": body.balance
                })),
            )
                .into_response();
        }
    }

    post_channel_close(State(s), Path(channel_id), Json(body)).await
}

async fn post_configurable_unilateral_close<N>(
    State(s): State<SpilmanState<ConfigurableHost, N, String>>,
    Path(channel_id): Path<String>,
) -> Response
where
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
{
    if let Some(closed_data) = s.host.get_closed_data(&channel_id) {
        return Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "earnedBeforeStage2Fees": closed_data.receiver_sum,
            "already_closed": true
        }))
        .into_response();
    }

    post_unilateral_close(State(s), Path(channel_id)).await
}

#[derive(Deserialize)]
struct CloseRequest {
    pub balance: u64,
    pub signature: String,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct RegisterRequest {
    pub channel_id: Option<String>,
    pub balance: Option<u64>,
    pub signature: Option<String>,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<serde_json::Value>,
}

async fn get_configurable_params<N>(
    State(s): State<SpilmanState<ConfigurableHost, N, String>>,
) -> Json<serde_json::Value>
where
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
{
    let active_pricing = s.host.get_active_pricing();
    let pricing_json: serde_json::Value = active_pricing
        .iter()
        .map(|(unit, cfg)| {
            let mut obj = serde_json::json!({
                "min_capacity": cfg.min_capacity,
                "variables": cfg.variables,
            });
            if let Some(max) = cfg.max_amount_per_output {
                obj["max_amount_per_output"] = serde_json::json!(max);
            }
            (unit.clone(), obj)
        })
        .collect();

    Json(serde_json::json!({
        "receiver_pubkey": s.host.server_pubkey().to_hex(),
        "pricing": pricing_json,
        "pricing_scale": s.host.pricing_scale(),
        "mints_units_keysets": s.host.get_mints_units_keysets(),
        "min_expiry_in_seconds": s.host.config().min_expiry_seconds,
    }))
}

async fn post_channel_register<H, N, C>(
    State(s): State<SpilmanState<H, N, C>>,
    Json(body): Json<RegisterRequest>,
) -> Response
where
    H: SpilmanHost<C> + Send + Sync + 'static,
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
    C: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    let channel_id =
        match body.channel_id {
            Some(id) => id,
            None => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing channel_id" })),
            )
                .into_response(),
        };
    let signature =
        match body.signature {
            Some(s) => s,
            None => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing signature" })),
            )
                .into_response(),
        };
    let params = match body.params {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing params" })),
            )
                .into_response()
        }
    };
    let funding_proofs = match body.funding_proofs {
        Some(p) => p,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Bad request", "reason": "missing funding_proofs" })),
        )
            .into_response(),
    };

    if body.balance.unwrap_or(0) != 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({ "success": false, "error": "Bad request", "reason": "funding requires balance=0", "status": 400 }),
            ),
        )
            .into_response();
    }

    let register_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": 0,
        "signature": signature,
        "params": params,
        "funding_proofs": funding_proofs,
    });

    match s.bridge.fund_channel_via_json(&register_body.to_string()) {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "channel_id": result.channel_id,
            "capacity": result.capacity,
            "already_known": result.already_known
        }))
        .into_response(),
        Err(e) => map_bridge_error(e).into_response(),
    }
}

async fn get_configurable_status_handler<N>(
    State(s): State<SpilmanState<ConfigurableHost, N, String>>,
    Path(channel_id): Path<String>,
) -> Response
where
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
{
    let funding = match s.host.get_funding_data(&channel_id) {
        Some(f) => f,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "unknown channel" })),
            )
                .into_response()
        }
    };

    let params: serde_json::Value = serde_json::from_str(&funding.params_json).unwrap_or_default();
    let capacity = params.get("capacity").and_then(|v| v.as_u64()).unwrap_or(0);

    let balance = s
        .host
        .get_balance(&channel_id)
        .map(|p| p.balance)
        .unwrap_or(0);
    let usage = s.host.get_usage(&channel_id).unwrap_or_default();
    let closed_data = s.host.get_closed_data(&channel_id);
    let amount_due = s.host.get_amount_due(&channel_id, None);

    Json(serde_json::json!({
        "channel_id": channel_id,
        "capacity": capacity,
        "balance": balance,
        "usage": usage,
        "amount_due": amount_due,
        "closed": closed_data.is_some(),
        "closed_amount": closed_data.as_ref().map(|c| c.closed_amount),
    }))
    .into_response()
}

async fn post_channel_close<H, N, C>(
    State(s): State<SpilmanState<H, N, C>>,
    Path(channel_id): Path<String>,
    Json(body): Json<CloseRequest>,
) -> Response
where
    H: SpilmanHost<C> + Send + Sync + 'static,
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
    C: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    // Specialized idempotency for ConfigurableHost
    // (We use a trick to see if H is actually ConfigurableHost)
    // Actually, we can just use the generic SpilmanHost methods.

    if s.host.get_channel_state(&channel_id) == ChannelState::Closed {
        // We can't get the full proofs generically, but let's try to return enough for success
        return (StatusCode::OK, Json(serde_json::json!({ "success": true, "already_closed": true, "channel_id": channel_id }))).into_response();
    }

    let mut close_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": body.balance,
        "signature": body.signature
    });
    if let Some(params) = &body.params {
        close_body["params"] = params.clone();
    }
    if let Some(funding_proofs) = &body.funding_proofs {
        close_body["funding_proofs"] = funding_proofs.clone();
    }

    match s
        .bridge
        .execute_cooperative_close_async(&close_body.to_string(), &*s.networking)
        .await
    {
        Ok(result) => {
            let sender_proofs = parse_sender_proofs(&result.sender_proofs);
            Json(serde_json::json!({
                "channel_id": result.channel_id,
                "total_value": result.total_value,
                "receiver_sum": result.receiver_sum,
                "sender_sum": result.sender_sum,
                "sender_proofs": sender_proofs,
                "already_closed": result.already_closed,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST),
            Json(e),
        )
            .into_response(),
    }
}

async fn post_unilateral_close<H, N, C>(
    State(s): State<SpilmanState<H, N, C>>,
    Path(channel_id): Path<String>,
) -> Response
where
    H: SpilmanHost<C> + Send + Sync + 'static,
    N: SpilmanAsyncNetworking + Send + Sync + 'static,
    C: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    if s.host.get_channel_state(&channel_id) == ChannelState::Closed {
        return Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "already_closed": true
        }))
        .into_response();
    }

    match s
        .bridge
        .execute_unilateral_close_async(&channel_id, &*s.networking)
        .await
    {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "earnedBeforeStage2Fees": result.receiver_sum,
            "already_closed": false
        }))
        .into_response(),
        Err(e) => (
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(e),
        )
            .into_response(),
    }
}

fn map_bridge_error(e: BridgeError) -> impl IntoResponse {
    let error_response = ClosePreparationError::from_bridge_error(e);
    let status = match error_response.status {
        402 => StatusCode::PAYMENT_REQUIRED,
        404 => StatusCode::NOT_FOUND,
        409 => StatusCode::CONFLICT,
        410 => StatusCode::GONE,
        500 => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(serde_json::json!({
            "success": false,
            "error": error_response.error,
            "reason": error_response.reason,
            "status": error_response.status
        })),
    )
}

fn parse_sender_proofs(raw: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(raw).unwrap_or(serde_json::json!([]))
}
