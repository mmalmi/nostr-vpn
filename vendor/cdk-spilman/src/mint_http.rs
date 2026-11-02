//! Shared pacing and rejection cooldowns for direct Cashu mint HTTP requests.

use std::time::SystemTime;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Default)]
struct MintRequests {
    next_request: Option<Instant>,
    retry_wait: Option<(Instant, Duration)>,
    failures: u32,
}

/// All direct Spilman HTTP paths share one paced connection slot per origin.
/// This survives creating new clients and spans buyer, refund and seller work.
/// CDK wallet requests have their own, persisted repository rate limiter.
///
/// # Panics
/// Panics if another thread poisoned the shared mint request map.
pub async fn send_mint_request(
    builder: reqwest::RequestBuilder,
) -> anyhow::Result<reqwest::Response> {
    static MINTS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<MintRequests>>>>> =
        OnceLock::new();
    let (client, request) = builder.timeout(Duration::from_secs(10)).build_split();
    let request = request?;
    let origin = request.url().origin().ascii_serialization();
    let state = MINTS
        .get_or_init(Mutex::default)
        .lock()
        .expect("mint request map poisoned")
        .entry(origin)
        .or_default()
        .clone();
    let mut state = state.lock().await;
    if let Some((started, delay)) = state.retry_wait {
        let remaining = delay.saturating_sub(started.elapsed());
        if !remaining.is_zero() {
            return Err(MintRetryAfter(
                remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() > 0)),
            )
            .into());
        }
    }
    if let Some(next) = state.next_request {
        tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    }
    state.next_request = Some(Instant::now() + Duration::from_secs(2));
    // Reserve a failure cooldown before I/O: cancellation must not immediately
    // permit another channel to repeat an ambiguous request.
    state.retry_wait = Some((Instant::now(), Duration::from_secs(60)));
    let response = client.execute(request).await;
    let retry = match &response {
        Ok(response) => {
            response.status().is_server_error()
                || matches!(response.status().as_u16(), 403 | 429)
                || response
                    .headers()
                    .contains_key(reqwest::header::RETRY_AFTER)
                    && !response.status().is_success()
        }
        Err(_) => true,
    };
    if retry {
        state.failures = state.failures.saturating_add(1);
        let backoff = (60_u64 << state.failures.saturating_sub(1).min(6)).min(3600);
        let delay = response
            .as_ref()
            .ok()
            .and_then(retry_after)
            .unwrap_or(0)
            .max(backoff);
        state.retry_wait = Some((Instant::now(), Duration::from_secs(delay)));
    } else {
        state.failures = 0;
        state.retry_wait = None;
    }
    response.map_err(Into::into)
}

/// Retained through anyhow context and daemon wallet IPC, without parsing errors.
#[derive(Debug)]
pub struct MintRetryAfter(pub u64);

impl std::fmt::Display for MintRetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mint requests are deferred for {} seconds", self.0)
    }
}

impl std::error::Error for MintRetryAfter {}

/// The mint answered but rejected this particular request.
#[derive(Debug)]
pub struct MintRequestRejected(pub u16);

impl std::fmt::Display for MintRequestRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cashu mint rejected the request (HTTP {})", self.0)
    }
}

impl std::error::Error for MintRequestRejected {}

/// Reject unsuccessful mint responses while retaining the server retry delay.
pub fn check_mint_response(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let message = format!("Cashu mint request failed with {}", response.status());
    match retry_after(&response) {
        Some(seconds) => Err(anyhow::Error::new(MintRetryAfter(seconds)).context(message)),
        None if matches!(response.status().as_u16(), 400 | 422) => {
            Err(MintRequestRejected(response.status().as_u16()).into())
        }
        None => Err(anyhow::anyhow!(message)),
    }
}

fn retry_after(response: &reqwest::Response) -> Option<u64> {
    let delay = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let value = value.trim();
            value.parse::<u64>().ok().or_else(|| {
                let date = httpdate::parse_http_date(value).ok()?;
                // Round up so an HTTP-date never permits an early retry.
                let duration = date.duration_since(SystemTime::now()).unwrap_or_default();
                Some(
                    duration
                        .as_secs()
                        .saturating_add(u64::from(duration.subsec_nanos() > 0)),
                )
            })
        });
    if matches!(response.status().as_u16(), 403 | 429) {
        Some(delay.unwrap_or(0).max(15 * 60))
    } else {
        delay
    }
}
