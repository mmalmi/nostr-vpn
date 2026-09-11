use std::time::SystemTime;

/// Retained through anyhow context and daemon wallet IPC, without parsing errors.
#[derive(Debug)]
pub struct MintRetryAfter(pub u64);

impl std::fmt::Display for MintRetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mint requested a retry delay of {} seconds", self.0)
    }
}

impl std::error::Error for MintRetryAfter {}

pub fn check_mint_response(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let message = format!("Cashu mint request failed with {}", response.status());
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
    match delay {
        Some(seconds) => Err(anyhow::Error::new(MintRetryAfter(seconds)).context(message)),
        None => Err(anyhow::anyhow!(message)),
    }
}
