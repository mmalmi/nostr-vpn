use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Result, anyhow, bail};
use nostr_vpn_core::config::FiatCurrency;
use serde::Deserialize;

use crate::native_state::NativePaidRouteWalletState;

pub const REFRESH_CADENCE: Duration = Duration::from_mins(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SOURCE_SPREAD: f64 = 0.05;
const COINBASE_URL: &str = "https://api.coinbase.com/v2/exchange-rates";
const KRAKEN_URL: &str = "https://api.kraken.com/0/public/Ticker";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeRateSource {
    Coinbase,
    Kraken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeRateStatus {
    Unavailable,
    Refreshing,
    Ready,
    Failed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExchangeRateSnapshot {
    pub currency: FiatCurrency,
    pub rate: Option<f64>,
    pub sources: Vec<ExchangeRateSource>,
    pub status: ExchangeRateStatus,
    pub timestamp: Option<SystemTime>,
    pub stale: bool,
}

#[derive(Clone)]
pub struct ExchangeRateService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ExchangeRateService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExchangeRateService")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

struct Inner {
    currency: FiatCurrency,
    client: reqwest::Client,
    state: Mutex<State>,
}

struct State {
    rate: Option<f64>,
    sources: Vec<ExchangeRateSource>,
    status: ExchangeRateStatus,
    timestamp: Option<SystemTime>,
    refreshed_at: Option<Instant>,
    next_refresh_at: Option<Instant>,
    refreshing: bool,
}

impl ExchangeRateService {
    #[must_use]
    pub fn for_currency(currency: FiatCurrency) -> Self {
        Self {
            inner: Arc::new(Inner {
                currency,
                client: reqwest::Client::new(),
                state: Mutex::new(State {
                    rate: None,
                    sources: Vec::new(),
                    status: ExchangeRateStatus::Unavailable,
                    timestamp: None,
                    refreshed_at: None,
                    next_refresh_at: None,
                    refreshing: false,
                }),
            }),
        }
    }

    #[must_use]
    pub fn refresh_if_due(&self) -> bool {
        let now = Instant::now();
        {
            let mut state = self.inner.state();
            if state.refreshing
                || state
                    .next_refresh_at
                    .is_some_and(|next_refresh| now < next_refresh)
            {
                return false;
            }
            state.refreshing = true;
            state.next_refresh_at = Some(now + REFRESH_CADENCE);
            state.status = ExchangeRateStatus::Refreshing;
        }
        let inner = Arc::clone(&self.inner);
        if std::thread::Builder::new()
            .name("nvpn-exchange-rate".to_string())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(inner.refresh()),
                    Err(_) => inner.note_refresh_failed(),
                }
            })
            .is_ok()
        {
            true
        } else {
            self.inner.note_refresh_failed();
            false
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> ExchangeRateSnapshot {
        let state = self.inner.state();
        let snapshot_is_stale = state.status == ExchangeRateStatus::Failed
            || state.refreshed_at.is_none_or(|refreshed_at| {
                Instant::now().saturating_duration_since(refreshed_at) >= REFRESH_CADENCE
            });
        ExchangeRateSnapshot {
            currency: self.inner.currency,
            rate: state.rate,
            sources: state.sources.clone(),
            status: state.status,
            timestamp: state.timestamp,
            stale: snapshot_is_stale,
        }
    }
}

pub(crate) fn apply_exchange_rate(
    wallet: &mut NativePaidRouteWalletState,
    snapshot: &ExchangeRateSnapshot,
) {
    wallet.fiat_currency = snapshot.currency.as_str().to_string();
    wallet.exchange_rate_status = match snapshot.status {
        ExchangeRateStatus::Refreshing | ExchangeRateStatus::Ready => "",
        ExchangeRateStatus::Failed if snapshot.rate.is_some() => "Using last rate",
        ExchangeRateStatus::Unavailable | ExchangeRateStatus::Failed => "Unavailable",
    }
    .to_string();
    wallet.exchange_rate_sources = snapshot
        .sources
        .iter()
        .map(|source| match source {
            ExchangeRateSource::Coinbase => "Coinbase",
            ExchangeRateSource::Kraken => "Kraken",
        })
        .collect::<Vec<_>>()
        .join(" + ");
    wallet.exchange_rate_stale = snapshot.stale;
    wallet.exchange_rate_updated_at_unix = snapshot
        .timestamp
        .and_then(|timestamp| timestamp.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs());

    let Some(rate) = snapshot.rate.filter(|rate| is_valid_rate(*rate)) else {
        return;
    };
    wallet.exchange_rate_text = format!("1 BTC = {rate:.2} {}", snapshot.currency.as_str());
    let amount = |msat| format_fiat_msat(msat, rate, snapshot.currency.as_str());
    if wallet.balance_known {
        wallet.fiat_balance_text = amount(wallet.total_balance_msat);
        wallet
            .total_balance_text
            .clone_from(&wallet.fiat_balance_text);
        if wallet.total_balance_msat > 0 {
            wallet
                .navigation_balance_text
                .clone_from(&wallet.fiat_balance_text);
        }
    }
    if wallet.channel_balance_msat > 0 {
        wallet.channel_balance_text =
            format!("{} in channels", amount(wallet.channel_balance_msat));
    }
    for mint in &mut wallet.mints {
        if mint.balance_known {
            mint.balance_text = amount(mint.balance_msat);
        }
    }
    let action = &mut wallet.last_action;
    if !action.amount_text.is_empty() {
        action.amount_text = amount(action.amount_sat.saturating_mul(1_000));
    }
    if action.fee_sat > 0 {
        action.fee_text = format!("{} fee", amount(action.fee_sat.saturating_mul(1_000)));
    }
}

pub(crate) fn format_fiat_msat(msat: u64, rate: f64, currency: &str) -> String {
    format_fiat(msat, rate, currency, false)
}

pub(crate) fn format_fiat_price_msat(msat: u64, rate: f64, currency: &str) -> String {
    format_fiat(msat, rate, currency, true)
}

#[allow(clippy::cast_precision_loss)]
fn format_fiat(msat: u64, rate: f64, currency: &str, price: bool) -> String {
    let value = msat as f64 / 100_000_000_000.0 * rate;
    let symbol = match currency {
        "USD" => "$",
        "EUR" => "€",
        "GBP" => "£",
        "JPY" => "¥",
        "CAD" => "CA$",
        "AUD" => "A$",
        _ => "CHF ",
    };
    if msat > 0 && value < 0.000_001 {
        return format!("<{symbol}0.000001");
    }
    let decimals = if value > 0.0 && value < if price { 1.0 } else { 0.01 } {
        6
    } else if currency == "JPY" {
        0
    } else {
        2
    };
    if decimals == 0 && value > 0.0 && value < 1.0 {
        return format!("<{symbol}1");
    }
    let mut value = format!("{value:.decimals$}");
    if decimals == 6 {
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') {
            value.pop();
        }
    }
    format!("≈ {symbol}{value}")
}

impl Inner {
    async fn refresh(self: Arc<Self>) {
        let result = fetch_rates(&self.client, self.currency).await;
        let mut state = self.state();
        state.refreshing = false;
        match result {
            Ok((rate, sources)) => {
                state.rate = Some(rate);
                state.sources = sources;
                state.status = ExchangeRateStatus::Ready;
                state.timestamp = Some(SystemTime::now());
                state.refreshed_at = Some(Instant::now());
            }
            Err(_) => state.status = ExchangeRateStatus::Failed,
        }
    }

    fn note_refresh_failed(&self) {
        let mut state = self.state();
        state.refreshing = false;
        state.status = ExchangeRateStatus::Failed;
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Deserialize)]
struct CoinbaseResponse {
    data: CoinbaseData,
}

#[derive(Deserialize)]
struct CoinbaseData {
    currency: String,
    rates: HashMap<String, String>,
}

#[derive(Deserialize)]
struct KrakenResponse {
    error: Vec<String>,
    #[serde(default)]
    result: HashMap<String, KrakenTicker>,
}

#[derive(Deserialize)]
struct KrakenTicker {
    #[serde(rename = "c")]
    last_trade: [String; 2],
}

async fn fetch_rates(
    client: &reqwest::Client,
    currency: FiatCurrency,
) -> Result<(f64, Vec<ExchangeRateSource>)> {
    let (coinbase, kraken) = tokio::join!(
        tokio::time::timeout(REQUEST_TIMEOUT, fetch_coinbase(client, currency)),
        tokio::time::timeout(REQUEST_TIMEOUT, fetch_kraken(client, currency)),
    );
    combine_rates(
        coinbase.ok().and_then(Result::ok),
        kraken.ok().and_then(Result::ok),
    )
}

async fn fetch_coinbase(client: &reqwest::Client, currency: FiatCurrency) -> Result<f64> {
    let payload = client
        .get(COINBASE_URL)
        .query(&[("currency", "BTC")])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse_coinbase(&payload, currency)
}

async fn fetch_kraken(client: &reqwest::Client, currency: FiatCurrency) -> Result<f64> {
    let pair = format!("XBT{}", currency.as_str());
    let payload = client
        .get(KRAKEN_URL)
        .query(&[("pair", pair)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse_kraken(&payload)
}

fn parse_coinbase(payload: &str, currency: FiatCurrency) -> Result<f64> {
    let response: CoinbaseResponse = serde_json::from_str(payload)?;
    if response.data.currency != "BTC" {
        bail!("unexpected Coinbase base currency");
    }
    let value = response
        .data
        .rates
        .get(currency.as_str())
        .ok_or_else(|| anyhow!("Coinbase rate is missing"))?;
    parse_rate(value)
}

fn parse_kraken(payload: &str) -> Result<f64> {
    let response: KrakenResponse = serde_json::from_str(payload)?;
    if !response.error.is_empty() {
        bail!("Kraken returned an API error");
    }
    if response.result.len() != 1 {
        bail!("Kraken returned an unexpected number of pairs");
    }
    let ticker = response
        .result
        .into_values()
        .next()
        .ok_or_else(|| anyhow!("Kraken rate is missing"))?;
    parse_rate(&ticker.last_trade[0])
}

fn combine_rates(
    coinbase: Option<f64>,
    kraken: Option<f64>,
) -> Result<(f64, Vec<ExchangeRateSource>)> {
    let mut rates = Vec::with_capacity(2);
    if let Some(rate) = coinbase.filter(|rate| is_valid_rate(*rate)) {
        rates.push((ExchangeRateSource::Coinbase, rate));
    }
    if let Some(rate) = kraken.filter(|rate| is_valid_rate(*rate)) {
        rates.push((ExchangeRateSource::Kraken, rate));
    }
    match rates.as_slice() {
        [] => bail!("no valid exchange-rate sources"),
        [(source, rate)] => Ok((*rate, vec![*source])),
        [(first_source, first), (second_source, second)] => {
            let (low, high) = if first <= second {
                (*first, *second)
            } else {
                (*second, *first)
            };
            if (high - low) / low > MAX_SOURCE_SPREAD {
                bail!("exchange-rate source spread exceeds limit");
            }
            let rate = first / 2.0 + second / 2.0;
            if !is_valid_rate(rate) {
                bail!("combined exchange rate is invalid");
            }
            Ok((rate, vec![*first_source, *second_source]))
        }
        _ => unreachable!("only two providers are configured"),
    }
}

fn parse_rate(value: &str) -> Result<f64> {
    let rate = value.parse::<f64>()?;
    if !is_valid_rate(rate) {
        bail!("exchange rate must be finite and positive");
    }
    Ok(rate)
}

fn is_valid_rate(rate: f64) -> bool {
    rate.is_finite() && rate > 0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_rate_eq(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn parses_supported_currency_case_insensitively() {
        assert_eq!("eur".parse(), Ok(FiatCurrency::Eur));
        assert!("NZD".parse::<FiatCurrency>().is_err());
    }

    #[test]
    fn parses_selected_coinbase_rate() {
        let payload = r#"{"data":{"currency":"BTC","rates":{"EUR":"58421.25","USD":"63000"}}}"#;
        assert_rate_eq(
            parse_coinbase(payload, FiatCurrency::Eur).unwrap(),
            58_421.25,
        );
    }

    #[test]
    fn rejects_invalid_coinbase_payloads() {
        let wrong_base = r#"{"data":{"currency":"ETH","rates":{"USD":"3000"}}}"#;
        let invalid_rate = r#"{"data":{"currency":"BTC","rates":{"USD":"NaN"}}}"#;
        assert!(parse_coinbase(wrong_base, FiatCurrency::Usd).is_err());
        assert!(parse_coinbase(invalid_rate, FiatCurrency::Usd).is_err());
    }

    #[test]
    fn parses_dynamic_kraken_pair_key() {
        let payload = r#"{"error":[],"result":{"XXBTZCAD":{"c":["86000.5","0.01"]}}}"#;
        assert_rate_eq(parse_kraken(payload).unwrap(), 86_000.5);
    }

    #[test]
    fn rejects_kraken_errors_and_ambiguous_results() {
        let api_error = r#"{"error":["EQuery:Unknown asset pair"],"result":{}}"#;
        let ambiguous = r#"{"error":[],"result":{"XBTUSD":{"c":["62000","1"]},"XXBTZUSD":{"c":["62001","1"]}}}"#;
        assert!(parse_kraken(api_error).is_err());
        assert!(parse_kraken(ambiguous).is_err());
    }

    #[test]
    fn averages_consistent_sources() {
        let (rate, sources) = combine_rates(Some(60_000.0), Some(61_000.0)).unwrap();
        assert_rate_eq(rate, 60_500.0);
        assert_eq!(
            sources,
            vec![ExchangeRateSource::Coinbase, ExchangeRateSource::Kraken]
        );
    }

    #[test]
    fn accepts_one_valid_source() {
        let (rate, sources) = combine_rates(Some(f64::INFINITY), Some(61_000.0)).unwrap();
        assert_rate_eq(rate, 61_000.0);
        assert_eq!(sources, vec![ExchangeRateSource::Kraken]);
    }

    #[test]
    fn rejects_excessive_spread_or_no_valid_source() {
        assert!(combine_rates(Some(60_000.0), Some(63_000.0)).is_ok());
        assert!(combine_rates(Some(60_000.0), Some(63_001.0)).is_err());
        assert!(combine_rates(Some(0.0), Some(f64::NAN)).is_err());
    }

    #[test]
    fn routine_exchange_rate_states_have_no_status_copy() {
        let mut wallet = NativePaidRouteWalletState::default();
        for status in [ExchangeRateStatus::Refreshing, ExchangeRateStatus::Ready] {
            apply_exchange_rate(
                &mut wallet,
                &ExchangeRateSnapshot {
                    currency: FiatCurrency::Usd,
                    rate: Some(63_000.0),
                    sources: vec![ExchangeRateSource::Coinbase],
                    status,
                    timestamp: None,
                    stale: false,
                },
            );
            assert_eq!(wallet.exchange_rate_status, "");
        }
    }

    #[test]
    fn wallet_fiat_display_preserves_fractional_sats_unknown_balances_and_accounting() {
        use crate::native_state::{
            NativePaidRouteWalletActionState, NativePaidRouteWalletMintState,
        };
        let mut wallet = NativePaidRouteWalletState {
            balance_known: true,
            total_balance_msat: 125_500,
            channel_balance_msat: 250_000,
            mints: vec![
                NativePaidRouteWalletMintState {
                    balance_known: true,
                    balance_msat: 125_500,
                    ..Default::default()
                },
                NativePaidRouteWalletMintState::default(),
            ],
            last_action: NativePaidRouteWalletActionState {
                amount_sat: 125,
                amount_text: "125 sat".into(),
                fee_sat: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let snapshot = ExchangeRateSnapshot {
            currency: FiatCurrency::Eur,
            rate: Some(80_000.0),
            sources: vec![],
            status: ExchangeRateStatus::Failed,
            timestamp: None,
            stale: true,
        };
        apply_exchange_rate(&mut wallet, &snapshot);
        assert_eq!(wallet.total_balance_text, "≈ €0.10");
        assert_eq!(wallet.navigation_balance_text, "≈ €0.10");
        assert_eq!(wallet.channel_balance_text, "≈ €0.20 in channels");
        assert_eq!(wallet.mints[0].balance_text, "≈ €0.10");
        assert_eq!(wallet.mints[1].balance_text, "");
        assert_eq!(wallet.last_action.amount_text, "≈ €0.10");
        assert_eq!(wallet.last_action.fee_text, "≈ €0.0008 fee");
        assert_eq!(wallet.exchange_rate_status, "Using last rate");
        assert_eq!(wallet.total_balance_msat, 125_500);
        assert_eq!(wallet.last_action.amount_sat, 125);
        assert_eq!(wallet.last_action.fee_sat, 1);
    }
}
