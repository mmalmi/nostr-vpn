use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::paid_routes::PaidRouteQualityMetrics;

pub const DEFAULT_PAID_ROUTE_PUBLIC_IP_URL: &str = "https://api.ipify.org?format=json";
pub const DEFAULT_PAID_ROUTE_GEOIP_URL_TEMPLATE: &str = "https://ipapi.co/{ip}/json";
pub const DEFAULT_PAID_ROUTE_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";
pub const DEFAULT_PAID_ROUTE_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";
pub const DEFAULT_PAID_ROUTE_BANDWIDTH_BYTES: u64 = 256 * 1024;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteProbeSample {
    pub realized_exit_ip: Option<String>,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

impl PaidRouteProbeSample {
    #[must_use]
    pub fn success(realized_exit_ip: String, latency_ms: u32) -> Self {
        Self {
            realized_exit_ip: Some(realized_exit_ip),
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            realized_exit_ip: None,
            latency_ms: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidRouteProbeMeasurement {
    pub realized_exit_ip: Option<String>,
    pub observed_country_code: Option<String>,
    pub observed_asn: Option<u32>,
    pub quality: PaidRouteQualityMetrics,
    pub samples: Vec<PaidRouteProbeSample>,
}

impl PaidRouteProbeMeasurement {
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.samples
            .iter()
            .filter(|sample| sample.realized_exit_ip.is_some())
            .count()
    }

    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.samples.len().saturating_sub(self.success_count())
    }
}

#[must_use]
pub fn paid_route_geoip_url(template: &str, ip: &str) -> String {
    if template.contains("{ip}") {
        template.replace("{ip}", ip)
    } else {
        format!("{}/{}", template.trim_end_matches('/'), ip)
    }
}

#[must_use]
pub fn paid_route_download_url(base: &str, bytes: u64) -> String {
    let bytes = bytes.max(1);
    if base.contains("{bytes}") {
        return base.replace("{bytes}", &bytes.to_string());
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}bytes={bytes}")
}

#[must_use]
pub fn paid_route_bandwidth_bps(bytes: u64, duration: Duration) -> Option<u64> {
    let nanos = duration.as_nanos();
    if bytes == 0 || nanos == 0 {
        return None;
    }
    let bits = u128::from(bytes).saturating_mul(8);
    let bps = bits.saturating_mul(1_000_000_000) / nanos;
    u64::try_from(bps).ok()
}

pub fn paid_route_stun_host_port(server: &str) -> Option<(String, u16)> {
    let server = server.trim();
    if server.is_empty() {
        return None;
    }

    let authority = server
        .strip_prefix("stun://")
        .or_else(|| server.strip_prefix("stun:"))
        .unwrap_or(server)
        .split('/')
        .next()
        .unwrap_or_default()
        .trim();
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or(3478);
        return Some((host.to_string(), port));
    }

    if let Some((host, raw_port)) = authority.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = raw_port.parse::<u16>()
    {
        return Some((host.to_string(), port));
    }

    Some((authority.to_string(), 3478))
}

pub fn paid_route_stun_transaction_id() -> [u8; 12] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = u128::from(std::process::id());
    let bytes = (nanos ^ (pid << 64) ^ pid).to_be_bytes();
    let mut transaction_id = [0_u8; 12];
    transaction_id.copy_from_slice(&bytes[4..16]);
    transaction_id
}

pub fn paid_route_stun_binding_request(transaction_id: [u8; 12]) -> [u8; 20] {
    let mut request = [0_u8; 20];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

pub fn parse_paid_route_stun_binding_response(
    response: &[u8],
    transaction_id: [u8; 12],
) -> Result<String> {
    if response.len() < 20 {
        return Err(anyhow!("paid exit STUN response was too short"));
    }
    let message_type = u16::from_be_bytes([response[0], response[1]]);
    if message_type != STUN_BINDING_SUCCESS_RESPONSE {
        return Err(anyhow!(
            "paid exit STUN response had unexpected type 0x{message_type:04x}"
        ));
    }
    let message_len = usize::from(u16::from_be_bytes([response[2], response[3]]));
    if response.len() < 20 + message_len {
        return Err(anyhow!("paid exit STUN response length was truncated"));
    }
    let cookie = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(anyhow!(
            "paid exit STUN response had an invalid magic cookie"
        ));
    }
    if response[8..20] != transaction_id {
        return Err(anyhow!(
            "paid exit STUN response transaction id did not match"
        ));
    }

    let mut offset = 20_usize;
    let end = 20 + message_len;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([
            response[offset + 2],
            response[offset + 3],
        ]));
        offset += 4;
        let attr_end = offset.saturating_add(attr_len);
        if attr_end > end {
            return Err(anyhow!("paid exit STUN attribute length was truncated"));
        }
        let attr = &response[offset..attr_end];
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            return parse_paid_route_stun_mapped_address(attr, true, &transaction_id);
        }
        if attr_type == STUN_ATTR_MAPPED_ADDRESS {
            return parse_paid_route_stun_mapped_address(attr, false, &transaction_id);
        }
        offset = attr_end + ((4 - (attr_len % 4)) % 4);
    }

    Err(anyhow!(
        "paid exit STUN response did not include a mapped address"
    ))
}

pub fn parse_paid_route_public_ip_response(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        for key in ["ip", "query", "origin"] {
            if let Some(parsed) = value
                .get(key)
                .and_then(Value::as_str)
                .and_then(first_public_ip_text)
            {
                return Some(parsed);
            }
        }
    }

    first_public_ip_text(trimmed)
}

#[must_use]
pub fn parse_paid_route_geoip_response(body: &str) -> (Option<String>, Option<u32>) {
    let Ok(value) = serde_json::from_str::<Value>(body.trim()) else {
        return (None, None);
    };

    let country = ["country_code", "countryCode", "country"]
        .into_iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| (2..=3).contains(&value.len()))
        .map(str::to_ascii_uppercase);

    let asn = ["asn", "as", "autonomous_system_number"]
        .into_iter()
        .find_map(|key| value.get(key))
        .and_then(parse_asn_value);

    (country, asn)
}

pub fn build_paid_route_probe_measurement(
    samples: Vec<PaidRouteProbeSample>,
    observed_country_code: Option<String>,
    observed_asn: Option<u32>,
    now_unix: u64,
) -> Result<PaidRouteProbeMeasurement> {
    let successful = samples
        .iter()
        .filter_map(|sample| {
            Some((
                sample.realized_exit_ip.as_ref()?.clone(),
                sample.latency_ms?,
            ))
        })
        .collect::<Vec<_>>();

    if successful.is_empty() {
        let details = samples
            .iter()
            .filter_map(|sample| sample.error.as_deref())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(anyhow!(
            "paid exit probe did not get a realized exit IP{}",
            if details.is_empty() {
                String::new()
            } else {
                format!(": {details}")
            }
        ));
    }

    let realized_exit_ip = successful
        .last()
        .map(|(ip, _)| ip.clone())
        .or_else(|| successful.first().map(|(ip, _)| ip.clone()));
    let latencies = successful
        .iter()
        .map(|(_, latency_ms)| *latency_ms)
        .collect::<Vec<_>>();
    let latency_ms = mean_u32(&latencies);
    let jitter_ms = jitter_ms(&latencies);
    let packet_loss_ppm = packet_loss_ppm(samples.len(), successful.len());

    Ok(PaidRouteProbeMeasurement {
        realized_exit_ip,
        observed_country_code: observed_country_code.map(|value| value.trim().to_ascii_uppercase()),
        observed_asn,
        quality: PaidRouteQualityMetrics {
            latency_ms,
            jitter_ms,
            packet_loss_ppm: Some(packet_loss_ppm),
            last_seen_unix: Some(now_unix),
            ..PaidRouteQualityMetrics::default()
        },
        samples,
    })
}

fn first_public_ip_text(input: &str) -> Option<String> {
    input
        .split(|ch: char| ch == ',' || ch == '"' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .find_map(|candidate| {
            candidate
                .parse::<IpAddr>()
                .ok()
                .map(|addr| addr.to_string())
        })
}

fn parse_paid_route_stun_mapped_address(
    attr: &[u8],
    xor: bool,
    transaction_id: &[u8; 12],
) -> Result<String> {
    if attr.len() < 8 {
        return Err(anyhow!("paid exit STUN mapped address was too short"));
    }
    let family = attr[1];
    match family {
        0x01 => {
            let mut octets = [attr[4], attr[5], attr[6], attr[7]];
            if xor {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (octet, mask) in octets.iter_mut().zip(cookie) {
                    *octet ^= mask;
                }
            }
            Ok(IpAddr::from(octets).to_string())
        }
        0x02 => {
            if attr.len() < 20 {
                return Err(anyhow!("paid exit STUN IPv6 mapped address was too short"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&attr[4..20]);
            if xor {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for index in 0..4 {
                    octets[index] ^= cookie[index];
                }
                for index in 0..12 {
                    octets[index + 4] ^= transaction_id[index];
                }
            }
            Ok(IpAddr::from(Ipv6Addr::from(octets)).to_string())
        }
        _ => Err(anyhow!(
            "paid exit STUN mapped address used unsupported family {family}"
        )),
    }
}

fn parse_asn_value(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str().and_then(parse_asn_text))
}

fn parse_asn_text(value: &str) -> Option<u32> {
    let digits = value
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse::<u32>().ok()
}

fn mean_u32(values: &[u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    let sum = values.iter().map(|value| u64::from(*value)).sum::<u64>();
    let len = u64::try_from(values.len()).ok()?;
    u32::try_from((sum + (len / 2)) / len).ok()
}

fn jitter_ms(values: &[u32]) -> Option<u32> {
    if values.len() < 2 {
        return Some(0);
    }
    let diffs = values
        .windows(2)
        .map(|pair| pair[0].abs_diff(pair[1]))
        .collect::<Vec<_>>();
    mean_u32(&diffs)
}

fn packet_loss_ppm(total: usize, successful: usize) -> u32 {
    if total == 0 {
        return 1_000_000;
    }
    let lost = total.saturating_sub(successful);
    u32::try_from((lost.saturating_mul(1_000_000)) / total).unwrap_or(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paid_route_probe_parses_public_ip_shapes() {
        assert_eq!(
            parse_paid_route_public_ip_response(r#"{"ip":"198.51.100.42"}"#).as_deref(),
            Some("198.51.100.42")
        );
        assert_eq!(
            parse_paid_route_public_ip_response(r#"{"origin":"198.51.100.43, 203.0.113.9"}"#)
                .as_deref(),
            Some("198.51.100.43")
        );
        assert_eq!(
            parse_paid_route_public_ip_response("2001:db8::1\n").as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn paid_route_probe_parses_geoip_shapes() {
        assert_eq!(
            parse_paid_route_geoip_response(r#"{"country_code":"fi","asn":"AS14593 Example"}"#),
            (Some("FI".to_string()), Some(14_593))
        );
        assert_eq!(
            parse_paid_route_geoip_response(r#"{"countryCode":"US","as":"AS15169 Google LLC"}"#),
            (Some("US".to_string()), Some(15_169))
        );
        assert_eq!(
            parse_paid_route_geoip_response(r#"{"country":"NL","asn":1234}"#),
            (Some("NL".to_string()), Some(1_234))
        );
    }

    #[test]
    fn paid_route_probe_builds_bandwidth_urls_and_bps() {
        assert_eq!(
            paid_route_download_url("https://speed.example/__down", 1024),
            "https://speed.example/__down?bytes=1024"
        );
        assert_eq!(
            paid_route_download_url("https://speed.example/__down?warm=1", 1024),
            "https://speed.example/__down?warm=1&bytes=1024"
        );
        assert_eq!(
            paid_route_download_url("https://speed.example/{bytes}", 1024),
            "https://speed.example/1024"
        );
        assert_eq!(
            paid_route_bandwidth_bps(1_000, Duration::from_millis(100)),
            Some(80_000)
        );
        assert_eq!(
            paid_route_bandwidth_bps(0, Duration::from_millis(100)),
            None
        );
        assert_eq!(paid_route_bandwidth_bps(1_000, Duration::ZERO), None);
    }

    #[test]
    fn paid_route_probe_parses_stun_server_urls() {
        assert_eq!(
            paid_route_stun_host_port("stun:stun.example.org"),
            Some(("stun.example.org".to_string(), 3478))
        );
        assert_eq!(
            paid_route_stun_host_port("stun://stun.example.org:19302"),
            Some(("stun.example.org".to_string(), 19302))
        );
        assert_eq!(
            paid_route_stun_host_port("stun:[2001:db8::1]:3479"),
            Some(("2001:db8::1".to_string(), 3479))
        );
        assert_eq!(
            paid_route_stun_host_port("2001:db8::2"),
            Some(("2001:db8::2".to_string(), 3478))
        );
        assert_eq!(paid_route_stun_host_port("   "), None);
    }

    #[test]
    fn paid_route_probe_parses_xor_mapped_stun_response() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mapped_ip = [198, 51, 100, 77];
        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12_u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.push(0);
        response.push(0x01);
        response
            .extend_from_slice(&(54_321_u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
        for (octet, mask) in mapped_ip.into_iter().zip(STUN_MAGIC_COOKIE.to_be_bytes()) {
            response.push(octet ^ mask);
        }

        assert_eq!(
            parse_paid_route_stun_binding_response(&response, transaction_id)
                .expect("parse STUN response"),
            "198.51.100.77"
        );
    }

    #[test]
    fn paid_route_probe_aggregates_latency_jitter_and_loss() {
        let measurement = build_paid_route_probe_measurement(
            vec![
                PaidRouteProbeSample::success("198.51.100.42".to_string(), 40),
                PaidRouteProbeSample::failure("timeout"),
                PaidRouteProbeSample::success("198.51.100.42".to_string(), 50),
            ],
            Some("fi".to_string()),
            Some(14_593),
            123,
        )
        .expect("measurement");

        assert_eq!(
            measurement.realized_exit_ip.as_deref(),
            Some("198.51.100.42")
        );
        assert_eq!(measurement.observed_country_code.as_deref(), Some("FI"));
        assert_eq!(measurement.observed_asn, Some(14_593));
        assert_eq!(measurement.quality.latency_ms, Some(45));
        assert_eq!(measurement.quality.jitter_ms, Some(10));
        assert_eq!(measurement.quality.packet_loss_ppm, Some(333_333));
        assert_eq!(measurement.quality.last_seen_unix, Some(123));
    }

    #[test]
    fn paid_route_probe_failure_preserves_transport_errors() {
        let error = build_paid_route_probe_measurement(
            vec![PaidRouteProbeSample::failure(
                "stun: timed out; https: connection reset",
            )],
            None,
            None,
            123,
        )
        .expect_err("all failed samples must fail the measurement");

        assert!(
            error
                .to_string()
                .contains("stun: timed out; https: connection reset")
        );
    }
}
