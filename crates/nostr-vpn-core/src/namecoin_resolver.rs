//! Minimal Namecoin resolver for invite-anchored discovery relay lists.
//!
//! TODO: consolidate with the nostr-vpn-namecoin crate introduced in the
//! `feat/namecoin-resolver` PR once that lands. This is a deliberately minimal
//! inline implementation scoped to discovery-relay resolution.
//!
//! Resolves a `.bit` (or `d/<name>`) Namecoin name via ElectrumX
//! `blockchain.name.get` over TLS, parses the JSON value, walks the ifa-0001
//! `map` for subdomain labels, and extracts `nostr.relays` as a list of
//! strings.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

/// Public ElectrumX servers we'll round-robin through. Both expose Namecoin
/// SSL on the default Electrum port (50002). These are reasonable defaults —
/// operators who want to pin a different server can override via
/// `NamecoinResolver::with_servers`.
pub const DEFAULT_ELECTRUMX_SERVERS: &[(&str, u16)] = &[
    ("electrum-nmc.le-space.de", 50002),
    ("nmc.bitcoins.sk", 50002),
];

/// Hard ceiling on the entire resolution flow (TCP connect + TLS handshake +
/// JSON-RPC request + JSON parse + map walk).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Decoded parts of a `.bit` or `d/<name>` alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedName {
    /// The Namecoin namespace + identifier in canonical `d/<name>` form,
    /// suitable for `blockchain.name.get`.
    pub name_key: String,
    /// Subdomain labels (most-specific first) below the apex. Empty for an
    /// apex name like `acmevpn.bit`.
    pub labels: Vec<String>,
}

/// Parse a user-facing alias (`acmevpn.bit`, `relays.acmevpn.bit`, `d/acmevpn`)
/// into the ElectrumX `name_key` plus the subdomain walk path.
pub fn parse_bit_name(alias: &str) -> Result<ParsedName> {
    let raw = alias.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Err(anyhow!("namecoin name is empty"));
    }

    if let Some(stripped) = raw.strip_prefix("d/") {
        if stripped.is_empty() {
            return Err(anyhow!("namecoin d/ name is empty"));
        }
        return Ok(ParsedName {
            name_key: format!("d/{stripped}"),
            labels: Vec::new(),
        });
    }

    let stripped = raw
        .strip_suffix(".bit")
        .ok_or_else(|| anyhow!("namecoin name must end in .bit or start with d/"))?;
    if stripped.is_empty() {
        return Err(anyhow!("namecoin .bit name is empty"));
    }
    let mut parts: Vec<&str> = stripped.split('.').collect();
    // Last segment is the apex `<name>`; everything before it is a subdomain
    // walk that we'll resolve via the ifa-0001 `map` field.
    let apex = parts
        .pop()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| anyhow!("namecoin .bit name has empty apex"))?;
    let labels: Vec<String> = parts
        .iter()
        .rev()
        .filter(|segment| !segment.is_empty())
        .map(|segment| (*segment).to_string())
        .collect();

    Ok(ParsedName {
        name_key: format!("d/{apex}"),
        labels,
    })
}

/// Abstract Namecoin/ElectrumX transport — production code wires this to a
/// TLS-fronted TCP socket; tests inject a synthetic responder.
#[async_trait]
pub trait NamecoinTransport: Send + Sync {
    /// Fetch the raw value of the given `name_key` (e.g. `d/acmevpn`). The
    /// returned string is the JSON value blob stored under the name. Returns
    /// an error if the lookup fails or the name is missing.
    async fn get_name_value(&self, name_key: &str) -> Result<String>;
}

/// Pulls `nostr.relays` out of a Namecoin record. Walks the optional ifa-0001
/// `map["<label>"]` chain for subdomain aliases.
pub fn extract_relays_from_record(value: &str, labels: &[String]) -> Result<Vec<String>> {
    let mut current: Value = serde_json::from_str(value)
        .with_context(|| format!("namecoin record is not valid JSON: {value}"))?;

    // Walk through the requested subdomain labels via the ifa-0001 `map`.
    for label in labels {
        let next = match current {
            Value::Object(mut map) => map.remove("map").ok_or_else(|| {
                anyhow!("namecoin record has no `map` field; cannot resolve label '{label}'")
            })?,
            other => {
                return Err(anyhow!(
                    "namecoin record at label '{label}' is not an object (got {other:?})",
                ));
            }
        };
        let mut sub_map = match next {
            Value::Object(map) => map,
            other => return Err(anyhow!("`map` is not an object (got {other:?})")),
        };
        current = sub_map
            .remove(label)
            .ok_or_else(|| anyhow!("namecoin record `map` has no entry for label '{label}'"))?;
    }

    let nostr = match current {
        Value::Object(mut map) => map.remove("nostr"),
        _ => None,
    };
    let Some(nostr) = nostr else {
        return Ok(Vec::new());
    };
    let relays = match nostr {
        Value::Object(mut map) => map.remove("relays").unwrap_or(Value::Null),
        _ => Value::Null,
    };
    match relays {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::String(s) => Ok(s),
                other => Err(anyhow!(
                    "`nostr.relays` entry is not a string (got {other:?})",
                )),
            })
            .collect(),
        other => Err(anyhow!("`nostr.relays` is not an array (got {other:?})",)),
    }
}

/// High-level resolver: parse the alias, fetch via the injected transport,
/// walk the record, return the relay list. Bounded by `RESOLVE_TIMEOUT`.
pub async fn resolve_relays<T: NamecoinTransport + ?Sized>(
    transport: &T,
    alias: &str,
) -> Result<Vec<String>> {
    let parsed = parse_bit_name(alias)?;
    let lookup = transport.get_name_value(&parsed.name_key);
    let raw = timeout(RESOLVE_TIMEOUT, lookup)
        .await
        .map_err(|_| anyhow!("namecoin resolution timed out after {RESOLVE_TIMEOUT:?}"))?
        .with_context(|| format!("namecoin lookup failed for '{}'", parsed.name_key))?;
    extract_relays_from_record(&raw, &parsed.labels)
}

/// Convenience: use the bundled TLS ElectrumX transport with the default
/// server list.
pub async fn resolve_relays_default(alias: &str) -> Result<Vec<String>> {
    let transport = ElectrumxTransport::default();
    resolve_relays(&transport, alias).await
}

/// JSON-RPC ElectrumX transport. Connects over TLS using the platform's
/// webpki-roots trust anchors and issues a single `blockchain.name.get`
/// request per call.
pub struct ElectrumxTransport {
    servers: Vec<(String, u16)>,
    connector: TlsConnector,
}

impl Default for ElectrumxTransport {
    fn default() -> Self {
        Self::with_servers(
            DEFAULT_ELECTRUMX_SERVERS
                .iter()
                .map(|(host, port)| ((*host).to_string(), *port))
                .collect(),
        )
    }
}

impl ElectrumxTransport {
    pub fn with_servers(servers: Vec<(String, u16)>) -> Self {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            servers,
            connector: TlsConnector::from(Arc::new(config)),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ElectrumxResponse {
    #[serde(default)]
    result: Option<NameGetResult>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct NameGetResult {
    #[serde(default)]
    value: Option<String>,
}

async fn electrumx_request(
    connector: &TlsConnector,
    host: &str,
    port: u16,
    name_key: &str,
) -> Result<String> {
    let stream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect {host}:{port}"))?;
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid TLS server name '{host}'"))?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("TLS handshake with {host}"))?;

    // ElectrumX speaks line-delimited JSON-RPC 2.0.
    let request = serde_json::json!({
        "id": 1,
        "method": "blockchain.name.get",
        "params": [name_key],
    });
    let mut line = serde_json::to_vec(&request)?;
    line.push(b'\n');
    tls.write_all(&line)
        .await
        .with_context(|| format!("write request to {host}"))?;

    let mut response = String::new();
    // Read until newline — ElectrumX terminates each response with `\n`.
    let mut buf = [0u8; 4096];
    loop {
        let n = tls
            .read(&mut buf)
            .await
            .with_context(|| format!("read response from {host}"))?;
        if n == 0 {
            break;
        }
        response.push_str(std::str::from_utf8(&buf[..n]).context("ElectrumX returned non-utf8")?);
        if response.contains('\n') {
            break;
        }
    }
    let first_line = response
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty response from {host}"))?;
    let parsed: ElectrumxResponse = serde_json::from_str(first_line)
        .with_context(|| format!("malformed JSON-RPC from {host}: {first_line}"))?;
    if let Some(error) = parsed.error {
        return Err(anyhow!("electrumx error from {host}: {error}"));
    }
    let result = parsed
        .result
        .ok_or_else(|| anyhow!("electrumx response from {host} missing result"))?;
    result
        .value
        .ok_or_else(|| anyhow!("electrumx result from {host} has no value"))
}

#[async_trait]
impl NamecoinTransport for ElectrumxTransport {
    async fn get_name_value(&self, name_key: &str) -> Result<String> {
        if self.servers.is_empty() {
            return Err(anyhow!("no electrumx servers configured"));
        }
        let mut last_err: Option<anyhow::Error> = None;
        for (host, port) in &self.servers {
            match electrumx_request(&self.connector, host, *port, name_key).await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    tracing::debug!(target: "namecoin", host = %host, error = %error, "electrumx attempt failed");
                    last_err = Some(error);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("namecoin lookup failed with no servers")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockTransport {
        responses: Mutex<Vec<Result<String>>>,
        last_key: Mutex<Option<String>>,
    }

    impl MockTransport {
        fn new(values: Vec<Result<String>>) -> Self {
            Self {
                responses: Mutex::new(values),
                last_key: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl NamecoinTransport for MockTransport {
        async fn get_name_value(&self, name_key: &str) -> Result<String> {
            *self.last_key.lock().unwrap() = Some(name_key.to_string());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Err(anyhow!("mock has no more responses"))
            } else {
                responses.remove(0)
            }
        }
    }

    #[test]
    fn parses_apex_bit_name() {
        let parsed = parse_bit_name("Acmevpn.BIT").expect("parses");
        assert_eq!(parsed.name_key, "d/acmevpn");
        assert!(parsed.labels.is_empty());
    }

    #[test]
    fn parses_subdomain_walk_most_specific_last() {
        let parsed = parse_bit_name("relays.acmevpn.bit").expect("parses");
        assert_eq!(parsed.name_key, "d/acmevpn");
        // Walk is most-specific first.
        assert_eq!(parsed.labels, vec!["relays".to_string()]);
    }

    #[test]
    fn parses_d_prefix_name() {
        let parsed = parse_bit_name(" d/acmevpn ").expect("parses");
        assert_eq!(parsed.name_key, "d/acmevpn");
        assert!(parsed.labels.is_empty());
    }

    #[test]
    fn rejects_empty_or_malformed_name() {
        assert!(parse_bit_name("").is_err());
        assert!(parse_bit_name("acmevpn").is_err());
        assert!(parse_bit_name(".bit").is_err());
        assert!(parse_bit_name("d/").is_err());
    }

    #[tokio::test]
    async fn resolve_apex_returns_relays() {
        let value = r#"{"nostr":{"relays":["wss://relay.acme/","wss://r2.example/"]},"info":"x"}"#;
        let transport = MockTransport::new(vec![Ok(value.to_string())]);
        let relays = resolve_relays(&transport, "acmevpn.bit")
            .await
            .expect("resolves");
        assert_eq!(
            relays,
            vec![
                "wss://relay.acme/".to_string(),
                "wss://r2.example/".to_string(),
            ]
        );
        assert_eq!(
            transport.last_key.lock().unwrap().as_deref(),
            Some("d/acmevpn"),
        );
    }

    #[tokio::test]
    async fn resolve_subdomain_walks_map() {
        let value = r#"{
            "info": "apex",
            "map": {
                "relays": {"nostr": {"relays": ["wss://sub.example/"]}}
            }
        }"#;
        let transport = MockTransport::new(vec![Ok(value.to_string())]);
        let relays = resolve_relays(&transport, "relays.acmevpn.bit")
            .await
            .expect("resolves");
        assert_eq!(relays, vec!["wss://sub.example/".to_string()]);
    }

    #[tokio::test]
    async fn resolve_missing_nostr_relays_returns_empty() {
        let transport = MockTransport::new(vec![Ok(r#"{"info":"x"}"#.to_string())]);
        let relays = resolve_relays(&transport, "acmevpn.bit")
            .await
            .expect("resolves");
        assert!(relays.is_empty());
    }

    #[tokio::test]
    async fn resolve_malformed_json_errors() {
        let transport = MockTransport::new(vec![Ok("not json".to_string())]);
        let error = resolve_relays(&transport, "acmevpn.bit")
            .await
            .expect_err("rejects bad JSON");
        assert!(format!("{error:#}").contains("valid JSON"));
    }

    #[tokio::test]
    async fn resolve_electrumx_error_propagates() {
        let transport = MockTransport::new(vec![Err(anyhow!("electrumx: NXNAME"))]);
        let error = resolve_relays(&transport, "acmevpn.bit")
            .await
            .expect_err("propagates transport error");
        assert!(format!("{error:#}").contains("NXNAME"));
    }

    #[tokio::test]
    async fn resolve_subdomain_missing_label_errors() {
        let value = r#"{"map": {"www": {"nostr": {"relays": []}}}}"#;
        let transport = MockTransport::new(vec![Ok(value.to_string())]);
        let error = resolve_relays(&transport, "relays.acmevpn.bit")
            .await
            .expect_err("missing label");
        assert!(format!("{error:#}").contains("'relays'"));
    }
}
