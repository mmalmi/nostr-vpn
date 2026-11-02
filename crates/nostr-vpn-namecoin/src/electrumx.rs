//! `ElectrumX`-backed `NamecoinResolver` implementation.
//!
//! Implements the subset of the `ElectrumX` protocol required to fetch a
//! Namecoin name value: a single `blockchain.name.get` JSON-RPC call over
//! either TLS or plain TCP. The reply is parsed as ifa-0001 Domain Name
//! Object JSON and walked to `nostr.names[<local>]`.

use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::alias::BitAlias;
use crate::resolver::{NamecoinError, NamecoinResolver, ResolverConfig, validate_hex_pubkey};

/// One configured `ElectrumX` endpoint.
#[derive(Debug, Clone)]
pub struct ElectrumXServer {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
}

impl ElectrumXServer {
    /// Parse a `host:port` or `ssl://host:port`/`tcp://host:port` spec.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let (scheme_tls, rest) = if let Some(rest) = raw.strip_prefix("ssl://") {
            (true, rest)
        } else if let Some(rest) = raw.strip_prefix("tcp://") {
            (false, rest)
        } else {
            (true, raw)
        };
        let (host, port_str) = rest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("electrumx server must include port: {raw}"))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid electrumx port: {port_str}"))?;
        if host.is_empty() {
            return Err(anyhow!("electrumx host must not be empty"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            use_tls: scheme_tls,
        })
    }
}

/// `ElectrumX` resolver.
pub struct ElectrumXResolver {
    servers: Vec<ElectrumXServer>,
    config: ResolverConfig,
}

impl ElectrumXResolver {
    /// Build a resolver with the provided servers and config.
    #[must_use]
    pub fn new(servers: Vec<ElectrumXServer>, config: ResolverConfig) -> Self {
        Self { servers, config }
    }

    /// Default server set used when the user hasn't overridden it.
    #[must_use]
    pub fn default_servers() -> Vec<ElectrumXServer> {
        vec![
            ElectrumXServer {
                host: "electrum-nmc.le-space.de".to_string(),
                port: 50002,
                use_tls: true,
            },
            ElectrumXServer {
                host: "nmc.bitcoins.sk".to_string(),
                port: 50002,
                use_tls: true,
            },
        ]
    }

    async fn fetch_name(&self, name: &str) -> Result<String, NamecoinError> {
        if self.servers.is_empty() {
            return Err(NamecoinError::Generic(
                "no electrumx servers configured".to_string(),
            ));
        }
        let mut last_error: Option<anyhow::Error> = None;
        for server in &self.servers {
            match timeout(self.config.timeout, fetch_name_from_server(server, name)).await {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(error)) => {
                    if let Some(transport) = error.downcast_ref::<NameLookupError>()
                        && matches!(transport, NameLookupError::NotFound)
                    {
                        return Err(NamecoinError::NotFound {
                            name: name.to_string(),
                        });
                    }
                    last_error = Some(error);
                }
                Err(_) => {
                    last_error = Some(anyhow!(
                        "electrumx request to {}:{} timed out after {:?}",
                        server.host,
                        server.port,
                        self.config.timeout
                    ));
                }
            }
        }
        let error =
            last_error.unwrap_or_else(|| anyhow!("electrumx request failed without an error"));
        Err(NamecoinError::Transport {
            server: self
                .servers
                .iter()
                .map(|s| format!("{}:{}", s.host, s.port))
                .collect::<Vec<_>>()
                .join(","),
            source: error,
        })
    }
}

#[async_trait]
impl NamecoinResolver for ElectrumXResolver {
    async fn resolve_nostr_pubkey(&self, alias: &BitAlias) -> Result<String, NamecoinError> {
        // Walk the alias parent (e.g. `example.bit` → `d/example`).
        // For `a.b.c.bit` we look up `d/c` (root) and walk via `map` into b → a.
        let parent_no_suffix = alias
            .parent()
            .strip_suffix(".bit")
            .unwrap_or(alias.parent())
            .to_string();

        // Split the parent into labels (most-specific first). The TLD
        // equivalent is the last label: `b.c.bit` → `[b, c]` → root is `c`.
        let parent_labels: Vec<&str> = parent_no_suffix.split('.').collect();
        let root_label = parent_labels
            .last()
            .copied()
            .ok_or_else(|| NamecoinError::Generic("empty .bit parent".to_string()))?;

        // Subdomain labels to walk through `map`, ordered top-down. For
        // `alice.example.bit` (local=alice, parent=example.bit) we look up
        // root `d/example` and read `nostr.names[alice]` directly. For
        // `a.b.c.bit` (local=a, parent=b.c.bit) we descend `map["b"]` and
        // then read `nostr.names[a]`.
        let mut map_walk: Vec<String> = parent_labels
            .iter()
            .rev()
            .skip(1)
            .map(|s| (*s).to_string())
            .collect();
        map_walk.reverse();

        let local = alias.local().to_string();

        let mut import_hops = 0u8;
        let mut current_name = format!("d/{root_label}");

        loop {
            let raw_value = self.fetch_name(&current_name).await?;
            let walked = walk_namecoin_value(&current_name, &raw_value, &map_walk, &local)?;
            match walked {
                WalkOutcome::Pubkey(hex) => {
                    return validate_hex_pubkey(&current_name, &hex);
                }
                WalkOutcome::Import(target) => {
                    import_hops += 1;
                    if import_hops > 1 {
                        return Err(NamecoinError::ImportLimit { name: current_name });
                    }
                    current_name = target;
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum NameLookupError {
    #[error("name not found")]
    NotFound,
}

async fn fetch_name_from_server(server: &ElectrumXServer, name: &str) -> anyhow::Result<String> {
    let request = serde_json::json!({
        "id": 1,
        "method": "blockchain.name.get",
        "params": [name],
    });
    let mut payload = serde_json::to_vec(&request)?;
    payload.push(b'\n');

    let response = if server.use_tls {
        send_tls(server, &payload).await?
    } else {
        send_plain(server, &payload).await?
    };

    parse_response(&response)
}

async fn send_plain(server: &ElectrumXServer, payload: &[u8]) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect((server.host.as_str(), server.port)).await?;
    stream.write_all(payload).await?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    Ok(buf)
}

async fn send_tls(server: &ElectrumXServer, payload: &[u8]) -> anyhow::Result<String> {
    let connector = tls_connector();
    let tcp = TcpStream::connect((server.host.as_str(), server.port)).await?;
    let dns_name = ServerName::try_from(server.host.clone())
        .map_err(|err| anyhow!("invalid TLS server name {}: {err}", server.host))?;
    let mut tls = connector.connect(dns_name, tcp).await?;
    tls.write_all(payload).await?;
    let mut reader = BufReader::new(tls);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    Ok(buf)
}

fn tls_connector() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone();
    TlsConnector::from(config)
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

fn parse_response(line: &str) -> anyhow::Result<String> {
    if line.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty response").into());
    }
    let envelope: JsonRpcEnvelope =
        serde_json::from_str(line).with_context(|| format!("invalid JSON-RPC response: {line}"))?;
    if let Some(error) = envelope.error {
        // ElectrumX returns either a string or a structured error.
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .map_or_else(|| error.to_string(), str::to_string);
        if message.to_ascii_lowercase().contains("not found")
            || message.to_ascii_lowercase().contains("unknown name")
        {
            return Err(NameLookupError::NotFound.into());
        }
        return Err(anyhow!("electrumx error: {message}"));
    }
    let result = envelope
        .result
        .ok_or_else(|| anyhow!("electrumx response missing result"))?;
    // ElectrumX `blockchain.name.get` returns an object with a `value`
    // string. Some servers wrap it differently — accept both shapes.
    if let Some(obj) = result.as_object() {
        if let Some(value) = obj.get("value").and_then(Value::as_str) {
            return Ok(value.to_string());
        }
        if let Some(value) = obj.get("value") {
            return Ok(value.to_string());
        }
    }
    if let Some(value) = result.as_str() {
        return Ok(value.to_string());
    }
    Err(anyhow!("electrumx response missing name value"))
}

#[derive(Debug)]
enum WalkOutcome {
    Pubkey(String),
    Import(String),
}

fn walk_namecoin_value(
    name: &str,
    raw_value: &str,
    map_walk: &[String],
    local: &str,
) -> Result<WalkOutcome, NamecoinError> {
    let root: Value =
        serde_json::from_str(raw_value).map_err(|err| NamecoinError::MalformedValue {
            name: name.to_string(),
            reason: format!("invalid JSON: {err}"),
        })?;
    let mut current = &root;

    // Walk through `map[label]` entries.
    for label in map_walk {
        let next = current
            .get("map")
            .and_then(|m| m.get(label.as_str()))
            .ok_or_else(|| NamecoinError::NoNostrEntry {
                name: name.to_string(),
                local: local.to_string(),
            })?;
        current = next;
    }

    // Expired records: ifa-0001 uses `expires_in <= 0` or `expired: true`.
    // Check this before reading `nostr.names` so callers see the precise
    // "this record is dead" error rather than treating it as a hit.
    if let Some(expired) = current.get("expired").and_then(Value::as_bool)
        && expired
    {
        return Err(NamecoinError::Expired {
            name: name.to_string(),
        });
    }
    if let Some(expires_in) = current.get("expires_in").and_then(Value::as_i64)
        && expires_in <= 0
    {
        return Err(NamecoinError::Expired {
            name: name.to_string(),
        });
    }

    // Look for nostr.names[local].
    if let Some(nostr) = current.get("nostr")
        && let Some(names) = nostr.get("names")
    {
        if let Some(value) = names.get(local).and_then(Value::as_str) {
            return Ok(WalkOutcome::Pubkey(value.to_string()));
        }
        // Apex fallback: when looking up "_" but the publisher used the
        // root label as the key (ifa-0001 quirk), try that too.
        if local == "_" {
            // Walk up to find a sensible label: use the first segment of
            // the lookup name (e.g. `d/example` → `example`).
            if let Some(root_label) = name.strip_prefix("d/")
                && let Some(value) = names.get(root_label).and_then(Value::as_str)
            {
                return Ok(WalkOutcome::Pubkey(value.to_string()));
            }
        }
    }

    // Look for `import` redirect.
    if let Some(import) = current.get("import").and_then(Value::as_str) {
        return Ok(WalkOutcome::Import(import.to_string()));
    }

    Err(NamecoinError::NoNostrEntry {
        name: name.to_string(),
        local: local.to_string(),
    })
}

/// Convenience: build an `ElectrumXResolver` from a list of `host:port`
/// strings using the default configuration.
pub fn parse_servers(raw: &[String]) -> anyhow::Result<Vec<ElectrumXServer>> {
    raw.iter()
        .map(|spec| ElectrumXServer::parse(spec))
        .collect()
}

/// Wrap a duration value (seconds) with sane defaults if the input is zero.
#[must_use]
pub fn duration_or_default(seconds: u64, default_secs: u64) -> Duration {
    if seconds == 0 {
        Duration::from_secs(default_secs)
    } else {
        Duration::from_secs(seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_value(value: &serde_json::Value) -> String {
        value.to_string()
    }

    #[test]
    fn parse_servers_accepts_bare_hostport() {
        let server = ElectrumXServer::parse("electrum.example.org:50002").unwrap();
        assert_eq!(server.host, "electrum.example.org");
        assert_eq!(server.port, 50002);
        assert!(server.use_tls);
    }

    #[test]
    fn parse_servers_honours_scheme() {
        let tls = ElectrumXServer::parse("ssl://electrum.example.org:50002").unwrap();
        assert!(tls.use_tls);
        let plain = ElectrumXServer::parse("tcp://electrum.example.org:50001").unwrap();
        assert!(!plain.use_tls);
    }

    #[test]
    fn walks_apex_nostr_underscore_entry() {
        let value = raw_value(&serde_json::json!({
            "nostr": {
                "names": {
                    "_": "a".repeat(64)
                }
            }
        }));
        let outcome = walk_namecoin_value("d/example", &value, &[], "_").unwrap();
        let WalkOutcome::Pubkey(hex) = outcome else {
            panic!("expected pubkey");
        };
        assert_eq!(hex, "a".repeat(64));
    }

    #[test]
    fn walks_localpart_entry() {
        let value = raw_value(&serde_json::json!({
            "nostr": {
                "names": {
                    "alice": "b".repeat(64)
                }
            }
        }));
        let outcome = walk_namecoin_value("d/example", &value, &[], "alice").unwrap();
        let WalkOutcome::Pubkey(hex) = outcome else {
            panic!("expected pubkey");
        };
        assert_eq!(hex, "b".repeat(64));
    }

    #[test]
    fn walks_map_subtree() {
        let value = raw_value(&serde_json::json!({
            "map": {
                "team": {
                    "nostr": {
                        "names": {
                            "alice": "c".repeat(64)
                        }
                    }
                }
            }
        }));
        let outcome =
            walk_namecoin_value("d/example", &value, &["team".to_string()], "alice").unwrap();
        let WalkOutcome::Pubkey(hex) = outcome else {
            panic!("expected pubkey");
        };
        assert_eq!(hex, "c".repeat(64));
    }

    #[test]
    fn surfaces_import_redirects() {
        let value = raw_value(&serde_json::json!({
            "import": "d/other"
        }));
        let outcome = walk_namecoin_value("d/example", &value, &[], "_").unwrap();
        let WalkOutcome::Import(target) = outcome else {
            panic!("expected import");
        };
        assert_eq!(target, "d/other");
    }

    #[test]
    fn missing_local_returns_clear_error() {
        let value = raw_value(&serde_json::json!({
            "nostr": {
                "names": {
                    "bob": "d".repeat(64)
                }
            }
        }));
        let err = walk_namecoin_value("d/example", &value, &[], "alice").unwrap_err();
        match err {
            NamecoinError::NoNostrEntry { name, local } => {
                assert_eq!(name, "d/example");
                assert_eq!(local, "alice");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_json_is_reported() {
        let err = walk_namecoin_value("d/example", "not json", &[], "_").unwrap_err();
        assert!(matches!(err, NamecoinError::MalformedValue { .. }));
    }

    #[test]
    fn expired_records_are_rejected() {
        let value = raw_value(&serde_json::json!({
            "expired": true,
            "nostr": { "names": { "_": "e".repeat(64) } }
        }));
        let err = walk_namecoin_value("d/example", &value, &[], "_").unwrap_err();
        assert!(matches!(err, NamecoinError::Expired { .. }));
    }

    #[test]
    fn validates_pubkey_format() {
        let value = raw_value(&serde_json::json!({
            "nostr": { "names": { "_": "not-hex" } }
        }));
        // The walk returns the string; the resolver then validates it.
        let outcome = walk_namecoin_value("d/example", &value, &[], "_").unwrap();
        let WalkOutcome::Pubkey(hex) = outcome else {
            panic!("expected pubkey");
        };
        let err = validate_hex_pubkey("d/example", &hex).unwrap_err();
        assert!(matches!(err, NamecoinError::InvalidPubkey { .. }));
    }

    #[test]
    fn jsonrpc_response_value_field_is_extracted() {
        let response = serde_json::json!({
            "id": 1,
            "result": {
                "value": "{\"nostr\":{\"names\":{\"_\":\"f\"}}}"
            },
            "error": null,
        });
        let line = format!("{response}\n");
        let value = parse_response(&line).unwrap();
        assert!(value.starts_with('{'));
    }

    #[test]
    fn jsonrpc_not_found_maps_to_lookup_error() {
        let response = serde_json::json!({
            "id": 1,
            "result": null,
            "error": { "code": -1, "message": "name not found" },
        });
        let line = format!("{response}\n");
        let err = parse_response(&line).unwrap_err();
        assert!(err.downcast_ref::<NameLookupError>().is_some());
    }
}
