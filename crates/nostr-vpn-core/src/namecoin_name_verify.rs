// TODO: consolidate with the nostr-vpn-namecoin crate introduced in the
// `feat/namecoin-resolver` PR once that lands. Scoped to network-id name
// verification.
//
//! Optional Namecoin (`.bit`) anchor for `network_id`.
//!
//! A `network_id` of the form `acmevpn.bit` (or canonical `d/acmevpn`) is
//! treated as a chain-anchored name. The corresponding Namecoin record holds a
//! `nostr.admins` array of hex pubkeys that defines the legitimate admin set
//! for the network. Joiners verify on invite import that the invite's admin
//! list is a subset of the chain admin set; the daemon re-verifies on roster
//! updates. If the chain says otherwise, we refuse the action and (for roster
//! updates) quarantine the network instead of silently applying.
//!
//! Resolution is intentionally minimal: ElectrumX `blockchain.name.get` over
//! TLS to a small list of public servers, JSON `value` parsing, and the
//! ifa-0001 subdomain walk. The sibling `feat/namecoin-resolver` PR
//! introduces a full-fat crate that will replace this module.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use nostr_sdk::prelude::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, rustls};

/// Hard upper bound for a single ElectrumX call (connect + request + reply).
pub const NAMECOIN_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default ElectrumX servers tried in order until one returns a record. Both
/// support `blockchain.name.get` and listen on TLS port 50002.
pub const DEFAULT_ELECTRUMX_SERVERS: &[(&str, u16)] = &[
    ("electrum-nmc.le-space.de", 50002),
    ("nmc.bitcoins.sk", 50002),
];

/// Maximum number of ifa-0001 subdomain hops to follow when resolving a name.
pub const MAX_ALIAS_HOPS: u8 = 4;

/// A canonical `d/<name>` Namecoin network id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamecoinNetworkId {
    /// Lowercase canonical form, e.g. `d/acmevpn`.
    pub canonical: String,
    /// Optional dotted suffix labels (`d/acmevpn/foo/bar` becomes
    /// `["foo", "bar"]` and resolved against the parent record's
    /// ifa-0001 `map` chain).
    pub subdomain_labels: Vec<String>,
}

impl NamecoinNetworkId {
    /// Bare `d/<name>` form, without subdomain labels.
    pub fn root_name(&self) -> &str {
        &self.canonical
    }

    /// Human-friendly display of the canonical id, including any subdomain
    /// labels.
    pub fn display(&self) -> String {
        if self.subdomain_labels.is_empty() {
            self.canonical.clone()
        } else {
            format!("{}/{}", self.canonical, self.subdomain_labels.join("/"))
        }
    }
}

/// Parsed `nostr.admins` (and friends) from a Namecoin record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainNetworkRecord {
    /// Hex pubkeys (lowercase, 64 chars) parsed from the chain record's
    /// `nostr.admins` array. May be empty if the record is missing the
    /// field — callers MUST treat empty as "no admins published" and
    /// refuse to verify against it.
    pub admins: Vec<String>,
    /// Optional `nostr.network_name` from the record. Surfaced for UI only.
    pub network_name_hint: Option<String>,
}

impl ChainNetworkRecord {
    /// Build a record straight from a parsed Namecoin `value` blob. Returns
    /// `Ok(None)` if the field is missing or wrong shape (the caller decides
    /// whether that should fail closed).
    pub fn from_value(value: &Value) -> Result<Self> {
        let nostr = value
            .get("nostr")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("record is missing the `nostr` object"))?;

        let admins_value = nostr
            .get("admins")
            .ok_or_else(|| anyhow!("record `nostr.admins` is missing"))?;
        let admins_array = admins_value
            .as_array()
            .ok_or_else(|| anyhow!("record `nostr.admins` is not an array"))?;
        let admins = admins_array
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .ok_or_else(|| anyhow!("record `nostr.admins` entry is not a string"))
                    .and_then(canonicalize_admin_hex)
            })
            .collect::<Result<Vec<_>>>()?;

        let network_name_hint = nostr
            .get("network_name")
            .and_then(Value::as_str)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        Ok(Self {
            admins,
            network_name_hint,
        })
    }
}

/// Try to recognise `value` as a Namecoin-anchored network id. Returns `None`
/// for ordinary opaque ids (which keep working unchanged).
pub fn parse_namecoin_network_id(value: &str) -> Option<NamecoinNetworkId> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Accept both `acmevpn.bit` and `d/acmevpn` and `d/acmevpn/sub/labels`.
    let (root_label, subdomain_labels) = if let Some(rest) = trimmed.strip_prefix("d/") {
        let mut parts = rest.split('/');
        let root = parts.next().unwrap_or("").trim();
        let labels = parts
            .map(|label| label.trim().to_string())
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>();
        (root.to_string(), labels)
    } else if let Some(root) = trimmed.strip_suffix(".bit") {
        // ".bit" form does not natively carry subdomain labels.
        (root.trim().to_string(), Vec::new())
    } else {
        return None;
    };

    if root_label.is_empty() {
        return None;
    }
    if !is_valid_namecoin_label(&root_label) {
        return None;
    }
    for label in &subdomain_labels {
        if !is_valid_namecoin_label(label) {
            return None;
        }
    }

    let canonical = format!("d/{}", root_label.to_ascii_lowercase());
    Some(NamecoinNetworkId {
        canonical,
        subdomain_labels: subdomain_labels
            .into_iter()
            .map(|label| label.to_ascii_lowercase())
            .collect(),
    })
}

fn is_valid_namecoin_label(label: &str) -> bool {
    // Namecoin `d/` names are constrained to 1-63 chars of
    // `[a-z0-9-]`, no leading/trailing dash. (See Namecoin doc/wiki.)
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// Pluggable transport so we can mock the ElectrumX wire shape in tests
/// without standing up real TLS sockets. Each call corresponds to a single
/// `blockchain.name.get` request.
#[async_trait]
pub trait NamecoinTransport: Send + Sync {
    /// Fetch the raw `value` blob for `name` (e.g. `"d/acmevpn"`). Returns
    /// `Ok(None)` if the record is missing.
    async fn fetch_name_value(&self, name: &str) -> Result<Option<Value>>;
}

/// Verify that every invite admin appears in the chain admin set. The chain
/// is allowed to list extra admins not present in the invite.
pub fn verify_admins_against_chain(
    invite_admins: &[String],
    chain: &ChainNetworkRecord,
) -> Result<()> {
    if invite_admins.is_empty() {
        return Err(anyhow!(
            "invite admin list is empty; refusing to anchor an empty admin set"
        ));
    }
    if chain.admins.is_empty() {
        return Err(anyhow!(
            "chain record has no admins published (nostr.admins missing or empty); \
             refusing to verify against an empty anchor"
        ));
    }

    let normalized_chain = chain
        .admins
        .iter()
        .map(|admin| canonicalize_admin_hex(admin))
        .collect::<Result<Vec<_>>>()?;

    for admin in invite_admins {
        let normalized = canonicalize_admin_hex(admin)?;
        if !normalized_chain.iter().any(|chain| chain == &normalized) {
            return Err(anyhow!(
                "invite admin {admin} is not in the chain admin set"
            ));
        }
    }

    Ok(())
}

/// Normalize a pubkey (hex or npub bech32) to lowercase hex.
pub fn canonicalize_admin_hex(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("admin pubkey is empty"));
    }
    let public_key = PublicKey::parse(trimmed)
        .map_err(|error| anyhow!("invalid admin pubkey '{trimmed}': {error}"))?;
    Ok(public_key.to_hex().to_ascii_lowercase())
}

/// Resolve a Namecoin-anchored network id using the supplied transport.
///
/// Performs an ifa-0001 subdomain walk when the id carries `d/<root>/<...>`
/// labels. The walk follows the record's `map.<label>` chain (the convention
/// from Namecoin Improvement Proposal 0001) until the labels are exhausted or
/// a hop is missing.
pub async fn resolve_with_transport(
    transport: &dyn NamecoinTransport,
    id: &NamecoinNetworkId,
) -> Result<ChainNetworkRecord> {
    let root_value = transport
        .fetch_name_value(&id.canonical)
        .await
        .with_context(|| format!("fetching {} from chain", id.canonical))?
        .ok_or_else(|| anyhow!("Namecoin record {} not found", id.canonical))?;

    let mut current = root_value;
    let mut hops = 0u8;
    for label in &id.subdomain_labels {
        if hops >= MAX_ALIAS_HOPS {
            return Err(anyhow!(
                "subdomain walk for {} exceeded {MAX_ALIAS_HOPS} hops",
                id.display()
            ));
        }
        hops = hops.saturating_add(1);

        let next = current
            .get("map")
            .and_then(Value::as_object)
            .and_then(|map| map.get(label))
            .cloned();
        let Some(next) = next else {
            return Err(anyhow!(
                "subdomain label {label} not present in {} ifa-0001 map",
                id.canonical
            ));
        };
        current = next;
    }

    ChainNetworkRecord::from_value(&current)
}

/// Resolve a Namecoin-anchored network id using the default TLS-backed
/// transport against the public ElectrumX servers in
/// [`DEFAULT_ELECTRUMX_SERVERS`]. Honours [`NAMECOIN_RESOLVE_TIMEOUT`].
pub async fn resolve_network_record(id: &NamecoinNetworkId) -> Result<ChainNetworkRecord> {
    let transport = ElectrumXTlsTransport::new(DEFAULT_ELECTRUMX_SERVERS.to_vec());
    match timeout(
        NAMECOIN_RESOLVE_TIMEOUT,
        resolve_with_transport(&transport, id),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "Namecoin resolution timed out after {}s",
            NAMECOIN_RESOLVE_TIMEOUT.as_secs()
        )),
    }
}

/// Real ElectrumX transport. Tries each server in order until one succeeds.
pub struct ElectrumXTlsTransport {
    servers: Vec<(&'static str, u16)>,
}

impl ElectrumXTlsTransport {
    pub fn new(servers: Vec<(&'static str, u16)>) -> Self {
        Self { servers }
    }
}

#[async_trait]
impl NamecoinTransport for ElectrumXTlsTransport {
    async fn fetch_name_value(&self, name: &str) -> Result<Option<Value>> {
        let mut last_error: Option<anyhow::Error> = None;
        for (host, port) in &self.servers {
            match electrumx_name_get_tls(host, *port, name).await {
                Ok(Some(value)) => return Ok(Some(value)),
                Ok(None) => return Ok(None),
                Err(error) => {
                    tracing::debug!(
                        host,
                        port,
                        name,
                        ?error,
                        "namecoin resolver: server failed, trying next"
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| anyhow!("no ElectrumX servers configured for namecoin resolver")))
    }
}

async fn electrumx_name_get_tls(host: &str, port: u16, name: &str) -> Result<Option<Value>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to ElectrumX server {host}:{port}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|error| anyhow!("invalid ElectrumX host {host}: {error}"))?
        .to_owned();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}:{port}"))?;

    let request = serde_json::json!({
        "id": 1,
        "method": "blockchain.name.get",
        "params": [name],
    });
    let mut payload = serde_json::to_vec(&request)?;
    payload.push(b'\n');
    tls.write_all(&payload).await?;
    tls.flush().await?;

    let mut reader = BufReader::new(tls);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(anyhow!("ElectrumX server closed connection before reply"));
    }

    let response: Value = serde_json::from_str(line.trim())
        .with_context(|| format!("parsing ElectrumX reply from {host}:{port}"))?;

    if let Some(error) = response.get("error")
        && !error.is_null()
    {
        // ElectrumX returns an error object when the name is missing. Treat
        // a -32600/"name not found" style error as "no record"; surface
        // others as failures.
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let lc = message.to_ascii_lowercase();
        if lc.contains("not found") || lc.contains("does not exist") {
            return Ok(None);
        }
        return Err(anyhow!("ElectrumX returned error: {message}"));
    }

    let result = response
        .get("result")
        .ok_or_else(|| anyhow!("ElectrumX reply has no `result` field"))?;
    if result.is_null() {
        return Ok(None);
    }
    let value_str = result
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("ElectrumX `result.value` is missing or not a string"))?;
    let value: Value = serde_json::from_str(value_str.trim())
        .with_context(|| format!("parsing record `value` for {name}"))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct StubTransport {
        responses: Mutex<HashMap<String, Result<Option<Value>, String>>>,
    }

    impl StubTransport {
        fn new(entries: Vec<(&str, Result<Option<Value>, String>)>) -> Self {
            Self {
                responses: Mutex::new(
                    entries
                        .into_iter()
                        .map(|(name, value)| (name.to_string(), value))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl NamecoinTransport for StubTransport {
        async fn fetch_name_value(&self, name: &str) -> Result<Option<Value>> {
            let entry = self
                .responses
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or_else(|| Err(format!("no stub for {name}")));
            entry.map_err(|message| anyhow!(message))
        }
    }

    fn fake_admin(_byte: u8) -> String {
        // Real secp256k1 keys; deterministic randomness isn't required for
        // these tests because we only care about set membership.
        use nostr_sdk::prelude::Keys;
        Keys::generate().public_key().to_hex()
    }

    fn fake_record(admins: &[&str]) -> Value {
        let array: Vec<Value> = admins
            .iter()
            .map(|a| Value::String((*a).to_string()))
            .collect();
        serde_json::json!({ "nostr": { "admins": array, "network_name": "Acme" } })
    }

    #[test]
    fn parse_namecoin_network_id_accepts_dot_bit_and_d_prefix() {
        let bit = parse_namecoin_network_id("AcmeVPN.bit").expect("recognised .bit form");
        let dformat = parse_namecoin_network_id("d/AcmeVPN").expect("recognised d/ form");
        assert_eq!(bit.canonical, "d/acmevpn");
        assert_eq!(dformat.canonical, "d/acmevpn");
        assert!(bit.subdomain_labels.is_empty());

        let walked = parse_namecoin_network_id("d/acmevpn/eu/west").expect("walks");
        assert_eq!(walked.canonical, "d/acmevpn");
        assert_eq!(walked.subdomain_labels, vec!["eu", "west"]);
    }

    #[test]
    fn parse_namecoin_network_id_rejects_legacy_opaque_ids() {
        assert!(parse_namecoin_network_id("nostr-vpn").is_none());
        assert!(parse_namecoin_network_id("abc123def4567890").is_none());
        assert!(parse_namecoin_network_id("").is_none());
        assert!(parse_namecoin_network_id("d/").is_none());
        assert!(parse_namecoin_network_id("d/-bad").is_none());
        assert!(parse_namecoin_network_id("not.a.bit.ish").is_none());
    }

    #[test]
    fn verify_passes_when_invite_admins_are_subset() {
        let alice = fake_admin(0x11);
        let bob = fake_admin(0x22);
        let chain = ChainNetworkRecord {
            admins: vec![alice.clone(), bob.clone()],
            network_name_hint: None,
        };
        verify_admins_against_chain(&[alice], &chain).expect("subset accepted");
    }

    #[test]
    fn verify_rejects_admin_not_in_chain() {
        let alice = fake_admin(0x11);
        let mallory = fake_admin(0x99);
        let chain = ChainNetworkRecord {
            admins: vec![alice.clone()],
            network_name_hint: None,
        };
        let err = verify_admins_against_chain(&[alice, mallory], &chain).unwrap_err();
        assert!(format!("{err}").contains("not in the chain admin set"));
    }

    #[test]
    fn verify_rejects_empty_invite_admins() {
        let chain = ChainNetworkRecord {
            admins: vec![fake_admin(0x11)],
            network_name_hint: None,
        };
        let err = verify_admins_against_chain(&[], &chain).unwrap_err();
        assert!(format!("{err}").contains("invite admin list is empty"));
    }

    #[test]
    fn verify_rejects_empty_chain_admins() {
        let chain = ChainNetworkRecord {
            admins: vec![],
            network_name_hint: None,
        };
        let err = verify_admins_against_chain(&[fake_admin(0x11)], &chain).unwrap_err();
        assert!(format!("{err}").contains("no admins"));
    }

    #[tokio::test]
    async fn resolve_with_transport_returns_admins_for_valid_record() {
        let alice = fake_admin(0x11);
        let bob = fake_admin(0x22);
        let id = parse_namecoin_network_id("acmevpn.bit").unwrap();
        let transport =
            StubTransport::new(vec![("d/acmevpn", Ok(Some(fake_record(&[&alice, &bob]))))]);
        let record = resolve_with_transport(&transport, &id).await.unwrap();
        assert_eq!(record.admins, vec![alice, bob]);
        assert_eq!(record.network_name_hint.as_deref(), Some("Acme"));
    }

    #[tokio::test]
    async fn resolve_with_transport_walks_subdomain_chain() {
        let alice = fake_admin(0x11);
        let parent = serde_json::json!({
            "map": {
                "eu": {
                    "map": {
                        "west": { "nostr": { "admins": [alice.clone()] } }
                    }
                }
            },
            "nostr": { "admins": [] }
        });
        let id = parse_namecoin_network_id("d/acmevpn/eu/west").unwrap();
        let transport = StubTransport::new(vec![("d/acmevpn", Ok(Some(parent)))]);
        let record = resolve_with_transport(&transport, &id).await.unwrap();
        assert_eq!(record.admins, vec![alice]);
    }

    #[tokio::test]
    async fn resolve_with_transport_fails_for_missing_record() {
        let id = parse_namecoin_network_id("acmevpn.bit").unwrap();
        let transport = StubTransport::new(vec![("d/acmevpn", Ok(None))]);
        let err = resolve_with_transport(&transport, &id).await.unwrap_err();
        assert!(format!("{err}").contains("not found"));
    }

    #[tokio::test]
    async fn resolve_with_transport_fails_for_malformed_record() {
        let id = parse_namecoin_network_id("acmevpn.bit").unwrap();
        let transport = StubTransport::new(vec![(
            "d/acmevpn",
            Ok(Some(
                serde_json::json!({ "nostr": { "admins": "not-an-array" } }),
            )),
        )]);
        let err = resolve_with_transport(&transport, &id).await.unwrap_err();
        assert!(format!("{err}").contains("not an array"));
    }

    #[tokio::test]
    async fn resolve_with_transport_fails_when_admins_missing() {
        let id = parse_namecoin_network_id("acmevpn.bit").unwrap();
        let transport = StubTransport::new(vec![(
            "d/acmevpn",
            Ok(Some(serde_json::json!({ "nostr": {} }))),
        )]);
        let err = resolve_with_transport(&transport, &id).await.unwrap_err();
        assert!(format!("{err}").contains("admins"));
    }
}
