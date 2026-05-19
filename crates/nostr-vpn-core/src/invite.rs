//! Canonical `nvpn://invite/...` payload.
//!
//! The CLI and the native-app cores both decode/encode invites; both used to
//! ship near-identical copies. This module is the single source of truth for
//! the wire shape (camelCase JSON, version 3) and the `parse_network_invite`
//! / `to_npub` helpers. Higher-level "apply this invite to my config" logic
//! still lives crate-locally because each consumer has its own config model.

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr_sdk::prelude::{PublicKey, ToBech32};
use serde::{Deserialize, Serialize};

use crate::config::normalize_nostr_pubkey;

pub const NETWORK_INVITE_PREFIX: &str = "nvpn://invite/";
pub const NETWORK_INVITE_VERSION: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInvite {
    pub v: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_name: String,
    pub network_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inviter_npub: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inviter_node_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inviter_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    /// Optional Namecoin `.bit` name whose record's `nostr.relays` field
    /// defines the network's discovery relay set. Resolved on import and
    /// via `nvpn relays refresh`; rotating relays requires only one
    /// `name_update` Namecoin transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_record: Option<String>,
}

/// Decode `nvpn://invite/<base64>` (or a bare JSON document) into a normalized
/// `NetworkInvite`. Normalization: trims whitespace, npub-encodes all pubkeys,
/// derives the inviter from the first admin when omitted, drops legacy relay
/// hints, and trims/lowercases the optional `relay_record` Namecoin name.
pub fn parse_network_invite(value: &str) -> Result<NetworkInvite> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("invite code is empty"));
    }

    let mut invite = if trimmed.starts_with('{') {
        serde_json::from_str::<NetworkInvite>(trimmed)
            .context("failed to parse network invite JSON")?
    } else {
        let payload = trimmed
            .strip_prefix(NETWORK_INVITE_PREFIX)
            .unwrap_or(trimmed);
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .context("failed to decode network invite payload")?;
        serde_json::from_slice::<NetworkInvite>(&decoded)
            .context("failed to parse network invite payload")?
    };

    if invite.v != 1 && invite.v != 2 && invite.v != NETWORK_INVITE_VERSION {
        return Err(anyhow!(
            "unsupported invite version {}; expected 1, 2, or {}",
            invite.v,
            NETWORK_INVITE_VERSION
        ));
    }

    invite.network_name = invite.network_name.trim().to_string();
    invite.network_id = invite.network_id.trim().to_string();
    if invite.network_id.is_empty() {
        return Err(anyhow!("invite network id is empty"));
    }

    invite.admins = normalized_invite_pubkeys(&invite.admins)?;
    if invite.inviter_npub.trim().is_empty() {
        invite.inviter_npub = invite
            .admins
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("invite must include at least one admin"))?;
    } else {
        invite.inviter_npub = to_npub(&normalize_nostr_pubkey(&invite.inviter_npub)?);
        if !invite
            .admins
            .iter()
            .any(|admin| admin == &invite.inviter_npub)
        {
            invite.admins.push(invite.inviter_npub.clone());
        }
    }
    if invite.admins.is_empty() {
        invite.admins.push(invite.inviter_npub.clone());
        invite.admins.sort();
        invite.admins.dedup();
    }

    invite.inviter_node_name = invite.inviter_node_name.trim().to_string();
    invite.inviter_endpoints = normalized_invite_strings(&invite.inviter_endpoints);
    invite.participants = normalized_invite_pubkeys(&invite.participants)?;
    if invite.participants.is_empty() && invite.v < NETWORK_INVITE_VERSION {
        invite.participants.push(invite.inviter_npub.clone());
    }
    invite.relays.clear();
    invite.relay_record = invite
        .relay_record
        .as_ref()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());

    Ok(invite)
}

/// Encode a `NetworkInvite` into `nvpn://invite/<base64>`.
pub fn encode_network_invite(invite: &NetworkInvite) -> Result<String> {
    let bytes = serde_json::to_vec(invite).context("failed to encode network invite JSON")?;
    Ok(format!(
        "{NETWORK_INVITE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}

/// Convert a 32-byte hex pubkey to its `npub1...` bech32 form. Returns the
/// original string if it's not valid hex — callers that need a hard error
/// should `normalize_nostr_pubkey` first.
pub fn to_npub(pubkey_hex: &str) -> String {
    PublicKey::parse(pubkey_hex)
        .ok()
        .and_then(|pubkey| pubkey.to_bech32().ok())
        .unwrap_or_else(|| pubkey_hex.to_string())
}

fn normalized_invite_pubkeys(pubkeys: &[String]) -> Result<Vec<String>> {
    let mut normalized = pubkeys
        .iter()
        .map(|pubkey| normalize_nostr_pubkey(pubkey).map(|value| to_npub(&value)))
        .collect::<Result<Vec<_>>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalized_invite_strings(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::Keys;

    fn sample_invite(relay_record: Option<&str>) -> NetworkInvite {
        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        NetworkInvite {
            v: NETWORK_INVITE_VERSION,
            network_name: "Acme".to_string(),
            network_id: "8d4f34f5425bc50e".to_string(),
            inviter_npub: admin_npub.clone(),
            inviter_node_name: "alice".to_string(),
            inviter_endpoints: vec!["192.168.50.10:51820".to_string()],
            admins: vec![admin_npub],
            participants: Vec::new(),
            relays: Vec::new(),
            relay_record: relay_record.map(str::to_string),
        }
    }

    #[test]
    fn roundtrip_with_relay_record() {
        let original = sample_invite(Some("acmevpn.bit"));
        let encoded = encode_network_invite(&original).expect("encode invite");
        let parsed = parse_network_invite(&encoded).expect("parse invite");
        assert_eq!(parsed.relay_record.as_deref(), Some("acmevpn.bit"));
        assert_eq!(parsed.network_id, "8d4f34f5425bc50e");
    }

    #[test]
    fn roundtrip_without_relay_record_stays_unset() {
        let original = sample_invite(None);
        let encoded = encode_network_invite(&original).expect("encode invite");
        let parsed = parse_network_invite(&encoded).expect("parse invite");
        assert!(parsed.relay_record.is_none());
    }

    #[test]
    fn invite_without_relay_record_field_parses() {
        // Mirrors a v3 invite shipped before the relay_record field existed:
        // the JSON document simply omits the key, which must still parse.
        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let raw = serde_json::json!({
            "v": NETWORK_INVITE_VERSION,
            "networkId": "8d4f34f5425bc50e",
            "inviterNpub": admin_npub,
            "admins": [admin_npub],
        })
        .to_string();
        let parsed = parse_network_invite(&raw).expect("legacy invite parses");
        assert!(parsed.relay_record.is_none());
        assert_eq!(parsed.network_id, "8d4f34f5425bc50e");
    }

    #[test]
    fn relay_record_is_trimmed_and_blank_treated_as_none() {
        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let raw = serde_json::json!({
            "v": NETWORK_INVITE_VERSION,
            "networkId": "8d4f34f5425bc50e",
            "inviterNpub": admin_npub,
            "admins": [admin_npub],
            "relayRecord": "  acmevpn.bit  ",
        })
        .to_string();
        let parsed = parse_network_invite(&raw).expect("invite parses");
        assert_eq!(parsed.relay_record.as_deref(), Some("acmevpn.bit"));

        let raw_blank = serde_json::json!({
            "v": NETWORK_INVITE_VERSION,
            "networkId": "8d4f34f5425bc50e",
            "inviterNpub": admin_npub,
            "admins": [admin_npub],
            "relayRecord": "   ",
        })
        .to_string();
        let parsed_blank = parse_network_invite(&raw_blank).expect("invite parses");
        assert!(parsed_blank.relay_record.is_none());
    }

    #[test]
    fn base64_round_trip_is_stable() {
        let original = sample_invite(Some("d/acmevpn"));
        let encoded = encode_network_invite(&original).expect("encode invite");
        // Re-parsing and re-encoding must yield the same string.
        let parsed = parse_network_invite(&encoded).expect("parse invite");
        let reencoded = encode_network_invite(&parsed).expect("re-encode invite");
        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn legacy_relays_field_is_dropped() {
        let admin_npub = Keys::generate()
            .public_key()
            .to_bech32()
            .expect("admin npub");
        let raw = serde_json::json!({
            "v": NETWORK_INVITE_VERSION,
            "networkId": "8d4f34f5425bc50e",
            "inviterNpub": admin_npub,
            "admins": [admin_npub],
            "relays": ["wss://relay.example/"],
        })
        .to_string();
        let parsed = parse_network_invite(&raw).expect("invite parses");
        assert!(parsed.relays.is_empty());
    }
}
