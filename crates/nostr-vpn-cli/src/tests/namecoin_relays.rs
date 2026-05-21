use crate::*;
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::invite::{
    NETWORK_INVITE_VERSION, NetworkInvite, encode_network_invite, parse_network_invite,
};
use nostr_vpn_core::namecoin_resolver::{NamecoinTransport, resolve_relays};

use async_trait::async_trait;

struct StaticTransport {
    value: String,
}

#[async_trait]
impl NamecoinTransport for StaticTransport {
    async fn get_name_value(&self, _name_key: &str) -> anyhow::Result<String> {
        Ok(self.value.clone())
    }
}

#[test]
fn create_invite_round_trip_carries_relay_record() {
    let admin_npub = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("admin npub");
    let invite = NetworkInvite {
        v: NETWORK_INVITE_VERSION,
        network_name: String::new(),
        network_id: "8d4f34f5425bc50e".to_string(),
        inviter_npub: admin_npub.clone(),
        inviter_node_name: String::new(),
        inviter_endpoints: Vec::new(),
        admins: vec![admin_npub],
        participants: Vec::new(),
        relays: Vec::new(),
        relay_record: Some("acmevpn.bit".to_string()),
    };
    let encoded = encode_network_invite(&invite).expect("encode");
    let parsed = parse_network_invite(&encoded).expect("parse");
    assert_eq!(parsed.relay_record.as_deref(), Some("acmevpn.bit"));
}

#[tokio::test]
async fn import_invite_with_relay_record_applies_resolved_relays() {
    let admin_npub = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("admin npub");
    let invite = NetworkInvite {
        v: NETWORK_INVITE_VERSION,
        network_name: "Acme".to_string(),
        network_id: "8d4f34f5425bc50e".to_string(),
        inviter_npub: admin_npub.clone(),
        inviter_node_name: "alice".to_string(),
        inviter_endpoints: Vec::new(),
        admins: vec![admin_npub],
        participants: Vec::new(),
        relays: Vec::new(),
        relay_record: Some("acmevpn.bit".to_string()),
    };
    let encoded = encode_network_invite(&invite).expect("encode");
    let parsed = parse_network_invite(&encoded).expect("parse");

    let mut config = AppConfig::generated();
    // Pre-seed the global relays with something we expect to be replaced.
    config.nostr.relays = vec!["wss://stale.example/".to_string()];

    apply_network_invite_to_active_network(&mut config, &parsed).expect("apply invite");

    // Network must remember the anchoring record so refresh works later.
    assert_eq!(
        config.active_network().relay_record.as_deref(),
        Some("acmevpn.bit"),
    );

    // Resolve via a static mock transport — mirrors what the CLI does
    // synchronously after `apply_network_invite_to_active_network`.
    let record = config.active_network().relay_record.clone().unwrap();
    let transport = StaticTransport {
        value: r#"{"nostr":{"relays":["wss://relay.acme/","wss://r2.example/"]}}"#.to_string(),
    };
    let resolved = resolve_relays(&transport, &record)
        .await
        .expect("resolve relays");
    crate::network_signaling::apply_resolved_discovery_relays(
        &mut config,
        &record,
        resolved.clone(),
    );

    assert_eq!(
        resolved,
        vec![
            "wss://relay.acme/".to_string(),
            "wss://r2.example/".to_string(),
        ]
    );
    // Apply path goes through ensure_defaults during normal CLI save; the
    // raw apply call should set the relays verbatim and lose the stale entry.
    assert_eq!(
        config.nostr.relays,
        vec![
            "wss://relay.acme/".to_string(),
            "wss://r2.example/".to_string(),
        ]
    );
}

#[tokio::test]
async fn create_invite_includes_persisted_relay_record() {
    let admin_npub = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("admin npub");
    let mut config = AppConfig::generated();
    let active_id = config.active_network().id.clone();
    if let Some(network) = config.network_by_id_mut(&active_id) {
        network.network_id = "8d4f34f5425bc50e".to_string();
        network.admins = vec![
            nostr_vpn_core::config::normalize_nostr_pubkey(&admin_npub).expect("normalize admin"),
        ];
        network.invite_inviter = network.admins[0].clone();
        network.relay_record = Some("acmevpn.bit".to_string());
    }

    let encoded = active_network_invite_code(&config).expect("invite");
    let parsed = parse_network_invite(&encoded).expect("parse invite");
    assert_eq!(parsed.relay_record.as_deref(), Some("acmevpn.bit"));
}
