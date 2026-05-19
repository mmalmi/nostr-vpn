//! Integration tests proving the CLI roster/init paths accept `.bit`
//! aliases when handed a [`MockResolver`].

use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_namecoin::MockResolver;

use crate::config_bootstrap::apply_participants_override_async;
use crate::namecoin_resolver::ResolverHandle;

fn fresh_config() -> AppConfig {
    let mut config = AppConfig::generated();
    config.ensure_defaults();
    config
}

fn random_pubkey_hex() -> (String, String) {
    let keys = Keys::generate();
    let hex = keys.public_key().to_hex();
    let npub = keys.public_key().to_bech32().unwrap();
    (hex, npub)
}

#[tokio::test]
async fn add_participant_via_bit_alias_resolves_to_hex_and_records_alias() {
    let (hex, _npub) = random_pubkey_hex();

    let mock = MockResolver::new();
    mock.insert("alice@example.bit", hex.clone());
    let handle = ResolverHandle::from_mock(mock);

    let mut config = fresh_config();
    apply_participants_override_async(
        &mut config,
        vec!["alice@example.bit".to_string()],
        Some(&handle),
    )
    .await
    .expect("resolve and apply");

    let network = config.active_network();
    assert!(
        network.participants.iter().any(|p| p == &hex),
        "expected canonical hex in participants: {:?}",
        network.participants
    );
    assert_eq!(
        network.aliases.get(&hex).map(String::as_str),
        Some("alice@example.bit"),
        "expected stored alias for participant"
    );
}

#[tokio::test]
async fn apex_alias_resolves_through_resolver() {
    let (hex, _npub) = random_pubkey_hex();

    let mock = MockResolver::new();
    mock.insert("example.bit", hex.clone());
    let handle = ResolverHandle::from_mock(mock);

    let mut config = fresh_config();
    apply_participants_override_async(&mut config, vec!["example.bit".to_string()], Some(&handle))
        .await
        .expect("resolve and apply");

    assert!(config.active_network().participants.contains(&hex));
    assert_eq!(
        config
            .active_network()
            .aliases
            .get(&hex)
            .map(String::as_str),
        Some("example.bit"),
    );
}

#[tokio::test]
async fn npub_input_still_works_with_alias_path() {
    let (hex, npub) = random_pubkey_hex();
    let mock = MockResolver::new();
    let handle = ResolverHandle::from_mock(mock);

    let mut config = fresh_config();
    apply_participants_override_async(&mut config, vec![npub.clone()], Some(&handle))
        .await
        .expect("resolve and apply");

    assert!(
        config.active_network().participants.contains(&hex),
        "npub should normalize to hex"
    );
    assert!(
        config.active_network().aliases.is_empty(),
        "npub input must not record an alias"
    );
}

#[tokio::test]
async fn unknown_bit_alias_surfaces_clear_error() {
    let mock = MockResolver::new();
    let handle = ResolverHandle::from_mock(mock);

    let mut config = fresh_config();
    let err = apply_participants_override_async(
        &mut config,
        vec!["ghost@nope.bit".to_string()],
        Some(&handle),
    )
    .await
    .expect_err("unknown alias should fail");

    let message = err.to_string();
    assert!(
        message.contains("ghost@nope.bit"),
        "error should mention the alias, got: {message}"
    );
}

#[tokio::test]
async fn alias_without_resolver_errors_cleanly() {
    let mut config = fresh_config();
    let err =
        apply_participants_override_async(&mut config, vec!["alice@example.bit".to_string()], None)
            .await
            .expect_err("missing resolver must fail");

    let message = err.to_string();
    assert!(
        message.contains("alice@example.bit"),
        "error should mention the alias, got: {message}"
    );
}
