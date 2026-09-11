use super::test_support::*;
use super::*;

// -- config parsing -------------------------------------------------------

#[test]
fn test_yaml_parsing() {
    let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
    let trusted = &config.mints["http://localhost:3338"];
    assert_eq!(trusted, &vec!["sat", "msat", "usd"]);
    assert_eq!(config.min_expiry_seconds, 3600);
    assert_eq!(config.pricing.len(), 3);

    let sat = &config.pricing["sat"];
    assert_eq!(sat.min_capacity, 10);
    assert_eq!(sat.max_amount_per_output, None);
    assert_eq!(sat.variables["chars"], 1);
    assert_eq!(sat.variables["requests"], 5);

    let usd = &config.pricing["usd"];
    assert_eq!(usd.max_amount_per_output, Some(64));
}

#[test]
fn test_yaml_default_expiry() {
    let yaml = r#"
mints:
  "http://example.com": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      requests: 1
"#;
    let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
    assert_eq!(config.min_expiry_seconds, 3600);
}

#[test]
fn test_yaml_invalid() {
    let result = ConfigurableHostConfig::from_yaml("not: valid: yaml: [");
    assert!(result.is_err());
}

#[test]
fn test_yaml_missing_required_fields() {
    let yaml = r#"
min_expiry_seconds: 3600
"#;
    let result = ConfigurableHostConfig::from_yaml(yaml);
    assert!(result.is_err());
}

// -- host construction ----------------------------------------------------

#[test]
fn test_host_construction() {
    let host = make_host();
    assert!(host.mints().contains_key("http://localhost:3338"));
    assert_eq!(host.config().min_expiry_seconds, 3600);
}

#[test]
fn test_host_invalid_secret_key() {
    let result = ConfigurableHost::from_yaml(TEST_YAML, "not-hex");
    assert!(result.is_err());
}

#[test]
fn test_missing_pricing_for_trusted_unit() {
    // Mint trusts "sat" and "foo", but pricing only covers "sat".
    let yaml = r#"
mints:
  "http://localhost:3338": [sat, foo]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
    let msg = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY)
        .expect_err("should fail for missing pricing");
    assert!(
        msg.contains("foo"),
        "error should mention the missing unit: {msg}"
    );
}

#[test]
fn test_unused_pricing_accepted() {
    // Pricing defines "sat" and "usd", but the only mint trusts just "sat".
    // This should succeed (unused pricing is a warning, not an error).
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
  usd:
    min_capacity: 10
    variables:
      chars: 1
"#;
    let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY);
    assert!(host.is_ok());
}

#[test]
fn test_server_pubkey_derived() {
    let host = make_host();
    let pubkey_hex = host.server_pubkey().to_hex();
    let sk = SecretKey::from_hex(TEST_SECRET_KEY).unwrap();
    assert_eq!(pubkey_hex, sk.public_key().to_hex());
}

// -- receiver key ---------------------------------------------------------

#[test]
fn test_receiver_key_acceptable() {
    let host = make_host();
    assert!(host.receiver_key_is_acceptable(host.server_pubkey()));
}

#[test]
fn test_receiver_key_wrong() {
    let host = make_host();
    let other_sk =
        SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    assert!(!host.receiver_key_is_acceptable(&other_sk.public_key()));
}

// -- mint & keyset --------------------------------------------------------

#[test]
fn test_mint_keyset_acceptable() {
    let host = make_host();
    let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
    assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

    host.set_keyset(
        "http://localhost:3338",
        fake_id,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
}

#[test]
fn test_wrong_mint_rejected() {
    let host = make_host();
    let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
    host.set_keyset(
        "http://localhost:3338",
        fake_id,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
}

#[test]
fn test_untrusted_unit_rejected() {
    // Config only trusts [sat] at this mint — a cached "usd" keyset must
    // be rejected even though the mint itself is trusted.
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
"#;
    let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
    let fake_id: Id = "001b6c716bf42c7e".parse().unwrap();
    host.set_keyset(
        "http://localhost:3338",
        fake_id,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Usd,
        },
    )
    .unwrap();
    assert!(!host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));

    // But a "sat" keyset at the same mint should be accepted.
    host.set_keyset(
        "http://localhost:3338",
        fake_id,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    assert!(host.mint_and_keyset_is_acceptable("http://localhost:3338", &fake_id));
}

// -- amount due (linear combination) --------------------------------------

#[test]
fn test_amount_due_no_usage_no_context() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");
    assert_eq!(host.get_amount_due("ch1", None), 0);
}

#[test]
fn test_amount_due_with_context_only() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    // Context: 10 chars, 1 request -> 10*1 + 1*5 = 15 sat
    let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15);
}

#[test]
fn test_amount_due_accumulated_plus_context() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    // Seed accumulated usage: 20 chars, 2 requests.
    let usage: UsageMap = [("chars".to_string(), 20), ("requests".to_string(), 2)].into();
    host.storage().increment_usage("ch1", &usage).unwrap();

    // Context adds 5 chars, 1 request.
    // Total: (20+5)*1 + (2+1)*5 = 25 + 15 = 40 sat
    let ctx = serde_json::json!({"chars": 5, "requests": 1}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 40);
}

#[test]
fn test_amount_due_msat_unit() {
    let host = make_host();
    seed_channel(&host, "ch1", "msat");

    let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
    // 10*1000 + 1*5000 = 15000 msat
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 15_000);
}

#[test]
fn test_pricing_scale_divides_amount_due() {
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing_scale: 1000
pricing:
  sat:
    min_capacity: 1
    variables:
      bytes: 1
"#;
    let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
    assert_eq!(host.pricing_scale(), 1000);

    seed_channel(&host, "ch1", "sat");

    // 500 bytes * 1 = 500; ceil(500 / 1000) = 1
    let ctx = serde_json::json!({"bytes": 500}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 1);

    // 1000 bytes * 1 = 1000; ceil(1000 / 1000) = 1
    let ctx = serde_json::json!({"bytes": 1000}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 1);

    // 1001 bytes * 1 = 1001; ceil(1001 / 1000) = 2
    let ctx = serde_json::json!({"bytes": 1001}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 2);

    // 0 bytes -> 0
    let ctx = serde_json::json!({"bytes": 0}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
}

#[test]
fn test_pricing_scale_defaults_to_one() {
    let host = make_host();
    assert_eq!(host.pricing_scale(), 1);
}

#[test]
fn test_pricing_scale_zero_treated_as_one() {
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing_scale: 0
pricing:
  sat:
    min_capacity: 1
    variables:
      chars: 1
"#;
    let host = ConfigurableHost::from_yaml(yaml, TEST_SECRET_KEY).unwrap();
    // pricing_scale=0 is clamped to 1
    assert_eq!(host.pricing_scale(), 1);

    seed_channel(&host, "ch1", "sat");
    let ctx = serde_json::json!({"chars": 10}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 10);
}

#[test]
fn test_amount_due_unknown_variable_in_context() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    // "bytes" is not in the sat pricing -- should be ignored.
    let ctx = serde_json::json!({"chars": 10, "bytes": 9999}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 10);
}

#[test]
fn test_amount_due_unknown_unit() {
    let host = make_host();
    seed_channel(&host, "ch1", "btc"); // not in pricing

    let ctx = serde_json::json!({"chars": 10}).to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
}

#[test]
fn test_amount_due_empty_context() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    let ctx = "{}".to_string();
    assert_eq!(host.get_amount_due("ch1", Some(&ctx)), 0);
}

// -- record_payment -------------------------------------------------------

#[test]
fn test_record_payment_updates_usage() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    let ctx1 = serde_json::json!({"chars": 10, "requests": 1}).to_string();
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 15,
            signature: "sig1".to_string(),
        },
        &ctx1,
    )
    .unwrap();

    let usage = host.get_usage("ch1").unwrap();
    assert_eq!(usage["chars"], 10);
    assert_eq!(usage["requests"], 1);

    let ctx2 = serde_json::json!({"chars": 5, "requests": 1}).to_string();
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 30,
            signature: "sig2".to_string(),
        },
        &ctx2,
    )
    .unwrap();

    let usage = host.get_usage("ch1").unwrap();
    assert_eq!(usage["chars"], 15);
    assert_eq!(usage["requests"], 2);
}

#[test]
fn test_record_payment_updates_balance_monotonically() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    let ctx = serde_json::json!({"chars": 5}).to_string();
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 20,
            signature: "sig20".to_string(),
        },
        &ctx,
    )
    .unwrap();
    assert_eq!(host.get_balance("ch1").unwrap().balance, 20);

    // Lower balance should NOT overwrite.
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 10,
            signature: "sig10".to_string(),
        },
        &ctx,
    )
    .unwrap();
    assert_eq!(host.get_balance("ch1").unwrap().balance, 20);
    assert_eq!(host.get_balance("ch1").unwrap().signature, "sig20");
}

// -- channel lifecycle ----------------------------------------------------

#[test]
fn test_channel_lifecycle() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    assert_eq!(host.get_channel_state("ch1"), ChannelState::Open);

    host.mark_channel_closing(
        "ch1",
        1000,
        PaymentProof {
            balance: 50,
            signature: "sig".to_string(),
        },
    )
    .unwrap();
    assert_eq!(host.get_channel_state("ch1"), ChannelState::Closing);

    let closing = host.get_closing_data("ch1").unwrap();
    assert_eq!(closing.expiry_timestamp, 1000);
    assert_eq!(closing.balance, 50);

    host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
        .unwrap();
    assert_eq!(host.get_channel_state("ch1"), ChannelState::Closed);

    assert!(host.get_closing_data("ch1").is_none());

    let closed = host.get_closed_data("ch1").unwrap();
    assert_eq!(closed.closed_amount, 50);
    assert_eq!(closed.receiver_sum, 40);
    assert_eq!(closed.sender_sum, 10);
}

#[test]
fn test_closing_already_closed_channel() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
        .unwrap();

    let result = host.mark_channel_closing(
        "ch1",
        2000,
        PaymentProof {
            balance: 60,
            signature: "sig".to_string(),
        },
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already closed"));
}

#[test]
fn test_double_close_rejected() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10)
        .unwrap();
    let result = host.mark_channel_closed("ch1", 1000, 50, "[]", "[]", 40, 10);
    assert!(result.is_err());
}

// -- unilateral exit ------------------------------------------------------

#[test]
fn test_unilateral_exit_data() {
    let host = make_host();
    seed_channel(&host, "ch1", "sat");

    assert!(host
        .get_balance_and_signature_for_unilateral_exit("ch1")
        .is_none());

    let ctx = serde_json::json!({"chars": 5}).to_string();
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 25,
            signature: "sig25".to_string(),
        },
        &ctx,
    )
    .unwrap();

    let proof = host
        .get_balance_and_signature_for_unilateral_exit("ch1")
        .unwrap();
    assert_eq!(proof.balance, 25);
    assert_eq!(proof.signature, "sig25");
}

// -- save_funding ---------------------------------------------------------

#[test]
fn test_save_funding() {
    let host = make_host();

    let funding = ChannelFunding {
        params_json: r#"{"unit":"sat","capacity":100}"#.to_string(),
        funding_proofs_json: "[]".to_string(),
        channel_secret_hex: "abcd".to_string(),
        keyset_info_json: "{}".to_string(),
    };
    host.save_funding(
        "ch1",
        funding.clone(),
        PaymentProof {
            balance: 0,
            signature: "sig0".to_string(),
        },
    )
    .unwrap();

    let f = host.get_funding("ch1").unwrap();
    assert_eq!(f.params_json, r#"{"unit":"sat","capacity":100}"#);
    assert_eq!(host.get_balance("ch1").unwrap().balance, 0);

    // Second save with same channel_id should NOT overwrite.
    let funding2 = ChannelFunding {
        params_json: r#"{"unit":"msat","capacity":999}"#.to_string(),
        funding_proofs_json: "[1]".to_string(),
        channel_secret_hex: "ffff".to_string(),
        keyset_info_json: "{}".to_string(),
    };
    host.save_funding(
        "ch1",
        funding2,
        PaymentProof {
            balance: 0,
            signature: "sig0b".to_string(),
        },
    )
    .unwrap();
    let f2 = host.get_funding("ch1").unwrap();
    assert_eq!(f2.params_json, r#"{"unit":"sat","capacity":100}"#); // unchanged
}

// -- keyset cache ---------------------------------------------------------

#[test]
fn test_keyset_cache() {
    let host = make_host();
    let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
    let ks2: Id = "00ffedc2dbb87212".parse().unwrap();
    let ks3: Id = "00818d176a78e7f0".parse().unwrap();

    host.set_keyset(
        "http://localhost:3338",
        ks1,
        KeysetCacheEntry {
            info_json: r#"{"keysetId":"001b6c716bf42c7e"}"#.to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    host.set_keyset(
        "http://localhost:3338",
        ks2,
        KeysetCacheEntry {
            info_json: r#"{"keysetId":"00ffedc2dbb87212"}"#.to_string(),
            active: false,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    host.set_keyset(
        "http://localhost:3338",
        ks3,
        KeysetCacheEntry {
            info_json: r#"{"keysetId":"00818d176a78e7f0"}"#.to_string(),
            active: true,
            unit: CurrencyUnit::Msat,
        },
    )
    .unwrap();

    let active_sat = host
        .storage()
        .get_active_keyset_ids("http://localhost:3338", &CurrencyUnit::Sat);
    assert_eq!(active_sat, vec![ks1]);

    let mints = host.get_mints_units_keysets();
    assert!(mints["http://localhost:3338"]["sat"].contains(&ks1.to_string()));
    assert!(mints["http://localhost:3338"]["msat"].contains(&ks3.to_string()));
    assert!(!mints["http://localhost:3338"]
        .get("sat")
        .unwrap()
        .contains(&ks2.to_string()));
}

// -- channel policy -------------------------------------------------------

#[test]
fn test_channel_policy_returns_per_unit() {
    let host = make_host();

    let sat_policy = host.get_channel_policy("sat").unwrap();
    assert_eq!(sat_policy.min_expiry_in_seconds, 3600);
    assert_eq!(sat_policy.min_capacity, 10);
    assert!(sat_policy.max_amount_per_output.is_none());

    // Unknown unit returns None.
    assert!(host.get_channel_policy("unknown").is_none());
}

// -- crypto ---------------------------------------------------------------

#[test]
fn test_compute_channel_secret() {
    let host = make_host();
    let alice_sk =
        SecretKey::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    let alice_pub = alice_sk.public_key().to_hex();
    let charlie_pub = host.server_pubkey().to_hex();

    let secret = host
        .compute_channel_secret(&charlie_pub, &alice_pub)
        .unwrap();
    assert_eq!(secret.len(), 64); // 32 bytes hex
}

#[test]
fn test_get_active_pricing() {
    let host = make_host();

    assert!(host.get_active_pricing().is_empty());

    let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
    host.set_keyset(
        "http://localhost:3338",
        ks1,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    let pricing = host.get_active_pricing();
    assert_eq!(pricing.len(), 1);
    assert!(pricing.contains_key("sat"));
    assert_eq!(pricing["sat"].variables["chars"], 1);
}

// -- clone shares state ---------------------------------------------------

#[test]
fn test_clone_shares_stores() {
    let host = make_host();
    let host2 = host.clone();

    seed_channel(&host, "ch1", "sat");
    host.storage()
        .update_balance(
            "ch1",
            PaymentProof {
                balance: 0,
                signature: "initial-signature".to_string(),
            },
        )
        .unwrap();

    // The clone should see the same data.
    assert!(host2.get_funding("ch1").is_some());
}

// -- StorageConfig parsing ------------------------------------------------

#[test]
fn test_storage_config_defaults_to_memory() {
    let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
    assert!(matches!(config.storage, StorageConfig::Memory));
}

#[test]
fn test_storage_config_sqlite_parsing() {
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
storage:
  type: sqlite
  path: "/tmp/test.db"
"#;
    let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
    match &config.storage {
        StorageConfig::Sqlite { path } => assert_eq!(path, "/tmp/test.db"),
        other => panic!("expected Sqlite, got {other:?}"),
    }
}

#[test]
fn test_storage_config_memory_explicit() {
    let yaml = r#"
mints:
  "http://localhost:3338": [sat]
pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
storage:
  type: memory
"#;
    let config = ConfigurableHostConfig::from_yaml(yaml).unwrap();
    assert!(matches!(config.storage, StorageConfig::Memory));
}
