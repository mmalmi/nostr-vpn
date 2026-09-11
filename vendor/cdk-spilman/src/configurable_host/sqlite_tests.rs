use super::test_support::*;
use super::*;

fn make_sqlite() -> SqliteStorage {
    SqliteStorage::open_in_memory().unwrap()
}

#[test]
fn test_funding_roundtrip() {
    let s = make_sqlite();
    assert!(s.get_funding("ch1").is_none());

    let funding = ChannelFunding {
        params_json: r#"{"unit":"sat"}"#.to_string(),
        funding_proofs_json: "[]".to_string(),
        channel_secret_hex: "abcd".to_string(),
        keyset_info_json: "{}".to_string(),
    };
    s.save_funding("ch1", funding.clone()).unwrap();

    let f = s.get_funding("ch1").unwrap();
    assert_eq!(f.params_json, r#"{"unit":"sat"}"#);
    assert_eq!(f.channel_secret_hex, "abcd");

    // Idempotent: second save should not overwrite.
    let funding2 = ChannelFunding {
        params_json: r#"{"unit":"msat"}"#.to_string(),
        funding_proofs_json: "[1]".to_string(),
        channel_secret_hex: "ffff".to_string(),
        keyset_info_json: "{}".to_string(),
    };
    s.save_funding("ch1", funding2).unwrap();
    let f2 = s.get_funding("ch1").unwrap();
    assert_eq!(f2.params_json, r#"{"unit":"sat"}"#); // unchanged
}

#[test]
fn test_balance_monotonic() {
    let s = make_sqlite();
    // Need a channel row first.
    s.save_funding(
        "ch1",
        ChannelFunding {
            params_json: "{}".to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".to_string(),
            keyset_info_json: "{}".to_string(),
        },
    )
    .unwrap();

    assert!(s.get_balance("ch1").is_none()); // balance is 0, signature is ''

    s.update_balance(
        "ch1",
        PaymentProof {
            balance: 20,
            signature: "sig20".to_string(),
        },
    )
    .unwrap();
    assert_eq!(s.get_balance("ch1").unwrap().balance, 20);

    // Lower balance should NOT overwrite.
    s.update_balance(
        "ch1",
        PaymentProof {
            balance: 10,
            signature: "sig10".to_string(),
        },
    )
    .unwrap();
    assert_eq!(s.get_balance("ch1").unwrap().balance, 20);
    assert_eq!(s.get_balance("ch1").unwrap().signature, "sig20");

    // Higher balance should overwrite.
    s.update_balance(
        "ch1",
        PaymentProof {
            balance: 30,
            signature: "sig30".to_string(),
        },
    )
    .unwrap();
    assert_eq!(s.get_balance("ch1").unwrap().balance, 30);
}

#[test]
fn test_usage_increment() {
    let s = make_sqlite();
    assert!(s.get_usage("ch1").is_none());

    let mut inc1 = UsageMap::new();
    inc1.insert("chars".to_string(), 10);
    inc1.insert("requests".to_string(), 1);
    s.increment_usage("ch1", &inc1).unwrap();

    let u = s.get_usage("ch1").unwrap();
    assert_eq!(u["chars"], 10);
    assert_eq!(u["requests"], 1);

    // Increment again.
    let mut inc2 = UsageMap::new();
    inc2.insert("chars".to_string(), 5);
    inc2.insert("requests".to_string(), 2);
    s.increment_usage("ch1", &inc2).unwrap();

    let u2 = s.get_usage("ch1").unwrap();
    assert_eq!(u2["chars"], 15);
    assert_eq!(u2["requests"], 3);
}

#[test]
fn test_channel_lifecycle() {
    let s = make_sqlite();
    s.save_funding(
        "ch1",
        ChannelFunding {
            params_json: "{}".to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".to_string(),
            keyset_info_json: "{}".to_string(),
        },
    )
    .unwrap();

    assert_eq!(s.get_state("ch1"), ChannelState::Open);

    s.mark_closing(
        "ch1",
        ClosingData {
            expiry_timestamp: 1000,
            balance: 50,
            signature: "sig50".to_string(),
        },
    )
    .unwrap();
    assert_eq!(s.get_state("ch1"), ChannelState::Closing);

    let closing = s.get_closing_data("ch1").unwrap();
    assert_eq!(closing.expiry_timestamp, 1000);
    assert_eq!(closing.balance, 50);

    s.mark_closed(
        "ch1",
        ClosedDataView {
            expiry_timestamp: 1000,
            closed_amount: 50,
            value_after_stage1: 50,
            receiver_sum: 40,
            sender_sum: 10,
            receiver_proofs_json: "[]".to_string(),
            sender_proofs_json: "[]".to_string(),
        },
    )
    .unwrap();
    assert_eq!(s.get_state("ch1"), ChannelState::Closed);

    // closing_json should be cleared
    assert!(s.get_closing_data("ch1").is_none());

    let closed = s.get_closed_data("ch1").unwrap();
    assert_eq!(closed.closed_amount, 50);
    assert_eq!(closed.receiver_sum, 40);
    assert_eq!(closed.sender_sum, 10);
}

#[test]
fn test_double_close_rejected() {
    let s = make_sqlite();
    s.save_funding(
        "ch1",
        ChannelFunding {
            params_json: "{}".to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "aa".to_string(),
            keyset_info_json: "{}".to_string(),
        },
    )
    .unwrap();

    let data = ClosedDataView {
        expiry_timestamp: 1000,
        closed_amount: 50,
        value_after_stage1: 50,
        receiver_sum: 40,
        sender_sum: 10,
        receiver_proofs_json: "[]".to_string(),
        sender_proofs_json: "[]".to_string(),
    };
    s.mark_closed("ch1", data.clone()).unwrap();
    let result = s.mark_closed("ch1", data);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already closed"));
}

#[test]
fn test_keyset_roundtrip() {
    let s = make_sqlite();
    let kid: Id = "001b6c716bf42c7e".parse().unwrap();

    assert!(s.get_keyset("http://mint", &kid).is_none());

    s.set_keyset(
        "http://mint",
        kid,
        KeysetCacheEntry {
            info_json: r#"{"id":"001b6c716bf42c7e"}"#.to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();

    let entry = s.get_keyset("http://mint", &kid).unwrap();
    assert_eq!(entry.unit, CurrencyUnit::Sat);
    assert!(entry.active);

    // Update: mark inactive.
    s.set_keyset(
        "http://mint",
        kid,
        KeysetCacheEntry {
            info_json: r#"{"id":"001b6c716bf42c7e"}"#.to_string(),
            active: false,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    let entry2 = s.get_keyset("http://mint", &kid).unwrap();
    assert!(!entry2.active);
}

#[test]
fn test_active_keyset_ids() {
    let s = make_sqlite();
    let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
    let ks2: Id = "00ffedc2dbb87212".parse().unwrap();

    s.set_keyset(
        "http://mint",
        ks1,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    s.set_keyset(
        "http://mint",
        ks2,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: false,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();

    let active = s.get_active_keyset_ids("http://mint", &CurrencyUnit::Sat);
    assert_eq!(active, vec![ks1]);
}

#[test]
fn test_mints_units_keysets() {
    let s = make_sqlite();
    let ks1: Id = "001b6c716bf42c7e".parse().unwrap();
    let ks2: Id = "00818d176a78e7f0".parse().unwrap();

    s.set_keyset(
        "http://mint",
        ks1,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();
    s.set_keyset(
        "http://mint",
        ks2,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Msat,
        },
    )
    .unwrap();

    let muk = s.get_mints_units_keysets();
    assert!(muk["http://mint"]["sat"].contains(&ks1.to_string()));
    assert!(muk["http://mint"]["msat"].contains(&ks2.to_string()));
}

#[test]
fn test_active_units() {
    let s = make_sqlite();
    let ks1: Id = "001b6c716bf42c7e".parse().unwrap();

    assert!(s.get_active_units().is_empty());

    s.set_keyset(
        "http://mint",
        ks1,
        KeysetCacheEntry {
            info_json: "{}".to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .unwrap();

    let units = s.get_active_units();
    assert!(units.contains("sat"));
    assert_eq!(units.len(), 1);
}

#[test]
fn test_end_to_end_with_configurable_host() {
    // End-to-end: construct a ConfigurableHost with SqliteStorage
    let config = ConfigurableHostConfig::from_yaml(TEST_YAML).unwrap();
    let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
    let host = ConfigurableHost::with_storage(config, TEST_SECRET_KEY, storage.clone()).unwrap();

    seed_channel(&host, "ch1", "sat");
    storage
        .update_balance(
            "ch1",
            PaymentProof {
                balance: 0,
                signature: "initial-signature".to_string(),
            },
        )
        .unwrap();
    assert!(host.get_funding("ch1").is_some());

    let ctx = serde_json::json!({"chars": 10, "requests": 1}).to_string();
    host.record_payment(
        "ch1",
        PaymentProof {
            balance: 15,
            signature: "sig15".to_string(),
        },
        &ctx,
    )
    .unwrap();

    assert_eq!(host.get_balance("ch1").unwrap().balance, 15);
    assert_eq!(host.get_usage("ch1").unwrap()["chars"], 10);
}

#[test]
fn test_file_persistence() {
    // Verify data survives across two separate SqliteStorage instances
    // pointing at the same file.
    let dir = std::env::temp_dir().join("spilman_test_persist");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.db");
    let path_str = path.to_str().unwrap();

    // Clean up from any previous run.
    let _ = std::fs::remove_file(&path);

    // Session 1: create and populate.
    {
        let s = SqliteStorage::open(path_str).unwrap();
        s.save_funding(
            "ch1",
            ChannelFunding {
                params_json: r#"{"unit":"sat"}"#.to_string(),
                funding_proofs_json: "[]".to_string(),
                channel_secret_hex: "abcd".to_string(),
                keyset_info_json: "{}".to_string(),
            },
        )
        .unwrap();
        s.update_balance(
            "ch1",
            PaymentProof {
                balance: 42,
                signature: "sig42".to_string(),
            },
        )
        .unwrap();
        let mut inc = UsageMap::new();
        inc.insert("chars".to_string(), 100);
        s.increment_usage("ch1", &inc).unwrap();
    }

    // Session 2: reopen and verify.
    {
        let s = SqliteStorage::open(path_str).unwrap();
        let f = s.get_funding("ch1").unwrap();
        assert_eq!(f.channel_secret_hex, "abcd");
        assert_eq!(s.get_balance("ch1").unwrap().balance, 42);
        assert_eq!(s.get_usage("ch1").unwrap()["chars"], 100);
    }

    // Clean up.
    let _ = std::fs::remove_file(&path);
}
