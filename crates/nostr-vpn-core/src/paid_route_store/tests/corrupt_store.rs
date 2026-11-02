use super::{persistence::*, *};

#[test]
fn corrupt_paid_route_store_fails_every_load_and_keeps_bytes() {
    let scratch = ScratchDir::new("corrupt-store");

    let truncated_path = scratch.path().join("truncated.json");
    let truncated_bytes = r#"{"version": 7, "channels": {"#;
    fs::write(&truncated_path, truncated_bytes).expect("write truncated store");
    let first = load_paid_route_store(&truncated_path).expect_err("first load must fail");
    let second = load_paid_route_store(&truncated_path).expect_err("second load must fail");
    assert_eq!(first.to_string(), second.to_string());
    assert!(
        first.to_string().contains("unreadable"),
        "unexpected error: {first:#}"
    );
    assert_eq!(
        fs::read(&truncated_path).expect("read truncated store"),
        truncated_bytes.as_bytes()
    );

    let typed_path = scratch.path().join("typed.json");
    let typed_bytes = r#"{"version": 7, "wallet": {"mints": "not-a-list"}}"#;
    fs::write(&typed_path, typed_bytes).expect("write typed store");
    assert!(load_paid_route_store(&typed_path).is_err());
    assert!(load_paid_route_store(&typed_path).is_err());
    assert_eq!(
        fs::read(&typed_path).expect("read typed store"),
        typed_bytes.as_bytes()
    );

    // Removing the corrupt file is the documented recovery path.
    fs::remove_file(&truncated_path).expect("remove truncated store");
    assert_eq!(
        load_paid_route_store(&truncated_path).expect("load default after removal"),
        PaidRouteStore::default()
    );
}

#[test]
fn valid_paid_route_store_still_loads_unchanged() {
    let scratch = ScratchDir::new("valid-store");
    let store_path = scratch.path().join("paid-routes.json");
    let mut store = PaidRouteStore::default();
    assert!(store.upsert_wallet_mint("https://mint.minibits.cash/Bitcoin", "Minibits", None, 99));
    fs::write(
        &store_path,
        serde_json::to_vec(&store).expect("serialize store"),
    )
    .expect("write valid store");

    assert_eq!(
        load_paid_route_store(&store_path).expect("load valid store"),
        store
    );
    assert_eq!(
        fs::read(&store_path).expect("read valid store"),
        serde_json::to_vec(&store).expect("serialize store")
    );
}
