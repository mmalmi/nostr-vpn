#[cfg(all(feature = "paid-exit", unix))]
#[test]
fn wallet_history_reads_daemon_activity_without_refreshing_mints_or_losing_invoice() {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt as _;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-wallet-history-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let script_path = dir.join("fake-nvpn");
    let response_path = dir.join("response.json");
    let calls_path = dir.join("calls.txt");
    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncat '{}'\n",
            calls_path.display(),
            response_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut runtime = NativeAppRuntime::new(dir.to_str().unwrap(), String::new()).unwrap();
    runtime.nvpn_bin = Some(script_path);
    runtime.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
        kind: "topup".to_string(),
        payment_request: "current-unpaid-invoice".to_string(),
        ..Default::default()
    };
    let activity = json!({"activity": [
        {"id":"older", "kind":"top_up", "status":"expired", "mint_url":"https://old.example",
         "unit":"sat", "amount_sat":100, "created_at_unix":10, "payment_request":"private-invoice"},
        {"id":"newer", "kind":"token_send", "status":"pending", "mint_url":"https://new.example",
         "unit":"sat", "amount_sat":5, "fee_sat":1, "created_at_unix":20, "token":"private-token"}
    ]});
    fs::write(&response_path, activity.to_string()).unwrap();
    runtime.dispatch(NativeAppAction::RefreshPaidRouteWalletHistory);
    let history = runtime.state().paid_route_market.wallet.history;
    assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
    assert!(history.loaded);
    assert_eq!(history.entries.len(), 2);
    assert_eq!(history.entries[0].id, "newer");
    assert_eq!(history.entries[0].status, "pending");
    assert_eq!(history.entries[0].fee_sat, 1);
    assert_eq!(history.entries[1].status, "expired");
    let public_history = serde_json::to_string(&history).unwrap();
    assert!(!public_history.contains("private-token"));
    assert!(!public_history.contains("private-invoice"));
    assert_eq!(
        runtime.paid_route_wallet_last_action.payment_request,
        "current-unpaid-invoice"
    );
    let calls = fs::read_to_string(&calls_path).unwrap();
    assert!(calls.contains("--json show --activity"), "{calls}");
    assert!(!calls.contains("--refresh"), "{calls}");
    assert!(!dir.join("cashu/wallet.lock").exists());

    // A failed refresh keeps the last known entries and exposes the error.
    fs::write(&response_path, "unavailable").unwrap();
    runtime.dispatch(NativeAppAction::RefreshPaidRouteWalletHistory);
    let failed = runtime.state().paid_route_market.wallet.history;
    assert_eq!(failed.entries, history.entries);
    assert_ne!(failed.error, "");

    // An empty response is a successfully loaded empty wallet, not a spinner.
    fs::write(&response_path, r#"{"activity":[]}"#).unwrap();
    runtime.dispatch(NativeAppAction::RefreshPaidRouteWalletHistory);
    let empty = runtime.state().paid_route_market.wallet.history;
    assert!(empty.loaded);
    assert_eq!(empty.entries, [] as [crate::native_state::NativePaidRouteWalletActivityState; 0]);
    assert_eq!(empty.error, "");
    drop(runtime);
    fs::remove_dir_all(dir).unwrap();
}
