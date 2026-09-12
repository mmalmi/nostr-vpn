#[test]
fn all_internet_mode_switches_persist_and_reselect_through_native_actions() {
    use nostr_sdk::prelude::Keys;
    let modes = ["direct", "private_vpn", "wireguard", "paid_automatic", "paid_manual"];
    let peer = Keys::generate().public_key().to_hex();
    let seller = Keys::generate().public_key().to_hex();
    for from in modes {
        for to in modes {
            let dir = unique_service_test_dir("nvpn-all-internet-modes");
            let mut runtime = NativeAppRuntime::from_startup_error(&anyhow!("test runtime"));
            runtime.startup_error = None;
            runtime.last_error.clear();
            runtime.mobile_runtime = true;
            runtime.config_path = dir.join("config.toml");
            create_test_network(&mut runtime, "Mode switch test");
            runtime.config.active_network_mut().devices.push(peer.clone());
            runtime.config.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.into();
            runtime.config.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.into();
            runtime.config.wireguard_exit.address = "10.99.99.2/32".into();
            runtime.config.wireguard_exit.endpoint = "192.0.2.1:51820".into();
            runtime.config.save(&runtime.config_path).unwrap();
            // Every directed pair, plus choosing the current item again. This
            // uses the same action/save/load/state boundary as the native UI.
            for mode in [from, to, to] {
                let exit = match mode {
                    "private_vpn" => Some(peer.clone()),
                    "paid_manual" => Some(seller.clone()),
                    _ => None,
                };
                runtime.dispatch(NativeAppAction::UpdateSettings {
                    patch: SettingsPatch {
                        internet_source: Some(mode.into()),
                        exit_node: exit.clone(),
                        ..SettingsPatch::default()
                    },
                });
                assert!(runtime.last_error.is_empty(), "{from} -> {to}: {}", runtime.last_error);
                runtime.reload_config_from_disk().unwrap();
                let saved = AppConfig::load(&runtime.config_path).unwrap();
                assert_eq!(saved.internet_source.as_str(), mode, "{from} -> {to}");
                assert_eq!(saved.exit_node, exit.unwrap_or_default(), "{from} -> {to}");
                assert_eq!(saved.exit_node_public_paid_exit, mode == "paid_manual");
                assert_eq!(saved.wireguard_exit.enabled, mode == "wireguard");
                assert_eq!(runtime.state().internet_source, mode);
                // Switching away must preserve the imported upstream for reuse.
                assert_eq!(saved.wireguard_exit.private_key, TEST_WG_PRIVATE_KEY);
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
