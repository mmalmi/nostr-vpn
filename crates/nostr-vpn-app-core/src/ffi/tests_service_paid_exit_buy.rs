    #[cfg(feature = "paid-exit")]
    fn approve_manual_provider_mint(
        runtime: &mut NativeAppRuntime,
        seller_npub: &str,
        offer_config: &nostr_vpn_core::paid_routes::PaidExitConfig,
        store_path: &Path,
    ) -> nostr_vpn_core::paid_route_store::PaidRouteStore {
        use nostr_vpn_core::paid_route_store::{load_paid_route_store, update_paid_route_store};
        use nostr_vpn_core::paid_routes::ManualPaidExitProvider;

        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: seller_npub.to_string(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(runtime.config.manual_paid_exit_provider.npub, seller_npub);
        assert!(runtime.config.manual_paid_exit_provider.mint.is_empty());
        assert!(
            load_paid_route_store(store_path)
                .expect("load wallet after bare npub")
                .wallet
                .mints
                .is_empty(),
            "a bare provider npub must not approve a mint"
        );

        let provider_link = ManualPaidExitProvider::seller_link(seller_npub, offer_config)
            .expect("seller link");
        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: provider_link.clone(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let mut store = load_paid_route_store(store_path).expect("load approved wallet mint");
        assert_eq!(store.wallet.mints.len(), 1);

        store.wallet.mints[0].label = "Minibits".to_string();
        store.wallet.mints[0].balance_msat = Some(7_000);
        store.wallet.mints[0].last_checked_unix = 123;
        update_paid_route_store(store_path, |target| {
            *target = store;
            Ok(())
        })
        .expect("persist wallet metadata");
        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: provider_link,
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        let store = load_paid_route_store(store_path).expect("reload approved wallet mint");
        assert_eq!(store.wallet.mints[0].label, "Minibits");
        assert_eq!(store.wallet.mints[0].balance_msat, Some(7_000));
        assert_eq!(store.wallet.mints[0].last_checked_unix, 123);
        store
    }

    #[cfg(feature = "paid-exit")]
    fn assert_paid_route_activation_requires_fresh_end_to_end_probe(
        runtime: &mut NativeAppRuntime,
        store_path: &Path,
        seller: &Keys,
        seller_npub: &str,
    ) {
        use nostr_vpn_core::paid_route_store::{load_paid_route_store, update_paid_route_store};

        let store = load_paid_route_store(store_path).expect("load paid route store");
        let session = store.sessions.values().next().expect("buyer session");
        let session_id = session.session.session_id.clone();
        let lease_id = session.session.lease_id.clone();
        assert!(
            store
                .buyer_session_allows_routing(&session_id, unix_timestamp())
                .expect("route decision")
        );
        assert_eq!(
            store
                .buyer_session_seller_npub(&session_id)
                .expect("session seller"),
            seller_npub
        );
        let state = runtime.state();
        assert!(!state.exit_node_active);
        assert!(!state.exit_node_blocked);
        assert!(state.exit_node_status_text.ends_with("Pending"));

        update_paid_route_store(store_path, |store| {
            store.acknowledge_buyer_session_open(
                &seller.public_key().to_hex(),
                &lease_id,
                unix_timestamp(),
            )?;
            Ok(())
        })
        .expect("acknowledge seller admission");
        let state = runtime.state();
        assert!(
            !state.exit_node_active,
            "admission without an end-to-end probe is pending"
        );
        assert!(state.exit_node_status_text.ends_with("Pending"));

        update_paid_route_store(store_path, |store| {
            store.update_session_probe(
                nostr_vpn_core::paid_route_store::UpdatePaidRouteSessionProbeRequest {
                    session_id: session_id.clone(),
                    realized_exit_ip: Some("198.51.100.42".to_string()),
                    observed_country_code: None,
                    observed_asn: None,
                    quality: None,
                    now_unix: unix_timestamp(),
                },
            )?;
            Ok(())
        })
        .expect("record fresh end-to-end health probe");
        runtime.daemon_state = Some(DaemonRuntimeState {
            vpn_enabled: true,
            vpn_active: true,
            peers: Vec::new(),
            ..DaemonRuntimeState::default()
        });
        let state = runtime.state();
        assert!(
            state.exit_node_active,
            "a public paid seller does not need to be in the private peer roster"
        );
        assert!(!state.exit_node_blocked);
        assert!(
            state
                .exit_node_status_text
                .ends_with("198.51.100.42 · Connected"),
            "{}",
            state.exit_node_status_text
        );
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn mobile_manual_provider_link_waits_for_a_signed_offer_and_uses_its_exact_terms() {
        use nostr_vpn_core::paid_route_store::{
            load_paid_route_store, paid_route_store_file_path, upsert_paid_route_offer,
        };
        use nostr_vpn_core::paid_routes::{
            ManualPaidExitProvider, PaidExitConfig,
            signed_paid_exit_offer_from_config_with_receiver,
        };

        let dir = unique_service_test_dir("nvpn-app-core-manual-provider-link");
        let error = anyhow!("test runtime");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Manual provider link test");
        runtime.config.save(&runtime.config_path).expect("save config");

        let seller = Keys::generate();
        let seller_npub = seller.public_key().to_bech32().expect("seller npub");
        let mint = "https://mint.example";
        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: seller_npub.clone(),
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(
            load_paid_route_store(&paid_route_store_file_path(&runtime.config_path))
                .expect("bare provider store")
                .sessions
                .is_empty(),
            "a bare npub must wait for discovered signed terms"
        );

        let provider = ManualPaidExitProvider::new(&seller_npub, Some(2_500_000), Some(mint))
            .expect("manual provider link");
        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: provider.link().expect("encode provider link"),
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert!(runtime.vpn_enabled);
        assert!(runtime.vpn_active);
        assert_eq!(runtime.config.internet_source, InternetSource::Direct);
        let store_path = paid_route_store_file_path(&runtime.config_path);
        let store = load_paid_route_store(&store_path).expect("manual provider store");
        assert!(store.sessions.is_empty(), "the link must not synthesize an offer");

        let mut too_expensive = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        too_expensive.pricing.price_msat_per_gb = 2_500_001;
        too_expensive.channel.accepted_mints = vec![mint.to_string()];
        let receiver = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let rejected = signed_paid_exit_offer_from_config_with_receiver(
            "too-expensive",
            &seller,
            &too_expensive,
            Some(receiver),
            None,
            unix_timestamp(),
        )
        .expect("sign expensive seller offer");
        upsert_paid_route_offer(&store_path, rejected, Vec::new(), unix_timestamp())
            .expect("persist expensive seller offer");
        runtime.dispatch(NativeAppAction::Tick);
        assert!(
            runtime.last_error.contains("over the configured maximum"),
            "{}",
            runtime.last_error
        );
        assert!(
            load_paid_route_store(&store_path)
                .expect("store after rejected offer")
                .sessions
                .is_empty()
        );

        let mut seller_terms = too_expensive;
        seller_terms.pricing.price_msat_per_gb = 2_000_000;
        seller_terms.channel.max_channel_capacity_sat = 321;
        seller_terms.channel.channel_expiry_secs = 7_200;
        seller_terms.channel.free_probe_units = 2_097_152;
        seller_terms.channel.grace_units = 65_536;
        let accepted = signed_paid_exit_offer_from_config_with_receiver(
            "internet-exit",
            &seller,
            &seller_terms,
            Some(receiver),
            None,
            unix_timestamp(),
        )
        .expect("sign accepted seller offer");
        upsert_paid_route_offer(&store_path, accepted, Vec::new(), unix_timestamp())
            .expect("persist accepted seller offer");
        runtime.dispatch(NativeAppAction::Tick);

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(runtime.config.internet_source, InternetSource::PaidManual);
        assert_eq!(runtime.config.exit_node, seller.public_key().to_hex());
        assert!(runtime.config.exit_node_public_paid_exit);
        let saved = AppConfig::load(&runtime.config_path).expect("load saved config");
        assert_eq!(saved.manual_paid_exit_provider, provider);
        assert_eq!(saved.internet_source, InternetSource::PaidManual);
        let store = load_paid_route_store(&store_path).expect("connected provider store");
        assert_eq!(store.offers.len(), 2, "only signed offers are retained");
        assert_eq!(store.sessions.len(), 1);
        let session = store.sessions.values().next().expect("manual buyer session");
        assert_eq!(
            store.selected_buyer_session_id,
            session.session.session_id,
            "the GUI must persist the exact selected session, not only its seller"
        );
        assert!(
            store
                .buyer_session_open_attempts
                .contains_key(&session.session.session_id),
            "the daemon needs a bounded acknowledgment deadline"
        );
        let channel = &store.channels[&session.session.payment.channel_id];
        let terms = channel.accepted_terms.as_ref().expect("accepted seller terms");
        assert_eq!(terms.pricing.price_msat_per_gb, 2_000_000);
        assert_eq!(terms.channel.accepted_mints, [mint]);
        assert_eq!(terms.channel.max_channel_capacity_sat, 321);
        assert_eq!(terms.channel.channel_expiry_secs, 7_200);
        assert_eq!(terms.channel.free_probe_units, 2_097_152);
        assert_eq!(terms.channel.grace_units, 65_536);
        let quote_id = &store.leases[&session.session.lease_id].lease.quote_id;
        assert_eq!(store.quotes[quote_id].quote.receiver_pubkey_hex, receiver);
        assert!(
            store
                .buyer_session_allows_routing(&session.session.session_id, unix_timestamp())
                .expect("manual session routes through the default free probe")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn free_manual_provider_link_connects_without_a_mint() {
        use nostr_vpn_core::paid_route_store::{
            paid_route_store_file_path, upsert_paid_route_offer,
        };
        use nostr_vpn_core::paid_routes::{
            ManualPaidExitProvider, PaidExitConfig, signed_paid_exit_offer_from_config,
        };

        let dir = unique_service_test_dir("nvpn-app-core-free-manual-provider");
        let error = anyhow!("test runtime");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Free manual provider test");
        runtime.config.save(&runtime.config_path).expect("save config");

        let seller = Keys::generate();
        let seller_npub = seller.public_key().to_bech32().expect("seller npub");
        let mut offer_config = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        offer_config.pricing.price_msat_per_gb = 0;
        offer_config.channel.accepted_mints.clear();
        let provider_link = ManualPaidExitProvider::seller_link(&seller_npub, &offer_config)
            .expect("free seller link");
        runtime.dispatch(NativeAppAction::SetManualPaidExitProvider {
            provider: provider_link,
        });
        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);

        let signed = signed_paid_exit_offer_from_config(
            "free-internet-exit",
            &seller,
            &offer_config,
            None,
            unix_timestamp(),
        )
        .expect("sign free offer");
        upsert_paid_route_offer(
            &paid_route_store_file_path(&runtime.config_path),
            signed,
            Vec::new(),
            unix_timestamp(),
        )
        .expect("persist free offer");
        runtime.dispatch(NativeAppAction::Tick);

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(runtime.config.internet_source, InternetSource::PaidManual);
        assert_eq!(runtime.config.exit_node, seller.public_key().to_hex());

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "paid-exit")]
    #[test]
    fn gui_buy_paid_route_offer_selects_and_activates_the_exit_route() {
        use nostr_vpn_core::paid_route_store::{
            paid_route_offer_store_key, paid_route_store_file_path, update_paid_route_store,
        };
        use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

        let dir = unique_service_test_dir("nvpn-app-core-paid-route-buy");
        let error = anyhow!("test runtime");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Paid route test");
        runtime.config.save(&runtime.config_path).expect("save config");

        let seller = Keys::generate();
        let seller_npub = seller.public_key().to_bech32().expect("seller npub");
        let mint = "https://mint.minibits.cash/Bitcoin";
        let mut offer_config = PaidExitConfig {
            enabled: true,
            ..PaidExitConfig::default()
        };
        offer_config.pricing.price_msat_per_gb = 25;
        offer_config.channel.accepted_mints = vec![mint.to_string()];
        offer_config.channel.free_probe_units = 1_048_576;
        let signed = signed_paid_exit_offer_from_config(
            "internet-exit",
            &seller,
            &offer_config,
            None,
            unix_timestamp(),
        )
        .expect("sign offer");
        let store_path = paid_route_store_file_path(&runtime.config_path);
        let mut store =
            approve_manual_provider_mint(&mut runtime, &seller_npub, &offer_config, &store_path);
        assert_eq!(store.wallet.mints[0].url, mint);

        store
            .upsert_signed_offer(signed, vec!["wss://relay.example".to_string()], unix_timestamp())
            .expect("store offer");
        let offer_key = paid_route_offer_store_key(&seller_npub, "internet-exit");
        update_paid_route_store(&store_path, |target| {
            *target = store;
            Ok(())
        })
        .expect("persist store");

        runtime.dispatch(NativeAppAction::BuyPaidRouteOffer {
            offer_key,
            mint_url: None,
            channel_capacity_sat: None,
        });

        assert!(runtime.last_error.is_empty(), "{}", runtime.last_error);
        assert_eq!(runtime.config.internet_source, InternetSource::PaidManual);
        assert!(runtime.config.exit_node_public_paid_exit);
        assert_eq!(
            runtime.config.exit_node,
            seller.public_key().to_hex()
        );
        assert!(runtime.vpn_enabled);
        assert!(runtime.vpn_active);
        let saved = AppConfig::load(&runtime.config_path).expect("load saved config");
        assert_eq!(saved.internet_source, InternetSource::PaidManual);
        assert_eq!(saved.exit_node, seller.public_key().to_hex());
        assert_paid_route_activation_requires_fresh_end_to_end_probe(
            &mut runtime,
            &store_path,
            &seller,
            &seller_npub,
        );

        let _ = fs::remove_dir_all(&dir);
    }
    #[cfg(feature = "paid-exit")]
    #[test]
    fn gui_buy_paid_route_offer_failure_reaches_the_ui_error_state() {
        let dir = unique_service_test_dir("nvpn-app-core-paid-route-buy-error");
        let error = anyhow!("test runtime");
        let mut runtime = NativeAppRuntime::from_startup_error(&error);
        runtime.startup_error = None;
        runtime.last_error.clear();
        runtime.mobile_runtime = true;
        runtime.config_path = dir.join("config.toml");
        create_test_network(&mut runtime, "Paid route error test");
        runtime.config.save(&runtime.config_path).expect("save config");

        runtime.dispatch(NativeAppAction::BuyPaidRouteOffer {
            offer_key: "missing-seller:internet-exit".to_string(),
            mint_url: None,
            channel_capacity_sat: None,
        });

        let state = runtime.state();
        assert!(state.error.contains("was not found"), "{}", state.error);

        let _ = fs::remove_dir_all(&dir);
    }
