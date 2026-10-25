#[cfg(feature = "paid-exit")]
#[test]
fn disabled_seller_preserves_channel_control_peers_until_vpn_resumes() {
    use nostr_vpn_core::paid_route_store::{
        PaidRouteChannelRecord, PaidRouteChannelRole, PaidRouteLifecycleStatus, PaidRouteStore,
        update_paid_route_store,
    };
    use nostr_vpn_core::paid_routes::PaidExitConfig;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-disabled-settlement-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");

    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    app.connect_to_non_roster_fips_peers = false;
    app.paid_exit.enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }
    assert!(!fips_private_runtime_active(&app, false));

    let buyer = Keys::generate();
    let buyer_npub = buyer.public_key().to_bech32().expect("buyer npub");
    let mut accepted_terms = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    accepted_terms.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let mut store = PaidRouteStore::default();
    store.channels.insert(
        "seller-channel-1".to_string(),
        PaidRouteChannelRecord {
            channel_id: "seller-channel-1".to_string(),
            offer_id: "internet-exit".to_string(),
            role: PaidRouteChannelRole::Seller,
            status: PaidRouteLifecycleStatus::Active,
            payment: Default::default(),
            accepted_terms: Some(accepted_terms),
            mint_url: "https://mint.example".to_string(),
            counterparty_npub: buyer_npub.clone(),
            created_at_unix: 100,
            expires_at_unix: 500,
            updated_at_unix: 100,
            error: String::new(),
        },
    );
    let store_path = paid_route_store_file_path(&config_path);
    update_paid_route_store(&store_path, |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("persist seller channel");

    assert!(!fips_private_runtime_active(&app, false));
    assert!(fips_private_runtime_active(&app, true));

    let network_id = app.effective_network_id();
    let own_npub = app
        .nostr_keys()
        .expect("seller keys")
        .public_key()
        .to_bech32()
        .expect("seller npub");
    let own_pubkey = app.own_nostr_pubkey_hex().expect("seller pubkey");
    let mut recent_peers = nostr_vpn_core::recent_peers::RecentPeerEndpoints::new(
        own_npub,
        nostr_vpn_core::recent_peers::recent_peers_scope(&network_id),
    )
    .expect("recent peers cache");
    assert!(recent_peers.note_success(&buyer.public_key().to_hex(), "203.0.113.41:51821", 100));
    let config = fips_tunnel_config_from_app(FipsTunnelConfigInput {
        app: &app,
        config_path: &config_path,
        network_id: &network_id,
        iface: "utun-test".to_string(),
        underlay_interface: None,
        underlay_interface_mtu: None,
        own_pubkey: Some(&own_pubkey),
        recent_peers: Some(&recent_peers),
        live_peer_endpoints: &[],
        ethernet_underlay: None,
    })
    .expect("build disabled seller settlement config");
    let buyer_control_peer = config
        .endpoint_peers
        .iter()
        .find(|peer| peer.npub == buyer_npub)
        .expect("existing buyer remains a control peer");
    assert!(buyer_control_peer.auto_reconnect);
    assert!(config.paid_route_admissions.is_empty());
    assert!(
        config
            .peers
            .iter()
            .all(|peer| peer.participant_pubkey != buyer.public_key().to_hex()),
        "disabled selling must not restore buyer routing admission"
    );

    store
        .channels
        .get_mut("seller-channel-1")
        .expect("seller channel")
        .status = PaidRouteLifecycleStatus::Closed;
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("persist closed seller channel");
    assert!(
        !fips_private_runtime_active(&app, false),
        "closing the channel must leave VPN off"
    );

    let refreshed = fips_tunnel_config_from_app(FipsTunnelConfigInput {
        app: &app,
        config_path: &config_path,
        network_id: &network_id,
        iface: "utun-test".to_string(),
        underlay_interface: None,
        underlay_interface_mtu: None,
        own_pubkey: Some(&own_pubkey),
        recent_peers: Some(&recent_peers),
        live_peer_endpoints: &[],
        ethernet_underlay: None,
    })
    .expect("rebuild after settlement channel closes");
    assert!(
        refreshed
            .endpoint_peers
            .iter()
            .all(|peer| peer.npub != buyer_npub),
        "a new build must reload the store and withdraw the closed settlement peer"
    );
    assert!(refreshed.paid_route_admissions.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_settle_signs_manual_cooperative_close_from_wallet() {
    use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentSigner};
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{
        OpenPaidRouteBuyerSessionRequest, PaidRouteBuyerPaymentUpdatesDueRequest,
        PaidRouteLifecycleStatus, PaidRouteStore, RecordPaidRouteBuyerUsageRequest,
        update_paid_route_store,
    };
    use nostr_vpn_core::paid_routes::{
        PaidExitConfig, PaidRouteUsage, signed_paid_exit_offer_from_config,
    };
    use serde_json::json;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-settle-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");

    let mut app = AppConfig::generated();
    app.fips_host_tunnel_enabled = false;
    for network in &mut app.networks {
        network.listen_for_join_requests = false;
    }
    let buyer_keys = app.nostr_keys().expect("buyer keys");
    let buyer_npub = buyer_keys.public_key().to_bech32().expect("buyer npub");
    let seller = Keys::generate();
    app.select_public_paid_exit_node(&seller.public_key().to_hex())
        .expect("select seller");
    let mut offer_config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    offer_config.channel.free_probe_units = 0;
    offer_config.channel.grace_units = 0;
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, 123)
            .expect("sign offer");

    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Example", None, 122);
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let session = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer_npub.clone(),
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: 125,
        })
        .expect("open buyer session");
    store
        .record_buyer_usage(RecordPaidRouteBuyerUsageRequest {
            seller_pubkey: seller.public_key().to_hex(),
            usage_delta: PaidRouteUsage {
                rx_bytes: 60,
                tx_bytes: 50,
                billable_bytes: 110,
                ..PaidRouteUsage::default()
            },
            now_unix: 126,
        })
        .expect("record buyer usage")
        .expect("matched buyer session");

    let wallet_data_dir = dir.join("wallet");
    let result = paid_exit_settle_with_signer(PaidExitSettleRequest {
        app: &app,
        config_path: &config_path,
        store: &mut store,
        signer: &RuntimeFakePaymentSigner,
        session_id: &session.session_id,
        dry_run: false,
        wallet_data_dir: &wallet_data_dir,
        now_unix: 128,
    })
    .expect("settle channel");
    update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("persist closing channel");
    let queued_payments = load_paid_exit_payment_outbox(&config_path);
    assert_eq!(queued_payments.len(), 1);
    let payment_id = queued_payments[0].id.clone();

    assert!(result.payment.changed);
    assert_eq!(result.payment.payload_type, "cooperative_close");
    assert_eq!(result.payment.session_id, session.session_id);
    assert_eq!(result.payment.channel_id, session.channel_id);
    assert_eq!(result.payment.lease_id, session.lease_id);
    assert_eq!(result.payment.delivered_units, 110);
    assert_eq!(result.payment.amount_due_msat, 1);
    assert_eq!(result.payment.paid_msat, 1_000);
    assert!(!result.dry_run);
    assert_eq!(result.queued, Some(true));
    assert!(result.persisted);

    let channel = store.channels.get(&session.channel_id).expect("channel");
    assert_eq!(channel.status, PaidRouteLifecycleStatus::Closing);
    assert_eq!(channel.payment.paid_msat, 1_000);
    assert_eq!(
        channel
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.balance),
        Some(1)
    );
    let expected_signature = format!("closed-{}-1", session.channel_id);
    assert_eq!(
        channel
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.signature.as_str()),
        Some(expected_signature.as_str())
    );
    let lease = store.leases.get(&session.lease_id).expect("lease");
    assert_eq!(lease.status, PaidRouteLifecycleStatus::Closing);
    assert!(
        store
            .buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
                now_unix: 129,
                min_increment_msat: 1,
            })
            .is_empty()
    );

    app.set_internet_source(InternetSource::Direct);
    assert!(
        !app.connect_to_non_roster_fips_peers,
        "leaving paid mode must release implicit market discovery ownership"
    );
    assert!(!fips_private_runtime_active(&app, false));
    assert!(!fips_private_runtime_active(&app, false));
    assert!(fips_private_runtime_active(&app, true));
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let network_id = app.effective_network_id();
    let own_pubkey = app.own_nostr_pubkey_hex().expect("buyer pubkey");
    let mut recent_peers = nostr_vpn_core::recent_peers::RecentPeerEndpoints::new(
        buyer_npub,
        nostr_vpn_core::recent_peers::recent_peers_scope(&network_id),
    )
    .expect("recent peers cache");
    assert!(recent_peers.note_success(&seller.public_key().to_hex(), "203.0.113.40:51821", 128,));
    let config = fips_tunnel_config_from_app(FipsTunnelConfigInput {
        app: &app,
        config_path: &config_path,
        network_id: &network_id,
        iface: "utun-test".to_string(),
        underlay_interface: None,
        underlay_interface_mtu: None,
        own_pubkey: Some(&own_pubkey),
        recent_peers: Some(&recent_peers),
        live_peer_endpoints: &[],
        ethernet_underlay: None,
    })
    .expect("build direct-mode config with pending close");
    let seller_control_peer = config
        .endpoint_peers
        .iter()
        .find(|peer| peer.npub == seller_npub)
        .expect("pending close keeps seller as a control peer");
    assert!(seller_control_peer.auto_reconnect);
    assert!(
        seller_control_peer
            .addresses
            .iter()
            .any(|hint| hint.addr == "203.0.113.40:51821")
    );
    assert!(
        config
            .peers
            .iter()
            .all(|peer| peer.participant_pubkey != seller.public_key().to_hex()),
        "pending close must not restore the seller as an exit route"
    );

    assert!(
        acknowledge_paid_exit_payment(&config_path, &seller.public_key().to_hex(), &payment_id)
            .expect("acknowledge cooperative close"),
        "seller acknowledgment must remove the queued close"
    );
    assert!(
        !fips_private_runtime_active(&app, false),
        "acknowledging a queued close must leave VPN off"
    );

    let _ = std::fs::remove_dir_all(&dir);

    struct RuntimeFakePaymentSigner;

    impl CashuSpilmanPaymentSigner for RuntimeFakePaymentSigner {
        fn sign_cashu_spilman_payment(
            &self,
            channel_id: &str,
            balance: u64,
            include_funding: bool,
        ) -> std::result::Result<CashuSpilmanPayment, String> {
            Ok(CashuSpilmanPayment {
                channel_id: channel_id.to_string(),
                balance,
                signature: format!("signed-{channel_id}-{balance}"),
                params: include_funding.then(|| json!({"channel": channel_id})),
                funding_proofs: include_funding.then(|| json!({"proofs": []})),
            })
        }

        fn sign_cashu_spilman_close(
            &self,
            channel_id: &str,
            final_balance: u64,
        ) -> std::result::Result<CashuSpilmanPayment, String> {
            Ok(CashuSpilmanPayment {
                channel_id: channel_id.to_string(),
                balance: final_balance,
                signature: format!("closed-{channel_id}-{final_balance}"),
                params: None,
                funding_proofs: None,
            })
        }
    }
}
