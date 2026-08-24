use super::*;
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::paid_route_store::{
    OpenPaidRouteBuyerSessionRequest, PaidRouteLifecycleStatus,
};
use nostr_vpn_core::paid_routes::{
    PaidExitConfig, PaidRouteChannelTerms, PaidRouteIpSupport, signed_paid_exit_offer_from_config,
};

#[test]
fn manual_unacknowledged_session_fails_and_falls_back_to_direct() {
    let seller = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let mint = "https://mint.example";
    let offer_config = PaidExitConfig {
        enabled: true,
        channel: PaidRouteChannelTerms {
            accepted_mints: vec![mint.to_string()],
            max_channel_capacity_sat: 100,
            channel_expiry_secs: 600,
            free_probe_units: 1_048_576,
            ..PaidRouteChannelTerms::default()
        },
        ip_support: PaidRouteIpSupport {
            ipv4: true,
            ..PaidRouteIpSupport::default()
        },
        ..PaidExitConfig::default()
    };
    let signed =
        signed_paid_exit_offer_from_config("manual-timeout", &seller, &offer_config, None, 100)
            .expect("signed offer");
    let directory = std::env::temp_dir().join(format!(
        "nvpn-manual-paid-exit-timeout-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create test directory");
    let config_path = directory.join("config.toml");
    let store_path = paid_route_store_file_path(&config_path);
    let mut app = AppConfig::generated();
    let buyer_npub = app
        .nostr_keys()
        .expect("buyer keys")
        .public_key()
        .to_bech32()
        .expect("buyer npub");

    let session = update_paid_route_store(&store_path, |store| {
        store.upsert_wallet_mint(mint, "test", None, 100);
        store.upsert_signed_offer(signed, Vec::new(), 100)?;
        let session = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "manual-timeout".to_string(),
            buyer_npub,
            mint_url: Some(mint.to_string()),
            channel_capacity_sat: Some(20),
            initial_paid_msat: 0,
            now_unix: 100,
        })?;
        store.begin_buyer_session_open_attempt(&session.session_id, 100)?;
        Ok(session)
    })
    .expect("create selected buyer session");
    app.select_public_paid_exit_node(&seller_npub)
        .expect("select manual seller");
    app.save(&config_path).expect("save manual selection");

    let early = reconcile_selected_paid_exit_session(
        &mut app,
        &config_path,
        &seller.public_key().to_hex(),
        129,
    )
    .expect("early reconciliation");
    assert!(!early.selected_session_timed_out);
    assert_eq!(
        app.internet_source,
        nostr_vpn_core::config::InternetSource::PaidManual
    );

    let timed_out = reconcile_selected_paid_exit_session(
        &mut app,
        &config_path,
        &seller.public_key().to_hex(),
        130,
    )
    .expect("timeout reconciliation");
    assert!(timed_out.selected_session_timed_out);
    assert_eq!(timed_out.selected_session_id, session.session_id);
    assert_eq!(
        app.internet_source,
        nostr_vpn_core::config::InternetSource::Direct
    );
    assert_eq!(
        AppConfig::load(&config_path)
            .expect("saved direct fallback")
            .internet_source,
        nostr_vpn_core::config::InternetSource::Direct
    );
    let store = load_paid_route_store(&store_path).expect("reloaded failed session");
    assert_eq!(
        store.channels[&session.channel_id].status,
        PaidRouteLifecycleStatus::Failed
    );
    assert!(
        store.channels[&session.channel_id]
            .error
            .contains("acknowledge")
    );

    let _ = std::fs::remove_dir_all(directory);
}
