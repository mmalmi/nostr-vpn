use super::*;

const PRIMARY: &str = "https://primary.example";
const ALTERNATIVE: &str = "https://alternative.example";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (TestDirectory, AppConfig, PaidExitAutomaticBuyer, u64) {
    let dir = TestDirectory(
        std::env::temp_dir().join(format!("nvpn-mint-failover-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir_all(dir.path()).unwrap();
    let path = dir.path().join("config.toml");
    let now = unix_timestamp();
    let mut app = AppConfig::generated();
    app.set_internet_source(InternetSource::PaidAutomatic);
    let seller = Keys::generate();
    let config = PaidExitConfig {
        enabled: true,
        pricing: PaidRoutePricing {
            price_msat_per_gb: 20_000,
        },
        channel: PaidRouteChannelTerms {
            accepted_mints: vec![PRIMARY.into(), ALTERNATIVE.into()],
            max_channel_capacity_sat: 20,
            channel_expiry_secs: 86_400,
            free_probe_units: 1_048_576,
            ..Default::default()
        },
        ip_support: PaidRouteIpSupport {
            ipv4: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let signed = nostr_vpn_core::paid_routes::signed_paid_exit_offer_from_config(
        "exit", &seller, &config, None, now,
    )
    .unwrap();
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.upsert_signed_offer(signed, vec![], now)?;
        store.upsert_wallet_mint(PRIMARY, "primary", Some(16_000), now);
        store.set_default_mint(PRIMARY);
        Ok(())
    })
    .unwrap();
    let mut automatic = PaidExitAutomaticBuyer::default();
    reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now).unwrap();
    let session_id = automatic.candidate.as_ref().unwrap().session_id.clone();
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.begin_buyer_session_funding(&session_id, now)?;
        store
            .sessions
            .get_mut(&session_id)
            .unwrap()
            .last_successful_probe_unix = now;
        store.defer_buyer_mint_retry(PRIMARY, now, true, Some(600))?;
        store.upsert_wallet_mint(ALTERNATIVE, "alternative", Some(10_000), now);
        Ok(())
    })
    .unwrap();
    (dir, app, automatic, now)
}

#[test]
fn mint_failover_prefers_smaller_usable_balance_over_blocked_default() {
    let (dir, _, _, now) = fixture();
    let path = dir.path().join("config.toml");
    let mut store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    store.upsert_wallet_mint(ALTERNATIVE, "alternative", Some(1_000), now);
    let selection = store.select_automatic_offer(now + 1).unwrap();
    assert_eq!(selection.mint_url, ALTERNATIVE);
    assert_eq!(selection.channel_capacity_sat, 1);
}

#[test]
fn mint_failover_uses_new_balance_without_rejecting_verified_seller() {
    let (dir, mut app, mut automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    let previous = automatic.candidate.as_ref().unwrap().session_id.clone();
    assert!(
        reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now + 1,).unwrap()
    );
    let candidate = automatic.candidate.as_ref().unwrap();
    assert_eq!(candidate.selection.mint_url, ALTERNATIVE);
    assert_ne!(candidate.session_id, previous);
    assert!(!candidate.failed);
    assert!(candidate.selection.previously_verified);
    assert!(automatic.rejected_offers.is_empty());
    let store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    let channel = &store.channels[&store.sessions[&candidate.session_id]
        .session
        .payment
        .channel_id];
    assert_eq!(channel.mint_url, ALTERNATIVE);
    assert_eq!(store.wallet.default_mint, PRIMARY);
    assert_eq!(app.internet_source, InternetSource::PaidAutomatic);
    assert_eq!(
        store.sessions.len(),
        2,
        "retain the old session for recovery"
    );
}

#[test]
fn mint_failover_restart_does_not_recover_session_for_wrong_mint() {
    let (dir, mut app, _, now) = fixture();
    let path = dir.path().join("config.toml");
    let mut automatic = PaidExitAutomaticBuyer::default();
    reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now + 1).unwrap();
    let candidate = automatic.candidate.as_ref().unwrap();
    let store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    let channel = &store.channels[&store.sessions[&candidate.session_id]
        .session
        .payment
        .channel_id];
    assert_eq!(candidate.selection.mint_url, ALTERNATIVE);
    assert_eq!(channel.mint_url, ALTERNATIVE);
}

#[test]
fn mint_failover_within_same_second_preserves_original_session_identity() {
    let (dir, mut app, mut automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    let original = automatic.candidate.as_ref().unwrap().session_id.clone();
    reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now).unwrap();
    let store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    assert_ne!(store.selected_buyer_session_id, original);
    assert_eq!(store.sessions.len(), 2);
    assert_eq!(
        store.channels[&store.sessions[&original].session.payment.channel_id].mint_url,
        PRIMARY
    );
}

#[tokio::test]
async fn mint_failover_waits_for_inflight_funding() {
    let (dir, mut app, mut automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    let previous = automatic.candidate.as_ref().unwrap().session_id.clone();
    automatic.funding = Some(tokio::spawn(std::future::pending()));
    assert!(
        !reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now + 1,)
            .unwrap()
    );
    let candidate = automatic.candidate.as_ref().unwrap();
    assert_eq!(candidate.session_id, previous);
    assert!(!candidate.failed);
    automatic.funding.take().unwrap().abort();
}

#[test]
fn mint_failover_keeps_existing_funded_channel_during_cooldown() {
    let (dir, _, automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    let mut store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    let session = store
        .sessions
        .get_mut(&automatic.candidate.unwrap().session_id)
        .unwrap();
    let channel_id = session.session.payment.channel_id.clone();
    let payment = CashuSpilmanPayment {
        channel_id: channel_id.clone(),
        balance: 1,
        signature: "signed".into(),
        params: Some(json!({"unit": "sat"})),
        funding_proofs: Some(json!({"proofs": []})),
    };
    session.session.payment.cashu_spilman_payment = Some(payment.clone());
    store
        .channels
        .get_mut(&channel_id)
        .unwrap()
        .payment
        .cashu_spilman_payment = Some(payment);
    assert_eq!(
        store.select_automatic_offer(now + 1).unwrap().mint_url,
        PRIMARY
    );
}

#[test]
fn mint_failover_waits_without_rejecting_seller_when_all_mints_cooling_down() {
    let (dir, mut app, mut automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.defer_buyer_mint_retry(ALTERNATIVE, now, true, Some(600))
    })
    .unwrap();
    reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now + 1).unwrap();
    let candidate = automatic.candidate.as_ref().unwrap();
    assert!(!candidate.failed);
    assert_eq!(candidate.selection.mint_url, PRIMARY);
}

#[test]
fn mint_fee_shortfall_selects_other_funds_and_preserves_existing_credit() {
    let (dir, mut app, mut automatic, now) = fixture();
    let path = dir.path().join("config.toml");
    let session_id = automatic.candidate.as_ref().unwrap().session_id.clone();
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.buyer_mint_retries.clear();
        store.upsert_wallet_mint(PRIMARY, "primary", Some(3000), now);
        store.record_buyer_session_funding_shortfall(&session_id, 5000)
    })
    .unwrap();
    reconcile_automatic_paid_exit_selection(&mut automatic, &mut app, &path, now + 1).unwrap();
    assert_eq!(
        automatic.candidate.as_ref().unwrap().selection.mint_url,
        ALTERNATIVE
    );
    let mut store = load_paid_route_store(&paid_route_store_file_path(&path)).unwrap();
    assert!(store.buyer_mint_retries.is_empty());
    store
        .sessions
        .get_mut(&session_id)
        .unwrap()
        .session
        .payment
        .cashu_spilman_payment = Some(CashuSpilmanPayment {
        channel_id: "funded-channel".into(),
        balance: 1,
        signature: "signed".into(),
        params: Some("{}".into()),
        funding_proofs: Some("[]".into()),
    });
    assert_eq!(store.buyer_session_funding_retry_at(&session_id), 0);
}
