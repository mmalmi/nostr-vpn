#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_spilman_receiver_mode_names_processing_state() {
    assert_eq!(paid_exit_spilman_receiver_mode(true), "processing");
    assert_eq!(paid_exit_spilman_receiver_mode(false), "claim_only");
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_status_snapshot_reports_store_sessions_and_routing() {
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
    use nostr_vpn_core::paid_routes::{
        PaidExitConfig, PaidRouteQualityMetrics, signed_paid_exit_offer_from_config,
    };

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut offer_config = PaidExitConfig::default();
    offer_config.enabled = true;
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    offer_config.channel.free_probe_units = 0;
    offer_config.channel.grace_units = 0;
    offer_config.location.country_code = "fi".to_string();

    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, 123)
            .expect("sign offer");
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let result = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 1_000,
            now_unix: 125,
        })
        .expect("open buyer session");
    let session = &mut store
        .sessions
        .get_mut(&result.session_id)
        .expect("stored session")
        .session;
    session.usage.rx_bytes = 100;
    session.usage.billable_bytes = 100;
    session.realized_exit_ip = Some("198.51.100.42".to_string());
    session.observed_country_code = Some("FI".to_string());
    session.quality = Some(PaidRouteQualityMetrics {
        latency_ms: Some(42),
        jitter_ms: Some(7),
        ..PaidRouteQualityMetrics::default()
    });

    let app = AppConfig::generated();
    let snapshot = paid_exit_status_snapshot_json(&app, Path::new("/tmp/paid-routes.json"), &store)
        .expect("status snapshot");

    assert_eq!(snapshot["counts"]["sessions"].as_u64(), Some(1));
    assert_eq!(snapshot["counts"]["channels"].as_u64(), Some(1));
    assert_eq!(
        snapshot["sessions"][0]["routing"]["state"].as_str(),
        Some("paid")
    );
    assert_eq!(
        snapshot["sessions"][0]["routing"]["shared_internet"].as_str(),
        Some("on: paid")
    );
    assert_eq!(
        snapshot["sessions"][0]["routing"]["amount_due_msat"].as_u64(),
        Some(1_000)
    );
    assert_eq!(
        snapshot["sessions"][0]["realized_exit_ip"].as_str(),
        Some("198.51.100.42")
    );
    assert_eq!(
        snapshot["sessions"][0]["country_claim"]["status"].as_str(),
        Some("match")
    );
    assert_eq!(
        snapshot["sessions"][0]["quality"]["latency_ms"].as_u64(),
        Some(42)
    );
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_record_probe_once_persists_session_measurements() {
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
    use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-record-probe-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let app = AppConfig::generated();
    app.save(&config_path).expect("save config");

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut offer_config = PaidExitConfig::default();
    offer_config.enabled = true;
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, 123)
            .expect("sign offer");
    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let session = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 1_000,
            now_unix: 125,
        })
        .expect("open buyer session");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("write store");

    let result = paid_exit_record_probe_once(PaidExitRecordProbeArgs {
        config: Some(config_path.clone()),
        session: session.session_id.clone(),
        realized_exit_ip: Some("198.51.100.42".to_string()),
        observed_country_code: Some("fi".to_string()),
        observed_asn: Some(14_593),
        latency_ms: Some(42),
        jitter_ms: Some(7),
        packet_loss_ppm: Some(500),
        down_bps: Some(10_000_000),
        up_bps: Some(1_000_000),
        uptime_secs: Some(3600),
        last_seen_unix: Some(130),
        no_reload_daemon: true,
        json: false,
    })
    .expect("record probe");

    assert!(result.probe.changed);
    assert_eq!(
        result.probe.realized_exit_ip.as_deref(),
        Some("198.51.100.42")
    );
    assert_eq!(result.probe.observed_country_code.as_deref(), Some("FI"));
    assert_eq!(
        result
            .probe
            .quality
            .as_ref()
            .and_then(|quality| quality.down_bps),
        Some(10_000_000)
    );

    let store = load_paid_route_store(&store_path).expect("load store");
    let snapshot =
        paid_exit_status_snapshot_json(&app, &store_path, &store).expect("status snapshot");
    assert_eq!(
        snapshot["sessions"][0]["realized_exit_ip"].as_str(),
        Some("198.51.100.42")
    );
    assert_eq!(
        snapshot["sessions"][0]["observed_country_code"].as_str(),
        Some("FI")
    );
    assert_eq!(
        snapshot["sessions"][0]["quality"]["packet_loss_ppm"].as_u64(),
        Some(500)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_probe_once_measures_and_persists_session() {
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
    use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-probe-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let app = AppConfig::generated();
    app.save(&config_path).expect("save config");

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut offer_config = PaidExitConfig::default();
    offer_config.enabled = true;
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, 123)
            .expect("sign offer");
    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let session = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 1_000,
            now_unix: 125,
        })
        .expect("open buyer session");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("write store");

    let (server_base, server) = spawn_paid_exit_probe_fixture_server(5);
    let result = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(paid_exit_probe_once(PaidExitProbeArgs {
            config: Some(config_path.clone()),
            session: session.session_id.clone(),
            ip_url: Some(format!("{server_base}/ip")),
            stun_servers: Vec::new(),
            no_stun: true,
            geoip_url_template: Some(format!("{server_base}/geo/{{ip}}")),
            no_geoip: false,
            download_url: Some(format!("{server_base}/download")),
            upload_url: Some(format!("{server_base}/upload")),
            bandwidth_bytes: 1_024,
            no_bandwidth: false,
            samples: 2,
            timeout_secs: 2,
            no_reload_daemon: true,
            json: false,
        }))
        .expect("probe");
    server.join().expect("server exits");

    assert!(result.probe.changed);
    assert_eq!(
        result.measurement.realized_exit_ip.as_deref(),
        Some("198.51.100.42")
    );
    assert_eq!(
        result.measurement.observed_country_code.as_deref(),
        Some("FI")
    );
    assert_eq!(result.measurement.observed_asn, Some(14_593));
    assert_eq!(result.measurement.success_count(), 2);
    assert_eq!(result.measurement.failure_count(), 0);
    assert_eq!(result.measurement.quality.packet_loss_ppm, Some(0));
    assert!(result.measurement.quality.down_bps.unwrap_or_default() > 0);
    assert!(result.measurement.quality.up_bps.unwrap_or_default() > 0);
    assert!(
        result.bandwidth_error.is_none(),
        "{:?}",
        result.bandwidth_error
    );

    let store = load_paid_route_store(&store_path).expect("load store");
    let snapshot =
        paid_exit_status_snapshot_json(&app, &store_path, &store).expect("status snapshot");
    assert_eq!(
        snapshot["sessions"][0]["realized_exit_ip"].as_str(),
        Some("198.51.100.42")
    );
    assert_eq!(
        snapshot["sessions"][0]["observed_country_code"].as_str(),
        Some("FI")
    );
    assert_eq!(
        snapshot["sessions"][0]["observed_asn"].as_u64(),
        Some(14_593)
    );
    assert_eq!(
        snapshot["sessions"][0]["quality"]["packet_loss_ppm"].as_u64(),
        Some(0)
    );
    assert!(
        snapshot["sessions"][0]["quality"]["down_bps"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        snapshot["sessions"][0]["quality"]["up_bps"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_probe_once_uses_stun_for_realized_exit_ip() {
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
    use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-stun-probe-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let app = AppConfig::generated();
    app.save(&config_path).expect("save config");

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let mut offer_config = PaidExitConfig::default();
    offer_config.enabled = true;
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, 123)
            .expect("sign offer");
    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let session = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub: buyer.public_key().to_bech32().expect("buyer npub"),
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 1_000,
            now_unix: 125,
        })
        .expect("open buyer session");
    update_paid_route_store(&store_path, |target| {
        *target = store;
        Ok(())
    })
    .expect("write store");

    let (stun_server, stun_fixture) = spawn_paid_exit_stun_fixture([198, 51, 100, 77]);
    let result = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(paid_exit_probe_once(PaidExitProbeArgs {
            config: Some(config_path.clone()),
            session: session.session_id.clone(),
            ip_url: Some("http://127.0.0.1:9/unused".to_string()),
            stun_servers: vec![stun_server],
            no_stun: false,
            geoip_url_template: None,
            no_geoip: true,
            download_url: None,
            upload_url: None,
            bandwidth_bytes: 0,
            no_bandwidth: true,
            samples: 1,
            timeout_secs: 2,
            no_reload_daemon: true,
            json: false,
        }))
        .expect("probe");
    stun_fixture.join().expect("stun fixture exits");

    assert!(result.probe.changed);
    assert_eq!(
        result.measurement.realized_exit_ip.as_deref(),
        Some("198.51.100.77")
    );
    assert_eq!(result.measurement.success_count(), 1);
    assert_eq!(result.measurement.failure_count(), 0);

    let store = load_paid_route_store(&store_path).expect("load store");
    let snapshot =
        paid_exit_status_snapshot_json(&app, &store_path, &store).expect("status snapshot");
    assert_eq!(
        snapshot["sessions"][0]["realized_exit_ip"].as_str(),
        Some("198.51.100.77")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
fn spawn_paid_exit_probe_fixture_server(
    expected_requests: usize,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let addr = listener.local_addr().expect("fixture addr");
    let base = format!("http://{addr}");
    let handle = std::thread::spawn(move || {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().expect("accept fixture request");
            let mut request = [0_u8; 8192];
            let read =
                std::io::Read::read(&mut stream, &mut request).expect("read fixture request");
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let body = if path.starts_with("/geo/") {
                r#"{"country_code":"fi","asn":"AS14593 Example Net"}"#.to_string()
            } else if path.starts_with("/download") {
                "x".repeat(1024)
            } else if path.starts_with("/upload") {
                r#"{"ok":true}"#.to_string()
            } else {
                r#"{"ip":"198.51.100.42"}"#.to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            std::io::Write::write_all(&mut stream, response.as_bytes())
                .expect("write fixture response");
        }
    });
    (base, handle)
}

#[cfg(feature = "paid-exit")]
fn spawn_paid_exit_stun_fixture(mapped_ip: [u8; 4]) -> (String, std::thread::JoinHandle<()>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind STUN fixture");
    let addr = socket.local_addr().expect("STUN fixture addr");
    let server = format!("stun:{addr}");
    let handle = std::thread::spawn(move || {
        let mut request = [0_u8; 1500];
        let (len, peer) = socket
            .recv_from(&mut request)
            .expect("receive STUN request");
        assert!(len >= 20, "STUN request was too short");
        assert_eq!(u16::from_be_bytes([request[0], request[1]]), 0x0001);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            0x2112_A442
        );
        let transaction_id = request[8..20].to_vec();
        let response = paid_exit_stun_fixture_response(&transaction_id, mapped_ip);
        socket
            .send_to(&response, peer)
            .expect("send STUN fixture response");
    });
    (server, handle)
}

#[cfg(feature = "paid-exit")]
fn paid_exit_stun_fixture_response(transaction_id: &[u8], mapped_ip: [u8; 4]) -> Vec<u8> {
    assert_eq!(transaction_id.len(), 12);
    let mut response = Vec::new();
    response.extend_from_slice(&0x0101_u16.to_be_bytes());
    response.extend_from_slice(&12_u16.to_be_bytes());
    response.extend_from_slice(&0x2112_A442_u32.to_be_bytes());
    response.extend_from_slice(transaction_id);
    response.extend_from_slice(&0x0020_u16.to_be_bytes());
    response.extend_from_slice(&8_u16.to_be_bytes());
    response.push(0);
    response.push(0x01);
    let xor_port = 54_321_u16 ^ ((0x2112_A442_u32 >> 16) as u16);
    response.extend_from_slice(&xor_port.to_be_bytes());
    for (octet, mask) in mapped_ip.into_iter().zip(0x2112_A442_u32.to_be_bytes()) {
        response.push(octet ^ mask);
    }
    response
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_run_once_enables_seller_and_stores_offer() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-run-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");

    let args = PaidExitRunArgs {
        config: Some(config_path.clone()),
        offer_id: Some("starlink-fi".to_string()),
        publish: false,
        no_reload_daemon: true,
        upstream: Some("host-default".to_string()),
        price_msat_per_gb: Some(250),
        accepted_mints: Some("https://mint.example".to_string()),
        accepted_mint: vec!["https://other-mint.example".to_string()],
        country_code: Some("fi".to_string()),
        network_class: Some(nostr_vpn_core::paid_routes::ExitNetworkClass::Residential),
        asn: Some(12_345),
        max_channel_capacity_sat: Some(250),
        channel_expiry_secs: Some(300),
        free_probe_units: Some("4 KB".to_string()),
        grace_units: Some("1 KB".to_string()),
        json: false,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime
        .block_on(paid_exit_run_once(args))
        .expect("run paid exit once");

    let app = load_or_default_config(&config_path).expect("load saved config");
    assert_eq!(
        app.paid_exit.location.network_class,
        nostr_vpn_core::paid_routes::ExitNetworkClass::Residential
    );
    let store =
        load_paid_route_store(&paid_route_store_file_path(&config_path)).expect("load store");

    assert!(app.paid_exit.enabled);
    assert_eq!(app.paid_exit.pricing.price_msat_per_gb, 250);
    assert_eq!(app.paid_exit.location.country_code, "FI");
    assert_eq!(
        app.paid_exit.channel.accepted_mints,
        vec![
            "https://mint.example".to_string(),
            "https://other-mint.example".to_string()
        ]
    );
    assert_eq!(result.offer.offer_id, "starlink-fi");
    assert_eq!(result.offer.pricing.price_msat_per_gb, 250);
    assert_eq!(result.offer.access.private_vpn_access.as_str(), "denied");
    assert!(result.publish.is_none());
    assert!(!result.daemon_reload_attempted);
    assert_eq!(store.offers.len(), 1);
    assert_eq!(store.wallet.mints.len(), 2);
    assert_eq!(result.status["counts"]["offers"].as_u64(), Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_run_once_rejects_incomplete_wireguard_upstream() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-wg-incomplete-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let error = match runtime.block_on(paid_exit_run_once(PaidExitRunArgs {
        config: Some(config_path.clone()),
        offer_id: Some("wg-exit".to_string()),
        publish: false,
        no_reload_daemon: true,
        upstream: Some("wireguard_exit".to_string()),
        price_msat_per_gb: Some(500),
        accepted_mints: Some("https://mint.example".to_string()),
        accepted_mint: vec![],
        country_code: Some("fi".to_string()),
        network_class: None,
        asn: None,
        max_channel_capacity_sat: Some(100),
        channel_expiry_secs: Some(600),
        free_probe_units: Some("64 KB".to_string()),
        grace_units: Some("16 KB".to_string()),
        json: false,
    })) {
        Ok(_) => panic!("incomplete WireGuard upstream should not be advertised"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("wireguard_exit is incomplete"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_run_once_enables_configured_wireguard_upstream() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-wg-run-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let mut app = AppConfig::generated();
    app.wireguard_exit.enabled = false;
    app.wireguard_exit.address = "10.200.0.2/32".to_string();
    app.wireguard_exit.private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
    app.wireguard_exit.peer_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
    app.wireguard_exit.peer_preshared_key =
        "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".to_string();
    app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();
    app.wireguard_exit.allowed_ips = vec!["0.0.0.0/0".to_string()];
    app.save(&config_path).expect("save configured upstream");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime
        .block_on(paid_exit_run_once(PaidExitRunArgs {
            config: Some(config_path.clone()),
            offer_id: Some("wg-exit".to_string()),
            publish: false,
            no_reload_daemon: true,
            upstream: Some("wg".to_string()),
            price_msat_per_gb: Some(500),
            accepted_mints: Some("https://mint.example".to_string()),
            accepted_mint: vec![],
            country_code: Some("fi".to_string()),
            network_class: None,
            asn: None,
            max_channel_capacity_sat: Some(100),
            channel_expiry_secs: Some(600),
            free_probe_units: Some("64 KB".to_string()),
            grace_units: Some("16 KB".to_string()),
            json: false,
        }))
        .expect("run paid exit with configured WireGuard upstream");

    let saved = load_or_default_config(&config_path).expect("load saved config");
    assert_eq!(
        saved.paid_exit.access.upstream,
        PaidExitUpstream::WireGuardExit
    );
    assert!(saved.wireguard_exit.enabled);
    assert_eq!(
        result.offer.access.upstream,
        PaidExitUpstream::WireGuardExit
    );
    assert_eq!(
        result.status["config"]["upstream"].as_str(),
        Some("wireguard_exit")
    );
    assert_eq!(
        result.status["config"]["private_vpn_access"].as_str(),
        Some("denied")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_advertisable_rejects_disabled_wireguard_upstream() {
    let mut app = AppConfig::generated();
    app.paid_exit.enabled = true;
    app.paid_exit.access.upstream = PaidExitUpstream::WireGuardExit;
    app.wireguard_exit.enabled = false;
    app.wireguard_exit.address = "10.200.0.2/32".to_string();
    app.wireguard_exit.private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_string();
    app.wireguard_exit.peer_public_key = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".to_string();
    app.wireguard_exit.endpoint = "198.51.100.20:51820".to_string();

    let error = ensure_paid_exit_advertisable(&app)
        .expect_err("disabled WireGuard upstream should not be advertised");

    assert!(error.to_string().contains("wireguard_exit is disabled"));
}
