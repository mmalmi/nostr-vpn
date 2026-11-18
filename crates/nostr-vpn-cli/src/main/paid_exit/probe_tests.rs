use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn args(config: Option<PathBuf>, url: String) -> PaidExitProbeArgs {
    PaidExitProbeArgs {
        config,
        session: "unselected-session".into(),
        ip_url: Some(url),
        stun_servers: Vec::new(),
        no_stun: true,
        geoip_url_template: None,
        no_geoip: true,
        download_url: None,
        upload_url: None,
        bandwidth_bytes: 0,
        no_bandwidth: true,
        samples: 1,
        timeout_secs: 1,
        no_reload_daemon: true,
        json: false,
    }
}

#[tokio::test]
async fn paid_probe_rejects_unselected_session_before_contacting_ip_service() {
    let directory = std::env::temp_dir().join(format!("nvpn-probe-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let config = directory.join("config.toml");
    AppConfig::generated().save(&config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 1024];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        count.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n198.51.100.77")
            .await
            .unwrap();
    });
    assert!(paid_exit_probe_once(args(Some(config), url)).await.is_err());
    server.abort();
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "an unselected or stopped route must not disclose the host IP to a probe endpoint"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn paid_probe_stun_cannot_escape_a_missing_tunnel() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let server = tokio::spawn(async move {
        let mut request = [0; 1500];
        let (_, peer) = socket.recv_from(&mut request).await.unwrap();
        count.fetch_add(1, Ordering::SeqCst);
        let mut response = request[..20].to_vec();
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response.extend_from_slice(&[0, 1, 0, 8, 0, 1, 0x12, 0x34, 198, 51, 100, 77]);
        socket.send_to(&response, peer).await.unwrap();
    });
    let mut options = args(None, "http://127.0.0.1:1".into());
    options.no_stun = false;
    options.stun_servers = vec![address.to_string()];
    let measurement = paid_exit_probe_measurement(
        &options,
        &AppConfig::generated(),
        unix_timestamp(),
        Some("nvpn-missing"),
    )
    .await;
    server.abort();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "STUN must respect the same tunnel binding as HTTPS"
    );
    assert!(
        measurement.is_err(),
        "an unbound result must not become a successful measurement"
    );
}

fn admitted_fixture() -> (AppConfig, PaidRouteStore, String, DaemonRuntimeState) {
    use nostr_vpn_core::paid_routes::signed_paid_exit_offer_from_config;
    let seller = nostr_sdk::Keys::generate();
    let mut app = AppConfig::generated();
    app.internet_source = InternetSource::PaidManual;
    app.select_public_paid_exit_node(&seller.public_key().to_hex())
        .unwrap();
    let now = unix_timestamp();
    let mut offer = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    offer.channel.accepted_mints = vec!["https://mint.example".into()];
    offer.channel.free_probe_units = 1_048_576;
    offer.channel.grace_units = 262_144;
    let signed =
        signed_paid_exit_offer_from_config("internet", &seller, &offer, None, now).unwrap();
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Fixture", None, now);
    store.upsert_signed_offer(signed, Vec::new(), now).unwrap();
    let opened = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet".into(),
            buyer_npub: app.own_nostr_pubkey_hex().unwrap(),
            mint_url: Some("https://mint.example".into()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: now,
        })
        .unwrap();
    store
        .begin_buyer_session_open_attempt(&opened.session_id, now)
        .unwrap();
    store
        .acknowledge_buyer_session_open(&seller.public_key().to_hex(), &opened.lease_id, now)
        .unwrap();
    let state = DaemonRuntimeState {
        updated_at: now,
        tunnel_interface: "fixture-tun".into(),
        probe_route_generation: "fixture-generation".into(),
        tunnel_exit_peer: Some(seller.public_key().to_hex()),
        vpn_enabled: true,
        vpn_active: true,
        ..DaemonRuntimeState::default()
    };
    (app, store, opened.session_id, state)
}

#[test]
fn paid_probe_binding_requires_live_selected_admitted_exit() {
    use paid_exit_probe_binding_impl::paid_exit_probe_binding_from_state as resolve;
    let (app, store, session, state) = admitted_fixture();
    let now = unix_timestamp();
    let binding = resolve(&app, &store, &session, true, Some(123), &state, now).unwrap();
    assert_eq!(binding.interface, "fixture-tun");
    let mut restored = state.clone();
    restored.probe_route_generation = "after-a-b-a".into();
    assert_ne!(
        binding,
        resolve(&app, &store, &session, true, Some(123), &restored, now).unwrap()
    );
    let mut paused = state.clone();
    paused.vpn_enabled = false;
    let mut inactive = state.clone();
    inactive.vpn_active = false;
    let mut stale = state.clone();
    stale.updated_at = 0;
    let mut other_seller = state.clone();
    other_seller.tunnel_exit_peer = Some(nostr_sdk::Keys::generate().public_key().to_hex());
    let mut old_daemon = state.clone();
    old_daemon.tunnel_interface.clear();
    for bad_state in [paused, inactive, stale, other_seller, old_daemon] {
        assert!(resolve(&app, &store, &session, true, Some(123), &bad_state, now).is_err());
    }
    assert!(resolve(&app, &store, &session, false, Some(123), &state, now).is_err());
    let mut pending = store.clone();
    pending.buyer_session_admissions.clear();
    assert!(resolve(&app, &pending, &session, true, Some(123), &state, now).is_err());
    let mut unselected = store.clone();
    unselected.selected_buyer_session_id.clear();
    assert!(resolve(&app, &unselected, &session, true, Some(123), &state, now).is_err());
    let mut direct = app.clone();
    direct.set_internet_source(InternetSource::Direct);
    assert!(resolve(&direct, &store, &session, true, Some(123), &state, now).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn paid_probe_stun_preserves_bound_ipv4_and_ipv6() {
    #[cfg(target_os = "linux")]
    let interface = "lo";
    #[cfg(target_os = "macos")]
    let interface = "lo0";
    for host in ["127.0.0.1:0", "[::1]:0"] {
        let socket = tokio::net::UdpSocket::bind(host).await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut request = [0; 1500];
            let (_, peer) = socket.recv_from(&mut request).await.unwrap();
            let mut response = request[..20].to_vec();
            response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            let (family, bytes) = match peer.ip() {
                std::net::IpAddr::V4(ip) => (1, ip.octets().to_vec()),
                std::net::IpAddr::V6(ip) => (2, ip.octets().to_vec()),
            };
            let len = 4 + bytes.len() as u16;
            response[2..4].copy_from_slice(&(4 + len).to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&len.to_be_bytes());
            response.extend_from_slice(&[0, family]);
            response.extend_from_slice(&peer.port().to_be_bytes());
            response.extend_from_slice(&bytes);
            socket.send_to(&response, peer).await.unwrap();
        });
        let ip = paid_exit_probe_stun_public_ip(
            &address.to_string(),
            Duration::from_secs(2),
            Some(interface),
        )
        .await
        .unwrap();
        assert_eq!(ip, address.ip().to_string());
        server.await.unwrap();
        assert!(
            paid_exit_probe_stun_public_ip(
                &address.to_string(),
                Duration::from_secs(1),
                Some("nvpn-missing")
            )
            .await
            .is_err()
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires root to create the protected daemon runtime fixture"
)]
async fn paid_probe_command_saves_only_current_bound_measurements() {
    const CHILD: &str = "NVPN_TEST_BOUND_PROBE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "paid_exit_probe_tests::paid_probe_command_saves_only_current_bound_measurements",
                "--nocapture",
                "--include-ignored",
            ])
            .env(CHILD, "1")
            .env(DAEMON_STATUS_MODE_ENV, DAEMON_STATUS_MODE_STATE_FILE)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    #[cfg(target_os = "linux")]
    let interface = "lo";
    #[cfg(target_os = "macos")]
    let interface = "lo0";
    for (host, change_exit) in [
        ("127.0.0.1:0", 0),
        ("[::1]:0", 0),
        ("127.0.0.1:0", 1),
        ("127.0.0.1:0", 2),
    ] {
        let directory =
            std::env::temp_dir().join(format!("nvpn-probe-command-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("config.toml");
        let (app, store, session, mut state) = admitted_fixture();
        app.save(&config).unwrap();
        let store_path = paid_route_store_file_path(&config);
        update_paid_route_store(&store_path, |saved| {
            *saved = store;
            Ok(())
        })
        .unwrap();
        state.tunnel_interface = interface.into();
        write_daemon_state(&daemon_state_file_path(&config).unwrap(), &state).unwrap();
        let listener = tokio::net::TcpListener::bind(host).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut options = args(Some(config.clone()), format!("http://{address}"));
        options.session = session.clone();
        let mut server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            if change_exit == 1 {
                let mut changed = app;
                changed.set_internet_source(InternetSource::Direct);
                changed.save(&config).unwrap();
                assert_eq!(
                    load_or_default_config(&config).unwrap().internet_source,
                    InternetSource::Direct,
                    "the fixture must apply the same source transition as the command"
                );
            } else if change_exit == 2 {
                let path = daemon_state_file_path(&config).unwrap();
                let previous = read_daemon_state(&path).unwrap().unwrap();
                invalidate_daemon_probe_route(&config).unwrap();
                let mut switched = previous.clone();
                switched.probe_route_generation = current_daemon_probe_route_generation();
                switched.tunnel_exit_peer = Some(nostr_sdk::Keys::generate().public_key().to_hex());
                write_current_daemon_probe_state(&path, &switched).unwrap();
                invalidate_daemon_probe_route(&config).unwrap();
                // A previously queued snapshot cannot reauthorize the old A.
                write_current_daemon_probe_state(&path, &previous).unwrap();
                assert!(
                    read_daemon_state(&path)
                        .unwrap()
                        .unwrap()
                        .tunnel_exit_peer
                        .is_none()
                );
                let mut restored = previous;
                restored.probe_route_generation = current_daemon_probe_route_generation();
                write_current_daemon_probe_state(&path, &restored).unwrap();
            }
            assert_eq!(peer.ip(), address.ip(), "request must use the bound interface");
            let body = "198.51.100.42";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let result = paid_exit_probe_once(options).await;
        tokio::time::timeout(Duration::from_secs(3), &mut server)
            .await
            .expect("probe fixture receives the bound request")
            .unwrap();
        let saved = load_paid_route_store(&store_path).unwrap();
        let observed = &saved.sessions[&session].session.realized_exit_ip;
        if change_exit != 0 {
            assert!(result.is_err(), "route change scenario {change_exit}");
            assert!(
                observed.is_none(),
                "a result for a changed route must not be saved"
            );
        } else {
            result.unwrap();
            assert_eq!(observed.as_deref(), Some("198.51.100.42"));
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
