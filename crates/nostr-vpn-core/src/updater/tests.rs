use super::*;

#[test]
fn auto_source_checks_htree_before_github() {
    assert_eq!(
        manifest_urls_for(ProductUpdateSource::Auto, None),
        vec![
            HTREE_MANIFEST_URL.to_string(),
            GITHUB_LATEST_RELEASE_URL.to_string(),
        ]
    );
}

#[test]
fn auto_source_can_cross_check_github_when_secure_hashtree_is_not_newer() {
    assert!(should_try_github_fallback(ProductUpdateSource::Auto, false));
    assert!(!should_try_github_fallback(ProductUpdateSource::Auto, true));
    assert!(!should_try_github_fallback(
        ProductUpdateSource::Hashtree,
        false
    ));
    assert!(!should_try_github_fallback(
        ProductUpdateSource::Github,
        false
    ));
}

#[test]
fn compares_semver_like_tags() {
    assert!(version_is_newer("v4.0.55", "4.0.52"));
    assert!(version_is_newer("v4.0.13", "4.0.12"));
    assert!(!version_is_newer("v4.0.12", "4.0.12"));
    assert!(!version_is_newer("v4.0.11", "4.0.12"));
}

#[test]
fn resolves_relative_manifest_asset_urls() {
    assert_eq!(
        manifest_asset_url(
            "https://example.invalid/latest/release.json",
            "assets/nvpn.tgz"
        ),
        "https://example.invalid/latest/assets/nvpn.tgz"
    );
}

#[tokio::test]
async fn updater_discovers_signed_roots_from_configured_websocket_seed_without_vpn_or_relays() {
    use nostr_pubsub::{EventBus, EventSource, VerifiedEvent};
    use nostr_sdk::prelude::{EventBuilder, Filter, Keys, Kind, Tag, TagKind};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("seed port");
    let address = listener.local_addr().expect("seed address");
    drop(listener);
    let mut app = AppConfig {
        fips_bootstrap_enabled: false,
        fips_websocket_seed_urls: vec!["ws://unused.invalid/fips".to_string()],
        ..AppConfig::default()
    };
    let mut seed_config = update_endpoint_config(&app);
    assert!(!seed_config.node.discovery.nostr.enabled);
    assert!(!seed_config.dns.enabled);
    assert!(!seed_config.node.control.enabled);
    assert!(seed_config.peers.is_empty());
    seed_config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        bind_addr: Some(address.to_string()),
        ..WebSocketConfig::default()
    });
    let seed = Arc::new(
        FipsEndpoint::builder()
            .config(seed_config)
            .without_system_tun()
            .bind()
            .await
            .expect("seed endpoint"),
    );
    let publisher = FipsPubsubClient::start(Arc::clone(&seed), FipsPubsubClientOptions::default())
        .await
        .expect("seed pubsub");
    let keys = Keys::generate();
    let event = EventBuilder::new(Kind::Custom(30_064), "")
        .tags([
            Tag::identifier("releases/test-update"),
            Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
            Tag::custom(TagKind::Custom("hash".into()), ["ab".repeat(32)]),
        ])
        .sign_with_keys(&keys)
        .expect("signed release root");
    publisher
        .publish(
            VerifiedEvent::try_from(event.clone()).expect("verified root"),
            EventSource::local_index("release-publisher"),
        )
        .await
        .expect("retain root at seed");
    app.fips_peer_endpoints.insert(
        seed.npub().to_string(),
        vec![format!("websocket:ws://{address}/fips")],
    );
    let (endpoint, client) = update_pubsub(&app)
        .await
        .expect("standalone updater network");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let subscription = client
        .fresh_subscriber()
        .subscribe(
            vec![
                Filter::new()
                    .author(keys.public_key())
                    .kind(Kind::Custom(30_064))
                    .identifier("releases/test-update"),
            ],
            Arc::new(move |delivery| {
                let _ = tx.send(delivery);
            }),
        )
        .await
        .expect("fresh update subscription");
    let delivery = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("seed replay before deadline")
        .expect("signed update received");
    assert_eq!(delivery.event.as_event().id, event.id);
    assert!(
        endpoint
            .relay_statuses()
            .await
            .expect("relay status")
            .is_empty()
    );
    subscription.close().await.expect("close subscription");
    client.shutdown_shared().await;
    endpoint.shutdown().await.expect("stop updater endpoint");
    publisher.shutdown().await;
    seed.shutdown().await.expect("stop seed");
}

#[tokio::test]
async fn cached_root_without_live_peers_cannot_claim_current_version_is_latest() {
    use nostr_sdk::prelude::{EventBuilder, Keys, Kind, Tag, TagKind, ToBech32};
    let keys = Keys::generate();
    let directory = std::env::temp_dir().join(format!("nvpn-update-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("cache directory");
    let config_path = directory.join("config.toml");
    let cached = EventBuilder::new(Kind::Custom(30_064), "")
        .tags([
            Tag::identifier("releases/offline-test"),
            Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
            Tag::custom(TagKind::Custom("hash".into()), ["ab".repeat(32)]),
        ])
        .sign_with_keys(&keys)
        .expect("cached signed root");
    fs::write(
        crate::control_pubsub::control_pubsub_store_path(&config_path),
        serde_json::to_vec(&serde_json::json!({ "events": [cached] })).expect("cache JSON"),
    )
    .expect("write cached root");
    let app = AppConfig {
        fips_bootstrap_enabled: false,
        ..AppConfig::default()
    };
    let (endpoint, client) = update_pubsub(&app).await.expect("offline updater network");
    let result = secure_selection_with_pubsub(
        "9999.0.0",
        ProductUpdateMode::Cli,
        Arc::new(client.fresh_subscriber()),
        UpdateRef {
            npub: keys.public_key().to_bech32().expect("release publisher"),
            tree_name: "releases/offline-test".to_string(),
            path: Some("latest".to_string()),
        },
        Some(&config_path),
    )
    .await;
    assert!(
        result.is_err(),
        "cached root must not make an offline check conclusive"
    );
    client.shutdown_shared().await;
    endpoint.shutdown().await.expect("stop updater endpoint");
    std::fs::remove_dir_all(directory).expect("remove test cache");
}
