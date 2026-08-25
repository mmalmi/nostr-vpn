use crate::*;
use nostr_sdk::async_utility::futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::control_pubsub::FIPS_PEER_ADVERT_KIND;
use nostr_vpn_core::paid_routes::signed_paid_exit_offer_from_config;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

include!("runtime_misc_paid_exit_relay/relayless.rs");
include!("runtime_misc_paid_exit_relay/settlement.rs");

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn control_pubsub_relay_mode_bridges_relay_ingress_and_mesh_egress() {
    use nostr_sdk::prelude::{EventBuilder, Kind, Tag, TagKind, Timestamp};
    use nostr_social_graph::Rating;
    use nostr_social_memory::RatingEventExt;
    use nostr_vpn_core::config::{NostrPubsubConfig, NostrPubsubMode};

    let endpoint_keys = Keys::generate();
    let blocked_author = Keys::generate();
    let endpoint_advert = |author: &Keys, address: &str| {
        EventBuilder::new(
            Kind::Custom(37_195),
            serde_json::json!({
                "identifier": "fips-overlay-v1",
                "version": 1,
                "endpoints": [{"transport": "udp", "addr": address}],
            })
            .to_string(),
        )
        .tags([
            Tag::identifier("fips-overlay-v1"),
            Tag::custom(TagKind::custom("protocol"), ["fips-overlay-v1".to_string()]),
            Tag::custom(TagKind::custom("version"), ["1".to_string()]),
            Tag::expiration(Timestamp::from(unix_timestamp().saturating_add(3_600))),
        ])
        .sign_with_keys(author)
        .expect("signed FIPS endpoint advert")
    };
    let relay_event = endpoint_advert(&Keys::generate(), "8.8.8.8:51820");
    let blocked_relay_event = endpoint_advert(&blocked_author, "8.8.4.4:51820");
    let relay = LocalNostrRelay::spawn_with_events(vec![
        serde_json::to_value(&relay_event).expect("relay event JSON"),
        serde_json::to_value(&blocked_relay_event).expect("blocked relay event JSON"),
    ])
    .await;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("nvpn-control-relay-{nonce}"));
    let config_path = directory.join("config.toml");
    let mut rating = Rating::new(
        endpoint_keys.public_key().to_hex(),
        blocked_author.public_key().to_hex(),
        0,
        0,
        100,
    );
    rating.scope = Some("fips.peer".to_string());
    rating.created_at = unix_timestamp();
    rating.sample_count = Some(1);
    let blocked_author_rating = rating
        .to_event(&endpoint_keys)
        .expect("signed blocked-author rating");
    let store_path = crate::control_pubsub_runtime::control_pubsub_store_file_path(&config_path);
    std::fs::create_dir_all(store_path.parent().expect("store parent"))
        .expect("create control pubsub store parent");
    std::fs::write(
        &store_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "events": [blocked_author_rating],
        }))
        .expect("encode seeded reputation store"),
    )
    .expect("seed control pubsub reputation store");
    let mut endpoint_config = fips_endpoint::Config::new();
    endpoint_config.node.discovery.nostr.enabled = true;
    endpoint_config.node.discovery.nostr.advertise = true;
    endpoint_config.node.discovery.nostr.peerfinding_source =
        fips_endpoint::NostrPeerfindingSource::External;
    endpoint_config.transports.udp =
        fips_endpoint::TransportInstances::Single(fips_endpoint::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            advertise_on_nostr: Some(true),
            public: Some(false),
            ..fips_endpoint::UdpConfig::default()
        });
    let endpoint = Arc::new(
        fips_core::FipsEndpoint::builder()
            .config(endpoint_config)
            .identity_nsec(
                endpoint_keys
                    .secret_key()
                    .to_bech32()
                    .expect("endpoint nsec"),
            )
            .without_system_tun()
            .bind()
            .await
            .expect("bind FIPS endpoint"),
    );
    let runtime = crate::control_pubsub_runtime::ControlPubsubFipsRuntime::start(
        Arc::clone(&endpoint),
        NostrPubsubConfig {
            mode: NostrPubsubMode::Relay,
            ..NostrPubsubConfig::default()
        },
        vec![relay.url.clone()],
        Some(store_path),
    )
    .await
    .expect("start control relay bridge")
    .expect("relay mode is enabled");

    let local_advert_author = endpoint_keys.public_key().to_hex();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if relay.events().iter().any(|event| {
                event["kind"].as_u64() == Some(FIPS_PEER_ADVERT_KIND.into())
                    && event["pubkey"].as_str() == Some(local_advert_author.as_str())
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("local signed FIPS advert reaches the configured pubsub relay");

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if runtime
                .events()
                .await
                .iter()
                .any(|event| event.id == relay_event.id)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("relay event reaches the control pubsub cache");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        runtime
            .events()
            .await
            .iter()
            .all(|event| event.id != blocked_relay_event.id),
        "known-bad relay author must be filtered before cache and mesh fanout"
    );

    let mesh_event = EventBuilder::new(Kind::Custom(7_368), "mesh rating")
        .sign_with_keys(&Keys::generate())
        .expect("signed mesh event");
    let mesh_event_id = mesh_event.id.to_hex();
    assert!(
        crate::control_pubsub_runtime::queue_control_pubsub_event(&config_path, &mesh_event)
            .expect("queue mesh event through relay bridge")
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if relay
                .events()
                .iter()
                .any(|event| event["id"].as_str() == Some(mesh_event_id.as_str()))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("mesh event reaches the relay");

    runtime.stop().await;
    endpoint.shutdown().await.expect("shutdown FIPS endpoint");
    relay.stop().await;
    let _ = std::fs::remove_dir_all(directory);
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_offer_publish_and_discover_roundtrips_without_relays() {
    use nostr_vpn_core::config::NostrPubsubMode;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("nvpn-paid-exit-pubsub-{nonce}"));
    let config_path = directory.join("config.toml");
    let mut app = AppConfig::generated();
    app.nostr.relays.clear();
    app.nostr.pubsub.mode = NostrPubsubMode::Client;
    app.paid_exit.enabled = true;
    app.paid_exit.pricing.price_msat_per_gb = 750;
    app.paid_exit.channel.accepted_mints = vec!["https://mint.example".to_string()];
    app.paid_exit.location.country_code = "fi".to_string();
    app.paid_exit.normalize();

    let keys = app.nostr_keys().expect("app keys");
    let signed = signed_paid_exit_offer_from_config(
        "internet-exit",
        &keys,
        &app.paid_exit,
        Some(local_paid_exit_quality_hint()),
        unix_timestamp(),
    )
    .expect("signed offer");
    let offer = signed.offer().expect("offer");

    let publish = publish_paid_exit_offer_pubsub(&app, &config_path, &signed)
        .expect("publish paid exit offer");
    assert_eq!(publish["nostr_pubsub_queued"].as_bool(), Some(true));

    let discovered = std::fs::read_dir(
        crate::control_pubsub_runtime::control_pubsub_outbox_directory(&config_path),
    )
    .expect("read Nostr pubsub outbox")
    .filter_map(|entry| entry.ok())
    .filter_map(|entry| std::fs::read(entry.path()).ok())
    .filter_map(|bytes| serde_json::from_slice::<Event>(&bytes).ok())
    .filter_map(|event| SignedPaidRouteOffer::from_event(event).ok())
    .collect::<Vec<_>>();
    assert_eq!(discovered.len(), 1);
    let discovered_offer = discovered[0].offer().expect("discovered offer");
    assert_eq!(discovered_offer.offer_id, offer.offer_id);
    assert_eq!(discovered_offer.seller_npub, offer.seller_npub);
    assert_eq!(discovered_offer.location.country_code, "FI");
    assert_eq!(discovered_offer.pricing.price_msat_per_gb, 750);

    let _ = std::fs::remove_dir_all(directory);
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_rating_cache_filters_untrusted_pubsub_publishers() {
    let trusted_author = Keys::generate();
    let untrusted_author = Keys::generate();
    let trusted_npub = trusted_author.public_key().to_bech32().unwrap();
    let untrusted_npub = untrusted_author.public_key().to_bech32().unwrap();
    let trusted_seller = Keys::generate();
    let spam_seller = Keys::generate();
    let trusted_seller_npub = trusted_seller.public_key().to_bech32().unwrap();
    let spam_seller_npub = spam_seller.public_key().to_bech32().unwrap();
    let trusted_event = build_paid_exit_rating_fact_event(
        &trusted_author,
        &trusted_npub,
        &trusted_seller_npub,
        "fips.peer",
        "session-trusted",
        90,
        600,
    )
    .expect("trusted rating event");
    let spam_event = build_paid_exit_rating_fact_event(
        &untrusted_author,
        &untrusted_npub,
        &spam_seller_npub,
        "fips.peer",
        "session-spam",
        100,
        601,
    )
    .expect("spam rating event");
    let trusted_authors =
        paid_exit_trusted_rating_author_set(&[trusted_author.public_key().to_hex()]).unwrap();
    let events = json!({
        "events": [
            serde_json::to_value(spam_event).expect("encode spam event"),
            serde_json::to_value(trusted_event).expect("encode trusted event"),
        ]
    });

    let scores = paid_exit_rating_scores_from_value(&events, "fips.peer", &trusted_authors)
        .expect("rating scores");
    assert_eq!(
        scores.get(&trusted_seller_npub),
        Some(&PaidExitRatingScore {
            score: 80,
            created_at: 600,
        })
    );
    assert!(!scores.contains_key(&spam_seller_npub));
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_rating_cache_selects_matching_historical_facts() {
    let rater = Keys::generate();
    let rater_npub = rater.public_key().to_bech32().expect("rater npub");
    let seller = Keys::generate();
    let seller_npub = seller.public_key().to_bech32().expect("seller npub");
    let other_seller = Keys::generate();
    let other_seller_npub = other_seller
        .public_key()
        .to_bech32()
        .expect("other seller npub");
    let other_scope = build_paid_exit_rating_fact_event(
        &rater,
        &rater_npub,
        &other_seller_npub,
        "nvpn.exit",
        "history-other-scope",
        100,
        499,
    )
    .expect("other scope rating event");
    let wanted = build_paid_exit_rating_fact_event(
        &rater,
        &rater_npub,
        &seller_npub,
        "fips.peer",
        "history-fips-peer",
        95,
        500,
    )
    .expect("wanted rating event");
    let events = json!({
        "events": [
            serde_json::to_value(other_scope).expect("encode other event"),
            serde_json::to_value(wanted).expect("encode wanted event"),
        ]
    });

    let scores = paid_exit_rating_scores_from_value(&events, "fips.peer", &HashSet::new())
        .expect("rating scores");
    assert_eq!(
        scores.get(&seller_npub),
        Some(&PaidExitRatingScore {
            score: 90,
            created_at: 500,
        })
    );
    assert!(!scores.contains_key(&other_seller_npub));
}

#[cfg(feature = "paid-exit")]
struct LocalNostrRelay {
    url: String,
    events: Arc<Mutex<Vec<serde_json::Value>>>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "paid-exit")]
impl LocalNostrRelay {
    async fn spawn_with_events(initial_events: Vec<serde_json::Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local relay");
        let url = format!("ws://{}", listener.local_addr().expect("relay addr"));
        let events = Arc::new(Mutex::new(initial_events));
        let (shutdown, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(run_local_nostr_relay(
            listener,
            Arc::clone(&events),
            shutdown_rx,
        ));
        Self {
            url,
            events,
            shutdown: Some(shutdown),
            handle,
        }
    }

    fn events(&self) -> Vec<serde_json::Value> {
        self.events.lock().expect("relay events lock").clone()
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.handle.await;
    }
}

#[cfg(feature = "paid-exit")]
async fn run_local_nostr_relay(
    listener: TcpListener,
    events: Arc<Mutex<Vec<serde_json::Value>>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let events = Arc::clone(&events);
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(message) = ws.next().await {
                        let Ok(message) = message else {
                            break;
                        };
                        let Some(text) = relay_message_text(&message) else {
                            continue;
                        };
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                            continue;
                        };
                        let Some(items) = value.as_array() else {
                            continue;
                        };
                        match items.first().and_then(serde_json::Value::as_str) {
                            Some("EVENT") => {
                                if let Some(event) = items.get(1).cloned() {
                                    let event_id = event
                                        .get("id")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or_default()
                                        .to_string();
                                    events.lock().expect("relay events lock").push(event);
                                    let ok = serde_json::json!(["OK", event_id, true, ""]);
                                    let _ = ws.send(Message::Text(ok.to_string().into())).await;
                                }
                            }
                            Some("REQ") => {
                                let Some(subscription_id) =
                                    items.get(1).and_then(serde_json::Value::as_str)
                                else {
                                    continue;
                                };
                                let snapshot = events.lock().expect("relay events lock").clone();
                                for event in snapshot {
                                    let response =
                                        serde_json::json!(["EVENT", subscription_id, event]);
                                    let _ =
                                        ws.send(Message::Text(response.to_string().into())).await;
                                }
                                let eose = serde_json::json!(["EOSE", subscription_id]);
                                let _ = ws.send(Message::Text(eose.to_string().into())).await;
                            }
                            Some("CLOSE") => break,
                            _ => {}
                        }
                    }
                });
            }
        }
    }
}

#[cfg(feature = "paid-exit")]
fn relay_message_text(message: &Message) -> Option<&str> {
    match message {
        Message::Text(text) => Some(text.as_ref()),
        _ => None,
    }
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_buy_and_use_select_public_exit_route() {
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::paid_route_store::{PaidRouteStore, update_paid_route_store};
    use nostr_vpn_core::paid_routes::{
        PaidExitConfig, signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints,
    };

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-use-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let mut app = AppConfig::generated();
    app.connect_to_non_roster_fips_peers = false;
    app.fips_nostr_discovery_enabled = false;
    app.wireguard_exit.enabled = true;
    app.save(&config_path).expect("save buyer config");

    let seller = Keys::generate();
    let mut offer_config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    let now_unix = unix_timestamp();
    let seller_endpoint = "1.1.1.1:2122".to_string();
    let signed_offer = signed_paid_exit_offer_from_config_with_receiver_and_fips_endpoints(
        "internet-exit",
        &seller,
        &offer_config,
        None,
        std::slice::from_ref(&seller_endpoint),
        None,
        now_unix,
    )
    .expect("sign offer");
    let offer = signed_offer.offer().expect("offer");

    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Example", None, now_unix);
    store
        .upsert_signed_offer(
            signed_offer,
            vec!["wss://relay.example".to_string()],
            now_unix,
        )
        .expect("store offer");
    update_paid_route_store(&store_path, |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("write store");

    let buy = paid_exit_buy_once(PaidExitBuyArgs {
        config: Some(config_path.clone()),
        offer: Some("internet-exit".to_string()),
        best_rated: false,
        mint: None,
        channel_capacity_sat: Some(10),
        initial_paid_msat: 0,
        no_select_exit_node: false,
        no_reload_daemon: true,
        json: false,
    })
    .expect("buy paid exit");

    assert_eq!(buy.session.seller_npub, offer.seller_npub);
    let seller_hex = seller.public_key().to_hex();
    assert_eq!(buy.selected_exit_node.as_deref(), Some(seller_hex.as_str()));
    assert!(!buy.daemon_reload_attempted);
    let saved = AppConfig::load(&config_path).expect("load selected config");
    assert_eq!(saved.exit_node, seller_hex);
    assert_eq!(saved.internet_source, InternetSource::PaidManual);
    assert!(saved.connect_to_non_roster_fips_peers);
    assert!(!saved.fips_nostr_discovery_enabled);
    assert!(!saved.wireguard_exit.enabled);
    assert_eq!(
        saved.fips_peer_endpoint_hints(&offer.seller_npub),
        vec![seller_endpoint.clone()]
    );

    let mut reset = saved;
    reset.exit_node.clear();
    reset.connect_to_non_roster_fips_peers = false;
    reset.fips_nostr_discovery_enabled = false;
    reset.wireguard_exit.enabled = true;
    reset
        .set_fips_peer_endpoint_hints(&offer.seller_npub, &[])
        .expect("clear seller endpoint hints");
    reset.save(&config_path).expect("save reset config");

    let selected = paid_exit_use_once(PaidExitUseArgs {
        config: Some(config_path.clone()),
        session: buy.session.session_id,
        no_reload_daemon: true,
        json: false,
    })
    .expect("use paid exit session");

    assert_eq!(selected.seller_npub, offer.seller_npub);
    assert_eq!(selected.selected_exit_node, seller_hex);
    assert!(!selected.daemon_reload_attempted);
    let saved = AppConfig::load(&config_path).expect("load used config");
    assert_eq!(saved.exit_node, seller_hex);
    assert_eq!(saved.internet_source, InternetSource::PaidManual);
    assert!(saved.connect_to_non_roster_fips_peers);
    assert!(!saved.fips_nostr_discovery_enabled);
    assert!(!saved.wireguard_exit.enabled);
    assert_eq!(
        saved.fips_peer_endpoint_hints(&offer.seller_npub),
        vec![seller_endpoint]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[test]
fn paid_exit_buy_selects_route_before_payment_or_free_probe() {
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::paid_route_store::{
        PaidRouteStore, load_paid_route_store, update_paid_route_store,
    };
    use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-select-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let app = AppConfig::generated();
    app.save(&config_path).expect("save buyer config");

    let seller = Keys::generate();
    let mut offer_config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    offer_config.pricing.price_msat_per_gb = 1_000;
    offer_config.channel.accepted_mints = vec!["https://mint.example".to_string()];
    offer_config.channel.free_probe_units = 0;
    offer_config.channel.grace_units = 0;
    let now_unix = unix_timestamp();
    let signed_offer =
        signed_paid_exit_offer_from_config("internet-exit", &seller, &offer_config, None, now_unix)
            .expect("sign offer");

    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Example", None, now_unix);
    store
        .upsert_signed_offer(
            signed_offer,
            vec!["wss://relay.example".to_string()],
            now_unix,
        )
        .expect("store offer");
    update_paid_route_store(&store_path, |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("write store");

    let buy = paid_exit_buy_once(PaidExitBuyArgs {
        config: Some(config_path.clone()),
        offer: Some("internet-exit".to_string()),
        best_rated: false,
        mint: None,
        channel_capacity_sat: Some(10),
        initial_paid_msat: 0,
        no_select_exit_node: false,
        no_reload_daemon: true,
        json: false,
    })
    .expect("buy paid exit");

    let stored = load_paid_route_store(&store_path).expect("reload bought session");
    assert!(
        !stored
            .buyer_session_allows_routing(&buy.session.session_id, unix_timestamp())
            .expect("read pre-payment route state")
    );
    let seller_hex = seller.public_key().to_hex();
    assert_eq!(buy.selected_exit_node.as_deref(), Some(seller_hex.as_str()));
    let saved = AppConfig::load(&config_path).expect("load selected config");
    assert_eq!(saved.exit_node, seller_hex);
    assert!(saved.exit_node_public_paid_exit);

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_create_payment_command_updates_buyer_session() {
    use cashu_service::CashuSpilmanPayment;
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{OpenPaidRouteBuyerSessionRequest, PaidRouteStore};
    use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};
    use serde_json::json;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-create-payment-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
    let app = AppConfig::generated();
    app.save(&config_path).expect("save buyer config");

    let seller = Keys::generate();
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

    let buyer_npub = app
        .nostr_keys()
        .expect("buyer keys")
        .public_key()
        .to_bech32()
        .expect("buyer npub");
    let store_path = paid_route_store_file_path(&config_path);
    let mut store = PaidRouteStore::default();
    store.upsert_wallet_mint("https://mint.example", "Example", None, 122);
    store
        .upsert_signed_offer(signed_offer, vec!["wss://relay.example".to_string()], 124)
        .expect("store offer");
    let session = store
        .open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector: "internet-exit".to_string(),
            buyer_npub,
            mint_url: Some("https://mint.example".to_string()),
            channel_capacity_sat: Some(10),
            initial_paid_msat: 0,
            now_unix: 125,
        })
        .expect("open buyer session");
    update_paid_route_store(&store_path, |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("write store");

    paid_exit_create_payment_command(PaidExitCreatePaymentArgs {
        config: Some(config_path.clone()),
        session: session.session_id.clone(),
        kind: PaidExitCreatePaymentKind::BalanceUpdate,
        payment: Some(
            serde_json::to_string(&runtime_spilman_payment(&session.channel_id, 1))
                .expect("serialize payment"),
        ),
        payment_stdin: false,
        open_from_wallet: false,
        sign_from_wallet: false,
        mint: None,
        keyset_id: None,
        keyset_info: None,
        keyset_info_file: None,
        max_amount_per_output: 64,
        delivered_units: Some(100),
        paid_msat: Some(1_000),
        json: false,
    })
    .await
    .expect("create buyer payment");

    let store = load_paid_route_store(&store_path).expect("load store");
    let record = &store.sessions[&session.session_id];
    assert_eq!(record.session.usage.billable_bytes, 100);
    assert_eq!(record.session.payment.paid_msat, 1_000);
    assert_eq!(
        record
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.balance),
        Some(1)
    );

    let _ = std::fs::remove_dir_all(&dir);

    fn runtime_spilman_payment(channel_id: &str, balance: u64) -> CashuSpilmanPayment {
        CashuSpilmanPayment {
            channel_id: channel_id.to_string(),
            balance,
            signature: format!("signature-{channel_id}-{balance}"),
            params: Some(json!({"channel": channel_id})),
            funding_proofs: Some(json!({"proofs": []})),
        }
    }
}

#[cfg(feature = "paid-exit")]
#[tokio::test]
async fn paid_exit_stream_payments_signs_due_buyer_usage_update() {
    use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentSigner};
    use nostr_sdk::prelude::{Keys, ToBech32};
    use nostr_vpn_core::paid_route_store::{
        OpenPaidRouteBuyerSessionRequest, PaidRouteBuyerPaymentUpdatesDueRequest, PaidRouteStore,
        RecordPaidRouteBuyerUsageRequest,
    };
    use nostr_vpn_core::paid_routes::{
        PaidExitConfig, PaidRouteUsage, signed_paid_exit_offer_from_config,
    };
    use serde_json::json;

    let mut app = AppConfig::generated();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("nvpn-paid-exit-stream-{nonce}"));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let config_path = dir.join("config.toml");
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

    let mut due = store.buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
        now_unix: 127,
        min_increment_msat: 1,
    });
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].session_id, session.session_id);
    assert_eq!(due[0].delivered_units, 110);
    assert_eq!(due[0].target_paid_msat, 1_000);

    let result =
        paid_exit_stream_payment_updates_with_signer(PaidExitStreamPaymentUpdatesRequest {
            app: &app,
            config_path: &config_path,
            store: &mut store,
            signer: &RuntimeFakePaymentSigner,
            buyer_npub: &buyer_npub,
            due: std::mem::take(&mut due),
            queue: true,
            now_unix: 128,
        });

    assert!(result.changed);
    assert_eq!(result.signed.len(), 1);
    assert_eq!(result.persisted_count(), 1);
    assert!(result.errors.is_empty());
    assert_eq!(
        result.signed[0]["due"]["target_paid_msat"].as_u64(),
        Some(1_000)
    );
    assert_eq!(
        result.signed[0]["payment"]["paid_msat"].as_u64(),
        Some(1_000)
    );
    assert_eq!(result.signed[0]["persisted"].as_bool(), Some(true));

    let record = &store.sessions[&session.session_id];
    assert_eq!(record.session.usage.rx_bytes, 60);
    assert_eq!(record.session.usage.tx_bytes, 50);
    assert_eq!(record.session.payment.paid_msat, 1_000);
    assert_eq!(
        record
            .session
            .payment
            .cashu_spilman_payment
            .as_ref()
            .map(|payment| payment.balance),
        Some(1)
    );
    assert!(
        store
            .buyer_payment_updates_due(PaidRouteBuyerPaymentUpdatesDueRequest {
                now_unix: 129,
                min_increment_msat: 1,
            })
            .is_empty()
    );
    update_paid_route_store(&paid_route_store_file_path(&config_path), |target| {
        *target = store.clone();
        Ok(())
    })
    .expect("persist buyer store");
    let queued = load_paid_exit_payment_outbox(&config_path);
    assert_eq!(queued.len(), 1);
    assert!(
        acknowledge_paid_exit_payment(&config_path, &seller.public_key().to_hex(), &queued[0].id)
            .expect("acknowledge seller payment")
    );
    let acknowledged = load_paid_route_store(&paid_route_store_file_path(&config_path))
        .expect("load acknowledged buyer store");
    assert!(
        !acknowledged
            .buyer_has_seller_admission(&seller.public_key().to_hex(), 129)
            .expect("payment acknowledgment is not seller admission")
    );
    assert!(load_paid_exit_payment_outbox(&config_path).is_empty());
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
    }
}
