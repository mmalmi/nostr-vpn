mod support;

use std::time::Duration;

use nostr_sdk::prelude::Keys;
use nostr_vpn_core::join_requests::{
    MeshJoinRequest, NostrJoinRequestListener, publish_join_request,
};
use tokio::time::timeout;

use crate::support::ws_relay::WsRelay;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_join_requests_arrive_over_local_nostr_relay_without_plaintext_leaks() {
    let mut relay = WsRelay::new();
    relay.start().await.expect("relay should start");
    let relay_url = relay.url().expect("relay url");

    let owner_keys = Keys::generate();
    let requester_keys = Keys::generate();
    let owner_pubkey = owner_keys.public_key().to_hex();
    let requester_pubkey = requester_keys.public_key().to_hex();

    let listener =
        NostrJoinRequestListener::new_with_keys(owner_keys).expect("owner join request listener");
    listener
        .connect(std::slice::from_ref(&relay_url))
        .await
        .expect("listener connect");

    tokio::time::sleep(Duration::from_millis(200)).await;

    publish_join_request(
        requester_keys,
        std::slice::from_ref(&relay_url),
        owner_pubkey.clone(),
        MeshJoinRequest {
            network_id: "mesh-home".to_string(),
            requester_node_name: "alice-phone".to_string(),
        },
    )
    .await
    .expect("join request should publish");

    let received = timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("timed out waiting for join request")
        .expect("join request expected");

    assert_eq!(received.sender_pubkey, requester_pubkey);
    assert_eq!(
        received.request,
        MeshJoinRequest {
            network_id: "mesh-home".to_string(),
            requester_node_name: "alice-phone".to_string(),
        }
    );

    let mut relay_event = None;
    for _ in 0..50 {
        let events = relay.events_snapshot().await;
        relay_event = events
            .into_iter()
            .find(|event| event.pubkey == received.sender_pubkey);
        if relay_event.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let event = relay_event.expect("join request event should be stored on relay");
    let outer_event_json =
        serde_json::to_string(&event).expect("relay event snapshot should serialize");
    assert!(!outer_event_json.contains("mesh-home"));
    assert!(!outer_event_json.contains("alice-phone"));

    listener.disconnect().await;
    relay.stop().await;
}
