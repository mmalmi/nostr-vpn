use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};

use crate::config::{normalize_nostr_pubkey, normalize_runtime_network_id};
use crate::signaling::NOSTR_KIND_NOSTR_VPN;

const JOIN_REQUEST_PROTOCOL_VERSION: u8 = 1;
const JOIN_REQUEST_EXPIRATION_SECS: u64 = 7 * 24 * 60 * 60;
const JOIN_REQUEST_LOOKBACK_SECS: u64 = JOIN_REQUEST_EXPIRATION_SECS;
const JOIN_REQUEST_IDENTIFIER_PREFIX: &str = "join-request:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshJoinRequest {
    pub network_id: String,
    #[serde(default)]
    pub requester_node_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMeshJoinRequest {
    pub sender_pubkey: String,
    pub requested_at: u64,
    pub request: MeshJoinRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MeshJoinRequestEnvelope {
    v: u8,
    network_id: String,
    #[serde(default)]
    requester_node_name: String,
}

pub struct NostrJoinRequestListener {
    own_pubkey: String,
    keys: Keys,
    client: Client,
    connected: AtomicBool,
    recv_rx: Mutex<broadcast::Receiver<ReceivedMeshJoinRequest>>,
    recv_tx: broadcast::Sender<ReceivedMeshJoinRequest>,
}

impl NostrJoinRequestListener {
    pub fn from_secret_key(secret_key: &str) -> Result<Self> {
        let keys = Keys::parse(secret_key).context("invalid nostr secret key")?;
        Self::new_with_keys(keys)
    }

    pub fn new_with_keys(keys: Keys) -> Result<Self> {
        let own_pubkey = keys.public_key().to_hex();
        let client = ClientBuilder::new()
            .signer(keys.clone())
            .database(nostr_sdk::database::MemoryDatabase::new())
            .build();
        let (recv_tx, recv_rx) = broadcast::channel(256);

        Ok(Self {
            own_pubkey,
            keys,
            client,
            connected: AtomicBool::new(false),
            recv_rx: Mutex::new(recv_rx),
            recv_tx,
        })
    }

    pub async fn connect(&self, relays: &[String]) -> Result<()> {
        if self.connected.load(Ordering::Relaxed) {
            return Ok(());
        }

        for relay in relays {
            self.client
                .add_relay(relay)
                .await
                .with_context(|| format!("failed to add relay {relay}"))?;
        }

        self.client.connect().await;
        self.client
            .subscribe(
                vec![
                    Filter::new()
                        .kind(join_request_event_kind())
                        .custom_tag(
                            SingleLetterTag::lowercase(Alphabet::P),
                            vec![self.own_pubkey.clone()],
                        )
                        .since(Timestamp::now() - Duration::from_secs(JOIN_REQUEST_LOOKBACK_SECS)),
                ],
                None,
            )
            .await
            .context("failed to subscribe to mesh join request events")?;

        self.start_event_forwarder();
        self.connected.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub async fn disconnect(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.client.disconnect().await;
    }

    pub async fn recv(&self) -> Option<ReceivedMeshJoinRequest> {
        let mut rx = self.recv_rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    fn start_event_forwarder(&self) {
        let mut notifications = self.client.notifications();
        let own_pubkey = self.own_pubkey.clone();
        let keys = self.keys.clone();
        let recv_tx = self.recv_tx.clone();

        tokio::spawn(async move {
            loop {
                let notification = match notifications.recv().await {
                    Ok(notification) => notification,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                };

                let RelayPoolNotification::Event { event, .. } = notification else {
                    continue;
                };
                let Some(request) = decode_received_join_request_event(&event, &own_pubkey, &keys)
                else {
                    continue;
                };
                let _ = recv_tx.send(request);
            }
        });
    }
}

pub async fn publish_join_request(
    keys: Keys,
    relays: &[String],
    recipient_pubkey: String,
    request: MeshJoinRequest,
) -> Result<()> {
    let request = normalize_join_request(request)?;
    let recipient = normalize_nostr_pubkey(&recipient_pubkey)?;
    let recipient_pubkey = PublicKey::from_hex(&recipient)
        .with_context(|| format!("invalid recipient pubkey {recipient}"))?;

    let envelope = encode_join_request(request)?;
    let content =
        serde_json::to_string(&envelope).context("failed to serialize mesh join request")?;
    let encrypted_content = nip44::encrypt(
        keys.secret_key(),
        &recipient_pubkey,
        &content,
        nip44::Version::V2,
    )
    .context("failed to encrypt mesh join request")?;
    let tags = vec![
        Tag::identifier(join_request_identifier(&recipient)),
        Tag::public_key(recipient_pubkey),
        Tag::expiration(Timestamp::now() + Duration::from_secs(JOIN_REQUEST_EXPIRATION_SECS)),
    ];
    let event = EventBuilder::new(join_request_event_kind(), encrypted_content, tags)
        .to_event(&keys)
        .context("failed to sign mesh join request")?;
    let client = ClientBuilder::new()
        .signer(keys)
        .database(nostr_sdk::database::MemoryDatabase::new())
        .build();

    for relay in relays {
        client
            .add_relay(relay)
            .await
            .with_context(|| format!("failed to add relay {relay}"))?;
    }

    client.connect().await;
    let send_result = match client.send_event(event).await {
        Ok(output) if !output.success.is_empty() => Ok(()),
        Ok(_) => Err(anyhow!("mesh join request rejected by all relays")),
        Err(error) => Err(anyhow!(error).context("failed to publish mesh join request")),
    };
    let _ = client.disconnect().await;
    send_result
}

fn encode_join_request(request: MeshJoinRequest) -> Result<MeshJoinRequestEnvelope> {
    let request = normalize_join_request(request)?;
    Ok(MeshJoinRequestEnvelope {
        v: JOIN_REQUEST_PROTOCOL_VERSION,
        network_id: request.network_id,
        requester_node_name: request.requester_node_name,
    })
}

fn decode_join_request(envelope: MeshJoinRequestEnvelope) -> Result<MeshJoinRequest> {
    if envelope.v != JOIN_REQUEST_PROTOCOL_VERSION {
        return Err(anyhow!(
            "unsupported mesh join request version {}; expected {}",
            envelope.v,
            JOIN_REQUEST_PROTOCOL_VERSION
        ));
    }

    normalize_join_request(MeshJoinRequest {
        network_id: envelope.network_id,
        requester_node_name: envelope.requester_node_name,
    })
}

fn normalize_join_request(request: MeshJoinRequest) -> Result<MeshJoinRequest> {
    let network_id = normalize_runtime_network_id(&request.network_id);
    if network_id.is_empty() {
        return Err(anyhow!("mesh join request network_id must not be empty"));
    }

    Ok(MeshJoinRequest {
        network_id,
        requester_node_name: request.requester_node_name.trim().to_string(),
    })
}

fn join_request_identifier(recipient: &str) -> String {
    format!("{JOIN_REQUEST_IDENTIFIER_PREFIX}{recipient}")
}

fn join_request_event_kind() -> Kind {
    Kind::from(NOSTR_KIND_NOSTR_VPN)
}

fn is_join_request_event(event: &Event) -> bool {
    event.kind.as_u16() == NOSTR_KIND_NOSTR_VPN
}

pub(crate) fn decode_received_join_request_event(
    event: &Event,
    own_pubkey: &str,
    keys: &Keys,
) -> Option<ReceivedMeshJoinRequest> {
    if !is_join_request_event_for_recipient(event, own_pubkey) {
        return None;
    }

    let plaintext = nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content).ok()?;
    decode_received_join_request_plaintext(event, own_pubkey, &plaintext)
}

pub(crate) fn decode_received_join_request_plaintext(
    event: &Event,
    own_pubkey: &str,
    plaintext: &str,
) -> Option<ReceivedMeshJoinRequest> {
    if !is_join_request_event_for_recipient(event, own_pubkey) {
        return None;
    }

    let envelope = serde_json::from_str::<MeshJoinRequestEnvelope>(plaintext).ok()?;
    let request = decode_join_request(envelope).ok()?;
    Some(ReceivedMeshJoinRequest {
        sender_pubkey: event.pubkey.to_hex(),
        requested_at: event.created_at.as_u64(),
        request,
    })
}

fn is_join_request_event_for_recipient(event: &Event, own_pubkey: &str) -> bool {
    if !is_join_request_event(event) {
        return false;
    }
    if event.pubkey.to_hex() == own_pubkey {
        return false;
    }
    if first_tag_value(event, "d")
        .as_deref()
        .filter(|value| value.starts_with(JOIN_REQUEST_IDENTIFIER_PREFIX))
        .is_none()
    {
        return false;
    }
    tag_contains_value(event, "p", own_pubkey)
}

fn first_tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let values = tag.clone().to_vec();
        if values.len() >= 2 && values[0] == name {
            Some(values[1].clone())
        } else {
            None
        }
    })
}

fn tag_contains_value(event: &Event, name: &str, expected: &str) -> bool {
    event.tags.iter().any(|tag| {
        let values = tag.clone().to_vec();
        values.len() >= 2 && values[0] == name && values[1] == expected
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_received_join_request_event_parses_encrypted_event_for_recipient() {
        let owner_keys = Keys::generate();
        let requester_keys = Keys::generate();
        let owner_pubkey = owner_keys.public_key().to_hex();

        let envelope = MeshJoinRequestEnvelope {
            v: JOIN_REQUEST_PROTOCOL_VERSION,
            network_id: "mesh-home".to_string(),
            requester_node_name: "alice-phone".to_string(),
        };
        let plaintext = serde_json::to_string(&envelope).expect("join request plaintext");
        let encrypted_content = nip44::encrypt(
            requester_keys.secret_key(),
            &owner_keys.public_key(),
            &plaintext,
            nip44::Version::V2,
        )
        .expect("encrypt join request");
        let event = EventBuilder::new(
            join_request_event_kind(),
            encrypted_content,
            vec![
                Tag::identifier(join_request_identifier(&owner_pubkey)),
                Tag::public_key(owner_keys.public_key()),
                Tag::expiration(Timestamp::now() + Duration::from_secs(60)),
            ],
        )
        .to_event(&requester_keys)
        .expect("sign join request");

        let received = decode_received_join_request_event(&event, &owner_pubkey, &owner_keys)
            .expect("decode join request");

        assert_eq!(received.sender_pubkey, requester_keys.public_key().to_hex());
        assert_eq!(received.requested_at, event.created_at.as_u64());
        assert_eq!(
            received.request,
            MeshJoinRequest {
                network_id: "mesh-home".to_string(),
                requester_node_name: "alice-phone".to_string(),
            }
        );
    }
}
