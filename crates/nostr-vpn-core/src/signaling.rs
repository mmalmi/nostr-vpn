use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};

use crate::config::normalize_nostr_pubkey;
use crate::control::PeerAnnouncement;

pub const NOSTR_KIND_NOSTR_VPN: u16 = 31990;
const SIGNAL_HELLO_TAG: &str = "hello";
const SIGNAL_EXPIRATION_SECS: u64 = 300;
const SIGNAL_HELLO_LOOKBACK_SECS: u64 = 60;
const SIGNAL_PRIVATE_LOOKBACK_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SignalPayload {
    Hello,
    Announce(PeerAnnouncement),
    Disconnect { node_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEnvelope {
    pub network_id: String,
    pub sender_pubkey: String,
    pub payload: SignalPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingNetwork {
    pub network_id: String,
    pub participants: Vec<String>,
}

#[derive(Debug, Clone)]
struct ConfiguredSignalingNetwork {
    network_id: String,
    participants: HashSet<String>,
}

pub struct NostrSignalingClient {
    default_network_id: String,
    network_ids: HashSet<String>,
    own_pubkey: String,
    keys: Keys,
    client: Client,
    networks: Vec<ConfiguredSignalingNetwork>,
    participant_pubkeys: HashSet<String>,
    connected: AtomicBool,
    recv_rx: Mutex<broadcast::Receiver<SignalEnvelope>>,
    recv_tx: broadcast::Sender<SignalEnvelope>,
}

impl NostrSignalingClient {
    pub fn new(network_id: String) -> Result<Self> {
        Self::new_with_keys(network_id, Keys::generate(), Vec::new())
    }

    pub fn from_secret_key(
        network_id: String,
        secret_key: &str,
        participants: Vec<String>,
    ) -> Result<Self> {
        let keys = Keys::parse(secret_key).context("invalid nostr secret key")?;
        Self::new_with_keys(network_id, keys, participants)
    }

    pub fn from_secret_key_with_networks(
        secret_key: &str,
        networks: Vec<SignalingNetwork>,
    ) -> Result<Self> {
        let keys = Keys::parse(secret_key).context("invalid nostr secret key")?;
        Self::new_with_keys_and_networks(keys, networks)
    }

    pub fn new_with_keys(
        network_id: String,
        keys: Keys,
        participants: Vec<String>,
    ) -> Result<Self> {
        Self::new_with_keys_and_networks(
            keys,
            vec![SignalingNetwork {
                network_id,
                participants,
            }],
        )
    }

    pub fn new_with_keys_and_networks(keys: Keys, networks: Vec<SignalingNetwork>) -> Result<Self> {
        let own_pubkey = keys.public_key().to_hex();
        let networks = normalize_signaling_networks(networks)?;
        let default_network_id = networks
            .first()
            .map(|network| network.network_id.clone())
            .ok_or_else(|| anyhow!("at least one signaling network is required"))?;
        let network_ids = networks
            .iter()
            .map(|network| network.network_id.clone())
            .collect::<HashSet<_>>();
        let participant_pubkeys = networks
            .iter()
            .flat_map(|network| network.participants.iter().cloned())
            .collect::<HashSet<_>>();

        let client = ClientBuilder::new()
            .signer(keys.clone())
            .database(nostr_sdk::database::MemoryDatabase::new())
            .build();

        let (recv_tx, recv_rx) = broadcast::channel(2048);

        Ok(Self {
            default_network_id,
            network_ids,
            own_pubkey,
            keys,
            client,
            networks,
            participant_pubkeys,
            connected: AtomicBool::new(false),
            recv_rx: Mutex::new(recv_rx),
            recv_tx,
        })
    }

    pub async fn connect(&self, relays: &[String]) -> Result<()> {
        for relay in relays {
            self.client
                .add_relay(relay)
                .await
                .with_context(|| format!("failed to add relay {relay}"))?;
        }

        self.client.connect().await;

        let private_filter = Filter::new()
            .kind(Kind::Custom(NOSTR_KIND_NOSTR_VPN))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::P),
                vec![self.own_pubkey.clone()],
            )
            .since(Timestamp::now() - Duration::from_secs(SIGNAL_PRIVATE_LOOKBACK_SECS));

        let mut filters = vec![private_filter];
        let hello_authors = self
            .participant_pubkeys
            .iter()
            .filter(|participant| participant.as_str() != self.own_pubkey)
            .filter_map(|participant| PublicKey::from_hex(participant).ok())
            .collect::<Vec<_>>();
        if !hello_authors.is_empty() {
            let hello_filter = Filter::new()
                .kind(Kind::Custom(NOSTR_KIND_NOSTR_VPN))
                .authors(hello_authors)
                .custom_tag(
                    SingleLetterTag::lowercase(Alphabet::L),
                    vec![SIGNAL_HELLO_TAG],
                )
                .since(Timestamp::now() - Duration::from_secs(SIGNAL_HELLO_LOOKBACK_SECS));
            filters.push(hello_filter);
        }

        self.client
            .subscribe(filters, None)
            .await
            .context("failed to subscribe to nostr-vpn events")?;

        self.start_event_forwarder();
        self.connected.store(true, Ordering::Relaxed);

        Ok(())
    }

    pub async fn disconnect(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.client.disconnect().await;
    }

    pub async fn publish(&self, payload: SignalPayload) -> Result<()> {
        if matches!(&payload, SignalPayload::Hello) {
            return self.publish_hello().await;
        }

        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow!("client not connected"));
        }

        let recipients: Vec<String> = self
            .participant_pubkeys
            .iter()
            .filter(|participant| participant.as_str() != self.own_pubkey)
            .cloned()
            .collect();
        if recipients.is_empty() {
            return Err(anyhow!(
                "no configured participants to send private signaling message to"
            ));
        }

        self.publish_private_to(payload, &recipients).await
    }

    pub async fn publish_to(&self, payload: SignalPayload, recipients: &[String]) -> Result<()> {
        if matches!(&payload, SignalPayload::Hello) {
            return self.publish_hello().await;
        }

        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow!("client not connected"));
        }

        self.publish_private_to(payload, recipients).await
    }

    async fn publish_hello(&self) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow!("client not connected"));
        }

        let expiration = Timestamp::now() + Duration::from_secs(SIGNAL_EXPIRATION_SECS);
        let tags = vec![
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                vec![SIGNAL_HELLO_TAG.to_string()],
            ),
            Tag::expiration(expiration),
        ];
        let event = EventBuilder::new(Kind::Custom(NOSTR_KIND_NOSTR_VPN), "", tags)
            .to_event(&self.keys)
            .context("failed to sign public hello event")?;
        let output = self
            .client
            .send_event(event)
            .await
            .context("failed to publish public hello event")?;
        if output.success.is_empty() {
            return Err(anyhow!("public hello event rejected by all relays"));
        }

        Ok(())
    }

    async fn publish_private_to(
        &self,
        payload: SignalPayload,
        recipients: &[String],
    ) -> Result<()> {
        let recipients: HashSet<String> = recipients
            .iter()
            .filter(|participant| participant.as_str() != self.own_pubkey)
            .filter(|participant| self.participant_pubkeys.contains(participant.as_str()))
            .cloned()
            .collect();
        if recipients.is_empty() {
            return Err(anyhow!(
                "no configured participants to send private signaling message to"
            ));
        }

        let mut delivered = HashSet::new();
        let mut first_error = None;

        for network in &self.networks {
            let network_recipients = recipients
                .iter()
                .filter(|participant| network.participants.contains(participant.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if network_recipients.is_empty() {
                continue;
            }

            match self
                .publish_private_to_network(
                    payload.clone(),
                    &network.network_id,
                    &network_recipients,
                )
                .await
            {
                Ok(sent) => delivered.extend(sent),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if delivered == recipients {
            return Ok(());
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        Err(anyhow!("private signaling event rejected by all relays"))
    }

    async fn publish_private_to_network(
        &self,
        payload: SignalPayload,
        network_id: &str,
        recipients: &[String],
    ) -> Result<HashSet<String>> {
        let envelope = SignalEnvelope {
            network_id: network_id.to_string(),
            sender_pubkey: self.own_pubkey.clone(),
            payload,
        };

        let content = serde_json::to_string(&envelope).context("failed to serialize envelope")?;

        let mut delivered = HashSet::new();
        let expiration = Timestamp::now() + Duration::from_secs(SIGNAL_EXPIRATION_SECS);
        for recipient in recipients {
            let recipient_pubkey = PublicKey::from_hex(recipient)
                .with_context(|| format!("invalid recipient pubkey {recipient}"))?;

            let encrypted_content = nip44::encrypt(
                self.keys.secret_key(),
                &recipient_pubkey,
                &content,
                nip44::Version::V2,
            )
            .context("failed to encrypt signaling payload")?;

            let tags = vec![
                Tag::public_key(recipient_pubkey),
                Tag::expiration(expiration),
            ];
            let builder =
                EventBuilder::new(Kind::Custom(NOSTR_KIND_NOSTR_VPN), encrypted_content, tags);
            let event = builder
                .to_event(&self.keys)
                .context("failed to sign private nostr event")?;

            let output = self
                .client
                .send_event(event)
                .await
                .context("failed to publish private nostr event")?;

            if !output.success.is_empty() {
                delivered.insert(recipient.clone());
            }
        }

        if delivered.is_empty() {
            return Err(anyhow!("private signaling event rejected by all relays"));
        }

        Ok(delivered)
    }

    pub async fn recv(&self) -> Option<SignalEnvelope> {
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
        let default_network_id = self.default_network_id.clone();
        let network_ids = self.network_ids.clone();
        let networks = self.networks.clone();
        let participant_pubkeys = self.participant_pubkeys.clone();
        let keys = self.keys.clone();
        let recv_tx = self.recv_tx.clone();

        tokio::spawn(async move {
            loop {
                let notification = match notifications.recv().await {
                    Ok(notification) => notification,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                };

                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind != Kind::Custom(NOSTR_KIND_NOSTR_VPN) {
                        continue;
                    }

                    if first_tag_value(&event, "l").as_deref() == Some(SIGNAL_HELLO_TAG) {
                        let sender_pubkey = event.pubkey.to_hex();
                        if sender_pubkey == own_pubkey {
                            continue;
                        }

                        if !participant_pubkeys.is_empty()
                            && !participant_pubkeys.contains(&sender_pubkey)
                        {
                            continue;
                        }

                        let matched_network_ids = networks
                            .iter()
                            .filter(|network| {
                                network.participants.is_empty()
                                    || network.participants.contains(&sender_pubkey)
                            })
                            .map(|network| network.network_id.clone())
                            .collect::<Vec<_>>();

                        if matched_network_ids.is_empty() {
                            let _ = recv_tx.send(SignalEnvelope {
                                network_id: default_network_id.clone(),
                                sender_pubkey,
                                payload: SignalPayload::Hello,
                            });
                            continue;
                        }

                        for network_id in matched_network_ids {
                            let _ = recv_tx.send(SignalEnvelope {
                                network_id,
                                sender_pubkey: sender_pubkey.clone(),
                                payload: SignalPayload::Hello,
                            });
                        }
                        continue;
                    }

                    if event.pubkey.to_hex() == own_pubkey {
                        continue;
                    }

                    let Some(recipient_pubkey) = first_tag_value(&event, "p") else {
                        continue;
                    };
                    if recipient_pubkey != own_pubkey {
                        continue;
                    }

                    let plaintext =
                        match nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content) {
                            Ok(plaintext) => plaintext,
                            Err(_) => continue,
                        };

                    let Ok(envelope) = serde_json::from_str::<SignalEnvelope>(&plaintext) else {
                        continue;
                    };

                    if !network_ids.contains(&envelope.network_id) {
                        continue;
                    }

                    let Some(network) = networks
                        .iter()
                        .find(|network| network.network_id == envelope.network_id)
                    else {
                        continue;
                    };

                    if envelope.sender_pubkey == own_pubkey {
                        continue;
                    }

                    if envelope.sender_pubkey != event.pubkey.to_hex() {
                        continue;
                    }

                    if !network.participants.is_empty()
                        && !network.participants.contains(&envelope.sender_pubkey)
                    {
                        continue;
                    }

                    if !participant_pubkeys.is_empty()
                        && !participant_pubkeys.contains(&envelope.sender_pubkey)
                    {
                        continue;
                    }

                    let _ = recv_tx.send(envelope);
                }
            }
        });
    }
}

fn normalize_participants(participants: Vec<String>) -> Result<HashSet<String>> {
    let mut normalized = HashSet::with_capacity(participants.len());
    for participant in participants {
        normalized.insert(normalize_nostr_pubkey(&participant)?);
    }
    Ok(normalized)
}

fn normalize_signaling_networks(
    networks: Vec<SignalingNetwork>,
) -> Result<Vec<ConfiguredSignalingNetwork>> {
    let mut normalized = Vec::<ConfiguredSignalingNetwork>::new();
    for network in networks {
        let network_id = network.network_id.trim();
        if network_id.is_empty() {
            return Err(anyhow!("network_id must not be empty"));
        }

        let participants = normalize_participants(network.participants)?;
        if let Some(existing) = normalized
            .iter_mut()
            .find(|existing| existing.network_id == network_id)
        {
            existing.participants.extend(participants);
            continue;
        }

        normalized.push(ConfiguredSignalingNetwork {
            network_id: network_id.to_string(),
            participants,
        });
    }

    if normalized.is_empty() {
        return Err(anyhow!("at least one signaling network is required"));
    }

    Ok(normalized)
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
