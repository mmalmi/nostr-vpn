use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use nostr_pubsub::{
    DEFAULT_INV_WANT_MAX_WIRE_BYTES, EventPolicyContext, EventSource, InvWantAction, InvWantCodec,
    InvWantMesh, InvWantMeshOptions, InvWantMeshRetainedState, InvWantWireMessage, MeshPeer,
    MeshPeerPolicy, PolicyDecision, PubsubError, PubsubPolicy, QueryEvent, Result, VerifiedEvent,
};

const LENGTH_PREFIX_BYTES: usize = size_of::<u32>();

pub const FIPS_NOSTR_PUBSUB_INV_WANT_PROTOCOL: &str = "nostr.pubsub";
pub const FIPS_NOSTR_PUBSUB_INV_WANT_VERSION: u8 = 1;

/// Bounds for the reliable Inv/WANT record layer carried by a TCP/FIPS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsInvWantStreamOptions {
    pub mesh: InvWantMeshOptions,
    /// Inv/WANT envelope namespace. Products can preserve an existing wire
    /// namespace while sharing this state machine and stream carrier.
    pub protocol: String,
    pub protocol_version: u8,
    /// Maximum encoded Inv/WANT envelope, excluding its four-byte prefix.
    pub max_record_bytes: usize,
    /// Maximum peers allowed to retain partial stream input simultaneously.
    pub max_input_peers: usize,
    /// Maximum complete records processed in one receive turn.
    pub max_records_per_receive: usize,
}

impl Default for FipsInvWantStreamOptions {
    fn default() -> Self {
        Self {
            mesh: InvWantMeshOptions::default(),
            protocol: FIPS_NOSTR_PUBSUB_INV_WANT_PROTOCOL.to_string(),
            protocol_version: FIPS_NOSTR_PUBSUB_INV_WANT_VERSION,
            max_record_bytes: DEFAULT_INV_WANT_MAX_WIRE_BYTES,
            max_input_peers: 64,
            max_records_per_receive: 64,
        }
    }
}

impl FipsInvWantStreamOptions {
    fn validate(&self) -> Result<()> {
        if self.max_record_bytes == 0 {
            return Err(validation("max_record_bytes must be greater than zero"));
        }
        if self.protocol.trim().is_empty() {
            return Err(validation("protocol must not be empty"));
        }
        if self.max_record_bytes > u32::MAX as usize {
            return Err(validation("max_record_bytes exceeds the record prefix"));
        }
        if self.max_input_peers == 0 {
            return Err(validation("max_input_peers must be greater than zero"));
        }
        if self.max_records_per_receive == 0 {
            return Err(validation(
                "max_records_per_receive must be greater than zero",
            ));
        }
        self.max_record_bytes
            .checked_add(LENGTH_PREFIX_BYTES)
            .ok_or_else(|| validation("record buffer size overflows"))?;
        Ok(())
    }
}

/// Work emitted by [`FipsInvWantStream`]. Transport drivers write `Send`
/// records to the named peer and pass `Deliver` events to the application.
#[derive(Debug, Clone)]
pub enum FipsInvWantStreamAction {
    Send { peer_id: String, record: Vec<u8> },
    Deliver(Box<QueryEvent>),
}

/// Bounded, policy-aware Inv/WANT state above a reliable byte stream.
///
/// This owns no sockets and no tasks. A thin TCP/FIPS driver supplies stream
/// bytes and executes returned records, keeping clocks and reconnect evidence
/// explicit and testable.
pub struct FipsInvWantStream {
    mesh: InvWantMesh,
    codec: InvWantCodec,
    options: FipsInvWantStreamOptions,
    event_policy: Option<Arc<dyn PubsubPolicy>>,
    peer_policy: Option<Arc<dyn MeshPeerPolicy>>,
    inputs: HashMap<String, RecordDecoder>,
}

impl FipsInvWantStream {
    pub fn new(options: FipsInvWantStreamOptions) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            mesh: InvWantMesh::new(options.mesh.clone()),
            codec: InvWantCodec::new(
                options.protocol.clone(),
                options.protocol_version,
                options.max_record_bytes,
            ),
            options,
            event_policy: None,
            peer_policy: None,
            inputs: HashMap::new(),
        })
    }

    #[must_use]
    pub fn with_event_policy(mut self, policy: Arc<dyn PubsubPolicy>) -> Self {
        self.event_policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_peer_policy(mut self, policy: Arc<dyn MeshPeerPolicy>) -> Self {
        self.peer_policy = Some(policy);
        self
    }

    /// Restore one verified event from durable application storage.
    pub fn seed(&mut self, event: VerifiedEvent, now_ms: u64) -> Result<()> {
        self.ensure_event_record_fits(&event)?;
        self.mesh.seed_verified(event, now_ms)
    }

    /// Publish one locally verified event to the selected connected peers.
    pub fn publish(
        &mut self,
        event: VerifiedEvent,
        connected_peers: impl IntoIterator<Item = String>,
        now_ms: u64,
    ) -> Result<Vec<FipsInvWantStreamAction>> {
        self.ensure_event_record_fits(&event)?;
        let peers = self.select_peers(connected_peers)?;
        let actions = self.mesh.publish_verified(event, &peers, now_ms)?;
        self.encode_actions(actions, None)
    }

    /// Replay bounded cached inventories whenever a peer connects or reconnects.
    pub fn peer_connected(
        &mut self,
        peer_id: &str,
        now_ms: u64,
    ) -> Result<Vec<FipsInvWantStreamAction>> {
        if self.select_peer(peer_id)?.is_none() {
            return Ok(Vec::new());
        }
        let actions = self.mesh.replay_cached_to_peer(peer_id, now_ms);
        self.encode_actions(actions, None)
    }

    /// Remove all partial input retained for a disconnected stream peer.
    pub fn disconnect_peer(&mut self, peer_id: &str) {
        self.inputs.remove(peer_id);
    }

    /// Consume a bounded byte-stream fragment from one authenticated peer.
    pub async fn receive_bytes(
        &mut self,
        source_peer: &str,
        bytes: &[u8],
        connected_peers: impl IntoIterator<Item = String>,
        now_ms: u64,
    ) -> Result<Vec<FipsInvWantStreamAction>> {
        if self.select_peer(source_peer)?.is_none() {
            self.disconnect_peer(source_peer);
            return Ok(Vec::new());
        }
        let records = self.decode_records(source_peer, bytes)?;
        let peers = self.select_peers(connected_peers)?;
        let mut output = Vec::new();
        for record in records {
            let message = match self.codec.decode(&record) {
                Ok(message) => message,
                Err(error) => {
                    self.mesh.record_invalid_message(source_peer);
                    return Err(error);
                }
            };
            let actions = self
                .receive_message(source_peer, message, &peers, now_ms)
                .await?;
            output.extend(actions);
        }
        Ok(output)
    }

    #[must_use]
    pub fn retained_state(&self) -> InvWantMeshRetainedState {
        self.mesh.retained_state()
    }

    #[must_use]
    pub fn buffered_input_bytes(&self, peer_id: &str) -> usize {
        self.inputs.get(peer_id).map_or(0, RecordDecoder::len)
    }

    #[must_use]
    pub fn input_peer_count(&self) -> usize {
        self.inputs.len()
    }

    #[must_use]
    pub fn remaining_input_capacity(&self, peer_id: &str) -> usize {
        self.inputs.get(peer_id).map_or_else(
            || self.options.max_record_bytes + LENGTH_PREFIX_BYTES,
            RecordDecoder::remaining_capacity,
        )
    }

    /// Whether another complete retained record can be processed without
    /// reading more stream bytes.
    #[must_use]
    pub fn has_ready_input(&self, peer_id: &str) -> bool {
        self.inputs
            .get(peer_id)
            .is_some_and(RecordDecoder::has_complete_record)
    }

    pub fn maintain(&mut self, now_ms: u64) {
        self.mesh.maintain(now_ms);
    }

    async fn receive_message(
        &mut self,
        source_peer: &str,
        message: InvWantWireMessage,
        peers: &[MeshPeer],
        now_ms: u64,
    ) -> Result<Vec<FipsInvWantStreamAction>> {
        let InvWantWireMessage::Frame { event_id, event } = message else {
            let actions = self.mesh.receive(source_peer, message, peers, now_ms)?;
            return self.encode_actions(actions, None);
        };
        let verified = match VerifiedEvent::try_from(*event) {
            Ok(event) => event,
            Err(error) => {
                self.mesh.record_invalid_message(source_peer);
                return Err(error);
            }
        };
        let source = EventSource::fips_endpoint(source_peer);
        let priority = match self.event_policy.as_ref() {
            None => source.kind.default_priority(),
            Some(policy) => match policy
                .check_event(EventPolicyContext {
                    event: &verified,
                    source: &source,
                })
                .await
            {
                Ok(
                    PolicyDecision::Allow { priority } | PolicyDecision::Throttle { priority, .. },
                ) => priority,
                Ok(PolicyDecision::Drop { .. }) => {
                    self.mesh.dismiss_frame(source_peer, &event_id);
                    return Ok(Vec::new());
                }
                Err(error) => {
                    self.mesh.dismiss_frame(source_peer, &event_id);
                    return Err(error);
                }
            },
        };
        let actions = self.mesh.receive_verified_frame(
            source_peer,
            &event_id,
            verified.clone(),
            peers,
            now_ms,
        )?;
        self.encode_actions(actions, Some(&(verified, priority)))
    }

    fn select_peers(&self, peer_ids: impl IntoIterator<Item = String>) -> Result<Vec<MeshPeer>> {
        let mut selected = BTreeMap::new();
        for peer_id in peer_ids {
            if let Some(peer) = self.select_peer(&peer_id)? {
                selected.insert(peer_id, peer);
            }
        }
        Ok(selected.into_values().collect())
    }

    fn ensure_event_record_fits(&self, event: &VerifiedEvent) -> Result<()> {
        self.codec
            .encode(&InvWantWireMessage::Frame {
                event_id: event.as_event().id.to_hex(),
                event: Box::new(event.as_event().clone()),
            })
            .map(|_| ())
    }

    fn select_peer(&self, peer_id: &str) -> Result<Option<MeshPeer>> {
        let selected = match self.peer_policy.as_ref() {
            Some(policy) => policy.select_mesh_peer(peer_id),
            None => Ok(Some(MeshPeer::new(peer_id))),
        }?;
        Ok(selected.map(|mut peer| {
            peer.id = peer_id.to_string();
            peer
        }))
    }

    fn decode_records(&mut self, peer_id: &str, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !self.inputs.contains_key(peer_id) {
            if self.inputs.len() >= self.options.max_input_peers {
                return Err(PubsubError::Storage(format!(
                    "FIPS pubsub input peer limit is {}",
                    self.options.max_input_peers
                )));
            }
            self.inputs.insert(
                peer_id.to_string(),
                RecordDecoder::new(self.options.max_record_bytes),
            );
        }
        self.inputs
            .get_mut(peer_id)
            .expect("input decoder was inserted")
            .push(bytes, self.options.max_records_per_receive)
    }

    fn encode_actions(
        &self,
        actions: Vec<InvWantAction>,
        admitted_delivery: Option<&(VerifiedEvent, i32)>,
    ) -> Result<Vec<FipsInvWantStreamAction>> {
        actions
            .into_iter()
            .map(|action| match action {
                InvWantAction::Send { peer_id, message } => {
                    let payload = self.codec.encode(&message)?;
                    Ok(FipsInvWantStreamAction::Send {
                        peer_id,
                        record: encode_record(payload, self.options.max_record_bytes)?,
                    })
                }
                InvWantAction::Deliver { source_peer, event } => {
                    let Some((verified, priority)) = admitted_delivery.as_ref() else {
                        return Err(PubsubError::Storage(
                            "mesh delivered an event outside frame admission".to_string(),
                        ));
                    };
                    debug_assert_eq!(verified.as_event().id, event.id);
                    Ok(FipsInvWantStreamAction::Deliver(Box::new(QueryEvent {
                        event: verified.clone(),
                        source: EventSource::fips_endpoint(source_peer),
                        priority: *priority,
                    })))
                }
            })
            .collect()
    }
}

struct RecordDecoder {
    max_record_bytes: usize,
    buffer: Vec<u8>,
}

impl RecordDecoder {
    fn new(max_record_bytes: usize) -> Self {
        Self {
            max_record_bytes,
            buffer: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8], max_records: usize) -> Result<Vec<Vec<u8>>> {
        let attempted = self
            .buffer
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| validation("record input length overflows"))?;
        if attempted > self.max_record_bytes + LENGTH_PREFIX_BYTES {
            self.buffer.clear();
            return Err(validation(format!(
                "record input is {attempted} bytes, maximum buffered input is {}",
                self.max_record_bytes + LENGTH_PREFIX_BYTES
            )));
        }
        self.buffer.extend_from_slice(bytes);

        let mut records = Vec::new();
        let mut consumed = 0;
        while records.len() < max_records
            && self.buffer.len().saturating_sub(consumed) >= LENGTH_PREFIX_BYTES
        {
            let declared = usize::try_from(u32::from_be_bytes(
                self.buffer[consumed..consumed + LENGTH_PREFIX_BYTES]
                    .try_into()
                    .expect("record prefix is complete"),
            ))
            .map_err(|_| validation("record length does not fit this platform"))?;
            if declared > self.max_record_bytes {
                self.buffer.clear();
                return Err(validation(format!(
                    "record declares {declared} bytes, maximum is {}",
                    self.max_record_bytes
                )));
            }
            let record_bytes = LENGTH_PREFIX_BYTES + declared;
            if self.buffer.len() - consumed < record_bytes {
                break;
            }
            let start = consumed + LENGTH_PREFIX_BYTES;
            records.push(self.buffer[start..consumed + record_bytes].to_vec());
            consumed += record_bytes;
        }
        if consumed == self.buffer.len() {
            self.buffer.clear();
        } else if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(records)
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn remaining_capacity(&self) -> usize {
        self.max_record_bytes
            .saturating_add(LENGTH_PREFIX_BYTES)
            .saturating_sub(self.buffer.len())
    }

    fn has_complete_record(&self) -> bool {
        if self.buffer.len() < LENGTH_PREFIX_BYTES {
            return false;
        }
        let Ok(prefix) = self.buffer[..LENGTH_PREFIX_BYTES].try_into() else {
            return false;
        };
        let Ok(declared) = usize::try_from(u32::from_be_bytes(prefix)) else {
            return false;
        };
        declared <= self.max_record_bytes
            && self.buffer.len() >= LENGTH_PREFIX_BYTES.saturating_add(declared)
    }
}

fn encode_record(payload: Vec<u8>, max_record_bytes: usize) -> Result<Vec<u8>> {
    if payload.len() > max_record_bytes {
        return Err(validation(format!(
            "record is {} bytes, maximum is {max_record_bytes}",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len()).map_err(|_| validation("record is too large"))?;
    let mut record = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    record.extend_from_slice(&length.to_be_bytes());
    record.extend(payload);
    Ok(record)
}

fn validation(message: impl Into<String>) -> PubsubError {
    PubsubError::Validation(message.into())
}
