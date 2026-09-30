use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Display;
use std::sync::Arc;

use fips_core::discovery::local::LocalInstanceCapability;
use fips_core::{FipsEndpoint, PeerIdentity};
use fips_tcp::{Config as TcpConfig, ConnectionId, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use nostr_pubsub::{PubsubError, QueryEvent, Result, VerifiedEvent};

use crate::{
    FIPS_NOSTR_PUBSUB_INV_WANT_PROTOCOL, FIPS_NOSTR_PUBSUB_INV_WANT_VERSION,
    FIPS_NOSTR_PUBSUB_SERVICE_PORT, FipsInvWantStream, FipsInvWantStreamAction,
};

const STREAM_IO_CHUNK_BYTES: usize = 16 * 1024;
const MAX_READY_INPUT_TURNS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsInvWantTcpDriverOptions {
    /// Authenticated FSP capability namespace, without its `/version` suffix.
    pub service_namespace: String,
    /// Authenticated FSP capability version.
    pub service_version: u8,
    /// FSP service port and internal TCP listener port.
    pub service_port: u16,
    /// Maximum distinct authenticated peers retained by the driver.
    pub max_peers: usize,
    /// Maximum pending complete records retained for one peer.
    pub max_queued_records_per_peer: usize,
    /// Maximum pending unsent record bytes retained for one peer.
    pub max_queued_bytes_per_peer: usize,
    /// Maximum bytes read and maximum bytes written in one drive turn.
    pub max_io_bytes_per_drive: usize,
}

impl Default for FipsInvWantTcpDriverOptions {
    fn default() -> Self {
        Self {
            service_namespace: FIPS_NOSTR_PUBSUB_INV_WANT_PROTOCOL.to_string(),
            service_version: FIPS_NOSTR_PUBSUB_INV_WANT_VERSION,
            service_port: FIPS_NOSTR_PUBSUB_SERVICE_PORT,
            max_peers: 64,
            max_queued_records_per_peer: 2_048,
            max_queued_bytes_per_peer: 16 * 1_024 * 1_024,
            max_io_bytes_per_drive: 512 * 1_024,
        }
    }
}

impl FipsInvWantTcpDriverOptions {
    fn validate(&self) -> Result<()> {
        if self
            .service_namespace
            .trim()
            .trim_end_matches('/')
            .is_empty()
        {
            return Err(validation("service namespace must not be empty"));
        }
        if self.service_port == 0 {
            return Err(validation("service port must not be zero"));
        }
        for (name, value) in [
            ("max_peers", self.max_peers),
            (
                "max_queued_records_per_peer",
                self.max_queued_records_per_peer,
            ),
            ("max_queued_bytes_per_peer", self.max_queued_bytes_per_peer),
            ("max_io_bytes_per_drive", self.max_io_bytes_per_drive),
        ] {
            if value == 0 {
                return Err(validation(format!("{name} must be greater than zero")));
            }
        }
        self.max_peers
            .checked_mul(2)
            .ok_or_else(|| validation("TCP connection limit overflows"))?;
        Ok(())
    }

    #[must_use]
    pub fn capability_name(&self) -> String {
        format!(
            "{}/{}",
            self.service_namespace.trim().trim_end_matches('/'),
            self.service_version
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FipsInvWantTcpQueueSnapshot {
    /// Peers with at least one pending record.
    pub peers: usize,
    /// Complete records not yet fully accepted by `fips-tcp`.
    pub records: usize,
    /// Record bytes not yet accepted by `fips-tcp`.
    pub bytes: usize,
}

#[derive(Debug, Default)]
pub struct FipsInvWantTcpDriveReport {
    /// FSP datagrams consumed by the TCP adapter in this turn.
    pub fips_datagrams: usize,
    /// Malformed or over-capacity TCP segments isolated in this turn.
    pub rejected_tcp_segments: usize,
    /// Reliable stream bytes delivered to the Inv/WANT layer.
    pub stream_bytes_read: usize,
    /// Reliable stream bytes accepted from the driver's pending queues.
    pub stream_bytes_written: usize,
    /// Distinct peers with an established selected stream after this turn.
    pub connected_peers: usize,
    /// Verified, policy-admitted events produced in this turn.
    pub deliveries: Vec<QueryEvent>,
}

/// Manually driven reliable Inv/WANT service over authenticated FIPS peers.
///
/// The driver owns no task or reconnect policy. Applications call [`Self::receive`]
/// when waiting for network input, call [`Self::poll`] for timers and pending
/// writes, and decide when an authenticated [`PeerIdentity`] should reconnect.
pub struct FipsInvWantTcpDriver {
    local_npub: String,
    tcp: FipsTcpEndpoint,
    stream: FipsInvWantStream,
    options: FipsInvWantTcpDriverOptions,
    connections: HashMap<ConnectionId, TrackedConnection>,
    active: BTreeMap<String, ConnectionId>,
    queues: BTreeMap<String, PeerQueue>,
}

impl FipsInvWantTcpDriver {
    pub async fn bind(
        endpoint: Arc<FipsEndpoint>,
        stream: FipsInvWantStream,
        options: FipsInvWantTcpDriverOptions,
        isn_seed: u64,
    ) -> Result<Self> {
        options.validate()?;
        let max_connections = options
            .max_peers
            .checked_mul(2)
            .ok_or_else(|| validation("TCP connection limit overflows"))?;
        let tcp_config = TcpConfig {
            receive_buffer: u16::MAX as usize,
            send_buffer: options.max_queued_bytes_per_peer,
            max_connections,
            max_connections_per_peer: 2,
            ..TcpConfig::default()
        };
        let capability =
            LocalInstanceCapability::service(options.capability_name(), options.service_port);
        let local_npub = endpoint.npub().to_string();
        let tcp = FipsTcpEndpoint::bind_with_capability(endpoint, capability, tcp_config, isn_seed)
            .await
            .map_err(|error| storage_error("bind TCP/FIPS pubsub service", error))?;
        Ok(Self {
            local_npub,
            tcp,
            stream,
            options,
            connections: HashMap::new(),
            active: BTreeMap::new(),
            queues: BTreeMap::new(),
        })
    }

    pub async fn connect_peer(&mut self, peer: PeerIdentity, now_ms: u64) -> Result<()> {
        let peer_npub = peer.npub();
        if self.connections.iter().any(|(id, connection)| {
            connection.peer == peer_npub
                && matches!(
                    self.tcp.state(*id),
                    Some(
                        State::SynSent | State::SynReceived | State::Established | State::CloseWait
                    )
                )
        }) {
            return Ok(());
        }
        self.ensure_peer_capacity(&peer_npub)?;
        let id = self
            .tcp
            .connect(peer, now_ms)
            .await
            .map_err(|error| storage_error("connect TCP/FIPS pubsub peer", error))?;
        self.connections.insert(
            id,
            TrackedConnection {
                peer: peer_npub,
                direction: Direction::Outbound,
            },
        );
        Ok(())
    }

    pub fn seed(&mut self, event: VerifiedEvent, now_ms: u64) -> Result<()> {
        self.stream.seed(event, now_ms)
    }

    pub fn publish(
        &mut self,
        event: VerifiedEvent,
        now_ms: u64,
    ) -> Result<FipsInvWantTcpQueueSnapshot> {
        let actions = self
            .stream
            .publish(event, self.active.keys().cloned(), now_ms)?;
        self.apply_actions(actions, &mut Vec::new())?;
        Ok(self.queue_snapshot())
    }

    pub async fn receive(&mut self, now_ms: u64) -> Result<FipsInvWantTcpDriveReport> {
        let received = self
            .tcp
            .receive_report(now_ms)
            .await
            .map_err(|error| storage_error("receive TCP/FIPS pubsub batch", error))?;
        let mut report = FipsInvWantTcpDriveReport {
            fips_datagrams: received.datagrams,
            rejected_tcp_segments: received.rejected(),
            ..FipsInvWantTcpDriveReport::default()
        };
        self.drive_ready(now_ms, &mut report).await?;
        Ok(report)
    }

    pub async fn poll(&mut self, now_ms: u64) -> Result<FipsInvWantTcpDriveReport> {
        self.tcp
            .poll(now_ms)
            .await
            .map_err(|error| storage_error("poll TCP/FIPS pubsub transport", error))?;
        let mut report = FipsInvWantTcpDriveReport::default();
        self.drive_ready(now_ms, &mut report).await?;
        Ok(report)
    }

    pub async fn abort_peer(&mut self, peer: PeerIdentity) -> Result<()> {
        let peer_npub = peer.npub();
        let ids = self
            .connections
            .iter()
            .filter_map(|(id, connection)| (connection.peer == peer_npub).then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            if self.tcp.state(id).is_some() {
                self.tcp
                    .abort(id)
                    .await
                    .map_err(|error| storage_error("abort TCP/FIPS pubsub peer", error))?;
            }
            self.connections.remove(&id);
        }
        self.active.remove(&peer_npub);
        self.queues.remove(&peer_npub);
        self.stream.disconnect_peer(&peer_npub);
        Ok(())
    }

    #[must_use]
    pub fn connected_peer_count(&self) -> usize {
        self.active.len()
    }

    #[must_use]
    pub fn queue_snapshot(&self) -> FipsInvWantTcpQueueSnapshot {
        self.queues.values().fold(
            FipsInvWantTcpQueueSnapshot {
                peers: self.queues.len(),
                ..FipsInvWantTcpQueueSnapshot::default()
            },
            |mut snapshot, queue| {
                snapshot.records = snapshot.records.saturating_add(queue.records.len());
                snapshot.bytes = snapshot.bytes.saturating_add(queue.bytes);
                snapshot
            },
        )
    }

    async fn drive_ready(
        &mut self,
        now_ms: u64,
        report: &mut FipsInvWantTcpDriveReport,
    ) -> Result<()> {
        self.stream.maintain(now_ms);
        self.accept_connections().await?;
        self.refresh_active(now_ms, report).await?;
        self.read_active(now_ms, report).await?;
        self.flush_queues(now_ms, report).await?;
        self.finish_remote_closes(now_ms).await?;
        self.refresh_active(now_ms, report).await?;
        report.connected_peers = self.active.len();
        Ok(())
    }

    async fn accept_connections(&mut self) -> Result<()> {
        while let Some(id) = self.tcp.accept() {
            let peer = self
                .tcp
                .peer(id)
                .ok_or_else(|| storage("accepted TCP/FIPS stream has no authenticated peer"))?
                .npub();
            if self.ensure_peer_capacity(&peer).is_err() {
                self.tcp
                    .abort(id)
                    .await
                    .map_err(|error| storage_error("reject excess TCP/FIPS peer", error))?;
                continue;
            }
            self.connections.entry(id).or_insert(TrackedConnection {
                peer,
                direction: Direction::Inbound,
            });
        }
        Ok(())
    }

    async fn refresh_active(
        &mut self,
        now_ms: u64,
        report: &mut FipsInvWantTcpDriveReport,
    ) -> Result<()> {
        self.connections
            .retain(|id, _| self.tcp.state(*id).is_some());
        let mut candidates = BTreeMap::<String, Vec<(ConnectionId, Direction)>>::new();
        for (id, connection) in &self.connections {
            if matches!(
                self.tcp.state(*id),
                Some(State::Established | State::CloseWait)
            ) {
                candidates
                    .entry(connection.peer.clone())
                    .or_default()
                    .push((*id, connection.direction));
            }
        }
        let mut next_active = BTreeMap::new();
        let mut extras = Vec::new();
        for (peer, mut streams) in candidates {
            let prefer_outbound = self.local_npub < peer;
            streams.sort_by_key(|(id, direction)| {
                let preferred = matches!(direction, Direction::Outbound) == prefer_outbound;
                (!preferred, id.get())
            });
            let (selected, _) = streams.remove(0);
            next_active.insert(peer, selected);
            extras.extend(streams.into_iter().map(|(id, _)| id));
        }
        for id in extras {
            self.tcp
                .abort(id)
                .await
                .map_err(|error| storage_error("deduplicate TCP/FIPS pubsub stream", error))?;
            self.connections.remove(&id);
        }

        let changed = self
            .active
            .keys()
            .chain(next_active.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|peer| self.active.get(peer) != next_active.get(peer))
            .collect::<Vec<_>>();
        self.active = next_active;
        for peer in changed {
            self.stream.disconnect_peer(&peer);
            self.queues.remove(&peer);
            if self.active.contains_key(&peer) {
                let actions = self.stream.peer_connected(&peer, now_ms)?;
                self.apply_actions(actions, &mut report.deliveries)?;
            }
        }
        Ok(())
    }

    async fn read_active(
        &mut self,
        now_ms: u64,
        report: &mut FipsInvWantTcpDriveReport,
    ) -> Result<()> {
        let connected = self.active.keys().cloned().collect::<Vec<_>>();
        let streams = self
            .active
            .iter()
            .map(|(peer, id)| (peer.clone(), *id))
            .collect::<Vec<_>>();
        let mut budget = self.options.max_io_bytes_per_drive;
        for (peer, id) in streams {
            let mut turns = 0;
            while turns < MAX_READY_INPUT_TURNS {
                if self.stream.has_ready_input(&peer) {
                    let actions = self
                        .stream
                        .receive_bytes(&peer, &[], connected.clone(), now_ms)
                        .await?;
                    self.apply_actions(actions, &mut report.deliveries)?;
                    turns += 1;
                    continue;
                }
                if budget == 0 {
                    break;
                }
                let read_max = self
                    .stream
                    .remaining_input_capacity(&peer)
                    .min(STREAM_IO_CHUNK_BYTES)
                    .min(budget);
                if read_max == 0 {
                    break;
                }
                let bytes = self
                    .tcp
                    .read(id, read_max, now_ms)
                    .await
                    .map_err(|error| storage_error("read TCP/FIPS pubsub stream", error))?;
                if bytes.is_empty() {
                    break;
                }
                budget -= bytes.len();
                report.stream_bytes_read = report.stream_bytes_read.saturating_add(bytes.len());
                let actions = self
                    .stream
                    .receive_bytes(&peer, &bytes, connected.clone(), now_ms)
                    .await?;
                self.apply_actions(actions, &mut report.deliveries)?;
                turns += 1;
            }
        }
        Ok(())
    }

    async fn flush_queues(
        &mut self,
        now_ms: u64,
        report: &mut FipsInvWantTcpDriveReport,
    ) -> Result<()> {
        let streams = self
            .active
            .iter()
            .map(|(peer, id)| (peer.clone(), *id))
            .collect::<Vec<_>>();
        let mut budget = self.options.max_io_bytes_per_drive;
        for (peer, id) in streams {
            while budget > 0 {
                let chunk = self
                    .queues
                    .get(&peer)
                    .and_then(|queue| queue.records.front())
                    .map(|record| {
                        let end = record
                            .offset
                            .saturating_add(STREAM_IO_CHUNK_BYTES.min(budget))
                            .min(record.bytes.len());
                        record.bytes[record.offset..end].to_vec()
                    });
                let Some(chunk) = chunk else {
                    break;
                };
                let accepted = self
                    .tcp
                    .write(id, &chunk, now_ms)
                    .await
                    .map_err(|error| storage_error("write TCP/FIPS pubsub stream", error))?;
                if accepted == 0 {
                    break;
                }
                budget -= accepted;
                report.stream_bytes_written = report.stream_bytes_written.saturating_add(accepted);
                let queue = self.queues.get_mut(&peer).expect("queue still exists");
                let record = queue.records.front_mut().expect("record still exists");
                record.offset += accepted;
                queue.bytes = queue.bytes.saturating_sub(accepted);
                if record.offset == record.bytes.len() {
                    queue.records.pop_front();
                }
            }
            if self
                .queues
                .get(&peer)
                .is_some_and(|queue| queue.records.is_empty())
            {
                self.queues.remove(&peer);
            }
        }
        Ok(())
    }

    async fn finish_remote_closes(&mut self, now_ms: u64) -> Result<()> {
        let ids = self
            .active
            .iter()
            .filter_map(|(peer, id)| {
                (self.tcp.is_read_closed(*id) && !self.queues.contains_key(peer)).then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in ids {
            self.tcp
                .close(id, now_ms)
                .await
                .map_err(|error| storage_error("close TCP/FIPS pubsub stream", error))?;
        }
        Ok(())
    }

    fn apply_actions(
        &mut self,
        actions: Vec<FipsInvWantStreamAction>,
        deliveries: &mut Vec<QueryEvent>,
    ) -> Result<()> {
        let mut sends = Vec::new();
        let mut admitted_deliveries = Vec::new();
        let mut additions = BTreeMap::<String, (usize, usize)>::new();
        for action in actions {
            match action {
                FipsInvWantStreamAction::Send { peer_id, record } => {
                    let addition = additions.entry(peer_id.clone()).or_default();
                    addition.0 = addition.0.saturating_add(1);
                    addition.1 = addition.1.saturating_add(record.len());
                    sends.push((peer_id, record));
                }
                FipsInvWantStreamAction::Deliver(event) => admitted_deliveries.push(*event),
            }
        }
        let new_peers = additions
            .keys()
            .filter(|peer| !self.queues.contains_key(*peer))
            .count();
        if self.queues.len().saturating_add(new_peers) > self.options.max_peers {
            return Err(storage("TCP/FIPS pubsub queue peer limit reached"));
        }
        for (peer, (records, bytes)) in &additions {
            let existing = self.queues.get(peer);
            if existing
                .map_or(0, |queue| queue.records.len())
                .saturating_add(*records)
                > self.options.max_queued_records_per_peer
            {
                return Err(queue_full(peer, "record count"));
            }
            if existing
                .map_or(0, |queue| queue.bytes)
                .saturating_add(*bytes)
                > self.options.max_queued_bytes_per_peer
            {
                return Err(queue_full(peer, "byte count"));
            }
        }
        for (peer, record) in sends {
            let queue = self.queues.entry(peer).or_default();
            queue.bytes = queue.bytes.saturating_add(record.len());
            queue.records.push_back(QueuedRecord {
                bytes: record,
                offset: 0,
            });
        }
        deliveries.extend(admitted_deliveries);
        Ok(())
    }

    fn ensure_peer_capacity(&self, peer: &str) -> Result<()> {
        let peers = self
            .connections
            .values()
            .map(|connection| connection.peer.as_str())
            .collect::<BTreeSet<_>>();
        if !peers.contains(peer) && peers.len() >= self.options.max_peers {
            return Err(storage(format!(
                "TCP/FIPS pubsub peer limit is {}",
                self.options.max_peers
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Inbound,
    Outbound,
}

struct TrackedConnection {
    peer: String,
    direction: Direction,
}

#[derive(Default)]
struct PeerQueue {
    records: VecDeque<QueuedRecord>,
    bytes: usize,
}

struct QueuedRecord {
    bytes: Vec<u8>,
    offset: usize,
}

fn queue_full(peer: &str, resource: &str) -> PubsubError {
    storage(format!(
        "TCP/FIPS pubsub queue {resource} limit reached for {peer}"
    ))
}

fn validation(message: impl Into<String>) -> PubsubError {
    PubsubError::Validation(message.into())
}

fn storage(message: impl Into<String>) -> PubsubError {
    PubsubError::Storage(message.into())
}

fn storage_error(context: &str, error: impl Display) -> PubsubError {
    storage(format!("{context}: {error}"))
}
