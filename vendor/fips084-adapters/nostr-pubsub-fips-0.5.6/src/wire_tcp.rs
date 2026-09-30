use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fips_core::discovery::local::LocalInstanceCapability;
use fips_core::{FipsEndpoint, PeerIdentity};
use fips_tcp::{Config as TcpConfig, ConnectionId, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use nostr_pubsub::{PubsubError, Result};

use crate::{FIPS_NOSTR_PUBSUB_CAPABILITY, FIPS_NOSTR_PUBSUB_SERVICE_PORT};

const IO_CHUNK_BYTES: usize = 16 * 1024;
const MAX_READY_INPUT_TURNS: usize = 16;
const SERVICE_RETRY_INTERVAL: Duration = Duration::from_secs(3);

type ReceivedFrames = Vec<(PeerIdentity, Vec<u8>)>;

pub(crate) struct WireTcpOptions {
    pub frame_capacity: usize,
    pub peer_capacity: usize,
    pub queue_records_per_peer: usize,
    pub queue_bytes_per_peer: usize,
    pub drive_io_bytes: usize,
    pub drive_frames: usize,
}

pub(crate) struct WireTcpReport {
    pub frames: Vec<(PeerIdentity, Vec<u8>)>,
    pub newly_connected: Vec<PeerIdentity>,
    pub connected_peers: usize,
    pub tcp_datagrams: usize,
    pub rejected_tcp_datagrams: usize,
    pub rejected_frames: usize,
}

pub(crate) struct WireTcpDriver {
    local_npub: String,
    // Next outbound attempt per selected peer; failed/short-lived services must
    // not turn the polling timer or application sends into a handshake loop.
    selected_peers: BTreeMap<String, Option<Instant>>,
    tcp: FipsTcpEndpoint,
    options: WireTcpOptions,
    connections: HashMap<ConnectionId, TrackedConnection>,
    active: BTreeMap<String, ConnectionId>,
    queues: BTreeMap<String, PeerQueue>,
    inputs: HashMap<String, RecordDecoder>,
}

impl WireTcpDriver {
    pub async fn bind(
        endpoint: Arc<FipsEndpoint>,
        options: WireTcpOptions,
        isn_seed: u64,
    ) -> Result<Self> {
        let max_connections = options
            .peer_capacity
            .checked_mul(2)
            .ok_or_else(|| storage("TCP connection limit overflows"))?;
        let tcp_config = TcpConfig {
            receive_buffer: u16::MAX as usize,
            send_buffer: options.queue_bytes_per_peer,
            max_connections,
            max_connections_per_peer: 2,
            ..TcpConfig::default()
        };
        let capability = LocalInstanceCapability::service(
            FIPS_NOSTR_PUBSUB_CAPABILITY,
            FIPS_NOSTR_PUBSUB_SERVICE_PORT,
        );
        let local_npub = endpoint.npub().to_string();
        let tcp = FipsTcpEndpoint::bind_with_capability(endpoint, capability, tcp_config, isn_seed)
            .await
            .map_err(|error| storage_error("bind TCP/FIPS Nostr pubsub service", error))?;
        Ok(Self {
            local_npub,
            selected_peers: BTreeMap::new(),
            tcp,
            options,
            connections: HashMap::new(),
            active: BTreeMap::new(),
            queues: BTreeMap::new(),
            inputs: HashMap::new(),
        })
    }

    fn has_peer_connection(&self, peer_npub: &str) -> bool {
        self.connections.iter().any(|(id, connection)| {
            connection.peer == peer_npub
                && matches!(
                    self.tcp.state(*id),
                    Some(
                        State::SynSent | State::SynReceived | State::Established | State::CloseWait
                    )
                )
        })
    }

    pub async fn select_peers(&mut self, peers: BTreeSet<String>) {
        let removed = self
            .selected_peers
            .keys()
            .filter(|peer| !peers.contains(*peer))
            .cloned()
            .collect::<Vec<_>>();
        self.selected_peers.retain(|peer, _| peers.contains(peer));
        for peer in peers {
            self.selected_peers.entry(peer).or_default();
        }
        for peer in removed {
            if let Ok(peer) = PeerIdentity::from_npub(&peer) {
                let _ = self.forget_peer(peer).await;
            }
        }
    }

    pub async fn connect_peer(&mut self, peer_npub: &str, now_ms: u64) -> Result<()> {
        self.ensure_peer_selected(peer_npub)?;
        if self.has_peer_connection(peer_npub) {
            return Ok(());
        }
        if self.selected_peers[peer_npub].is_some_and(|retry_at| Instant::now() < retry_at) {
            return Ok(());
        }
        self.ensure_peer_capacity(peer_npub)?;
        let peer = PeerIdentity::from_npub(peer_npub)
            .map_err(|error| storage_error("decode TCP/FIPS Nostr pubsub peer", error))?;
        // Keep this deadline through connect errors, stream closes and link
        // refreshes. Only deselection releases it along with the peer's queue.
        // Wall-clock adjustments must not bypass or prolong this retry delay.
        self.selected_peers.insert(
            peer_npub.to_owned(),
            Some(Instant::now() + SERVICE_RETRY_INTERVAL),
        );
        let id = self
            .tcp
            .connect(peer, now_ms)
            .await
            .map_err(|error| storage_error("connect TCP/FIPS Nostr pubsub peer", error))?;
        self.connections.insert(
            id,
            TrackedConnection {
                peer: peer_npub.to_owned(),
                direction: Direction::Outbound,
            },
        );
        Ok(())
    }

    pub fn queue_frame(&mut self, peer: PeerIdentity, frame: &[u8]) -> Result<()> {
        self.ensure_peer_selected(&peer.npub())?;
        if frame.len() > self.options.frame_capacity {
            return Err(storage(format!(
                "Nostr pubsub frame is {} bytes, maximum is {}",
                frame.len(),
                self.options.frame_capacity
            )));
        }
        let record = encode_record(frame)?;
        let peer_npub = peer.npub();
        let is_new = !self.queues.contains_key(&peer_npub);
        if is_new && self.queues.len() >= self.options.peer_capacity {
            return Err(storage("TCP/FIPS Nostr pubsub queue peer limit reached"));
        }
        let queue = self.queues.entry(peer_npub.clone()).or_default();
        if queue.records.len() >= self.options.queue_records_per_peer {
            return Err(storage(format!(
                "TCP/FIPS Nostr pubsub record queue is full for {peer_npub}"
            )));
        }
        if queue.bytes.saturating_add(record.len()) > self.options.queue_bytes_per_peer {
            return Err(storage(format!(
                "TCP/FIPS Nostr pubsub byte queue is full for {peer_npub}"
            )));
        }
        queue.bytes = queue.bytes.saturating_add(record.len());
        queue.records.push_back(QueuedRecord {
            bytes: record,
            offset: 0,
        });
        Ok(())
    }

    pub async fn receive(&mut self, now_ms: u64) -> Result<WireTcpReport> {
        let received = self
            .tcp
            .receive_report(now_ms)
            .await
            .map_err(|error| storage_error("receive TCP/FIPS Nostr pubsub batch", error))?;
        let mut report = self.drive_ready(now_ms).await?;
        report.tcp_datagrams = received.datagrams;
        report.rejected_tcp_datagrams = received.rejected();
        Ok(report)
    }

    pub async fn poll(&mut self, now_ms: u64) -> Result<WireTcpReport> {
        self.tcp
            .poll(now_ms)
            .await
            .map_err(|error| storage_error("poll TCP/FIPS Nostr pubsub transport", error))?;
        self.drive_ready(now_ms).await
    }

    pub async fn abort_peer(&mut self, peer: PeerIdentity) -> Result<()> {
        let peer_npub = peer.npub();
        let ids = self
            .connections
            .iter()
            .filter_map(|(id, connection)| (connection.peer == peer_npub).then_some(*id))
            .collect::<Vec<_>>();
        let mut last_error = None;
        for id in ids {
            if self.tcp.state(id).is_some()
                && let Err(error) = self.tcp.abort(id).await
            {
                last_error = Some(storage_error("abort TCP/FIPS Nostr pubsub peer", error));
            }
            self.connections.remove(&id);
        }
        self.active.remove(&peer_npub);
        self.inputs.remove(&peer_npub);
        if let Some(queue) = self.queues.get_mut(&peer_npub) {
            queue.restart();
        }
        last_error.map_or(Ok(()), Err)
    }

    pub async fn forget_peer(&mut self, peer: PeerIdentity) -> Result<()> {
        self.selected_peers.remove(&peer.npub());
        self.queues.remove(&peer.npub());
        self.abort_peer(peer).await
    }

    pub(crate) fn connection_count(&self) -> usize {
        self.connections.len()
    }

    async fn drive_ready(&mut self, now_ms: u64) -> Result<WireTcpReport> {
        self.accept_connections().await?;
        let newly_connected = self.refresh_active().await?;
        let (frames, rejected_frames) = self.read_active(now_ms).await?;
        self.flush_queues(now_ms).await?;
        self.finish_remote_closes(now_ms).await?;
        let more_connected = self.refresh_active().await?;
        let mut newly_connected = newly_connected;
        newly_connected.extend(more_connected);
        newly_connected.sort_unstable_by_key(PeerIdentity::npub);
        newly_connected.dedup_by_key(|peer| peer.npub());
        Ok(WireTcpReport {
            frames,
            newly_connected,
            connected_peers: self.active.len(),
            tcp_datagrams: 0,
            rejected_tcp_datagrams: 0,
            rejected_frames,
        })
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

    async fn refresh_active(&mut self) -> Result<Vec<PeerIdentity>> {
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
        let newly_connected = changed
            .iter()
            .filter(|peer| next_active.contains_key(*peer))
            .filter_map(|peer| PeerIdentity::from_npub(peer).ok())
            .collect::<Vec<_>>();
        self.active = next_active;
        for peer in changed {
            self.inputs.remove(&peer);
            if let Some(queue) = self.queues.get_mut(&peer) {
                queue.restart();
            }
        }
        Ok(newly_connected)
    }

    async fn read_active(&mut self, now_ms: u64) -> Result<(ReceivedFrames, usize)> {
        let streams = self
            .active
            .iter()
            .map(|(peer, id)| (peer.clone(), *id))
            .collect::<Vec<_>>();
        let mut budget = self.options.drive_io_bytes;
        let mut frames = Vec::new();
        let mut rejected = 0;
        'streams: for (peer, id) in streams {
            let mut turns = 0;
            while turns < MAX_READY_INPUT_TURNS && frames.len() < self.options.drive_frames {
                if self
                    .inputs
                    .get(&peer)
                    .is_some_and(RecordDecoder::has_complete_record)
                {
                    let decoded = self
                        .inputs
                        .get_mut(&peer)
                        .expect("decoder exists")
                        .take(self.options.drive_frames - frames.len());
                    let identity = PeerIdentity::from_npub(&peer)
                        .map_err(|error| storage_error("decode authenticated peer", error))?;
                    let Ok(decoded) = decoded else {
                        self.abort_peer(identity).await?;
                        rejected += 1;
                        continue 'streams;
                    };
                    frames.extend(decoded.into_iter().map(|frame| (identity, frame)));
                    turns += 1;
                    continue;
                }
                if budget == 0 {
                    break;
                }
                let decoder = self
                    .inputs
                    .entry(peer.clone())
                    .or_insert_with(|| RecordDecoder::new(self.options.frame_capacity));
                let read_max = decoder.remaining_capacity().min(IO_CHUNK_BYTES).min(budget);
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
                decoder.push(&bytes)?;
                turns += 1;
            }
        }
        Ok((frames, rejected))
    }

    async fn flush_queues(&mut self, now_ms: u64) -> Result<()> {
        let streams = self
            .active
            .iter()
            .map(|(peer, id)| (peer.clone(), *id))
            .collect::<Vec<_>>();
        let mut budget = self.options.drive_io_bytes;
        for (peer, id) in streams {
            while budget > 0 {
                let chunk = self
                    .queues
                    .get(&peer)
                    .and_then(|queue| queue.records.front())
                    .map(|record| {
                        let end = record
                            .offset
                            .saturating_add(IO_CHUNK_BYTES.min(budget))
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
                let queue = self.queues.get_mut(&peer).expect("queue exists");
                let record = queue.records.front_mut().expect("record exists");
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

    fn ensure_peer_capacity(&self, peer: &str) -> Result<()> {
        self.ensure_peer_selected(peer)?;
        let peers = self
            .connections
            .values()
            .map(|connection| connection.peer.as_str())
            .collect::<BTreeSet<_>>();
        if !peers.contains(peer) && peers.len() >= self.options.peer_capacity {
            return Err(storage(format!(
                "TCP/FIPS pubsub peer limit is {}",
                self.options.peer_capacity
            )));
        }
        Ok(())
    }

    fn ensure_peer_selected(&self, peer: &str) -> Result<()> {
        if !self.selected_peers.contains_key(peer) {
            return Err(storage("TCP/FIPS Nostr pubsub peer is no longer selected"));
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

impl PeerQueue {
    fn restart(&mut self) {
        for record in &mut self.records {
            record.offset = 0;
        }
        self.bytes = self.records.iter().map(|record| record.bytes.len()).sum();
    }
}

struct QueuedRecord {
    bytes: Vec<u8>,
    offset: usize,
}

struct RecordDecoder {
    max_frame_bytes: usize,
    buffer: Vec<u8>,
}

impl RecordDecoder {
    fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            buffer: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.buffer.len().saturating_add(bytes.len()) > self.max_frame_bytes + 4 {
            self.buffer.clear();
            return Err(storage("TCP/FIPS pubsub input exceeds frame bound"));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn take(&mut self, max_frames: usize) -> Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        let mut consumed = 0;
        while frames.len() < max_frames && self.buffer.len().saturating_sub(consumed) >= 4 {
            let declared = u32::from_be_bytes(
                self.buffer[consumed..consumed + 4]
                    .try_into()
                    .expect("record prefix is complete"),
            ) as usize;
            if declared > self.max_frame_bytes {
                self.buffer.clear();
                return Err(storage("TCP/FIPS pubsub frame exceeds configured bound"));
            }
            let record_bytes = 4 + declared;
            if self.buffer.len() - consumed < record_bytes {
                break;
            }
            frames.push(self.buffer[consumed + 4..consumed + record_bytes].to_vec());
            consumed += record_bytes;
        }
        if consumed == self.buffer.len() {
            self.buffer.clear();
        } else if consumed > 0 {
            self.buffer.drain(..consumed);
        }
        Ok(frames)
    }

    fn has_complete_record(&self) -> bool {
        if self.buffer.len() < 4 {
            return false;
        }
        let declared = u32::from_be_bytes(
            self.buffer[..4]
                .try_into()
                .expect("record prefix is complete"),
        ) as usize;
        // An invalid prefix is also ready: take() must reject it immediately
        // instead of waiting for a payload that cannot fit in this decoder.
        declared > self.max_frame_bytes || self.buffer.len() >= 4 + declared
    }

    fn remaining_capacity(&self) -> usize {
        self.max_frame_bytes
            .saturating_add(4)
            .saturating_sub(self.buffer.len())
    }
}

fn encode_record(frame: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(frame.len()).map_err(|_| storage("pubsub frame is too large"))?;
    let mut record = Vec::with_capacity(frame.len() + 4);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(frame);
    Ok(record)
}

fn storage(message: impl Into<String>) -> PubsubError {
    PubsubError::Storage(message.into())
}

fn storage_error(context: &str, error: impl std::fmt::Display) -> PubsubError {
    storage(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips_core::config::{IdentityConfig, SimTransportConfig, TransportInstances};
    use fips_core::{Config, Identity, SimNetwork, register_sim_network, unregister_sim_network};

    #[test]
    fn oversized_record_prefix_is_ready_for_rejection_without_filling_the_buffer() {
        for declared in [1025_u32, u32::MAX] {
            let mut decoder = RecordDecoder::new(1024);
            let prefix = declared.to_be_bytes();
            decoder.push(&prefix[..3]).unwrap();
            assert!(!decoder.has_complete_record());
            decoder.push(&prefix[3..]).unwrap();
            // This is the driver's readiness predicate: it must let take()
            // reject the prefix before more peer bytes fill the bounded input.
            assert!(decoder.has_complete_record());
            assert!(decoder.take(1).is_err());
            assert_eq!(decoder.remaining_capacity(), 1028);
            assert!(!decoder.has_complete_record());
            decoder.push(&encode_record(b"valid").unwrap()).unwrap();
            assert_eq!(decoder.take(1).unwrap(), vec![b"valid".to_vec()]);
        }
    }

    #[tokio::test]
    async fn oversized_record_aborts_only_its_stream_and_preserves_other_frames() {
        let mut config = Config::new();
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.lan.enabled = false;
        let endpoint = Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind(),
            )
            .await
            .unwrap(),
        );
        let mut peers = [74, 75].map(|value| {
            PeerIdentity::from_npub(&Identity::from_secret_bytes(&[value; 32]).unwrap().npub())
                .unwrap()
        });
        peers.sort_by_key(PeerIdentity::npub);
        let [healthy, malformed] = peers;
        let mut driver = WireTcpDriver::bind(
            endpoint.clone(),
            WireTcpOptions {
                frame_capacity: 1024,
                peer_capacity: 2,
                queue_records_per_peer: 4,
                queue_bytes_per_peer: 4096,
                drive_io_bytes: 4096,
                drive_frames: 4,
            },
            99,
        )
        .await
        .unwrap();
        driver
            .select_peers(peers.map(|peer| peer.npub()).into())
            .await;
        for peer in peers {
            driver.connect_peer(&peer.npub(), 0).await.unwrap();
            let id = driver
                .connections
                .iter()
                .find(|(_, connection)| connection.peer == peer.npub())
                .unwrap()
                .0;
            driver.active.insert(peer.npub(), *id);
            let mut decoder = RecordDecoder::new(1024);
            decoder
                .push(&if peer == healthy {
                    encode_record(b"valid").unwrap()
                } else {
                    u32::MAX.to_be_bytes().to_vec()
                })
                .unwrap();
            driver.inputs.insert(peer.npub(), decoder);
        }
        let malformed_id = driver.active[&malformed.npub()];
        assert_eq!(
            driver.read_active(1).await.unwrap(),
            (vec![(healthy, b"valid".to_vec())], 1)
        );
        assert!(!driver.inputs.contains_key(&malformed.npub()));
        assert!(!driver.active.contains_key(&malformed.npub()));
        assert_eq!(driver.connection_count(), 1);
        assert!(driver.tcp.state(malformed_id).is_none());
        assert_eq!(driver.read_active(2).await.unwrap(), (Vec::new(), 0));
        drop(driver);
        endpoint.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn connection_admission_defers_validation_and_preserves_queued_recovery() {
        let network = format!("pubsub-wire-queue-{}", std::process::id());
        register_sim_network(&network, SimNetwork::new(7375));
        let mut config = Config::new();
        config.node.identity = IdentityConfig {
            nsec: Some(hex::encode([71; 32])),
            persistent: false,
        };
        config.node.discovery.nostr.enabled = false;
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(network.clone()),
            addr: Some("queue-local".to_string()),
            auto_connect: Some(false),
            ..Default::default()
        });
        let endpoint = Arc::new(
            Box::pin(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind(),
            )
            .await
            .unwrap(),
        );
        let mut driver = WireTcpDriver::bind(
            endpoint.clone(),
            WireTcpOptions {
                frame_capacity: 1024,
                peer_capacity: 1,
                queue_records_per_peer: 4,
                queue_bytes_per_peer: 4096,
                drive_io_bytes: 4096,
                drive_frames: 4,
            },
            73,
        )
        .await
        .unwrap();
        let early =
            PeerIdentity::from_npub(&Identity::from_secret_bytes(&[72; 32]).unwrap().npub())
                .unwrap();
        let late = PeerIdentity::from_npub(&Identity::from_secret_bytes(&[73; 32]).unwrap().npub())
            .unwrap();
        driver.select_peers(BTreeSet::from([early.npub()])).await;
        driver.connect_peer(&early.npub(), 100).await.unwrap();
        driver.queue_frame(early, b"partly-written").unwrap();
        let queued = driver.queues.get_mut(&early.npub()).unwrap();
        queued.records.front_mut().unwrap().offset = 3;
        queued.bytes -= 3;

        driver.abort_peer(early).await.unwrap();
        let queued = driver.queues.get(&early.npub()).unwrap();
        assert_eq!(queued.records.front().unwrap().offset, 0);
        assert_eq!(queued.bytes, b"partly-written".len() + 4);

        // A link refresh keeps queued data and the remaining retry deadline.
        driver.select_peers(BTreeSet::from([early.npub()])).await;
        driver.connect_peer(&early.npub(), u64::MAX).await.unwrap();
        assert_eq!(driver.connection_count(), 0);
        driver.connect_peer(&early.npub(), 0).await.unwrap();
        assert_eq!(driver.connection_count(), 0);
        tokio::time::sleep(SERVICE_RETRY_INTERVAL).await;
        driver.connect_peer(&early.npub(), 0).await.unwrap();
        assert_eq!(driver.connection_count(), 1);

        driver.select_peers(BTreeSet::from([late.npub()])).await;
        assert!(!driver.queues.contains_key(&early.npub()));
        assert!(driver.queue_frame(early, b"delayed old command").is_err());
        assert!(driver.connect_peer(&early.npub(), 0).await.is_err());
        driver.queue_frame(late, b"replacement request").unwrap();
        assert_eq!(driver.queues.len(), 1);
        assert!(driver.queues.contains_key(&late.npub()));
        assert_eq!(driver.selected_peers.len(), 1);
        driver.connect_peer(&late.npub(), 1_100).await.unwrap();
        assert_eq!(driver.connection_count(), 1);

        // An invalid sentinel makes decoding observable without a counter or
        // timing assertion: admission must reject/skip it before validation.
        let invalid = "not-an-npub";
        let error = driver.connect_peer(invalid, 0).await.unwrap_err();
        assert!(error.to_string().contains("no longer selected"));
        driver
            .select_peers(BTreeSet::from([invalid.to_owned()]))
            .await;
        driver.selected_peers.insert(
            invalid.to_owned(),
            Some(Instant::now() + SERVICE_RETRY_INTERVAL),
        );
        driver.connect_peer(invalid, 0).await.unwrap();
        assert_eq!(driver.connection_count(), 0);
        driver.selected_peers.insert(invalid.to_owned(), None);
        let error = driver.connect_peer(invalid, 0).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("decode TCP/FIPS Nostr pubsub peer")
        );
        assert_eq!(driver.connection_count(), 0);
        assert!(driver.queues.is_empty());
        drop(driver);
        endpoint.shutdown().await.unwrap();
        unregister_sim_network(&network);
    }
}
