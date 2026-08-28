use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use fips_core::{FipsEndpoint, PeerIdentity};
use fips_tcp::{Config, ConnectionId, MarkerStatus, SendMarker, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::fips_control::{
    FipsControlFrame, JoinRosterControl, decode_fips_control_frame, encode_fips_control_frame,
};

/// Reliable nVPN state-control records. Ping/pong remains datagram-based because
/// delayed delivery would make liveness misleading.
pub const FIPS_STATE_CONTROL_SERVICE_PORT: u16 = 7_370;
pub const FIPS_STATE_CONTROL_MAX_RECORD_BYTES: usize = 128 * 1024;

const COMMAND_CAPACITY: usize = 64;
const DELIVERY_CAPACITY: usize = 128;
const MAX_CONNECTIONS: usize = 256;
const MAX_CONNECTIONS_PER_PEER: usize = 8;
const IO_CHUNK_BYTES: usize = 16 * 1024;
const DRIVE_INTERVAL: Duration = Duration::from_millis(20);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_CLOSE_RETENTION_MS: u64 = 250;
const JOIN_ROSTER_ACK_RETRY_INTERVAL: Duration = Duration::from_secs(1);
static CONTROL_ISN_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct ReceivedFipsControlFrame {
    pub source_peer: PeerIdentity,
    pub frame: FipsControlFrame,
}

struct SendRequest {
    peer: PeerIdentity,
    bytes: Vec<u8>,
    response: Option<oneshot::Sender<std::result::Result<usize, String>>>,
}

struct OutboundRecord {
    bytes: Vec<u8>,
    offset: usize,
    final_marker: Option<SendMarker>,
    started: Instant,
    connected_at: Option<Instant>,
    response: Option<oneshot::Sender<std::result::Result<usize, String>>>,
}

struct InboundRecord {
    peer: PeerIdentity,
    bytes: Vec<u8>,
    started: Instant,
    ready: Option<FipsControlFrame>,
}

/// One state-control record per short FIPS-TCP stream.
///
/// Successful `send` means the authenticated peer's TCP stack acknowledged
/// the complete record. It deliberately does not add an application ACK.
pub struct FipsControlTcpRuntime {
    sender: FipsControlTcpSender,
    received_rx: mpsc::Receiver<ReceivedFipsControlFrame>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
pub struct FipsControlTcpSender {
    command_tx: mpsc::Sender<SendRequest>,
    received_tx: broadcast::Sender<ReceivedFipsControlFrame>,
}

impl FipsControlTcpSender {
    pub async fn send(&self, peer: PeerIdentity, frame: &FipsControlFrame) -> Result<usize> {
        let bytes = encode_stateful_record(frame)?;
        let (response, result) = oneshot::channel();
        self.command_tx
            .send(SendRequest {
                peer,
                bytes,
                response: Some(response),
            })
            .await
            .context("FIPS-TCP state-control runtime stopped before send")?;
        result
            .await
            .context("FIPS-TCP state-control runtime stopped during send")?
            .map_err(anyhow::Error::msg)
    }

    /// Admit a periodic state-control record to the bounded delivery queue
    /// without waiting for the remote TCP acknowledgement. Transactional
    /// callers should keep using [`Self::send`].
    pub fn enqueue(&self, peer: PeerIdentity, frame: &FipsControlFrame) -> Result<usize> {
        let bytes = encode_stateful_record(frame)?;
        let len = bytes.len();
        self.command_tx
            .try_send(SendRequest {
                peer,
                bytes,
                response: None,
            })
            .map_err(|error| anyhow!("FIPS-TCP state-control queue unavailable: {error}"))?;
        Ok(len)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ReceivedFipsControlFrame> {
        self.received_tx.subscribe()
    }
}

/// Retransmit an idempotent signed join roster until the authenticated guest
/// confirms that this exact roster event was durably applied.
pub async fn send_join_roster_with_receipt(
    sender: &FipsControlTcpSender,
    destination: PeerIdentity,
    control: &JoinRosterControl,
    timeout: Duration,
) -> Result<usize> {
    let frame = FipsControlFrame::JoinRoster {
        control: Box::new(control.clone()),
    };
    let sent_len = encode_stateful_record(&frame)?.len();
    let roster_event_id = control.signed_roster.artifact_hash();
    let mut receipts = sender.subscribe();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_transport_error = None;

    loop {
        let transport = sender.send(destination, &frame);
        tokio::pin!(transport);
        let transport_sent = loop {
            tokio::select! {
                result = &mut transport => break Some(result),
                receipt = receipts.recv() => {
                    if receipt.is_ok_and(|receipt| {
                        join_roster_ack_matches(&receipt, destination, &roster_event_id)
                    }) {
                        return Ok(sent_len);
                    }
                }
                () = tokio::time::sleep_until(deadline) => break None,
            }
        };
        match transport_sent {
            Some(Ok(_)) => {}
            Some(Err(error)) if sender.command_tx.is_closed() => return Err(error),
            Some(Err(error)) => last_transport_error = Some(error.to_string()),
            None => {
                last_transport_error.get_or_insert_with(|| {
                    "FIPS-TCP transport acknowledgement did not complete before the delivery deadline"
                        .to_string()
                });
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(join_roster_ack_timeout_error(
                destination,
                last_transport_error.as_deref(),
            ));
        }

        let retry_at = (tokio::time::Instant::now() + JOIN_ROSTER_ACK_RETRY_INTERVAL).min(deadline);
        loop {
            tokio::select! {
                receipt = receipts.recv() => {
                    if receipt.is_ok_and(|receipt| {
                        join_roster_ack_matches(&receipt, destination, &roster_event_id)
                    }) {
                        return Ok(sent_len);
                    }
                }
                () = tokio::time::sleep_until(retry_at) => break,
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(join_roster_ack_timeout_error(
                destination,
                last_transport_error.as_deref(),
            ));
        }
    }
}

fn join_roster_ack_matches(
    received: &ReceivedFipsControlFrame,
    destination: PeerIdentity,
    roster_event_id: &str,
) -> bool {
    received.source_peer == destination
        && matches!(
            &received.frame,
            FipsControlFrame::JoinRosterAck { roster_event_id: received_id }
                if received_id.eq_ignore_ascii_case(roster_event_id)
        )
}

fn join_roster_ack_timeout_error(
    destination: PeerIdentity,
    transport_error: Option<&str>,
) -> anyhow::Error {
    match transport_error {
        Some(error) => anyhow!(
            "join roster application receipt from {destination} timed out; last transport error: {error}"
        ),
        None => anyhow!("join roster application receipt from {destination} timed out"),
    }
}

fn encode_stateful_record(frame: &FipsControlFrame) -> Result<Vec<u8>> {
    if !is_stateful(frame) {
        return Err(anyhow!("ping/pong must use the FIPS datagram probe path"));
    }
    let bytes = encode_fips_control_frame(frame)?;
    if bytes.len() > FIPS_STATE_CONTROL_MAX_RECORD_BYTES {
        return Err(anyhow!(
            "FIPS state-control record is {} bytes; maximum is {FIPS_STATE_CONTROL_MAX_RECORD_BYTES}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

impl FipsControlTcpRuntime {
    pub async fn start(endpoint: Arc<FipsEndpoint>) -> Result<Self> {
        Self::start_with_delivery_capacity(endpoint, DELIVERY_CAPACITY).await
    }

    async fn start_with_delivery_capacity(
        endpoint: Arc<FipsEndpoint>,
        delivery_capacity: usize,
    ) -> Result<Self> {
        let config = Config {
            receive_buffer: u16::MAX as usize,
            send_buffer: u16::MAX as usize,
            max_connections: MAX_CONNECTIONS,
            max_connections_per_peer: MAX_CONNECTIONS_PER_PEER,
            // Control records use a fresh ephemeral port and both runtimes
            // close as soon as the complete record enters the local delivery
            // queue. Retaining those closed tuples for the general TCP
            // defaults (30-60 seconds) lets ordinary roster/capability bursts
            // exhaust the eight-stream peer budget and starve a join receipt.
            fin_wait_2_ms: CONTROL_CLOSE_RETENTION_MS,
            time_wait_ms: CONTROL_CLOSE_RETENTION_MS,
            ..Config::default()
        };
        let tcp = FipsTcpEndpoint::bind(
            Arc::clone(&endpoint),
            FIPS_STATE_CONTROL_SERVICE_PORT,
            config,
            control_isn_seed(endpoint.npub()),
        )
        .await
        .context("failed to bind FIPS-TCP state-control service")?;
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (received_tx, received_rx) = mpsc::channel(delivery_capacity);
        let (observed_tx, _) = broadcast::channel(delivery_capacity.max(1));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run(
            tcp,
            command_rx,
            received_tx,
            observed_tx.clone(),
            shutdown_rx,
        ));
        Ok(Self {
            sender: FipsControlTcpSender {
                command_tx,
                received_tx: observed_tx,
            },
            received_rx,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub async fn send(&self, peer: PeerIdentity, frame: &FipsControlFrame) -> Result<usize> {
        self.sender.send(peer, frame).await
    }

    pub fn sender(&self) -> FipsControlTcpSender {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<ReceivedFipsControlFrame> {
        self.received_rx.recv().await
    }

    pub fn drain(&mut self) -> Vec<ReceivedFipsControlFrame> {
        let mut received = Vec::new();
        while let Ok(frame) = self.received_rx.try_recv() {
            received.push(frame);
        }
        received
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for FipsControlTcpRuntime {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

async fn run(
    mut tcp: FipsTcpEndpoint,
    mut commands: mpsc::Receiver<SendRequest>,
    received: mpsc::Sender<ReceivedFipsControlFrame>,
    observed: broadcast::Sender<ReceivedFipsControlFrame>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut outbound = HashMap::<ConnectionId, OutboundRecord>::new();
    let mut inbound = HashMap::<ConnectionId, InboundRecord>::new();
    let mut drive_delay = next_drive_delay(false);
    let drive = tokio::time::sleep(drive_delay);
    tokio::pin!(drive);

    loop {
        // `receive_report` snapshots the TCP clock before awaiting a packet.
        // Retaining the close-retention deadline while quiet bounds that clock
        // staleness and retires closed tuples without waking at the active
        // 20 ms retransmission cadence.
        let receive_now = now_ms();
        let (now, drive_fired) = tokio::select! {
            _ = &mut shutdown => break,
            command = commands.recv() => {
                let Some(command) = command else { break; };
                let now = now_ms();
                match tcp.connect(command.peer, now).await {
                    Ok(id) => {
                        outbound.insert(id, OutboundRecord {
                            bytes: command.bytes,
                            offset: 0,
                            final_marker: None,
                            started: Instant::now(),
                            connected_at: None,
                            response: command.response,
                        });
                    }
                    Err(error) => {
                        if let Some(response) = command.response {
                            let _ = response.send(Err(error.to_string()));
                        }
                    }
                }
                (now, false)
            }
            result = tcp.receive_report(receive_now) => {
                if result.is_err() { break; }
                (now_ms(), false)
            }
            () = &mut drive => {
                let now = now_ms();
                if tcp.poll(now).await.is_err() { break; }
                (now, true)
            }
        };
        drive_ready(
            &mut tcp,
            &received,
            &observed,
            &mut outbound,
            &mut inbound,
            now,
        )
        .await;

        let next_delay = next_drive_delay(!outbound.is_empty() || !inbound.is_empty());
        if drive_fired || next_delay != drive_delay {
            drive_delay = next_delay;
            drive
                .as_mut()
                .reset(tokio::time::Instant::now() + drive_delay);
        }
    }

    for (_, mut record) in outbound {
        if let Some(response) = record.response.take() {
            let _ = response.send(Err("FIPS-TCP state-control runtime stopped".to_string()));
        }
    }
}

fn next_drive_delay(has_open_record: bool) -> Duration {
    if has_open_record {
        DRIVE_INTERVAL
    } else {
        Duration::from_millis(CONTROL_CLOSE_RETENTION_MS)
    }
}

async fn drive_ready(
    tcp: &mut FipsTcpEndpoint,
    received: &mpsc::Sender<ReceivedFipsControlFrame>,
    observed: &broadcast::Sender<ReceivedFipsControlFrame>,
    outbound: &mut HashMap<ConnectionId, OutboundRecord>,
    inbound: &mut HashMap<ConnectionId, InboundRecord>,
    now_ms: u64,
) {
    while let Some(id) = tcp.accept() {
        if inbound.len() >= MAX_CONNECTIONS {
            let _ = tcp.abort(id).await;
            continue;
        }
        let Some(peer) = tcp.peer(id) else {
            let _ = tcp.abort(id).await;
            continue;
        };
        inbound.insert(
            id,
            InboundRecord {
                peer,
                bytes: Vec::new(),
                started: Instant::now(),
                ready: None,
            },
        );
    }

    for id in outbound.keys().copied().collect::<Vec<_>>() {
        let Some(mut record) = outbound.remove(&id) else {
            continue;
        };
        if record
            .response
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
        {
            let _ = tcp.abort(id).await;
            continue;
        }
        let result = drive_outbound(tcp, id, &mut record, now_ms).await;
        match result {
            Ok(Some(sent)) => {
                if let Some(response) = record.response.take() {
                    let _ = response.send(Ok(sent));
                }
            }
            Ok(None) => {
                outbound.insert(id, record);
            }
            Err(error) => {
                let _ = tcp.abort(id).await;
                if let Some(response) = record.response.take() {
                    let _ = response.send(Err(error));
                }
            }
        }
    }

    for id in inbound.keys().copied().collect::<Vec<_>>() {
        let Some(mut record) = inbound.remove(&id) else {
            continue;
        };
        if let Some(frame) = record.ready.take() {
            if !try_deliver(received, observed, &mut record, frame) {
                inbound.insert(id, record);
            }
            continue;
        }
        match drive_inbound(tcp, id, &mut record, now_ms).await {
            Ok(Some(frame)) => {
                if !try_deliver(received, observed, &mut record, frame) {
                    inbound.insert(id, record);
                }
            }
            Ok(None) => {
                inbound.insert(id, record);
            }
            Err(()) => {
                let _ = tcp.abort(id).await;
            }
        }
    }
}

fn try_deliver(
    received: &mpsc::Sender<ReceivedFipsControlFrame>,
    observed: &broadcast::Sender<ReceivedFipsControlFrame>,
    record: &mut InboundRecord,
    frame: FipsControlFrame,
) -> bool {
    let delivered = ReceivedFipsControlFrame {
        source_peer: record.peer,
        frame,
    };
    match received.try_send(delivered.clone()) {
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {
            let _ = observed.send(delivered);
            true
        }
        Err(mpsc::error::TrySendError::Full(message)) => {
            record.ready = Some(message.frame);
            false
        }
    }
}

async fn drive_outbound(
    tcp: &mut FipsTcpEndpoint,
    id: ConnectionId,
    record: &mut OutboundRecord,
    now_ms: u64,
) -> std::result::Result<Option<usize>, String> {
    let Some(state) = tcp.state(id) else {
        return Err("FIPS-TCP state-control connection closed before delivery".to_string());
    };
    if let Some(reason) = outbound_timeout_reason(record, state, Instant::now()) {
        return Err(reason.to_string());
    }
    if matches!(state, State::Established | State::CloseWait) && record.offset < record.bytes.len()
    {
        let end = record
            .offset
            .saturating_add(IO_CHUNK_BYTES)
            .min(record.bytes.len());
        let (accepted, marker) = tcp
            .write_with_marker(id, &record.bytes[record.offset..end], now_ms)
            .await
            .map_err(|error| error.to_string())?;
        record.offset = record.offset.saturating_add(accepted);
        if accepted > 0 && record.offset == record.bytes.len() {
            record.final_marker = Some(marker);
        }
    }
    let Some(marker) = record.final_marker.as_ref() else {
        return Ok(None);
    };
    match tcp.marker_status(marker) {
        MarkerStatus::Pending => Ok(None),
        MarkerStatus::ConnectionGone => {
            Err("FIPS-TCP state-control connection closed before acknowledgment".to_string())
        }
        MarkerStatus::Acked => {
            tcp.close(id, now_ms)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Some(record.bytes.len()))
        }
    }
}

fn outbound_timeout_reason(
    record: &mut OutboundRecord,
    state: State,
    now: Instant,
) -> Option<&'static str> {
    if matches!(state, State::Established | State::CloseWait) {
        let connected_at = *record.connected_at.get_or_insert(now);
        return (now.duration_since(connected_at) >= STREAM_TIMEOUT)
            .then_some("FIPS-TCP state-control send timed out");
    }
    (now.duration_since(record.started) >= CONNECTION_TIMEOUT)
        .then_some("FIPS-TCP state-control connection timed out")
}

async fn drive_inbound(
    tcp: &mut FipsTcpEndpoint,
    id: ConnectionId,
    record: &mut InboundRecord,
    now_ms: u64,
) -> std::result::Result<Option<FipsControlFrame>, ()> {
    if record.started.elapsed() >= STREAM_TIMEOUT || tcp.state(id).is_none() {
        return Err(());
    }
    if matches!(tcp.state(id), Some(State::Established | State::CloseWait)) {
        let remaining = FIPS_STATE_CONTROL_MAX_RECORD_BYTES.saturating_sub(record.bytes.len());
        if remaining == 0 {
            return Err(());
        }
        let bytes = tcp
            .read(id, remaining.min(IO_CHUNK_BYTES), now_ms)
            .await
            .map_err(|_| ())?;
        record.bytes.extend(bytes);
        if let Some(frame) = decode_complete_stateful_record(&record.bytes) {
            tcp.close(id, now_ms).await.map_err(|_| ())?;
            return Ok(Some(frame));
        }
    }
    if !tcp.is_read_closed(id) {
        return Ok(None);
    }
    tcp.close(id, now_ms).await.map_err(|_| ())?;
    let frame = decode_complete_stateful_record(&record.bytes).ok_or(())?;
    Ok(Some(frame))
}

fn decode_complete_stateful_record(bytes: &[u8]) -> Option<FipsControlFrame> {
    decode_fips_control_frame(bytes)
        .ok()
        .flatten()
        .filter(is_stateful)
}

fn is_stateful(frame: &FipsControlFrame) -> bool {
    !matches!(
        frame,
        FipsControlFrame::Ping { .. } | FipsControlFrame::Pong { .. }
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn control_isn_seed(npub: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(npub.as_bytes());
    hasher.update(now_ms().to_be_bytes());
    hasher.update(
        CONTROL_ISN_NONCE
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes(),
    );
    let digest = hasher.finalize();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

#[cfg(test)]
mod tests;
