use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use nostr_vpn_core::nat::{
    DISCOVER_REQUEST_PREFIX, ENDPOINT_RESPONSE_PREFIX, PUNCH_ACK_PREFIX, PUNCH_REQUEST_PREFIX,
};
use nostr_vpn_core::node_record::{
    NODE_RECORD_D_TAG, NodeRecord, NodeRecordMode, NodeService, NodeServiceKind,
    publish_node_record,
};
use nostr_vpn_core::relay::{
    NatAssistOperatorState, RelayAllocationGranted, RelayAllocationRejectReason,
    RelayAllocationRejected, RelayOperatorSessionState, RelayOperatorState, RelayProbeGranted,
    RelayProbeRejected, ServiceOperatorState,
};
use nostr_vpn_core::service_signaling::{RelayServiceClient, ServicePayload};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Instant;

const DEFAULT_LEASE_SECS: u64 = 120;
const DEFAULT_PROBE_LEASE_SECS: u64 = 8;
const DEFAULT_PUBLISH_INTERVAL_SECS: u64 = 30;
const DEFAULT_NAT_ASSIST_PORT: u16 = 3478;
const DEFAULT_MAX_ACTIVE_RELAY_SESSIONS: usize = 64;
const DEFAULT_MAX_SESSIONS_PER_REQUESTER: usize = 8;
const DEFAULT_MAX_BYTES_PER_SESSION: u64 = 128 * 1024 * 1024;
const DEFAULT_STATE_FILE_NAME: &str = "relay.operator.json";
const STATE_WRITE_INTERVAL_SECS: u64 = 1;

#[derive(Debug, Parser)]
#[command(name = "nvpn-udp-relay")]
#[command(about = "Experimental public UDP services for nostr-vpn")]
struct Args {
    #[arg(long)]
    secret_key: String,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long, default_value = "0.0.0.0")]
    bind_ip: String,
    #[arg(long)]
    advertise_host: String,
    #[arg(long, default_value_t = false)]
    disable_relay: bool,
    #[arg(long, default_value_t = false)]
    enable_nat_assist: bool,
    #[arg(long, default_value_t = DEFAULT_NAT_ASSIST_PORT)]
    nat_assist_port: u16,
    #[arg(long, default_value_t = DEFAULT_LEASE_SECS)]
    lease_secs: u64,
    #[arg(long)]
    relay_port_range_start: Option<u16>,
    #[arg(long)]
    relay_port_range_end: Option<u16>,
    #[arg(long, default_value_t = DEFAULT_PUBLISH_INTERVAL_SECS)]
    publish_interval_secs: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_ACTIVE_RELAY_SESSIONS)]
    max_active_sessions: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_SESSIONS_PER_REQUESTER)]
    max_sessions_per_requester: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_BYTES_PER_SESSION)]
    max_bytes_per_session: u64,
    #[arg(long)]
    max_forward_bps: Option<u64>,
    #[arg(long)]
    price_hint_msats: Option<u64>,
    #[arg(long)]
    state_file: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct SessionLeg {
    bound_addr: Option<SocketAddr>,
}

#[derive(Debug, Default)]
struct SessionState {
    requester: SessionLeg,
    target: SessionLeg,
    forwarding: SessionForwardingState,
}

#[derive(Debug, Clone)]
struct RelayServiceLimits {
    max_active_sessions: usize,
    max_sessions_per_requester: usize,
    max_bytes_per_session: u64,
    max_forward_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayPortRange {
    start: u16,
    end: u16,
}

impl RelayPortRange {
    fn new(start: u16, end: u16) -> Result<Self> {
        if start == 0 || end == 0 {
            return Err(anyhow!("relay port range cannot include port 0"));
        }
        if end < start {
            return Err(anyhow!(
                "invalid relay port range {start}-{end}: end must be >= start"
            ));
        }

        Ok(Self { start, end })
    }

    fn len(self) -> usize {
        usize::from(self.end - self.start) + 1
    }

    fn capacity_sessions(self) -> usize {
        self.len() / 2
    }

    fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }

    fn next_after(self, port: u16) -> u16 {
        if port >= self.end {
            self.start
        } else {
            port + 1
        }
    }
}

#[derive(Debug)]
struct RelayPortAllocator {
    range: RelayPortRange,
    next_port: u16,
}

impl RelayPortAllocator {
    fn new(range: RelayPortRange) -> Self {
        Self {
            range,
            next_port: range.start,
        }
    }

    fn bind_pair(
        &mut self,
        bind_ip: IpAddr,
        advertise_host: &str,
    ) -> Result<(Arc<UdpSocket>, Arc<UdpSocket>, String, String)> {
        let advertise_ip = parse_advertise_ip(advertise_host)?;
        let mut first_port = self.next_port;
        let start_port = self.next_port;
        let mut tried_first = false;

        while !tried_first || first_port != start_port {
            tried_first = true;
            let requester_bind_addr = SocketAddr::new(bind_ip, first_port);
            let requester_socket = match bind_udp_socket(requester_bind_addr) {
                Ok(socket) => socket,
                Err(error) if io_error_kind(&error) == Some(ErrorKind::AddrInUse) => {
                    first_port = self.range.next_after(first_port);
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to bind requester relay leg on {requester_bind_addr}")
                    });
                }
            };

            let requester_addr = requester_socket
                .local_addr()
                .context("failed to read requester leg addr")?;
            let second_start = self.range.next_after(first_port);
            let mut second_port = second_start;
            let mut tried_second = false;

            while !tried_second || second_port != second_start {
                tried_second = true;
                if second_port == first_port {
                    break;
                }

                let target_bind_addr = SocketAddr::new(bind_ip, second_port);
                match bind_udp_socket(target_bind_addr) {
                    Ok(target_socket) => {
                        let target_addr = target_socket
                            .local_addr()
                            .context("failed to read target leg addr")?;
                        self.next_port = self.range.next_after(second_port);
                        let requester_ingress_endpoint =
                            SocketAddr::new(advertise_ip, requester_addr.port()).to_string();
                        let target_ingress_endpoint =
                            SocketAddr::new(advertise_ip, target_addr.port()).to_string();
                        return Ok((
                            requester_socket,
                            target_socket,
                            requester_ingress_endpoint,
                            target_ingress_endpoint,
                        ));
                    }
                    Err(error) if io_error_kind(&error) == Some(ErrorKind::AddrInUse) => {
                        second_port = self.range.next_after(second_port);
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to bind target relay leg on {target_bind_addr}")
                        });
                    }
                }
            }

            drop(requester_socket);
            first_port = self.range.next_after(first_port);
        }

        Err(anyhow!(
            "no free relay port pair available in configured range {}-{}",
            self.range.start,
            self.range.end
        ))
    }
}

struct RelayLegTask {
    rx_socket: Arc<UdpSocket>,
    tx_socket: Arc<UdpSocket>,
    state: Arc<Mutex<SessionState>>,
    service_runtime_state: Arc<Mutex<ServiceRuntimeState>>,
    relay_limits: RelayServiceLimits,
    request_id: String,
    requester_leg: bool,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct SessionForwardingState {
    forward_window: Option<ForwardWindow>,
    total_forwarded_bytes: u64,
    closed: bool,
}

#[derive(Debug, Clone, Copy)]
struct ForwardWindow {
    last_refill: Instant,
    available_bytes: u64,
}

#[derive(Debug, Default)]
struct RelayRuntimeState {
    relay_pubkey: String,
    advertised_endpoint: String,
    total_sessions_served: u64,
    total_forwarded_bytes: u64,
    current_forward_bps: u64,
    last_rate_sample_at: u64,
    last_rate_sample_bytes: u64,
    known_peer_pubkeys: HashSet<String>,
    active_sessions: HashMap<String, RelayOperatorSessionState>,
}

impl RelayRuntimeState {
    fn prune_expired_sessions(&mut self, now: u64) {
        self.active_sessions
            .retain(|_, session| session.expires_at > now);
    }

    fn allocation_rejection_for_requester(
        &mut self,
        requester_pubkey: &str,
        now: u64,
        limits: &RelayServiceLimits,
    ) -> Option<(RelayAllocationRejectReason, Option<u64>)> {
        self.prune_expired_sessions(now);

        if self.active_sessions.len() >= limits.max_active_sessions {
            return Some((RelayAllocationRejectReason::OverCapacity, Some(30)));
        }

        let requester_sessions = self
            .active_sessions
            .values()
            .filter(|session| session.requester_pubkey == requester_pubkey)
            .count();
        if requester_sessions >= limits.max_sessions_per_requester {
            return Some((
                RelayAllocationRejectReason::TooManySessionsForRequester,
                Some(60),
            ));
        }

        None
    }

    fn note_session_started(&mut self, session: RelayOperatorSessionState) {
        self.prune_expired_sessions(unix_timestamp());
        self.total_sessions_served = self.total_sessions_served.saturating_add(1);
        self.known_peer_pubkeys
            .insert(session.requester_pubkey.clone());
        self.known_peer_pubkeys
            .insert(session.target_pubkey.clone());
        self.active_sessions
            .insert(session.request_id.clone(), session);
    }

    fn note_forwarded_bytes(&mut self, request_id: &str, requester_leg: bool, bytes: u64) {
        self.total_forwarded_bytes = self.total_forwarded_bytes.saturating_add(bytes);
        if let Some(session) = self.active_sessions.get_mut(request_id) {
            if requester_leg {
                session.bytes_from_requester = session.bytes_from_requester.saturating_add(bytes);
            } else {
                session.bytes_from_target = session.bytes_from_target.saturating_add(bytes);
            }
        }
    }

    fn snapshot(&mut self, now: u64) -> RelayOperatorState {
        self.prune_expired_sessions(now);

        let elapsed = now.saturating_sub(self.last_rate_sample_at);
        if elapsed > 0 {
            let bytes_delta = self
                .total_forwarded_bytes
                .saturating_sub(self.last_rate_sample_bytes);
            self.current_forward_bps = bytes_delta / elapsed;
            self.last_rate_sample_at = now;
            self.last_rate_sample_bytes = self.total_forwarded_bytes;
        } else if self.last_rate_sample_at == 0 {
            self.last_rate_sample_at = now;
            self.last_rate_sample_bytes = self.total_forwarded_bytes;
        }

        let mut known_peer_pubkeys = self.known_peer_pubkeys.iter().cloned().collect::<Vec<_>>();
        known_peer_pubkeys.sort();

        let mut active_sessions = self.active_sessions.values().cloned().collect::<Vec<_>>();
        active_sessions.sort_by(|left, right| {
            left.started_at
                .cmp(&right.started_at)
                .then_with(|| left.request_id.cmp(&right.request_id))
        });

        RelayOperatorState {
            updated_at: now,
            relay_pubkey: self.relay_pubkey.clone(),
            advertised_endpoint: self.advertised_endpoint.clone(),
            total_sessions_served: self.total_sessions_served,
            total_forwarded_bytes: self.total_forwarded_bytes,
            current_forward_bps: self.current_forward_bps,
            unique_peer_count: known_peer_pubkeys.len(),
            known_peer_pubkeys,
            active_sessions,
        }
    }
}

impl SessionForwardingState {
    fn allow_forward(
        &mut self,
        limits: &RelayServiceLimits,
        now: Instant,
        bytes: usize,
    ) -> Result<(), RelayAllocationRejectReason> {
        if self.closed {
            return Err(RelayAllocationRejectReason::ByteLimitExceeded);
        }

        let bytes = bytes as u64;
        if self.total_forwarded_bytes.saturating_add(bytes) > limits.max_bytes_per_session {
            self.closed = true;
            return Err(RelayAllocationRejectReason::ByteLimitExceeded);
        }

        if let Some(max_forward_bps) = limits.max_forward_bps {
            let burst = max_forward_bps.max(bytes);
            let window = self.forward_window.get_or_insert(ForwardWindow {
                last_refill: now,
                available_bytes: burst,
            });
            let elapsed = now
                .saturating_duration_since(window.last_refill)
                .as_secs_f64();
            if elapsed > 0.0 {
                let refill = (elapsed * max_forward_bps as f64) as u64;
                window.available_bytes = window.available_bytes.saturating_add(refill).min(burst);
                window.last_refill = now;
            }
            if window.available_bytes < bytes {
                return Err(RelayAllocationRejectReason::RateLimited);
            }
            window.available_bytes = window.available_bytes.saturating_sub(bytes);
        }

        self.total_forwarded_bytes = self.total_forwarded_bytes.saturating_add(bytes);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct NatAssistRuntimeState {
    advertised_endpoint: String,
    total_discovery_requests: u64,
    total_punch_requests: u64,
    current_request_bps: u64,
    last_rate_sample_at: u64,
    last_rate_sample_requests: u64,
    known_clients: HashSet<String>,
}

impl NatAssistRuntimeState {
    fn note_discovery_request(&mut self, src: SocketAddr) {
        self.total_discovery_requests = self.total_discovery_requests.saturating_add(1);
        self.known_clients.insert(src.ip().to_string());
    }

    fn note_punch_request(&mut self, src: SocketAddr) {
        self.total_punch_requests = self.total_punch_requests.saturating_add(1);
        self.known_clients.insert(src.ip().to_string());
    }

    fn snapshot(&mut self, now: u64) -> NatAssistOperatorState {
        let total_requests = self
            .total_discovery_requests
            .saturating_add(self.total_punch_requests);
        let elapsed = now.saturating_sub(self.last_rate_sample_at);
        if elapsed > 0 {
            let requests_delta = total_requests.saturating_sub(self.last_rate_sample_requests);
            self.current_request_bps = requests_delta / elapsed;
            self.last_rate_sample_at = now;
            self.last_rate_sample_requests = total_requests;
        } else if self.last_rate_sample_at == 0 {
            self.last_rate_sample_at = now;
            self.last_rate_sample_requests = total_requests;
        }

        NatAssistOperatorState {
            updated_at: now,
            advertised_endpoint: self.advertised_endpoint.clone(),
            total_discovery_requests: self.total_discovery_requests,
            total_punch_requests: self.total_punch_requests,
            current_request_bps: self.current_request_bps,
            unique_client_count: self.known_clients.len(),
        }
    }
}

#[derive(Debug, Default)]
struct ServiceRuntimeState {
    operator_pubkey: String,
    relay: Option<RelayRuntimeState>,
    nat_assist: Option<NatAssistRuntimeState>,
}

impl ServiceRuntimeState {
    fn note_session_started(&mut self, session: RelayOperatorSessionState) {
        if let Some(relay) = self.relay.as_mut() {
            relay.note_session_started(session);
        }
    }

    fn note_forwarded_bytes(&mut self, request_id: &str, requester_leg: bool, bytes: u64) {
        if let Some(relay) = self.relay.as_mut() {
            relay.note_forwarded_bytes(request_id, requester_leg, bytes);
        }
    }

    fn note_discovery_request(&mut self, src: SocketAddr) {
        if let Some(nat_assist) = self.nat_assist.as_mut() {
            nat_assist.note_discovery_request(src);
        }
    }

    fn note_punch_request(&mut self, src: SocketAddr) {
        if let Some(nat_assist) = self.nat_assist.as_mut() {
            nat_assist.note_punch_request(src);
        }
    }

    fn snapshot(&mut self, now: u64) -> ServiceOperatorState {
        ServiceOperatorState {
            updated_at: now,
            operator_pubkey: self.operator_pubkey.clone(),
            relay: self.relay.as_mut().map(|relay| relay.snapshot(now)),
            nat_assist: self
                .nat_assist
                .as_mut()
                .map(|nat_assist| nat_assist.snapshot(now)),
        }
    }
}

fn relay_runtime_state_from_snapshot(
    snapshot: RelayOperatorState,
    relay_pubkey: String,
    advertised_endpoint: String,
    now: u64,
) -> RelayRuntimeState {
    RelayRuntimeState {
        relay_pubkey,
        advertised_endpoint,
        total_sessions_served: snapshot.total_sessions_served,
        total_forwarded_bytes: snapshot.total_forwarded_bytes,
        current_forward_bps: 0,
        last_rate_sample_at: now,
        last_rate_sample_bytes: snapshot.total_forwarded_bytes,
        known_peer_pubkeys: snapshot.known_peer_pubkeys.into_iter().collect(),
        active_sessions: HashMap::new(),
    }
}

fn nat_assist_runtime_state_from_snapshot(
    snapshot: NatAssistOperatorState,
    advertised_endpoint: String,
    now: u64,
) -> NatAssistRuntimeState {
    let total_requests = snapshot
        .total_discovery_requests
        .saturating_add(snapshot.total_punch_requests);
    NatAssistRuntimeState {
        advertised_endpoint,
        total_discovery_requests: snapshot.total_discovery_requests,
        total_punch_requests: snapshot.total_punch_requests,
        current_request_bps: 0,
        last_rate_sample_at: now,
        last_rate_sample_requests: total_requests,
        known_clients: HashSet::new(),
    }
}

fn load_runtime_state(
    path: &Path,
    operator_pubkey: String,
    relay_endpoint: Option<String>,
    nat_assist_endpoint: Option<String>,
) -> ServiceRuntimeState {
    let now = unix_timestamp();
    let Ok(raw) = fs::read(path) else {
        return ServiceRuntimeState {
            operator_pubkey: operator_pubkey.clone(),
            relay: relay_endpoint.map(|advertised_endpoint| RelayRuntimeState {
                relay_pubkey: operator_pubkey.clone(),
                advertised_endpoint,
                last_rate_sample_at: now,
                ..RelayRuntimeState::default()
            }),
            nat_assist: nat_assist_endpoint.map(|advertised_endpoint| NatAssistRuntimeState {
                advertised_endpoint,
                last_rate_sample_at: now,
                ..NatAssistRuntimeState::default()
            }),
        };
    };

    match serde_json::from_slice::<ServiceOperatorState>(&raw) {
        Ok(snapshot)
            if snapshot.relay.is_some()
                || snapshot.nat_assist.is_some()
                || !snapshot.operator_pubkey.trim().is_empty() =>
        {
            ServiceRuntimeState {
                operator_pubkey: operator_pubkey.clone(),
                relay: relay_endpoint.map(|advertised_endpoint| {
                    let advertised_endpoint_fallback = advertised_endpoint.clone();
                    snapshot.relay.map_or_else(
                        || RelayRuntimeState {
                            relay_pubkey: operator_pubkey.clone(),
                            advertised_endpoint: advertised_endpoint_fallback,
                            last_rate_sample_at: now,
                            ..RelayRuntimeState::default()
                        },
                        |relay| {
                            relay_runtime_state_from_snapshot(
                                relay,
                                operator_pubkey.clone(),
                                advertised_endpoint,
                                now,
                            )
                        },
                    )
                }),
                nat_assist: nat_assist_endpoint.map(|advertised_endpoint| {
                    let advertised_endpoint_fallback = advertised_endpoint.clone();
                    snapshot.nat_assist.map_or_else(
                        || NatAssistRuntimeState {
                            advertised_endpoint: advertised_endpoint_fallback,
                            last_rate_sample_at: now,
                            ..NatAssistRuntimeState::default()
                        },
                        |nat_assist| {
                            nat_assist_runtime_state_from_snapshot(
                                nat_assist,
                                advertised_endpoint,
                                now,
                            )
                        },
                    )
                }),
            }
        }
        Err(_) | Ok(_) => match serde_json::from_slice::<RelayOperatorState>(&raw) {
            Ok(snapshot) => ServiceRuntimeState {
                operator_pubkey: operator_pubkey.clone(),
                relay: relay_endpoint.map(|advertised_endpoint| {
                    relay_runtime_state_from_snapshot(
                        snapshot,
                        operator_pubkey.clone(),
                        advertised_endpoint,
                        now,
                    )
                }),
                nat_assist: nat_assist_endpoint.map(|advertised_endpoint| NatAssistRuntimeState {
                    advertised_endpoint,
                    last_rate_sample_at: now,
                    ..NatAssistRuntimeState::default()
                }),
            },
            Err(error) => {
                eprintln!(
                    "relay-service: failed to parse existing state file {}: {error}",
                    path.display()
                );
                ServiceRuntimeState {
                    operator_pubkey: operator_pubkey.clone(),
                    relay: relay_endpoint.map(|advertised_endpoint| RelayRuntimeState {
                        relay_pubkey: operator_pubkey.clone(),
                        advertised_endpoint,
                        last_rate_sample_at: now,
                        ..RelayRuntimeState::default()
                    }),
                    nat_assist: nat_assist_endpoint.map(|advertised_endpoint| {
                        NatAssistRuntimeState {
                            advertised_endpoint,
                            last_rate_sample_at: now,
                            ..NatAssistRuntimeState::default()
                        }
                    }),
                }
            }
        },
    }
}

fn node_record_services(args: &Args) -> Result<Vec<NodeService>> {
    let mut services = Vec::new();
    if !args.disable_relay {
        services.push(NodeService {
            kind: NodeServiceKind::Relay,
            endpoint: format!("{}:0", args.advertise_host),
            protocol: Some("udp-port-pair".to_string()),
            price_hint_msats: args.price_hint_msats,
        });
    }
    if args.enable_nat_assist {
        services.push(NodeService {
            kind: NodeServiceKind::NatAssist,
            endpoint: SocketAddr::new(
                parse_advertise_ip(&args.advertise_host)?,
                args.nat_assist_port,
            )
            .to_string(),
            protocol: Some("udp-reflector".to_string()),
            price_hint_msats: None,
        });
    }
    Ok(services)
}

fn spawn_node_record_publisher(args: &Args) -> Result<()> {
    let services = node_record_services(args)?;
    let secret_key = args.secret_key.clone();
    let relays = args.relays.clone();
    let publish_interval_secs = args.publish_interval_secs.max(5);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(publish_interval_secs));
        loop {
            interval.tick().await;
            let record = NodeRecord {
                mode: NodeRecordMode::PublicService,
                services: services.clone(),
                updated_at: unix_timestamp(),
                expires_at: unix_timestamp() + publish_interval_secs * 3,
            };
            if let Err(error) = publish_node_record(&secret_key, &relays, &record).await {
                eprintln!(
                    "relay-service: failed to publish {} record: {error}",
                    NODE_RECORD_D_TAG,
                );
            }
        }
    });
    Ok(())
}

fn spawn_nat_assist_listener(
    bind_ip: IpAddr,
    port: u16,
    service_runtime_state: Arc<Mutex<ServiceRuntimeState>>,
) -> Result<()> {
    let bind_addr = SocketAddr::new(bind_ip, port);
    let socket = bind_udp_socket(bind_addr)
        .with_context(|| format!("failed to bind nat assist on {bind_addr}"))?;
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (read, src) = match socket.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("relay-service: nat assist recv failed: {error}");
                    return;
                }
            };
            let payload = std::str::from_utf8(&buf[..read]).unwrap_or_default();
            if payload.starts_with(DISCOVER_REQUEST_PREFIX) {
                {
                    let mut stats = service_runtime_state.lock().await;
                    stats.note_discovery_request(src);
                }
                let response = format!("{ENDPOINT_RESPONSE_PREFIX} {src}");
                let _ = socket.send_to(response.as_bytes(), src).await;
                continue;
            }
            if payload.starts_with(PUNCH_REQUEST_PREFIX) {
                {
                    let mut stats = service_runtime_state.lock().await;
                    stats.note_punch_request(src);
                }
                let _ = socket.send_to(PUNCH_ACK_PREFIX.as_bytes(), src).await;
            }
        }
    });
    Ok(())
}

async fn send_allocation_rejection(
    service_client: &RelayServiceClient,
    recipient_pubkey: &str,
    request_id: String,
    network_id: String,
    reason: RelayAllocationRejectReason,
    retry_after_secs: Option<u64>,
) -> Result<()> {
    service_client
        .publish_to(
            ServicePayload::RelayAllocationRejected(RelayAllocationRejected {
                request_id,
                network_id,
                relay_pubkey: service_client.own_pubkey().to_string(),
                reason,
                retry_after_secs,
            }),
            recipient_pubkey,
        )
        .await
}

async fn send_probe_rejection(
    service_client: &RelayServiceClient,
    recipient_pubkey: &str,
    request_id: String,
    reason: RelayAllocationRejectReason,
    retry_after_secs: Option<u64>,
) -> Result<()> {
    service_client
        .publish_to(
            ServicePayload::RelayProbeRejected(RelayProbeRejected {
                request_id,
                relay_pubkey: service_client.own_pubkey().to_string(),
                reason,
                retry_after_secs,
            }),
            recipient_pubkey,
        )
        .await
}

fn bind_relay_leg_pair(
    bind_ip: IpAddr,
    advertise_host: &str,
    relay_port_allocator: Option<&Arc<StdMutex<RelayPortAllocator>>>,
) -> Result<(Arc<UdpSocket>, Arc<UdpSocket>, String, String)> {
    if let Some(relay_port_allocator) = relay_port_allocator {
        let mut relay_port_allocator = relay_port_allocator
            .lock()
            .map_err(|_| anyhow!("relay port allocator poisoned"))?;
        return relay_port_allocator.bind_pair(bind_ip, advertise_host);
    }

    let requester_socket = bind_udp_socket(SocketAddr::new(bind_ip, 0))
        .with_context(|| format!("failed to bind requester leg on {bind_ip}"))?;
    let target_socket = bind_udp_socket(SocketAddr::new(bind_ip, 0))
        .with_context(|| format!("failed to bind target leg on {bind_ip}"))?;
    let requester_addr = requester_socket
        .local_addr()
        .context("failed to read requester leg addr")?;
    let target_addr = target_socket
        .local_addr()
        .context("failed to read target leg addr")?;
    let advertise_ip = parse_advertise_ip(advertise_host)?;
    let requester_ingress_endpoint =
        SocketAddr::new(advertise_ip, requester_addr.port()).to_string();
    let target_ingress_endpoint = SocketAddr::new(advertise_ip, target_addr.port()).to_string();
    Ok((
        requester_socket,
        target_socket,
        requester_ingress_endpoint,
        target_ingress_endpoint,
    ))
}

fn relay_port_range(args: &Args) -> Result<Option<RelayPortRange>> {
    match (args.relay_port_range_start, args.relay_port_range_end) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(anyhow!(
            "both --relay-port-range-start and --relay-port-range-end are required together"
        )),
        (Some(_), Some(_)) if args.disable_relay => Err(anyhow!(
            "relay port range flags cannot be used with --disable-relay"
        )),
        (Some(start), Some(end)) => {
            let range = RelayPortRange::new(start, end)?;
            if range.capacity_sessions() == 0 {
                return Err(anyhow!(
                    "relay port range {}-{} must contain at least 2 ports",
                    range.start,
                    range.end
                ));
            }
            if args.enable_nat_assist && range.contains(args.nat_assist_port) {
                return Err(anyhow!(
                    "nat assist port {} overlaps relay port range {}-{}",
                    args.nat_assist_port,
                    range.start,
                    range.end
                ));
            }
            if args.max_active_sessions > range.capacity_sessions() {
                return Err(anyhow!(
                    "relay port range {}-{} supports at most {} simultaneous sessions; lower --max-active-sessions or widen the range",
                    range.start,
                    range.end,
                    range.capacity_sessions()
                ));
            }
            Ok(Some(range))
        }
    }
}

fn bind_udp_socket(bind_addr: SocketAddr) -> Result<Arc<UdpSocket>> {
    let socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| format!("failed to bind udp socket on {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("failed to set nonblocking on udp socket {bind_addr}"))?;
    let socket = UdpSocket::from_std(socket)
        .with_context(|| format!("failed to create async udp socket for {bind_addr}"))?;
    Ok(Arc::new(socket))
}

fn io_error_kind(error: &anyhow::Error) -> Option<ErrorKind> {
    error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.relays.is_empty() {
        return Err(anyhow!("at least one --relay is required"));
    }
    if args.disable_relay && !args.enable_nat_assist {
        return Err(anyhow!(
            "at least one public service must be enabled (relay or nat assist)"
        ));
    }

    let bind_ip = args
        .bind_ip
        .parse::<IpAddr>()
        .with_context(|| format!("invalid bind ip {}", args.bind_ip))?;
    let relay_port_range = relay_port_range(&args)?;
    let state_file = args
        .state_file
        .clone()
        .unwrap_or_else(default_state_file_path);
    let service_client = Arc::new(RelayServiceClient::from_secret_key(&args.secret_key)?);
    service_client.connect(&args.relays).await?;

    println!(
        "nvpn-udp-relay connected as {} on {} relays",
        service_client.own_pubkey(),
        args.relays.len()
    );

    let relay_endpoint = (!args.disable_relay).then(|| format!("{}:0", args.advertise_host));
    let nat_assist_endpoint = if args.enable_nat_assist {
        Some(
            SocketAddr::new(
                parse_advertise_ip(&args.advertise_host)?,
                args.nat_assist_port,
            )
            .to_string(),
        )
    } else {
        None
    };
    let service_runtime_state = Arc::new(Mutex::new(load_runtime_state(
        &state_file,
        service_client.own_pubkey().to_string(),
        relay_endpoint,
        nat_assist_endpoint,
    )));
    let relay_limits = RelayServiceLimits {
        max_active_sessions: args.max_active_sessions.max(1),
        max_sessions_per_requester: args.max_sessions_per_requester.max(1),
        max_bytes_per_session: args.max_bytes_per_session.max(1),
        max_forward_bps: args.max_forward_bps.filter(|value| *value > 0),
    };
    let relay_port_allocator =
        relay_port_range.map(|range| Arc::new(StdMutex::new(RelayPortAllocator::new(range))));
    spawn_state_writer(state_file, service_runtime_state.clone());
    spawn_node_record_publisher(&args)?;
    if args.enable_nat_assist {
        spawn_nat_assist_listener(bind_ip, args.nat_assist_port, service_runtime_state.clone())?;
    }

    if args.disable_relay {
        std::future::pending::<()>().await;
        return Ok(());
    }

    loop {
        let Some(message) = service_client.recv().await else {
            break;
        };
        match message.payload {
            ServicePayload::RelayAllocationRequest(request) => {
                if let Some((reason, retry_after_secs)) = service_runtime_state
                    .lock()
                    .await
                    .relay
                    .as_mut()
                    .and_then(|relay| {
                        relay.allocation_rejection_for_requester(
                            &message.sender_pubkey,
                            unix_timestamp(),
                            &relay_limits,
                        )
                    })
                {
                    send_allocation_rejection(
                        &service_client,
                        &message.sender_pubkey,
                        request.request_id.clone(),
                        request.network_id.clone(),
                        reason,
                        retry_after_secs,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to send allocation rejection to {}",
                            message.sender_pubkey
                        )
                    })?;
                    continue;
                }

                let (
                    requester_socket,
                    target_socket,
                    requester_ingress_endpoint,
                    target_ingress_endpoint,
                ) = match bind_relay_leg_pair(
                    bind_ip,
                    &args.advertise_host,
                    relay_port_allocator.as_ref(),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!(
                            "relay-service: failed to bind relay ports for allocation {}: {error}",
                            request.request_id
                        );
                        if let Err(rejection_error) = send_allocation_rejection(
                            &service_client,
                            &message.sender_pubkey,
                            request.request_id.clone(),
                            request.network_id.clone(),
                            RelayAllocationRejectReason::OverCapacity,
                            Some(30),
                        )
                        .await
                        {
                            eprintln!(
                                "relay-service: failed to send allocation rejection to {} after bind failure: {rejection_error}",
                                message.sender_pubkey
                            );
                        }
                        continue;
                    }
                };
                let state = Arc::new(Mutex::new(SessionState::default()));
                let lease_secs = args.lease_secs.max(30);
                let started_at = unix_timestamp();
                let expires_at = started_at + lease_secs;
                let expires_at_instant = Instant::now() + Duration::from_secs(lease_secs);
                let request_id = request.request_id.clone();
                let network_id = request.network_id.clone();
                let target_pubkey = request.target_pubkey.clone();
                let requester_pubkey = message.sender_pubkey.clone();

                let response = RelayAllocationGranted {
                    request_id: request_id.clone(),
                    network_id: network_id.clone(),
                    relay_pubkey: service_client.own_pubkey().to_string(),
                    requester_ingress_endpoint: requester_ingress_endpoint.clone(),
                    target_ingress_endpoint: target_ingress_endpoint.clone(),
                    expires_at,
                };
                service_client
                    .publish_to(
                        ServicePayload::RelayAllocationGranted(response),
                        &message.sender_pubkey,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to send allocation response to {}",
                            message.sender_pubkey
                        )
                    })?;

                {
                    let mut stats = service_runtime_state.lock().await;
                    stats.note_session_started(RelayOperatorSessionState {
                        request_id: request_id.clone(),
                        network_id,
                        requester_pubkey,
                        target_pubkey,
                        requester_ingress_endpoint,
                        target_ingress_endpoint,
                        started_at,
                        expires_at,
                        bytes_from_requester: 0,
                        bytes_from_target: 0,
                    });
                }

                spawn_leg(RelayLegTask {
                    rx_socket: requester_socket.clone(),
                    tx_socket: target_socket.clone(),
                    state: state.clone(),
                    service_runtime_state: service_runtime_state.clone(),
                    relay_limits: relay_limits.clone(),
                    request_id: request_id.clone(),
                    requester_leg: true,
                    expires_at: expires_at_instant,
                });
                spawn_leg(RelayLegTask {
                    rx_socket: target_socket.clone(),
                    tx_socket: requester_socket.clone(),
                    state,
                    service_runtime_state: service_runtime_state.clone(),
                    relay_limits: relay_limits.clone(),
                    request_id,
                    requester_leg: false,
                    expires_at: expires_at_instant,
                });
            }
            ServicePayload::RelayProbeRequest(request) => {
                if let Some((reason, retry_after_secs)) = service_runtime_state
                    .lock()
                    .await
                    .relay
                    .as_mut()
                    .and_then(|relay| {
                        relay.allocation_rejection_for_requester(
                            &message.sender_pubkey,
                            unix_timestamp(),
                            &relay_limits,
                        )
                    })
                {
                    send_probe_rejection(
                        &service_client,
                        &message.sender_pubkey,
                        request.request_id.clone(),
                        reason,
                        retry_after_secs,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to send probe rejection to {}",
                            message.sender_pubkey
                        )
                    })?;
                    continue;
                }

                let (
                    requester_socket,
                    target_socket,
                    requester_ingress_endpoint,
                    target_ingress_endpoint,
                ) = match bind_relay_leg_pair(
                    bind_ip,
                    &args.advertise_host,
                    relay_port_allocator.as_ref(),
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!(
                            "relay-service: failed to bind relay ports for probe {}: {error}",
                            request.request_id
                        );
                        if let Err(rejection_error) = send_probe_rejection(
                            &service_client,
                            &message.sender_pubkey,
                            request.request_id.clone(),
                            RelayAllocationRejectReason::OverCapacity,
                            Some(30),
                        )
                        .await
                        {
                            eprintln!(
                                "relay-service: failed to send probe rejection to {} after bind failure: {rejection_error}",
                                message.sender_pubkey
                            );
                        }
                        continue;
                    }
                };
                let state = Arc::new(Mutex::new(SessionState::default()));
                let lease_secs = DEFAULT_PROBE_LEASE_SECS;
                let started_at = unix_timestamp();
                let expires_at = started_at + lease_secs;
                let expires_at_instant = Instant::now() + Duration::from_secs(lease_secs);
                let request_id = request.request_id.clone();

                service_client
                    .publish_to(
                        ServicePayload::RelayProbeGranted(RelayProbeGranted {
                            request_id: request_id.clone(),
                            relay_pubkey: service_client.own_pubkey().to_string(),
                            requester_ingress_endpoint: requester_ingress_endpoint.clone(),
                            target_ingress_endpoint: target_ingress_endpoint.clone(),
                            expires_at,
                        }),
                        &message.sender_pubkey,
                    )
                    .await
                    .with_context(|| {
                        format!("failed to send probe grant to {}", message.sender_pubkey)
                    })?;

                {
                    let mut stats = service_runtime_state.lock().await;
                    stats.note_session_started(RelayOperatorSessionState {
                        request_id: request_id.clone(),
                        network_id: "__probe__".to_string(),
                        requester_pubkey: message.sender_pubkey.clone(),
                        target_pubkey: message.sender_pubkey.clone(),
                        requester_ingress_endpoint,
                        target_ingress_endpoint,
                        started_at,
                        expires_at,
                        bytes_from_requester: 0,
                        bytes_from_target: 0,
                    });
                }

                spawn_leg(RelayLegTask {
                    rx_socket: requester_socket.clone(),
                    tx_socket: target_socket.clone(),
                    state: state.clone(),
                    service_runtime_state: service_runtime_state.clone(),
                    relay_limits: relay_limits.clone(),
                    request_id: request_id.clone(),
                    requester_leg: true,
                    expires_at: expires_at_instant,
                });
                spawn_leg(RelayLegTask {
                    rx_socket: target_socket.clone(),
                    tx_socket: requester_socket.clone(),
                    state,
                    service_runtime_state: service_runtime_state.clone(),
                    relay_limits: relay_limits.clone(),
                    request_id,
                    requester_leg: false,
                    expires_at: expires_at_instant,
                });
            }
            ServicePayload::RelayAllocationGranted(_)
            | ServicePayload::RelayAllocationRejected(_)
            | ServicePayload::RelayProbeGranted(_)
            | ServicePayload::RelayProbeRejected(_) => {}
        }
    }

    service_client.disconnect().await;
    Ok(())
}

fn spawn_leg(task: RelayLegTask) {
    let RelayLegTask {
        rx_socket,
        tx_socket,
        state,
        service_runtime_state,
        relay_limits,
        request_id,
        requester_leg,
        expires_at,
    } = task;
    tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(expires_at) => return,
                recv = rx_socket.recv_from(&mut buffer) => {
                    let Ok((len, src)) = recv else {
                        return;
                    };
                    let maybe_dest = {
                        let mut state = state.lock().await;
                        if state
                            .forwarding
                            .allow_forward(&relay_limits, Instant::now(), len)
                            .is_err()
                        {
                            None
                        } else if requester_leg {
                            match state.requester.bound_addr {
                                Some(bound) if bound != src => None,
                                Some(_) => state.target.bound_addr,
                                None => {
                                    state.requester.bound_addr = Some(src);
                                    state.target.bound_addr
                                }
                            }
                        } else {
                            match state.target.bound_addr {
                                Some(bound) if bound != src => None,
                                Some(_) => state.requester.bound_addr,
                                None => {
                                    state.target.bound_addr = Some(src);
                                    state.requester.bound_addr
                                }
                            }
                        }
                    };
                    if let Some(dest) = maybe_dest
                        && let Ok(sent) = tx_socket.send_to(&buffer[..len], dest).await
                    {
                        let mut stats = service_runtime_state.lock().await;
                        stats.note_forwarded_bytes(&request_id, requester_leg, sent as u64);
                    }
                }
            }
        }
    });
}

fn spawn_state_writer(path: PathBuf, service_runtime_state: Arc<Mutex<ServiceRuntimeState>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(STATE_WRITE_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let snapshot = {
                let mut stats = service_runtime_state.lock().await;
                stats.snapshot(unix_timestamp())
            };
            if let Err(error) = write_state_file(&path, &snapshot) {
                eprintln!(
                    "relay-service: failed to write state file {}: {error}",
                    path.display()
                );
            }
        }
    });
}

fn default_state_file_path() -> PathBuf {
    dirs::config_dir()
        .map(|dir| dir.join("nvpn").join(DEFAULT_STATE_FILE_NAME))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_FILE_NAME))
}

fn write_state_file(path: &Path, state: &ServiceOperatorState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_vec_pretty(state).context("failed to serialize relay state")?;
    write_runtime_file_atomically(path, &raw)?;
    set_private_state_file_permissions(path)?;
    Ok(())
}

fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("runtime file has no parent: {}", path.display()))?;
    let temp_path = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("relay-state"),
        std::process::id(),
        unix_timestamp()
    ));
    fs::write(&temp_path, contents)
        .with_context(|| format!("failed to write temp runtime file {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn set_private_state_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set relay state file permissions on {}",
                path.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}

fn parse_advertise_ip(value: &str) -> Result<IpAddr> {
    value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid advertise host '{value}', expected an IP address"))
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        DEFAULT_LEASE_SECS, DEFAULT_MAX_ACTIVE_RELAY_SESSIONS, DEFAULT_MAX_BYTES_PER_SESSION,
        DEFAULT_MAX_SESSIONS_PER_REQUESTER, DEFAULT_NAT_ASSIST_PORT, DEFAULT_PUBLISH_INTERVAL_SECS,
        NatAssistRuntimeState, RelayPortAllocator, RelayPortRange, RelayRuntimeState,
        RelayServiceLimits, SessionForwardingState, bind_relay_leg_pair, relay_port_range,
        unix_timestamp,
    };
    use nostr_vpn_core::relay::{
        NatAssistOperatorState, RelayAllocationRejectReason, RelayOperatorSessionState,
        RelayOperatorState, ServiceOperatorState,
    };
    use tokio::time::Instant;

    fn unique_state_path() -> PathBuf {
        env::temp_dir().join(format!(
            "nvpn-relay-state-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("epoch")
                .as_nanos()
        ))
    }

    fn find_reserved_udp_range(port_count: usize) -> (u16, Vec<std::net::UdpSocket>) {
        for start in 40_000_u16..60_000_u16 {
            let end = start.saturating_add(port_count as u16).saturating_sub(1);
            if end < start {
                break;
            }
            let mut reservations = Vec::with_capacity(port_count);
            let mut all_free = true;
            for port in start..=end {
                match std::net::UdpSocket::bind(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port,
                )) {
                    Ok(socket) => reservations.push(socket),
                    Err(_) => {
                        all_free = false;
                        break;
                    }
                }
            }
            if all_free {
                return (start, reservations);
            }
        }

        panic!("failed to reserve UDP test range");
    }

    #[test]
    fn relay_runtime_state_tracks_forwarded_bytes_and_unique_peers() {
        let mut state = RelayRuntimeState {
            relay_pubkey: "relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            ..RelayRuntimeState::default()
        };
        let now = unix_timestamp();
        state.note_session_started(RelayOperatorSessionState {
            request_id: "req-1".to_string(),
            network_id: "mesh-1".to_string(),
            requester_pubkey: "requester-a".to_string(),
            target_pubkey: "target-b".to_string(),
            requester_ingress_endpoint: "198.51.100.9:40001".to_string(),
            target_ingress_endpoint: "198.51.100.9:40002".to_string(),
            started_at: now.saturating_sub(2),
            expires_at: now + 60,
            bytes_from_requester: 0,
            bytes_from_target: 0,
        });
        state.note_forwarded_bytes("req-1", true, 512);
        state.note_forwarded_bytes("req-1", false, 256);
        let snapshot = state.snapshot(now);

        assert_eq!(snapshot.total_sessions_served, 1);
        assert_eq!(snapshot.total_forwarded_bytes, 768);
        assert_eq!(snapshot.unique_peer_count, 2);
        assert_eq!(snapshot.active_sessions.len(), 1);
        assert_eq!(snapshot.active_sessions[0].bytes_from_requester, 512);
        assert_eq!(snapshot.active_sessions[0].bytes_from_target, 256);
    }

    #[test]
    fn relay_runtime_state_prunes_expired_sessions_from_active_snapshot() {
        let now = unix_timestamp();
        let mut state = RelayRuntimeState {
            relay_pubkey: "relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            active_sessions: HashMap::from([(
                "expired".to_string(),
                RelayOperatorSessionState {
                    request_id: "expired".to_string(),
                    network_id: "mesh-1".to_string(),
                    requester_pubkey: "requester-a".to_string(),
                    target_pubkey: "target-b".to_string(),
                    requester_ingress_endpoint: "198.51.100.9:40001".to_string(),
                    target_ingress_endpoint: "198.51.100.9:40002".to_string(),
                    started_at: now.saturating_sub(10),
                    expires_at: now.saturating_sub(1),
                    bytes_from_requester: 100,
                    bytes_from_target: 50,
                },
            )]),
            ..RelayRuntimeState::default()
        };

        let snapshot = state.snapshot(now);
        assert!(snapshot.active_sessions.is_empty());
    }

    #[test]
    fn relay_runtime_state_rejects_when_over_capacity() {
        let now = unix_timestamp();
        let mut state = RelayRuntimeState {
            relay_pubkey: "relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            active_sessions: HashMap::from([
                (
                    "req-1".to_string(),
                    RelayOperatorSessionState {
                        request_id: "req-1".to_string(),
                        network_id: "mesh-1".to_string(),
                        requester_pubkey: "requester-a".to_string(),
                        target_pubkey: "target-b".to_string(),
                        requester_ingress_endpoint: "198.51.100.9:40001".to_string(),
                        target_ingress_endpoint: "198.51.100.9:40002".to_string(),
                        started_at: now.saturating_sub(2),
                        expires_at: now + 60,
                        bytes_from_requester: 0,
                        bytes_from_target: 0,
                    },
                ),
                (
                    "req-2".to_string(),
                    RelayOperatorSessionState {
                        request_id: "req-2".to_string(),
                        network_id: "mesh-1".to_string(),
                        requester_pubkey: "requester-c".to_string(),
                        target_pubkey: "target-d".to_string(),
                        requester_ingress_endpoint: "198.51.100.9:40003".to_string(),
                        target_ingress_endpoint: "198.51.100.9:40004".to_string(),
                        started_at: now.saturating_sub(2),
                        expires_at: now + 60,
                        bytes_from_requester: 0,
                        bytes_from_target: 0,
                    },
                ),
            ]),
            ..RelayRuntimeState::default()
        };

        let rejection = state.allocation_rejection_for_requester(
            "requester-z",
            now,
            &RelayServiceLimits {
                max_active_sessions: 2,
                max_sessions_per_requester: 4,
                max_bytes_per_session: 1_024,
                max_forward_bps: None,
            },
        );

        assert_eq!(
            rejection,
            Some((RelayAllocationRejectReason::OverCapacity, Some(30)))
        );
    }

    #[test]
    fn relay_runtime_state_rejects_requester_when_session_cap_reached() {
        let now = unix_timestamp();
        let mut state = RelayRuntimeState {
            relay_pubkey: "relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            active_sessions: HashMap::from([(
                "req-1".to_string(),
                RelayOperatorSessionState {
                    request_id: "req-1".to_string(),
                    network_id: "mesh-1".to_string(),
                    requester_pubkey: "requester-a".to_string(),
                    target_pubkey: "target-b".to_string(),
                    requester_ingress_endpoint: "198.51.100.9:40001".to_string(),
                    target_ingress_endpoint: "198.51.100.9:40002".to_string(),
                    started_at: now.saturating_sub(2),
                    expires_at: now + 60,
                    bytes_from_requester: 0,
                    bytes_from_target: 0,
                },
            )]),
            ..RelayRuntimeState::default()
        };

        let rejection = state.allocation_rejection_for_requester(
            "requester-a",
            now,
            &RelayServiceLimits {
                max_active_sessions: 8,
                max_sessions_per_requester: 1,
                max_bytes_per_session: 1_024,
                max_forward_bps: None,
            },
        );

        assert_eq!(
            rejection,
            Some((
                RelayAllocationRejectReason::TooManySessionsForRequester,
                Some(60)
            ))
        );
    }

    #[test]
    fn runtime_state_seeded_from_snapshot_keeps_cumulative_totals() {
        let now = unix_timestamp();
        let snapshot = RelayOperatorState {
            updated_at: now.saturating_sub(10),
            relay_pubkey: "old-relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            total_sessions_served: 4,
            total_forwarded_bytes: 8_192,
            current_forward_bps: 321,
            unique_peer_count: 3,
            known_peer_pubkeys: vec![
                "requester-a".to_string(),
                "target-b".to_string(),
                "target-c".to_string(),
            ],
            active_sessions: vec![RelayOperatorSessionState {
                request_id: "stale".to_string(),
                network_id: "mesh-1".to_string(),
                requester_pubkey: "requester-a".to_string(),
                target_pubkey: "target-b".to_string(),
                requester_ingress_endpoint: "198.51.100.9:40001".to_string(),
                target_ingress_endpoint: "198.51.100.9:40002".to_string(),
                started_at: now.saturating_sub(5),
                expires_at: now + 60,
                bytes_from_requester: 3_000,
                bytes_from_target: 2_000,
            }],
        };

        let state = super::relay_runtime_state_from_snapshot(
            snapshot,
            "relay-now".to_string(),
            "203.0.113.7:0".to_string(),
            now,
        );

        assert_eq!(state.relay_pubkey, "relay-now");
        assert_eq!(state.advertised_endpoint, "203.0.113.7:0");
        assert_eq!(state.total_sessions_served, 4);
        assert_eq!(state.total_forwarded_bytes, 8_192);
        assert_eq!(state.last_rate_sample_bytes, 8_192);
        assert_eq!(state.current_forward_bps, 0);
        assert_eq!(state.known_peer_pubkeys.len(), 3);
        assert!(state.active_sessions.is_empty());
    }

    #[test]
    fn nat_assist_runtime_state_tracks_requests_and_unique_clients() {
        let mut state = NatAssistRuntimeState {
            advertised_endpoint: "198.51.100.9:3478".to_string(),
            ..NatAssistRuntimeState::default()
        };
        let now = unix_timestamp();
        state.note_discovery_request(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, 10),
            50000,
        )));
        state.note_punch_request(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, 10),
            50001,
        )));
        state.note_discovery_request(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, 11),
            50002,
        )));

        let snapshot = state.snapshot(now);

        assert_eq!(snapshot.total_discovery_requests, 2);
        assert_eq!(snapshot.total_punch_requests, 1);
        assert_eq!(snapshot.unique_client_count, 2);
        assert_eq!(snapshot.advertised_endpoint, "198.51.100.9:3478");
    }

    #[test]
    fn session_forwarding_state_enforces_byte_cap() {
        let mut state = SessionForwardingState::default();
        let limits = RelayServiceLimits {
            max_active_sessions: 8,
            max_sessions_per_requester: 2,
            max_bytes_per_session: 512,
            max_forward_bps: None,
        };
        let now = Instant::now();

        assert!(state.allow_forward(&limits, now, 256).is_ok());
        assert!(state.allow_forward(&limits, now, 256).is_ok());
        assert_eq!(
            state.allow_forward(&limits, now, 1),
            Err(RelayAllocationRejectReason::ByteLimitExceeded)
        );
    }

    #[test]
    fn session_forwarding_state_enforces_rate_limit() {
        let mut state = SessionForwardingState::default();
        let limits = RelayServiceLimits {
            max_active_sessions: 8,
            max_sessions_per_requester: 2,
            max_bytes_per_session: 4_096,
            max_forward_bps: Some(512),
        };
        let now = Instant::now();

        assert!(state.allow_forward(&limits, now, 512).is_ok());
        assert_eq!(
            state.allow_forward(&limits, now, 1),
            Err(RelayAllocationRejectReason::RateLimited)
        );
        assert!(
            state
                .allow_forward(&limits, now + Duration::from_secs(1), 256)
                .is_ok()
        );
    }

    #[test]
    fn relay_port_range_requires_both_bounds() {
        let args = super::Args {
            secret_key: "00".repeat(32),
            relays: vec!["wss://temp.iris.to".to_string()],
            bind_ip: "0.0.0.0".to_string(),
            advertise_host: "203.0.113.7".to_string(),
            disable_relay: false,
            enable_nat_assist: false,
            nat_assist_port: DEFAULT_NAT_ASSIST_PORT,
            lease_secs: DEFAULT_LEASE_SECS,
            relay_port_range_start: Some(12_000),
            relay_port_range_end: None,
            publish_interval_secs: DEFAULT_PUBLISH_INTERVAL_SECS,
            max_active_sessions: DEFAULT_MAX_ACTIVE_RELAY_SESSIONS,
            max_sessions_per_requester: DEFAULT_MAX_SESSIONS_PER_REQUESTER,
            max_bytes_per_session: DEFAULT_MAX_BYTES_PER_SESSION,
            max_forward_bps: None,
            price_hint_msats: None,
            state_file: None,
        };

        let error = relay_port_range(&args).expect_err("missing range end should fail");
        assert!(error.to_string().contains(
            "both --relay-port-range-start and --relay-port-range-end are required together"
        ));
    }

    #[test]
    fn relay_port_range_rejects_nat_assist_overlap() {
        let args = super::Args {
            secret_key: "00".repeat(32),
            relays: vec!["wss://temp.iris.to".to_string()],
            bind_ip: "0.0.0.0".to_string(),
            advertise_host: "203.0.113.7".to_string(),
            disable_relay: false,
            enable_nat_assist: true,
            nat_assist_port: 12_000,
            lease_secs: DEFAULT_LEASE_SECS,
            relay_port_range_start: Some(12_000),
            relay_port_range_end: Some(12_127),
            publish_interval_secs: DEFAULT_PUBLISH_INTERVAL_SECS,
            max_active_sessions: 32,
            max_sessions_per_requester: DEFAULT_MAX_SESSIONS_PER_REQUESTER,
            max_bytes_per_session: DEFAULT_MAX_BYTES_PER_SESSION,
            max_forward_bps: None,
            price_hint_msats: None,
            state_file: None,
        };

        let error = relay_port_range(&args).expect_err("overlapping nat assist should fail");
        assert!(
            error
                .to_string()
                .contains("nat assist port 12000 overlaps relay port range 12000-12127")
        );
    }

    #[tokio::test]
    async fn relay_port_allocator_skips_busy_ports() {
        let (start, mut reservations) = find_reserved_udp_range(4);
        let busy_socket = reservations.remove(0);
        drop(reservations);

        let range = RelayPortRange::new(start, start + 3).expect("range");
        let mut allocator = RelayPortAllocator::new(range);
        let (_, _, requester_endpoint, target_endpoint) = allocator
            .bind_pair(IpAddr::V4(Ipv4Addr::LOCALHOST), "127.0.0.1")
            .expect("bind relay pair");

        let requester_port = requester_endpoint
            .rsplit(':')
            .next()
            .expect("requester port")
            .parse::<u16>()
            .expect("requester port number");
        let target_port = target_endpoint
            .rsplit(':')
            .next()
            .expect("target port")
            .parse::<u16>()
            .expect("target port number");

        assert_ne!(requester_port, start);
        assert_ne!(target_port, start);
        assert_ne!(requester_port, target_port);

        drop(busy_socket);
    }

    #[test]
    fn relay_port_allocator_rejects_exhausted_range() {
        let (start, reservations) = find_reserved_udp_range(2);
        let range = RelayPortRange::new(start, start + 1).expect("range");
        let mut allocator = RelayPortAllocator::new(range);

        let error = allocator
            .bind_pair(IpAddr::V4(Ipv4Addr::LOCALHOST), "127.0.0.1")
            .expect_err("fully reserved range should fail");
        assert!(error.to_string().contains(&format!(
            "no free relay port pair available in configured range {start}-{}",
            start + 1
        )));

        drop(reservations);
    }

    #[tokio::test]
    async fn bind_relay_leg_pair_uses_configured_range() {
        let (start, reservations) = find_reserved_udp_range(4);
        drop(reservations);

        let allocator = Arc::new(std::sync::Mutex::new(RelayPortAllocator::new(
            RelayPortRange::new(start, start + 3).expect("range"),
        )));

        let (_, _, requester_endpoint, target_endpoint) = bind_relay_leg_pair(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
            Some(&allocator),
        )
        .expect("bind relay pair");

        let requester_port = requester_endpoint
            .rsplit(':')
            .next()
            .expect("requester port")
            .parse::<u16>()
            .expect("requester port number");
        let target_port = target_endpoint
            .rsplit(':')
            .next()
            .expect("target port")
            .parse::<u16>()
            .expect("target port number");

        assert!((start..=start + 3).contains(&requester_port));
        assert!((start..=start + 3).contains(&target_port));
        assert_ne!(requester_port, target_port);
    }

    #[test]
    fn load_runtime_state_upgrades_legacy_relay_snapshot() {
        let now = unix_timestamp();
        let path = unique_state_path();
        let legacy = RelayOperatorState {
            updated_at: now.saturating_sub(10),
            relay_pubkey: "old-relay".to_string(),
            advertised_endpoint: "198.51.100.9:0".to_string(),
            total_sessions_served: 4,
            total_forwarded_bytes: 8_192,
            current_forward_bps: 0,
            unique_peer_count: 2,
            known_peer_pubkeys: vec!["requester-a".to_string(), "target-b".to_string()],
            active_sessions: Vec::new(),
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&legacy).expect("serialize legacy state"),
        )
        .expect("write state");

        let state = super::load_runtime_state(
            &path,
            "relay-now".to_string(),
            Some("203.0.113.7:0".to_string()),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 3478).to_string()),
        );

        assert_eq!(state.operator_pubkey, "relay-now");
        assert_eq!(
            state.relay.as_ref().expect("relay").total_sessions_served,
            4
        );
        assert_eq!(
            state.relay.as_ref().expect("relay").advertised_endpoint,
            "203.0.113.7:0"
        );
        assert_eq!(
            state
                .nat_assist
                .as_ref()
                .expect("nat assist")
                .advertised_endpoint,
            "203.0.113.7:3478"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_runtime_state_restores_service_snapshot() {
        let now = unix_timestamp();
        let path = unique_state_path();
        let snapshot = ServiceOperatorState {
            updated_at: now.saturating_sub(10),
            operator_pubkey: "service".to_string(),
            relay: Some(RelayOperatorState {
                updated_at: now.saturating_sub(10),
                relay_pubkey: "service".to_string(),
                advertised_endpoint: "198.51.100.9:0".to_string(),
                total_sessions_served: 4,
                total_forwarded_bytes: 8_192,
                current_forward_bps: 0,
                unique_peer_count: 2,
                known_peer_pubkeys: vec!["requester-a".to_string(), "target-b".to_string()],
                active_sessions: Vec::new(),
            }),
            nat_assist: Some(NatAssistOperatorState {
                updated_at: now.saturating_sub(10),
                advertised_endpoint: "198.51.100.9:3478".to_string(),
                total_discovery_requests: 7,
                total_punch_requests: 3,
                current_request_bps: 0,
                unique_client_count: 2,
            }),
        };
        std::fs::write(
            &path,
            serde_json::to_vec(&snapshot).expect("serialize service state"),
        )
        .expect("write state");

        let state = super::load_runtime_state(
            &path,
            "service-now".to_string(),
            Some("203.0.113.7:0".to_string()),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 3478).to_string()),
        );

        assert_eq!(state.operator_pubkey, "service-now");
        assert_eq!(
            state.relay.as_ref().expect("relay").total_sessions_served,
            4
        );
        assert_eq!(
            state
                .nat_assist
                .as_ref()
                .expect("nat assist")
                .total_discovery_requests,
            7
        );
        assert_eq!(
            state
                .nat_assist
                .as_ref()
                .expect("nat assist")
                .total_punch_requests,
            3
        );
        let _ = fs::remove_file(path);
    }
}
