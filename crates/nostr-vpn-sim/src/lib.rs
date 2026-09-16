use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use fips_core::config::{IdentityConfig, PeerConfig, RoutingMode, TransportInstances};
use fips_core::{
    Config, FipsEndpoint, Identity, PeerIdentity, SimLink, SimNetwork, SimNetworkStats,
    SimTransportConfig, register_sim_network, unregister_sim_network,
};
use nostr_pubsub_fips::FIPS_NOSTR_PUBSUB_SERVICE_PORT;
use nostr_sdk::prelude::{Event, Keys, Kind, Timestamp};
use nostr_social_graph::RatingGraphConfig;
use nostr_social_memory::rating_from_event;
use nostr_vpn_core::config::{NostrPubsubConfig, NostrPubsubMode};
use nostr_vpn_core::control_pubsub::RATING_FACT_KIND;
use nostr_vpn_core::paid_routes::{PaidExitConfig, signed_paid_exit_offer_from_config};
use nvpn::control_pubsub_runtime::ControlPubsubFipsRuntime;
use serde::{Deserialize, Serialize};

mod reputation;
use reputation::{
    PEER_RATING_SCOPE, ReputationSeedReport, ReputationSetup, SharedMeshPeerPolicy,
    SharedReputationGraph, build_reputation_policies, canonical_rating_event,
};

const DEFAULT_SEED: u64 = 0x4e56_504e_5055_4253;
const DEFAULT_HONEST_RATIO_PERCENT: usize = 80;
const DEFAULT_MALFORMED_PUBSUB_DATAGRAMS_PER_ATTACKER: usize = 8;
const DELIVERY_POLL_INTERVAL: Duration = Duration::from_millis(50);

static NETWORK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationConfig {
    pub node_count: usize,
    pub attacker_count: usize,
    pub malformed_pubsub_datagrams_per_attacker: usize,
    pub convergence_timeout_ms: u64,
    pub delivery_timeout_ms: u64,
    pub seed: u64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        let node_count = 100;
        Self {
            node_count,
            attacker_count: node_count * (100 - DEFAULT_HONEST_RATIO_PERCENT) / 100,
            malformed_pubsub_datagrams_per_attacker:
                DEFAULT_MALFORMED_PUBSUB_DATAGRAMS_PER_ATTACKER,
            convergence_timeout_ms: 15_000,
            delivery_timeout_ms: 15_000,
            seed: DEFAULT_SEED,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationReport {
    pub node_count: usize,
    pub honest_node_count: usize,
    pub attacker_count: usize,
    pub connected_node_count: usize,
    pub baseline_honest_deliveries: usize,
    pub exit_rating_honest_deliveries: usize,
    pub baseline_delivery_basis_points: u32,
    pub post_attack_honest_deliveries: usize,
    pub post_attack_delivery_basis_points: u32,
    pub malformed_pubsub_datagrams_attempted: usize,
    pub malformed_pubsub_datagrams_sent: usize,
    pub rating_spam_published: usize,
    pub rating_spam_stored_by_honest_nodes: usize,
    pub trusted_positive_ratings_applied: usize,
    pub trusted_negative_ratings_applied: usize,
    pub untrusted_ratings_ignored: usize,
    pub received_untrusted_ratings_ignored: usize,
    pub unknown_honest_peer_links: usize,
    pub unknown_attacker_peer_links: usize,
    pub max_events_stored_per_node: usize,
    pub total_events_stored: usize,
    pub attack_network: SimNetworkStats,
}

#[derive(Clone)]
struct NodeSpec {
    secret_hex: String,
    npub: String,
    peer_identity: PeerIdentity,
    sim_addr: String,
    neighbors: Vec<usize>,
}

struct SimulationRuntime {
    config: SimulationConfig,
    network_id: String,
    network: SimNetwork,
    specs: Vec<NodeSpec>,
    keys: Vec<Keys>,
    endpoints: Vec<Arc<FipsEndpoint>>,
    pubsub: Vec<ControlPubsubFipsRuntime>,
    reputation_graphs: Vec<Option<SharedReputationGraph>>,
    reputation_seed: ReputationSeedReport,
}

pub async fn run_simulation(config: SimulationConfig) -> Result<SimulationReport> {
    validate_config(&config)?;
    let mut runtime = Box::pin(SimulationRuntime::start(config)).await?;
    let result = runtime.run_scenario().await;
    let shutdown = runtime.shutdown().await;
    match (result, shutdown) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

impl SimulationRuntime {
    async fn start(config: SimulationConfig) -> Result<Self> {
        let sequence = NETWORK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let network_id = format!("nvpn-pubsub-sim-{}-{sequence}", std::process::id());
        let specs = node_specs(&config);
        let keys = specs
            .iter()
            .map(|spec| Keys::parse(&spec.secret_hex).expect("deterministic key parses"))
            .collect::<Vec<_>>();
        let ReputationSetup {
            policies: peer_policies,
            graphs: reputation_graphs,
            report: reputation_seed,
        } = build_reputation_policies(&config, &specs, &keys)?;
        let network = simulation_network(config.seed, &specs);
        register_sim_network(network_id.clone(), network.clone());
        let endpoints = start_sim_endpoints(&config, &network_id, &specs).await?;
        let pubsub = start_pubsub_runtimes(&network_id, &endpoints, &peer_policies).await?;
        let connected_pubsub_node_count = match wait_for_pubsub_connections(
            &pubsub,
            Duration::from_millis(config.convergence_timeout_ms),
        )
        .await
        {
            Ok(count) => count,
            Err(error) => {
                shutdown_partial(pubsub, &endpoints, &network_id).await;
                return Err(error).context("failed to query standard FIPS pubsub readiness");
            }
        };
        if connected_pubsub_node_count < config.node_count {
            shutdown_partial(pubsub, &endpoints, &network_id).await;
            bail!(
                "only {connected_pubsub_node_count}/{} nodes fully subscribed over standard FIPS pubsub",
                config.node_count
            );
        }

        Ok(Self {
            config,
            network_id,
            network,
            specs,
            keys,
            endpoints,
            pubsub,
            reputation_graphs,
            reputation_seed,
        })
    }

    async fn run_scenario(&mut self) -> Result<SimulationReport> {
        let honest_node_count = self.config.node_count - self.config.attacker_count;
        let baseline = signed_live_paid_offer(&self.keys[0], "simulation-baseline");
        if !self.pubsub[0].publish(baseline.clone()).await? {
            bail!("baseline publisher had no connected pubsub peer");
        }
        let baseline_honest_deliveries = self
            .wait_for_honest_delivery(&baseline, honest_node_count)
            .await;

        let before_attack = self.network.stats();
        let (malformed_pubsub_datagrams_attempted, malformed_pubsub_datagrams_sent) =
            self.inject_malformed_pubsub_datagrams().await?;
        let rating_spam_published = self.publish_rating_spam().await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let rating_spam_stored_by_honest_nodes =
            self.honest_rating_event_count(honest_node_count).await;
        let received_untrusted_ratings_ignored =
            self.apply_received_ratings(honest_node_count).await?;
        let post_attack = signed_live_paid_offer(&self.keys[1], "simulation-post-attack");
        if !self.pubsub[1].publish(post_attack.clone()).await? {
            bail!("post-attack publisher had no connected pubsub peer");
        }
        let post_attack_honest_deliveries = self
            .wait_for_honest_delivery(&post_attack, honest_node_count)
            .await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        let exit_rating_honest_deliveries =
            self.verify_exit_rating_delivery(honest_node_count).await?;
        let mut total_events_stored = 0usize;
        let mut max_events_stored_per_node = 0usize;
        for runtime in &self.pubsub {
            let count = runtime.events().await.len();
            total_events_stored = total_events_stored.saturating_add(count);
            max_events_stored_per_node = max_events_stored_per_node.max(count);
        }

        Ok(SimulationReport {
            node_count: self.config.node_count,
            honest_node_count,
            attacker_count: self.config.attacker_count,
            connected_node_count: self.config.node_count,
            baseline_honest_deliveries,
            exit_rating_honest_deliveries,
            baseline_delivery_basis_points: basis_points(
                baseline_honest_deliveries,
                honest_node_count,
            ),
            post_attack_honest_deliveries,
            post_attack_delivery_basis_points: basis_points(
                post_attack_honest_deliveries,
                honest_node_count,
            ),
            malformed_pubsub_datagrams_attempted,
            malformed_pubsub_datagrams_sent,
            rating_spam_published,
            rating_spam_stored_by_honest_nodes,
            trusted_positive_ratings_applied: self.reputation_seed.trusted_positive_ratings_applied,
            trusted_negative_ratings_applied: self.reputation_seed.trusted_negative_ratings_applied,
            untrusted_ratings_ignored: self
                .reputation_seed
                .untrusted_ratings_ignored
                .saturating_add(received_untrusted_ratings_ignored),
            received_untrusted_ratings_ignored,
            unknown_honest_peer_links: self.reputation_seed.unknown_honest_peer_links,
            unknown_attacker_peer_links: self.reputation_seed.unknown_attacker_peer_links,
            max_events_stored_per_node,
            total_events_stored,
            attack_network: self.network.stats().delta_since(&before_attack),
        })
    }

    async fn wait_for_honest_delivery(&self, event: &Event, honest_count: usize) -> usize {
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.delivery_timeout_ms);
        let mut best = 0usize;
        loop {
            let mut delivered = 0usize;
            for runtime in self.pubsub.iter().take(honest_count) {
                if runtime
                    .events()
                    .await
                    .iter()
                    .any(|stored| stored.id == event.id)
                {
                    delivered += 1;
                }
            }
            best = best.max(delivered);
            if delivered == honest_count || tokio::time::Instant::now() >= deadline {
                return best;
            }
            tokio::time::sleep(DELIVERY_POLL_INTERVAL).await;
        }
    }

    async fn honest_rating_event_count(&self, honest_count: usize) -> usize {
        let mut count = 0usize;
        for runtime in self.pubsub.iter().take(honest_count) {
            count = count.saturating_add(
                runtime
                    .events()
                    .await
                    .iter()
                    .filter(|event| event.kind == Kind::Custom(RATING_FACT_KIND))
                    .count(),
            );
        }
        count
    }

    async fn apply_received_ratings(&self, honest_count: usize) -> Result<usize> {
        let config = RatingGraphConfig::for_scopes([PEER_RATING_SCOPE]);
        let mut ignored = 0usize;
        for (index, runtime) in self.pubsub.iter().take(honest_count).enumerate() {
            let ratings = runtime
                .events()
                .await
                .iter()
                .filter(|event| event.kind == Kind::Custom(RATING_FACT_KIND))
                .filter_map(|event| rating_from_event(event).ok())
                .collect::<Vec<_>>();
            let Some(graph) = self.reputation_graphs[index].as_ref() else {
                continue;
            };
            let projection = graph
                .write()
                .map_err(|_| anyhow::anyhow!("simulation reputation graph lock poisoned"))?
                .apply_ratings(&ratings, &config)?;
            ignored = ignored.saturating_add(projection.ignored_ratings);
        }
        Ok(ignored)
    }

    async fn inject_malformed_pubsub_datagrams(&self) -> Result<(usize, usize)> {
        let honest_count = self.config.node_count - self.config.attacker_count;
        let mut attempted = 0usize;
        let mut sent = 0usize;
        for attacker in honest_count..self.config.node_count {
            let targets = self.specs[attacker]
                .neighbors
                .iter()
                .copied()
                .filter(|target| *target < honest_count)
                .collect::<Vec<_>>();
            for sequence in 0..self.config.malformed_pubsub_datagrams_per_attacker {
                for target in &targets {
                    attempted += 1;
                    // This deliberately bypasses the reliable stream carrier.
                    // A short FSP payload can never be a complete TCP/FIPS
                    // segment, so it exercises bounded malformed-input
                    // isolation without claiming to be a valid inventory.
                    let payload = (attacker as u64)
                        .to_be_bytes()
                        .into_iter()
                        .chain((sequence as u64).to_be_bytes())
                        .collect();
                    if self.endpoints[attacker]
                        .send_datagram(
                            self.specs[*target].peer_identity,
                            FIPS_NOSTR_PUBSUB_SERVICE_PORT,
                            FIPS_NOSTR_PUBSUB_SERVICE_PORT,
                            payload,
                        )
                        .await
                        .is_ok()
                    {
                        sent += 1;
                    }
                }
            }
        }
        Ok((attempted, sent))
    }

    async fn verify_exit_rating_delivery(&self, honest_count: usize) -> Result<usize> {
        use nostr_sdk::ToBech32;
        use nostr_vpn_core::paid_route_ratings::{
            exit_rating_event, exit_rating_scores, trust_exit_rating_authors,
        };
        let now = Timestamp::now().as_secs();
        let seller = self.keys[2].public_key().to_bech32()?;
        let mut local = nostr_vpn_core::paid_route_store::PaidRouteStore::default();
        local.record_exit_rating(&self.keys[0], &seller, 80, false, now)?;
        let event = local
            .pending_exit_ratings()
            .pop()
            .context("pending automatic rating")?;
        self.pubsub[0].publish(event.clone()).await?;
        let delivered = self.wait_for_honest_delivery(&event, honest_count).await;
        if delivered * 10 < honest_count * 8 {
            bail!("automatic exit rating did not reach honest peers");
        }
        for attacker in honest_count..self.keys.len() {
            let spam = exit_rating_event(&self.keys[attacker], &seller, -100, true, now)?;
            self.pubsub[attacker].publish(spam).await?;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        for index in 1..honest_count {
            let events = self.pubsub[index].events().await;
            if !events.iter().any(|stored| stored.id == event.id) {
                continue;
            }
            let mut graph =
                nostr_social_graph::SocialGraph::new(&self.keys[index].public_key().to_hex());
            trust_exit_rating_authors(&mut graph, &[self.keys[0].public_key().to_hex()])?;
            let scores = exit_rating_scores(&events, &graph, now);
            let score = scores
                .get(&seller)
                .context("received automatic exit rating")?;
            if score.score != 80 || score.authors != 1 {
                bail!("untrusted exit ratings changed reputation");
            }
            let fact = rating_from_event(&event)?;
            if !fact.evidence.is_empty() || fact.window_start.is_some() {
                bail!("measurement leaked into rating");
            }
        }
        Ok(delivered)
    }

    async fn publish_rating_spam(&self) -> Result<usize> {
        let honest_count = self.config.node_count - self.config.attacker_count;
        let mut published = 0usize;
        for attacker in honest_count..self.config.node_count {
            let attacker_pubkey = self.keys[attacker].public_key().to_hex();
            let event = canonical_rating_event(
                &self.keys[attacker],
                &attacker_pubkey,
                &attacker_pubkey,
                100,
                100 + attacker as u64,
                "sybil self-praise",
            )?;
            if self.pubsub[attacker].publish(event).await? {
                published += 1;
            }
        }
        Ok(published)
    }

    async fn shutdown(&mut self) -> Result<()> {
        while let Some(runtime) = self.pubsub.pop() {
            runtime.stop().await;
        }
        let mut shutdown_error = None;
        for endpoint in &self.endpoints {
            if let Err(error) = endpoint.shutdown().await {
                shutdown_error = Some(error);
            }
        }
        unregister_sim_network(&self.network_id);
        if let Some(error) = shutdown_error {
            return Err(error).context("failed to shut down simulated FIPS endpoint");
        }
        Ok(())
    }
}

fn simulation_network(seed: u64, specs: &[NodeSpec]) -> SimNetwork {
    let network = SimNetwork::new(seed);
    for (index, spec) in specs.iter().enumerate() {
        for neighbor in &spec.neighbors {
            if index < *neighbor {
                network.set_link(
                    spec.sim_addr.clone(),
                    specs[*neighbor].sim_addr.clone(),
                    SimLink::default(),
                );
            }
        }
    }
    network
}

async fn start_sim_endpoints(
    config: &SimulationConfig,
    network_id: &str,
    specs: &[NodeSpec],
) -> Result<Vec<Arc<FipsEndpoint>>> {
    let mut endpoints = Vec::with_capacity(config.node_count);
    for (index, spec) in specs.iter().enumerate() {
        let endpoint = Box::pin(
            FipsEndpoint::builder()
                .config(endpoint_config(config, network_id, specs, index))
                .identity_nsec(spec.secret_hex.clone())
                .without_system_tun()
                .packet_channel_capacity(8_192)
                .bind(),
        )
        .await;
        match endpoint {
            Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
            Err(error) => {
                shutdown_partial(Vec::new(), &endpoints, network_id).await;
                return Err(error).context("failed to start simulated FIPS endpoint");
            }
        }
    }

    let connected_node_count = wait_for_connections(
        &endpoints,
        specs,
        Duration::from_millis(config.convergence_timeout_ms),
    )
    .await;
    if connected_node_count < config.node_count {
        shutdown_partial(Vec::new(), &endpoints, network_id).await;
        bail!(
            "only {connected_node_count}/{} FIPS nodes reached their configured peer count",
            config.node_count
        );
    }
    Ok(endpoints)
}

async fn start_pubsub_runtimes(
    network_id: &str,
    endpoints: &[Arc<FipsEndpoint>],
    peer_policies: &[Option<SharedMeshPeerPolicy>],
) -> Result<Vec<ControlPubsubFipsRuntime>> {
    let pubsub_config = NostrPubsubConfig {
        mode: NostrPubsubMode::Client,
        fanout: 8,
        max_hops: 10,
        max_event_bytes: 56 * 1024,
    };
    let mut pubsub = Vec::with_capacity(endpoints.len());
    for (index, endpoint) in endpoints.iter().enumerate() {
        let runtime = match peer_policies[index].as_ref() {
            Some(peer_policy) => {
                ControlPubsubFipsRuntime::start_with_peer_policy(
                    Arc::clone(endpoint),
                    pubsub_config.clone(),
                    Vec::new(),
                    None,
                    Arc::clone(peer_policy),
                )
                .await
            }
            None => {
                ControlPubsubFipsRuntime::start(
                    Arc::clone(endpoint),
                    pubsub_config.clone(),
                    Vec::new(),
                    None,
                )
                .await
            }
        };
        match runtime {
            Ok(Some(runtime)) => pubsub.push(runtime),
            Ok(None) => {
                shutdown_partial(pubsub, endpoints, network_id).await;
                bail!("control pubsub unexpectedly disabled");
            }
            Err(error) => {
                shutdown_partial(pubsub, endpoints, network_id).await;
                return Err(error).context("failed to start Nostr VPN pubsub runtime");
            }
        }
    }
    Ok(pubsub)
}

async fn shutdown_partial(
    mut pubsub: Vec<ControlPubsubFipsRuntime>,
    endpoints: &[Arc<FipsEndpoint>],
    network_id: &str,
) {
    while let Some(runtime) = pubsub.pop() {
        runtime.stop().await;
    }
    for endpoint in endpoints {
        let _ = endpoint.shutdown().await;
    }
    unregister_sim_network(network_id);
}

fn validate_config(config: &SimulationConfig) -> Result<()> {
    if config.node_count < 4 {
        bail!("node_count must be at least 4");
    }
    if config.attacker_count == 0 || config.attacker_count >= config.node_count - 1 {
        bail!("attacker_count must leave at least two honest nodes");
    }
    if config.malformed_pubsub_datagrams_per_attacker == 0 {
        bail!("malformed_pubsub_datagrams_per_attacker must be non-zero");
    }
    Ok(())
}

fn node_specs(config: &SimulationConfig) -> Vec<NodeSpec> {
    let adjacency = adjacency(config.node_count);
    (0..config.node_count)
        .map(|index| {
            let secret_bytes = deterministic_secret(config.seed, index);
            let identity = Identity::from_secret_bytes(&secret_bytes)
                .expect("deterministic simulation identity is valid");
            NodeSpec {
                secret_hex: hex::encode(secret_bytes),
                npub: identity.npub(),
                peer_identity: PeerIdentity::from_pubkey_full(identity.pubkey_full()),
                sim_addr: format!("nvpn-node-{index}"),
                neighbors: adjacency[index].iter().copied().collect(),
            }
        })
        .collect()
}

fn adjacency(node_count: usize) -> Vec<BTreeSet<usize>> {
    let mut adjacency = vec![BTreeSet::new(); node_count];
    for index in 0..node_count {
        for offset in [1, 7, 31] {
            let offset = offset % node_count;
            if offset == 0 {
                continue;
            }
            let forward = (index + offset) % node_count;
            let backward = (index + node_count - offset) % node_count;
            if forward != index {
                adjacency[index].insert(forward);
                adjacency[forward].insert(index);
            }
            if backward != index {
                adjacency[index].insert(backward);
                adjacency[backward].insert(index);
            }
        }
    }
    adjacency
}

fn endpoint_config(
    simulation: &SimulationConfig,
    network_id: &str,
    specs: &[NodeSpec],
    node_index: usize,
) -> Config {
    let spec = &specs[node_index];
    let mut config = Config::new();
    config.node.identity = IdentityConfig {
        nsec: Some(spec.secret_hex.clone()),
        persistent: false,
    };
    config.node.limits.max_connections = simulation.node_count + 32;
    config.node.limits.max_peers = simulation.node_count + 32;
    config.node.limits.max_links = simulation.node_count + 32;
    config.node.limits.max_pending_inbound = simulation.node_count * 16;
    config.node.rate_limit.handshake_burst = 10_000;
    config.node.rate_limit.handshake_rate = 10_000.0;
    config.node.rate_limit.handshake_timeout_secs = 8;
    config.node.rate_limit.handshake_resend_interval_ms = 100;
    config.node.rate_limit.handshake_max_resends = 20;
    config.node.retry.base_interval_secs = 1;
    config.node.retry.max_retries = 20;
    config.node.retry.max_backoff_secs = 4;
    config.node.discovery.attempt_timeouts_secs = vec![1, 1, 2];
    config.node.discovery.forward_min_interval_secs = 0;
    config.node.tree.announce_min_interval_ms = 25;
    config.node.tree.parent_hysteresis = 0.0;
    config.node.tree.hold_down_secs = 0;
    config.node.tree.reeval_interval_secs = 1;
    config.node.routing.mode = RoutingMode::Tree;
    config.node.heartbeat_interval_secs = 1;
    config.node.link_dead_timeout_secs = 4;
    config.node.system_files_enabled = false;
    config.tun.enabled = false;
    config.dns.enabled = false;
    config.transports.sim = TransportInstances::Single(SimTransportConfig {
        network: Some(network_id.to_string()),
        addr: Some(spec.sim_addr.clone()),
        mtu: Some(1_280),
        auto_connect: Some(false),
        accept_connections: Some(true),
    });
    config.peers = spec
        .neighbors
        .iter()
        .map(|neighbor| {
            PeerConfig::new(
                specs[*neighbor].npub.clone(),
                "sim",
                specs[*neighbor].sim_addr.clone(),
            )
            .with_alias(format!("node-{neighbor}"))
        })
        .collect();
    config
}

async fn wait_for_connections(
    endpoints: &[Arc<FipsEndpoint>],
    specs: &[NodeSpec],
    timeout: Duration,
) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut best = 0usize;
    loop {
        let mut connected = 0usize;
        for (endpoint, spec) in endpoints.iter().zip(specs) {
            let peer_count = endpoint
                .peers()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|peer| peer.connected)
                .count();
            if peer_count >= spec.neighbors.len() {
                connected += 1;
            }
        }
        best = best.max(connected);
        if connected == endpoints.len() || tokio::time::Instant::now() >= deadline {
            return best;
        }
        tokio::time::sleep(DELIVERY_POLL_INTERVAL).await;
    }
}

async fn wait_for_pubsub_connections(
    runtimes: &[ControlPubsubFipsRuntime],
    timeout: Duration,
) -> Result<usize> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut best = 0usize;
    loop {
        let mut connected = 0usize;
        for runtime in runtimes {
            let peer_count = runtime.connected_peer_count().await?;
            if peer_count > 0 && runtime.peer_subscription_count().await? >= peer_count {
                connected += 1;
            }
        }
        best = best.max(connected);
        if connected == runtimes.len() || tokio::time::Instant::now() >= deadline {
            return Ok(best);
        }
        tokio::time::sleep(DELIVERY_POLL_INTERVAL).await;
    }
}

fn deterministic_secret(seed: u64, index: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[16..24].copy_from_slice(&seed.to_be_bytes());
    bytes[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    bytes
}

fn signed_live_paid_offer(keys: &Keys, offer_id: &str) -> Event {
    let config = PaidExitConfig {
        enabled: true,
        ..PaidExitConfig::default()
    };
    signed_paid_exit_offer_from_config(offer_id, keys, &config, None, Timestamp::now().as_secs())
        .expect("simulation paid-exit offer signs")
        .event
}

fn basis_points(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(numerator.saturating_mul(10_000) / denominator).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simulation_test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_stack_size(8 * 1024 * 1024)
            .enable_all()
            .build()
            .expect("simulation test runtime")
    }

    #[test]
    fn twelve_instance_full_path_smoke() {
        let report = simulation_test_runtime()
            .block_on(run_simulation(SimulationConfig {
                node_count: 12,
                attacker_count: 3,
                malformed_pubsub_datagrams_per_attacker: 2,
                convergence_timeout_ms: 10_000,
                delivery_timeout_ms: 10_000,
                seed: DEFAULT_SEED,
            }))
            .expect("twelve-instance simulation");
        eprintln!("{report:#?}");

        assert_eq!(report.connected_node_count, 12, "{report:?}");
        assert!(report.baseline_delivery_basis_points >= 8_000, "{report:?}");
        assert!(
            report.post_attack_delivery_basis_points >= 8_000,
            "{report:?}"
        );
        assert_eq!(report.rating_spam_published, 3, "{report:?}");
        assert!(
            report.malformed_pubsub_datagrams_attempted > 0,
            "{report:?}"
        );
        assert_eq!(
            report.malformed_pubsub_datagrams_sent, report.malformed_pubsub_datagrams_attempted,
            "{report:?}"
        );
        assert!(report.trusted_positive_ratings_applied > 0, "{report:?}");
        assert!(report.trusted_negative_ratings_applied > 0, "{report:?}");
        assert!(report.unknown_honest_peer_links > 0, "{report:?}");
        assert!(report.unknown_attacker_peer_links > 0, "{report:?}");
        assert!(
            report.received_untrusted_ratings_ignored >= report.rating_spam_stored_by_honest_nodes,
            "{report:?}"
        );
    }

    #[test]
    #[ignore = "34-second adversarial lane; run explicitly or through the simulator binary"]
    fn hundred_instance_adversarial_pubsub_remains_live_and_bounded() {
        let report = simulation_test_runtime()
            .block_on(run_simulation(SimulationConfig::default()))
            .expect("hundred-instance simulation");
        eprintln!("{report:#?}");

        assert_eq!(report.connected_node_count, 100, "{report:?}");
        assert!(report.baseline_delivery_basis_points >= 9_000, "{report:?}");
        assert!(
            report.post_attack_delivery_basis_points >= 9_000,
            "{report:?}"
        );
        assert_eq!(report.rating_spam_published, 20, "{report:?}");
        assert!(report.trusted_positive_ratings_applied > 0, "{report:?}");
        assert!(report.trusted_negative_ratings_applied > 0, "{report:?}");
        assert!(report.unknown_honest_peer_links > 0, "{report:?}");
        assert!(report.unknown_attacker_peer_links > 0, "{report:?}");
        assert!(
            report.received_untrusted_ratings_ignored >= report.rating_spam_stored_by_honest_nodes,
            "{report:?}"
        );
        assert!(report.max_events_stored_per_node <= 22, "{report:?}");
        assert!(report.attack_network.packets_sent < 200_000, "{report:?}");
        assert!(report.attack_network.bytes_sent < 40_000_000, "{report:?}");
    }
}
