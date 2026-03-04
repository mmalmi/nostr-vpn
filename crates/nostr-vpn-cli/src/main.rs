use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Args, Parser, Subcommand};
use hex::encode as encode_hex;
use nostr_vpn_core::config::{
    AppConfig, DEFAULT_RELAYS, derive_network_id_from_participants, maybe_autoconfigure_node,
    normalize_nostr_pubkey,
};
use nostr_vpn_core::control::PeerAnnouncement;
use nostr_vpn_core::crypto::generate_keypair;
use nostr_vpn_core::magic_dns::{
    MagicDnsResolverConfig, MagicDnsServer, build_magic_dns_records, install_system_resolver,
    uninstall_system_resolver,
};
use nostr_vpn_core::nat::{discover_public_udp_endpoint, hole_punch_udp};
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload};
use nostr_vpn_core::wireguard::{InterfaceConfig, PeerConfig, render_wireguard_config};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "nvpn")]
#[command(about = "Nostr-signaled WireGuard control plane built on boringtun")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a local config file (keys are generated automatically).
    Init {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        /// Participant Nostr pubkeys (npub or hex) that define the network.
        #[arg(long = "participant")]
        participants: Vec<String>,
    },
    /// Generate a boringtun-compatible keypair.
    Keygen {
        #[arg(long)]
        json: bool,
    },
    /// Bring the node up (publish presence and optionally discover peers).
    Up(UpArgs),
    /// Run a full data-plane session from config (presence + boringtun tunnel).
    Connect(ConnectArgs),
    /// Bring the node down (publish disconnect signal).
    Down(DownArgs),
    /// Show local and discovered peer status.
    Status(StatusArgs),
    /// Update persisted node/network settings.
    Set(SetArgs),
    /// Ping a peer by node ID or tunnel IP.
    Ping(PingArgs),
    /// Check relay reachability and latency.
    Netcheck(NetcheckArgs),
    /// Show local or peer tunnel IPs.
    Ip(IpArgs),
    /// Resolve a node/tunnel IP to peer metadata.
    Whois(WhoisArgs),
    /// Broadcast this node's presence signal over Nostr.
    Announce {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
        #[arg(long = "participant")]
        participants: Vec<String>,
        #[arg(long)]
        node_id: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        tunnel_ip: Option<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        relay: Vec<String>,
    },
    /// Listen for peer presence signals.
    Listen {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        network_id: Option<String>,
        #[arg(long = "participant")]
        participants: Vec<String>,
        #[arg(long)]
        relay: Vec<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Render a WireGuard config from local values and peer tuples.
    RenderWg {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Format: <public_key>,<allowed_ips>,<endpoint>
        #[arg(long = "peer")]
        peers: Vec<String>,
    },
    /// Discover your public UDP endpoint through a reflector.
    NatDiscover(NatDiscoverArgs),
    /// Send UDP punch packets to a peer endpoint to open NAT mappings.
    HolePunch(HolePunchArgs),
    /// Internal low-level tunnel helper for e2e scripts.
    #[command(hide = true)]
    TunnelUp(TunnelUpArgs),
}

#[derive(Debug, Args)]
struct TunnelUpArgs {
    #[arg(long)]
    iface: String,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    listen_port: u16,
    #[arg(long)]
    address: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    peer_endpoint: String,
    #[arg(long)]
    peer_allowed_ip: String,
    #[arg(long, default_value_t = 5)]
    keepalive_secs: u16,
    #[arg(long, default_value_t = 0)]
    hole_punch_attempts: u32,
    #[arg(long, default_value_t = 120)]
    hole_punch_interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    hole_punch_recv_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct UpArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    tunnel_ip: Option<String>,
    #[arg(long)]
    public_key: Option<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value = "utun100")]
    iface: String,
    #[arg(long, default_value_t = 20)]
    announce_interval_secs: u64,
}

#[derive(Debug, Args)]
struct DownArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SetArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long)]
    magic_dns_suffix: Option<String>,
    #[arg(long)]
    node_name: Option<String>,
    #[arg(long)]
    node_id: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    tunnel_ip: Option<String>,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long = "relay")]
    relays: Vec<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    auto_disconnect_relays_when_mesh_ready: Option<bool>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PingArgs {
    target: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long, default_value_t = 3)]
    count: u32,
    #[arg(long, default_value_t = 2)]
    timeout_secs: u64,
}

#[derive(Debug, Args)]
struct NetcheckArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 4)]
    timeout_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IpArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    peer: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct WhoisArgs {
    query: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    network_id: Option<String>,
    #[arg(long = "participant")]
    participants: Vec<String>,
    #[arg(long)]
    relay: Vec<String>,
    #[arg(long, default_value_t = 2)]
    discover_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct NatDiscoverArgs {
    /// Reflector UDP endpoint (e.g. 198.51.100.1:3478).
    #[arg(long)]
    reflector: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    #[arg(long, default_value_t = 2)]
    timeout_secs: u64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct HolePunchArgs {
    #[arg(long)]
    peer_endpoint: String,
    #[arg(long, default_value_t = 51820)]
    listen_port: u16,
    #[arg(long, default_value_t = 40)]
    attempts: u32,
    #[arg(long, default_value_t = 120)]
    interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    recv_timeout_ms: u64,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            config,
            force,
            participants,
        } => {
            let path = config.unwrap_or_else(default_config_path);
            init_config(&path, force, participants)?;
        }
        Command::Keygen { json } => {
            let pair = generate_keypair();
            if json {
                println!("{}", serde_json::to_string_pretty(&pair)?);
            } else {
                println!("private_key={}", pair.private_key);
                println!("public_key={}", pair.public_key);
            }
        }
        Command::Up(args) => {
            let announce = publish_announcement(AnnounceRequest {
                config: args.config,
                network_id: args.network_id,
                participants: args.participants,
                node_id: args.node_id,
                endpoint: args.endpoint,
                tunnel_ip: args.tunnel_ip,
                public_key: args.public_key,
                relay: args.relay,
            })
            .await?;

            let peers = if args.discover_secs > 0 {
                discover_peers(
                    &announce.app,
                    &announce.network_id,
                    &announce.relays,
                    args.discover_secs,
                )
                .await?
            } else {
                Vec::new()
            };

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "up",
                        "network_id": announce.network_id,
                        "relays": announce.relays,
                        "announcement": announce.announcement,
                        "peers": peers,
                    }))?
                );
            } else {
                println!(
                    "up: published presence on {} relays for network {}",
                    announce.relays.len(),
                    announce.network_id
                );
                if !peers.is_empty() {
                    println!("discovered_peers={}", peers.len());
                }
            }
        }
        Command::Connect(args) => {
            connect_session(args).await?;
        }
        Command::Down(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let node_id = args.node_id.unwrap_or_else(|| app.node.id.clone());
            let relays = resolve_relays(&args.relay, &app);

            let client = NostrSignalingClient::from_secret_key(
                network_id.clone(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(&relays).await?;
            client
                .publish(SignalPayload::Disconnect {
                    node_id: node_id.clone(),
                })
                .await
                .context("failed to publish disconnect signal")?;
            client.disconnect().await;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "down",
                        "network_id": network_id,
                        "node_id": node_id,
                        "relays": relays,
                    }))?
                );
            } else {
                println!(
                    "down: published disconnect for {} on {} relays",
                    node_id,
                    relays.len()
                );
            }
        }
        Command::Status(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;
            let expected_peers = expected_peer_count(&app);
            let mesh_ready = expected_peers > 0 && peers.len() >= expected_peers;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "network_id": network_id,
                        "magic_dns_suffix": app.magic_dns_suffix,
                        "node_id": app.node.id,
                        "tunnel_ip": app.node.tunnel_ip,
                        "endpoint": app.node.endpoint,
                        "relays": relays,
                        "auto_disconnect_relays_when_mesh_ready": app.auto_disconnect_relays_when_mesh_ready,
                        "expected_peer_count": expected_peers,
                        "peer_count": peers.len(),
                        "mesh_ready": mesh_ready,
                        "peers": peers,
                    }))?
                );
            } else {
                println!("network: {network_id}");
                println!("magic_dns_suffix: {}", app.magic_dns_suffix);
                println!("node: {}", app.node.id);
                println!("tunnel_ip: {}", app.node.tunnel_ip);
                println!("endpoint: {}", app.node.endpoint);
                println!("relays: {}", relays.len());
                println!(
                    "relay_policy: {}",
                    if app.auto_disconnect_relays_when_mesh_ready {
                        "auto_disconnect_on_mesh_ready"
                    } else {
                        "keep_connected"
                    }
                );
                if expected_peers > 0 {
                    println!("mesh_progress: {}/{}", peers.len(), expected_peers);
                    println!("mesh_ready: {mesh_ready}");
                }
                println!("peers: {}", peers.len());
                for peer in peers {
                    println!("  {} {} {}", peer.node_id, peer.tunnel_ip, peer.endpoint);
                }
            }
        }
        Command::Set(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;

            if let Some(value) = args.network_id {
                app.network_id = value;
            }
            if let Some(value) = args.magic_dns_suffix {
                app.magic_dns_suffix = value;
            }
            if let Some(value) = args.node_name {
                app.node_name = value;
            }
            if let Some(value) = args.node_id {
                app.node.id = value;
            }
            if let Some(value) = args.endpoint {
                app.node.endpoint = value;
            }
            if let Some(value) = args.tunnel_ip {
                app.node.tunnel_ip = value;
            }
            if let Some(value) = args.listen_port {
                app.node.listen_port = value;
            }
            if let Some(value) = args.auto_disconnect_relays_when_mesh_ready {
                app.auto_disconnect_relays_when_mesh_ready = value;
            }
            if !args.relays.is_empty() {
                app.nostr.relays = args.relays;
            }
            apply_participants_override(&mut app, args.participants)?;
            app.ensure_defaults();
            maybe_autoconfigure_node(&mut app);
            app.save(&config_path)?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&app)?);
            } else {
                println!("saved {}", config_path.display());
                println!("network_id={}", app.effective_network_id());
                println!("node_id={}", app.node.id);
            }
        }
        Command::Ping(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;

            let target = resolve_ping_target(&args.target, &peers).ok_or_else(|| {
                anyhow!("target '{}' did not match an IP or known peer", args.target)
            })?;

            run_ping(&target, args.count, args.timeout_secs)?;
        }
        Command::Netcheck(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let checks = run_netcheck(&app, &network_id, &relays, args.timeout_secs).await;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&checks)?);
            } else {
                for check in &checks {
                    if let Some(error) = &check.error {
                        println!("relay {}: down ({error})", check.relay);
                    } else {
                        println!("relay {}: up ({} ms)", check.relay, check.latency_ms);
                    }
                }
                let ok = checks.iter().filter(|item| item.error.is_none()).count();
                println!("summary: {ok}/{} relays reachable", checks.len());
            }
        }
        Command::Ip(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;

            if !args.peer {
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "node_id": app.node.id,
                            "tunnel_ip": app.node.tunnel_ip,
                            "ip": strip_cidr(&app.node.tunnel_ip),
                        }))?
                    );
                } else {
                    println!("{}", strip_cidr(&app.node.tunnel_ip));
                }
            } else {
                let relays = resolve_relays(&args.relay, &app);
                let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;
                let peer_ips: Vec<String> = peers
                    .iter()
                    .map(|peer| strip_cidr(&peer.tunnel_ip).to_string())
                    .collect();
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&peer_ips)?);
                } else {
                    for ip in peer_ips {
                        println!("{ip}");
                    }
                }
            }
        }
        Command::Whois(args) => {
            let config_path = args.config.unwrap_or_else(default_config_path);
            let (app, network_id) =
                load_config_with_overrides(&config_path, args.network_id, args.participants)?;
            let relays = resolve_relays(&args.relay, &app);
            let peers = discover_peers(&app, &network_id, &relays, args.discover_secs).await?;

            let found = peers
                .iter()
                .find(|peer| {
                    peer.node_id == args.query
                        || peer.public_key == args.query
                        || peer.tunnel_ip == args.query
                        || strip_cidr(&peer.tunnel_ip) == args.query
                })
                .cloned();

            let Some(peer) = found else {
                return Err(anyhow!("no peer found for '{}'", args.query));
            };

            if args.json {
                println!("{}", serde_json::to_string_pretty(&peer)?);
            } else {
                println!("node_id={}", peer.node_id);
                println!("public_key={}", peer.public_key);
                println!("tunnel_ip={}", peer.tunnel_ip);
                println!("endpoint={}", peer.endpoint);
                println!("timestamp={}", peer.timestamp);
            }
        }
        Command::Announce {
            config,
            network_id,
            participants,
            node_id,
            endpoint,
            tunnel_ip,
            public_key,
            relay,
        } => {
            let announce = publish_announcement(AnnounceRequest {
                config,
                network_id,
                participants,
                node_id,
                endpoint,
                tunnel_ip,
                public_key,
                relay,
            })
            .await?;
            println!(
                "published presence on {} relays for network {network_id}",
                announce.relays.len(),
                network_id = announce.network_id
            );
        }
        Command::Listen {
            config,
            network_id,
            participants,
            relay,
            limit,
        } => {
            let config_path = config.unwrap_or_else(default_config_path);
            let mut app = load_or_default_config(&config_path)?;

            apply_participants_override(&mut app, participants)?;
            if let Some(network_id) = network_id {
                app.network_id = network_id;
            }

            let network_id = app.effective_network_id();
            let relays = resolve_relays(&relay, &app);

            let client = NostrSignalingClient::from_secret_key(
                network_id.clone(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(&relays).await?;

            let mut seen = 0_usize;
            loop {
                let Some(message) = client.recv().await else {
                    break;
                };

                println!("{}", serde_json::to_string_pretty(&message)?);

                seen += 1;
                if let Some(limit) = limit
                    && seen >= limit
                {
                    break;
                }
            }

            client.disconnect().await;
        }
        Command::NatDiscover(args) => {
            let reflector: SocketAddr = args
                .reflector
                .parse()
                .with_context(|| format!("invalid --reflector {}", args.reflector))?;
            let timeout = Duration::from_secs(args.timeout_secs.max(1));
            let public_endpoint =
                discover_public_udp_endpoint(reflector, args.listen_port, timeout)
                    .context("nat endpoint discovery failed")?;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "reflector": reflector.to_string(),
                        "listen_port": args.listen_port,
                        "public_endpoint": public_endpoint,
                    }))?
                );
            } else {
                println!("{public_endpoint}");
            }
        }
        Command::HolePunch(args) => {
            let peer_endpoint: SocketAddr = args
                .peer_endpoint
                .parse()
                .with_context(|| format!("invalid --peer-endpoint {}", args.peer_endpoint))?;
            let report = hole_punch_udp(
                args.listen_port,
                peer_endpoint,
                args.attempts.max(1),
                Duration::from_millis(args.interval_ms.max(1)),
                Duration::from_millis(args.recv_timeout_ms.max(1)),
            )
            .context("udp hole-punch failed")?;

            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "listen_addr": report.local_addr.to_string(),
                        "peer_endpoint": peer_endpoint.to_string(),
                        "packets_sent": report.packets_sent,
                        "packet_received": report.packet_received,
                    }))?
                );
            } else {
                println!(
                    "hole-punch: sent {} packets from {} to {}, received_response={}",
                    report.packets_sent, report.local_addr, peer_endpoint, report.packet_received
                );
            }
        }
        Command::RenderWg { config, peers } => {
            let config_path = config.unwrap_or_else(default_config_path);
            let app = load_or_default_config(&config_path)?;

            let interface = InterfaceConfig {
                private_key: app.node.private_key.clone(),
                address: app.node.tunnel_ip.clone(),
                listen_port: app.node.listen_port,
            };

            let parsed_peers = peers
                .iter()
                .map(|value| parse_peer_arg(value))
                .collect::<Result<Vec<_>>>()?;

            print!("{}", render_wireguard_config(&interface, &parsed_peers));
        }
        Command::TunnelUp(args) => tunnel_up(&args)?,
    }

    Ok(())
}

fn parse_peer_arg(value: &str) -> Result<PeerConfig> {
    let mut parts = value.split(',');
    let public_key = parts.next().unwrap_or_default().trim().to_string();
    let allowed_ips = parts.next().unwrap_or_default().trim().to_string();
    let endpoint = parts.next().unwrap_or_default().trim().to_string();

    if public_key.is_empty() || allowed_ips.is_empty() || endpoint.is_empty() {
        return Err(anyhow!(
            "invalid --peer format, expected <public_key>,<allowed_ips>,<endpoint>"
        ));
    }

    Ok(PeerConfig {
        public_key,
        allowed_ips,
        endpoint,
        persistent_keepalive: 25,
    })
}

#[derive(Debug)]
struct AnnounceRequest {
    config: Option<PathBuf>,
    network_id: Option<String>,
    participants: Vec<String>,
    node_id: Option<String>,
    endpoint: Option<String>,
    tunnel_ip: Option<String>,
    public_key: Option<String>,
    relay: Vec<String>,
}

#[derive(Debug)]
struct PublishedAnnouncement {
    app: AppConfig,
    network_id: String,
    relays: Vec<String>,
    announcement: PeerAnnouncement,
}

#[derive(Debug, Serialize)]
struct RelayCheck {
    relay: String,
    latency_ms: u128,
    error: Option<String>,
}

fn load_config_with_overrides(
    path: &Path,
    network_id: Option<String>,
    participants: Vec<String>,
) -> Result<(AppConfig, String)> {
    let mut app = load_or_default_config(path)?;
    apply_participants_override(&mut app, participants)?;
    if let Some(network_id) = network_id {
        app.network_id = network_id;
    }
    maybe_autoconfigure_node(&mut app);

    let network_id = app.effective_network_id();
    Ok((app, network_id))
}

async fn publish_announcement(request: AnnounceRequest) -> Result<PublishedAnnouncement> {
    let config_path = request.config.unwrap_or_else(default_config_path);
    let (app, network_id) =
        load_config_with_overrides(&config_path, request.network_id, request.participants)?;
    let node_id = request.node_id.unwrap_or_else(|| app.node.id.clone());
    let endpoint = request
        .endpoint
        .unwrap_or_else(|| app.node.endpoint.clone());
    let tunnel_ip = request
        .tunnel_ip
        .unwrap_or_else(|| app.node.tunnel_ip.clone());
    let public_key = request
        .public_key
        .unwrap_or_else(|| app.node.public_key.clone());
    let relays = resolve_relays(&request.relay, &app);

    let client = NostrSignalingClient::from_secret_key(
        network_id.clone(),
        &app.nostr.secret_key,
        app.participant_pubkeys_hex(),
    )?;
    client.connect(&relays).await?;

    let announcement = PeerAnnouncement {
        node_id,
        public_key,
        endpoint,
        tunnel_ip,
        timestamp: unix_timestamp(),
    };

    client
        .publish(SignalPayload::Announce(announcement.clone()))
        .await
        .context("failed to publish presence signal")?;

    client.disconnect().await;

    Ok(PublishedAnnouncement {
        app,
        network_id,
        relays,
        announcement,
    })
}

async fn discover_peers(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    discover_secs: u64,
) -> Result<Vec<PeerAnnouncement>> {
    if discover_secs == 0 {
        return Ok(Vec::new());
    }

    let client = NostrSignalingClient::from_secret_key(
        network_id.to_string(),
        &app.nostr.secret_key,
        app.participant_pubkeys_hex(),
    )?;
    client.connect(relays).await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(discover_secs);
    let mut peers: std::collections::HashMap<String, PeerAnnouncement> =
        std::collections::HashMap::new();

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let wait_for = std::cmp::min(
            deadline.saturating_duration_since(now),
            Duration::from_millis(250),
        );

        match tokio::time::timeout(wait_for, client.recv()).await {
            Ok(Some(message)) => match message.payload {
                SignalPayload::Announce(announcement) => {
                    let should_insert = peers
                        .get(&announcement.node_id)
                        .is_none_or(|existing| existing.timestamp <= announcement.timestamp);
                    if should_insert {
                        peers.insert(announcement.node_id.clone(), announcement);
                    }
                }
                SignalPayload::Disconnect { node_id } => {
                    peers.remove(&node_id);
                }
            },
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    client.disconnect().await;

    let mut values: Vec<PeerAnnouncement> = peers.into_values().collect();
    values.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(values)
}

#[derive(Debug, Clone)]
struct TunnelPeer {
    pubkey_hex: String,
    endpoint: String,
    allowed_ip: String,
}

const MAGIC_DNS_PORT: u16 = 1053;

struct ConnectMagicDnsRuntime {
    suffix: String,
    resolver_installed: bool,
    server: MagicDnsServer,
}

impl ConnectMagicDnsRuntime {
    fn start(app: &AppConfig) -> Option<Self> {
        let records = build_magic_dns_records(app);
        if records.is_empty() {
            println!("magicdns: skipped (no configured alias records)");
            return None;
        }

        let server = match MagicDnsServer::start(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, MAGIC_DNS_PORT)),
            records.clone(),
        ) {
            Ok(server) => server,
            Err(error) => {
                eprintln!(
                    "magicdns: preferred port {MAGIC_DNS_PORT} unavailable ({error}); trying random local port"
                );
                match MagicDnsServer::start(
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                    records,
                ) {
                    Ok(server) => server,
                    Err(error) => {
                        eprintln!("magicdns: failed to start local dns server: {error}");
                        return None;
                    }
                }
            }
        };
        let local_addr = server.local_addr();

        let suffix = app
            .magic_dns_suffix
            .trim()
            .trim_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            println!(
                "magicdns: local dns running on {local_addr} (system split-dns disabled; empty suffix)"
            );
            return Some(Self {
                suffix,
                resolver_installed: false,
                server,
            });
        }

        let nameserver = match local_addr {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => {
                eprintln!("magicdns: local dns unexpectedly bound to IPv6; split-dns disabled");
                return Some(Self {
                    suffix,
                    resolver_installed: false,
                    server,
                });
            }
        };

        let resolver_config = MagicDnsResolverConfig {
            suffix: suffix.clone(),
            nameserver,
            port: local_addr.port(),
        };

        match install_system_resolver(&resolver_config) {
            Ok(()) => {
                println!(
                    "magicdns: active for .{} via {}:{}",
                    suffix, resolver_config.nameserver, resolver_config.port
                );
                Some(Self {
                    suffix,
                    resolver_installed: true,
                    server,
                })
            }
            Err(error) => {
                eprintln!(
                    "magicdns: system resolver install failed ({error}); local dns remains on {local_addr}"
                );
                Some(Self {
                    suffix,
                    resolver_installed: false,
                    server,
                })
            }
        }
    }
}

impl Drop for ConnectMagicDnsRuntime {
    fn drop(&mut self) {
        if self.resolver_installed
            && !self.suffix.is_empty()
            && let Err(error) = uninstall_system_resolver(&self.suffix)
        {
            eprintln!(
                "magicdns: failed to remove system resolver for .{}: {error}",
                self.suffix
            );
        }

        self.server.stop();
    }
}

struct CliTunnelRuntime {
    iface: String,
    handle: Option<DeviceHandle>,
    uapi_socket_path: Option<String>,
    last_fingerprint: Option<String>,
}

impl CliTunnelRuntime {
    fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            handle: None,
            uapi_socket_path: None,
            last_fingerprint: None,
        }
    }

    fn ensure_started(&mut self) -> Result<()> {
        if cfg!(not(unix)) {
            return Err(anyhow!(
                "connect is currently supported on unix platforms only"
            ));
        }

        if self.handle.is_some() {
            return Ok(());
        }

        let handle = DeviceHandle::new(
            &self.iface,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: true,
                #[cfg(target_os = "linux")]
                use_multi_queue: false,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
            },
        )
        .with_context(|| format!("failed to create boringtun interface {}", self.iface))?;

        let socket = format!("/var/run/wireguard/{}.sock", self.iface);
        wait_for_socket(&socket)?;

        self.handle = Some(handle);
        self.uapi_socket_path = Some(socket);
        Ok(())
    }

    fn apply(
        &mut self,
        app: &AppConfig,
        own_pubkey: Option<&str>,
        peer_announcements: &HashMap<String, PeerAnnouncement>,
    ) -> Result<()> {
        let mut peers = app
            .participants
            .iter()
            .filter(|participant| Some(participant.as_str()) != own_pubkey)
            .filter_map(|participant| peer_announcements.get(participant))
            .map(tunnel_peer_from_announcement)
            .collect::<Result<Vec<_>>>()?;
        peers.sort_by(|left, right| left.pubkey_hex.cmp(&right.pubkey_hex));

        let local_address = local_interface_address_for_tunnel(&app.node.tunnel_ip);
        let fingerprint = tunnel_fingerprint(
            &self.iface,
            &app.node.private_key,
            app.node.listen_port,
            &local_address,
            &peers,
        );
        if self.last_fingerprint.as_deref() == Some(fingerprint.as_str()) && self.handle.is_some() {
            return Ok(());
        }

        self.ensure_started()?;
        let socket = self
            .uapi_socket_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing uapi socket path"))?;

        let private_key_hex = key_b64_to_hex(&app.node.private_key)?;
        wg_set(
            socket,
            &format!(
                "private_key={private_key_hex}\nlisten_port={}",
                app.node.listen_port
            ),
        )?;
        wg_set(socket, "replace_peers=true")?;

        for peer in peers {
            wg_set(
                socket,
                &format!(
                    "public_key={}\nendpoint={}\nreplace_allowed_ips=true\nallowed_ip={}\npersistent_keepalive_interval=5",
                    peer.pubkey_hex, peer.endpoint, peer.allowed_ip
                ),
            )?;
        }

        apply_local_interface_network(
            &self.iface,
            &local_address,
            &[String::from("10.44.0.0/24")],
        )?;

        self.last_fingerprint = Some(fingerprint);
        Ok(())
    }

    fn stop(&mut self) {
        self.handle = None;
        self.uapi_socket_path = None;
        self.last_fingerprint = None;
    }
}

fn tunnel_peer_from_announcement(announcement: &PeerAnnouncement) -> Result<TunnelPeer> {
    let endpoint: SocketAddr = announcement
        .endpoint
        .parse()
        .with_context(|| format!("invalid peer endpoint {}", announcement.endpoint))?;
    let pubkey_hex = key_b64_to_hex(&announcement.public_key)?;
    let allowed_ip = format!("{}/32", strip_cidr(&announcement.tunnel_ip));

    Ok(TunnelPeer {
        pubkey_hex,
        endpoint: endpoint.to_string(),
        allowed_ip,
    })
}

fn local_interface_address_for_tunnel(tunnel_ip: &str) -> String {
    format!("{}/24", strip_cidr(tunnel_ip))
}

fn tunnel_fingerprint(
    iface: &str,
    private_key: &str,
    listen_port: u16,
    local_address: &str,
    peers: &[TunnelPeer],
) -> String {
    let mut peer_entries = peers
        .iter()
        .map(|peer| format!("{}|{}|{}", peer.pubkey_hex, peer.endpoint, peer.allowed_ip))
        .collect::<Vec<_>>();
    peer_entries.sort();
    format!(
        "{iface}|{private_key}|{listen_port}|{local_address}|{}",
        peer_entries.join(";")
    )
}

async fn connect_session(args: ConnectArgs) -> Result<()> {
    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let config_path = args.config.unwrap_or_else(default_config_path);
    let (app, network_id) =
        load_config_with_overrides(&config_path, args.network_id, args.participants)?;
    if app.participants.is_empty() {
        return Err(anyhow!(
            "at least one participant must be configured before running connect"
        ));
    }

    let relays = resolve_relays(&args.relay, &app);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let expected_peers = expected_peer_count(&app);
    let mut peer_announcements = HashMap::<String, PeerAnnouncement>::new();
    let mut tunnel_runtime = CliTunnelRuntime::new(args.iface);
    let _magic_dns_runtime = ConnectMagicDnsRuntime::start(&app);

    let client = NostrSignalingClient::from_secret_key(
        network_id.clone(),
        &app.nostr.secret_key,
        app.participant_pubkeys_hex(),
    )?;
    client.connect(&relays).await?;

    let local_announcement = PeerAnnouncement {
        node_id: app.node.id.clone(),
        public_key: app.node.public_key.clone(),
        endpoint: app.node.endpoint.clone(),
        tunnel_ip: app.node.tunnel_ip.clone(),
        timestamp: unix_timestamp(),
    };
    client
        .publish(SignalPayload::Announce(local_announcement.clone()))
        .await
        .context("failed to publish local presence signal")?;
    tunnel_runtime
        .apply(&app, own_pubkey.as_deref(), &peer_announcements)
        .context("failed to initialize tunnel runtime")?;

    println!(
        "connect: network {} on {} relays; waiting for {expected_peers} configured peer(s)",
        network_id,
        relays.len()
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(args.announce_interval_secs.max(5)));
    announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut last_mesh_count = 0_usize;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = announce_interval.tick() => {
                let refreshed = PeerAnnouncement {
                    timestamp: unix_timestamp(),
                    ..local_announcement.clone()
                };
                let _ = client.publish(SignalPayload::Announce(refreshed)).await;
            }
            message = client.recv() => {
                let Some(message) = message else {
                    break;
                };

                match message.payload {
                    SignalPayload::Announce(announcement) => {
                        if let Some(existing) = peer_announcements.get(&message.sender_pubkey)
                            && existing.timestamp > announcement.timestamp
                        {
                            continue;
                        }
                        peer_announcements.insert(message.sender_pubkey, announcement);
                    }
                    SignalPayload::Disconnect { .. } => {
                        peer_announcements.remove(&message.sender_pubkey);
                    }
                }

                tunnel_runtime
                    .apply(&app, own_pubkey.as_deref(), &peer_announcements)
                    .context("failed to apply tunnel update")?;

                let connected = app
                    .participants
                    .iter()
                    .filter(|participant| Some(participant.as_str()) != own_pubkey.as_deref())
                    .filter(|participant| peer_announcements.contains_key(*participant))
                    .count();
                if connected != last_mesh_count {
                    println!("mesh: {connected}/{expected_peers} peers with presence");
                    last_mesh_count = connected;
                }
            }
        }
    }

    let _ = client
        .publish(SignalPayload::Disconnect {
            node_id: app.node.id.clone(),
        })
        .await;
    client.disconnect().await;
    tunnel_runtime.stop();
    println!("connect: disconnected");

    Ok(())
}

fn run_ping(target: &str, count: u32, timeout_secs: u64) -> Result<()> {
    let mut command = ProcessCommand::new("ping");
    if cfg!(target_os = "windows") {
        command
            .arg("-n")
            .arg(count.to_string())
            .arg("-w")
            .arg((timeout_secs.saturating_mul(1000)).to_string())
            .arg(target);
    } else {
        command
            .arg("-c")
            .arg(count.to_string())
            .arg("-W")
            .arg(timeout_secs.to_string())
            .arg(target);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to execute ping for {target}"))?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        return Err(anyhow!("ping failed for {target}"));
    }

    Ok(())
}

fn resolve_ping_target(target: &str, peers: &[PeerAnnouncement]) -> Option<String> {
    if target.parse::<IpAddr>().is_ok() {
        return Some(target.to_string());
    }

    peers.iter().find_map(|peer| {
        let tunnel_ip = strip_cidr(&peer.tunnel_ip);
        if peer.node_id == target || peer.tunnel_ip == target || tunnel_ip == target {
            Some(tunnel_ip.to_string())
        } else {
            None
        }
    })
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

fn expected_peer_count(config: &AppConfig) -> usize {
    if config.participants.is_empty() {
        return 0;
    }

    let mut expected = config.participants.len();
    if let Ok(own_pubkey) = config.own_nostr_pubkey_hex()
        && config
            .participants
            .iter()
            .any(|participant| participant == &own_pubkey)
    {
        expected = expected.saturating_sub(1);
    }

    expected
}

async fn run_netcheck(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    timeout_secs: u64,
) -> Vec<RelayCheck> {
    let mut checks = Vec::with_capacity(relays.len());

    for relay in relays {
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), async {
            let client = NostrSignalingClient::from_secret_key(
                network_id.to_string(),
                &app.nostr.secret_key,
                app.participant_pubkeys_hex(),
            )?;
            client.connect(std::slice::from_ref(relay)).await?;
            client.disconnect().await;
            Result::<(), anyhow::Error>::Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: None,
            }),
            Ok(Err(error)) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some(error.to_string()),
            }),
            Err(_) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some("timeout".to_string()),
            }),
        }
    }

    checks
}

fn init_config(path: &Path, force: bool, participants: Vec<String>) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "config already exists at {} (pass --force to overwrite)",
            path.display()
        ));
    }

    let mut config = AppConfig::generated();
    apply_participants_override(&mut config, participants)?;
    maybe_autoconfigure_node(&mut config);
    config.save(path)?;

    println!("wrote {}", path.display());
    println!("network_id={}", config.effective_network_id());
    println!("nostr_pubkey={}", config.nostr.public_key);
    Ok(())
}

fn default_config_path() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        let mut path = dir;
        path.push("nvpn");
        path.push("config.toml");
        return path;
    }

    PathBuf::from("nvpn.toml")
}

fn load_or_default_config(path: &Path) -> Result<AppConfig> {
    if path.exists() {
        return AppConfig::load(path);
    }

    let config = AppConfig::generated();
    config.save(path)?;
    Ok(config)
}

fn apply_participants_override(config: &mut AppConfig, participants: Vec<String>) -> Result<()> {
    if participants.is_empty() {
        return Ok(());
    }

    let mut normalized = participants
        .iter()
        .map(|participant| normalize_nostr_pubkey(participant))
        .collect::<Result<Vec<_>>>()?;

    normalized.sort();
    normalized.dedup();
    config.participants = normalized;

    if config.network_id.trim().is_empty() {
        config.network_id = derive_network_id_from_participants(&config.participants);
    }

    Ok(())
}

fn resolve_relays(cli_relays: &[String], config: &AppConfig) -> Vec<String> {
    if !cli_relays.is_empty() {
        return cli_relays.to_vec();
    }

    if !config.nostr.relays.is_empty() {
        return config.nostr.relays.clone();
    }

    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn tunnel_up(args: &TunnelUpArgs) -> Result<()> {
    if cfg!(not(unix)) {
        return Err(anyhow!(
            "tunnel-up is currently supported on unix platforms only"
        ));
    }

    if args.iface.trim().is_empty() {
        return Err(anyhow!("--iface must not be empty"));
    }

    let private_key_hex = key_b64_to_hex(&args.private_key)?;
    let peer_public_key_hex = key_b64_to_hex(&args.peer_public_key)?;

    if args.hole_punch_attempts > 0 {
        let peer_endpoint: SocketAddr = args.peer_endpoint.parse().with_context(|| {
            format!(
                "invalid --peer-endpoint '{}' (required as ip:port when hole-punching)",
                args.peer_endpoint
            )
        })?;
        let report = hole_punch_udp(
            args.listen_port,
            peer_endpoint,
            args.hole_punch_attempts,
            Duration::from_millis(args.hole_punch_interval_ms.max(1)),
            Duration::from_millis(args.hole_punch_recv_timeout_ms.max(1)),
        )
        .context("pre-tunnel hole-punch failed")?;

        println!(
            "pre-punch: sent {} packets from {} to {}, received_response={}",
            report.packets_sent, report.local_addr, peer_endpoint, report.packet_received
        );
    }

    // Keep handle alive for process lifetime; dropping tears down the device.
    let _handle = DeviceHandle::new(
        &args.iface,
        DeviceConfig {
            n_threads: 2,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: false,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        },
    )
    .with_context(|| format!("failed to create boringtun interface {}", args.iface))?;

    let uapi_socket = format!("/var/run/wireguard/{}.sock", args.iface);
    wait_for_socket(&uapi_socket)?;

    wg_set(
        &uapi_socket,
        &format!(
            "private_key={private_key_hex}\nlisten_port={}",
            args.listen_port
        ),
    )?;
    wg_set(
        &uapi_socket,
        &format!(
            "public_key={peer_public_key_hex}\nendpoint={}\nreplace_allowed_ips=true\nallowed_ip={}\npersistent_keepalive_interval={}",
            args.peer_endpoint, args.peer_allowed_ip, args.keepalive_secs
        ),
    )?;

    apply_local_interface_network(
        &args.iface,
        &args.address,
        std::slice::from_ref(&args.peer_allowed_ip),
    )?;

    println!(
        "boringtun interface {} up: {}, peer {} via {}",
        args.iface, args.address, args.peer_allowed_ip, args.peer_endpoint
    );

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn key_b64_to_hex(value: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(value)
        .with_context(|| "invalid base64 key encoding")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32-byte key material"));
    }
    Ok(encode_hex(bytes))
}

fn apply_local_interface_network(
    iface: &str,
    address: &str,
    route_targets: &[String],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_checked(
            ProcessCommand::new("ip")
                .arg("address")
                .arg("replace")
                .arg(address)
                .arg("dev")
                .arg(iface),
        )?;
        run_checked(
            ProcessCommand::new("ip")
                .arg("link")
                .arg("set")
                .arg("mtu")
                .arg("1380")
                .arg("up")
                .arg("dev")
                .arg(iface),
        )?;
        for target in route_targets {
            run_checked(
                ProcessCommand::new("ip")
                    .arg("route")
                    .arg("replace")
                    .arg(target)
                    .arg("dev")
                    .arg(iface),
            )?;
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let ip = strip_cidr(address).to_string();
        run_checked(
            ProcessCommand::new("ifconfig")
                .arg(iface)
                .arg("inet")
                .arg(&ip)
                .arg(&ip)
                .arg("netmask")
                .arg("255.255.255.0")
                .arg("up"),
        )?;
        for target in route_targets {
            apply_macos_route(iface, target)?;
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(anyhow!(
        "interface setup is not implemented for this platform"
    ))
}

#[cfg(target_os = "macos")]
fn apply_macos_route(iface: &str, target: &str) -> Result<()> {
    let target_ip = strip_cidr(target);
    let is_host = target.ends_with("/32") || !target.contains('/');

    let add_result = if is_host {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("add")
                .arg("-host")
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        )
    } else {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("add")
                .arg("-net")
                .arg(target)
                .arg("-interface")
                .arg(iface),
        )
    };

    if add_result.is_ok() {
        return Ok(());
    }

    if is_host {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("change")
                .arg("-host")
                .arg(target_ip)
                .arg("-interface")
                .arg(iface),
        )
    } else {
        run_checked(
            ProcessCommand::new("route")
                .arg("-n")
                .arg("change")
                .arg("-net")
                .arg(target)
                .arg("-interface")
                .arg(iface),
        )
    }
}

fn wait_for_socket(path: &str) -> Result<()> {
    for _ in 0..50 {
        if fs::metadata(path).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!("timed out waiting for uapi socket at {path}"))
}

fn wg_set(socket_path: &str, body: &str) -> Result<()> {
    let mut socket =
        UnixStream::connect(socket_path).with_context(|| format!("connect {socket_path}"))?;
    write!(socket, "set=1\n{body}\n\n").context("failed to send uapi set")?;
    socket
        .shutdown(std::net::Shutdown::Write)
        .context("failed to close uapi write half")?;

    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .context("failed to read uapi response")?;

    if !response.contains("errno=0") {
        return Err(anyhow!("uapi set failed: {}", response.trim()));
    }

    Ok(())
}

fn run_checked(command: &mut ProcessCommand) -> Result<()> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {display}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "command failed: {display}\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn clap_binary_name_is_nvpn() {
        let command = Cli::command();
        assert_eq!(command.get_name(), "nvpn");
    }

    #[test]
    fn clap_includes_tailscale_style_commands() {
        let command = Cli::command();
        for name in [
            "up",
            "connect",
            "down",
            "status",
            "set",
            "ping",
            "netcheck",
            "ip",
            "whois",
            "nat-discover",
            "hole-punch",
        ] {
            assert!(
                command
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() == name),
                "missing subcommand {name}"
            );
        }
    }
}
