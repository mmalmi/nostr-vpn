use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[path = "android_session_planning.rs"]
mod android_session_planning;
#[path = "android_session_tunnel.rs"]
mod android_session_tunnel;

use android_session_planning::*;
use android_session_tunnel::*;

use crate::DaemonRuntimeState;
use crate::android_session_runtime::{signal_payload_kind, unix_timestamp};
use crate::android_vpn::AndroidVpnExt;
use crate::mobile_wg::PeerRuntimeStatus;
use nostr_vpn_core::config::{AppConfig, maybe_autoconfigure_node};
use nostr_vpn_core::paths::PeerPathBook;
use nostr_vpn_core::presence::PeerPresenceBook;
use nostr_vpn_core::signaling::{NostrSignalingClient, SignalPayload};

const ANDROID_TUN_MTU: u16 = 1_280;
const ANDROID_SESSION_STATUS_WAITING: &str = "Waiting for participants";
const ANDROID_ANNOUNCE_INTERVAL_SECS: u64 = 5;
const ANDROID_PUBLISH_TIMEOUT_SECS: u64 = 3;
const ANDROID_SIGNAL_STALE_AFTER_SECS: u64 = 45;
const ANDROID_TIMER_INTERVAL_MILLIS: u64 = 250;

#[derive(Default)]
struct AndroidSessionSnapshot {
    running: bool,
    state: Option<DaemonRuntimeState>,
}

pub(crate) struct AndroidSessionManager {
    app: tauri::AppHandle,
    runtime_handle: Handle,
    snapshot: std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    stop_tx: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
}

struct ActiveTunnelTask {
    listen_port: u16,
    state: std::sync::Arc<std::sync::Mutex<TunnelTaskState>>,
    stop_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

struct MobileTunIo {
    reader: tokio::fs::File,
    writer: tokio::fs::File,
}

#[derive(Default)]
struct TunnelTaskState {
    peer_statuses: Vec<PeerRuntimeStatus>,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct TunnelPeer {
    participant: String,
    pubkey_b64: String,
    endpoint: SocketAddr,
    allowed_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlannedTunnelPeer {
    participant: String,
    endpoint: String,
    peer: TunnelPeer,
}

struct ReconcileSession<'a> {
    own_pubkey: Option<&'a str>,
    recipients: &'a [String],
}

struct ReconcileTunnelState<'a> {
    current_tunnel: &'a mut Option<ActiveTunnelTask>,
    current_listen_port: &'a mut u16,
    current_fingerprint: &'a mut Option<String>,
}

impl AndroidSessionManager {
    pub(crate) fn new(app: tauri::AppHandle, runtime_handle: Handle) -> Self {
        Self {
            app,
            runtime_handle,
            snapshot: std::sync::Arc::new(std::sync::Mutex::new(AndroidSessionSnapshot::default())),
            stop_tx: None,
            task: None,
        }
    }

    pub(crate) fn start(&mut self, config: AppConfig) -> Result<()> {
        self.stop()?;
        eprintln!(
            "android-session: start requested network_id={} participants={} endpoint={} tunnel_ip={}",
            config.effective_network_id(),
            config.participant_pubkeys_hex().len(),
            config.node.endpoint,
            config.node.tunnel_ip,
        );
        self.app
            .android_vpn()
            .prepare()
            .map_err(|error| anyhow!("failed to prepare android vpn permission: {error}"))?;

        let (stop_tx, stop_rx) = watch::channel(false);
        let snapshot = self.snapshot.clone();
        let app = self.app.clone();

        self.store_snapshot(
            true,
            Some(DaemonRuntimeState {
                session_active: true,
                relay_connected: false,
                session_status: "Connecting…".to_string(),
                ..DaemonRuntimeState::default()
            }),
        );

        let join = self.runtime_handle.spawn(async move {
            if let Err(error) = run_android_session(app, config, snapshot.clone(), stop_rx).await {
                eprintln!("android-session: run failed: {error:#}");
                if let Ok(mut guard) = snapshot.lock() {
                    guard.running = false;
                    guard.state = Some(DaemonRuntimeState {
                        session_active: false,
                        relay_connected: false,
                        session_status: format!("Android session failed: {error}"),
                        ..DaemonRuntimeState::default()
                    });
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(join);
        Ok(())
    }

    pub(crate) fn reload(&mut self, config: AppConfig) -> Result<()> {
        self.start(config)
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = self.runtime_handle.block_on(task);
        }

        self.store_snapshot(
            false,
            Some(DaemonRuntimeState {
                session_active: false,
                relay_connected: false,
                session_status: "Disconnected".to_string(),
                ..DaemonRuntimeState::default()
            }),
        );
        Ok(())
    }

    pub(crate) fn status(&self) -> (bool, Option<DaemonRuntimeState>) {
        self.snapshot
            .lock()
            .map(|snapshot| (snapshot.running, snapshot.state.clone()))
            .unwrap_or((false, None))
    }

    fn store_snapshot(&self, running: bool, state: Option<DaemonRuntimeState>) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            snapshot.running = running;
            snapshot.state = state;
        }
    }
}

async fn run_android_session(
    app_handle: tauri::AppHandle,
    mut config: AppConfig,
    snapshot: std::sync::Arc<std::sync::Mutex<AndroidSessionSnapshot>>,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    config.ensure_defaults();
    maybe_autoconfigure_node(&mut config);

    let expected_peers = expected_peer_count(&config);
    let own_pubkey = config.own_nostr_pubkey_hex().ok();
    let relays = resolve_relays(&config);
    let recipients = configured_recipients(&config, own_pubkey.as_deref());
    eprintln!(
        "android-session: run starting network_id={} expected_peers={} recipients={} relays={}",
        config.effective_network_id(),
        expected_peers,
        recipients.len(),
        relays.len(),
    );

    let client = NostrSignalingClient::from_secret_key_with_networks(
        &config.nostr.secret_key,
        signaling_networks_for_app(&config),
    )?;
    eprintln!("android-session: connecting signaling client");
    client
        .connect(&relays)
        .await
        .context("failed to connect signaling client")?;
    eprintln!("android-session: signaling client connected");

    let mut presence = PeerPresenceBook::default();
    let mut path_book = PeerPathBook::default();
    let mut current_tunnel: Option<ActiveTunnelTask> = None;
    let mut current_listen_port = config.node.listen_port;
    let mut current_fingerprint: Option<String> = None;

    eprintln!(
        "android-session: publishing private announce to {} recipients on port {}",
        recipients.len(),
        current_listen_port,
    );
    publish_hello_best_effort(&client).await;
    publish_private_announce_best_effort(&client, &config, current_listen_port, &recipients).await;
    update_snapshot(
        &snapshot,
        build_runtime_state(
            &config,
            expected_peers,
            true,
            current_tunnel.as_ref(),
            own_pubkey.as_deref(),
            &presence,
        ),
    );

    let mut announce_interval =
        tokio::time::interval(Duration::from_secs(ANDROID_ANNOUNCE_INTERVAL_SECS));
    let mut status_interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    break;
                }
            }
            envelope = client.recv() => {
                let Some(envelope) = envelope else {
                    return Err(anyhow!("signaling client closed"));
                };
                let sender_pubkey = envelope.sender_pubkey.clone();
                let payload_kind = signal_payload_kind(&envelope.payload);
                eprintln!(
                    "android-session: received {payload_kind} from {}",
                    sender_pubkey,
                );
                presence.apply_signal(
                    envelope.sender_pubkey,
                    envelope.payload,
                    unix_timestamp(),
                );
                reconcile_tunnel(
                    &app_handle,
                    &client,
                    &config,
                    ReconcileSession {
                        own_pubkey: own_pubkey.as_deref(),
                        recipients: &recipients,
                    },
                    &mut presence,
                    &mut path_book,
                    ReconcileTunnelState {
                        current_tunnel: &mut current_tunnel,
                        current_listen_port: &mut current_listen_port,
                        current_fingerprint: &mut current_fingerprint,
                    },
                )
                .await?;
                update_snapshot(
                    &snapshot,
                    build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_tunnel.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    ),
                );
            }
            _ = announce_interval.tick() => {
                publish_hello_best_effort(&client).await;
                publish_private_announce_best_effort(&client, &config, current_listen_port, &recipients).await;
            }
            _ = status_interval.tick() => {
                let now = unix_timestamp();
                presence.prune_stale(now, ANDROID_SIGNAL_STALE_AFTER_SECS);
                note_successful_runtime_paths(current_tunnel.as_ref(), &presence, &mut path_book, now);
                update_snapshot(
                    &snapshot,
                    build_runtime_state(
                        &config,
                        expected_peers,
                        true,
                        current_tunnel.as_ref(),
                        own_pubkey.as_deref(),
                        &presence,
                    ),
                );
            }
        }
    }

    let disconnect = SignalPayload::Disconnect {
        node_id: config.node.id.clone(),
    };
    let _ = client.publish_to(disconnect, &recipients).await;
    client.disconnect().await;

    if let Some(tunnel) = current_tunnel.take() {
        stop_tunnel_task(&app_handle, tunnel).await;
    } else {
        let _ = app_handle.android_vpn().stop();
    }

    update_snapshot(
        &snapshot,
        DaemonRuntimeState {
            session_active: false,
            relay_connected: false,
            session_status: "Disconnected".to_string(),
            ..DaemonRuntimeState::default()
        },
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::android_session_planning::{
        planned_tunnel_peers, runtime_local_signal_endpoint, tunnel_fingerprint,
    };
    use super::android_session_tunnel::write_tunnel_packets;
    use crate::android_session_runtime::{open_mobile_tun_io, should_retry_tun_io};
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::config::AppConfig;
    use nostr_vpn_core::control::PeerAnnouncement;
    use nostr_vpn_core::paths::PeerPathBook;
    use std::collections::HashMap;
    use std::time::Duration;

    fn participant() -> String {
        Keys::generate().public_key().to_hex()
    }

    fn peer_announcement(endpoint: &str, tunnel_ip: &str, routes: &[&str]) -> PeerAnnouncement {
        PeerAnnouncement {
            node_id: format!("node-{endpoint}"),
            public_key: "dummy-public-key".to_string(),
            endpoint: endpoint.to_string(),
            local_endpoint: None,
            public_endpoint: Some(endpoint.to_string()),
            relay_endpoint: None,
            relay_pubkey: None,
            relay_expires_at: None,
            tunnel_ip: tunnel_ip.to_string(),
            advertised_routes: routes.iter().map(|route| (*route).to_string()).collect(),
            timestamp: 1,
        }
    }

    #[test]
    fn planned_tunnel_peers_assign_selected_exit_node_default_route() {
        let mut config = AppConfig::generated();
        let exit_participant = participant();
        let routed_participant = participant();
        config.networks[0].participants =
            vec![exit_participant.clone(), routed_participant.clone()];
        config.exit_node = exit_participant.clone();
        config.ensure_defaults();

        let announcements = HashMap::from([
            (
                exit_participant.clone(),
                peer_announcement(
                    "203.0.113.20:51820",
                    "10.44.0.2/32",
                    &["10.60.0.0/24", "0.0.0.0/0", "::/0"],
                ),
            ),
            (
                routed_participant.clone(),
                peer_announcement("203.0.113.21:51820", "10.44.0.3/32", &["10.70.0.0/24"]),
            ),
        ]);

        let planned = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("192.0.2.10:51820"),
            10,
        )
        .expect("planned tunnel peers");

        let exit_peer = planned
            .iter()
            .find(|planned| planned.participant == exit_participant)
            .expect("exit peer");
        assert_eq!(
            exit_peer.peer.allowed_ips,
            vec![
                "10.44.0.2/32".to_string(),
                "0.0.0.0/0".to_string(),
                "10.60.0.0/24".to_string(),
            ]
        );

        let routed_peer = planned
            .iter()
            .find(|planned| planned.participant == routed_participant)
            .expect("routed peer");
        assert_eq!(
            routed_peer.peer.allowed_ips,
            vec!["10.44.0.3/32".to_string(), "10.70.0.0/24".to_string()]
        );
    }

    #[test]
    fn planned_tunnel_peers_ignore_default_route_without_selected_exit_node() {
        let mut config = AppConfig::generated();
        let exit_participant = participant();
        config.networks[0].participants = vec![exit_participant.clone()];
        config.ensure_defaults();

        let announcements = HashMap::from([(
            exit_participant,
            peer_announcement(
                "203.0.113.20:51820",
                "10.44.0.2/32",
                &["0.0.0.0/0", "10.60.0.0/24"],
            ),
        )]);

        let planned = planned_tunnel_peers(
            &config,
            None,
            &announcements,
            &mut PeerPathBook::default(),
            Some("192.0.2.10:51820"),
            10,
        )
        .expect("planned tunnel peers");

        assert_eq!(
            planned[0].peer.allowed_ips,
            vec!["10.44.0.2/32".to_string(), "10.60.0.0/24".to_string()]
        );
    }

    #[test]
    fn runtime_local_signal_endpoint_preserves_non_loopback_host_with_new_port() {
        assert_eq!(
            runtime_local_signal_endpoint("198.51.100.10:6000", 51820),
            "198.51.100.10:51820"
        );
    }

    #[test]
    fn tunnel_fingerprint_changes_when_peer_public_key_changes() {
        let config = AppConfig::generated();
        let participant = participant();
        let peer = |pubkey_b64: &str| super::PlannedTunnelPeer {
            participant: participant.clone(),
            endpoint: "192.168.178.44:51820".to_string(),
            peer: super::TunnelPeer {
                participant: participant.clone(),
                pubkey_b64: pubkey_b64.to_string(),
                endpoint: "192.168.178.44:51820".parse().expect("socket address"),
                allowed_ips: vec!["10.44.1.158/32".to_string()],
            },
        };

        let first = tunnel_fingerprint(&config, 51820, &[peer("peer-key-a")]);
        let second = tunnel_fingerprint(&config, 51820, &[peer("peer-key-b")]);

        assert_ne!(first, second);
    }

    #[test]
    fn tun_io_retries_would_block_and_interrupted() {
        assert!(should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(!should_retry_tun_io(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        )));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn mobile_tun_io_supports_bidirectional_unseekable_fds() {
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use tokio::io::AsyncReadExt;

        let (local, mut peer) = UnixStream::pair().expect("unix stream pair");
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("peer read timeout");
        let mut tun = open_mobile_tun_io(local.into_raw_fd()).expect("tun io");

        peer.write_all(b"ping").expect("write inbound bytes");
        let mut inbound = [0_u8; 4];
        tun.reader
            .read_exact(&mut inbound)
            .await
            .expect("read inbound bytes");
        assert_eq!(&inbound, b"ping");

        write_tunnel_packets(&mut tun.writer, &[b"pong".to_vec()])
            .await
            .expect("write outbound bytes");
        let mut outbound = [0_u8; 4];
        peer.read_exact(&mut outbound).expect("read outbound bytes");
        assert_eq!(&outbound, b"pong");
    }
}
