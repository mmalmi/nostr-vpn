use std::sync::Weak;

use super::{
    ClientInner, HashMap, HashSet, Ordering, PeerIdentity, SourceId, TCP_POLL_INTERVAL,
    TransportCommand, WireTcpDriver, mpsc, now_ms,
};
use crate::wire_tcp::WireTcpReport;

pub(super) async fn transport_loop(
    inner: Weak<ClientInner>,
    mut driver: WireTcpDriver,
    mut commands: mpsc::Receiver<TransportCommand>,
) {
    let mut poll_tick = tokio::time::interval(TCP_POLL_INTERVAL);
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut known_links = HashMap::new();
    // Startup subscriptions enqueue their REQs before the transport task starts.
    if let Some(inner) = inner.upgrade() {
        sync_transport_peers(&inner, &mut driver, &mut known_links).await;
    }
    loop {
        let Some(inner) = inner.upgrade() else {
            break;
        };
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                match command {
                    TransportCommand::Send { peer, frame } => {
                        if inner.peer_is_in_cooldown(&peer.npub(), now_ms()) {
                            continue;
                        }
                        if driver.queue_frame(peer, &frame).is_err()
                            || driver.connect_peer(&peer.npub(), now_ms()).await.is_err()
                        {
                            inner.transport_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    TransportCommand::Cooldown { peer } => {
                        known_links.remove(&peer.npub());
                        forget_peer_state(&inner, &peer.npub());
                        let _ = driver.forget_peer(peer).await;
                    }
                }
            }
            report = driver.receive(now_ms()) => {
                if let Ok(report) = report {
                    inner.tcp_receive_batches.fetch_add(1, Ordering::Relaxed);
                    process_wire_report(&inner, &mut driver, report).await;
                } else {
                    inner.transport_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = poll_tick.tick() => {
                sync_transport_peers(&inner, &mut driver, &mut known_links).await;
                if tcp_driver_poll_needed(driver.connection_count()) {
                    inner.tcp_poll_turns.fetch_add(1, Ordering::Relaxed);
                    if let Ok(report) = driver.poll(now_ms()).await {
                        process_wire_report(&inner, &mut driver, report).await;
                    } else {
                        inner.transport_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

pub(super) const fn tcp_driver_poll_needed(connection_count: usize) -> bool {
    connection_count != 0
}

async fn sync_transport_peers(
    inner: &ClientInner,
    driver: &mut WireTcpDriver,
    known_links: &mut HashMap<String, u64>,
) {
    let Ok(peers) = inner.connected_peer_links().await else {
        return;
    };
    let next_links = peers
        .iter()
        .filter(|peer| !inner.peer_is_in_cooldown(&peer.npub, now_ms()))
        .map(|peer| (peer.npub.clone(), peer.link_id))
        .collect::<HashMap<_, _>>();
    let changed = known_links
        .iter()
        .filter(|(npub, link_id)| next_links.get(*npub) != Some(*link_id))
        .filter_map(|(npub, _)| PeerIdentity::from_npub(npub).ok())
        .collect::<Vec<_>>();
    driver
        .select_peers(next_links.keys().cloned().collect())
        .await;
    for peer in changed {
        if next_links.contains_key(&peer.npub()) {
            let _ = driver.abort_peer(peer).await;
        } else {
            forget_peer_state(inner, &peer.npub());
        }
    }
    for peer in peers {
        if inner.peer_is_in_cooldown(&peer.npub, now_ms()) {
            continue;
        }
        if driver.connect_peer(&peer.npub, now_ms()).await.is_err() {
            inner.transport_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    *known_links = next_links;
}

fn forget_peer_state(inner: &ClientInner, peer_npub: &str) {
    inner.reset_peer_epoch(peer_npub);
    if let Ok(mut subscriptions) = inner.peer_subscriptions.lock() {
        subscriptions.remove_peer(&SourceId::new(peer_npub));
    }
    if let Ok(mut subscriptions) = inner.lock_subscriptions() {
        for subscription in subscriptions.values_mut() {
            subscription.peers.remove(peer_npub);
        }
    }
}

async fn process_wire_report(
    inner: &ClientInner,
    driver: &mut WireTcpDriver,
    report: WireTcpReport,
) {
    inner
        .transport_errors
        .fetch_add(report.rejected_frames as u64, Ordering::Relaxed);
    inner
        .tcp_datagrams_received
        .fetch_add(report.tcp_datagrams as u64, Ordering::Relaxed);
    inner
        .tcp_datagrams_rejected
        .fetch_add(report.rejected_tcp_datagrams as u64, Ordering::Relaxed);
    inner
        .connected_transport_peers
        .store(report.connected_peers, Ordering::Relaxed);
    let mut cooled_peers = HashSet::new();
    for peer in report.newly_connected {
        if inner.peer_is_in_cooldown(&peer.npub(), now_ms()) {
            cooled_peers.insert(peer.npub());
            forget_peer_state(inner, &peer.npub());
            let _ = driver.forget_peer(peer).await;
            continue;
        }
        inner.reset_peer_epoch(&peer.npub());
        for frame in inner.replay_frames_for_peer(&peer.npub()) {
            let _ = driver.queue_frame(peer, &frame);
        }
    }
    for (peer, frame) in report.frames {
        if cooled_peers.contains(&peer.npub()) || inner.peer_is_in_cooldown(&peer.npub(), now_ms())
        {
            if cooled_peers.insert(peer.npub()) {
                forget_peer_state(inner, &peer.npub());
                let _ = driver.forget_peer(peer).await;
            }
            continue;
        }
        inner.handle_frame(peer, &frame).await;
    }
    for (peer, frame) in inner.retry_pending_frames(now_ms()) {
        if driver.queue_frame(peer, &frame).is_ok() {
            inner.want_frames_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
}
