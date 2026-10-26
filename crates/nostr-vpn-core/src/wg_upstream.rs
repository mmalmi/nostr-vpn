//! Userspace WireGuard upstream runtime — single-peer (Mullvad/Proton-style).
//!
//! Wraps `boringtun::noise::Tunn` for the case where this device is a WG
//! *client* of one upstream provider, not a multi-peer mesh participant.
//! Lives here in `nostr-vpn-core` so desktop and mobile share the same
//! boringtun pump while platform-specific crates own tun/routing glue.
//!
//! Three jobs run through one coordinator task so `Tunn` doesn't need a mutex:
//!   * UDP-rx: receive ciphertext from upstream → `Tunn::decapsulate` →
//!     forward plaintext to the platform writer.
//!   * tun-rx: receive plaintext from the platform reader →
//!     `Tunn::encapsulate` → send ciphertext to upstream.
//!   * timer: every 250ms call `Tunn::update_timers` so the handshake +
//!     keepalive state machine can re-key / re-init on schedule.
//!
//! Platforms wire the tun side through one of three constructors:
//!   * `start_handshake_only` — no tun, just a connectivity probe (safe
//!     to run on a host with live internet).
//!   * `start_with_channels` — caller pumps plaintext packet batches via
//!     mpsc channels. Used by mobile (iOS NEPacketTunnelProvider, Android
//!     VpnService) where the OS owns the tun.
//!   * `start_with_tun` (POSIX) / `start_with_wintun` (Windows) — the
//!     daemon path; the runtime owns reader+writer tasks that talk to
//!     the OS tun directly.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::raw::c_int;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::config::WireGuardExitConfig;

pub const MAX_WG_PACKET: usize = 65_535;
const TIMER_TICK: Duration = Duration::from_millis(250);

type TunPacket = Vec<u8>;
type TunPacketBatch = Vec<TunPacket>;
type TunPacketRx = mpsc::Receiver<TunPacketBatch>;
type TunPacketTx = mpsc::Sender<TunPacketBatch>;
type TunIo = (TunPacketRx, TunPacketTx);
type TunTaskHandles = (JoinHandle<()>, JoinHandle<()>);

struct TunTaskAbortGuard(Option<TunTaskHandles>);

impl TunTaskAbortGuard {
    fn take(&mut self) -> Option<TunTaskHandles> {
        self.0.take()
    }
}

impl Drop for TunTaskAbortGuard {
    fn drop(&mut self) {
        if let Some((reader, writer)) = self.0.take() {
            reader.abort();
            writer.abort();
        }
    }
}

/// Default time the daemon / mobile runtime waits for the WG handshake
/// to complete before giving up. Acts as the implicit watchdog: by
/// only swapping the default route after a real handshake, a
/// misconfigured config or unreachable upstream cannot take the host
/// offline.
pub const DAEMON_WG_UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle to a running userspace WG upstream tunnel.
///
/// Drop or call [`Self::shutdown`] to stop the pump tasks. If the
/// runtime owns the tun (POSIX `start_with_tun` or Windows
/// `start_with_wintun`), the platform reader+writer tasks are also
/// aborted here.
pub struct WgUpstreamRuntime {
    pump: Option<JoinHandle<()>>,
    tun_reader: Option<JoinHandle<()>>,
    tun_writer: Option<JoinHandle<()>>,
    handshake: Arc<HandshakeState>,
    upstream: SocketAddr,
    udp: Arc<UdpSocket>,
    // Keeping the sender alive prevents the coordinator's control branch
    // from becoming an always-ready closed channel on non-macOS targets.
    _control_tx: mpsc::UnboundedSender<WgUpstreamCommand>,
}

#[derive(Default)]
struct HandshakeState {
    completed: Notify,
    last_age: RwLock<Option<Duration>>,
    // Zero means no completed initiator handshake. WireGuard receiver
    // indices are stored as index + 1 so every u32 value remains representable.
    last_completed_receiver_index: AtomicU64,
}

enum WgUpstreamCommand {
    ForceHandshake {
        response: oneshot::Sender<Result<u32>>,
    },
    #[cfg(target_os = "macos")]
    RebindInterface {
        interface_index: u32,
        response: oneshot::Sender<Result<u32>>,
    },
}

#[derive(Clone)]
pub struct WgUpstreamHandshakeObserver {
    handshake: Arc<HandshakeState>,
}

impl WgUpstreamHandshakeObserver {
    pub fn has_completed_handshake(&self) -> bool {
        self.handshake
            .last_completed_receiver_index
            .load(Ordering::Acquire)
            != 0
    }

    /// Wait for at most `timeout` for the WG handshake to complete.
    /// Returns `true` if a handshake was observed; `false` on timeout.
    pub async fn wait_for_handshake(&self, timeout: Duration) -> bool {
        wait_for_handshake(&self.handshake, timeout).await
    }
}

impl WgUpstreamRuntime {
    /// Probe the WG handshake without creating a tun device.
    /// Safe-by-construction: cannot blackhole the host's internet.
    pub async fn start_handshake_only(config: &WireGuardExitConfig) -> Result<Self> {
        Self::start_with_io(config, None, None).await
    }

    /// Build the runtime with raw mpsc channels for tun I/O. Used by
    /// platforms where the OS owns the tun (iOS NEPacketTunnelProvider,
    /// Android VpnService): the host code feeds plaintext packet batches
    /// into `tun_in_rx` and reads plaintext packet batches out of
    /// `tun_out_tx`.
    pub async fn start_with_channels(
        config: &WireGuardExitConfig,
        tun_in_rx: TunPacketRx,
        tun_out_tx: TunPacketTx,
    ) -> Result<Self> {
        Self::start_with_io(config, Some((tun_in_rx, tun_out_tx)), None).await
    }

    /// Lower-level constructor used by the desktop daemon: callers
    /// build their own platform-specific tun reader/writer tasks (e.g.
    /// using `boringtun::device::tun::TunSocket` on POSIX or
    /// `wintun::Session` on Windows) and hand them in along with the
    /// matching channel pair. This keeps the platform-specific tun
    /// imports out of `nostr-vpn-core` so the crate continues to build
    /// on mobile without the boringtun `device` feature.
    pub async fn start_with_io(
        config: &WireGuardExitConfig,
        tun_io: Option<TunIo>,
        tun_handles: Option<TunTaskHandles>,
    ) -> Result<Self> {
        Self::start_with_io_inner(config, tun_io, tun_handles, None, None).await
    }

    /// macOS constructor that pins encrypted WG UDP traffic to the
    /// selected physical underlay before the first handshake is sent.
    #[cfg(target_os = "macos")]
    pub async fn start_with_io_on_interface(
        config: &WireGuardExitConfig,
        tun_io: Option<TunIo>,
        tun_handles: Option<TunTaskHandles>,
        interface_index: u32,
    ) -> Result<Self> {
        Self::start_with_io_inner(config, tun_io, tun_handles, Some(interface_index), None).await
    }

    /// macOS restart constructor for an endpoint that was resolved before
    /// split-default routing made system DNS dependent on the active tunnel.
    #[cfg(target_os = "macos")]
    pub async fn start_with_io_on_interface_at_upstream(
        config: &WireGuardExitConfig,
        tun_io: Option<TunIo>,
        tun_handles: Option<TunTaskHandles>,
        interface_index: u32,
        upstream: SocketAddr,
    ) -> Result<Self> {
        Self::start_with_io_inner(
            config,
            tun_io,
            tun_handles,
            Some(interface_index),
            Some(upstream),
        )
        .await
    }

    async fn start_with_io_inner(
        config: &WireGuardExitConfig,
        tun_io: Option<TunIo>,
        tun_handles: Option<TunTaskHandles>,
        interface_index: Option<u32>,
        resolved_upstream: Option<SocketAddr>,
    ) -> Result<Self> {
        let mut tun_handles = TunTaskAbortGuard(tun_handles);
        log_android_info("wg-upstream: start_with_io entered");
        let private = decode_private_key(&config.private_key)?;
        let public = decode_public_key(&config.peer_public_key)?;
        let preshared = decode_optional_preshared_key(&config.peer_preshared_key)?;
        let upstream = match resolved_upstream {
            Some(upstream) => upstream,
            None => resolve_endpoint(&config.endpoint).await?,
        };
        log_android_info(&format!(
            "wg-upstream: keys decoded, upstream resolved to {upstream}"
        ));

        let bind_addr = udp_bind_addr_for_upstream(upstream);
        let udp = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind upstream WG udp socket on {bind_addr}"))?;
        let udp_socket_fd = raw_udp_socket_fd(&udp);
        #[cfg(target_os = "macos")]
        if let Some(interface_index) = interface_index {
            bind_apple_udp_socket_to_interface(udp_socket_fd, upstream, interface_index)?;
        }
        #[cfg(not(target_os = "macos"))]
        debug_assert!(interface_index.is_none());
        log_android_info(&format!(
            "wg-upstream: udp socket bound, fd={udp_socket_fd}"
        ));
        let udp = Arc::new(udp);

        let keepalive = if config.persistent_keepalive_secs == 0 {
            None
        } else {
            Some(config.persistent_keepalive_secs)
        };
        let tunn = Tunn::new(private, public, preshared, keepalive, 1, None);

        let handshake = Arc::new(HandshakeState::default());
        let (tun_in_rx, tun_out_tx) = match tun_io {
            Some((rx, tx)) => (Some(rx), Some(tx)),
            None => (None, None),
        };
        let (tun_reader, tun_writer) = match tun_handles.take() {
            Some((r, w)) => (Some(r), Some(w)),
            None => (None, None),
        };

        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let pump = tokio::spawn(run_pump(
            tunn,
            Arc::clone(&udp),
            upstream,
            tun_in_rx,
            tun_out_tx,
            handshake.clone(),
            control_rx,
        ));

        Ok(Self {
            pump: Some(pump),
            tun_reader,
            tun_writer,
            handshake,
            upstream,
            udp,
            _control_tx: control_tx,
        })
    }

    /// Wait for at most `timeout` for the WG handshake to complete.
    /// Returns `true` if a handshake was observed; `false` on timeout.
    pub async fn wait_for_handshake(&self, timeout: Duration) -> bool {
        wait_for_handshake(&self.handshake, timeout).await
    }

    pub fn handshake_observer(&self) -> WgUpstreamHandshakeObserver {
        WgUpstreamHandshakeObserver {
            handshake: self.handshake.clone(),
        }
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    pub fn is_running(&self) -> bool {
        self.pump.as_ref().is_some_and(|pump| !pump.is_finished())
    }

    /// Raw fd of the UDP socket talking to the WG upstream. On Android
    /// the host should pass this to `VpnService.protect(fd)` so the
    /// encrypted UDP escapes the VPN tun. Returns -1 on platforms
    /// where the underlying socket type doesn't expose a raw fd.
    pub fn udp_socket_fd(&self) -> c_int {
        raw_udp_socket_fd(&self.udp)
    }

    /// Actively initiate a fresh authenticated handshake on the live UDP
    /// socket. Mobile platforms use this immediately after the OS migrates
    /// that socket to a new physical underlay.
    pub async fn force_handshake(&self) -> Result<u32> {
        let (response, result) = oneshot::channel();
        self._control_tx
            .send(WgUpstreamCommand::ForceHandshake { response })
            .map_err(|_| anyhow!("WG upstream pump stopped before forced handshake"))?;
        result
            .await
            .context("WG upstream pump stopped while forcing handshake")?
    }

    /// Rebind encrypted WG UDP traffic to a new macOS underlay and
    /// actively initiate a fresh handshake on it. The returned receiver index
    /// identifies the exact forced initiation whose response must complete.
    #[cfg(target_os = "macos")]
    pub async fn rebind_interface(&mut self, interface_index: u32) -> Result<u32> {
        let (response, result) = oneshot::channel();
        self._control_tx
            .send(WgUpstreamCommand::RebindInterface {
                interface_index,
                response,
            })
            .map_err(|_| anyhow!("WG upstream pump stopped before underlay rebind"))?;
        result
            .await
            .context("WG upstream pump stopped while forcing post-rebind handshake")?
    }

    /// Wait for the authenticated response to one exact locally initiated
    /// WireGuard handshake. Delayed responses to older initiations and cookie
    /// challenges cannot satisfy this proof.
    pub async fn wait_for_handshake_response(
        &self,
        receiver_index: u32,
        timeout: Duration,
    ) -> bool {
        wait_for_handshake_response(&self.handshake, receiver_index, timeout).await
    }

    /// Stop the pump and drop the tunnel state. Idempotent.
    pub async fn shutdown(mut self) {
        if let Some(reader) = self.tun_reader.take() {
            reader.abort();
            let _ = reader.await;
        }
        if let Some(writer) = self.tun_writer.take() {
            writer.abort();
            let _ = writer.await;
        }
        if let Some(pump) = self.pump.take() {
            pump.abort();
            let _ = pump.await;
        }
    }
}

async fn wait_for_handshake(handshake: &Arc<HandshakeState>, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if handshake.last_age.read().await.is_some() {
            return true;
        }
        let notified = handshake.completed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if handshake.last_age.read().await.is_some() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            _ = &mut notified => continue,
            _ = tokio::time::sleep(remaining) => {
                return handshake.last_age.read().await.is_some();
            },
        }
    }
}

async fn wait_for_handshake_response(
    handshake: &Arc<HandshakeState>,
    receiver_index: u32,
    timeout: Duration,
) -> bool {
    let expected = u64::from(receiver_index) + 1;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if handshake
            .last_completed_receiver_index
            .load(Ordering::Acquire)
            == expected
        {
            return true;
        }
        let notified = handshake.completed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if handshake
            .last_completed_receiver_index
            .load(Ordering::Acquire)
            == expected
        {
            return true;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            _ = &mut notified => continue,
            _ = tokio::time::sleep(remaining) => {
                return handshake
                    .last_completed_receiver_index
                    .load(Ordering::Acquire)
                    == expected;
            },
        }
    }
}

impl Drop for WgUpstreamRuntime {
    fn drop(&mut self) {
        if let Some(reader) = self.tun_reader.take() {
            reader.abort();
        }
        if let Some(writer) = self.tun_writer.take() {
            writer.abort();
        }
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

/// Subset of `WireGuardExitConfig` that meaningfully affects the
/// userspace tunnel — used to short-circuit reconcile if nothing
/// changed. We deliberately exclude DNS / MTU since they don't
/// require tearing the WG tunnel down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardExitFingerprint {
    pub enabled: bool,
    pub address: String,
    pub address_v6: String,
    pub private_key: String,
    pub peer_public_key: String,
    pub peer_preshared_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_secs: u16,
}

impl WireGuardExitFingerprint {
    pub fn from_config(config: &WireGuardExitConfig) -> Self {
        Self {
            enabled: config.enabled,
            address: config.address.clone(),
            address_v6: config.address_v6.clone(),
            private_key: config.private_key.clone(),
            peer_public_key: config.peer_public_key.clone(),
            peer_preshared_key: config.peer_preshared_key.clone(),
            endpoint: config.endpoint.clone(),
            allowed_ips: config.allowed_ips.clone(),
            persistent_keepalive_secs: config.persistent_keepalive_secs,
        }
    }
}

async fn run_pump(
    mut tunn: Tunn,
    udp: Arc<UdpSocket>,
    upstream: SocketAddr,
    mut tun_in_rx: Option<TunPacketRx>,
    tun_out_tx: Option<TunPacketTx>,
    handshake: Arc<HandshakeState>,
    mut control_rx: mpsc::UnboundedReceiver<WgUpstreamCommand>,
) {
    log_android_info(&format!(
        "wg-upstream: run_pump starting, upstream={upstream}"
    ));

    let mut udp_buf = vec![0u8; MAX_WG_PACKET];
    let mut out = vec![0u8; MAX_WG_PACKET];
    match tunn.format_handshake_initiation(&mut out, false) {
        TunnResult::WriteToNetwork(packet) => {
            let len = packet.len();
            match udp.send_to(packet, upstream).await {
                Ok(n) => log_android_info(&format!(
                    "wg-upstream: initial handshake init sent ({n}/{len} bytes to {upstream})"
                )),
                Err(error) => {
                    log_android_warn(&format!(
                        "wg-upstream: initial handshake send failed: {error}"
                    ));
                    tracing::warn!(?error, "wg-upstream: initial handshake send failed");
                }
            }
        }
        _ => {
            log_android_info("wg-upstream: format_handshake_initiation returned non-WriteToNetwork")
        }
    }

    // Recovery state: when boringtun's `update_timers` mysteriously
    // declines to send a keepalive (observed on iOS — session goes
    // idle, no keepalive fires, eventually decap returns
    // NoCurrentSession), force a re-handshake ourselves.
    let mut consecutive_decap_errors: u32 = 0;
    let mut last_self_keepalive = std::time::Instant::now();
    let mut ticker = interval(TIMER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tun_out_batch = Vec::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tun_out_batch.clear();
                {
                    let result = tunn.update_timers(&mut out);
                    handle_tunn_result(
                        &result,
                        &udp,
                        upstream,
                        tun_out_tx.as_ref(),
                        &mut tun_out_batch,
                    ).await;
                }
                drain_decapsulate(
                    &mut tunn,
                    &udp,
                    upstream,
                    tun_out_tx.as_ref(),
                    &mut out,
                    &mut tun_out_batch,
                ).await;
                if !flush_tun_out_batch(tun_out_tx.as_ref(), &mut tun_out_batch).await {
                    break;
                }
                let (age, _) = refresh_handshake_state(&tunn, &handshake, false).await;

                // Belt-and-braces keepalive: every 20s, if the
                // session is alive, push a 0-byte plaintext through
                // encapsulate(). boringtun emits a Transport message
                // that resets both sides' rekey timers. This compensates
                // for boringtun's `update_timers` not firing
                // persistent_keepalive reliably on iOS-suspended runtimes.
                if age.is_some() && last_self_keepalive.elapsed() >= Duration::from_secs(20) {
                    last_self_keepalive = std::time::Instant::now();
                    let ka_result = tunn.encapsulate(&[], &mut out);
                    if let TunnResult::WriteToNetwork(packet) = &ka_result {
                        log_android_info(&format!(
                            "wg-upstream: self-keepalive {} bytes",
                            packet.len()
                        ));
                    }
                    handle_tunn_result(
                        &ka_result,
                        &udp,
                        upstream,
                        tun_out_tx.as_ref(),
                        &mut tun_out_batch,
                    ).await;
                    if !flush_tun_out_batch(tun_out_tx.as_ref(), &mut tun_out_batch).await {
                        break;
                    }
                }
            }
            received = udp.recv_from(&mut udp_buf) => {
                tun_out_batch.clear();
                let (len, source) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        log_android_warn(&format!("wg-upstream: udp recv failed: {error}"));
                        tracing::warn!(?error, "wg-upstream: udp recv failed");
                        continue;
                    }
                };

                {
                    let result = tunn.decapsulate(Some(source.ip()), &udp_buf[..len], &mut out);
                    let completed_handshake_receiver =
                        completed_handshake_receiver_index(&udp_buf[..len], &result);
                    if matches!(result, TunnResult::Done) {
                        consecutive_decap_errors = 0;
                    } else if let TunnResult::Err(error) = &result {
                        consecutive_decap_errors = consecutive_decap_errors.saturating_add(1);
                        log_android_warn(&format!(
                            "wg-upstream: decap err {error:?} (run={consecutive_decap_errors})"
                        ));
                    } else {
                        consecutive_decap_errors = 0;
                    }
                    handle_tunn_result(
                        &result,
                        &udp,
                        upstream,
                        tun_out_tx.as_ref(),
                        &mut tun_out_batch,
                    ).await;
                    if let Some(receiver_index) = completed_handshake_receiver {
                        record_completed_handshake(&tunn, &handshake, receiver_index).await;
                    }
                }
                drain_decapsulate(
                    &mut tunn,
                    &udp,
                    upstream,
                    tun_out_tx.as_ref(),
                    &mut out,
                    &mut tun_out_batch,
                ).await;
                if !flush_tun_out_batch(tun_out_tx.as_ref(), &mut tun_out_batch).await {
                    break;
                }
                refresh_handshake_state(&tunn, &handshake, false).await;

                // 5+ consecutive decap errors means our session lost
                // sync with the upstream. Force a fresh handshake init
                // — boringtun will accept the next response and
                // install new keys.
                if consecutive_decap_errors >= 5 {
                    log_android_warn(
                        "wg-upstream: forcing re-handshake after persistent decap errors",
                    );
                    consecutive_decap_errors = 0;
                    if let TunnResult::WriteToNetwork(packet) =
                        tunn.format_handshake_initiation(&mut out, true)
                    {
                        let _ = udp.send_to(packet, upstream).await;
                    }
                }
            }
            packets = recv_tun_packets(&mut tun_in_rx) => {
                let Some(packets) = packets else {
                    break;
                };
                tun_out_batch.clear();
                for packet in packets {
                    let len = packet.len();
                    let result = tunn.encapsulate(&packet, &mut out);
                    if let TunnResult::Err(error) = &result {
                        log_android_warn(&format!("wg-upstream: encap err {error:?}"));
                    }
                    if let TunnResult::WriteToNetwork(packet) = &result
                        && len == 0
                    {
                        log_android_info(&format!(
                            "wg-upstream: encap keepalive -> {}B net",
                            packet.len()
                        ));
                    }
                    handle_tunn_result(
                        &result,
                        &udp,
                        upstream,
                        tun_out_tx.as_ref(),
                        &mut tun_out_batch,
                    ).await;
                }
                if !flush_tun_out_batch(tun_out_tx.as_ref(), &mut tun_out_batch).await {
                    break;
                }
            }
            Some(command) = control_rx.recv() => {
                match command {
                    WgUpstreamCommand::ForceHandshake { response } => {
                        let result =
                            force_new_handshake(&mut tunn, &udp, upstream, &mut out).await;
                        let _ = response.send(result);
                    }
                    #[cfg(target_os = "macos")]
                    WgUpstreamCommand::RebindInterface {
                        interface_index,
                        response,
                    } => {
                        let result = rebind_and_force_new_handshake(
                            &mut tunn,
                            &udp,
                            upstream,
                            interface_index,
                            &mut out,
                        ).await;
                        let _ = response.send(result);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
async fn rebind_and_force_new_handshake(
    tunn: &mut Tunn,
    udp: &UdpSocket,
    upstream: SocketAddr,
    interface_index: u32,
    out: &mut [u8],
) -> Result<u32> {
    bind_apple_udp_socket_to_interface(raw_udp_socket_fd(udp), upstream, interface_index)?;
    force_new_handshake(tunn, udp, upstream, out).await
}

async fn force_new_handshake(
    tunn: &mut Tunn,
    udp: &UdpSocket,
    upstream: SocketAddr,
    out: &mut [u8],
) -> Result<u32> {
    let packet = match tunn.format_handshake_initiation(out, true) {
        TunnResult::WriteToNetwork(packet) => packet,
        TunnResult::Err(error) => {
            return Err(anyhow!("format forced WG handshake: {error:?}"));
        }
        _ => return Err(anyhow!("forced WG handshake produced no network packet")),
    };
    let receiver_index = handshake_initiation_sender_index(packet)
        .ok_or_else(|| anyhow!("forced WG handshake produced an invalid initiation"))?;
    udp.send_to(packet, upstream)
        .await
        .with_context(|| format!("send forced WG handshake to {upstream}"))?;
    Ok(receiver_index)
}

async fn recv_tun_packets(tun_in_rx: &mut Option<TunPacketRx>) -> Option<TunPacketBatch> {
    match tun_in_rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn refresh_handshake_state(
    tunn: &Tunn,
    handshake: &Arc<HandshakeState>,
    completed_handshake: bool,
) -> (Option<Duration>, bool) {
    let (age, _, _, _, _) = tunn.stats();
    let became_live = {
        let mut last_age = handshake.last_age.write().await;
        let became_live = last_age.is_none() && age.is_some();
        *last_age = age;
        became_live
    };
    let newly_completed = completed_handshake && age.is_some();
    if became_live || newly_completed {
        handshake.completed.notify_waiters();
    }
    (age, newly_completed)
}

async fn record_completed_handshake(
    tunn: &Tunn,
    handshake: &Arc<HandshakeState>,
    receiver_index: u32,
) {
    let (age, completed) = refresh_handshake_state(tunn, handshake, true).await;
    if completed {
        handshake
            .last_completed_receiver_index
            .store(u64::from(receiver_index) + 1, Ordering::Release);
        handshake.completed.notify_waiters();
        log_android_info(&format!("wg-upstream: handshake completed, age={age:?}"));
    }
}

fn completed_handshake_receiver_index(incoming: &[u8], result: &TunnResult<'_>) -> Option<u32> {
    let receiver_index = match Tunn::parse_incoming_packet(incoming).ok()? {
        Packet::HandshakeResponse(response) => response.receiver_idx,
        _ => return None,
    };
    let TunnResult::WriteToNetwork(outgoing) = result else {
        return None;
    };
    matches!(
        Tunn::parse_incoming_packet(outgoing),
        Ok(Packet::PacketData(_))
    )
    .then_some(receiver_index)
}

fn handshake_initiation_sender_index(packet: &[u8]) -> Option<u32> {
    if !matches!(
        Tunn::parse_incoming_packet(packet),
        Ok(Packet::HandshakeInit(_))
    ) {
        return None;
    }
    packet
        .get(4..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
}

async fn handle_tunn_result(
    result: &TunnResult<'_>,
    udp: &Arc<UdpSocket>,
    upstream: SocketAddr,
    tun_out_tx: Option<&TunPacketTx>,
    tun_out_batch: &mut TunPacketBatch,
) {
    match result {
        TunnResult::Done => {}
        TunnResult::Err(error) => {
            log_android_warn(&format!("wg-upstream: tunn error {error:?}"));
        }
        TunnResult::WriteToNetwork(packet) => {
            if let Err(error) = udp.send_to(packet, upstream).await {
                log_android_warn(&format!(
                    "wg-upstream: udp send failed ({} bytes): {error}",
                    packet.len()
                ));
                tracing::warn!(?error, "wg-upstream: udp send failed");
            }
        }
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            let len = packet.len();
            if tun_out_tx.is_some() {
                tun_out_batch.push(packet.to_vec());
            } else {
                log_android_warn(&format!(
                    "wg-upstream: dropped {len}-byte plaintext (no tun_out_tx)"
                ));
            }
        }
    }
}

async fn flush_tun_out_batch(
    tun_out_tx: Option<&TunPacketTx>,
    packets: &mut TunPacketBatch,
) -> bool {
    if packets.is_empty() {
        return true;
    }
    let Some(tx) = tun_out_tx else {
        packets.clear();
        return true;
    };
    let next_batch = Vec::with_capacity(packets.capacity());
    let batch = std::mem::replace(packets, next_batch);
    if let Err(error) = tx.send(batch).await {
        log_android_warn(&format!("wg-upstream: tun_out batch send failed: {error}"));
        return false;
    }
    true
}

async fn drain_decapsulate(
    tunn: &mut Tunn,
    udp: &Arc<UdpSocket>,
    upstream: SocketAddr,
    tun_out_tx: Option<&TunPacketTx>,
    out: &mut [u8],
    tun_out_batch: &mut TunPacketBatch,
) {
    loop {
        let result = tunn.decapsulate(None, &[], out);
        match &result {
            TunnResult::Done | TunnResult::Err(_) => return,
            _ => handle_tunn_result(&result, udp, upstream, tun_out_tx, tun_out_batch).await,
        }
    }
}

// Platform-specific tun reader/writer tasks (POSIX TunSocket, Windows
// WinTun) live in nvpn, where the boringtun `device` feature
// is enabled. Mobile callers don't need them — they use
// `start_with_channels` and feed packets directly from the OS-managed
// tun (NEPacketTunnelProvider on iOS, VpnService on Android).

fn decode_private_key(encoded: &str) -> Result<StaticSecret> {
    let raw = decode_key_bytes(encoded.trim()).context("invalid WG private key")?;
    Ok(StaticSecret::from(raw))
}

fn decode_public_key(encoded: &str) -> Result<PublicKey> {
    let raw = decode_key_bytes(encoded.trim()).context("invalid WG public key")?;
    Ok(PublicKey::from(raw))
}

fn decode_optional_preshared_key(encoded: &str) -> Result<Option<[u8; 32]>> {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        decode_key_bytes(trimmed).context("invalid WG preshared key")?,
    ))
}

fn decode_key_bytes(encoded: &str) -> Result<[u8; 32]> {
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("base64 decode failed"))?;
    raw.try_into()
        .map_err(|_| anyhow!("WG key must be exactly 32 bytes"))
}

include!("wg_upstream_platform.rs");

#[cfg(test)]
include!("wg_upstream_tests.rs");
