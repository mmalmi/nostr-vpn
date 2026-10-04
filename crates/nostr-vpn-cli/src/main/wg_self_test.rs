#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_wg_upstream_test(args: WgUpstreamTestArgs) -> Result<()> {
    use std::time::Duration;

    if args.self_test {
        return run_wg_upstream_self_test(args).await;
    }

    let config_file = args
        .config_file
        .as_ref()
        .ok_or_else(|| anyhow!("--config-file is required unless --self-test is set"))?;
    let raw = std::fs::read_to_string(config_file)
        .with_context(|| format!("read WG config file {}", config_file.display()))?;
    let cfg = parse_wireguard_exit_config(&raw)
        .with_context(|| format!("parse WG config file {}", config_file.display()))?;

    let timeout = Duration::from_secs(args.timeout_secs);

    if args.replace_default {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return run_wg_upstream_replace_default(&cfg, &args, timeout).await;
        #[cfg(target_os = "windows")]
        return run_wg_upstream_windows_replace_default(&cfg, &args, timeout).await;
    }

    if let Some(scoped_host) = args.scoped_host {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return run_wg_upstream_scoped_host(&cfg, &args, timeout, scoped_host).await;

        #[cfg(target_os = "windows")]
        return run_wg_upstream_windows_scoped_host(&cfg, &args, timeout, scoped_host).await;
    }

    run_wg_upstream_handshake_only(&cfg, timeout, args.timeout_secs).await
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_wg_upstream_self_test(args: WgUpstreamTestArgs) -> Result<()> {
    let (cfg, server) = start_wg_upstream_self_test_server().await?;
    let timeout = std::time::Duration::from_secs(args.timeout_secs);
    let result = if args.replace_default {
        let mut args = args;
        args.probe_target
            .get_or_insert(IpAddr::V4(Ipv4Addr::new(10, 99, 99, 1)));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            run_wg_upstream_replace_default(&cfg, &args, timeout).await
        }
        #[cfg(target_os = "windows")]
        {
            run_wg_upstream_windows_replace_default(&cfg, &args, timeout).await
        }
    } else if let Some(scoped_host) = args
        .scoped_host
        .or(Some(IpAddr::V4(Ipv4Addr::new(10, 99, 99, 1))))
    {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            run_wg_upstream_scoped_host(&cfg, &args, timeout, scoped_host).await
        }
        #[cfg(target_os = "windows")]
        {
            run_wg_upstream_windows_scoped_host(&cfg, &args, timeout, scoped_host).await
        }
    } else {
        run_wg_upstream_handshake_only(&cfg, timeout, args.timeout_secs).await
    };
    server.shutdown().await;
    result
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct WgSelfTestServer {
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl WgSelfTestServer {
    async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn start_wg_upstream_self_test_server() -> Result<(
    nostr_vpn_core::config::WireGuardExitConfig,
    WgSelfTestServer,
)> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use boringtun::noise::{Tunn, TunnResult};
    use nostr_vpn_core::wg_upstream::MAX_WG_PACKET;
    use tokio::net::UdpSocket;

    let (client_private, client_public) = wg_self_test_keypair(0x11);
    let (server_private, server_public) = wg_self_test_keypair(0x51);
    let client_private_b64 = STANDARD.encode(client_private.to_bytes());
    let server_public_b64 = STANDARD.encode(server_public.as_bytes());

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .context("bind local WG self-test responder")?;
    let server_addr = socket
        .local_addr()
        .context("read self-test responder addr")?;
    let server_socket = std::sync::Arc::new(socket);
    let handle = tokio::spawn(async move {
        let mut server_tunn = Tunn::new(server_private, client_public, None, Some(25), 2, None);
        let mut udp_buf = vec![0u8; MAX_WG_PACKET];
        loop {
            let Ok((n, src)) = server_socket.recv_from(&mut udp_buf).await else {
                continue;
            };
            let mut out = vec![0u8; MAX_WG_PACKET];
            let action = match server_tunn.decapsulate(Some(src.ip()), &udp_buf[..n], &mut out) {
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                TunnResult::WriteToTunnelV4(packet, _) => {
                    let reply = wg_self_test_icmp_echo_reply(packet)
                        .unwrap_or_else(|| wg_self_test_ipv4_echo(packet));
                    let mut reply_out = vec![0u8; MAX_WG_PACKET];
                    match server_tunn.encapsulate(&reply, &mut reply_out) {
                        TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(bytes) = action {
                let _ = server_socket.send_to(&bytes, src).await;
            }
            loop {
                let mut drain_buf = vec![0u8; MAX_WG_PACKET];
                let drained = match server_tunn.decapsulate(None, &[], &mut drain_buf) {
                    TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                    _ => None,
                };
                let Some(bytes) = drained else { break };
                let _ = server_socket.send_to(&bytes, src).await;
            }
        }
    });

    let cfg_text = format!(
        "[Interface]\nPrivateKey = {client_private_b64}\nAddress = 10.99.99.2/32\nMTU = 1420\n\n[Peer]\nPublicKey = {server_public_b64}\nEndpoint = {server_addr}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n"
    );
    let cfg =
        parse_wireguard_exit_config(&cfg_text).context("parse generated WG self-test config")?;
    Ok((cfg, WgSelfTestServer { handle }))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn wg_self_test_keypair(
    seed: u8,
) -> (
    boringtun::x25519::StaticSecret,
    boringtun::x25519::PublicKey,
) {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add((idx as u8).wrapping_mul(13));
    }
    let private = boringtun::x25519::StaticSecret::from(bytes);
    let public = boringtun::x25519::PublicKey::from(&private);
    (private, public)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn wg_self_test_ipv4_echo(packet: &[u8]) -> Vec<u8> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return packet.to_vec();
    }
    let mut reply = packet.to_vec();
    let src = [reply[12], reply[13], reply[14], reply[15]];
    let dst = [reply[16], reply[17], reply[18], reply[19]];
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    reply
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn wg_self_test_icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 28 || request[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(request[0] & 0x0f) * 4;
    if ihl < 20 || request.len() < ihl + 8 || request[9] != 1 || request[ihl] != 8 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([request[2], request[3]]));
    if total_len < ihl + 8 || total_len > request.len() {
        return None;
    }

    let mut reply = request[..total_len].to_vec();
    reply[8] = 64;
    reply[10] = 0;
    reply[11] = 0;
    let src = [reply[12], reply[13], reply[14], reply[15]];
    let dst = [reply[16], reply[17], reply[18], reply[19]];
    reply[12..16].copy_from_slice(&dst);
    reply[16..20].copy_from_slice(&src);
    let header_checksum = wg_self_test_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    reply[ihl] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_checksum = wg_self_test_checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(reply)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn wg_self_test_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let Some(&byte) = remainder.first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_wg_upstream_handshake_only(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    timeout: std::time::Duration,
    timeout_secs: u64,
) -> Result<()> {
    use crate::wg_upstream_runtime::WgUpstreamRuntime;

    let runtime = WgUpstreamRuntime::start_handshake_only(cfg)
        .await
        .context("start userspace WG runtime")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");
    let ok = runtime.wait_for_handshake(timeout).await;
    runtime.shutdown().await;
    if ok {
        println!("wg-upstream-test: handshake completed");
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {timeout_secs}s"
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_wg_upstream_scoped_host(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
    scoped_host: std::net::IpAddr,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_scoped_host_route;
    use boringtun::device::tun::TunSocket;
    use std::sync::Arc;
    use std::time::Duration;

    // Scoped-host mode: bring up a tun, install a single host route
    // through it, then send real pings through the WG tunnel.
    // Refuse to scope the upstream endpoint itself — that would make
    // the encrypted UDP loop back into the WG iface and never escape.
    if let Some(endpoint_host) = cfg.endpoint.split(':').next()
        && let Ok(endpoint_ip) = endpoint_host.parse::<std::net::IpAddr>()
        && endpoint_ip == scoped_host
    {
        return Err(anyhow!(
            "--scoped-host {scoped_host} matches the WG upstream endpoint; \
             that would route the encrypted UDP back into the tunnel"
        ));
    }

    let tun_name = args
        .tun_name
        .clone()
        .unwrap_or_else(default_wg_test_tun_name);
    let tun = TunSocket::new(&tun_name)
        .with_context(|| format!("create tun device {tun_name}"))?
        .set_non_blocking()
        .context("set tun non-blocking")?;
    let actual_iface = tun
        .name()
        .context("read assigned tun interface name (probably needs root)")?;
    let tun = Arc::new(tun);

    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    let _route = apply_scoped_host_route(&actual_iface, &cfg.address, scoped_host, mtu)
        .with_context(|| {
            format!(
                "install scoped host route for {scoped_host} via {actual_iface} \
                 (probably needs root)"
            )
        })?;
    println!(
        "wg-upstream-test: tun {actual_iface} up at {} mtu {mtu}, \
         host route {scoped_host} via {actual_iface} installed",
        cfg.address.trim_end_matches("/32")
    );

    let runtime = crate::wg_upstream_runtime::start_wg_runtime_with_posix_tun(cfg, tun.clone())
        .await
        .context("start userspace WG runtime with tun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    let handshake_ok = runtime.wait_for_handshake(timeout).await;
    if !handshake_ok {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, pinging {scoped_host}…");

    let mut ping = tokio::process::Command::new("ping");
    ping.arg("-c").arg(args.ping_count.to_string());
    #[cfg(target_os = "linux")]
    ping.arg("-W").arg("2");
    #[cfg(target_os = "macos")]
    ping.arg("-W").arg("2000"); // macOS ping -W is in milliseconds
    ping.arg(scoped_host.to_string());
    let status = ping.status().await.context("spawn ping")?;
    let ping_ok = status.success();

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding tunnel up for {}s…",
            args.hold_secs
        );
        tokio::time::sleep(Duration::from_secs(args.hold_secs)).await;
    }

    runtime.shutdown().await;
    drop(_route);
    // tun (Arc<TunSocket>) drops here when the last ref goes; on macOS
    // closing the utun fd auto-removes the device. Linux's tun device
    // hangs around if anyone else has it open, so name collisions on a
    // re-run will surface as ENXIO from TunSocket::new.

    if ping_ok {
        println!(
            "wg-upstream-test: pinged {scoped_host} successfully through {actual_iface} \
             via WG upstream {upstream}"
        );
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: ping {scoped_host} failed (handshake completed, \
             but no replies came back through the tunnel)"
        ))
    }
}

#[cfg(target_os = "windows")]
async fn run_wg_upstream_windows_scoped_host(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
    scoped_host: std::net::IpAddr,
) -> Result<()> {
    use crate::wg_upstream_runtime::{
        apply_windows_scoped_host_route, start_wg_runtime_with_wintun,
    };
    use std::sync::Arc;
    use std::time::Duration;

    if let Some(endpoint_host) = cfg.endpoint.split(':').next()
        && let Ok(endpoint_ip) = endpoint_host.parse::<std::net::IpAddr>()
        && endpoint_ip == scoped_host
    {
        return Err(anyhow!(
            "--scoped-host {scoped_host} matches the WG upstream endpoint; \
             that would route the encrypted UDP back into the tunnel"
        ));
    }

    let adapter_name = if cfg.interface.trim().is_empty() {
        "nvpn-wg-test".to_string()
    } else {
        cfg.interface.clone()
    };
    let wintun = nostr_vpn_wintun::load_wintun().context("load wintun.dll for WG upstream test")?;
    let adapter = wintun::Adapter::open(&wintun, &adapter_name)
        .or_else(|_| wintun::Adapter::create(&wintun, &adapter_name, "NostrVPN", None))
        .with_context(|| format!("open or create wintun adapter {adapter_name}"))?;

    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    adapter
        .set_mtu(mtu as usize)
        .with_context(|| format!("set MTU on wintun adapter {adapter_name}"))?;
    let parsed_address = crate::windows_tunnel::windows_interface_address(&cfg.address)?;
    adapter
        .set_network_addresses_tuple(
            parsed_address.address.into(),
            parsed_address.mask.into(),
            None,
        )
        .with_context(|| format!("set address on wintun adapter {adapter_name}"))?;
    let interface_index = adapter
        .get_adapter_index()
        .with_context(|| format!("read interface index for {adapter_name}"))?;
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .with_context(|| format!("start wintun session for {adapter_name}"))?,
    );
    let _route =
        apply_windows_scoped_host_route(interface_index, scoped_host).with_context(|| {
            format!(
                "install scoped host route for {scoped_host} via {adapter_name} \
             (probably needs Administrator)"
            )
        })?;
    println!(
        "wg-upstream-test: wintun {adapter_name} up at {} mtu {mtu}, \
         host route {scoped_host} via interface {interface_index} installed",
        cfg.address.trim_end_matches("/32")
    );

    let runtime = start_wg_runtime_with_wintun(cfg, session.clone())
        .await
        .context("start userspace WG runtime on wintun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    if !runtime.wait_for_handshake(timeout).await {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, pinging {scoped_host}...");

    let source_ip = parsed_address.address.to_string();
    let mut ping_result = Ok(false);
    for attempt in 1..=5 {
        if attempt > 1 {
            println!("wg-upstream-test: retrying probe ping through the WG tunnel...");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let mut ping = tokio::process::Command::new("ping");
        ping.arg("-n")
            .arg(args.ping_count.to_string())
            .arg("-w")
            .arg("3000")
            .arg("-S")
            .arg(&source_ip)
            .arg(scoped_host.to_string());
        let status = match ping.status().await.context("spawn ping") {
            Ok(status) => status,
            Err(error) => {
                ping_result = Err(error);
                break;
            }
        };
        if status.success() {
            ping_result = Ok(true);
            break;
        }
    }
    let ping_ok = ping_result?;

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding tunnel up for {}s - Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    runtime.shutdown().await;
    drop(_route);

    if ping_ok {
        println!(
            "wg-upstream-test: pinged {scoped_host} successfully through {adapter_name} \
             via WG upstream {upstream}"
        );
        Ok(())
    } else {
        Err(anyhow!(
            "wg-upstream-test: ping {scoped_host} failed (handshake completed, \
             but no replies came back through the tunnel)"
        ))
    }
}

#[cfg(target_os = "windows")]
async fn run_wg_upstream_windows_replace_default(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_daemon_wg_upstream;
    use std::time::Duration;

    let mut handle = apply_daemon_wg_upstream(cfg, timeout)
        .await
        .context("bring up Windows WG upstream and swap default route")?;
    println!(
        "wg-upstream-test: handshake completed, default route now via {}, upstream {}",
        handle.iface,
        handle.upstream.ip()
    );

    let probe_result = if let Some(probe) = args.probe_target {
        let mut result = Ok(false);
        for attempt in 1..=3 {
            if attempt > 1 {
                println!("wg-upstream-test: retrying probe ping through the WG tunnel...");
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                println!("wg-upstream-test: pinging {probe} through the WG tunnel...");
            }
            let mut ping = tokio::process::Command::new("ping");
            ping.arg("-n")
                .arg(args.ping_count.to_string())
                .arg("-w")
                .arg("3000")
                .arg(probe.to_string());
            let status = match ping.status().await.context("spawn ping") {
                Ok(status) => status,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            };
            if status.success() {
                result = Ok(true);
                break;
            }
        }
        result
    } else {
        Ok(true)
    };

    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding the tunnel up for {}s - Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    handle
        .cleanup()
        .await
        .context("restore Windows WG upstream routes")?;

    if !probe_result? {
        return Err(anyhow!(
            "wg-upstream-test: probe ping failed (handshake completed and \
             default route swapped, but no replies came back through the tunnel)"
        ));
    }
    println!(
        "wg-upstream-test: Windows full default-route mode worked end-to-end. \
         Default route restored."
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_wg_upstream_replace_default(
    cfg: &nostr_vpn_core::config::WireGuardExitConfig,
    args: &WgUpstreamTestArgs,
    timeout: std::time::Duration,
) -> Result<()> {
    use crate::wg_upstream_runtime::apply_full_default_route;
    use boringtun::device::tun::TunSocket;
    use std::sync::Arc;
    use std::time::Duration;

    // 1. Bring up the tun. No routing impact yet — the host is fine
    // even if the WG handshake fails.
    let tun_name = args
        .tun_name
        .clone()
        .unwrap_or_else(default_wg_test_tun_name);
    let tun = TunSocket::new(&tun_name)
        .with_context(|| format!("create tun device {tun_name}"))?
        .set_non_blocking()
        .context("set tun non-blocking")?;
    let actual_iface = tun
        .name()
        .context("read assigned tun interface name (probably needs root)")?;
    let tun = Arc::new(tun);

    // 2. Start the WG runtime against the upstream. The first packet
    // from the runtime is the handshake init; until we wait for it
    // there's no proof the upstream is reachable / our config is
    // valid.
    let runtime = crate::wg_upstream_runtime::start_wg_runtime_with_posix_tun(cfg, tun.clone())
        .await
        .context("start userspace WG runtime with tun")?;
    let upstream = runtime.upstream();
    println!("wg-upstream-test: probing handshake to {upstream}");

    // 3. Watchdog. wait_for_handshake yields on a Notify; if no
    // handshake by the deadline, we shut down without ever touching
    // the routing table. The host's internet stays up.
    let handshake_ok = runtime.wait_for_handshake(timeout).await;
    if !handshake_ok {
        runtime.shutdown().await;
        return Err(anyhow!(
            "wg-upstream-test: no handshake from {upstream} within {}s; \
             routing table NOT modified",
            args.timeout_secs
        ));
    }
    println!("wg-upstream-test: handshake completed, swapping default route…");

    // 4. Now and only now do we swap the default route. The returned
    // guard restores the original default + deletes the bypass on
    // Drop, so a panic / Ctrl-C from this point on still recovers.
    let mtu = if cfg.mtu > 0 { cfg.mtu } else { 1420 };
    let mut full_route =
        apply_full_default_route(&actual_iface, &cfg.address, upstream, mtu, None)
        .with_context(|| {
            format!(
                "swap default route via {actual_iface} (probably needs root). \
                 If you see 'Network is unreachable' below, the original default \
                 was already restored — your internet should be back."
            )
        })?;
    println!(
        "wg-upstream-test: default route now via {actual_iface}, bypass for {} via captured underlay",
        upstream.ip()
    );

    // 5. Optional probe — verify data plane round-trips through WG.
    let probe_ok = if let Some(probe) = args.probe_target {
        println!("wg-upstream-test: pinging {probe} through the WG tunnel…");
        let mut ping = tokio::process::Command::new("ping");
        ping.arg("-c").arg(args.ping_count.to_string());
        #[cfg(target_os = "linux")]
        ping.arg("-W").arg("2");
        #[cfg(target_os = "macos")]
        ping.arg("-W").arg("2000");
        ping.arg(probe.to_string());
        let status = ping.status().await.context("spawn ping")?;
        status.success()
    } else {
        true
    };

    // 6. Hold the tunnel up so the user can curl ifconfig.me / inspect
    // routes / look in tcpdump. Wrap the sleep in a select! with
    // Ctrl-C so that interrupting the command still falls through to
    // the route-revert path below (rather than aborting the runtime
    // with the default route still pointed at the WG tun).
    if args.hold_secs > 0 {
        println!(
            "wg-upstream-test: holding the tunnel up for {}s — Ctrl-C to revert sooner",
            args.hold_secs
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.hold_secs)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("wg-upstream-test: Ctrl-C received, reverting now");
            }
        }
    }

    // 7. Cleanup. Order matters here:
    //   a. Restore default route + delete bypass (FullDefaultRoute
    //      Drop). Critical to do this BEFORE the runtime stops, so the
    //      few seconds of "WG runtime stopping" don't have the kernel
    //      trying to push outgoing packets through a torn-down WG tun.
    //   b. Stop the runtime (closes UDP socket, the boringtun coordinator
    //      task exits).
    //   c. Drop the tun (utun auto-removes when its fd closes; Linux
    //      tun lingers but its routes are already gone).
    if let Err(error) = full_route.revert() {
        eprintln!("wg-upstream-test: WARNING — route revert failed: {error}");
    }
    drop(full_route);
    runtime.shutdown().await;
    drop(tun);

    if !probe_ok {
        return Err(anyhow!(
            "wg-upstream-test: probe ping failed (handshake completed and \
             default route swapped, but no replies came back through the tunnel)"
        ));
    }
    println!(
        "wg-upstream-test: full default-route mode worked end-to-end. \
         Default route restored."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_wg_test_tun_name() -> String {
    "nvpn-wg-test".to_string()
}

#[cfg(target_os = "macos")]
fn default_wg_test_tun_name() -> String {
    // boringtun's macOS TunSocket::new requires the name to start with
    // "utun". Plain "utun" tells the kernel to pick the next available
    // index; the actual assigned name is read back via tun.name().
    "utun".to_string()
}

pub(crate) fn runtime_exit_node_default_routes() -> Vec<String> {
    runtime_supported_advertised_routes(exit_node_default_routes())
}

pub(crate) fn runtime_effective_advertised_routes(app: &AppConfig) -> Vec<String> {
    runtime_supported_advertised_routes(app.effective_advertised_routes())
}

fn runtime_supported_advertised_routes(routes: Vec<String>) -> Vec<String> {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        routes.into_iter().filter(|route| route != "::/0").collect()
    }

    #[cfg(all(
        not(target_os = "linux"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    {
        routes
            .into_iter()
            .filter(|route| !is_default_exit_node_route(route))
            .collect()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn runtime_local_exit_forwarding_routes(app: &AppConfig) -> Vec<String> {
    let mut routes = runtime_effective_advertised_routes(app);
    if app.paid_exit.enabled && app.paid_exit_seller_egress().is_ok() {
        routes.extend(runtime_exit_node_default_routes());
    }
    routes.sort();
    routes.dedup();
    routes
}
