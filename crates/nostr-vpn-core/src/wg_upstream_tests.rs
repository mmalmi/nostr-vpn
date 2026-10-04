#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_wireguard_exit_config;

    #[test]
    fn dual_stack_resolution_prefers_hotspot_stable_ipv4() {
        let ipv6 = "[2001:db8::45]:51820".parse().unwrap();
        let ipv4 = "192.0.2.45:51820".parse().unwrap();
        assert_eq!(select_roaming_stable_endpoint([ipv6, ipv4]), Some(ipv4));
        assert_eq!(select_roaming_stable_endpoint([ipv6]), Some(ipv6));
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
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

    fn ipv4_icmp_echo_request(src: [u8; 4], dst: [u8; 4], seq: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[1] = 0;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        let header_checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

        packet[20] = 8;
        packet[21] = 0;
        packet[24..26].copy_from_slice(&0x4e56u16.to_be_bytes());
        packet[26..28].copy_from_slice(&seq.to_be_bytes());
        let icmp_checksum = internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
        packet
    }

    fn ipv4_icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
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
        let header_checksum = internet_checksum(&reply[..ihl]);
        reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());

        reply[ihl] = 0;
        reply[ihl + 2] = 0;
        reply[ihl + 3] = 0;
        let icmp_checksum = internet_checksum(&reply[ihl..]);
        reply[ihl + 2..ihl + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
        Some(reply)
    }

    #[test]
    fn upstream_udp_bind_uses_loopback_for_loopback_peer() {
        assert_eq!(
            udp_bind_addr_for_upstream("127.0.0.1:51820".parse().unwrap()),
            "127.0.0.1:0".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            udp_bind_addr_for_upstream("[::1]:51820".parse().unwrap()),
            "[::1]:0".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn upstream_udp_bind_preserves_non_loopback_ip_family() {
        assert_eq!(
            udp_bind_addr_for_upstream("198.51.100.10:51820".parse().unwrap()),
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            udp_bind_addr_for_upstream("[2001:db8::1]:51820".parse().unwrap()),
            "[::]:0".parse::<SocketAddr>().unwrap()
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn apple_interface_binding_sets_both_ip_family_options() {
        let interface_name = b"lo0\0";
        let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr().cast()) };
        assert_ne!(interface_index, 0, "lo0 interface index");

        for upstream in ["127.0.0.1:51820", "[::1]:51820"] {
            let upstream = upstream.parse::<SocketAddr>().unwrap();
            let socket = UdpSocket::bind(udp_bind_addr_for_upstream(upstream))
                .await
                .unwrap();
            let socket_fd = raw_udp_socket_fd(&socket);
            assert!(
                bind_apple_udp_socket_to_interface(socket_fd, upstream, 0).is_err(),
                "zero must never clear an active interface binding"
            );
            bind_apple_udp_socket_to_interface(socket_fd, upstream, interface_index).unwrap();

            let (level, option) = match upstream {
                SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
                SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
            };
            let mut actual = 0 as c_int;
            let mut length = std::mem::size_of_val(&actual) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    socket_fd,
                    level,
                    option,
                    (&mut actual as *mut c_int).cast(),
                    &mut length,
                )
            };
            assert_eq!(result, 0, "getsockopt for {upstream}");
            assert_eq!(actual as u32, interface_index, "binding for {upstream}");
        }
    }

    #[test]
    fn only_authenticated_handshake_completion_matches_the_expected_receiver() {
        let receiver_index = 0x1234_5678_u32;
        let mut response = vec![0_u8; 92];
        response[0..4].copy_from_slice(&2_u32.to_le_bytes());
        response[8..12].copy_from_slice(&receiver_index.to_le_bytes());

        let mut cookie = vec![0_u8; 64];
        cookie[0..4].copy_from_slice(&3_u32.to_le_bytes());
        let cookie_result = TunnResult::WriteToNetwork(cookie.as_mut_slice());
        assert_eq!(
            completed_handshake_receiver_index(&response, &cookie_result),
            None,
            "a cookie challenge is not a completed handshake"
        );

        let mut keepalive = vec![0_u8; 32];
        keepalive[0..4].copy_from_slice(&4_u32.to_le_bytes());
        let keepalive_result = TunnResult::WriteToNetwork(keepalive.as_mut_slice());
        assert_eq!(
            completed_handshake_receiver_index(&response, &keepalive_result),
            Some(receiver_index)
        );
    }

    #[test]
    fn forced_handshake_token_is_the_initiation_sender_index() {
        let sender_index = 0x8765_4321_u32;
        let mut initiation = vec![0_u8; 148];
        initiation[0..4].copy_from_slice(&1_u32.to_le_bytes());
        initiation[4..8].copy_from_slice(&sender_index.to_le_bytes());
        assert_eq!(
            handshake_initiation_sender_index(&initiation),
            Some(sender_index)
        );
    }

    fn random_keypair() -> (StaticSecret, PublicKey, String, String) {
        // Deterministic but unique per call. boringtun + x25519-dalek
        // accept any 32-byte little-endian secret; ChaCha20-style
        // clamping is applied internally on use.
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (nanos as u8).wrapping_add(i as u8 * 7);
        }
        let private = StaticSecret::from(bytes);
        let public = PublicKey::from(&private);
        let priv_b64 = STANDARD.encode(private.to_bytes());
        let pub_b64 = STANDARD.encode(public.as_bytes());
        (private, public, priv_b64, pub_b64)
    }

    /// Stand up a paired Tunn on a real UDP port acting as the upstream
    /// "server"; verifies both the initial and forced handshakes complete
    /// without replacing the live runtime or its UDP socket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn handshake_refreshes_without_runtime_or_socket_restart() {
        let (_, _client_pub, client_priv_b64, _) = random_keypair();
        let (server_priv_obj, _, _, server_pub_b64) = random_keypair();

        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_socket = Arc::new(server_socket);

        let mut server_tunn = Tunn::new(
            server_priv_obj,
            PublicKey::from(&decode_private_key(&client_priv_b64).unwrap()),
            None,
            Some(25),
            2,
            None,
        );

        let server_socket_pump = server_socket.clone();
        let server_pump = tokio::spawn(async move {
            let mut udp_buf = vec![0u8; MAX_WG_PACKET];
            for _ in 0..32 {
                let (n, src) = match tokio::time::timeout(
                    Duration::from_millis(500),
                    server_socket_pump.recv_from(&mut udp_buf),
                )
                .await
                {
                    Ok(Ok(value)) => value,
                    _ => continue,
                };
                let mut out = vec![0u8; MAX_WG_PACKET];
                let to_send = match server_tunn.decapsulate(Some(src.ip()), &udp_buf[..n], &mut out)
                {
                    TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                    _ => None,
                };
                if let Some(bytes) = to_send {
                    let _ = server_socket_pump.send_to(&bytes, src).await;
                }
                loop {
                    let mut drain_buf = vec![0u8; MAX_WG_PACKET];
                    let drained = match server_tunn.decapsulate(None, &[], &mut drain_buf) {
                        TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                        _ => None,
                    };
                    let Some(bytes) = drained else { break };
                    let _ = server_socket_pump.send_to(&bytes, src).await;
                }
            }
        });

        let cfg_text = format!(
            "[Interface]\nPrivateKey = {client_priv_b64}\nAddress = 10.99.99.2/32\n\n[Peer]\nPublicKey = {server_pub_b64}\nEndpoint = {server_addr}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n"
        );
        let cfg = parse_wireguard_exit_config(&cfg_text).expect("parse WG config");

        let runtime = WgUpstreamRuntime::start_handshake_only(&cfg)
            .await
            .expect("start runtime");
        let handshake = runtime.handshake_observer();
        #[cfg(target_os = "macos")]
        let mut runtime = runtime;
        let ok = runtime.wait_for_handshake(Duration::from_secs(10)).await;
        assert!(
            ok,
            "expected handshake to complete against the paired responder"
        );
        assert!(handshake.has_completed_handshake());

        let original_socket_fd = runtime.udp_socket_fd();
        let receiver_index = runtime
            .force_handshake()
            .await
            .expect("force a fresh handshake without restarting the WG runtime");
        assert_eq!(
            runtime.udp_socket_fd(),
            original_socket_fd,
            "underlay refresh must preserve the live WG socket"
        );
        assert!(
            runtime.is_running(),
            "underlay refresh must preserve the live WG runtime"
        );
        assert!(
            runtime
                .wait_for_handshake_response(receiver_index, Duration::from_secs(10))
                .await,
            "expected the exact forced handshake response on the live WG socket"
        );

        #[cfg(target_os = "macos")]
        {
            let interface_name = b"lo0\0";
            let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr().cast()) };
            assert_ne!(interface_index, 0, "lo0 interface index");
            let receiver_index = runtime
                .rebind_interface(interface_index)
                .await
                .expect("rebind WG socket and force handshake");
            assert!(
                runtime
                    .wait_for_handshake_response(receiver_index, Duration::from_secs(10))
                    .await,
                "expected the forced handshake response after live interface rebind"
            );
        }

        runtime.shutdown().await;
        server_pump.abort();
        let _ = server_pump.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn channels_round_trip_plaintext_packets_against_paired_responder() {
        let (_, _client_pub, client_priv_b64, _) = random_keypair();
        let (server_priv_obj, _, _, server_pub_b64) = random_keypair();

        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_socket = Arc::new(server_socket);

        let mut server_tunn = Tunn::new(
            server_priv_obj,
            PublicKey::from(&decode_private_key(&client_priv_b64).unwrap()),
            None,
            Some(25),
            2,
            None,
        );

        let request = ipv4_icmp_echo_request([10, 99, 99, 2], [10, 99, 99, 1], 7);
        let expected_reply = ipv4_icmp_echo_reply(&request).expect("reply packet");

        let server_socket_pump = server_socket.clone();
        let server_pump = tokio::spawn(async move {
            let mut udp_buf = vec![0u8; MAX_WG_PACKET];
            for _ in 0..64 {
                let (n, src) = match tokio::time::timeout(
                    Duration::from_millis(500),
                    server_socket_pump.recv_from(&mut udp_buf),
                )
                .await
                {
                    Ok(Ok(value)) => value,
                    _ => continue,
                };
                let mut out = vec![0u8; MAX_WG_PACKET];
                let action = match server_tunn.decapsulate(Some(src.ip()), &udp_buf[..n], &mut out)
                {
                    TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        let reply = ipv4_icmp_echo_reply(packet).expect("ICMP echo request");
                        let mut reply_out = vec![0u8; MAX_WG_PACKET];
                        match server_tunn.encapsulate(&reply, &mut reply_out) {
                            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                if let Some(bytes) = action {
                    let _ = server_socket_pump.send_to(&bytes, src).await;
                }
                loop {
                    let mut drain_buf = vec![0u8; MAX_WG_PACKET];
                    let drained = match server_tunn.decapsulate(None, &[], &mut drain_buf) {
                        TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                        _ => None,
                    };
                    let Some(bytes) = drained else { break };
                    let _ = server_socket_pump.send_to(&bytes, src).await;
                }
            }
        });

        let cfg_text = format!(
            "[Interface]\nPrivateKey = {client_priv_b64}\nAddress = 10.99.99.2/32\n\n[Peer]\nPublicKey = {server_pub_b64}\nEndpoint = {server_addr}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 1\n"
        );
        let cfg = parse_wireguard_exit_config(&cfg_text).expect("parse WG config");
        let (tun_in_tx, tun_in_rx) = mpsc::channel(8);
        let (tun_out_tx, mut tun_out_rx) = mpsc::channel(8);

        let runtime = WgUpstreamRuntime::start_with_channels(&cfg, tun_in_rx, tun_out_tx)
            .await
            .expect("start runtime");
        let ok = runtime.wait_for_handshake(Duration::from_secs(10)).await;
        assert!(
            ok,
            "expected handshake to complete against the paired responder"
        );

        tun_in_tx
            .send(vec![request])
            .await
            .expect("send plaintext packet into tunnel");
        let actual_replies = tokio::time::timeout(Duration::from_secs(10), tun_out_rx.recv())
            .await
            .expect("reply timeout")
            .expect("reply channel closed");
        let actual_reply = actual_replies.into_iter().next().expect("reply packet");
        runtime.shutdown().await;
        server_pump.abort();
        let _ = server_pump.await;

        assert_eq!(actual_reply, expected_reply);
    }
}
