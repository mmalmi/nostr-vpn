use super::super::tests::{
    available_udp_port, direct_udp_endpoint_config_many, wait_for_fips_peer,
};
use super::*;
use nostr_sdk::prelude::{Keys, ToBech32};

async fn endpoint(
    keys: &Keys,
    port: u16,
    links: &[(&str, u16, bool)],
    routes: Vec<FipsMeshPeerConfig>,
) -> Arc<FipsPrivateMeshRuntime> {
    Arc::new(
        FipsPrivateMeshRuntime::bind_with_config_scoped(
            keys.secret_key().to_bech32().unwrap(),
            None,
            routes,
            direct_udp_endpoint_config_many(port, links),
            vec!["10.44.1.2/32".into()],
            vec![],
            vec![],
        )
        .await
        .unwrap(),
    )
}

fn tcp(src: SocketAddrV4, dst: SocketAddrV4) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[3] = 40;
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&src.ip().octets());
    bytes[16..20].copy_from_slice(&dst.ip().octets());
    bytes[20..22].copy_from_slice(&src.port().to_be_bytes());
    bytes[22..24].copy_from_slice(&dst.port().to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 2;
    bytes
}

async fn receive(runtime: &FipsPrivateMeshRuntime) -> Vec<FipsEndpointDirectPacketRun> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Ok(runs) = runtime.direct_endpoint_rx.try_recv(32) {
                return runs;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("FIPS peer received data")
}

#[test]
fn candidate_probe_and_ordinary_tcp_use_different_authenticated_exits() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(two_sellers());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn endpoints() -> (
    Arc<FipsPrivateMeshRuntime>,
    Arc<FipsPrivateMeshRuntime>,
    Arc<FipsPrivateMeshRuntime>,
    PeerIdentity,
    PeerIdentity,
) {
    let buyer = Keys::generate();
    let old = Keys::generate();
    let new = Keys::generate();
    let npub = |keys: &Keys| keys.public_key().to_bech32().unwrap();
    let (buyer_id, old_id, new_id) = (npub(&buyer), npub(&old), npub(&new));
    let (buyer_port, old_port, new_port) = (
        available_udp_port(),
        available_udp_port(),
        available_udp_port(),
    );
    let incumbent = endpoint(&old, old_port, &[(&buyer_id, buyer_port, false)], vec![]).await;
    let candidate = endpoint(&new, new_port, &[(&buyer_id, buyer_port, false)], vec![]).await;
    let buyer = endpoint(
        &buyer,
        buyer_port,
        &[(&old_id, old_port, true), (&new_id, new_port, true)],
        vec![FipsMeshPeerConfig {
            participant_pubkey: old.public_key().to_hex(),
            endpoint_npub: old_id.clone(),
            allowed_ips: vec!["0.0.0.0/0".into()],
        }],
    )
    .await;
    wait_for_fips_peer(&buyer, &old_id).await;
    wait_for_fips_peer(&buyer, &new_id).await;
    (
        buyer,
        incumbent,
        candidate,
        PeerIdentity::from_npub(&buyer_id).unwrap(),
        PeerIdentity::from_npub(&new_id).unwrap(),
    )
}

async fn two_sellers() {
    let (buyer, incumbent, candidate, buyer_identity, seller) = endpoints().await;
    let local: SocketAddrV4 = "10.44.1.2:42000".parse().unwrap();
    let other = SocketAddrV4::new(*local.ip(), 42001);
    let remote: SocketAddrV4 = "1.1.1.1:443".parse().unwrap();
    let path = CandidatePath {
        mesh: buyer.clone(),
        seller,
        source: *local.ip(),
        interface: String::new(),
    };
    let registration = path.register(6, local.into(), remote).unwrap();
    let probe = tcp(local, remote);
    let ordinary = tcp(other, remote);
    buyer
        .blocking_send_tun_pipeline_packet_turn(
            [
                TunPipelinePacket::new(probe.clone()),
                TunPipelinePacket::new(ordinary.clone()),
            ],
            2,
            &mut vec![],
        )
        .unwrap();
    for (runtime, expected) in [(&candidate, &probe), (&incumbent, &ordinary)] {
        let runs = receive(runtime).await;
        assert_eq!(
            runs.iter()
                .flat_map(|r| r.packet_slices())
                .collect::<Vec<_>>(),
            vec![expected.as_slice()]
        );
    }
    let reply = tcp(remote, local);
    let (events, _) = tokio::sync::mpsc::channel(1);
    let mesh = buyer.mesh.load();
    let mut output = DirectTunWriteBatch::with_capacity(2);
    for (sender, allowed) in [(&incumbent, false), (&candidate, true)] {
        sender
            .endpoint
            .send_batch_to_peer(buyer_identity, vec![reply.clone()])
            .await
            .unwrap();
        let runs = receive(&buyer).await;
        let (_, admitted) = buyer
            .admit_direct_endpoint_packet_runs_blocking(&mesh, runs, &mut output, &events)
            .unwrap();
        assert_eq!(admitted, usize::from(allowed));
        assert_eq!(registration.flow.received.load(Ordering::Acquire), allowed);
    }
    drop(registration);
    buyer
        .blocking_send_tun_pipeline_packet_turn(
            [TunPipelinePacket::new(probe.clone())],
            1,
            &mut vec![],
        )
        .unwrap();
    let runs = receive(&incumbent).await;
    assert_eq!(runs[0].packet_slices().next(), Some(probe.as_slice()));
}

// The wrapper provides TUN descriptors from two isolated network namespaces.
// Only the candidate can forward into the Internet-connected namespace.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires scripts/test-linux-paid-exit-candidate and public HTTPS"]
fn live_candidate_reaches_dns_and_https_over_its_own_fips_connection() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(live_probe());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(target_os = "linux")]
async fn live_probe() {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    let tun = |key| {
        let fd = std::env::var(key)
            .expect("use the isolated namespace wrapper")
            .parse::<i32>()
            .unwrap();
        assert!(fd > 2);
        // The wrapper transfers sole ownership of these nonblocking TUN files.
        unsafe { std::fs::File::from_raw_fd(fd) }
    };
    let mut buyer_tun = tun("NVPN_FIXTURE_BUYER_FD");
    let mut seller_tun = tun("NVPN_FIXTURE_SELLER_FD");
    let (buyer, _incumbent, candidate, buyer_id, seller) = endpoints().await;
    let path = CandidatePath {
        mesh: buyer.clone(),
        seller,
        source: "10.44.1.2".parse().unwrap(),
        interface: "nvpnprobe".into(),
    };
    let worker: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut packet = vec![0; 65535];
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        loop {
            if let Ok(n) = buyer_tun.read(&mut packet) {
                buyer.blocking_send_tun_pipeline_packet_turn(
                    [TunPipelinePacket::new(packet[..n].to_vec())],
                    1,
                    &mut vec![],
                )?;
            }
            if let Ok(runs) = candidate.direct_endpoint_rx.try_recv(32) {
                for p in runs.iter().flat_map(|run| run.packet_slices()) {
                    seller_tun.write_all(p)?;
                }
            }
            if let Ok(n) = seller_tun.read(&mut packet) {
                candidate
                    .endpoint
                    .send_batch_to_peer(buyer_id, vec![packet[..n].to_vec()])
                    .await?;
            }
            if let Ok(runs) = buyer.direct_endpoint_rx.try_recv(32) {
                let mut output = DirectTunWriteBatch::with_capacity(32);
                buyer.admit_direct_endpoint_packet_runs_blocking(
                    &buyer.mesh.load(),
                    runs,
                    &mut output,
                    &tx,
                )?;
                for p in output.run_slices() {
                    buyer_tun.write_all(p)?;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    let config = nostr_vpn_core::config::ExitDnsConfig::default()
        .resolver_config(None)
        .unwrap();
    tokio::select! {
        result=path.check(config)=>result.expect("candidate must carry validated DNS and public HTTPS"),
        result=worker=>panic!("packet forwarding ended: {result:?}")
    }
}
