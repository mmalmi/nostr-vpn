use super::*;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use nostr_vpn_core::config::ExitDnsResolverConfig;
use std::net::SocketAddrV4;
use tokio::net::{TcpSocket, UdpSocket};
use tokio_rustls::{TlsConnector, rustls};

/// A reserved daemon socket is the only traffic eligible for the alternate peer.
pub(super) struct ProbeFlow {
    seller: PeerIdentity,
    protocol: u8,
    local: SocketAddrV4,
    remote: SocketAddrV4,
    received: AtomicBool,
}

impl ProbeFlow {
    fn matches(&self, bytes: &[u8], src: SocketAddrV4, dst: SocketAddrV4) -> bool {
        if bytes.len() < 20
            || bytes[0] >> 4 != 4
            || bytes[9] != self.protocol
            || bytes[6] & 0x3f != 0
            || bytes[7] != 0
            || bytes[12..16] != src.ip().octets()
            || bytes[16..20] != dst.ip().octets()
        {
            return false;
        }
        let offset = usize::from(bytes[0] & 15) * 4;
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let minimum = if self.protocol == 6 { 20 } else { 8 };
        offset >= 20
            && length <= bytes.len()
            && length >= offset + minimum
            && bytes[offset..offset + 2] == src.port().to_be_bytes()
            && bytes[offset + 2..offset + 4] == dst.port().to_be_bytes()
    }

    pub(super) fn matches_outbound(&self, packet: &[u8]) -> bool {
        self.matches(packet, self.local, self.remote)
    }

    pub(super) fn send_run(
        &self,
        mesh: &FipsPrivateMeshRuntime,
        packet: Vec<u8>,
    ) -> Result<FipsEndpointIdentitySendRun> {
        let key = self.seller.pubkey().serialize();
        mesh.note_paid_route_outbound_packet(None, Some(&key), &packet)?;
        Ok(FipsEndpointIdentitySendRun::new(
            None,
            Some(key),
            self.seller,
            packet,
        ))
    }

    pub(super) fn admit_reply(&self, peer: PeerIdentity, packet: &[u8]) -> Option<bool> {
        self.matches(packet, self.remote, self.local).then(|| {
            // A seller is identified by the x-only key in its signed offer.
            // The authenticated handshake also carries the full key's parity.
            if peer.pubkey() != self.seller.pubkey() {
                return false;
            }
            self.received.store(true, Ordering::Release);
            true
        })
    }
}

struct Registration<'a> {
    slot: &'a arc_swap::ArcSwapOption<ProbeFlow>,
    flow: Arc<ProbeFlow>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.slot.compare_and_swap(&self.flow, None);
    }
}

struct CandidatePath {
    mesh: Arc<FipsPrivateMeshRuntime>,
    seller: PeerIdentity,
    source: Ipv4Addr,
    interface: String,
}

impl CandidatePath {
    async fn check(self, config: ExitDnsResolverConfig) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let ip = self.dns(config).await?;
            let url = reqwest::Url::parse(
                nostr_vpn_core::paid_route_probe::DEFAULT_PAID_ROUTE_PUBLIC_IP_URL,
            )?;
            let body = self.https(&url, ip, None).await?;
            anyhow::ensure!(
                crate::parse_paid_route_public_ip_response(std::str::from_utf8(&body)?).is_some(),
                "candidate returned no public exit address"
            );
            Ok(())
        })
        .await
        .context("candidate Internet check timed out")?
    }

    fn register(
        &self,
        protocol: u8,
        local: SocketAddr,
        remote: SocketAddrV4,
    ) -> Result<Registration<'_>> {
        let SocketAddr::V4(local) = local else {
            anyhow::bail!("candidate probe needs an IPv4 socket")
        };
        let flow = Arc::new(ProbeFlow {
            seller: self.seller,
            local,
            remote,
            protocol,
            received: AtomicBool::new(false),
        });
        let slot = &self.mesh.candidate_probe;
        if slot
            .compare_and_swap(std::ptr::null::<ProbeFlow>(), Some(flow.clone()))
            .is_some()
        {
            anyhow::bail!("another candidate probe is in progress");
        }
        Ok(Registration { slot, flow })
    }

    async fn https(&self, url: &reqwest::Url, ip: Ipv4Addr, dns: Option<Vec<u8>>) -> Result<Bytes> {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("missing HTTPS probe host"))?;
        anyhow::ensure!(url.scheme() == "https", "candidate probe requires HTTPS");
        let dest = SocketAddrV4::new(ip, url.port().unwrap_or(443));
        let socket = TcpSocket::new_v4()?;
        socket.bind((self.source, 0).into())?;
        crate::paid_exit_probe_binding_impl::bind_paid_exit_probe_socket(
            &socket2::SockRef::from(&socket),
            &self.interface,
            false,
        )?;
        let registration = self.register(6, socket.local_addr()?, dest)?;
        let tcp = socket.connect(dest.into()).await?;
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let stream = TlsConnector::from(Arc::new(tls))
            .connect(host.to_owned().try_into()?, tcp)
            .await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let exchange = async {
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut req = hyper::Request::builder().uri(path);
            req = req.header(hyper::header::HOST, url.authority());
            let body = if let Some(packet) = dns {
                req = req
                    .method("POST")
                    .header("content-type", "application/dns-message")
                    .header("accept", "application/dns-message");
                packet
            } else {
                Vec::new()
            };
            let reply = sender
                .send_request(req.body(Full::new(Bytes::from(body)))?)
                .await?;
            anyhow::ensure!(
                reply.status().is_success(),
                "candidate HTTPS returned {}",
                reply.status()
            );
            let body = Limited::new(reply.into_body(), 4096)
                .collect()
                .await
                .map_err(|e| anyhow!("{e}"))?
                .to_bytes();
            anyhow::ensure!(
                registration.flow.received.load(Ordering::Acquire),
                "reply did not arrive from candidate"
            );
            Ok(body)
        };
        tokio::pin!(exchange);
        tokio::pin!(connection);
        tokio::select! {
            biased;
            result = &mut exchange => result,
            ended = &mut connection => { ended?; exchange.await }
        }
    }

    async fn dns(&self, config: ExitDnsResolverConfig) -> Result<Ipv4Addr> {
        let question = crate::secure_dns_runtime::paid_exit_dns_question();
        let packet = question.to_vec()?;
        let (url, servers) = match config {
            ExitDnsResolverConfig::Doh { url, bootstrap_ips } => {
                (Some(reqwest::Url::parse(&url)?), bootstrap_ips)
            }
            ExitDnsResolverConfig::ThroughExit { servers } => (None, servers),
            ExitDnsResolverConfig::FailClosed => anyhow::bail!("DNS is unavailable"),
        };
        let mut failure = anyhow!("no IPv4 DNS server is configured");
        for ip in servers.into_iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        }) {
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                let reply = if let Some(url) = &url {
                    self.https(url, ip, Some(packet.clone())).await?
                } else {
                    let remote = SocketAddrV4::new(ip, 53);
                    let socket = UdpSocket::bind((self.source, 0)).await?;
                    crate::paid_exit_probe_binding_impl::bind_paid_exit_probe_socket(
                        &socket2::SockRef::from(&socket),
                        &self.interface,
                        false,
                    )?;
                    let registration = self.register(17, socket.local_addr()?, remote)?;
                    socket.connect(remote).await?;
                    socket.send(&packet).await?;
                    let mut reply = vec![0; 4096];
                    let size = socket.recv(&mut reply).await?;
                    anyhow::ensure!(
                        registration.flow.received.load(Ordering::Acquire),
                        "DNS reply did not arrive from candidate"
                    );
                    reply.truncate(size);
                    Bytes::from(reply)
                };
                crate::secure_dns_runtime::paid_exit_dns_answer(&question, &reply)
            })
            .await;
            match result {
                Ok(Ok(ip)) => return Ok(ip),
                Ok(Err(error)) => failure = error,
                Err(_) => failure = anyhow!("candidate DNS timed out"),
            }
        }
        Err(failure)
    }
}

impl FipsPrivateTunnelRuntime {
    pub(crate) fn probe_paid_exit_candidate(
        &self,
        seller: &str,
        source: Ipv4Addr,
        config: ExitDnsResolverConfig,
    ) -> Result<tokio::task::JoinHandle<Result<()>>> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let path = CandidatePath {
                mesh: self.mesh.clone(),
                seller: control_frame_participant_identity(seller)
                    .ok_or_else(|| anyhow!("invalid candidate seller"))?,
                interface: self.iface().to_owned(),
                source,
            };
            Ok(tokio::spawn(path.check(config)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = (seller, source, config);
            anyhow::bail!("candidate probes are unavailable on this platform")
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "exit_probe/tests.rs"]
mod tests;
