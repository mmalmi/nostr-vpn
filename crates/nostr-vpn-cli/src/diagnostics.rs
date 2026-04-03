mod port_mapping;
mod probes;

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use netdev::get_default_interface;
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::diagnostics::{
    HealthIssue, HealthSeverity, NetcheckReport, NetworkSummary, PortMappingStatus, RelayCheck,
};

pub(crate) use self::port_mapping::PortMappingRuntime;
use self::port_mapping::probe_port_mapping_services;
use self::probes::{
    CAPTIVE_PORTAL_ENDPOINTS, check_captive_portal_endpoint, mapping_varies_by_dest_ip,
};
#[cfg(test)]
use self::probes::{CaptivePortalEndpoint, parse_http_response};
#[cfg(target_os = "macos")]
use crate::macos_network::{
    macos_default_routes, macos_ipconfig_ipv4_for_interface, macos_ipconfig_router_for_interface,
    macos_underlay_default_route_from_routes, macos_underlay_default_route_from_system,
};
use crate::{DaemonPeerState, DaemonStatus, discover_public_udp_endpoint_via_stun, unix_timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NetworkSnapshot {
    pub default_interface: Option<String>,
    pub primary_ipv4: Option<Ipv4Addr>,
    pub primary_ipv6: Option<Ipv6Addr>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub gateway_ipv6: Option<Ipv6Addr>,
}

impl NetworkSnapshot {
    #[must_use]
    pub(crate) fn fingerprint(&self) -> String {
        [
            self.default_interface.as_deref().unwrap_or(""),
            &self
                .primary_ipv4
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .primary_ipv6
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .gateway_ipv4
                .map_or_else(String::new, |value| value.to_string()),
            &self
                .gateway_ipv6
                .map_or_else(String::new, |value| value.to_string()),
        ]
        .join("|")
    }

    #[must_use]
    pub(crate) fn changed_since(&self, previous: &Self) -> bool {
        self.fingerprint() != previous.fingerprint()
    }

    #[must_use]
    pub(crate) fn summary(
        &self,
        changed_at: Option<u64>,
        captive_portal: Option<bool>,
    ) -> NetworkSummary {
        NetworkSummary {
            default_interface: self.default_interface.clone(),
            primary_ipv4: self.primary_ipv4.map(|value| value.to_string()),
            primary_ipv6: self.primary_ipv6.map(|value| value.to_string()),
            gateway_ipv4: self.gateway_ipv4.map(|value| value.to_string()),
            gateway_ipv6: self.gateway_ipv6.map(|value| value.to_string()),
            changed_at,
            captive_portal,
        }
    }
}

pub(crate) fn capture_network_snapshot() -> NetworkSnapshot {
    #[cfg(target_os = "macos")]
    {
        let snapshot = capture_macos_network_snapshot();
        if snapshot.default_interface.is_some()
            || snapshot.primary_ipv4.is_some()
            || snapshot.gateway_ipv4.is_some()
        {
            return snapshot;
        }
    }

    let mut snapshot = NetworkSnapshot::default();
    let Ok(interface) = get_default_interface() else {
        return snapshot;
    };

    snapshot.default_interface = Some(interface.name.clone());
    snapshot.primary_ipv4 = interface
        .ipv4_addrs()
        .into_iter()
        .find(|ip| !ip.is_loopback() && !ip.is_link_local());
    snapshot.primary_ipv6 = interface.ipv6_addrs().into_iter().find(|ip| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_unicast_link_local()
            && !ip.is_multicast()
    });
    if let Some(gateway) = interface.gateway {
        snapshot.gateway_ipv4 = gateway.ipv4.first().copied();
        snapshot.gateway_ipv6 = gateway.ipv6.first().copied();
    }

    snapshot
}

#[cfg(target_os = "macos")]
fn capture_macos_network_snapshot() -> NetworkSnapshot {
    let mut snapshot = NetworkSnapshot::default();

    let underlay = macos_default_routes()
        .ok()
        .and_then(|routes| {
            macos_underlay_default_route_from_routes(&routes)
                .or_else(|| macos_underlay_default_route_from_system().ok().flatten())
        })
        .or_else(|| macos_underlay_default_route_from_system().ok().flatten());

    let Some(underlay) = underlay else {
        return snapshot;
    };

    snapshot.default_interface = Some(underlay.interface.clone());
    snapshot.primary_ipv4 = macos_ipconfig_ipv4_for_interface(&underlay.interface)
        .ok()
        .flatten();
    snapshot.gateway_ipv4 = underlay
        .gateway
        .as_deref()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .or_else(|| {
            macos_ipconfig_router_for_interface(&underlay.interface)
                .ok()
                .flatten()
        });

    snapshot
}

pub(crate) async fn run_netcheck_report(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    timeout_secs: u64,
) -> NetcheckReport {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let relay_checks = check_relays(app, network_id, relays, timeout_secs).await;

    let mut public_v4_endpoints = Vec::new();
    for server in &app.nat.stun_servers {
        if let Ok(endpoint) = discover_public_udp_endpoint_via_stun(server, 0, timeout)
            && endpoint
                .parse::<SocketAddr>()
                .is_ok_and(|value| value.is_ipv4())
        {
            public_v4_endpoints.push(endpoint);
        }
    }

    public_v4_endpoints.sort();
    public_v4_endpoints.dedup();

    let snapshot = capture_network_snapshot();
    let port_mapping = probe_port_mapping_services(&snapshot, timeout).await;
    let captive_portal = detect_captive_portal(timeout).await;

    let preferred_relay = relay_checks
        .iter()
        .filter(|check| check.error.is_none())
        .min_by_key(|check| check.latency_ms)
        .map(|check| check.relay.clone());

    NetcheckReport {
        checked_at: unix_timestamp(),
        udp: !public_v4_endpoints.is_empty(),
        ipv4: !public_v4_endpoints.is_empty(),
        ipv6: snapshot.primary_ipv6.is_some(),
        public_ipv4: public_v4_endpoints.first().cloned(),
        public_ipv6: None,
        mapping_varies_by_dest_ip: mapping_varies_by_dest_ip(&public_v4_endpoints),
        captive_portal,
        preferred_relay,
        relay_checks,
        port_mapping,
    }
}

pub(crate) fn build_health_issues(
    app: &AppConfig,
    session_active: bool,
    relay_connected: bool,
    _mesh_ready: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    peers: &[DaemonPeerState],
) -> Vec<HealthIssue> {
    let mut issues = Vec::new();

    if session_active && !relay_connected {
        issues.push(HealthIssue::new(
            "relay.disconnected",
            HealthSeverity::Warning,
            "Relay bootstrap is disconnected",
            "Direct mesh may still work, but Nostr relay signaling is currently unavailable.",
        ));
    }

    if session_active && network.captive_portal == Some(true) {
        issues.push(HealthIssue::new(
            "network.captive_portal",
            HealthSeverity::Critical,
            "Captive portal detected",
            "This network appears to intercept HTTP connectivity checks. VPN bootstrap may fail until the portal is cleared.",
        ));
    }

    if session_active
        && port_mapping.active_protocol.is_none()
        && network.primary_ipv4.is_none()
        && network.primary_ipv6.is_none()
    {
        issues.push(HealthIssue::new(
            "network.no_primary_address",
            HealthSeverity::Critical,
            "No primary network address detected",
            "No usable default interface address was detected for announcing this node.",
        ));
    }

    if session_active
        && port_mapping.active_protocol.is_none()
        && app.nat.enabled
        && network.primary_ipv4.is_some()
    {
        issues.push(HealthIssue::new(
            "nat.no_public_mapping",
            HealthSeverity::Info,
            "No active port mapping",
            "Direct connectivity may still succeed via STUN or LAN discovery, but no PCP/NAT-PMP/UPnP mapping is currently active.",
        ));
    }

    if session_active && !app.exit_node.is_empty() {
        let selected_peer = peers
            .iter()
            .find(|peer| peer.participant_pubkey == app.exit_node);
        match selected_peer {
            Some(peer) if !peer.reachable => issues.push(HealthIssue::new(
                "exit_node.offline",
                HealthSeverity::Critical,
                "Selected exit node is offline",
                "Default-route traffic is pinned to a peer that does not currently have a recent handshake.",
            )),
            Some(peer)
                if !peer
                    .advertised_routes
                    .iter()
                    .any(|route| route == "0.0.0.0/0" || route == "::/0") =>
            {
                issues.push(HealthIssue::new(
                    "exit_node.unavailable",
                    HealthSeverity::Warning,
                    "Selected exit node is not advertising default routes",
                    "Choose a peer that offers exit-node routes or clear the exit-node setting.",
                ));
            }
            None => issues.push(HealthIssue::new(
                "exit_node.unknown",
                HealthSeverity::Warning,
                "Selected exit node is not present",
                "The configured exit-node peer is not part of the currently known runtime peer set.",
            )),
            Some(_) => {}
        }
    }

    if session_active
        && peers
            .iter()
            .any(|peer| peer.error.as_deref() == Some("signal stale"))
    {
        issues.push(HealthIssue::new(
            "peer.signal_stale",
            HealthSeverity::Warning,
            "One or more peers have stale signaling",
            "The tunnel can keep running from cached paths, but one or more peer announcements have expired.",
        ));
    }

    issues
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_doctor_bundle(
    path: &Path,
    app: &AppConfig,
    network_id: &str,
    daemon_status: &DaemonStatus,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    issues: &[HealthIssue],
    netcheck: &NetcheckReport,
    log_tail: &str,
) -> Result<PathBuf> {
    let output_path = if path.extension().is_some() {
        path.to_path_buf()
    } else {
        path.join(format!("nvpn-doctor-{}.json", unix_timestamp()))
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let daemon_state_raw = if daemon_status.state_file.exists() {
        fs::read_to_string(&daemon_status.state_file).unwrap_or_default()
    } else {
        String::new()
    };

    let bundle = serde_json::json!({
        "generatedAt": unix_timestamp(),
        "networkId": network_id,
        "config": sanitized_config_json(app),
        "daemon": {
            "running": daemon_status.running,
            "pid": daemon_status.pid,
            "stateFile": daemon_status.state_file,
            "logFile": daemon_status.log_file,
            "state": daemon_status.state,
            "rawState": daemon_state_raw,
        },
        "network": network,
        "portMapping": port_mapping,
        "health": issues,
        "netcheck": netcheck,
        "logTail": log_tail,
    });
    fs::write(&output_path, serde_json::to_vec_pretty(&bundle)?)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    Ok(output_path)
}

fn sanitized_config_json(app: &AppConfig) -> serde_json::Value {
    serde_json::json!({
        "networkId": app.effective_network_id(),
        "nodeName": app.node_name,
        "autoconnect": app.autoconnect,
        "magicDnsSuffix": app.magic_dns_suffix,
        "exitNode": app.exit_node,
        "nostr": {
            "publicKey": app.nostr.public_key,
            "relays": app.nostr.relays,
        },
        "node": {
            "id": app.node.id,
            "publicKey": app.node.public_key,
            "endpoint": app.node.endpoint,
            "tunnelIp": app.node.tunnel_ip,
            "listenPort": app.node.listen_port,
            "advertisedRoutes": app.node.advertised_routes,
            "advertiseExitNode": app.node.advertise_exit_node,
        },
        "networks": app.networks,
    })
}

async fn check_relays(
    app: &AppConfig,
    network_id: &str,
    relays: &[String],
    timeout_secs: u64,
) -> Vec<RelayCheck> {
    let mut checks = Vec::with_capacity(relays.len());

    for relay in relays {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), async {
            let client = crate::NostrSignalingClient::from_secret_key(
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
                transport: Some("websocket".to_string()),
            }),
            Ok(Err(error)) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some(error.to_string()),
                transport: Some("websocket".to_string()),
            }),
            Err(_) => checks.push(RelayCheck {
                relay: relay.clone(),
                latency_ms: started.elapsed().as_millis(),
                error: Some("timeout".to_string()),
                transport: Some("websocket".to_string()),
            }),
        }
    }

    checks
}

pub(crate) async fn detect_captive_portal(timeout: Duration) -> Option<bool> {
    for endpoint in CAPTIVE_PORTAL_ENDPOINTS {
        match tokio::task::spawn_blocking({
            let endpoint = *endpoint;
            move || check_captive_portal_endpoint(endpoint, timeout)
        })
        .await
        .ok()
        .flatten()
        {
            Some(found) => return Some(found),
            None => continue,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::probes::{probe_nat_pmp_server, probe_pcp_server, probe_upnp_ssdp_server};
    use super::{
        CaptivePortalEndpoint, NetworkSnapshot, build_health_issues, check_captive_portal_endpoint,
        mapping_varies_by_dest_ip, parse_http_response,
    };
    use nostr_vpn_core::config::AppConfig;
    use nostr_vpn_core::diagnostics::ProbeState;

    use crate::DaemonPeerState;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn network_snapshot_change_detection_uses_fingerprint() {
        let left = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            ..NetworkSnapshot::default()
        };
        let right = NetworkSnapshot {
            default_interface: Some("en1".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            ..NetworkSnapshot::default()
        };

        assert!(right.changed_since(&left));
    }

    #[test]
    fn mapping_varies_by_dest_ip_requires_multiple_distinct_addresses() {
        assert_eq!(
            mapping_varies_by_dest_ip(&[
                "203.0.113.10:51820".to_string(),
                "203.0.113.10:40000".to_string(),
            ]),
            Some(false)
        );
        assert_eq!(
            mapping_varies_by_dest_ip(&[
                "203.0.113.10:51820".to_string(),
                "203.0.113.20:40000".to_string(),
            ]),
            Some(true)
        );
    }

    #[test]
    fn nat_pmp_probe_detects_gateway_response() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind natpmp server");
        let addr = server.local_addr().expect("natpmp addr");
        thread::spawn(move || {
            let mut buf = [0_u8; 64];
            let (read, peer) = server.recv_from(&mut buf).expect("recv natpmp");
            assert_eq!(&buf[..read], &[0, 0]);
            let response = [0_u8, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 20];
            server.send_to(&response, peer).expect("send natpmp");
        });

        let status = probe_nat_pmp_server(addr, Duration::from_secs(1));
        assert_eq!(status.state, ProbeState::Available);
    }

    #[test]
    fn pcp_probe_detects_gateway_response() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind pcp server");
        let addr = server.local_addr().expect("pcp addr");
        thread::spawn(move || {
            let mut buf = [0_u8; 128];
            let (_read, peer) = server.recv_from(&mut buf).expect("recv pcp");
            let mut response = [0_u8; 24];
            response[0] = 2;
            response[1] = 0x80;
            response[3] = 0;
            response[11] = 1;
            server.send_to(&response, peer).expect("send pcp");
        });

        let status = probe_pcp_server(
            addr,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9))),
            Duration::from_secs(1),
        );
        assert_eq!(status.state, ProbeState::Available);
    }

    #[test]
    fn upnp_probe_detects_ssdp_response() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind ssdp server");
        let addr = server.local_addr().expect("ssdp addr");
        thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            let (_read, peer) = server.recv_from(&mut buf).expect("recv ssdp");
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "LOCATION: http://127.0.0.1/rootDesc.xml\r\n",
                "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
                "\r\n"
            );
            server
                .send_to(response.as_bytes(), peer)
                .expect("send ssdp");
        });

        let status = probe_upnp_ssdp_server(addr, Duration::from_secs(1));
        assert_eq!(status.state, ProbeState::Available);
    }

    #[test]
    fn captive_portal_check_flags_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let addr = listener.local_addr().expect("listener addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://login/\r\nContent-Length: 0\r\n\r\n",
                )
                .expect("write");
        });

        let endpoint = CaptivePortalEndpoint {
            url: Box::leak(format!("http://{addr}/generate_204").into_boxed_str()),
            expected_status: 204,
            expected_prefix: "",
        };

        assert_eq!(
            check_captive_portal_endpoint(endpoint, Duration::from_secs(1)),
            Some(true)
        );
    }

    #[test]
    fn parse_http_response_extracts_status_and_body() {
        let (status, body) = parse_http_response("HTTP/1.1 204 No Content\r\nX-Test: ok\r\n\r\n")
            .expect("parse response");
        assert_eq!(status, 204);
        assert_eq!(body, "");
    }

    #[test]
    fn health_issues_flag_selected_exit_node_when_offline() {
        let app = AppConfig {
            exit_node: "peer-a".to_string(),
            ..AppConfig::default()
        };
        let network = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 4)),
            ..NetworkSnapshot::default()
        }
        .summary(Some(10), Some(false));
        let issues = build_health_issues(
            &app,
            true,
            true,
            false,
            &network,
            &Default::default(),
            &[DaemonPeerState {
                participant_pubkey: "peer-a".to_string(),
                node_id: "node-a".to_string(),
                tunnel_ip: "10.44.0.2/32".to_string(),
                endpoint: "203.0.113.20:51820".to_string(),
                runtime_endpoint: None,
                tx_bytes: 0,
                rx_bytes: 0,
                public_key: "pk".to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                presence_timestamp: 1,
                last_signal_seen_at: Some(1),
                reachable: false,
                last_handshake_at: None,
                error: Some("awaiting handshake".to_string()),
            }],
        );

        assert!(issues.iter().any(|issue| issue.code == "exit_node.offline"));
    }

    #[test]
    fn health_issues_skip_exit_node_warning_when_session_is_inactive() {
        let app = AppConfig {
            exit_node: "peer-a".to_string(),
            ..AppConfig::default()
        };
        let network = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 4)),
            ..NetworkSnapshot::default()
        }
        .summary(Some(10), Some(false));

        let issues = build_health_issues(
            &app,
            false,
            false,
            false,
            &network,
            &Default::default(),
            &[],
        );
        assert!(issues.iter().all(|issue| issue.code != "exit_node.unknown"));
    }

    #[test]
    fn health_issues_warn_when_relays_are_disconnected_even_if_mesh_is_ready() {
        let app = AppConfig::default();
        let network = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 4)),
            ..NetworkSnapshot::default()
        }
        .summary(Some(10), Some(false));

        let issues =
            build_health_issues(&app, true, false, true, &network, &Default::default(), &[]);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "relay.disconnected")
        );
    }
}
