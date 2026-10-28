mod port_mapping;
mod probes;
mod underlay_snapshot;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use netdev::get_interfaces;
use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::diagnostics::{
    HealthIssue, HealthSeverity, NetcheckReport, NetworkSummary, PortMappingStatus,
};

pub(crate) use self::port_mapping::PortMappingRuntime;
use self::port_mapping::probe_port_mapping_services;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use self::probes::check_captive_portal_endpoint_on_interface;
use self::probes::{
    CAPTIVE_PORTAL_ENDPOINTS, check_captive_portal_endpoint, mapping_varies_by_dest_ip,
};
#[cfg(test)]
use self::probes::{CaptivePortalEndpoint, parse_http_response};
pub(crate) use self::underlay_snapshot::{
    NetworkSnapshot, NetworkSnapshotSample, capture_network_snapshot,
    capture_network_snapshot_sample_excluding_interfaces, prefer_nonempty_network_snapshot,
};
use crate::{DaemonPeerState, DaemonStatus, unix_timestamp};

pub(crate) async fn run_netcheck_report(app: &AppConfig, timeout_secs: u64) -> NetcheckReport {
    let timeout = Duration::from_secs(timeout_secs.max(1));

    // Public endpoint discovery moved to fips-core's overlay-advert path; the
    // netcheck report no longer pre-runs STUN itself.
    let public_v4_endpoints: Vec<String> = Vec::new();
    let _ = (app, timeout);

    let snapshot = capture_network_snapshot();
    let port_mapping = probe_port_mapping_services(&snapshot, timeout).await;
    let captive_portal = detect_captive_portal(timeout).await;

    NetcheckReport {
        checked_at: unix_timestamp(),
        udp: !public_v4_endpoints.is_empty(),
        ipv4: !public_v4_endpoints.is_empty(),
        ipv6: snapshot.primary_ipv6.is_some(),
        public_ipv4: public_v4_endpoints.first().cloned(),
        public_ipv6: None,
        mapping_varies_by_dest_ip: mapping_varies_by_dest_ip(&public_v4_endpoints),
        captive_portal,
        port_mapping,
    }
}

pub(crate) fn build_health_issues(
    app: &AppConfig,
    vpn_active: bool,
    _mesh_ready: bool,
    network: &NetworkSummary,
    port_mapping: &PortMappingStatus,
    peers: &[DaemonPeerState],
) -> Vec<HealthIssue> {
    let mut issues = Vec::new();

    if vpn_active && local_identity_missing_from_active_roster(app) {
        issues.push(HealthIssue::new(
            "network.self_not_in_roster",
            HealthSeverity::Critical,
            "This device is not in the active network roster",
            "Peers will reject FIPS traffic from this device identity until an admin adds it to the active network or accepts its pending join request.",
        ));
    }

    if vpn_active && network.captive_portal == Some(true) {
        issues.push(HealthIssue::new(
            "network.captive_portal",
            HealthSeverity::Critical,
            "Captive portal detected",
            "This network appears to intercept HTTP connectivity checks. VPN bootstrap may fail until the portal is cleared.",
        ));
    }

    if vpn_active
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

    if vpn_active
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

    if vpn_active && !app.exit_node.is_empty() {
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

    if vpn_active
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

fn local_identity_missing_from_active_roster(app: &AppConfig) -> bool {
    let Some(network) = app.active_network_opt() else {
        return false;
    };
    if network.outbound_join_request.is_some() {
        return false;
    }

    !app.active_network_has_confirmed_local_identity()
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
        },
        "network": network,
        "portMapping": port_mapping,
        "health": issues,
        "netcheck": netcheck,
        "logTail": log_tail,
    });
    let bundle_bytes = serde_json::to_vec_pretty(&bundle)?;
    crate::write_private_runtime_file_atomically(&output_path, &bundle_bytes)
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
            "endpoint": app.node.endpoint,
            "tunnelIp": app.node.tunnel_ip,
            "listenPort": app.node.listen_port,
            "advertisedRoutes": app.node.advertised_routes,
            "advertiseExitNode": app.node.advertise_exit_node,
        },
        "wireguardExit": {
            "enabled": app.wireguard_exit.enabled,
            "configured": app.wireguard_exit.configured(),
            "interface": &app.wireguard_exit.interface,
            "address": &app.wireguard_exit.address,
            "endpoint": &app.wireguard_exit.endpoint,
            "allowedIps": &app.wireguard_exit.allowed_ips,
            "dns": &app.wireguard_exit.dns,
            "mtu": app.wireguard_exit.mtu,
            "persistentKeepaliveSecs": app.wireguard_exit.persistent_keepalive_secs,
            "privateKeySet": !app.wireguard_exit.private_key.trim().is_empty(),
            "peerPresharedKeySet": !app.wireguard_exit.peer_preshared_key.trim().is_empty(),
            "peerPublicKeySet": !app.wireguard_exit.peer_public_key.trim().is_empty(),
        },
        "networks": sanitized_networks_json(app),
    })
}

fn sanitized_networks_json(app: &AppConfig) -> Vec<serde_json::Value> {
    app.networks
        .iter()
        .map(|network| {
            serde_json::json!({
                "id": network.id,
                "name": network.name,
                "networkId": network.network_id,
                "enabled": network.enabled,
                "joinSecretSet": !network.join_secret.trim().is_empty(),
            })
        })
        .collect()
}

pub(crate) async fn detect_captive_portal(timeout: Duration) -> Option<bool> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(found) = detect_captive_portal_on_candidate_interfaces(timeout).await {
        return Some(found);
    }

    detect_captive_portal_on_default_route(timeout).await
}

async fn detect_captive_portal_on_default_route(timeout: Duration) -> Option<bool> {
    #[cfg(target_os = "linux")]
    if let Some(network) = crate::linux_host_network::current() {
        let client = network
            .http_client_builder()
            .ok()?
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .ok()?;
        for endpoint in CAPTIVE_PORTAL_ENDPOINTS {
            let Ok(response) = client
                .get(endpoint.url)
                .header("Cache-Control", "no-cache")
                .send()
                .await
            else {
                continue;
            };
            if response.status().as_u16() != endpoint.expected_status {
                return Some(true);
            }
            if endpoint.expected_prefix.is_empty() {
                return Some(false);
            }
            let Ok(body) = response.text().await else {
                continue;
            };
            return Some(!body.starts_with(endpoint.expected_prefix));
        }
        return None;
    }
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

#[cfg(any(target_os = "macos", target_os = "ios"))]
async fn detect_captive_portal_on_candidate_interfaces(timeout: Duration) -> Option<bool> {
    tokio::task::spawn_blocking(move || {
        detect_captive_portal_on_candidate_interfaces_blocking(timeout)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn detect_captive_portal_on_candidate_interfaces_blocking(timeout: Duration) -> Option<bool> {
    let mut saw_clean_endpoint = false;

    for (name, interface_index) in captive_portal_candidate_interfaces() {
        tracing::debug!(
            interface = %name,
            interface_index,
            "checking captive portal status on candidate interface"
        );

        for endpoint in CAPTIVE_PORTAL_ENDPOINTS {
            match check_captive_portal_endpoint_on_interface(*endpoint, timeout, interface_index) {
                Some(true) => return Some(true),
                Some(false) => saw_clean_endpoint = true,
                None => {}
            }
        }
    }

    saw_clean_endpoint.then_some(false)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn captive_portal_candidate_interfaces() -> Vec<(String, u32)> {
    get_interfaces()
        .into_iter()
        .filter(|interface| {
            interface.index != 0
                && interface.is_up()
                && !interface.is_loopback()
                && !interface.is_tun()
                && !interface.ipv4.is_empty()
                && captive_portal_interface_name_needs_detection(&interface.name)
        })
        .map(|interface| (interface.name, interface.index))
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "ios", test))]
fn captive_portal_interface_name_needs_detection(name: &str) -> bool {
    const EXCLUDED_PREFIXES: &[&str] = &[
        "tailscale",
        "tun",
        "tap",
        "docker",
        "kube",
        "wg",
        "ipsec",
        "pdp",
        "awdl",
        "bridge",
        "ap",
        "utun",
        "llw",
        "anpi",
        "lo",
        "stf",
        "gif",
        "xhc",
        "pktap",
    ];

    let name = name.to_ascii_lowercase();
    !EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::check_captive_portal_endpoint_on_interface;
    use super::probes::{probe_nat_pmp_server, probe_pcp_server, probe_upnp_ssdp_server};
    use super::{
        CaptivePortalEndpoint, NetworkSnapshot, build_health_issues,
        captive_portal_interface_name_needs_detection, check_captive_portal_endpoint,
        local_identity_missing_from_active_roster, mapping_varies_by_dest_ip, parse_http_response,
        sanitized_config_json,
    };
    use nostr_sdk::prelude::Keys;
    use nostr_vpn_core::config::{AppConfig, PendingOutboundJoinRequest};
    use nostr_vpn_core::diagnostics::ProbeState;

    use crate::DaemonPeerState;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

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

    #[cfg(target_os = "macos")]
    #[test]
    fn captive_portal_check_can_bind_to_loopback_interface_on_macos() {
        let interface = netdev::get_interfaces()
            .into_iter()
            .find(|interface| {
                interface.index != 0 && interface.is_loopback() && !interface.ipv4.is_empty()
            })
            .expect("loopback interface with IPv4 address");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let addr = listener.local_addr().expect("listener addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .expect("write");
        });

        let endpoint = CaptivePortalEndpoint {
            url: Box::leak(format!("http://{addr}/generate_204").into_boxed_str()),
            expected_status: 204,
            expected_prefix: "",
        };

        assert_eq!(
            check_captive_portal_endpoint_on_interface(
                endpoint,
                Duration::from_secs(1),
                interface.index
            ),
            Some(false)
        );
    }

    #[test]
    fn captive_portal_interface_filter_keeps_underlay_candidates() {
        assert!(captive_portal_interface_name_needs_detection("en0"));
        assert!(captive_portal_interface_name_needs_detection("eth0"));
        assert!(captive_portal_interface_name_needs_detection("wlan0"));
        assert!(captive_portal_interface_name_needs_detection("Wi-Fi"));

        for excluded in [
            "utun0",
            "awdl0",
            "llw0",
            "anpi1",
            "bridge100",
            "pdp_ip0",
            "tailscale0",
            "docker0",
            "wg0",
            "ipsec0",
            "lo0",
            "pktap0",
        ] {
            assert!(
                !captive_portal_interface_name_needs_detection(excluded),
                "{excluded} should be skipped"
            );
        }
    }

    #[test]
    fn parse_http_response_extracts_status_and_body() {
        let (status, body) = parse_http_response("HTTP/1.1 204 No Content\r\nX-Test: ok\r\n\r\n")
            .expect("parse response");
        assert_eq!(status, 204);
        assert_eq!(body, "");
    }

    #[test]
    fn sanitized_config_redacts_network_join_secrets() {
        let mut app = AppConfig::generated();
        app.networks[0].join_secret = "join-secret-redacted-test-value".to_string();
        let rendered = serde_json::to_string(&sanitized_config_json(&app)).expect("config JSON");
        assert!(
            !rendered.contains("join-secret-redacted-test-value"),
            "bundle config must not embed the join secret"
        );
        assert!(rendered.contains("\"joinSecretSet\":true"));

        app.networks[0].join_secret.clear();
        let rendered = serde_json::to_string(&sanitized_config_json(&app)).expect("config JSON");
        assert!(rendered.contains("\"joinSecretSet\":false"));
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
            false,
            &network,
            &Default::default(),
            &[DaemonPeerState {
                participant_pubkey: "peer-a".to_string(),
                node_id: "node-a".to_string(),
                tunnel_ip: "10.44.0.2/32".to_string(),
                endpoint: "203.0.113.20:51820".to_string(),
                runtime_endpoint: None,
                fips_endpoint_npub: String::new(),
                fips_transport_addr: String::new(),
                fips_transport_type: String::new(),
                fips_srtt_ms: None,
                fips_srtt_age_ms: None,
                fips_packets_sent: 0,
                fips_packets_recv: 0,
                fips_bytes_sent: 0,
                fips_bytes_recv: 0,
                fips_rekey_in_progress: false,
                fips_rekey_draining: false,
                fips_current_k_bit: None,
                fips_last_outbound_route: String::new(),
                direct_probe_pending: false,
                direct_probe_after_ms: None,
                direct_probe_retry_count: 0,
                direct_probe_auto_reconnect: false,
                direct_probe_expires_at_ms: None,
                fips_nostr_traversal_failures: 0,
                fips_nostr_traversal_in_cooldown: false,
                fips_nostr_traversal_cooldown_until_ms: None,
                fips_nostr_traversal_last_observed_skew_ms: None,
                tx_bytes: 0,
                rx_bytes: 0,
                public_key: "pk".to_string(),
                advertised_routes: vec!["0.0.0.0/0".to_string()],
                last_mesh_seen_at: 1,
                last_fips_seen_at: Some(1),
                last_fips_control_seen_at: Some(1),
                last_fips_data_seen_at: None,
                reachable: false,
                last_handshake_at: None,
                error: Some("awaiting handshake".to_string()),
            }],
        );

        assert!(issues.iter().any(|issue| issue.code == "exit_node.offline"));
    }

    #[test]
    fn health_issues_flag_local_identity_missing_from_active_roster() {
        let mut app = AppConfig::generated();
        let own_pubkey = app.own_nostr_pubkey_hex().expect("own pubkey");
        let admin = Keys::generate().public_key().to_hex();
        app.networks[0].enabled = true;
        app.networks[0].devices = vec![Keys::generate().public_key().to_hex()];
        app.networks[0].admins = vec![admin.clone()];
        app.ensure_defaults();
        let network = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 4)),
            ..NetworkSnapshot::default()
        }
        .summary(Some(10), Some(false));

        let issues = build_health_issues(&app, true, false, &network, &Default::default(), &[]);

        assert!(
            issues.iter().any(|issue| {
                issue.code == "network.self_not_in_roster"
                    && issue.detail.contains("until an admin adds it")
            }),
            "issues={issues:#?} members={:?} own={own_pubkey}",
            app.active_network_signal_pubkeys_hex()
        );
        assert!(
            !app.active_network_signal_pubkeys_hex()
                .iter()
                .any(|participant| participant == &own_pubkey)
        );

        app.networks[0].shared_roster_updated_at = 123;
        app.networks[0].shared_roster_signed_by = admin;
        assert!(!local_identity_missing_from_active_roster(&app));
    }

    #[test]
    fn health_issues_do_not_flag_pending_join_as_missing_roster() {
        let mut app = AppConfig::generated();
        let admin = Keys::generate().public_key().to_hex();
        app.networks[0].enabled = true;
        app.networks[0].devices.clear();
        app.networks[0].admins = vec![admin.clone()];
        app.networks[0].outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin,
            requested_at: 123,
        });
        app.ensure_defaults();
        let network = NetworkSnapshot {
            default_interface: Some("en0".to_string()),
            primary_ipv4: Some(Ipv4Addr::new(192, 168, 1, 4)),
            ..NetworkSnapshot::default()
        }
        .summary(Some(10), Some(false));

        let issues = build_health_issues(&app, true, false, &network, &Default::default(), &[]);

        assert!(
            issues
                .iter()
                .all(|issue| issue.code != "network.self_not_in_roster")
        );
    }

    #[test]
    fn health_issues_skip_exit_node_warning_when_vpn_is_inactive() {
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

        let issues = build_health_issues(&app, false, false, &network, &Default::default(), &[]);
        assert!(issues.iter().all(|issue| issue.code != "exit_node.unknown"));
    }
}
