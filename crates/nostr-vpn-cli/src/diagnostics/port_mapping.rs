use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use crab_nat::{
    InternetProtocol, PortMapping as CrabPortMapping, PortMappingOptions, PortMappingType,
    TimeoutConfig,
};
use igd_next::PortMappingProtocol;
use igd_next::aio::Gateway as UpnpGateway;
use igd_next::aio::tokio::{Tokio as UpnpProvider, search_gateway};
use nostr_vpn_core::diagnostics::{PortMappingStatus, ProbeState, ProbeStatus};

use super::NetworkSnapshot;
use super::probes::{
    NAT_PMP_DEFAULT_PORT, PCP_DEFAULT_PORT, SSDP_DISCOVERY_ADDR, probe_nat_pmp_server,
    probe_pcp_server, probe_upnp_ssdp_server,
};

const PORT_MAPPING_LEASE_SECS: u32 = 3_600;
const UPNP_DESCRIPTION: &str = "nostr-vpn";

#[derive(Debug, Clone)]
enum ActivePortMappingLease {
    Crab(CrabPortMapping),
    Upnp(UpnpLease),
}

#[derive(Debug, Clone)]
struct UpnpLease {
    gateway: UpnpGateway<UpnpProvider>,
    external_endpoint: SocketAddr,
    good_until: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct PortMappingRuntime {
    lease: Option<ActivePortMappingLease>,
    status: PortMappingStatus,
}

impl PortMappingRuntime {
    #[must_use]
    pub(crate) fn status(&self) -> PortMappingStatus {
        self.status.clone()
    }

    #[must_use]
    pub(crate) fn advertised_endpoint(&self) -> Option<String> {
        self.status.external_endpoint.clone()
    }

    pub(crate) async fn refresh(
        &mut self,
        snapshot: &NetworkSnapshot,
        listen_port: u16,
        timeout: Duration,
    ) -> Result<bool> {
        let previous_endpoint = self.advertised_endpoint();
        self.stop().await;

        let (gateway, local_ip) = match (snapshot.gateway_ipv4, snapshot.primary_ipv4) {
            (Some(gateway), Some(local_ip)) => (IpAddr::V4(gateway), IpAddr::V4(local_ip)),
            _ => {
                self.status = PortMappingStatus {
                    upnp: ProbeStatus::new(
                        ProbeState::Unsupported,
                        "default gateway or primary IPv4 unavailable",
                    ),
                    nat_pmp: ProbeStatus::new(
                        ProbeState::Unsupported,
                        "default gateway or primary IPv4 unavailable",
                    ),
                    pcp: ProbeStatus::new(
                        ProbeState::Unsupported,
                        "default gateway or primary IPv4 unavailable",
                    ),
                    ..PortMappingStatus::default()
                };
                return Ok(previous_endpoint != self.advertised_endpoint());
            }
        };

        let timeout_config = TimeoutConfig {
            initial_timeout: timeout.min(Duration::from_millis(500)),
            max_retries: 1,
            max_retry_timeout: Some(timeout),
        };
        let mapping_options = PortMappingOptions {
            external_port: NonZeroU16::new(listen_port),
            lifetime_seconds: Some(PORT_MAPPING_LEASE_SECS),
            timeout_config: Some(timeout_config),
        };

        match CrabPortMapping::new(
            gateway,
            local_ip,
            InternetProtocol::Udp,
            NonZeroU16::new(listen_port).ok_or_else(|| anyhow!("listen port must be non-zero"))?,
            mapping_options,
        )
        .await
        {
            Ok(mapping) => {
                let (protocol, external_ip) = match mapping.mapping_type() {
                    PortMappingType::NatPmp => (
                        "nat_pmp".to_string(),
                        crab_nat::natpmp::external_address(gateway, Some(timeout_config))
                            .await
                            .ok()
                            .map(IpAddr::V4),
                    ),
                    PortMappingType::Pcp { external_ip, .. } => {
                        ("pcp".to_string(), Some(external_ip))
                    }
                };
                let endpoint = external_ip
                    .map(|ip| SocketAddr::new(ip, mapping.external_port().get()).to_string());
                self.status = PortMappingStatus {
                    upnp: ProbeStatus::default(),
                    nat_pmp: ProbeStatus::new(
                        if protocol == "nat_pmp" {
                            ProbeState::Available
                        } else {
                            ProbeState::Unknown
                        },
                        if protocol == "nat_pmp" {
                            "mapped UDP listen port"
                        } else {
                            ""
                        },
                    ),
                    pcp: ProbeStatus::new(
                        if protocol == "pcp" {
                            ProbeState::Available
                        } else {
                            ProbeState::Unknown
                        },
                        if protocol == "pcp" {
                            "mapped UDP listen port"
                        } else {
                            ""
                        },
                    ),
                    active_protocol: Some(protocol),
                    external_endpoint: endpoint,
                    gateway: Some(gateway.to_string()),
                    good_until: Some(instant_to_unix(mapping.expiration())),
                };
                self.lease = Some(ActivePortMappingLease::Crab(mapping));
                return Ok(previous_endpoint != self.advertised_endpoint());
            }
            Err(error) => {
                self.status.nat_pmp = ProbeStatus::new(ProbeState::Error, error.to_string());
                self.status.pcp = ProbeStatus::new(ProbeState::Error, error.to_string());
            }
        }

        let local_addr = SocketAddr::new(local_ip, listen_port);
        match search_gateway(Default::default()).await {
            Ok(gateway) => {
                let endpoint = match gateway
                    .add_port(
                        PortMappingProtocol::UDP,
                        listen_port,
                        local_addr,
                        PORT_MAPPING_LEASE_SECS,
                        UPNP_DESCRIPTION,
                    )
                    .await
                {
                    Ok(()) => {
                        let external_ip = gateway.get_external_ip().await.ok();
                        external_ip.map(|ip| SocketAddr::new(ip, listen_port))
                    }
                    Err(_) => gateway
                        .get_any_address(
                            PortMappingProtocol::UDP,
                            local_addr,
                            PORT_MAPPING_LEASE_SECS,
                            UPNP_DESCRIPTION,
                        )
                        .await
                        .ok(),
                };

                if let Some(endpoint) = endpoint {
                    self.status.upnp =
                        ProbeStatus::new(ProbeState::Available, "mapped UDP listen port");
                    self.status.active_protocol = Some("upnp".to_string());
                    self.status.external_endpoint = Some(endpoint.to_string());
                    self.status.gateway = Some(gateway.addr.ip().to_string());
                    self.status.good_until = Some(system_time_to_unix(
                        SystemTime::now()
                            .checked_add(Duration::from_secs(u64::from(PORT_MAPPING_LEASE_SECS)))
                            .unwrap_or(SystemTime::now()),
                    ));
                    self.lease = Some(ActivePortMappingLease::Upnp(UpnpLease {
                        gateway,
                        external_endpoint: endpoint,
                        good_until: Instant::now()
                            + Duration::from_secs(u64::from(PORT_MAPPING_LEASE_SECS)),
                    }));
                } else {
                    self.status.upnp = ProbeStatus::new(
                        ProbeState::Unavailable,
                        "gateway responded but port mapping failed",
                    );
                }
            }
            Err(error) => {
                self.status.upnp = ProbeStatus::new(ProbeState::Unavailable, error.to_string());
            }
        }

        Ok(previous_endpoint != self.advertised_endpoint())
    }

    pub(crate) async fn renew_if_due(
        &mut self,
        snapshot: &NetworkSnapshot,
        listen_port: u16,
        timeout: Duration,
    ) -> Result<bool> {
        let Some(lease) = &mut self.lease else {
            return Ok(false);
        };

        let needs_renew = match lease {
            ActivePortMappingLease::Crab(mapping) => {
                mapping
                    .expiration()
                    .saturating_duration_since(Instant::now())
                    <= Duration::from_secs(300)
            }
            ActivePortMappingLease::Upnp(lease) => {
                lease.good_until.saturating_duration_since(Instant::now())
                    <= Duration::from_secs(300)
            }
        };

        if !needs_renew {
            return Ok(false);
        }

        self.refresh(snapshot, listen_port, timeout).await
    }

    pub(crate) async fn stop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };

        match lease {
            ActivePortMappingLease::Crab(mapping) => {
                let _ = mapping.try_drop().await;
            }
            ActivePortMappingLease::Upnp(lease) => {
                let _ = lease
                    .gateway
                    .remove_port(PortMappingProtocol::UDP, lease.external_endpoint.port())
                    .await;
            }
        }
    }
}

pub(super) async fn probe_port_mapping_services(
    snapshot: &NetworkSnapshot,
    timeout: Duration,
) -> PortMappingStatus {
    let mut status = PortMappingStatus::default();
    let Some(gateway) = snapshot.gateway_ipv4 else {
        status.upnp = ProbeStatus::new(ProbeState::Unsupported, "default IPv4 gateway unavailable");
        status.nat_pmp =
            ProbeStatus::new(ProbeState::Unsupported, "default IPv4 gateway unavailable");
        status.pcp = ProbeStatus::new(ProbeState::Unsupported, "default IPv4 gateway unavailable");
        return status;
    };

    status.nat_pmp = probe_nat_pmp_server(
        SocketAddr::V4(SocketAddrV4::new(gateway, NAT_PMP_DEFAULT_PORT)),
        timeout,
    );
    status.pcp = probe_pcp_server(
        SocketAddr::V4(SocketAddrV4::new(gateway, PCP_DEFAULT_PORT)),
        snapshot
            .primary_ipv4
            .map(IpAddr::V4)
            .or_else(|| snapshot.primary_ipv6.map(IpAddr::V6)),
        timeout,
    );
    status.upnp = probe_upnp_ssdp_server(
        SSDP_DISCOVERY_ADDR.parse().expect("valid ssdp addr"),
        timeout,
    );
    status
}

fn system_time_to_unix(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn instant_to_unix(value: Instant) -> u64 {
    let remaining = value.saturating_duration_since(Instant::now());
    system_time_to_unix(SystemTime::now() + remaining)
}
