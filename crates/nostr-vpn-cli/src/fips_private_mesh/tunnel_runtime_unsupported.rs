#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) struct FipsPrivateTunnelRuntime;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
impl FipsPrivateTunnelRuntime {
    pub(crate) async fn start(
        _config: FipsPrivateTunnelConfig,
        _cleanup_journal_config_path: &std::path::Path,
    ) -> Result<Self> {
        Err(anyhow!(
            "FIPS private tunnel runtime is not implemented for this platform"
        ))
    }

    pub(crate) fn iface(&self) -> &str {
        ""
    }

    pub(crate) fn active_listen_port(&self) -> Option<u16> {
        None
    }

    pub(crate) fn wireguard_exit_ready(&self) -> bool {
        false
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn paid_exit_seller_ready(&self) -> bool {
        false
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn paid_exit_dns_health_probe(
        &self,
    ) -> Result<crate::secure_dns_runtime::SecureDnsHealthProbe> {
        Err(anyhow!(
            "secure DNS is unavailable for paid exit health on this platform"
        ))
    }

    pub(crate) fn client_dataplane_enabled(&self) -> bool {
        false
    }

    pub(crate) fn ethernet_underlay(&self) -> Option<&FipsEthernetUnderlayConfig> {
        None
    }

    pub(crate) fn peer_statuses(&self) -> Vec<MeshPeerStatus> {
        Vec::new()
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn drain_paid_route_usage(&self, _participant: &str) -> Result<PaidRouteUsage> {
        Ok(PaidRouteUsage::default())
    }

    pub(crate) fn stale_participants_needing_path_refresh(&self, _now: u64) -> Vec<String> {
        Vec::new()
    }

    pub(crate) async fn relay_statuses(&self) -> Result<Vec<FipsRelayStatus>> {
        Ok(Vec::new())
    }

    pub(crate) async fn local_advertised_endpoints(&self) -> Result<Vec<OverlayEndpointAdvert>> {
        Ok(Vec::new())
    }

    pub(crate) fn peer_pubkeys(&self) -> Vec<String> {
        Vec::new()
    }

    pub(crate) async fn authenticated_endpoint_peers(&self) -> Result<Vec<FipsEndpointPeer>> {
        Ok(Vec::new())
    }

    pub(crate) fn peer_endpoint_hints(&self) -> Vec<(String, Vec<(String, u64)>)> {
        Vec::new()
    }

    pub(crate) async fn update_peers(
        &self,
        _endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<fips_endpoint::UpdatePeersOutcome> {
        Ok(fips_endpoint::UpdatePeersOutcome::default())
    }

    pub(crate) async fn refresh_peer_paths(
        &self,
        _endpoint_peers: &[FipsEndpointPeerTransportConfig],
    ) -> Result<usize> {
        Ok(0)
    }

    pub(crate) async fn rebind_network_transports(
        &self,
        _bind_interface: Option<String>,
    ) -> Result<usize> {
        Ok(0)
    }

    pub(crate) fn requires_endpoint_restart(&self, _config: &FipsPrivateTunnelConfig) -> bool {
        false
    }

    pub(crate) async fn apply_config(
        &self,
        _config: FipsPrivateTunnelConfig,
        _cleanup_journal_config_path: &std::path::Path,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn refresh_peer_dependent_routes(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn ping_peers(&self, _network_id: &str, _now: u64) -> Result<usize> {
        Ok(0)
    }

    pub(crate) async fn ping_pending_join_peers(
        &self,
        _network_id: &str,
        _now: u64,
    ) -> Result<usize> {
        Ok(0)
    }

    pub(crate) async fn refresh_link_statuses(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) fn enqueue_join_request(
        &self,
        _participant: &str,
        _requested_at: u64,
        _request: MeshJoinRequest,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) fn enqueue_roster(
        &self,
        _participant: &str,
        _signed_roster: SignedRoster,
    ) -> Result<()> {
        Ok(())
    }

    pub(crate) fn join_roster_delivery(
        &self,
        _participant: String,
        _join_roster: JoinRosterControl,
    ) -> Result<FipsJoinRosterDelivery> {
        Ok(Box::pin(async { Ok(()) }))
    }

    pub(crate) async fn send_join_roster_ack(
        &self,
        _participant: &str,
        _roster_event_id: String,
    ) -> Result<()> {
        Ok(())
    }
    pub(crate) fn enqueue_capabilities(
        &self,
        _participant: &str,
        _network_id: &str,
        _capabilities: PeerCapabilities,
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open(
        &self,
        _seller: &str,
        _open: PaidRouteSessionOpen,
    ) -> Result<()> {
        Err(anyhow!("paid route sessions are unsupported on this platform"))
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open_ack(
        &self,
        _buyer: &str,
        _lease_id: String,
    ) -> Result<()> {
        Err(anyhow!("paid route sessions are unsupported on this platform"))
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) fn enqueue_paid_route_payment(
        &self,
        _seller: &str,
        _id: String,
        _envelope: StreamingRoutePaymentEnvelope,
    ) -> Result<()> {
        Err(anyhow!("direct FIPS payments are unsupported on this platform"))
    }

    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_payment_ack(
        &self,
        _buyer: &str,
        _id: String,
    ) -> Result<()> {
        Err(anyhow!("direct FIPS payments are unsupported on this platform"))
    }

    pub(crate) fn peer_advertised_routes(&self, _participant: &str) -> Vec<String> {
        Vec::new()
    }

    pub(crate) fn drain_events(&mut self) -> Vec<FipsPrivateMeshEvent> {
        Vec::new()
    }

    pub(crate) async fn stop(self) -> Result<()> {
        Ok(())
    }
}
