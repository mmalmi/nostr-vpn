#[cfg(any(target_os = "linux", target_os = "macos"))]
fn combined_failures(failures: Vec<String>) -> Result<()> {
    if !failures.is_empty() {
        return Err(anyhow!(failures.join("; ")));
    }
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn fips_host_disabled_cleanup_due(runtime_running: bool, cleanup_complete: bool) -> bool {
    !runtime_running && !cleanup_complete
}
macro_rules! mesh_delegate {
    ($(#[$meta:meta])* async fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $result:ty) => {
        $(#[$meta])*
        pub(crate) async fn $name(&self, $($arg: $ty),*) -> $result {
            self.mesh.$name($($arg),*).await
        }
    };
    ($(#[$meta:meta])* fn $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $result:ty) => {
        $(#[$meta])*
        pub(crate) fn $name(&self, $($arg: $ty),*) -> $result {
            self.mesh.$name($($arg),*)
        }
    };
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl FipsPrivateTunnelRuntime {
    pub(crate) fn iface(&self) -> &str {
        &self.iface
    }
    pub(crate) fn active_listen_port(&self) -> Option<u16> {
        self.active_listen_port
    }
    #[cfg(all(
        feature = "paid-exit",
        any(target_os = "linux", target_os = "macos")
    ))]
    pub(crate) fn paid_exit_seller_ready(&self) -> bool {
        self.active_listen_port.is_some() && self.local_exit_seller_egress_ready
    }
    pub(crate) fn client_dataplane_enabled(&self) -> bool {
        self.config.client_dataplane_enabled
    }
    pub(crate) fn ethernet_underlay(&self) -> Option<&FipsEthernetUnderlayConfig> {
        self.config.ethernet_underlay.as_ref()
    }
    mesh_delegate!(fn peer_statuses() -> Vec<MeshPeerStatus>);
    mesh_delegate!(
        #[cfg(feature = "paid-exit")]
        fn drain_paid_route_usage(participant: &str) -> Result<PaidRouteUsage>
    );
    mesh_delegate!(fn stale_participants_needing_path_refresh(now: u64) -> Vec<String>);
    mesh_delegate!(async fn relay_statuses() -> Result<Vec<FipsRelayStatus>>);
    mesh_delegate!(async fn local_advertised_endpoints() -> Result<Vec<OverlayEndpointAdvert>>);
    mesh_delegate!(fn peer_pubkeys() -> Vec<String>);
    mesh_delegate!(async fn authenticated_endpoint_peers() -> Result<Vec<FipsEndpointPeer>>);
    mesh_delegate!(fn peer_endpoint_hints() -> Vec<(String, Vec<(String, u64)>)>);
    mesh_delegate!(
        /// Forward a refreshed peer roster and address hints without restarting the endpoint.
        async fn update_peers(endpoint_peers: &[FipsEndpointPeerTransportConfig])
            -> Result<fips_endpoint::UpdatePeersOutcome>
    );
    mesh_delegate!(
        async fn refresh_peer_paths(endpoint_peers: &[FipsEndpointPeerTransportConfig])
            -> Result<usize>
    );
    mesh_delegate!(async fn rebind_network_transports(bind_interface: Option<String>) -> Result<usize>);
    mesh_delegate!(async fn ping_peers(network_id: &str, now: u64) -> Result<usize>);
    mesh_delegate!(async fn ping_pending_join_peers(network_id: &str, now: u64) -> Result<usize>);
    mesh_delegate!(async fn refresh_link_statuses() -> Result<()>);
    mesh_delegate!(fn peer_advertised_routes(participant: &str) -> Vec<String>);
    pub(crate) fn enqueue_join_request(
        &self,
        participant: &str,
        requested_at: u64,
        request: MeshJoinRequest,
    ) -> Result<()> {
        self.mesh
            .enqueue_join_request(&self.state_control.sender(), participant, requested_at, request)
    }
    pub(crate) fn enqueue_roster(
        &self,
        participant: &str,
        signed_roster: SignedRoster,
    ) -> Result<()> {
        self.mesh
            .enqueue_roster(&self.state_control.sender(), participant, signed_roster)
    }
    pub(crate) fn join_roster_delivery(
        &self,
        participant: String,
        join_roster: JoinRosterControl,
    ) -> Result<FipsJoinRosterDelivery> {
        self.mesh.join_roster_delivery(
            self.state_control.sender(),
            participant,
            join_roster,
        )
    }
    pub(crate) async fn send_join_roster_ack(
        &self,
        participant: &str,
        roster_event_id: String,
    ) -> Result<()> {
        self.mesh
            .send_join_roster_ack(&self.state_control, participant, roster_event_id)
            .await
    }
    pub(crate) fn enqueue_capabilities(
        &self,
        participant: &str,
        network_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<()> {
        self.mesh.enqueue_capabilities(
            &self.state_control.sender(),
            participant,
            network_id,
            capabilities,
        )
    }
    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open(
        &self,
        seller: &str,
        open: PaidRouteSessionOpen,
    ) -> Result<()> {
        self.mesh
            .send_paid_route_session_open(&self.state_control, seller, open)
            .await
    }
    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_session_open_ack(
        &self,
        buyer: &str,
        lease_id: String,
    ) -> Result<()> {
        self.mesh
            .send_paid_route_session_open_ack(&self.state_control, buyer, lease_id)
            .await
    }
    #[cfg(feature = "paid-exit")]
    pub(crate) fn enqueue_paid_route_payment(
        &self,
        seller: &str,
        id: String,
        envelope: StreamingRoutePaymentEnvelope,
    ) -> Result<()> {
        self.mesh
            .enqueue_paid_route_payment(&self.state_control.sender(), seller, id, envelope)
    }
    #[cfg(feature = "paid-exit")]
    pub(crate) async fn send_paid_route_payment_ack(&self, buyer: &str, id: String) -> Result<()> {
        self.mesh
            .send_paid_route_payment_ack(&self.state_control, buyer, id)
            .await
    }
    pub(crate) fn drain_events(&mut self) -> Vec<FipsPrivateMeshEvent> {
        let mut events = drain_event_batch(&mut self.event_rx, FIPS_MESH_EVENT_DRAIN_LIMIT);
        let remaining = FIPS_MESH_EVENT_DRAIN_LIMIT.saturating_sub(events.len());
        for received in self.state_control.drain().into_iter().take(remaining) {
            match self.mesh.received_stateful_control_frame(received) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(error) => eprintln!("discarding invalid FIPS-TCP control record: {error}"),
            }
        }
        events
    }
}
