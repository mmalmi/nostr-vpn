use super::*;

impl NvpnBackend {
    pub(crate) fn start_lan_pairing(&mut self) -> Result<()> {
        if self.lan_pairing_running {
            return Ok(());
        }

        let own_npub = self
            .config
            .own_nostr_pubkey_hex()
            .map(|hex| to_npub(&hex))
            .unwrap_or_else(|_| self.config.nostr.public_key.clone());
        let node_name = self.config.node_name.clone();
        let endpoint = self.config.node.endpoint.clone();
        let invite = active_network_invite_code(&self.config)?;

        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = stop.clone();

        self.runtime.spawn(async move {
            run_lan_pairing_loop(tx, stop_flag, own_npub, node_name, endpoint, invite).await;
        });

        self.lan_pairing_rx = Some(rx);
        self.lan_pairing_stop = Some(stop);
        self.lan_pairing_running = true;
        self.lan_pairing_expires_at =
            Some(SystemTime::now() + Duration::from_secs(LAN_PAIRING_DURATION_SECS));
        self.lan_peers.clear();

        Ok(())
    }

    pub(crate) fn stop_lan_pairing(&mut self) {
        if let Some(stop) = self.lan_pairing_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        self.lan_pairing_rx = None;
        self.lan_pairing_running = false;
        self.lan_pairing_expires_at = None;
        self.lan_peers.clear();
    }

    pub(crate) fn refresh_lan_pairing(&mut self) {
        if self.lan_pairing_running && self.lan_pairing_remaining_secs() == 0 {
            self.stop_lan_pairing();
            return;
        }

        self.handle_lan_pairing_events();
        self.prune_lan_peers();
    }

    pub(crate) fn clear_connected_join_requests(&mut self) {
        let own_pubkey_hex = self.config.own_nostr_pubkey_hex().ok();
        let completed_networks = self
            .config
            .networks
            .iter()
            .filter_map(|network| {
                let request = network.outbound_join_request.as_ref()?;
                if self.outbound_join_request_connected(request, own_pubkey_hex.as_deref()) {
                    Some(network.id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if completed_networks.is_empty() {
            return;
        }

        for network_id in completed_networks {
            if let Some(network) = self.config.network_by_id_mut(&network_id) {
                network.outbound_join_request = None;
            }
        }

        if let Err(error) = self.persist_config_without_daemon_reload() {
            eprintln!("gui: failed to clear completed join request state: {error}");
        }
    }

    fn outbound_join_request_connected(
        &self,
        request: &PendingOutboundJoinRequest,
        own_pubkey_hex: Option<&str>,
    ) -> bool {
        if !matches!(
            self.peer_state_for(&request.recipient, own_pubkey_hex),
            ConfiguredPeerStatus::Online
        ) {
            return false;
        }

        let Some(last_handshake_at) = self
            .peer_status
            .get(&request.recipient)
            .and_then(|status| status.last_handshake_at)
        else {
            return false;
        };
        let Some(requested_at) = epoch_secs_to_system_time(request.requested_at) else {
            return false;
        };

        last_handshake_at > requested_at
    }

    pub(crate) fn lan_pairing_remaining_secs(&self) -> u64 {
        self.lan_pairing_expires_at
            .and_then(|expires_at| expires_at.duration_since(SystemTime::now()).ok())
            .map(|remaining| remaining.as_secs())
            .unwrap_or(0)
    }

    pub(crate) fn handle_lan_pairing_events(&mut self) {
        let recv_result = self
            .lan_pairing_rx
            .as_ref()
            .map(|receiver| receiver.try_recv());

        match recv_result {
            Some(Ok(event)) => {
                self.lan_peers.insert(
                    event.npub.clone(),
                    LanPeerRecord {
                        npub: event.npub,
                        node_name: event.node_name,
                        endpoint: event.endpoint,
                        network_name: event.network_name,
                        network_id: event.network_id,
                        invite: event.invite,
                        last_seen: event.seen_at,
                    },
                );

                if let Some(receiver) = &self.lan_pairing_rx {
                    while let Ok(event) = receiver.try_recv() {
                        self.lan_peers.insert(
                            event.npub.clone(),
                            LanPeerRecord {
                                npub: event.npub,
                                node_name: event.node_name,
                                endpoint: event.endpoint,
                                network_name: event.network_name,
                                network_id: event.network_id,
                                invite: event.invite,
                                last_seen: event.seen_at,
                            },
                        );
                    }
                }
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.lan_pairing_running = false;
                self.lan_pairing_rx = None;
                self.lan_pairing_stop = None;
                self.lan_pairing_expires_at = None;
                self.lan_peers.clear();
            }
            _ => {}
        }
    }

    pub(crate) fn prune_lan_peers(&mut self) {
        self.lan_peers.retain(|_, peer| {
            peer.last_seen
                .elapsed()
                .map(|elapsed| elapsed.as_secs() <= LAN_PAIRING_STALE_AFTER_SECS)
                .unwrap_or(false)
        });
    }

    pub(crate) fn lan_peer_rows(&self) -> Vec<LanPeerView> {
        let mut peers = self.lan_peers.values().cloned().collect::<Vec<_>>();
        peers.sort_by(|left, right| left.npub.cmp(&right.npub));

        peers
            .into_iter()
            .map(|peer| {
                let last_seen_secs = peer
                    .last_seen
                    .elapsed()
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or(0);

                LanPeerView {
                    npub: peer.npub,
                    node_name: peer.node_name,
                    endpoint: peer.endpoint,
                    network_name: peer.network_name,
                    network_id: peer.network_id,
                    invite: peer.invite,
                    last_seen_text: compact_age_text(last_seen_secs),
                }
            })
            .collect()
    }
}
