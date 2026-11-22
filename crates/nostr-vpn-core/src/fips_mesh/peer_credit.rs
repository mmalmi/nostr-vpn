const CREDIT_SESSION_PREFIX: &str = "peer-credit:";

#[cfg(feature = "peer-credit")]
#[derive(Debug)]
struct CreditWindow {
    session: String,
    initial_units: u64,
    address: IpAddr,
    closed: std::sync::atomic::AtomicBool,
    sealed: std::sync::atomic::AtomicBool,
    allowance: Mutex<peer_payments::Allowance>,
}

#[cfg(feature = "peer-credit")]
impl FipsMeshRuntime {
    /// Validate the locally allocated tunnel address and route ownership before
    /// opening a durable window. A peer cannot claim a private or occupied IP.
    pub fn check_credit_exit(
        &self,
        provider: &str,
        tunnel_ip: IpAddr,
        a: &peer_payments::Agreement,
    ) -> Result<()> {
        anyhow::ensure!(
            a.provider == normalize_nostr_pubkey(provider)?,
            "wrong credit provider"
        );
        anyhow::ensure!(
            a.service == "vpn.exit.upload_bytes"
                && a.resource == format!("internet-exit-upload:{tunnel_ip}"),
            "wrong credit service or resource"
        );
        let payer = parse_nostr_pubkey_bytes(&a.payer).context("invalid credit payer")?;
        let session = format!("{CREDIT_SESSION_PREFIX}{}", a.commitment()?);
        anyhow::ensure!(
            self.select_local_route_for_ip(tunnel_ip)
                .is_none_or(|route| route.is_default_route()),
            "tunnel address belongs to local route"
        );
        for (owner, admission) in &self.paid_route_admissions {
            if owner != &payer {
                anyhow::ensure!(
                    !admission
                        .allowed_ips
                        .iter()
                        .filter_map(|v| IpRoute::parse(v))
                        .any(|r| r.matches(tunnel_ip)),
                    "tunnel address is already paid for"
                );
            }
        }
        if let Some(old) = self.paid_route_admissions.get(&payer) {
            let finished = self.credit_allowances.get(&payer).is_some_and(|w| {
                w.session == old.session_id && w.closed.load(std::sync::atomic::Ordering::Acquire)
            });
            anyhow::ensure!(
                finished || old.session_id == session,
                "another payment session owns this exit"
            );
        }
        anyhow::ensure!(
            !self
                .peers
                .iter()
                .any(|peer| peer.participant_pubkey != Some(payer)
                    && peer
                        .routes
                        .iter()
                        .any(|r| !r.is_default_route() && r.matches(tunnel_ip))),
            "another configured peer owns the tunnel address"
        );
        anyhow::ensure!(
            !self
                .credit_allowances
                .iter()
                .any(|(owner, w)| owner != &payer
                    && w.address == tunnel_ip
                    && !w.closed.load(std::sync::atomic::Ordering::Acquire)),
            "another open credit window owns the address"
        );
        if let Some(old) = self.credit_allowances.get(&payer) {
            anyhow::ensure!(
                old.session == session || old.closed.load(std::sync::atomic::Ordering::Acquire),
                "an unresolved credit window exists"
            );
        }
        anyhow::ensure!(
            self.credit_allowances.contains_key(&payer) || self.credit_allowances.len() < 256,
            "credit exit limit"
        );
        Ok(())
    }

    /// Count only IP uploads eligible for this public exit service.
    pub fn credit_upload_packet(source: IpAddr, packet: &[u8]) -> bool {
        packet_endpoints(packet)
            .is_some_and(|(from, to)| from == source && is_public_exit_destination(to))
    }

    pub fn credit_upload_units(&self, payer: &str, id: &str) -> Result<u64> {
        let key = parse_nostr_pubkey_bytes(payer).context("invalid credit payer")?;
        let live = self
            .credit_allowances
            .get(&key)
            .context("no live upload meter")?;
        let window = live
            .allowance
            .lock()
            .map_err(|_| anyhow::anyhow!("upload meter unavailable"))?;
        anyhow::ensure!(window.agreement().id == id, "different service window");
        Ok(live.initial_units - window.remaining())
    }

    /// Seal before reading, under the packet-admission lock, so losses and
    /// in-flight packets cannot change the final amount after a payer signs.
    pub fn seal_credit_upload(&self, payer: &str, id: &str) -> Result<u64> {
        let key = parse_nostr_pubkey_bytes(payer).context("invalid payer")?;
        let live = self
            .credit_allowances
            .get(&key)
            .context("no live upload meter")?;
        let window = live
            .allowance
            .lock()
            .map_err(|_| anyhow::anyhow!("upload meter unavailable"))?;
        anyhow::ensure!(window.agreement().id == id, "different agreement");
        live.sealed
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(live.initial_units - window.remaining())
    }

    /// Recheck every live window after a local egress or route change. The
    /// enabled flag also closes admission through previously cached snapshots.
    pub fn reconcile_credit_exits(
        &mut self,
        provider: &str,
        ready: bool,
        upstream_peer: Option<&str>,
        now: u64,
    ) {
        let mut admissions: Vec<_> = self.paid_route_admissions.values().cloned().collect();
        for (payer, live) in &self.credit_allowances {
            if !ready
                || self.paid_route_admissions.contains_key(payer)
                || live.closed.load(std::sync::atomic::Ordering::Acquire)
            {
                continue;
            }
            let Ok(window) = live.allowance.lock() else {
                continue;
            };
            let a = window.agreement();
            if upstream_peer != Some(a.payer.as_str())
                && a.expires_at > now
                && self.check_credit_exit(provider, live.address, a).is_ok()
            {
                admissions.push(Self::credit_admission(
                    a,
                    live.address,
                    live.session.clone(),
                ));
            }
        }
        self.replace_paid_route_admissions(admissions);
    }

    /// Complete a receipt against the independently admitted upload-byte count.
    /// Serializing the final meter check with packet admission prevents a last
    /// packet from racing the final receipt. No network I/O occurs here.
    pub fn settle_credit_upload(
        &self,
        authenticated_peer: &str,
        receipt: &peer_payments::Signed<peer_payments::Receipt>,
        controller: &mut peer_payments::Controller<'_>,
    ) -> Result<peer_payments::Signed<peer_payments::Receipt>> {
        let payer = normalize_nostr_pubkey(authenticated_peer)?;
        anyhow::ensure!(payer == receipt.payload.payer, "receipt from another payer");
        let payer = parse_nostr_pubkey_bytes(&payer).context("invalid credit payer")?;
        let live = self
            .credit_allowances
            .get(&payer)
            .context("no live upload meter")?;
        let window = live
            .allowance
            .lock()
            .map_err(|_| anyhow::anyhow!("upload meter unavailable"))?;
        anyhow::ensure!(
            window.agreement().id == receipt.payload.agreement_id
                && window.agreement().commitment()? == receipt.payload.agreement_commitment,
            "wrong service window"
        );
        let ack = controller.receive_receipt(receipt, live.initial_units - window.remaining())?;
        if receipt.payload.final_receipt {
            live.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(ack)
    }
}

impl FipsMeshRuntime {
    /// Install an already persisted, single-owner service window. This prototype
    /// prices uploaded IP bytes; it does not replace Cashu's ACK-based meter or
    /// claim that credit is bitcoin. The payment controller owns negotiation.
    #[cfg(feature = "peer-credit")]
    pub fn install_credit_exit(
        &mut self,
        local_provider: &str,
        tunnel_ip: IpAddr,
        allowance: peer_payments::Allowance,
    ) -> Result<()> {
        let a = allowance.agreement();
        self.check_credit_exit(local_provider, tunnel_ip, a)?;
        let payer = parse_nostr_pubkey_bytes(&a.payer).context("invalid credit payer")?;
        let session = format!("{CREDIT_SESSION_PREFIX}{}", a.commitment()?);
        let mut admissions: Vec<_> = self
            .paid_route_admissions
            .values()
            .filter(|old| old.participant_pubkey != a.payer)
            .cloned()
            .collect();
        admissions.push(Self::credit_admission(a, tunnel_ip, session.clone()));
        self.credit_allowances.insert(
            payer,
            Arc::new(CreditWindow {
                session,
                address: tunnel_ip,
                closed: false.into(),
                sealed: false.into(),
                initial_units: allowance.remaining(),
                allowance: Mutex::new(allowance),
            }),
        );
        self.replace_paid_route_admissions(admissions);
        Ok(())
    }

    #[cfg(feature = "peer-credit")]
    fn credit_admission(
        a: &peer_payments::Agreement,
        tunnel_ip: IpAddr,
        session: String,
    ) -> FipsPaidRouteAdmission {
        let prefix = if tunnel_ip.is_ipv4() { 32 } else { 128 };
        FipsPaidRouteAdmission {
            participant_pubkey: a.payer.clone(),
            session_id: session,
            allowed_ips: vec![format!("{tunnel_ip}/{prefix}")],
            destination_allowed_ips: Vec::new(),
            allow_routing: true,
            state: PaidRouteAccessState::Grace,
            amount_due_msat: 0,
            paid_msat: 0,
            unpaid_msat: 0,
            expires_at_unix: a.expires_at,
            updated_at_unix: a.created_at,
        }
    }
}

impl FipsEndpointSourceAdmitter<'_> {
    fn admit_credit_packet(&self, bytes: usize) -> bool {
        // A cached source holds a reference to the shared live meter. Missing
        // or mismatched session state denies service even with warm IP caches.
        #[cfg(feature = "peer-credit")]
        {
            let Some(live) = self.credit_window else {
                return false;
            };
            let Ok(mut window) = live.allowance.lock() else {
                return false;
            };
            let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
                return false;
            };
            let Ok(bytes) = u64::try_from(bytes) else {
                return false;
            };
            self.runtime
                .credit_snapshot_active
                .load(std::sync::atomic::Ordering::Acquire)
                && !live.sealed.load(std::sync::atomic::Ordering::Acquire)
                && window.admit(bytes, now.as_secs())
        }
        #[cfg(not(feature = "peer-credit"))]
        {
            let _ = bytes;
            false
        }
    }
}
