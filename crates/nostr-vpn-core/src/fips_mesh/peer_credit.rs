const CREDIT_SESSION_PREFIX: &str = "peer-credit:";

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
        anyhow::ensure!(
            a.provider == normalize_nostr_pubkey(local_provider)?,
            "wrong credit provider"
        );
        anyhow::ensure!(
            a.service == "vpn.exit.upload_bytes"
                && a.resource == format!("internet-exit-upload:{tunnel_ip}"),
            "wrong credit service or resource"
        );
        let payer = parse_nostr_pubkey_bytes(&a.payer).context("invalid credit payer")?;
        let session = format!("{CREDIT_SESSION_PREFIX}{}", a.commitment()?);
        if let Some(existing) = self.paid_route_admissions.get(&payer) {
            anyhow::ensure!(
                existing.session_id == session,
                "another payment session owns this exit"
            );
        }
        anyhow::ensure!(
            self.credit_allowances.contains_key(&payer) || self.credit_allowances.len() < 256,
            "credit exit limit"
        );
        let prefix = if tunnel_ip.is_ipv4() { 32 } else { 128 };
        let mut admissions: Vec<_> = self
            .paid_route_admissions
            .values()
            .filter(|old| old.participant_pubkey != a.payer)
            .cloned()
            .collect();
        admissions.push(FipsPaidRouteAdmission {
            participant_pubkey: a.payer.clone(),
            session_id: session.clone(),
            allowed_ips: vec![format!("{tunnel_ip}/{prefix}")],
            destination_allowed_ips: Vec::new(),
            allow_routing: true,
            state: PaidRouteAccessState::Grace,
            amount_due_msat: 0,
            paid_msat: 0,
            unpaid_msat: 0,
            expires_at_unix: a.expires_at,
            updated_at_unix: a.created_at,
        });
        self.credit_allowances
            .insert(payer, (session, Arc::new(Mutex::new(allowance))));
        self.replace_paid_route_admissions(admissions);
        Ok(())
    }

    fn admit_credit_packet(&self, peer: &FipsMeshPeerRuntime, bytes: usize) -> bool {
        let Some(payer) = peer.participant_pubkey.as_ref() else {
            return true;
        };
        let Some(admission) = self.paid_route_admissions.get(payer) else {
            return true;
        };
        if !admission.session_id.starts_with(CREDIT_SESSION_PREFIX) {
            return true;
        }
        // A rebuilt runtime or disabled feature must never turn missing credit
        // state into an unlimited grace session, including with a warm IP cache.
        #[cfg(feature = "peer-credit")]
        {
            let Some((session, window)) = self.credit_allowances.get(payer) else {
                return false;
            };
            if *session != admission.session_id {
                return false;
            }
            let Ok(mut window) = window.lock() else {
                return false;
            };
            let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
                return false;
            };
            let Ok(bytes) = u64::try_from(bytes) else {
                return false;
            };
            window.admit(bytes, now.as_secs())
        }
        #[cfg(not(feature = "peer-credit"))]
        {
            let _ = bytes;
            false
        }
    }
}
