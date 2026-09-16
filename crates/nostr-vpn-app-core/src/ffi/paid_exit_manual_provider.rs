impl NativeAppRuntime {
    pub(super) fn buy_manual_paid_exit_provider_if_available(&mut self) -> Result<bool> {
        let provider = &self.config.manual_paid_exit_provider;
        if provider.is_default()
            || provider.max_price_msat_per_gb.is_none()
            || (self.config.internet_source == InternetSource::PaidManual
                && normalize_nostr_pubkey(&self.config.exit_node).ok()
                    == normalize_nostr_pubkey(&provider.npub).ok())
        {
            return Ok(false);
        }
        let store = load_paid_route_store(&self.paid_route_store_path())?;
        let now_unix = unix_timestamp();
        let mut rejected = None;
        let offer_key = store
            .offers
            .iter()
            .filter(|(_, record)| {
                record.signed_offer.is_live_at(now_unix)
                    && record.offer.seller_npub == provider.npub
            })
            .filter_map(|(key, record)| match provider.accepts(&record.offer) {
                Ok(()) => Some((record.signed_offer.event.created_at.as_secs(), key.clone())),
                Err(error) => {
                    rejected = Some(error);
                    None
                }
            })
            .max_by_key(|(created_at, _)| *created_at)
            .map(|(_, key)| key);
        let Some(offer_key) = offer_key else {
            if let Some(error) = rejected {
                return Err(error);
            }
            return Ok(false);
        };
        self.buy_paid_route_offer(&offer_key, None, None, InternetSource::PaidManual)?;
        Ok(true)
    }

    pub(super) fn import_manual_paid_exit_provider_offer(
        &mut self,
        duration_secs: u64,
    ) -> Result<()> {
        if self.mobile_runtime || self.config.manual_paid_exit_provider.is_default() {
            return Ok(());
        }
        let mut args = self.paid_exit_cli_args("discover")?;
        args.extend([
            "--duration-secs".to_string(),
            duration_secs.min(10).to_string(),
            "--provider".to_string(),
            self.config.manual_paid_exit_provider.link()?,
        ]);
        let output = self.run_nvpn_vec(&args)?;
        ensure_success("nvpn paid-exit targeted offer import", &output)
    }
}
