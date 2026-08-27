const DEFAULT_PAID_EXIT_WALLET_MINT: &str = "https://mint.minibits.cash/Bitcoin";

struct PaidRouteWalletTokenPreview {
    mint_url: String,
    amount_sat: u64,
    memo: String,
    state: &'static str,
    status_text: String,
    redeemable: bool,
}

fn paid_route_wallet_mint_label(store: &PaidRouteStore, mint_url: &str) -> String {
    store
        .wallet
        .mints
        .iter()
        .find(|mint| mint.url == mint_url)
        .map_or_else(
            || match mint_url {
                DEFAULT_PAID_EXIT_WALLET_MINT => "Minibits".to_string(),
                _ => String::new(),
            },
            |mint| mint.label.clone(),
        )
}

impl NativeAppRuntime {
    pub(super) fn paid_exit_seller_state(
        &self,
        app: Option<&AppConfig>,
        port_mapping: Option<&PortMappingStatus>,
        mobile: bool,
    ) -> NativePaidExitSellerState {
        let mut state = paid_exit_seller_state(
            app,
            self.daemon_state.as_ref(),
            port_mapping,
            paid_exit_seller_supported_for_current_target(mobile),
            &self.paid_route_store_path(),
        );
        if app.is_some_and(|app| app.wallet_fiat_enabled) {
            let snapshot = self.exchange_rate_service.snapshot();
            state.price_text = paid_route_price_text_with_fiat(
                state.price_msat_per_gb,
                snapshot.rate,
                snapshot.currency.as_str(),
                snapshot.stale,
            );
        }
        state
    }

    pub(super) fn paid_route_market_state(
        &self,
        app: Option<&AppConfig>,
    ) -> NativePaidRouteMarketState {
        let mut state = paid_route_market_state(
            app,
            &self.paid_route_store_path(),
            &self.paid_route_market_filter,
            &self.paid_route_wallet_last_action,
            &self.paid_route_payment_last_action,
        );
        if app.is_some_and(|app| app.wallet_fiat_enabled) {
            let snapshot = self.exchange_rate_service.snapshot();
            for offer in state.offers.iter_mut().chain(&mut state.visible_offers) {
                offer.price_text = paid_route_price_text_with_fiat(
                    offer.price_msat_per_gb,
                    snapshot.rate,
                    snapshot.currency.as_str(),
                    snapshot.stale,
                );
            }
        }
        state
    }

    fn paid_route_store_path(&self) -> PathBuf {
        paid_route_store_file_path(&self.config_path)
    }

    pub(super) fn active_paid_route_exit_ip(&self, selected_exit_node: &str) -> Option<String> {
        let selected_exit_node = normalize_nostr_pubkey(selected_exit_node).ok()?;
        let store = load_paid_route_store(&self.paid_route_store_path()).ok()?;
        let now_unix = unix_timestamp();
        store
            .sessions
            .values()
            .filter_map(|record| {
                let channel = store.channels.get(&record.session.payment.channel_id)?;
                let counterparty = normalize_nostr_pubkey(&channel.counterparty_npub).ok()?;
                (channel.role == PaidRouteChannelRole::Buyer
                    && counterparty == selected_exit_node
                    && store
                        .buyer_session_is_seller_admitted(&record.session.session_id)
                        .unwrap_or(false)
                    && store
                        .buyer_session_allows_routing(&record.session.session_id, now_unix)
                        .unwrap_or(false))
                .then(|| (
                    record.updated_at_unix,
                    record.session.realized_exit_ip.clone().unwrap_or_default(),
                ))
            })
            .max_by_key(|(updated_at, _)| *updated_at)
            .and_then(|(_, realized_exit_ip)| {
                (!realized_exit_ip.trim().is_empty()).then_some(realized_exit_ip)
            })
    }

    fn mutate_paid_route_store(
        &mut self,
        mutate: impl FnOnce(&mut PaidRouteStore) -> bool,
    ) -> Result<()> {
        let path = self.paid_route_store_path();
        update_paid_route_store(&path, |store| {
            mutate(store);
            Ok(())
        })
    }

    pub(super) fn add_paid_route_wallet_mint(
        &mut self,
        url: &str,
        label: Option<&str>,
    ) -> Result<()> {
        let url = normalize_paid_route_mint_url(url)?;
        self.mutate_paid_route_store(|store| {
            let default_changed = if store.wallet.default_mint.trim().is_empty() {
                store.wallet.default_mint.clone_from(&url);
                true
            } else {
                false
            };
            if let Some(existing) = store.wallet.mints.iter_mut().find(|mint| mint.url == url) {
                let Some(label) = label.map(str::trim) else {
                    return default_changed;
                };
                if existing.label == label {
                    return default_changed;
                }
                existing.label = label.to_string();
                true
            } else {
                store.upsert_wallet_mint(&url, label.unwrap_or_default(), None, unix_timestamp())
            }
        })
    }

    pub(super) fn remove_paid_route_wallet_mint(&mut self, url: &str) -> Result<()> {
        self.mutate_paid_route_store(|store| store.remove_wallet_mint(url))
    }

    pub(super) fn set_paid_route_default_mint(&mut self, url: &str) -> Result<()> {
        self.mutate_paid_route_store(|store| store.set_default_mint(url))
    }

    pub(super) fn refresh_paid_route_wallet(&mut self, refresh: bool) -> Result<()> {
        let pending_top_up = (self.paid_route_wallet_last_action.kind == "topup")
            .then(|| self.paid_route_wallet_last_action.clone());
        let (overview, activity) = {
            let wallet = self.cashu_wallet()?;
            let overview = wallet.overview(refresh)?;
            let activity = if refresh && pending_top_up.is_some() {
                wallet.activity()?
            } else {
                Vec::new()
            };
            (overview, activity)
        };
        self.sync_paid_route_wallet_overview(&overview)?;
        if let Some(mut top_up) = pending_top_up {
            let status = cashu_top_up_activity_status(&activity, &top_up.quote_id);
            if status == Some(PaidRouteTopUpActivityStatus::Complete) {
                top_up.kind = "topup_complete".to_string();
                top_up.status_text = format!("Received {} sat", top_up.amount_sat);
                top_up.payment_request.clear();
                self.paid_route_wallet_last_action = top_up;
                self.paid_route_wallet_next_refresh_at = None;
                return Ok(());
            }
            if status == Some(PaidRouteTopUpActivityStatus::Expired)
                || (top_up.expires_at_unix > 0 && top_up.expires_at_unix <= unix_timestamp())
            {
                top_up.kind = "topup_expired".to_string();
                top_up.status_text = "Invoice expired".to_string();
                top_up.payment_request.clear();
                self.paid_route_wallet_last_action = top_up;
                self.paid_route_wallet_next_refresh_at = None;
                return Ok(());
            }
            top_up.status_text = format!("Waiting for {} sat", top_up.amount_sat);
            self.paid_route_wallet_last_action = top_up;
            return Ok(());
        }
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "refresh".to_string(),
            status_text: "Wallet refreshed".to_string(),
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    pub(super) fn top_up_paid_route_wallet(
        &mut self,
        mint_url: Option<&str>,
        amount_sat: u64,
    ) -> Result<()> {
        let mint_url = self.paid_route_wallet_mint(mint_url)?;
        let quote = self
            .cashu_wallet()?
            .create_topup_quote(&mint_url, amount_sat)?;
        self.ensure_paid_route_wallet_mint(&quote.mint_url, None)?;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "topup".to_string(),
            status_text: format!("Top-up invoice for {amount_sat} sat"),
            mint_url: quote.mint_url,
            amount_sat: quote.amount,
            amount_text: paid_route_sat_text(amount_sat),
            quote_id: quote.quote_id,
            payment_request: quote.payment_request,
            expires_at_unix: quote.expiry_unix,
            ..NativePaidRouteWalletActionState::default()
        };
        self.paid_route_wallet_next_refresh_at =
            Some(std::time::Instant::now() + PAID_ROUTE_WALLET_TOP_UP_POLL_CADENCE);
        Ok(())
    }

    pub(super) fn refresh_pending_paid_route_wallet(&mut self) {
        if self.paid_route_wallet_last_action.kind != "topup" {
            self.paid_route_wallet_next_refresh_at = None;
            return;
        }
        let now = std::time::Instant::now();
        if self
            .paid_route_wallet_next_refresh_at
            .is_some_and(|next_refresh| now < next_refresh)
        {
            return;
        }
        self.paid_route_wallet_next_refresh_at = Some(now + PAID_ROUTE_WALLET_TOP_UP_POLL_CADENCE);
        let _ = self.refresh_paid_route_wallet(true);
    }

    pub(super) fn receive_paid_route_wallet_token(&mut self, token: &str) -> Result<()> {
        let token = token.trim();
        if token.is_empty() {
            return Err(anyhow!("Token is empty"));
        }
        let received = self.cashu_wallet()?.receive_token(token)?;
        let amount_sat = received.amount_sat;
        let overview = self.cashu_wallet()?.overview(false)?;
        self.sync_paid_route_wallet_overview(&overview)?;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "receive".to_string(),
            status_text: format!("Received {amount_sat} sat"),
            mint_url: received.mint_url,
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    pub(super) fn preview_paid_route_wallet_token(&mut self, token: &str) -> Result<()> {
        let token = token.trim();
        if token.is_empty() {
            return Err(anyhow!("Token is empty"));
        }
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "preview_checking".to_string(),
            status_text: "Checking token".to_string(),
            ..NativePaidRouteWalletActionState::default()
        };
        let preview = inspect_paid_route_wallet_token(token)?;
        let amount_sat = preview.amount_sat;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "preview".to_string(),
            status_text: preview.status_text,
            mint_url: preview.mint_url,
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            token_state: preview.state.to_string(),
            token_redeemable: preview.redeemable,
            token_memo: preview.memo,
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    pub(super) fn send_paid_route_wallet_token(
        &mut self,
        mint_url: Option<&str>,
        amount_sat: u64,
    ) -> Result<()> {
        let mint_url = self.paid_route_wallet_mint(mint_url)?;
        let sent = self.cashu_wallet()?.send_token(&mint_url, amount_sat)?;
        let amount_sat = sent.amount_sat;
        let fee_sat = sent.send_fee_sat;
        let overview = self.cashu_wallet()?.overview(false)?;
        self.sync_paid_route_wallet_overview(&overview)?;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "send".to_string(),
            status_text: format!("Created token for {amount_sat} sat"),
            mint_url: sent.mint_url,
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            fee_sat,
            fee_text: paid_route_fee_text(fee_sat),
            operation_id: sent.operation_id,
            token: sent.token,
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    pub(super) fn withdraw_paid_route_wallet_lightning(
        &mut self,
        mint_url: Option<&str>,
        invoice: &str,
    ) -> Result<()> {
        let invoice = invoice.trim();
        if invoice.is_empty() {
            return Err(anyhow!("Lightning invoice is empty"));
        }
        let mint_url = self.paid_route_wallet_mint(mint_url)?;
        let withdrawal = self.cashu_wallet()?.pay_lightning(&mint_url, invoice)?;
        let amount_sat = withdrawal.amount_sat;
        let fee_sat = withdrawal.fee_paid_sat;
        let overview = self.cashu_wallet()?.overview(false)?;
        self.sync_paid_route_wallet_overview(&overview)?;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "withdraw".to_string(),
            status_text: format!("Paid Lightning invoice for {amount_sat} sat"),
            mint_url: withdrawal.mint_url,
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            fee_sat,
            fee_text: paid_route_fee_text(fee_sat),
            quote_id: withdrawal.quote_id,
            preimage: withdrawal.preimage,
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    fn cashu_wallet(&self) -> Result<PaidRouteWalletClient<'_>> {
        PaidRouteWalletClient::new(self)
    }

    fn wallet_data_dir(&self) -> PathBuf {
        self.config_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    fn paid_route_wallet_mint(&self, explicit: Option<&str>) -> Result<String> {
        if let Some(mint) = explicit.map(str::trim).filter(|mint| !mint.is_empty()) {
            return normalize_paid_route_mint_url(mint);
        }
        let store = load_paid_route_store(&self.paid_route_store_path())?;
        if !store.wallet.default_mint.trim().is_empty() {
            return normalize_paid_route_mint_url(&store.wallet.default_mint);
        }
        Err(anyhow!(
            "No mint configured; add a mint before using the Cashu wallet"
        ))
    }

    fn ensure_paid_route_wallet_mint(
        &mut self,
        mint_url: &str,
        balance_msat: Option<u64>,
    ) -> Result<()> {
        let mint_url = normalize_paid_route_mint_url(mint_url)?;
        self.mutate_paid_route_store(|store| {
            let label = paid_route_wallet_mint_label(store, &mint_url);
            store.upsert_wallet_mint(&mint_url, label, balance_msat, unix_timestamp())
        })
    }

    fn sync_paid_route_wallet_overview(
        &mut self,
        overview: &cashu_service::CashuWalletOverview,
    ) -> Result<()> {
        self.mutate_paid_route_store(|store| {
            let mut changed = false;
            for entry in &overview.entries {
                if entry.unit != "sat" {
                    continue;
                }
                let label = paid_route_wallet_mint_label(store, &entry.mint_url);
                changed |= store.upsert_wallet_mint(
                    &entry.mint_url,
                    label,
                    Some(entry.balance.saturating_mul(1000)),
                    unix_timestamp(),
                );
            }
            changed
        })
    }

    pub(super) fn buy_paid_route_offer(
        &mut self,
        offer_key: &str,
        mint_url: Option<&str>,
        channel_capacity_sat: Option<u64>,
    ) -> Result<()> {
        let buyer_npub = self
            .config
            .nostr_keys()?
            .public_key()
            .to_bech32()
            .context("failed to encode buyer npub")?;
        let path = self.paid_route_store_path();
        let now_unix = unix_timestamp();
        let manual_provider = self.config.manual_paid_exit_provider.clone();
        let offer_key = offer_key.to_string();
        let requested_mint = mint_url.map(ToOwned::to_owned);
        let (result, wallet_can_fund, free_probe_ready) =
            update_paid_route_store(&path, |store| {
                let preferred_mint = if manual_provider.is_default() {
                    requested_mint
                } else {
                    let offer = store.live_offer_for_selector(&offer_key, now_unix)?;
                    manual_provider.accepts(&offer)?;
                    requested_mint.or_else(|| {
                        (!manual_provider.mint.is_empty()).then(|| manual_provider.mint.clone())
                    })
                };
                let result = store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
                    offer_selector: offer_key,
                    buyer_npub,
                    mint_url: preferred_mint,
                    channel_capacity_sat,
                    initial_paid_msat: 0,
                    now_unix,
                })?;
                let wallet_can_fund = paid_route_wallet_can_fund_channel(
                    &store.wallet,
                    &result.mint_url,
                    result.channel_capacity_sat,
                );
                let free_probe_ready =
                    store.buyer_session_allows_routing(&result.session_id, now_unix)?;
                Ok((result, wallet_can_fund, free_probe_ready))
            })?;
        if !wallet_can_fund && !free_probe_ready {
            return Err(anyhow!(
                "Paid route created but is not ready: the selected mint needs at least {} sat to fund it",
                result.channel_capacity_sat
            ));
        }

        // Persist the authenticated seller before payment, but only install public routes
        // after the seller acknowledges admission.
        self.select_paid_route_session(&result.session_id, false)?;

        if wallet_can_fund {
            self.open_paid_route_channel_from_wallet(
                &result.session_id,
                Some(&result.mint_url),
                None,
                None,
                None,
            )?;
            let envelope_json = self.paid_route_payment_last_action.envelope_json.clone();
            if !envelope_json.trim().is_empty() {
                self.send_paid_route_payment_envelope(&envelope_json)?;
            }
        }

        let store = load_paid_route_store(&path)?;
        if store.buyer_session_allows_routing(&result.session_id, unix_timestamp())? {
            self.select_paid_route_session(&result.session_id, true)?;
        } else {
            return Err(anyhow!(
                "Paid route created but is not ready: the selected mint needs at least {} sat to fund it",
                result.channel_capacity_sat
            ));
        }

        Ok(())
    }

    pub(super) fn buy_best_paid_route_offer(
        &mut self,
        mint_url: Option<&str>,
        channel_capacity_sat: Option<u64>,
    ) -> Result<()> {
        let store = load_paid_route_store(&self.paid_route_store_path())?;
        let offer_key = store.best_rated_offer_key()?;
        self.buy_paid_route_offer(&offer_key, mint_url, channel_capacity_sat)
    }

    pub(super) fn select_paid_route_session(
        &mut self,
        session_id: &str,
        connect: bool,
    ) -> Result<()> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            return Err(anyhow!("paid route session id is empty"));
        }
        let now_unix = unix_timestamp();
        let store_path = self.paid_route_store_path();
        let (seller_npub, endpoint_hints) = update_paid_route_store(&store_path, |store| {
            let seller_npub = store.buyer_session_seller_npub(session_id)?;
            if connect {
                store.retry_failed_funded_buyer_session(session_id, now_unix)?;
                if !store.buyer_session_allows_routing(session_id, now_unix)? {
                    return Err(anyhow!(
                        "paid route session is not ready to route yet; fund it or wait for seller admission"
                    ));
                }
            }
            store.begin_buyer_session_open_attempt(session_id, now_unix)?;
            let endpoint_hints = store.buyer_session_seller_fips_endpoints(session_id)?;
            Ok((seller_npub, endpoint_hints))
        })?;
        self.config
            .add_fips_peer_endpoint_hints(&seller_npub, &endpoint_hints)?;
        self.config.select_public_paid_exit_node(&seller_npub)?;
        self.save_reload_and_refresh()?;
        if connect && !self.vpn_enabled {
            self.connect_vpn()?;
        }
        Ok(())
    }

}

include!("paid_exit_actions/session_actions.rs");
