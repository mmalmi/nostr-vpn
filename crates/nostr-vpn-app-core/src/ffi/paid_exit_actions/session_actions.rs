impl NativeAppRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_paid_route_probe(
        &mut self,
        session_id: &str,
        realized_exit_ip: Option<&str>,
        observed_country_code: Option<&str>,
        observed_asn: Option<u32>,
        latency_ms: Option<u32>,
        jitter_ms: Option<u32>,
        packet_loss_ppm: Option<u32>,
        down_bps: Option<u64>,
        up_bps: Option<u64>,
        uptime_secs: Option<u64>,
        last_seen_unix: Option<u64>,
    ) -> Result<()> {
        let quality = PaidRouteQualityMetrics {
            latency_ms,
            jitter_ms,
            packet_loss_ppm,
            down_bps,
            up_bps,
            uptime_secs,
            last_seen_unix,
        };
        let path = self.paid_route_store_path();
        update_paid_route_store(&path, |store| {
            store.update_session_probe(UpdatePaidRouteSessionProbeRequest {
                session_id: session_id.to_string(),
                realized_exit_ip: realized_exit_ip.map(ToOwned::to_owned),
                observed_country_code: observed_country_code.map(ToOwned::to_owned),
                observed_asn,
                quality: (!quality.is_empty()).then_some(quality),
                now_unix: unix_timestamp(),
            })?;
            Ok(())
        })
    }

    pub(super) fn probe_paid_route_session(
        &mut self,
        session_id: &str,
        timeout_secs: u64,
    ) -> Result<()> {
        let mut args = self.paid_exit_cli_args("probe")?;
        args.extend([
            session_id.trim().to_string(),
            "--timeout-secs".to_string(),
            timeout_secs.max(1).to_string(),
        ]);
        let output = self.run_nvpn_vec(&args)?;
        let value = decode_paid_route_command_json_output(output, "nvpn paid-exit probe")?;
        self.paid_route_payment_last_action = paid_route_probe_action_state(&value);
        Ok(())
    }

    pub(super) fn create_paid_route_payment_envelope(
        &mut self,
        session_id: &str,
        kind: &str,
        payment_json: &str,
        delivered_units: Option<u64>,
        paid_msat: Option<u64>,
    ) -> Result<()> {
        let mut args = self.paid_exit_cli_args("create-payment")?;
        args.extend([
            session_id.trim().to_string(),
            "--kind".to_string(),
            kind.trim().to_string(),
            "--payment-stdin".to_string(),
        ]);
        if let Some(delivered_units) = delivered_units {
            args.push("--delivered-units".to_string());
            args.push(delivered_units.to_string());
        }
        if let Some(paid_msat) = paid_msat {
            args.push("--paid-msat".to_string());
            args.push(paid_msat.to_string());
        }

        let output = self.run_nvpn_vec_with_stdin(&args, payment_json.as_bytes())?;
        let value = decode_paid_route_command_json_output(output, "nvpn paid-exit create-payment")?;
        self.paid_route_payment_last_action = paid_route_payment_action_state("create", &value)?;
        Ok(())
    }

    pub(super) fn open_paid_route_channel_from_wallet(
        &mut self,
        session_id: &str,
        mint_url: Option<&str>,
        paid_msat: Option<u64>,
        max_amount_per_output: Option<u64>,
        keyset_id: Option<&str>,
    ) -> Result<()> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            return Err(anyhow!("paid route session id is empty"));
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        return self.open_paid_route_channel_from_daemon_wallet(
            session_id,
            mint_url,
            paid_msat,
            max_amount_per_output,
            keyset_id,
        );

        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
        let buyer_npub = self
            .config
            .nostr_keys()?
            .public_key()
            .to_bech32()
            .context("failed to encode buyer npub")?;
        let store_path = self.paid_route_store_path();
        let store = load_paid_route_store(&store_path)?;
        let request = paid_route_wallet_channel_open_request(
            &store,
            session_id,
            mint_url,
            paid_msat,
            max_amount_per_output,
            keyset_id,
        )?;
        let opened = self.cashu_wallet()?.open_spilman_channel(request)?;
        let payment = update_paid_route_store(&store_path, |store| {
            store.attach_buyer_spilman_channel(AttachPaidRouteBuyerSpilmanChannelRequest {
                session_id: session_id.to_string(),
                channel_id: opened.channel.channel_id.clone(),
                cashu_unit: opened.channel.unit.clone(),
                capacity_sat: opened.channel.capacity_sat,
                paid_msat: Some(opened.channel.opening_paid_msat),
                payment: opened.channel.payment.clone(),
                now_unix: unix_timestamp(),
            })?;
            store.build_buyer_payment_envelope(BuildPaidRouteBuyerPaymentEnvelopeRequest {
                session_id: session_id.to_string(),
                buyer_npub: buyer_npub.clone(),
                kind: BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
                payment: opened.channel.payment.clone(),
                delivered_units: None,
                paid_msat: Some(opened.channel.opening_paid_msat),
                now_unix: unix_timestamp(),
            })
        })?;
        self.paid_route_payment_last_action =
            paid_route_payment_action_state("open_channel", &json!({ "payment": payment }))?;
        let amount_sat = opened.wallet_send.amount_sat;
        let fee_sat = opened.wallet_send.send_fee_sat;
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "open_channel".to_string(),
            status_text: format!("Opened payment channel with {amount_sat} sat"),
            mint_url: opened.wallet_send.mint_url,
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            fee_sat,
            fee_text: paid_route_fee_text(fee_sat),
            operation_id: opened.wallet_send.operation_id,
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
        }
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    fn open_paid_route_channel_from_daemon_wallet(
        &mut self,
        session_id: &str,
        mint_url: Option<&str>,
        paid_msat: Option<u64>,
        max_amount_per_output: Option<u64>,
        keyset_id: Option<&str>,
    ) -> Result<()> {
        let mut args = self.paid_exit_cli_args("create-payment")?;
        args.extend([
            session_id.to_string(),
            "--kind".to_string(),
            "channel-open".to_string(),
            "--open-from-wallet".to_string(),
        ]);
        if let Some(mint_url) = mint_url.map(str::trim).filter(|value| !value.is_empty()) {
            args.extend(["--mint".to_string(), mint_url.to_string()]);
        }
        if let Some(paid_msat) = paid_msat {
            args.extend(["--paid-msat".to_string(), paid_msat.to_string()]);
        }
        if let Some(max_amount_per_output) = max_amount_per_output {
            args.extend([
                "--max-amount-per-output".to_string(),
                max_amount_per_output.to_string(),
            ]);
        }
        if let Some(keyset_id) = keyset_id.map(str::trim).filter(|value| !value.is_empty()) {
            args.extend(["--keyset-id".to_string(), keyset_id.to_string()]);
        }
        let output = self.run_nvpn_vec(&args)?;
        let value =
            decode_paid_route_command_json_output(output, "nvpn paid-exit create-payment")?;
        self.paid_route_payment_last_action =
            paid_route_payment_action_state("open_channel", &value)?;
        let wallet_send = value
            .get("wallet_open")
            .and_then(|wallet_open| wallet_open.get("wallet_send"))
            .ok_or_else(|| anyhow!("daemon wallet response has no channel funding result"))?;
        let amount_sat = json_u64(wallet_send, "amount_sat");
        let fee_sat = json_u64(wallet_send, "send_fee_sat");
        self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
            kind: "open_channel".to_string(),
            status_text: format!("Opened payment channel with {amount_sat} sat"),
            mint_url: json_string(wallet_send, "mint_url"),
            amount_sat,
            amount_text: paid_route_sat_text(amount_sat),
            fee_sat,
            fee_text: paid_route_fee_text(fee_sat),
            operation_id: json_string(wallet_send, "operation_id"),
            ..NativePaidRouteWalletActionState::default()
        };
        Ok(())
    }

    pub(super) fn sign_paid_route_payment_envelope_from_wallet(
        &mut self,
        session_id: &str,
        kind: &str,
        delivered_units: Option<u64>,
        paid_msat: Option<u64>,
    ) -> Result<()> {
        let kind = match kind.trim() {
            "channel-open" | "channel_open" => BuildPaidRouteBuyerPaymentEnvelopeKind::ChannelOpen,
            "balance-update" | "balance_update" => {
                BuildPaidRouteBuyerPaymentEnvelopeKind::BalanceUpdate
            }
            "cooperative-close" | "cooperative_close" => {
                BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose
            }
            other => return Err(anyhow!("unsupported paid route payment kind {other:?}")),
        };
        let buyer_npub = self
            .config
            .nostr_keys()?
            .public_key()
            .to_bech32()
            .context("failed to encode buyer npub")?;
        let store_path = self.paid_route_store_path();
        let signer = cashu_service::FileSpilmanPaymentSigner::load(&self.wallet_data_dir())
            .map_err(|error| anyhow!(error))?;
        let result = update_paid_route_store(&store_path, |store| {
            store.build_buyer_signed_payment_envelope(
                &signer,
                BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                    session_id: session_id.trim().to_string(),
                    buyer_npub,
                    kind,
                    delivered_units,
                    paid_msat,
                    now_unix: unix_timestamp(),
                },
            )
        })?;
        self.paid_route_payment_last_action =
            paid_route_payment_action_state("sign", &json!({ "payment": result }))?;
        Ok(())
    }

    pub(super) fn close_paid_route_channel_from_wallet(
        &mut self,
        session_id: &str,
        publish: bool,
    ) -> Result<()> {
        let buyer_npub = self
            .config
            .nostr_keys()?
            .public_key()
            .to_bech32()
            .context("failed to encode buyer npub")?;
        let store_path = self.paid_route_store_path();
        let signer = cashu_service::FileSpilmanPaymentSigner::load(&self.wallet_data_dir())
            .map_err(|error| anyhow!(error))?;
        let build = |store: &mut PaidRouteStore| {
            store.build_buyer_signed_payment_envelope(
                &signer,
                BuildPaidRouteBuyerSignedPaymentEnvelopeRequest {
                    session_id: session_id.trim().to_string(),
                    buyer_npub,
                    kind: BuildPaidRouteBuyerPaymentEnvelopeKind::CooperativeClose,
                    delivered_units: None,
                    paid_msat: None,
                    now_unix: unix_timestamp(),
                },
            )
        };
        let result = if publish {
            update_paid_route_store(&store_path, |store| {
                let result = build(store)?;
                let envelope_json = serde_json::to_string(&result.envelope)
                    .context("failed to encode paid route cooperative close envelope")?;
                self.send_paid_route_payment_envelope(&envelope_json)?;
                Ok(result)
            })?
        } else {
            build(&mut load_paid_route_store(&store_path)?)?
        };
        self.paid_route_payment_last_action =
            paid_route_payment_action_state("settle", &json!({ "payment": result }))?;
        Ok(())
    }

    pub(super) fn apply_paid_route_payment_envelope(&mut self, envelope_json: &str) -> Result<()> {
        let mut args = self.paid_exit_cli_args("apply-payment")?;
        args.push("--envelope-stdin".to_string());
        let output = self.run_nvpn_vec_with_stdin(&args, envelope_json.as_bytes())?;
        let value = decode_paid_route_command_json_output(output, "nvpn paid-exit apply-payment")?;
        self.paid_route_payment_last_action = paid_route_payment_action_state("apply", &value)?;
        Ok(())
    }

    pub(super) fn send_paid_route_payment_envelope(&mut self, envelope_json: &str) -> Result<()> {
        let value = self.send_paid_route_payment_envelope_value(envelope_json)?;
        self.paid_route_payment_last_action = paid_route_payment_send_action_state(&value);
        Ok(())
    }

    fn send_paid_route_payment_envelope_value(
        &mut self,
        envelope_json: &str,
    ) -> Result<serde_json::Value> {
        let mut args = self.paid_exit_cli_args("send-payment")?;
        args.push("--envelope-stdin".to_string());
        let output = self.run_nvpn_vec_with_stdin(&args, envelope_json.as_bytes())?;
        decode_paid_route_command_json_output(output, "nvpn paid-exit send-payment")
    }

    pub(super) fn stream_paid_route_payments(
        &mut self,
        publish: bool,
        min_increment_msat: u64,
        limit: u64,
    ) -> Result<()> {
        let mut args = self.paid_exit_cli_args("stream-payments")?;
        args.extend([
            "--min-increment-msat".to_string(),
            min_increment_msat.to_string(),
        ]);
        if publish {
            args.push("--publish".to_string());
        }
        if limit > 0 {
            args.push("--limit".to_string());
            args.push(limit.to_string());
        }
        let output = self.run_nvpn_vec(&args)?;
        let value =
            decode_paid_route_command_json_output(output, "nvpn paid-exit stream-payments")?;
        self.paid_route_payment_last_action = paid_route_payment_stream_action_state(&value)?;
        Ok(())
    }

    pub(super) fn receive_paid_route_payments(&mut self, duration_secs: u64) -> Result<()> {
        let duration_secs = duration_secs.clamp(1, 30).to_string();
        let output = self.run_nvpn([
            "paid-exit",
            "receive-payments",
            "--config",
            self.config_path_str()?,
            "--duration-secs",
            &duration_secs,
            "--json",
        ])?;
        let value =
            decode_paid_route_command_json_output(output, "nvpn paid-exit receive-payments")?;
        self.paid_route_payment_last_action = paid_route_payment_receive_action_state(&value)?;
        Ok(())
    }

    pub(super) fn collect_paid_exit_channel(&mut self, channel_id: &str) -> Result<()> {
        let channel_id = channel_id.trim();
        if channel_id.is_empty() {
            return Err(anyhow!("paid exit channel id is empty"));
        }
        let output = self.run_nvpn([
            "paid-exit",
            "collect",
            "--config",
            self.config_path_str()?,
            "--json",
            channel_id,
        ])?;
        let value = decode_paid_route_command_json_output(output, "nvpn paid-exit collect")?;
        self.paid_route_payment_last_action = paid_route_payment_collect_action_state(&value);
        if let Some(wallet_collect) = value
            .get("wallet_collect")
            .filter(|wallet_collect| !wallet_collect.is_null())
        {
            let amount_sat = json_u64(wallet_collect, "amount_sat");
            self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
                kind: "collect".to_string(),
                status_text: if amount_sat > 0 {
                    format!("Added {} to wallet", paid_route_sat_text(amount_sat))
                } else {
                    "Channel funds already in wallet".to_string()
                },
                mint_url: json_string(wallet_collect, "mint_url"),
                amount_sat,
                amount_text: paid_route_sat_text(amount_sat),
                ..NativePaidRouteWalletActionState::default()
            };
        }
        Ok(())
    }

    pub(super) fn collect_due_paid_exit_channels(&mut self) -> Result<()> {
        let output = self.run_nvpn([
            "paid-exit",
            "collect-due",
            "--config",
            self.config_path_str()?,
            "--json",
        ])?;
        let value = decode_paid_route_command_json_output(output, "nvpn paid-exit collect-due")?;
        self.paid_route_payment_last_action = paid_route_payment_collect_due_action_state(&value);
        let amount_sat = value
            .get("collected")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("wallet_collect"))
            .map(|wallet_collect| json_u64(wallet_collect, "amount_sat"))
            .fold(0_u64, u64::saturating_add);
        if amount_sat > 0 {
            self.paid_route_wallet_last_action = NativePaidRouteWalletActionState {
                kind: "collect".to_string(),
                status_text: format!("Added {} to wallet", paid_route_sat_text(amount_sat)),
                amount_sat,
                amount_text: paid_route_sat_text(amount_sat),
                ..NativePaidRouteWalletActionState::default()
            };
        }
        Ok(())
    }

    pub(super) fn publish_paid_exit_offer(&mut self) -> Result<()> {
        self.config.paid_exit.access.upstream = selected_paid_exit_upstream(&self.config)?;
        self.save_config()?;
        let output = self.run_nvpn([
            "paid-exit",
            "run",
            "--config",
            self.config_path_str()?,
            "--publish",
            "--json",
        ])?;
        ensure_success("nvpn paid-exit offer --publish", &output)
    }

    pub(super) fn discover_paid_route_offers(&mut self, duration_secs: u64) -> Result<()> {
        if self.config.enable_paid_exit_market_discovery() {
            self.save_reload_and_refresh()?;
        }
        let rating_discovery = &self.config.paid_exit.rating_discovery;
        let mut args = self.paid_exit_cli_args("discover")?;
        args.extend([
            "--duration-secs".to_string(),
            duration_secs.clamp(1, 30).to_string(),
        ]);
        if !rating_discovery.file.trim().is_empty() {
            args.push("--fips-peer-ratings".to_string());
            args.push(rating_discovery.file.clone());
        }
        for author in &rating_discovery.trusted_authors {
            args.push("--trusted-rating-author".to_string());
            args.push(author.clone());
        }
        if rating_discovery.configured() {
            args.push("--rating-scope".to_string());
            args.push(rating_discovery.scope.clone());
        }
        let output = self.run_nvpn_vec(&args)?;
        ensure_success("nvpn paid-exit discover", &output)
    }

    fn paid_exit_cli_args(&self, action: &str) -> Result<Vec<String>> {
        Ok(vec![
            "paid-exit".to_string(),
            action.to_string(),
            "--config".to_string(),
            self.config_path_str()?.to_string(),
            "--json".to_string(),
        ])
    }

    fn run_nvpn_vec(&self, args: &[String]) -> Result<Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {NVPN_BIN_ENV} or install nvpn"
            ));
        };
        Command::new(nvpn_bin)
            .args(args)
            .hide_console_window()
            .output()
            .with_context(|| format!("failed to execute {}", nvpn_bin.display()))
    }

    fn run_nvpn_vec_with_stdin(&self, args: &[String], stdin_bytes: &[u8]) -> Result<Output> {
        let Some(nvpn_bin) = &self.nvpn_bin else {
            return Err(anyhow!(
                "nvpn CLI binary not found; set {NVPN_BIN_ENV} or install nvpn"
            ));
        };
        let mut child = Command::new(nvpn_bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .hide_console_window()
            .spawn()
            .with_context(|| format!("failed to execute {}", nvpn_bin.display()))?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow!("failed to open nvpn stdin"))?;
            stdin
                .write_all(stdin_bytes)
                .context("failed to write nvpn stdin")?;
        }
        child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {}", nvpn_bin.display()))
    }
}
