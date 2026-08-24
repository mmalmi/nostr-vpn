struct PaidRouteWalletClient<'a> {
    runtime: &'a NativeAppRuntime,
}

impl<'a> PaidRouteWalletClient<'a> {
    fn new(runtime: &'a NativeAppRuntime) -> Result<Self> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?;
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        if runtime.nvpn_bin.is_none() {
            return Err(anyhow!(
                "nvpn CLI binary not found; the daemon-owned Cashu wallet is unavailable"
            ));
        }
        Ok(Self { runtime })
    }

    fn overview(&self, refresh_quotes: bool) -> Result<cashu_service::CashuWalletOverview> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .overview(refresh_quotes);

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mut args = self.runtime.paid_exit_cli_args("wallet")?;
            args.push("show".to_string());
            if refresh_quotes {
                args.push("--refresh".to_string());
            }
            let output = self.runtime.run_nvpn_vec(&args)?;
            let value = decode_paid_route_command_json_output(output, "nvpn paid-exit wallet show")?;
            cashu_overview_from_json(
                value
                    .get("cashu")
                    .ok_or_else(|| anyhow!("wallet response has no cashu overview"))?,
            )
        }
    }

    fn activity(&self) -> Result<Vec<cashu_service::CashuWalletActivityEntry>> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .activity();

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mut args = self.runtime.paid_exit_cli_args("wallet")?;
            args.extend(["show".to_string(), "--activity".to_string()]);
            let output = self.runtime.run_nvpn_vec(&args)?;
            let value = decode_paid_route_command_json_output(output, "nvpn paid-exit wallet show")?;
            serde_json::from_value(value.get("activity").cloned().unwrap_or_default())
                .context("wallet response has invalid activity")
        }
    }

    fn create_topup_quote(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<cashu_service::CashuTopupQuote> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .create_topup_quote(mint_url, amount_sat);

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mut args = self.runtime.paid_exit_cli_args("wallet")?;
            args.extend([
                "topup".to_string(),
                "--mint".to_string(),
                mint_url.to_string(),
                amount_sat.to_string(),
            ]);
            let output = self.runtime.run_nvpn_vec(&args)?;
            let value = decode_paid_route_command_json_output(output, "nvpn paid-exit wallet topup")?;
            Ok(cashu_topup_quote_from_json(
                value
                    .get("quote")
                    .ok_or_else(|| anyhow!("wallet response has no top-up quote"))?,
            ))
        }
    }

    fn receive_token(&self, token: &str) -> Result<cashu_service::CashuReceivedPayment> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .receive_token(token);

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        self.wallet_value_with_stdin("receive", "token", token, "received")
    }

    fn send_token(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<cashu_service::CashuSentPayment> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .send_token(mint_url, amount_sat);

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mut args = self.runtime.paid_exit_cli_args("wallet")?;
            args.extend([
                "send".to_string(),
                "--mint".to_string(),
                mint_url.to_string(),
                amount_sat.to_string(),
            ]);
            let output = self.runtime.run_nvpn_vec(&args)?;
            decode_wallet_result(output, "nvpn paid-exit wallet send", "sent")
        }
    }

    fn pay_lightning(
        &self,
        mint_url: &str,
        invoice: &str,
    ) -> Result<cashu_service::CashuLightningPayment> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        return self
            .runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .pay_lightning(mint_url, invoice);

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mut args = self.runtime.paid_exit_cli_args("wallet")?;
            args.extend([
                "withdraw".to_string(),
                "--mint".to_string(),
                mint_url.to_string(),
                invoice.to_string(),
            ]);
            let output = self.runtime.run_nvpn_vec(&args)?;
            decode_wallet_result(output, "nvpn paid-exit wallet withdraw", "withdrawal")
        }
    }

    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn open_spilman_channel(
        &self,
        request: cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    ) -> Result<cashu_service::StreamingRouteOpenCashuSpilmanChannelFromWalletResult> {
        self.runtime
            .cashu_wallet_runtime
            .as_ref()
            .context("Embedded Cashu wallet is unavailable")?
            .open_spilman_channel(request)
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    fn wallet_value_with_stdin<T: serde::de::DeserializeOwned>(
        &self,
        action: &str,
        stdin_flag: &str,
        input: &str,
        key: &str,
    ) -> Result<T> {
        let mut args = self.runtime.paid_exit_cli_args("wallet")?;
        args.extend([
            action.to_string(),
            format!("--{stdin_flag}-stdin"),
        ]);
        let output = self.runtime.run_nvpn_vec_with_stdin(&args, input.as_bytes())?;
        decode_wallet_result(output, &format!("nvpn paid-exit wallet {action}"), key)
    }
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn decode_wallet_result<T: serde::de::DeserializeOwned>(
    output: Output,
    command: &str,
    key: &str,
) -> Result<T> {
    let value = decode_paid_route_command_json_output(output, command)?;
    serde_json::from_value(
        value
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow!("wallet response has no {key}"))?,
    )
    .with_context(|| format!("wallet response has invalid {key}"))
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn cashu_overview_from_json(value: &serde_json::Value) -> Result<cashu_service::CashuWalletOverview> {
    let totals = value
        .get("totals")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|total| {
            Ok(cashu_service::CashuUnitTotal {
                unit: json_string(total, "unit"),
                balance: json_u64(total, "balance"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let entries = value
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| {
            Ok(cashu_service::CashuWalletEntry {
                mint_url: json_string(entry, "mint_url"),
                unit: json_string(entry, "unit"),
                balance: json_u64(entry, "balance"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = value
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|warning| warning.as_str().map(ToOwned::to_owned))
        .collect();
    Ok(cashu_service::CashuWalletOverview {
        totals,
        entries,
        warnings,
        legacy_state_detected: value
            .get("legacy_state_detected")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn cashu_topup_quote_from_json(value: &serde_json::Value) -> cashu_service::CashuTopupQuote {
    cashu_service::CashuTopupQuote {
        mint_url: json_string(value, "mint_url"),
        unit: json_string(value, "unit"),
        amount: json_u64(value, "amount_sat"),
        quote_id: json_string(value, "quote_id"),
        payment_request: json_string(value, "payment_request"),
        expiry_unix: json_u64(value, "expiry_unix"),
    }
}
