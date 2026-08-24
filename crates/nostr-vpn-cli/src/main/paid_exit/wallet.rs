
const DEFAULT_PAID_EXIT_WALLET_MINT: &str = "https://mint.minibits.cash/Bitcoin";

#[derive(Debug, Clone, Serialize)]
struct PaidExitWalletTokenPreview {
    mint_url: String,
    unit: String,
    amount_sat: u64,
    memo: String,
    state: &'static str,
    status_text: String,
    redeemable: bool,
}

async fn paid_exit_wallet_command(args: PaidExitWalletArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let data_dir = paid_exit_wallet_data_dir(&config_path);
    let store_path = paid_route_store_file_path(&config_path);
    let json_output = args.json;

    match args.command {
        PaidExitWalletCommand::Show(show) => {
            let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
                crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                    refresh_quotes: show.refresh,
                },
            )
            .await?,
            )?;
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let changed =
                    sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
                Ok((changed, store.clone()))
            })?;
            let activity = if show.activity {
                Some(
                    daemon_cashu_wallet_request::<Vec<cashu_service::CashuWalletActivityEntry>>(
                        &config_path,
                        crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Activity,
                    )
                    .await?,
                )
            } else {
                None
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "data_dir": data_dir.display().to_string(),
                        "changed": changed,
                        "wallet": store.wallet,
                        "cashu": cashu_wallet_overview_json(&overview),
                        "activity": activity,
                    }))?
                );
            } else {
                println!("store: {} changed={changed}", store_path.display());
                println!("data_dir: {}", data_dir.display());
                print_paid_exit_wallet(&store);
                print_cashu_wallet_overview(&overview);
                if let Some(activity) = activity {
                    println!("activity: {}", activity.len());
                    for entry in activity.iter().take(20) {
                        println!(
                            "  {:?} {:?} {} mint={} id={}",
                            entry.kind,
                            entry.status,
                            paid_exit_sat_text(entry.amount_sat),
                            entry.mint_url,
                            entry.id
                        );
                    }
                }
            }
            Ok(())
        }
        PaidExitWalletCommand::Topup(topup) => {
            let mint = paid_exit_wallet_mint(
                &load_paid_route_store(&store_path)?,
                topup.mint.as_deref(),
            )?;
            let quote: crate::cashu_wallet_daemon::DaemonCashuTopupQuote =
                daemon_cashu_wallet_request(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::CreateTopupQuote {
                    mint_url: mint,
                    amount_sat: topup.amount_sat,
                },
            )
            .await?;
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let changed = ensure_paid_exit_wallet_mint(store, &quote.mint_url, None)?;
                Ok((changed, store.clone()))
            })?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "data_dir": data_dir.display().to_string(),
                        "changed": changed,
                        "quote": {
                            "mint_url": quote.mint_url,
                            "unit": quote.unit,
                            "amount_sat": quote.amount,
                            "quote_id": quote.quote_id,
                            "payment_request": quote.payment_request,
                            "expiry_unix": quote.expiry_unix,
                        },
                        "wallet": store.wallet,
                    }))?
                );
            } else {
                println!("topup_quote: {}", quote.quote_id);
                println!("mint: {}", quote.mint_url);
                println!("amount: {}", paid_exit_sat_text(quote.amount));
                println!("expires_at: {}", quote.expiry_unix);
                println!("invoice: {}", quote.payment_request);
            }
            Ok(())
        }
        PaidExitWalletCommand::Receive(receive) => {
            let token = read_paid_exit_wallet_token(receive.token, receive.token_stdin)?;
            let payment: cashu_service::CashuReceivedPayment = daemon_cashu_wallet_request(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::ReceiveToken { token },
            )
            .await?;
            let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
                crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                    refresh_quotes: false,
                },
            )
            .await?,
            )?;
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let changed =
                    sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
                Ok((changed, store.clone()))
            })?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "data_dir": data_dir.display().to_string(),
                        "changed": changed,
                        "received": payment,
                        "wallet": store.wallet,
                        "cashu": cashu_wallet_overview_json(&overview),
                    }))?
                );
            } else {
                println!("received: {}", paid_exit_sat_text(payment.amount_sat));
                println!("mint: {}", payment.mint_url);
                println!("store: {} changed={changed}", store_path.display());
            }
            Ok(())
        }
        PaidExitWalletCommand::Inspect(inspect) => {
            let token = read_paid_exit_wallet_token(inspect.token, inspect.token_stdin)?;
            let preview = inspect_paid_exit_wallet_token(&token).await?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "token_preview": preview }))?
                );
            } else {
                println!("amount: {}", paid_exit_sat_text(preview.amount_sat));
                println!("mint: {}", preview.mint_url);
                println!("state: {}", preview.state);
                println!("status: {}", preview.status_text);
            }
            Ok(())
        }
        PaidExitWalletCommand::Send(send) => {
            let mint = paid_exit_wallet_mint(
                &load_paid_route_store(&store_path)?,
                send.mint.as_deref(),
            )?;
            let payment: cashu_service::CashuSentPayment = daemon_cashu_wallet_request(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::SendToken {
                    mint_url: mint,
                    amount_sat: send.amount_sat,
                },
            )
            .await?;
            let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
                crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                    refresh_quotes: false,
                },
            )
            .await?,
            )?;
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let changed =
                    sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
                Ok((changed, store.clone()))
            })?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "data_dir": data_dir.display().to_string(),
                        "changed": changed,
                        "sent": payment,
                        "wallet": store.wallet,
                        "cashu": cashu_wallet_overview_json(&overview),
                    }))?
                );
            } else {
                println!(
                    "sent: {} fee={}",
                    paid_exit_sat_text(payment.amount_sat),
                    paid_exit_sat_text(payment.send_fee_sat)
                );
                println!("mint: {}", payment.mint_url);
                println!("operation_id: {}", payment.operation_id);
                println!("token: {}", payment.token);
            }
            Ok(())
        }
        PaidExitWalletCommand::Withdraw(withdraw) => {
            let mint = paid_exit_wallet_mint(
                &load_paid_route_store(&store_path)?,
                withdraw.mint.as_deref(),
            )?;
            let payment: cashu_service::CashuLightningPayment = daemon_cashu_wallet_request(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::PayLightning {
                    mint_url: mint,
                    invoice: withdraw.invoice,
                },
            )
            .await?;
            let overview = crate::cashu_wallet_daemon::decode_daemon_cashu_wallet_overview(
                crate::cashu_wallet_daemon::request_daemon_cashu_wallet(
                &config_path,
                crate::cashu_wallet_daemon::DaemonCashuWalletCommand::Overview {
                    refresh_quotes: false,
                },
            )
            .await?,
            )?;
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let changed =
                    sync_paid_exit_wallet_store_from_cashu(store, &overview, unix_timestamp());
                Ok((changed, store.clone()))
            })?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "data_dir": data_dir.display().to_string(),
                        "changed": changed,
                        "withdrawal": payment,
                        "wallet": store.wallet,
                        "cashu": cashu_wallet_overview_json(&overview),
                    }))?
                );
            } else {
                println!(
                    "withdrawn: {} fee={}",
                    paid_exit_sat_text(payment.amount_sat),
                    paid_exit_sat_text(payment.fee_paid_sat)
                );
                println!("mint: {}", payment.mint_url);
                println!("quote_id: {}", payment.quote_id);
                println!("preimage: {}", payment.preimage);
            }
            Ok(())
        }
        command => {
            let (changed, store) = update_paid_route_store(&store_path, |store| {
                let mut changed = false;
                match command {
                    PaidExitWalletCommand::AddMint(add) => {
                        let url = normalize_mint_url(&add.url)?;
                        let label = add.label.unwrap_or_default();
                        changed |= store.upsert_wallet_mint(
                            &url,
                            label,
                            add.balance_msat,
                            unix_timestamp(),
                        );
                        if add.make_default {
                            changed |= store.set_default_mint(&url);
                        }
                    }
                    PaidExitWalletCommand::RemoveMint(mint) => {
                        changed |= store.remove_wallet_mint(normalize_mint_url(&mint.url)?);
                    }
                    PaidExitWalletCommand::SetDefault(mint) => {
                        changed |= store.set_default_mint(normalize_mint_url(&mint.url)?);
                    }
                    _ => unreachable!("wallet action returned before transactional mutation"),
                }
                Ok((changed, store.clone()))
            })?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "store_path": store_path.display().to_string(),
                        "changed": changed,
                        "wallet": store.wallet,
                    }))?
                );
            } else {
                println!("store: {} changed={changed}", store_path.display());
                print_paid_exit_wallet(&store);
            }
            Ok(())
        }
    }
}

async fn daemon_cashu_wallet_request<T: serde::de::DeserializeOwned>(
    config_path: &Path,
    command: crate::cashu_wallet_daemon::DaemonCashuWalletCommand,
) -> Result<T> {
    let value = crate::cashu_wallet_daemon::request_daemon_cashu_wallet(config_path, command).await?;
    serde_json::from_value(value).context("daemon returned an invalid Cashu wallet response")
}

async fn inspect_paid_exit_wallet_token(token_text: &str) -> Result<PaidExitWalletTokenPreview> {
    use cashu::nuts::{CurrencyUnit, Token};
    use std::str::FromStr;

    let token = Token::from_str(token_text).context("invalid Cashu token")?;
    let mint_url = token
        .mint_url()
        .context("Cashu token must contain proofs from one mint")?
        .to_string();
    let unit = token.unit().unwrap_or_default();
    if unit != CurrencyUnit::Sat {
        return Err(anyhow!("Cashu token unit must be sat, got {unit}"));
    }
    let amount_sat = token.value().context("invalid Cashu token amount")?.to_u64();
    let memo = token.memo().clone().unwrap_or_default();
    if token.token_secrets().is_empty() {
        return Err(anyhow!("Cashu token contains no proofs"));
    }

    Ok(PaidExitWalletTokenPreview {
        mint_url,
        unit: unit.to_string(),
        amount_sat,
        memo,
        state: "unchecked",
        status_text: "Mint will verify when redeemed".to_string(),
        redeemable: true,
    })
}

#[cfg(test)]
mod wallet_token_preview_tests {
    use super::inspect_paid_exit_wallet_token;

    #[tokio::test]
    async fn token_preview_parses_without_contacting_the_mint() {
        let token = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ";
        let preview = inspect_paid_exit_wallet_token(token)
            .await
            .expect("parse token preview");
        assert_eq!(preview.amount_sat, 10);
        assert_eq!(preview.mint_url, "https://8333.space:3338");
        assert_eq!(preview.memo, "Thank you very much.");
        assert_eq!(preview.state, "unchecked");
        assert!(preview.redeemable);
    }
}

fn paid_exit_wallet_data_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn paid_exit_wallet_mint(store: &PaidRouteStore, explicit: Option<&str>) -> Result<String> {
    if let Some(mint) = explicit {
        return normalize_mint_url(mint);
    }
    if !store.wallet.default_mint.trim().is_empty() {
        return normalize_mint_url(&store.wallet.default_mint);
    }
    Err(anyhow!(
        "No mint configured; add a mint or pass --mint before using Lightning receive or send"
    ))
}

fn ensure_paid_exit_wallet_mint(
    store: &mut PaidRouteStore,
    mint_url: &str,
    balance_msat: Option<u64>,
) -> Result<bool> {
    let mint_url = normalize_mint_url(mint_url)?;
    let label = store
        .wallet
        .mints
        .iter()
        .find(|mint| mint.url == mint_url)
        .map(|mint| mint.label.clone())
        .unwrap_or_else(|| {
            if mint_url == DEFAULT_PAID_EXIT_WALLET_MINT {
                "Minibits".to_string()
            } else {
                String::new()
            }
        });
    Ok(store.upsert_wallet_mint(&mint_url, label, balance_msat, unix_timestamp()))
}

fn sync_paid_exit_wallet_store_from_cashu(
    store: &mut PaidRouteStore,
    overview: &CashuWalletOverview,
    now_unix: u64,
) -> bool {
    let mut changed = false;
    for entry in &overview.entries {
        if entry.unit != "sat" {
            continue;
        }
        let label = store
            .wallet
            .mints
            .iter()
            .find(|mint| mint.url == entry.mint_url)
            .map(|mint| mint.label.clone())
            .unwrap_or_else(|| {
                if entry.mint_url == DEFAULT_PAID_EXIT_WALLET_MINT {
                    "Minibits".to_string()
                } else {
                    String::new()
                }
            });
        changed |= store.upsert_wallet_mint(
            &entry.mint_url,
            label,
            Some(entry.balance.saturating_mul(1000)),
            now_unix,
        );
    }
    changed
}

fn read_paid_exit_wallet_token(token: Option<String>, token_stdin: bool) -> Result<String> {
    if token_stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read Cashu token from stdin")?;
        let token = input.trim().to_string();
        if token.is_empty() {
            return Err(anyhow!("Cashu token from stdin is empty"));
        }
        return Ok(token);
    }

    let Some(token) = token else {
        return Err(anyhow!(
            "missing Cashu token; pass a token or --token-stdin"
        ));
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(anyhow!("Cashu token is empty"));
    }
    Ok(token)
}

fn read_paid_exit_payment_envelope(
    envelope: Option<String>,
    envelope_stdin: bool,
) -> Result<String> {
    if envelope_stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read paid route payment envelope from stdin")?;
        let envelope = input.trim().to_string();
        if envelope.is_empty() {
            return Err(anyhow!("paid route payment envelope from stdin is empty"));
        }
        return Ok(envelope);
    }

    let Some(envelope) = envelope else {
        return Err(anyhow!(
            "missing paid route payment envelope; pass --envelope or --envelope-stdin"
        ));
    };
    let envelope = envelope.trim().to_string();
    if envelope.is_empty() {
        return Err(anyhow!("paid route payment envelope is empty"));
    }
    Ok(envelope)
}

fn read_paid_exit_offer_event(
    event: Option<String>,
    event_stdin: bool,
    event_file: Option<PathBuf>,
) -> Result<String> {
    if event_stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read paid route offer event from stdin")?;
        let event = input.trim().to_string();
        if event.is_empty() {
            return Err(anyhow!("paid route offer event from stdin is empty"));
        }
        return Ok(event);
    }

    if let Some(path) = event_file {
        let event = fs::read_to_string(&path)
            .with_context(|| format!("failed to read paid route offer event {}", path.display()))?
            .trim()
            .to_string();
        if event.is_empty() {
            return Err(anyhow!("paid route offer event file is empty"));
        }
        return Ok(event);
    }

    let Some(event) = event else {
        return Err(anyhow!(
            "missing paid route offer event; pass --event, --event-stdin, or --event-file"
        ));
    };
    let event = event.trim().to_string();
    if event.is_empty() {
        return Err(anyhow!("paid route offer event is empty"));
    }
    Ok(event)
}

fn read_paid_exit_spilman_payment(payment: Option<String>, payment_stdin: bool) -> Result<String> {
    if payment_stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read Cashu Spilman payment from stdin")?;
        let payment = input.trim().to_string();
        if payment.is_empty() {
            return Err(anyhow!("Cashu Spilman payment from stdin is empty"));
        }
        return Ok(payment);
    }

    let Some(payment) = payment else {
        return Err(anyhow!(
            "missing Cashu Spilman payment; pass --payment or --payment-stdin"
        ));
    };
    let payment = payment.trim().to_string();
    if payment.is_empty() {
        return Err(anyhow!("Cashu Spilman payment is empty"));
    }
    Ok(payment)
}

fn read_optional_paid_exit_keyset_info(
    keyset_info: Option<String>,
    keyset_info_file: Option<PathBuf>,
) -> Result<Option<String>> {
    if let Some(path) = keyset_info_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read keyset info file {}", path.display()))?;
        let content = content.trim().to_string();
        if content.is_empty() {
            return Err(anyhow!("keyset info file {} is empty", path.display()));
        }
        return Ok(Some(content));
    }
    match keyset_info {
        Some(value) if value.trim().is_empty() => Err(anyhow!("keyset info JSON is empty")),
        Some(value) => Ok(Some(value.trim().to_string())),
        None => Ok(None),
    }
}

fn cashu_wallet_overview_json(overview: &CashuWalletOverview) -> serde_json::Value {
    json!({
        "totals": overview.totals.iter().map(|total| json!({
            "unit": total.unit,
            "balance": total.balance,
        })).collect::<Vec<_>>(),
        "entries": overview.entries.iter().map(|entry| json!({
            "mint_url": entry.mint_url,
            "unit": entry.unit,
            "balance": entry.balance,
        })).collect::<Vec<_>>(),
        "warnings": overview.warnings,
        "legacy_state_detected": overview.legacy_state_detected,
    })
}

fn print_cashu_wallet_overview(overview: &CashuWalletOverview) {
    if overview.totals.is_empty() && overview.entries.is_empty() {
        println!("cashu_wallet: empty");
    } else {
        println!("cashu_totals: {}", overview.totals.len());
        for total in &overview.totals {
            println!("  {} {}", total.balance, total.unit);
        }
        println!("cashu_mints: {}", overview.entries.len());
        for entry in &overview.entries {
            println!("  {} {} {}", entry.mint_url, entry.balance, entry.unit);
        }
    }
    for warning in &overview.warnings {
        println!("warning: {warning}");
    }
    if overview.legacy_state_detected {
        println!("legacy_cashu_wallet_state: detected");
    }
}

fn print_paid_exit_wallet(store: &PaidRouteStore) {
    println!(
        "default_mint: {}",
        display_or_none(&store.wallet.default_mint)
    );
    if store.wallet.mints.is_empty() {
        println!("mints: none");
        return;
    }

    println!("mints: {}", store.wallet.mints.len());
    for mint in &store.wallet.mints {
        let balance = mint
            .balance_msat
            .map(paid_exit_msat_text)
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} label={} balance={} last_checked={}",
            mint.url,
            display_or_none(&mint.label),
            balance,
            mint.last_checked_unix
        );
    }
}

#[cfg(test)]
mod paid_exit_wallet_tests {
    use super::*;

    #[test]
    fn wallet_operations_require_an_explicit_or_configured_mint() {
        let store = PaidRouteStore::default();

        let error = paid_exit_wallet_mint(&store, None).expect_err("missing mint");

        assert!(error.to_string().contains("No mint configured"));
    }
}
