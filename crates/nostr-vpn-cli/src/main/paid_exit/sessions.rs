
struct PaidExitBuyResult {
    store_path: PathBuf,
    session: OpenPaidRouteBuyerSessionResult,
    selected_exit_node: Option<String>,
    daemon_reload_attempted: bool,
}

struct PaidExitUseResult {
    config_path: PathBuf,
    store_path: PathBuf,
    session_id: String,
    seller_npub: String,
    selected_exit_node: String,
    daemon_reload_attempted: bool,
}

fn paid_exit_buy_command(args: PaidExitBuyArgs) -> Result<()> {
    let json_output = args.json;
    let result = paid_exit_buy_once(args)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_buy_result_json(&result))?
        );
    } else {
        print_paid_exit_buy_result(&result);
    }

    Ok(())
}

fn paid_exit_buy_once(args: PaidExitBuyArgs) -> Result<PaidExitBuyResult> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let mut app = load_or_default_config(&config_path)?;
    let buyer_npub = app
        .nostr_keys()?
        .public_key()
        .to_bech32()
        .context("failed to encode buyer npub")?;
    let store_path = paid_route_store_file_path(&config_path);
    let no_select_exit_node = args.no_select_exit_node;
    let no_reload_daemon = args.no_reload_daemon;
    let result = update_paid_route_store(&store_path, |store| {
        let offer_selector = paid_exit_buy_offer_selector(&args, store)?;
        store.open_buyer_session(OpenPaidRouteBuyerSessionRequest {
            offer_selector,
            buyer_npub,
            mint_url: args.mint,
            channel_capacity_sat: args.channel_capacity_sat,
            initial_paid_msat: args.initial_paid_msat,
            now_unix: unix_timestamp(),
        })
    })?;

    let (selected_exit_node, daemon_reload_attempted) = if no_select_exit_node {
        (None, false)
    } else {
        let selected = app.select_public_paid_exit_node(&result.seller_npub)?;
        app.save(&config_path)?;
        let daemon_reload_attempted = !no_reload_daemon;
        if daemon_reload_attempted {
            maybe_reload_running_daemon(&config_path);
        }
        (Some(selected), daemon_reload_attempted)
    };

    Ok(PaidExitBuyResult {
        store_path,
        session: result,
        selected_exit_node,
        daemon_reload_attempted,
    })
}

fn paid_exit_buy_offer_selector(args: &PaidExitBuyArgs, store: &PaidRouteStore) -> Result<String> {
    match (args.best_rated, args.offer.as_deref()) {
        (true, Some(_)) => Err(anyhow!(
            "--best-rated cannot be combined with an explicit paid-exit offer selector"
        )),
        (true, None) => store.best_rated_offer_key(),
        (false, Some(offer)) => {
            let offer = offer.trim();
            if offer.is_empty() {
                Err(anyhow!("paid exit offer selector is empty"))
            } else {
                Ok(offer.to_string())
            }
        }
        (false, None) => Err(anyhow!(
            "paid exit offer selector is required unless --best-rated is supplied"
        )),
    }
}

fn paid_exit_use_command(args: PaidExitUseArgs) -> Result<()> {
    let json_output = args.json;
    let result = paid_exit_use_once(args)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_use_result_json(&result))?
        );
    } else {
        print_paid_exit_use_result(&result);
    }

    Ok(())
}

fn paid_exit_use_once(args: PaidExitUseArgs) -> Result<PaidExitUseResult> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let mut app = load_or_default_config(&config_path)?;
    let store_path = paid_route_store_file_path(&config_path);
    let session_id = args.session.trim().to_string();
    if session_id.is_empty() {
        return Err(anyhow!("paid route session id is empty"));
    }
    let now_unix = unix_timestamp();
    let seller_npub = update_paid_route_store(&store_path, |store| {
        store.retry_failed_funded_buyer_session(&session_id, now_unix)?;
        if !store.buyer_session_allows_routing(&session_id, now_unix)? {
            return Err(anyhow!(
                "paid route session is not ready to route yet; fund it or wait for seller admission"
            ));
        }
        store.begin_buyer_session_open_attempt(&session_id, now_unix)?;
        store.buyer_session_seller_npub(&session_id)
    })?;
    let selected_exit_node = app.select_public_paid_exit_node(&seller_npub)?;
    app.save(&config_path)?;
    let daemon_reload_attempted = !args.no_reload_daemon;
    if daemon_reload_attempted {
        maybe_reload_running_daemon(&config_path);
    }

    Ok(PaidExitUseResult {
        config_path,
        store_path,
        session_id,
        seller_npub,
        selected_exit_node,
        daemon_reload_attempted,
    })
}

fn paid_exit_buy_result_json(result: &PaidExitBuyResult) -> serde_json::Value {
    json!({
        "store_path": result.store_path.display().to_string(),
        "session": result.session,
        "selected_exit_node": result.selected_exit_node,
        "daemon_reload_attempted": result.daemon_reload_attempted,
    })
}

fn paid_exit_use_result_json(result: &PaidExitUseResult) -> serde_json::Value {
    json!({
        "config_path": result.config_path.display().to_string(),
        "store_path": result.store_path.display().to_string(),
        "session_id": result.session_id,
        "seller_npub": result.seller_npub,
        "selected_exit_node": result.selected_exit_node,
        "daemon_reload_attempted": result.daemon_reload_attempted,
    })
}

fn print_paid_exit_buy_result(result: &PaidExitBuyResult) {
    println!("paid_exit_session: {}", result.session.session_id);
    println!("seller: {}", result.session.seller_npub);
    println!("offer: {}", result.session.offer_id);
    println!("mint: {}", display_or_none(&result.session.mint_url));
    println!(
        "channel: {} capacity={} expires_at={}",
        result.session.channel_id,
        paid_exit_sat_text(result.session.channel_capacity_sat),
        result.session.expires_at_unix
    );
    println!(
        "store: {} changed={}",
        result.store_path.display(),
        result.session.changed
    );
    if let Some(selected) = result.selected_exit_node.as_deref() {
        println!("selected_exit_node: {selected}");
    } else {
        println!("selected_exit_node: unchanged");
    }
    println!(
        "daemon_reload: {}",
        if result.daemon_reload_attempted {
            "attempted"
        } else {
            "skipped"
        }
    );
}

fn print_paid_exit_use_result(result: &PaidExitUseResult) {
    println!("paid_exit_session: {}", result.session_id);
    println!("seller: {}", result.seller_npub);
    println!("selected_exit_node: {}", result.selected_exit_node);
    println!("config: {}", result.config_path.display());
    println!("store: {}", result.store_path.display());
    println!(
        "daemon_reload: {}",
        if result.daemon_reload_attempted {
            "attempted"
        } else {
            "skipped"
        }
    );
}
