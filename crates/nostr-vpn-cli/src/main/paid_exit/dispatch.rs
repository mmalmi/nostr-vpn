async fn run_paid_exit_command(args: PaidExitArgs) -> Result<()> {
    match args.command {
        PaidExitCommand::Status(args) => paid_exit_status_command(args),
        PaidExitCommand::Rate(args) => paid_exit_rate_command(args),
        PaidExitCommand::Reselect(args) => paid_exit_reselect_command(args),
        PaidExitCommand::Run(args) => paid_exit_run_command(args).await,
        PaidExitCommand::Offer(args) => paid_exit_offer_command(args).await,
        PaidExitCommand::ImportOffer(args) => paid_exit_import_offer_command(args),
        PaidExitCommand::Discover(args) => paid_exit_discover_command(args).await,
        PaidExitCommand::Buy(args) => paid_exit_buy_command(args),
        PaidExitCommand::Use(args) => paid_exit_use_command(args),
        PaidExitCommand::Probe(args) => paid_exit_probe_command(args).await,
        PaidExitCommand::RecordProbe(args) => paid_exit_record_probe_command(args),
        PaidExitCommand::Ratings(args) => paid_exit_ratings_command(args).await,
        PaidExitCommand::CreatePayment(args) => paid_exit_create_payment_command(args).await,
        PaidExitCommand::CreateTokenLease(args) => paid_exit_create_token_lease_command(args),
        PaidExitCommand::StreamPayments(args) => paid_exit_stream_payments_command(args).await,
        PaidExitCommand::Settle(args) => paid_exit_settle_command(args).await,
        PaidExitCommand::ApplyPayment(args) => paid_exit_apply_payment_command(args).await,
        PaidExitCommand::SendPayment(args) => paid_exit_send_payment_command(args).await,
        PaidExitCommand::Collect(args) => paid_exit_collect_command(args).await,
        PaidExitCommand::CollectDue(args) => paid_exit_collect_due_command(args).await,
        PaidExitCommand::Wallet(args) => paid_exit_wallet_command(args).await,
    }
}

fn paid_exit_status_command(args: PaidExitStatusArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    let app = load_config_read_only(&config_path)?;
    let store_path = paid_route_store_file_path(&config_path);
    let store = load_paid_route_store(&store_path)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_status_snapshot_json(
                &app,
                &store_path,
                &store
            )?)?
        );
    } else {
        print_paid_exit_status_snapshot(&app, &store_path, &store)?;
    }

    Ok(())
}

fn paid_exit_rate_command(args: PaidExitRateArgs) -> Result<()> {
    let path = args.config.unwrap_or_else(default_config_path);
    let mut app = load_config_read_only(&path)?;
    let seller = args.provider.unwrap_or_else(|| app.exit_node.clone());
    let vote = match args.opinion {
        PaidExitOpinion::Up => 1,
        PaidExitOpinion::Down => -1,
        PaidExitOpinion::Clear => 0,
    };
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.rate_exit(&mut app, &seller, vote, unix_timestamp())
    })?;
    app.save(&path)?;
    maybe_reload_running_daemon(&path);
    if args.json {
        println!(
            "{}",
            json!({"provider": seller, "rating": vote, "saved": true})
        );
    } else {
        println!("Rating saved for automatic publication.");
    }
    Ok(())
}

fn paid_exit_reselect_command(args: PaidExitStatusArgs) -> Result<()> {
    let path = args.config.unwrap_or_else(default_config_path);
    let mut app = load_config_read_only(&path)?;
    update_paid_route_store(&paid_route_store_file_path(&path), |store| {
        store.request_exit_reselection(&app, unix_timestamp())
    })?;
    app.exit_node_leak_protection = true;
    app.save(&path)?;
    maybe_reload_running_daemon(&path);
    if args.json {
        println!("{}", json!({"reselection_requested": true}));
    } else {
        println!("Requested another provider; the running daemon will switch when ready.");
    }
    Ok(())
}
