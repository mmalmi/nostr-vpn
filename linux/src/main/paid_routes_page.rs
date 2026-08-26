mod paid_routes_wallet {
    use super::*;

    include!("paid_routes_page/wallet.rs");
}

fn paid_internet_available(state: &NativeAppState) -> bool {
    state.paid_route_market.supported || state.paid_exit_seller.supported
}

fn build_paid_routes_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Buy Internet", "network-wireless-symbolic");
    page.append(&badge("Experimental", "warn"));
    page.append(&badge(
        &state.exit_node_status_text,
        if state.exit_node_blocked {
            "bad"
        } else if state.exit_node_active {
            "ok"
        } else {
            "muted"
        },
    ));
    build_paid_route_market_card(app, page, state);
}

fn build_paid_exit_seller_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Sell Internet", "mail-send-symbolic");
    page.append(&badge("Experimental", "warn"));
    build_paid_exit_seller_card(app, page, state);
}

fn build_paid_route_wallet_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Wallet", "wallet-symbolic");
    let explanation = gtk::Label::new(Some(
        "Pay for internet access and receive earnings when you sell bandwidth.",
    ));
    explanation.set_wrap(true);
    explanation.set_xalign(0.0);
    explanation.add_css_class("dim-label");
    page.append(&explanation);
    paid_routes_wallet::build_paid_route_wallet_card(app, page, state);
}

fn build_paid_route_market_card(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let market = &state.paid_route_market;
    let buyer = card();
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    header.set_valign(gtk::Align::Center);
    section_header(&header, "Internet Sellers", "");
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    header.append(&spacer);
    let find = icon_text_button("Find", "system-search-symbolic");
    find.set_sensitive(market.supported);
    {
        let app = app.clone();
        find.connect_clicked(move |_| {
            dispatch(
                &app,
                NativeAppAction::DiscoverPaidRouteOffers { duration_secs: 5 },
            );
        });
    }
    header.append(&find);
    let pay = icon_text_button("Pay", "mail-send-symbolic");
    pay.set_sensitive(
        market
            .sessions
            .iter()
            .any(paid_route_session_can_sign_payment),
    );
    {
        let app = app.clone();
        pay.connect_clicked(move |_| {
            dispatch(
                &app,
                NativeAppAction::StreamPaidRoutePayments {
                    publish: true,
                    min_increment_msat: 1,
                    limit: 0,
                },
            );
        });
    }
    header.append(&pay);
    buyer.append(&header);

    detail_row(
        &buyer,
        "Wallet",
        &non_empty_or(
            &market.wallet.total_balance_text,
            &format_paid_route_msat(market.wallet.total_balance_msat),
        ),
    );
    detail_row(&buyer, "Status", &market.status_text);
    let provider_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let provider = entry(
        "Provider npub or paid exit link",
        &app.borrow().drafts.manual_paid_exit_provider,
    );
    provider.set_hexpand(true);
    {
        let app = app.clone();
        provider.connect_changed(move |entry| {
            app.borrow_mut().drafts.manual_paid_exit_provider = entry.text().to_string();
        });
    }
    provider_row.append(&provider);
    let add_provider = icon_text_button("Add provider", "list-add-symbolic");
    {
        let app = app.clone();
        let provider = provider.clone();
        add_provider.connect_clicked(move |_| {
            dispatch(
                &app,
                NativeAppAction::SetManualPaidExitProvider {
                    provider: provider.text().to_string(),
                },
            );
        });
    }
    provider_row.append(&add_provider);
    if !market.manual_provider_link.is_empty() {
        let clear = icon_text_button("Clear", "edit-clear-symbolic");
        {
            let app = app.clone();
            clear.connect_clicked(move |_| {
                app.borrow_mut().drafts.manual_paid_exit_provider.clear();
                dispatch(&app, NativeAppAction::ClearManualPaidExitProvider);
            });
        }
        provider_row.append(&clear);
    }
    buyer.append(&provider_row);
    detail_row(&buyer, "Provider", &market.manual_provider_status_text);
    detail_row(
        &buyer,
        "Payments",
        &paid_route_payment_action_text(&market.last_payment_action),
    );
    if !market.supported {
        empty_row(&buyer, "Buying internet is not supported on this platform");
        page.append(&buyer);
        return;
    }

    build_paid_route_filter(app, &buyer);

    section_header(&buyer, "Available", "");
    let offers = if market.hidden_offer_count > 0 || !market.visible_offers.is_empty() {
        &market.visible_offers
    } else {
        &market.offers
    };
    if market.offers.is_empty() {
        empty_row(&buyer, "No internet sellers found");
    } else if offers.is_empty() {
        empty_row(&buyer, "No matching sellers");
    } else {
        if market.hidden_offer_count > 0 {
            buyer.append(&badge(
                &format!("{} hidden by filters", market.hidden_offer_count),
                "muted",
            ));
        }
        for offer in offers.iter().take(8) {
            paid_route_offer_row(app, &buyer, state, offer);
        }
    }

    section_header(&buyer, "Your Paid Internet", "");
    if market.sessions.is_empty() {
        empty_row(&buyer, "No seller selected");
    } else {
        for session in &market.sessions {
            paid_route_session_row(
                app,
                &buyer,
                session,
                market.last_payment_action.envelope_json.as_str(),
                false,
            );
        }
    }

    page.append(&buyer);
}

fn build_paid_route_filter(app: &AppRef, parent: &gtk::Box) {
    let filter = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let country = entry("Country", &app.borrow().drafts.paid_route_country);
    {
        let app = app.clone();
        country.connect_changed(move |entry| {
            let normalized = normalize_paid_route_country_input(&entry.text());
            if entry.text() != normalized {
                entry.set_text(&normalized);
            }
            app.borrow_mut().drafts.paid_route_country = normalized;
        });
    }
    let apply = icon_text_button("Filter", "view-filter-symbolic");
    {
        let app = app.clone();
        apply.connect_clicked(move |_| {
            let drafts = app.borrow().drafts.clone();
            dispatch(
                &app,
                NativeAppAction::SetPaidRouteMarketFilter {
                    query: String::new(),
                    country_code: drafts.paid_route_country.trim().to_string(),
                    mint_url: String::new(),
                    require_ipv4: false,
                    require_ipv6: false,
                    sort: "quality".to_string(),
                },
            );
        });
    }
    let clear = icon_text_button("Clear", "edit-clear-symbolic");
    {
        let app = app.clone();
        clear.connect_clicked(move |_| {
            {
                let mut model = app.borrow_mut();
                model.drafts.paid_route_country.clear();
            }
            dispatch(
                &app,
                NativeAppAction::SetPaidRouteMarketFilter {
                    query: String::new(),
                    country_code: String::new(),
                    mint_url: String::new(),
                    require_ipv4: false,
                    require_ipv6: false,
                    sort: "quality".to_string(),
                },
            );
        });
    }
    filter.append(&country);
    filter.append(&apply);
    filter.append(&clear);
    parent.append(&filter);
}

fn normalize_paid_route_country_input(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphabetic)
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase()
}

fn paid_route_offer_row(
    app: &AppRef,
    parent: &gtk::Box,
    state: &NativeAppState,
    offer: &NativePaidRouteOfferState,
) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text.set_hexpand(true);

    let title = gtk::Label::new(Some(&paid_route_offer_title(offer)));
    title.add_css_class("heading");
    title.set_xalign(0.0);
    text.append(&title);
    let status = gtk::Label::new(Some(&non_empty_or(&offer.status_text, &offer.seller_npub)));
    status.add_css_class("caption");
    status.add_css_class("dim-label");
    status.set_xalign(0.0);
    status.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    text.append(&status);
    let metrics = paid_route_metric_text(
        &non_empty_or(
            &offer.quality_text,
            &paid_route_quality_text(offer.latency_ms, offer.jitter_ms, offer.packet_loss_ppm),
        ),
        &offer.bandwidth_text,
    );
    if !metrics.is_empty() {
        let label = gtk::Label::new(Some(&metrics));
        label.add_css_class("caption");
        label.add_css_class("dim-label");
        label.set_xalign(0.0);
        text.append(&label);
    }
    row.append(&text);

    let active = state.internet_source == "paid_manual" && state.exit_node == offer.seller_npub;
    let compatible_mint = offer
        .accepted_mints
        .iter()
        .any(|accepted| state.paid_route_market.wallet.mints.iter().any(|mint| mint.url == *accepted));
    let connect = icon_text_button(
        if active { "Active" } else { "Connect" },
        if active { "emblem-ok-symbolic" } else { "go-next-symbolic" },
    );
    connect.set_sensitive(!active && compatible_mint && !offer.key.is_empty());
    {
        let app = app.clone();
        let offer_key = offer.key.clone();
        connect.connect_clicked(move |_| {
            dispatch(
                &app,
                NativeAppAction::BuyPaidRouteOffer {
                    offer_key: offer_key.clone(),
                    mint_url: None,
                    channel_capacity_sat: None,
                },
            );
        });
    }
    row.append(&connect);
    parent.append(&row);
    if !compatible_mint {
        let help = gtk::Label::new(Some("Add one of this seller's accepted mints to buy"));
        help.add_css_class("caption");
        help.add_css_class("warning");
        help.set_xalign(0.0);
        parent.append(&help);
    }
}

fn paid_route_session_row(
    app: &AppRef,
    parent: &gtk::Box,
    session: &NativePaidRouteSessionState,
    envelope_json: &str,
    seller_view: bool,
) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text.set_hexpand(true);

    let title_text = if seller_view {
        paid_exit_seller_session_title(session)
    } else {
        paid_route_buyer_session_title(session)
    };
    let title = gtk::Label::new(Some(&title_text));
    title.add_css_class("heading");
    title.set_xalign(0.0);
    text.append(&title);

    for line in paid_route_session_lines(session) {
        let label = gtk::Label::new(Some(&line));
        label.add_css_class("caption");
        label.add_css_class("dim-label");
        label.set_xalign(0.0);
        label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&label);
    }
    row.append(&text);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    if seller_view {
        let collect = icon_text_button(
            &non_empty_or(&session.collect_action_text, "Collect"),
            "folder-download-symbolic",
        );
        collect.set_sensitive(paid_exit_seller_session_can_collect(session));
        {
            let app = app.clone();
            let channel_id = session.channel_id.clone();
            collect.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::CollectPaidExitChannel {
                        channel_id: channel_id.clone(),
                    },
                );
            });
        }
        buttons.append(&collect);
    } else {
        let connect = icon_text_button("Connect", "go-next-symbolic");
        {
            let app = app.clone();
            let session_id = session.session_id.clone();
            connect.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::SelectPaidRouteSession {
                        session_id: session_id.clone(),
                        connect: true,
                    },
                );
            });
        }
        buttons.append(&connect);

        let probe = icon_text_button("Probe", "network-wireless-symbolic");
        {
            let app = app.clone();
            let session_id = session.session_id.clone();
            probe.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::ProbePaidRouteSession {
                        session_id: session_id.clone(),
                        timeout_secs: 5,
                    },
                );
            });
        }
        buttons.append(&probe);

        if paid_route_session_can_open_channel(session) {
            let fund = icon_text_button("Fund", "wallet-symbolic");
            {
                let app = app.clone();
                let session_id = session.session_id.clone();
                fund.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::OpenPaidRouteChannelFromWallet {
                            session_id: session_id.clone(),
                            mint_url: None,
                            paid_msat: None,
                            max_amount_per_output: None,
                            keyset_id: None,
                        },
                    );
                });
            }
            buttons.append(&fund);
        }
        if paid_route_session_can_sign_payment(session) {
            let pay = icon_text_button("Pay", "mail-send-symbolic");
            {
                let app = app.clone();
                let session_id = session.session_id.clone();
                pay.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::SignPaidRoutePaymentEnvelopeFromWallet {
                            session_id: session_id.clone(),
                            kind: "balance-update".to_string(),
                            delivered_units: None,
                            paid_msat: None,
                        },
                    );
                });
            }
            buttons.append(&pay);
        }
        if paid_route_session_can_close_channel(session) {
            let settle = icon_text_button("Settle", "emblem-ok-symbolic");
            {
                let app = app.clone();
                let session_id = session.session_id.clone();
                settle.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::ClosePaidRouteChannelFromWallet {
                            session_id: session_id.clone(),
                            publish: true,
                        },
                    );
                });
            }
            buttons.append(&settle);
        }
        if !envelope_json.is_empty() {
            let send = icon_text_button("Send", "mail-send-symbolic");
            {
                let app = app.clone();
                let envelope_json = envelope_json.to_string();
                send.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::SendPaidRoutePaymentEnvelope {
                            envelope_json: envelope_json.clone(),
                        },
                    );
                });
            }
            buttons.append(&send);
        }
    }
    row.append(&buttons);
    parent.append(&row);
}

const PAID_EXIT_PRICE_ERROR: &str = "Price must be a whole number in msat/GB.";

fn paid_exit_seller_settings_patch(drafts: &Drafts) -> Result<SettingsPatch, &'static str> {
    let price = drafts
        .paid_exit_price_msat_per_gb
        .trim()
        .parse::<u64>()
        .map_err(|_| PAID_EXIT_PRICE_ERROR)?;
    Ok(SettingsPatch {
        paid_exit_price_msat_per_gb: Some(price),
        paid_exit_country_code: Some(normalize_paid_route_country_input(
            &drafts.paid_exit_country_code,
        )),
        paid_exit_accepted_mints: Some(drafts.paid_exit_accepted_mints.clone()),
        ..SettingsPatch::default()
    })
}

fn build_paid_exit_seller_card(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let seller = &state.paid_exit_seller;
    let seller_card = card();
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    header.set_valign(gtk::Align::Center);
    section_header(&header, "Sell Internet", "");
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    header.append(&spacer);
    let enabled = gtk::Switch::builder().active(seller.enabled).build();
    enabled.update_property(&[gtk::accessible::Property::Label(
        "nvpn-paid-exit-seller-enabled",
    )]);
    enabled.set_sensitive(seller.supported);
    {
        let app = app.clone();
        enabled.connect_active_notify(move |switch| {
            dispatch(
                &app,
                NativeAppAction::UpdateSettings {
                    patch: SettingsPatch {
                        paid_exit_enabled: Some(switch.is_active()),
                        ..SettingsPatch::default()
                    },
                },
            );
        });
    }
    header.append(&enabled);
    seller_card.append(&header);

    detail_row(
        &seller_card,
        "Status",
        &paid_exit_seller_status_text(seller),
    );
    detail_row(
        &seller_card,
        "Internet",
        &paid_exit_seller_internet_text(seller),
    );
    detail_row(
        &seller_card,
        "Pricing",
        &format!(
            "{} · {}",
            non_empty_or(&seller.country_code, "Country unset"),
            &seller.price_text
        ),
    );
    let price_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    price_row.set_valign(gtk::Align::Center);
    price_row.append(&gtk::Label::new(Some("Price (msat/GB)")));
    let price = entry(
        "0",
        &app.borrow().drafts.paid_exit_price_msat_per_gb,
    );
    price.update_property(&[gtk::accessible::Property::Label(
        "nvpn-paid-exit-price-msat-per-gb",
    )]);
    price_row.append(&price);
    price_row.append(&gtk::Label::new(Some("Country")));
    let country = entry("2-letter code", &app.borrow().drafts.paid_exit_country_code);
    country.update_property(&[gtk::accessible::Property::Label(
        "nvpn-paid-exit-country-code",
    )]);
    country.set_hexpand(false);
    country.set_width_chars(4);
    price_row.append(&country);
    seller_card.append(&price_row);

    let mints_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    mints_row.set_valign(gtk::Align::Center);
    mints_row.append(&gtk::Label::new(Some("Accepted mints")));
    let mints = entry(
        "Mint URLs, comma-separated",
        &app.borrow().drafts.paid_exit_accepted_mints,
    );
    mints.update_property(&[gtk::accessible::Property::Label(
        "nvpn-paid-exit-accepted-mints",
    )]);
    mints_row.append(&mints);
    seller_card.append(&mints_row);

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_valign(gtk::Align::Center);
    let save = icon_text_button("Save", "document-save-symbolic");
    save.update_property(&[gtk::accessible::Property::Label(
        "nvpn-paid-exit-seller-save",
    )]);
    let price_error = gtk::Label::new(Some(PAID_EXIT_PRICE_ERROR));
    price_error.add_css_class("caption");
    price_error.add_css_class("warning");
    let price_valid = paid_exit_seller_settings_patch(&app.borrow().drafts).is_ok();
    price_error.set_visible(!price_valid);
    save.set_sensitive(price_valid);
    {
        let app = app.clone();
        let save = save.clone();
        let price_error = price_error.clone();
        price.connect_changed(move |entry| {
            let valid = {
                let mut model = app.borrow_mut();
                model.drafts.paid_exit_price_msat_per_gb = entry.text().to_string();
                paid_exit_seller_settings_patch(&model.drafts).is_ok()
            };
            save.set_sensitive(valid);
            price_error.set_visible(!valid);
        });
    }
    {
        let app = app.clone();
        country.connect_changed(move |entry| {
            let normalized = normalize_paid_route_country_input(&entry.text());
            if entry.text() != normalized {
                entry.set_text(&normalized);
            }
            app.borrow_mut().drafts.paid_exit_country_code = normalized;
        });
    }
    {
        let app = app.clone();
        mints.connect_changed(move |entry| {
            app.borrow_mut().drafts.paid_exit_accepted_mints = entry.text().to_string();
        });
    }
    {
        let app = app.clone();
        let price_error = price_error.clone();
        save.connect_clicked(move |_| {
            let patch = paid_exit_seller_settings_patch(&app.borrow().drafts);
            match patch {
                Ok(patch) => {
                    dispatch(&app, NativeAppAction::UpdateSettings { patch });
                }
                Err(error) => {
                    price_error.set_text(error);
                    price_error.set_visible(true);
                }
            }
        });
    }
    actions.append(&save);
    actions.append(&price_error);
    seller_card.append(&actions);
    detail_row(&seller_card, "Paid exit link", &seller.provider_link);
    detail_row(
        &seller_card,
        "Trial",
        &format!(
            "Free {} · grace {}",
            non_empty_or(
                &seller.free_probe_text,
                &paid_route_traffic_unit_text(seller.free_probe_units),
            ),
            non_empty_or(
                &seller.grace_text,
                &paid_route_traffic_unit_text(seller.grace_units),
            )
        ),
    );
    detail_row(&seller_card, "Public IP", &seller.public_ip_text);
    detail_row(&seller_card, "Settlement", &seller.settlement_text);
    detail_row(
        &seller_card,
        "Credit",
        &format!(
            "{} {}",
            non_empty_or(&seller.channel_credit_title_text, "Pending buyer credit"),
            non_empty_or(
                &seller.channel_credit_text,
                &format_paid_route_msat(seller.channel_credit_msat),
            )
        ),
    );
    detail_row(
        &seller_card,
        "Totals",
        &paid_exit_seller_totals_text(seller),
    );
    if seller.total_unpaid_msat > 0 {
        seller_card.append(&badge(
            &format!(
                "{} behind",
                non_empty_or(
                    &seller.total_unpaid_text,
                    &format_paid_route_msat(seller.total_unpaid_msat),
                )
            ),
            "warn",
        ));
    }

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let collect = icon_text_button("Collect due", "folder-download-symbolic");
    collect.set_sensitive(seller.supported);
    {
        let app = app.clone();
        collect.connect_clicked(move |_| {
            dispatch(&app, NativeAppAction::CollectDuePaidExitChannels);
        });
    }
    actions.append(&collect);
    seller_card.append(&actions);

    section_header(&seller_card, "Customers", "");
    if seller.sessions.is_empty() {
        empty_row(&seller_card, "No customers connected");
    } else {
        for session in &seller.sessions {
            paid_route_session_row(app, &seller_card, session, "", true);
        }
    }

    page.append(&seller_card);
}

fn paid_route_session_lines(session: &NativePaidRouteSessionState) -> Vec<String> {
    let mut lines = vec![paid_route_session_detail(session)];
    if !session.location_text.is_empty() {
        lines.push(session.location_text.clone());
    } else if !session.realized_exit_ip.is_empty() {
        lines.push(format!(
            "{} · {}",
            session.realized_exit_ip,
            paid_route_country_claim_text(session),
        ));
    }
    let metric = paid_route_metric_text(
        &non_empty_or(
            &session.quality_text,
            &paid_route_quality_text(
                session.latency_ms,
                session.jitter_ms,
                session.packet_loss_ppm,
            ),
        ),
        &session.bandwidth_text,
    );
    if !metric.is_empty() {
        lines.push(metric);
    }
    if !session.settlement_text.is_empty() {
        lines.push(session.settlement_text.clone());
    }
    lines.push(format!(
        "{} · {}",
        non_empty_or(
            &session.paid_text,
            &format!("{} paid", format_paid_route_msat(session.paid_msat)),
        ),
        if session.unpaid_msat > 0 {
            non_empty_or(
                &session.unpaid_text,
                &format!("{} behind", format_paid_route_msat(session.unpaid_msat)),
            )
        } else {
            non_empty_or(
                &session.amount_due_text,
                &format!("{} due", format_paid_route_msat(session.amount_due_msat)),
            )
        }
    ));
    lines
}

fn paid_route_buyer_session_title(session: &NativePaidRouteSessionState) -> String {
    if !session.title_text.is_empty() {
        session.title_text.clone()
    } else if session.allow_routing {
        "Ready".to_string()
    } else if session.unpaid_msat > 0 {
        "Payment needed".to_string()
    } else if !session.payment_channel_ready {
        "Needs funds".to_string()
    } else {
        paid_route_plain_status(
            &non_empty_or(&session.status_text, &session.lifecycle_status),
            "Session",
        )
    }
}

fn paid_exit_seller_session_title(session: &NativePaidRouteSessionState) -> String {
    if !session.title_text.is_empty() {
        session.title_text.clone()
    } else if session.allow_routing {
        "Connected customer".to_string()
    } else if session.unpaid_msat > 0 {
        "Customer behind".to_string()
    } else {
        paid_route_plain_status(
            &non_empty_or(&session.status_text, &session.lifecycle_status),
            "Customer",
        )
    }
}

fn paid_route_session_detail(session: &NativePaidRouteSessionState) -> String {
    if !session.detail_text.is_empty() {
        return session.detail_text.clone();
    }
    let access = paid_route_access_title(
        &session.access_state,
        &non_empty_or(&session.lifecycle_status, "session"),
    );
    let units = if session.bytes > 0 {
        format!("{} used", format_bytes(session.bytes))
    } else if session.packets > 0 {
        format!("{} packets", session.packets)
    } else {
        format!("{} units", session.delivered_units)
    };
    format!(
        "{access}, {units}, {} due",
        format_paid_route_msat(session.amount_due_msat)
    )
}

fn paid_route_session_can_open_channel(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty() && !session.payment_channel_ready
}

fn paid_route_session_can_sign_payment(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty() && session.payment_channel_ready && session.unpaid_msat > 0
}

fn paid_route_session_can_close_channel(session: &NativePaidRouteSessionState) -> bool {
    !session.session_id.is_empty()
        && session.payment_channel_ready
        && !matches!(session.lifecycle_status.as_str(), "closed" | "expired")
}

fn paid_exit_seller_session_can_collect(session: &NativePaidRouteSessionState) -> bool {
    session.payment_channel_ready
        && session.paid_msat > 0
        && !session.channel_id.is_empty()
        && (!session.collect_action_text.is_empty()
            || !matches!(session.lifecycle_status.as_str(), "closed" | "expired"))
}

fn paid_route_offer_title(offer: &NativePaidRouteOfferState) -> String {
    format!(
        "{} · {}",
        non_empty_or(&offer.country_code, "Unknown country").to_uppercase(),
        &offer.price_text
    )
}

fn paid_exit_seller_status_text(seller: &NativePaidExitSellerState) -> String {
    if !seller.status_text.is_empty() {
        seller
            .status_text
            .replace("Paid exit selling", "Selling internet")
            .replace("paid exit selling", "selling internet")
    } else if seller.supported {
        "People can pay to use my internet".to_string()
    } else {
        "This platform cannot sell public internet access".to_string()
    }
}

fn paid_exit_seller_internet_text(seller: &NativePaidExitSellerState) -> String {
    if !seller.internet_text.is_empty() {
        seller.internet_text.clone()
    } else if matches!(
        seller.upstream.as_str(),
        "wireguard_exit" | "wireguard" | "wg" | "upstream_vpn" | "vpn"
    ) {
        "My internet through WireGuard".to_string()
    } else {
        "My internet".to_string()
    }
}

fn paid_exit_seller_totals_text(seller: &NativePaidExitSellerState) -> String {
    [
        format!("{} connected", seller.current_connection_count),
        format!("{} past", seller.past_connection_count),
        non_empty_or(
            &seller.total_traffic_text,
            &format!("{} routed", format_bytes(seller.total_billable_bytes)),
        ),
        format!(
            "{} paid",
            non_empty_or(
                &seller.total_paid_text,
                &format_paid_route_msat(seller.total_paid_msat),
            )
        ),
        format!(
            "{} due",
            non_empty_or(
                &seller.total_due_text,
                &format_paid_route_msat(seller.total_due_msat),
            )
        ),
    ]
    .join(" · ")
}

fn paid_route_payment_action_text(
    action: &nostr_vpn_app_core::native_state::NativePaidRoutePaymentActionState,
) -> String {
    if action.kind.is_empty() && action.status_text.is_empty() {
        String::new()
    } else {
        non_empty_or(
            &action.status_text,
            &paid_route_payment_action_title(&action.kind),
        )
    }
}

fn paid_route_wallet_action_text(
    action: &nostr_vpn_app_core::native_state::NativePaidRouteWalletActionState,
) -> String {
    if action.kind.is_empty() && action.status_text.is_empty() {
        String::new()
    } else {
        non_empty_or(
            &action.status_text,
            &paid_route_wallet_action_title(&action.kind),
        )
    }
}

fn paid_route_access_title(value: &str, fallback: &str) -> String {
    match value {
        "paid" => "Paid".to_string(),
        "free_probe" => "Free test".to_string(),
        "grace" => "Grace".to_string(),
        "suspended" => "Paused".to_string(),
        other => paid_route_plain_status(other, fallback),
    }
}

fn paid_route_plain_status(value: &str, fallback: &str) -> String {
    let raw = non_empty_or(value, fallback).replace('_', " ");
    let mut chars = raw.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn paid_route_quality_text(latency_ms: u32, jitter_ms: u32, packet_loss_ppm: u32) -> String {
    if latency_ms == 0 && jitter_ms == 0 && packet_loss_ppm == 0 {
        return "Quality unmeasured".to_string();
    }
    let loss = packet_loss_ppm as f64 / 10_000.0;
    format!("{latency_ms} ms · {jitter_ms} ms jitter · {loss:.2}% loss")
}

fn paid_route_metric_text(quality: &str, bandwidth: &str) -> String {
    [quality.trim(), bandwidth.trim()]
        .into_iter()
        .filter(|value| !value.is_empty() && *value != "Quality unmeasured")
        .collect::<Vec<_>>()
        .join(" · ")
}

fn paid_route_country_claim_text(session: &NativePaidRouteSessionState) -> String {
    match session.country_claim_status.as_str() {
        "match" => format!(
            "{} matches claim",
            non_empty_or(
                &session.observed_country_code,
                &session.claimed_country_code
            )
        ),
        "mismatch" => format!(
            "{} differs from {}",
            non_empty_or(&session.observed_country_code, "Observed country"),
            session.claimed_country_code,
        ),
        _ => non_empty_or(
            &session.observed_country_code,
            &non_empty_or(&session.claimed_country_code, "country unknown"),
        ),
    }
}

fn paid_route_traffic_unit_text(units: u64) -> String {
    format_bytes(units)
}

fn format_paid_route_msat(msat: u64) -> String {
    if msat >= 1_000 {
        let sat = msat as f64 / 1_000.0;
        if (sat.fract()).abs() < f64::EPSILON {
            format!("{sat:.0} sat")
        } else {
            format!("{sat:.3} sat")
        }
    } else {
        format!("{msat} msat")
    }
}

fn parse_positive_u64(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok().filter(|value| *value > 0)
}

include!("paid_routes_action_text.rs");
