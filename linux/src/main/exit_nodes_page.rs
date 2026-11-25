fn build_exit_nodes_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Internet", "");

    let exit = card();
    section_header(&exit, "Connect through", "network-workgroup-symbolic");
    let status_style = if state.exit_node_blocked {
        "bad"
    } else if state.exit_node_active {
        "ok"
    } else {
        "muted"
    };
    let status = badge(&state.exit_node_status_text, status_style);
    status.update_property(&[gtk::accessible::Property::Label(
        "nvpn-internet-source-status",
    )]);
    status.set_halign(gtk::Align::Start);
    exit.append(&status);

    let Some(network) = active_network(state).cloned() else {
        page.append(&exit);
        build_wireguard_settings_card(app, page, state);
        build_exit_dns_settings_card(app, page);
        return;
    };

    route_choice(
        app,
        &exit,
        "This device",
        "Use my normal connection",
        state.internet_source == "direct",
        true,
        ExitChoice::Direct,
    );

    let wg_subtitle = if !state.wireguard_exit_configured {
        "No WireGuard config saved yet".to_string()
    } else if state.wireguard_exit_endpoint.is_empty() {
        "Configured".to_string()
    } else {
        state.wireguard_exit_endpoint.clone()
    };
    route_choice(
        app,
        &exit,
        "WireGuard VPN",
        &wg_subtitle,
        state.internet_source == "wireguard",
        state.wireguard_exit_configured,
        ExitChoice::WireGuard,
    );
    if !state.wireguard_exit_configured && state.internet_source != "wireguard" {
        // The WireGuard choice stays disabled until a config is saved, so the
        // editor must be reachable right here.
        let setup = gtk::Expander::new(Some("Set up WireGuard upstream"));
        setup.set_expanded(app.borrow().wireguard_setup_expanded);
        {
            let app = app.clone();
            setup.connect_expanded_notify(move |setup| {
                app.borrow_mut().wireguard_setup_expanded = setup.is_expanded();
            });
        }
        let body = gtk::Box::new(gtk::Orientation::Vertical, 0);
        body.set_margin_top(10);
        build_wireguard_settings_card(app, &body, state);
        setup.set_child(Some(&body));
        exit.append(&setup);
    }

    if state.paid_route_market.supported {
        route_choice(
            app,
            &exit,
            "Paid Internet · Automatic",
            "Automatically choose a verified provider · Experimental",
            state.internet_source == "paid_automatic",
            true,
            ExitChoice::PaidAutomatic,
        );
        if state.internet_source == "paid_automatic" && !state.exit_node.is_empty() {
            let controls = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            if state.exit_node_active {
                if let Some(session) = state
                    .paid_route_market
                    .sessions
                    .iter()
                    .find(|session| session.seller_npub == state.exit_node && session.can_rate)
                {
                    paid_exit_rating_buttons(
                        app,
                        &controls,
                        &session.seller_npub,
                        session.personal_rating,
                    );
                }
            }
            let retry = gtk::Button::with_label("Try another");
            let app = app.clone();
            retry.set_widget_name("nvpn-route-retry");
            retry.connect_clicked(move |_| {
                dispatch(&app, NativeAppAction::ReselectPaidExit);
            });
            controls.append(&retry);
            exit.append(&controls);
        }
        route_choice(
            app,
            &exit,
            "Paid Internet · Manual",
            "Browse and choose a provider · Experimental",
            state.internet_source == "paid_manual",
            true,
            ExitChoice::PaidManual,
        );
    }
    switch_row(
        app,
        &exit,
        "Block internet if selected source disconnects",
        state.exit_node_leak_protection,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node_leak_protection: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    page.append(&exit);
    build_trusted_exit_card(app, page, &network, state);

    // Private sharing and public selling stay in separate cards so it is
    // clear who can use this device's connection.
    let share = card();
    section_header(
        &share,
        "Share with trusted devices",
        "security-high-symbolic",
    );
    switch_row(
        app,
        &share,
        "Share this device's internet",
        state.advertise_exit_node,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                advertise_exit_node: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    empty_row(
        &share,
        &format!(
            "Only devices in {} can use it. Nothing is offered publicly.",
            if network.name.trim().is_empty() {
                "this network"
            } else {
                network.name.trim()
            }
        ),
    );
    page.append(&share);

    if state.paid_exit_seller.supported {
        let sell = card();
        section_header(&sell, "Sell internet publicly", "mail-send-symbolic");
        empty_row(
            &sell,
            "Anyone can pay to use this device's internet · Experimental",
        );
        empty_row(
            &sell,
            &paid_exit_seller_status_text(&state.paid_exit_seller),
        );
        let open = gtk::Button::with_label("Selling settings");
        open.set_halign(gtk::Align::Start);
        open.set_widget_name("nvpn-paid-exit-seller-open");
        open.update_property(&[gtk::accessible::Property::Label(
            "nvpn-paid-exit-seller-open",
        )]);
        {
            let app = app.clone();
            open.connect_clicked(move |_| set_page(&app, Page::SellInternet));
        }
        sell.append(&open);
        page.append(&sell);
    }
    if state.internet_source == "wireguard" {
        build_wireguard_settings_card(app, page, state);
    }
    build_exit_dns_settings_card(app, page);
}

fn build_trusted_exit_card(
    app: &AppRef,
    page: &gtk::Box,
    network: &NativeNetworkState,
    state: &NativeAppState,
) {
    let trusted = card();
    section_header(&trusted, "Trusted devices", "security-high-symbolic");
    let candidates = exit_node_candidates(network, state);
    if candidates.is_empty() {
        empty_row(&trusted, "No trusted devices sharing internet");
        page.append(&trusted);
        return;
    }
    let search = (candidates.len() > SEARCH_VISIBILITY_THRESHOLD).then(|| {
        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("Search devices"));
        search.set_widget_name("nvpn-exit-search");
        trusted.append(&search);
        search
    });
    let mut rows = Vec::new();
    for participant in candidates {
        route_choice(
            app,
            &trusted,
            &device_name(&participant),
            non_empty_or(&participant.status_text, "Trusted device").as_str(),
            state.internet_source == "private_vpn" && state.exit_node == participant.npub,
            true,
            ExitChoice::Peer(participant.npub.clone()),
        );
        let haystack = format!("{} {}", device_name(&participant), participant.npub).to_lowercase();
        rows.push((trusted.last_child().unwrap(), haystack));
    }
    let none_found = gtk::Label::new(Some("No trusted devices found"));
    none_found.add_css_class("dim-label");
    none_found.set_visible(false);
    trusted.append(&none_found);
    if let Some(search) = search {
        // Filter in place so typing keeps focus.
        let filter = move |query: &str| {
            let query = query.trim().to_lowercase();
            let mut shown = 0;
            for (row, haystack) in &rows {
                let visible = query.is_empty() || haystack.contains(&query);
                row.set_visible(visible);
                shown += usize::from(visible);
            }
            none_found.set_visible(shown == 0);
        };
        let query = app.borrow().drafts.exit_search.clone();
        search.set_text(&query);
        filter(&query);
        let app = app.clone();
        search.connect_search_changed(move |search| {
            let query = search.text().to_string();
            filter(&query);
            app.borrow_mut().drafts.exit_search = query;
        });
    }
    page.append(&trusted);
}

#[derive(Clone)]
enum ExitChoice {
    Direct,
    WireGuard,
    Peer(String),
    PaidAutomatic,
    PaidManual,
}

fn route_choice(
    app: &AppRef,
    parent: &gtk::Box,
    title: &str,
    subtitle: &str,
    selected: bool,
    enabled: bool,
    choice: ExitChoice,
) {
    let button = gtk::Button::new();
    button.add_css_class("flat");
    button.add_css_class("nvpn-route-choice");
    let route = match &choice {
        ExitChoice::Direct => "direct",
        ExitChoice::WireGuard => "wireguard",
        ExitChoice::Peer(npub) => npub.as_str(),
        ExitChoice::PaidAutomatic => "paid-automatic",
        ExitChoice::PaidManual => "paid-manual",
    };
    button.set_widget_name(&format!("nvpn-route-{route}"));
    button.set_sensitive(enabled);

    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    let icon = gtk::Image::from_icon_name(if selected {
        "object-select-symbolic"
    } else {
        "radio-symbolic"
    });
    if selected {
        icon.add_css_class("success");
    }
    row.append(&icon);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text.set_hexpand(true);
    let title_label = gtk::Label::new(Some(title));
    title_label.set_xalign(0.0);
    title_label.add_css_class("heading");
    text.append(&title_label);
    let subtitle_label = gtk::Label::new(Some(subtitle));
    subtitle_label.set_xalign(0.0);
    subtitle_label.add_css_class("caption");
    subtitle_label.add_css_class("dim-label");
    text.append(&subtitle_label);
    row.append(&text);

    button.set_child(Some(&row));
    {
        let app = app.clone();
        let choice = choice.clone();
        button.connect_clicked(move |_| {
            if selected && !matches!(choice, ExitChoice::PaidManual) {
                return;
            }
            let patch = match choice.clone() {
                ExitChoice::Direct => SettingsPatch {
                    internet_source: Some("direct".to_string()),
                    ..SettingsPatch::default()
                },
                ExitChoice::WireGuard => SettingsPatch {
                    internet_source: Some("wireguard".to_string()),
                    ..SettingsPatch::default()
                },
                ExitChoice::Peer(npub) => SettingsPatch {
                    internet_source: Some("private_vpn".to_string()),
                    exit_node: Some(npub),
                    ..SettingsPatch::default()
                },
                ExitChoice::PaidAutomatic => SettingsPatch {
                    internet_source: Some("paid_automatic".to_string()),
                    ..SettingsPatch::default()
                },
                ExitChoice::PaidManual => {
                    set_page(&app, Page::PaidRoutes);
                    return;
                }
            };
            dispatch(&app, NativeAppAction::UpdateSettings { patch });
        });
    }
    parent.append(&button);
}
