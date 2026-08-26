fn build_exit_nodes_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Internet", "");

    let exit = card();
    section_header(&exit, "Internet Source", "");
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

    let all_exit_candidates = exit_node_candidates(&network, state);
    let show_search = all_exit_candidates.len() > SEARCH_VISIBILITY_THRESHOLD;
    if show_search {
        let search = entry("Search devices", &app.borrow().drafts.exit_search);
        {
            let app = app.clone();
            search.connect_changed(move |entry| {
                app.borrow_mut().drafts.exit_search = entry.text().to_string();
            });
        }
        exit.append(&search);
    }

    route_choice(
        app,
        &exit,
        "Direct",
        "Use normal internet routing",
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
        "WireGuard upstream",
        &wg_subtitle,
        state.internet_source == "wireguard",
        state.wireguard_exit_configured,
        ExitChoice::WireGuard,
    );

    let query = if show_search {
        app.borrow().drafts.exit_search.trim().to_ascii_lowercase()
    } else {
        String::new()
    };
    let exit_candidates = all_exit_candidates
        .into_iter()
        .filter(|participant| {
            query.is_empty()
                || device_name(participant)
                    .to_ascii_lowercase()
                    .contains(&query)
                || participant.npub.to_ascii_lowercase().contains(&query)
        })
        .collect::<Vec<_>>();
    if exit_candidates.is_empty() {
        empty_row(
            &exit,
            if query.is_empty() {
                "No exit nodes offered"
            } else {
                "No exit nodes found"
            },
        );
    } else {
        for participant in exit_candidates {
            let peer_selected = state.internet_source == "private_vpn"
                && state.exit_node == participant.npub;
            route_choice(
                app,
                &exit,
                &device_name(&participant),
                non_empty_or(&participant.status_text, "Exit node").as_str(),
                peer_selected,
                true,
                ExitChoice::Peer(participant.npub.clone()),
            );
        }
    }
    if state.paid_route_market.supported {
        route_choice(
            app,
            &exit,
            "Paid · Automatic · Experimental",
            "Experimental · choose a working, reasonably priced provider",
            state.internet_source == "paid_automatic",
            true,
            ExitChoice::PaidAutomatic,
        );
        route_choice(
            app,
            &exit,
            "Paid · Choose manually",
            "Experimental · browse internet sellers",
            state.internet_source == "paid_manual",
            true,
            ExitChoice::PaidManual,
        );
    }
    page.append(&exit);

    let offer = card();
    switch_row(
        app,
        &offer,
        "Offer this device as an exit node",
        state.advertise_exit_node,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                advertise_exit_node: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    switch_row(
        app,
        &offer,
        "Block internet if selected source disconnects",
        state.exit_node_leak_protection,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                exit_node_leak_protection: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    page.append(&offer);
    if state.paid_exit_seller.supported {
        let sell = icon_text_button("Sell internet access · Experimental", "mail-send-symbolic");
        sell.update_property(&[gtk::accessible::Property::Label(
            "nvpn-paid-exit-seller-open",
        )]);
        {
            let app = app.clone();
            sell.connect_clicked(move |_| set_page(&app, Page::SellInternet));
        }
        offer.append(&sell);
    }
    if state.internet_source == "wireguard" {
        build_wireguard_settings_card(app, page, state);
    }
    build_exit_dns_settings_card(app, page);
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
                ExitChoice::PaidManual => SettingsPatch {
                    internet_source: Some("paid_manual".to_string()),
                    ..SettingsPatch::default()
                },
            };
            dispatch(&app, NativeAppAction::UpdateSettings { patch });
            if matches!(choice, ExitChoice::PaidManual) {
                set_page(&app, Page::PaidRoutes);
            }
        });
    }
    parent.append(&button);
}
