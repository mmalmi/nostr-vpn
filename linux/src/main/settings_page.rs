fn build_settings_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    page_title(page, "Settings", "emblem-system-symbolic");

    let (service_settling, tray_error, update, tray_available) = {
        let model = app.borrow();
        (
            model.service_settling,
            model.tray_error.clone(),
            model.update.clone(),
            model.tray_available,
        )
    };

    let device = card();
    section_header(&device, "This Device", "");
    setting_entry(app, &device, "Name", "node_name");
    setting_entry(app, &device, "Tunnel IP", "tunnel_ip");
    setting_entry(app, &device, "Endpoint", "endpoint");
    setting_entry(app, &device, "Listen Port", "listen_port");

    let save = icon_text_button("Save", "");
    save.add_css_class("suggested-action");
    save.set_halign(gtk::Align::Start);
    {
        let app = app.clone();
        save.connect_clicked(move |_| save_device_settings(&app));
    }
    device.append(&save);
    page.append(&device);

    let general = card();
    section_header(&general, "General", "");
    switch_row(
        app,
        &general,
        "Start VPN automatically",
        state.autoconnect,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                autoconnect: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    if state.startup_settings_supported {
        switch_row(
            app,
            &general,
            "Launch on startup",
            state.launch_on_startup,
            |enabled| NativeAppAction::UpdateSettings {
                patch: SettingsPatch {
                    launch_on_startup: Some(enabled),
                    ..SettingsPatch::default()
                },
            },
        );
    }
    if state.tray_behavior_supported {
        switch_row_enabled(
            app,
            &general,
            "Tray on close",
            state.close_to_tray_on_close,
            tray_available,
            |enabled| NativeAppAction::UpdateSettings {
                patch: SettingsPatch {
                    close_to_tray_on_close: Some(enabled),
                    ..SettingsPatch::default()
                },
            },
        );
    }
    page.append(&general);

    if state.paid_route_market.supported {
        let wallet = card();
        section_header(&wallet, "Wallet", "");
        switch_row(
            app,
            &wallet,
            "Show fiat value",
            state.wallet_fiat_enabled,
            |enabled| NativeAppAction::UpdateSettings {
                patch: SettingsPatch {
                    wallet_fiat_enabled: Some(enabled),
                    ..SettingsPatch::default()
                },
            },
        );
        if state.wallet_fiat_enabled {
            let source = gtk::Label::new(Some("Rates from Coinbase and Kraken"));
            source.set_xalign(0.0);
            source.add_css_class("dim-label");
            wallet.append(&source);
            const CURRENCIES: [&str; 7] = ["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF"];
            let currency = gtk::DropDown::from_strings(&CURRENCIES);
            currency.set_selected(
                CURRENCIES
                    .iter()
                    .position(|value| *value == state.wallet_fiat_currency)
                    .unwrap_or_default() as u32,
            );
            {
                let app = app.clone();
                currency.connect_selected_notify(move |dropdown| {
                    let Some(value) = CURRENCIES.get(dropdown.selected() as usize) else {
                        return;
                    };
                    dispatch(
                        &app,
                        NativeAppAction::UpdateSettings {
                            patch: SettingsPatch {
                                wallet_fiat_currency: Some((*value).to_string()),
                                ..SettingsPatch::default()
                            },
                        },
                    );
                });
            }
            wallet.append(&currency);
        }
        page.append(&wallet);
    }

    let fips = card();
    section_header(&fips, "FIPS", "");
    switch_row(
        app,
        &fips,
        "Connect to non-roster FIPS peers",
        state.connect_to_non_roster_fips_peers,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                connect_to_non_roster_fips_peers: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    switch_row(
        app,
        &fips,
        "Find peers over Nostr relays",
        state.fips_nostr_discovery_enabled,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                fips_nostr_discovery_enabled: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    switch_row(
        app,
        &fips,
        "Use bootstrap servers",
        state.fips_bootstrap_enabled,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                fips_bootstrap_enabled: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    switch_row(
        app,
        &fips,
        "Enable WebRTC transport",
        state.fips_webrtc_enabled,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                fips_webrtc_enabled: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    page.append(&fips);

    let public_fips = card();
    section_header(&public_fips, "Public FIPS routing", "");
    let public_fips_help = gtk::Label::new(Some(
        "FIPS gives .fips addresses end-to-end encryption and identity-based routing. Hosts can reach each other without static IPs, domain names, TLS certificates, or NAT port forwarding.",
    ));
    public_fips_help.add_css_class("caption");
    public_fips_help.add_css_class("dim-label");
    public_fips_help.set_wrap(true);
    public_fips_help.set_xalign(0.0);
    public_fips.append(&public_fips_help);
    let learn_fips = gtk::LinkButton::with_label("https://learn.fips.network/", "Learn FIPS");
    learn_fips.set_halign(gtk::Align::Start);
    public_fips.append(&learn_fips);
    switch_row(
        app,
        &public_fips,
        "Route npub.fips outside VPN",
        state.fips_host_tunnel_enabled,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                fips_host_tunnel_enabled: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    let public_fips_details = gtk::Box::new(gtk::Orientation::Vertical, 10);
    public_fips_details.set_sensitive(state.fips_host_tunnel_enabled);
    let public_fips_address = public_fips_address(&state.own_npub);
    detail_row(
        &public_fips_details,
        "Your public FIPS address",
        &public_fips_address,
    );
    setting_entry_enabled(
        app,
        &public_fips_details,
        "Public .fips inbound TCP ports",
        "fips_host_inbound_tcp_ports",
        true,
    );
    let save = icon_text_button("Save", "");
    save.add_css_class("suggested-action");
    save.set_halign(gtk::Align::Start);
    save.set_sensitive(state.fips_host_tunnel_enabled);
    {
        let app = app.clone();
        save.connect_clicked(move |_| save_device_settings(&app));
    }
    public_fips_details.append(&save);
    public_fips.append(&public_fips_details);
    page.append(&public_fips);

    let relays = card();
    section_header(&relays, "Relays", "");
    let add_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    add_row.set_valign(gtk::Align::Center);
    let relay_input = entry("wss://relay.example.com", &app.borrow().drafts.relay_input);
    {
        let app = app.clone();
        relay_input.connect_changed(move |entry| {
            app.borrow_mut().drafts.relay_input = entry.text().to_string();
        });
    }
    {
        let app = app.clone();
        relay_input.connect_activate(move |_| add_relay_setting(&app));
    }
    add_row.append(&relay_input);
    let add_relay = gtk::Button::from_icon_name("list-add-symbolic");
    add_relay.set_tooltip_text(Some("Add relay"));
    {
        let app = app.clone();
        add_relay.connect_clicked(move |_| add_relay_setting(&app));
    }
    add_row.append(&add_relay);
    relays.append(&add_row);
    for relay in &state.relays {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.set_valign(gtk::Align::Center);
        let dot = gtk::Label::new(Some("●"));
        dot.add_css_class(if relay.enabled && relay.status == "connected" {
            "success"
        } else {
            "dim-label"
        });
        {
            let dot = dot.downgrade();
            let url = relay.url.clone();
            app.borrow_mut().live_updates.push(Rc::new(move |state| {
                if let Some(dot) = dot.upgrade() {
                    let connected = state.relays.iter().any(|relay|
                        relay.url == url && relay.enabled && relay.status == "connected");
                    if connected {
                        dot.remove_css_class("dim-label");
                        dot.add_css_class("success");
                    } else {
                        dot.remove_css_class("success");
                        dot.add_css_class("dim-label");
                    }
                }
            }));
        }
        row.append(&dot);
        let url = gtk::Label::new(Some(&relay.url));
        url.set_xalign(0.0);
        url.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        url.set_hexpand(true);
        if !relay.enabled {
            url.add_css_class("dim-label");
        }
        row.append(&url);
        let relay_switch = gtk::Switch::builder().active(relay.enabled).build();
        {
            let app = app.clone();
            let url = relay.url.clone();
            relay_switch.connect_active_notify(move |relay_switch| {
                set_relay_enabled(&app, &url, relay_switch.is_active());
            });
        }
        row.append(&relay_switch);
        let delete = gtk::Button::from_icon_name("edit-delete-symbolic");
        delete.set_tooltip_text(Some("Delete relay"));
        {
            let app = app.clone();
            let url = relay.url.clone();
            delete.connect_clicked(move |_| delete_relay_setting(&app, &url));
        }
        row.append(&delete);
        relays.append(&row);
    }
    page.append(&relays);

    let network = card();
    let network_header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    section_header(&network_header, "Networks", "");
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    network_header.append(&spacer);
    let new_name = entry("New network", &app.borrow().drafts.new_network_name);
    new_name.set_width_chars(18);
    {
        let app = app.clone();
        new_name.connect_changed(move |entry| {
            app.borrow_mut().drafts.new_network_name = entry.text().to_string();
        });
    }
    {
        let app = app.clone();
        new_name.connect_activate(move |_| add_network_from_draft(&app));
    }
    network_header.append(&new_name);
    let add = gtk::Button::from_icon_name("list-add-symbolic");
    add.set_tooltip_text(Some("Add network"));
    {
        let app = app.clone();
        add.connect_clicked(move |_| add_network_from_draft(&app));
    }
    network_header.append(&add);
    network.append(&network_header);

    if let Some(active) = active_network(state).cloned() {
        let rename = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let label = gtk::Label::new(Some("Active"));
        label.set_width_chars(10);
        label.set_xalign(0.0);
        label.add_css_class("dim-label");
        rename.append(&label);
        let input = entry("Network name", &app.borrow().drafts.network_name);
        {
            let app = app.clone();
            input.connect_changed(move |entry| {
                app.borrow_mut().drafts.network_name = entry.text().to_string();
            });
        }
        {
            let app = app.clone();
            let network_id = active.id.clone();
            input.connect_activate(move |_| save_active_network_name(&app, &network_id));
        }
        let save = gtk::Button::with_label("Save");
        {
            let app = app.clone();
            let network_id = active.id.clone();
            save.connect_clicked(move |_| save_active_network_name(&app, &network_id));
        }
        rename.append(&input);
        rename.append(&save);
        network.append(&rename);

        let mesh = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let label = gtk::Label::new(Some("Network ID"));
        label.set_width_chars(10);
        label.set_xalign(0.0);
        label.add_css_class("dim-label");
        mesh.append(&label);
        let mesh_id = entry("Network ID", &app.borrow().drafts.mesh_id);
        {
            let app = app.clone();
            mesh_id.connect_changed(move |entry| {
                app.borrow_mut().drafts.mesh_id = entry.text().to_string();
            });
        }
        {
            let app = app.clone();
            let network_id = active.id.clone();
            mesh_id.connect_activate(move |_| save_active_network_mesh_id(&app, &network_id));
        }
        mesh.append(&mesh_id);
        let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
        copy.set_tooltip_text(Some("Copy network ID"));
        {
            let network_id = active.network_id.clone();
            copy.connect_clicked(move |_| copy_text(&network_id));
        }
        mesh.append(&copy);
        let save = gtk::Button::with_label("Save");
        save.set_sensitive(active.local_is_admin);
        {
            let app = app.clone();
            let network_id = active.id.clone();
            save.connect_clicked(move |_| save_active_network_mesh_id(&app, &network_id));
        }
        mesh.append(&save);
        network.append(&mesh);

        switch_row_enabled(
            app,
            &network,
            "Allow join requests",
            active.join_requests_enabled,
            active.local_is_admin,
            {
                let network_id = active.id.clone();
                move |enabled| NativeAppAction::SetNetworkJoinRequestsEnabled {
                    network_id: network_id.clone(),
                    enabled,
                }
            },
        );

        let delete_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        delete_row.set_halign(gtk::Align::Start);
        let delete = icon_text_button("Delete network", "edit-delete-symbolic");
        delete.add_css_class("destructive-action");
        connect_remove_network_confirmation(
            &delete,
            app,
            active.id.clone(),
            display_network_name(&active),
        );
        delete_row.append(&delete);
        network.append(&delete_row);
    }

    let saved = gtk::Expander::new(Some("Saved Networks"));
    let saved_body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    saved_body.set_margin_top(10);
    let inactive = state
        .networks
        .iter()
        .filter(|network| !network.enabled)
        .cloned()
        .collect::<Vec<_>>();
    if inactive.is_empty() {
        empty_row(&saved_body, "No saved networks");
    } else {
        for saved_network in inactive {
            saved_network_row(app, &saved_body, &saved_network, state);
        }
    }
    saved.set_child(Some(&saved_body));
    network.append(&saved);
    page.append(&network);

    let system = card();
    {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.set_valign(gtk::Align::Center);
        let title = gtk::Label::new(Some("System"));
        title.add_css_class("title-3");
        title.set_xalign(0.0);
        row.append(&title);
        let label = system_version_label(state);
        if !label.is_empty() {
            let version = gtk::Label::new(Some(&label));
            version.add_css_class("caption");
            version.add_css_class("dim-label");
            version.set_selectable(true);
            version.set_xalign(0.0);
            row.append(&version);
        }
        system.append(&row);
    }
    let status_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    status_row.append(&badge(
        if state.service_installed {
            "Service installed"
        } else {
            "Service missing"
        },
        if state.service_installed {
            "ok"
        } else {
            "warn"
        },
    ));
    status_row.append(&badge(
        if state.service_running {
            "Running"
        } else {
            "Stopped"
        },
        if state.service_running { "ok" } else { "muted" },
    ));
    status_row.append(&badge(
        if state.cli_installed {
            "CLI installed"
        } else {
            "CLI missing"
        },
        if state.cli_installed { "ok" } else { "muted" },
    ));
    if service_update_recommended(state) {
        status_row.append(&badge("Update available", "warn"));
    }
    if service_settling {
        status_row.append(&badge("Settling", "muted"));
    }
    let update_badge = if update.available {
        format!("Update {}", update.version)
    } else {
        "Current".to_string()
    };
    status_row.append(&badge(
        &update_badge,
        if update.available { "warn" } else { "ok" },
    ));
    if update.checking {
        status_row.append(&badge("Checking", "muted"));
    }
    if update.downloading {
        status_row.append(&badge("Downloading", "muted"));
    }
    system.append(&status_row);

    let status_detail = first_non_empty(&[&update.status, &state.service_status_detail]);
    if let Some(status_detail) = status_detail {
        let detail = gtk::Label::new(Some(&status_detail));
        detail.add_css_class("caption");
        detail.add_css_class("dim-label");
        detail.set_xalign(0.0);
        detail.set_wrap(true);
        detail.set_selectable(true);
        system.append(&detail);
    }

    if let Some(error) = tray_error {
        if !error.trim().is_empty() {
            let detail = gtk::Label::new(Some(&format!("Tray unavailable: {error}")));
            detail.add_css_class("caption");
            detail.add_css_class("dim-label");
            detail.set_xalign(0.0);
            detail.set_wrap(true);
            system.append(&detail);
        }
    }

    let cli_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    cli_row.set_halign(gtk::Align::Start);
    let cli = icon_text_button(
        if state.cli_installed {
            "Reinstall CLI"
        } else {
            "Install CLI"
        },
        "utilities-terminal-symbolic",
    );
    cli.set_sensitive(state.cli_install_supported);
    {
        let app = app.clone();
        cli.connect_clicked(move |_| {
            dispatch(&app, NativeAppAction::InstallCli);
        });
    }
    cli_row.append(&cli);
    let check_update_button = icon_text_button("Check Updates", "view-refresh-symbolic");
    check_update_button.set_sensitive(!update.checking && !update.downloading);
    {
        let app = app.clone();
        check_update_button.connect_clicked(move |_| check_updates(&app, true));
    }
    cli_row.append(&check_update_button);
    let download_update_button =
        icon_text_button(update.download_action_label(), "folder-download-symbolic");
    download_update_button.set_sensitive(
        update.available && update.asset.is_some() && !update.checking && !update.downloading,
    );
    {
        let app = app.clone();
        download_update_button.connect_clicked(move |_| show_or_download_update(&app));
    }
    cli_row.append(&download_update_button);
    let uninstall_cli = icon_text_button("Uninstall CLI", "edit-delete-symbolic");
    uninstall_cli.set_sensitive(state.cli_install_supported && state.cli_installed);
    {
        let app = app.clone();
        uninstall_cli.connect_clicked(move |_| {
            dispatch(&app, NativeAppAction::UninstallCli);
        });
    }
    cli_row.append(&uninstall_cli);
    system.append(&cli_row);

    if state.service_supported {
        let service_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        service_row.set_halign(gtk::Align::Start);
        let service = icon_text_button(
            if service_update_recommended(state) {
                "Update Service"
            } else if state.service_installed {
                "Reinstall Service"
            } else {
                "Install Service"
            },
            "system-run-symbolic",
        );
        {
            let app = app.clone();
            service.connect_clicked(move |_| {
                dispatch(&app, NativeAppAction::InstallSystemService);
            });
        }
        service_row.append(&service);

        if state.service_enablement_supported && state.service_installed {
            let enable = icon_text_button(
                if state.service_disabled {
                    "Enable Service"
                } else {
                    "Disable Service"
                },
                if state.service_disabled {
                    "object-select-symbolic"
                } else {
                    "media-playback-stop-symbolic"
                },
            );
            {
                let app = app.clone();
                let disabled = state.service_disabled;
                enable.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        if disabled {
                            NativeAppAction::EnableSystemService
                        } else {
                            NativeAppAction::DisableSystemService
                        },
                    );
                });
            }
            service_row.append(&enable);
        }

        let uninstall = icon_text_button("Uninstall Service", "edit-delete-symbolic");
        uninstall.set_sensitive(state.service_installed);
        {
            let app = app.clone();
            uninstall.connect_clicked(move |_| {
                dispatch(&app, NativeAppAction::UninstallSystemService);
            });
        }
        service_row.append(&uninstall);
        system.append(&service_row);
    }
    page.append(&system);

    let advanced = gtk::Expander::new(Some("Advanced"));
    advanced.set_expanded(app.borrow().diagnostics_expanded);
    {
        let app = app.clone();
        advanced.connect_expanded_notify(move |advanced| {
            app.borrow_mut().diagnostics_expanded = advanced.is_expanded();
        });
    }
    let advanced_body = gtk::Box::new(gtk::Orientation::Vertical, 14);
    advanced_body.set_margin_top(10);
    build_diagnostics(app, &advanced_body, state);
    advanced.set_child(Some(&advanced_body));
    page.append(&advanced);
}

fn build_diagnostics(app: &AppRef, parent: &gtk::Box, state: &NativeAppState) {
    let diagnostics = card();
    section_header(&diagnostics, "Diagnostics", "dialog-information-symbolic");

    let metrics = gtk::FlowBox::new();
    metrics.set_selection_mode(gtk::SelectionMode::None);
    metrics.set_column_spacing(10);
    metrics.set_row_spacing(10);
    metrics.set_max_children_per_line(3);
    metrics.append(&live_metric(app, "Peers", |state| format!(
        "{}/{}", state.connected_peer_count, state.expected_peer_count
    )));
    metrics.append(&live_metric(app, "Roster FIPS", |state| format!(
        "{}/{} direct", state.fips_connected_peer_count, state.fips_roster_peer_count
    )));
    metrics.append(&live_metric(app, "Other FIPS", |state| state.non_fips_roster_peer_count.to_string()));
    metrics.append(&live_metric(app, "Interface", |state| non_empty_or(&state.network.default_interface, "unknown")));
    metrics.append(&live_metric(app, "IPv4", |state| non_empty_or(&state.network.primary_ipv4, "-")));
    metrics.append(&live_metric(app, "IPv6", |state| non_empty_or(&state.network.primary_ipv6, "-")));
    metrics.append(&live_metric(app, "Gateway", |state| first_non_empty(&[
        state.network.gateway_ipv4.as_str(), state.network.gateway_ipv6.as_str()
    ]).unwrap_or_else(|| "unknown".to_string())));
    metrics.append(&live_metric(app, "Mapping", |state| non_empty_or(&state.port_mapping.active_protocol, "none")));
    metrics.append(&live_metric(app, "External", |state| non_empty_or(&state.port_mapping.external_endpoint, "stun/direct")));
    diagnostics.append(&metrics);

    detail_row(&diagnostics, "This device", &state.own_npub);
    detail_row(&diagnostics, "Tunnel IP", &clean_ip(&state.tunnel_ip));
    detail_row(&diagnostics, "Endpoint", &state.endpoint);
    detail_row(&diagnostics, "Config", &state.config_path);
    live_detail_row(app, &diagnostics, "MagicDNS", |state| state.magic_dns_status.clone());
    live_detail_row(app, &diagnostics, "Runtime", |state| state.runtime_status_detail.clone());

    if state.health.is_empty() {
        empty_row(&diagnostics, "No health warnings");
    } else {
        for issue in &state.health {
            let title = if issue.severity.trim().is_empty() {
                issue.summary.clone()
            } else {
                format!("{}  {}", issue.severity, issue.summary)
            };
            row_label(
                &diagnostics,
                &title,
                &issue.detail,
                "dialog-warning-symbolic",
            );
        }
    }
    parent.append(&diagnostics);
}

fn setting_entry(app: &AppRef, parent: &gtk::Box, title: &str, key: &'static str) {
    setting_entry_enabled(app, parent, title, key, true);
}

fn setting_entry_enabled(
    app: &AppRef,
    parent: &gtk::Box,
    title: &str,
    key: &'static str,
    enabled: bool,
) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_width_chars(13);
    row.append(&label);

    let current = {
        let model = app.borrow();
        match key {
            "node_name" => model.drafts.node_name.clone(),
            "endpoint" => model.drafts.endpoint.clone(),
            "tunnel_ip" => model.drafts.tunnel_ip.clone(),
            "listen_port" => model.drafts.listen_port.clone(),
            "fips_host_inbound_tcp_ports" => model.drafts.fips_host_inbound_tcp_ports.clone(),
            _ => String::new(),
        }
    };
    let placeholder = if key == "fips_host_inbound_tcp_ports" {
        ""
    } else {
        title
    };
    let input = entry(placeholder, &current);
    input.set_sensitive(enabled);
    {
        let app = app.clone();
        input.connect_changed(move |entry| {
            let value = entry.text().to_string();
            let mut model = app.borrow_mut();
            match key {
                "node_name" => model.drafts.node_name = value,
                "endpoint" => model.drafts.endpoint = value,
                "tunnel_ip" => model.drafts.tunnel_ip = value,
                "listen_port" => model.drafts.listen_port = value,
                "fips_host_inbound_tcp_ports" => model.drafts.fips_host_inbound_tcp_ports = value,
                _ => {}
            }
        });
    }
    {
        let app = app.clone();
        input.connect_activate(move |_| save_device_settings(&app));
    }
    row.append(&input);
    parent.append(&row);
}

fn add_network_from_draft(app: &AppRef) {
    let name = app.borrow().drafts.new_network_name.trim().to_string();
    if name.is_empty() {
        return;
    }
    app.borrow_mut().drafts.new_network_name.clear();
    dispatch(app, NativeAppAction::AddNetwork { name });
}

fn save_active_network_name(app: &AppRef, network_id: &str) {
    let name = app.borrow().drafts.network_name.trim().to_string();
    if name.is_empty() {
        return;
    }
    dispatch(
        app,
        NativeAppAction::RenameNetwork {
            network_id: network_id.to_string(),
            name,
        },
    );
}

fn save_active_network_mesh_id(app: &AppRef, network_id: &str) {
    let mesh_id = normalize_network_id_input(&app.borrow().drafts.mesh_id);
    if mesh_id.is_empty() {
        return;
    }
    dispatch(
        app,
        NativeAppAction::SetNetworkMeshId {
            network_id: network_id.to_string(),
            mesh_id,
        },
    );
}

fn save_device_settings(app: &AppRef) {
    let drafts = app.borrow().drafts.clone();
    let listen_port = drafts.listen_port.trim().parse::<u16>().ok();
    dispatch(
        app,
        NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                node_name: Some(drafts.node_name),
                endpoint: Some(drafts.endpoint),
                tunnel_ip: Some(drafts.tunnel_ip),
                listen_port,
                fips_host_inbound_tcp_ports: Some(drafts.fips_host_inbound_tcp_ports),
                ..SettingsPatch::default()
            },
        },
    );
}

fn add_relay_setting(app: &AppRef) {
    let (state, input) = {
        let model = app.borrow();
        (model.state.clone(), model.drafts.relay_input.clone())
    };
    let Some(url) = normalize_relay_url(&input) else {
        return;
    };
    let (mut enabled, mut disabled) = relay_lists(&state);
    disabled.retain(|relay| relay != &url);
    if !enabled.contains(&url) {
        enabled.push(url);
    }
    app.borrow_mut().drafts.relay_input.clear();
    save_relay_lists(app, enabled, disabled);
}

fn set_relay_enabled(app: &AppRef, url: &str, enabled_value: bool) {
    let state = app.borrow().state.clone();
    let Some(url) = normalize_relay_url(url) else {
        return;
    };
    let (mut enabled, mut disabled) = relay_lists(&state);
    enabled.retain(|relay| relay != &url);
    disabled.retain(|relay| relay != &url);
    if enabled_value {
        enabled.push(url);
    } else {
        disabled.push(url);
    }
    save_relay_lists(app, enabled, disabled);
}

fn delete_relay_setting(app: &AppRef, url: &str) {
    let state = app.borrow().state.clone();
    let Some(url) = normalize_relay_url(url) else {
        return;
    };
    let (mut enabled, mut disabled) = relay_lists(&state);
    enabled.retain(|relay| relay != &url);
    disabled.retain(|relay| relay != &url);
    save_relay_lists(app, enabled, disabled);
}

fn relay_lists(state: &NativeAppState) -> (Vec<String>, Vec<String>) {
    let enabled = unique_relays(
        state
            .relays
            .iter()
            .filter(|relay| relay.enabled)
            .filter_map(|relay| normalize_relay_url(&relay.url))
            .collect(),
    );
    let mut disabled = unique_relays(
        state
            .relays
            .iter()
            .filter(|relay| !relay.enabled)
            .filter_map(|relay| normalize_relay_url(&relay.url))
            .collect(),
    );
    disabled.retain(|relay| !enabled.contains(relay));
    (enabled, disabled)
}

fn save_relay_lists(app: &AppRef, enabled: Vec<String>, disabled: Vec<String>) {
    let enabled = unique_relays(enabled);
    let mut disabled = unique_relays(disabled);
    disabled.retain(|relay| !enabled.contains(relay));
    dispatch(
        app,
        NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                relays: Some(enabled),
                disabled_relays: Some(disabled),
                ..SettingsPatch::default()
            },
        },
    );
}

fn normalize_relay_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        Some(trimmed.to_string())
    } else {
        Some(format!("wss://{trimmed}"))
    }
}

fn unique_relays(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn save_wireguard_exit_settings(app: &AppRef) {
    let config = app.borrow().drafts.wireguard_exit_config.clone();
    dispatch(
        app,
        NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_config: Some(config),
                ..SettingsPatch::default()
            },
        },
    );
}

fn import_wireguard_exit_config_file(app: &AppRef, button: &gtk::Button) {
    let parent = button
        .root()
        .and_then(|root| root.downcast::<gtk::Window>().ok());
    let dialog = gtk::FileDialog::builder()
        .title("Import WireGuard config")
        .accept_label("Import")
        .build();
    let app = app.clone();
    dialog.open(parent.as_ref(), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else {
            return;
        };
        let Some(path) = file.path() else {
            set_notice(&app, "Could not open config file");
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(config) if config.trim().is_empty() => {
                set_notice(&app, "Selected WireGuard config is empty.");
            }
            Ok(config) => {
                app.borrow_mut().drafts.wireguard_exit_config = config.clone();
                dispatch(
                    &app,
                    NativeAppAction::UpdateSettings {
                        patch: SettingsPatch {
                            wireguard_exit_config: Some(config),
                            ..SettingsPatch::default()
                        },
                    },
                );
            }
            Err(error) => set_notice(&app, format!("Could not read config file: {error}")),
        }
    });
}
