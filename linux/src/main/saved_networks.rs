fn build_wireguard_settings_card(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let card = card();
    section_header(&card, "WireGuard Upstream", "");
    let note = gtk::Label::new(Some(
        "Paste a WireGuard config from an upstream VPN provider such as Mullvad or Proton VPN.",
    ));
    note.add_css_class("muted");
    note.set_wrap(true);
    note.set_xalign(0.0);
    card.append(&note);
    switch_row(
        app,
        &card,
        "Use WireGuard upstream",
        state.wireguard_exit_enabled,
        |enabled| NativeAppAction::UpdateSettings {
            patch: SettingsPatch {
                wireguard_exit_enabled: Some(enabled),
                ..SettingsPatch::default()
            },
        },
    );
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_min_content_height(220);
    scroller.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    scroller.set_hexpand(true);

    let config = gtk::TextView::new();
    config.set_monospace(true);
    config.set_wrap_mode(gtk::WrapMode::None);
    config
        .buffer()
        .set_text(&app.borrow().drafts.wireguard_exit_config);
    {
        let app = app.clone();
        config.buffer().connect_changed(move |buffer| {
            let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), true);
            app.borrow_mut().drafts.wireguard_exit_config = text.to_string();
        });
    }
    scroller.set_child(Some(&config));
    card.append(&scroller);

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_halign(gtk::Align::Start);

    let import_wg = icon_text_button("Import File", "document-open-symbolic");
    {
        let app = app.clone();
        import_wg.connect_clicked(move |button| import_wireguard_exit_config_file(&app, button));
    }
    actions.append(&import_wg);

    let save_wg = icon_text_button("Save WireGuard", "");
    {
        let app = app.clone();
        save_wg.connect_clicked(move |_| save_wireguard_exit_settings(&app));
    }
    actions.append(&save_wg);
    card.append(&actions);
    page.append(&card);
}

fn build_exit_dns_settings_card(app: &AppRef, page: &gtk::Box) {
    const MODES: [&str; 3] = ["automatic", "encrypted", "through_exit"];
    const MODE_LABELS: [&str; 3] = [
        "Automatic (recommended)",
        "Encrypted DNS",
        "DNS through exit",
    ];
    const PROVIDERS: [&str; 3] = ["cloudflare", "quad9", "custom"];
    const PROVIDER_LABELS: [&str; 3] = ["Cloudflare", "Quad9", "Custom DoH"];

    let card = card();
    section_header(&card, "Exit DNS", "");
    let note = gtk::Label::new(Some(
        "MagicDNS stays local. Public DNS follows this policy while an internet exit is active.",
    ));
    note.add_css_class("muted");
    note.set_wrap(true);
    note.set_xalign(0.0);
    card.append(&note);

    let drafts = app.borrow().drafts.clone();
    let selectors = gtk::Builder::new();
    let mode = gtk::DropDown::from_strings(&MODE_LABELS);
    mode.set_selected(
        MODES
            .iter()
            .position(|value| *value == drafts.exit_dns_mode)
            .unwrap_or_default() as u32,
    );
    selectors.expose_object("nvpn-exit-dns-mode", &mode);
    mode.update_property(&[gtk::accessible::Property::Label("DNS mode")]);
    card.append(&mode);

    let encrypted = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let provider = gtk::DropDown::from_strings(&PROVIDER_LABELS);
    provider.set_selected(
        PROVIDERS
            .iter()
            .position(|value| *value == drafts.exit_dns_doh_provider)
            .unwrap_or_default() as u32,
    );
    selectors.expose_object("nvpn-exit-dns-provider", &provider);
    provider.update_property(&[gtk::accessible::Property::Label("DNS provider")]);
    encrypted.append(&provider);
    let custom = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let custom_url = entry("HTTPS DoH URL", &drafts.exit_dns_custom_doh_url);
    selectors.expose_object("nvpn-exit-dns-custom-url", &custom_url);
    custom_url.update_property(&[gtk::accessible::Property::Label(
        "Custom DNS-over-HTTPS URL",
    )]);
    let bootstrap_ips = entry(
        "Bootstrap IPs, comma separated",
        &drafts.exit_dns_custom_doh_bootstrap_ips,
    );
    selectors.expose_object("nvpn-exit-dns-bootstrap-ips", &bootstrap_ips);
    bootstrap_ips.update_property(&[gtk::accessible::Property::Label(
        "DNS bootstrap IP addresses",
    )]);
    custom.append(&custom_url);
    custom.append(&bootstrap_ips);
    encrypted.append(&custom);
    card.append(&encrypted);

    let through = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let through_servers = entry(
        "DNS server IPs, comma separated",
        &drafts.exit_dns_through_exit_servers,
    );
    selectors.expose_object("nvpn-exit-dns-through-servers", &through_servers);
    through_servers.update_property(&[gtk::accessible::Property::Label(
        "DNS servers through exit",
    )]);
    through.append(&through_servers);
    let through_note = gtk::Label::new(Some(
        "These DNS packets are sent only through the selected exit.",
    ));
    through_note.add_css_class("muted");
    through_note.set_wrap(true);
    through_note.set_xalign(0.0);
    through.append(&through_note);
    card.append(&through);

    encrypted.set_visible(drafts.exit_dns_mode == "encrypted");
    through.set_visible(drafts.exit_dns_mode == "through_exit");
    custom.set_visible(
        drafts.exit_dns_mode == "encrypted" && drafts.exit_dns_doh_provider == "custom",
    );

    {
        let app = app.clone();
        let encrypted = encrypted.clone();
        let through = through.clone();
        mode.connect_selected_notify(move |dropdown| {
            let Some(value) = MODES.get(dropdown.selected() as usize) else {
                return;
            };
            app.borrow_mut().drafts.exit_dns_mode = (*value).to_string();
            encrypted.set_visible(*value == "encrypted");
            through.set_visible(*value == "through_exit");
        });
    }
    {
        let app = app.clone();
        let custom = custom.clone();
        provider.connect_selected_notify(move |dropdown| {
            let Some(value) = PROVIDERS.get(dropdown.selected() as usize) else {
                return;
            };
            app.borrow_mut().drafts.exit_dns_doh_provider = (*value).to_string();
            custom.set_visible(*value == "custom");
        });
    }
    {
        let app = app.clone();
        custom_url.connect_changed(move |entry| {
            app.borrow_mut().drafts.exit_dns_custom_doh_url = entry.text().to_string();
        });
    }
    {
        let app = app.clone();
        bootstrap_ips.connect_changed(move |entry| {
            app.borrow_mut().drafts.exit_dns_custom_doh_bootstrap_ips = entry.text().to_string();
        });
    }
    {
        let app = app.clone();
        through_servers.connect_changed(move |entry| {
            app.borrow_mut().drafts.exit_dns_through_exit_servers = entry.text().to_string();
        });
    }

    let save = icon_text_button("Save Exit DNS", "");
    selectors.expose_object("nvpn-exit-dns-save", &save);
    save.update_property(&[gtk::accessible::Property::Label(
        "Save Exit DNS",
    )]);
    {
        let app = app.clone();
        save.connect_clicked(move |_| {
            let drafts = app.borrow().drafts.clone();
            dispatch(
                &app,
                NativeAppAction::UpdateSettings {
                    patch: SettingsPatch {
                        exit_dns_mode: Some(drafts.exit_dns_mode),
                        exit_dns_doh_provider: Some(drafts.exit_dns_doh_provider),
                        exit_dns_custom_doh_url: Some(drafts.exit_dns_custom_doh_url),
                        exit_dns_custom_doh_bootstrap_ips: Some(
                            drafts.exit_dns_custom_doh_bootstrap_ips,
                        ),
                        exit_dns_through_exit_servers: Some(
                            drafts.exit_dns_through_exit_servers,
                        ),
                        ..SettingsPatch::default()
                    },
                },
            );
        });
    }
    card.append(&save);
    page.append(&card);
}

fn saved_network_row(
    app: &AppRef,
    parent: &gtk::Box,
    network: &NativeNetworkState,
    state: &NativeAppState,
) {
    let expander = gtk::Expander::new(None::<&str>);
    expander.add_css_class("nvpn-route-choice");

    let header = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    header.set_valign(gtk::Align::Center);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 3);
    text.set_hexpand(true);
    let name = gtk::Label::new(Some(&display_network_name(network)));
    name.add_css_class("heading");
    name.set_xalign(0.0);
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.append(&name);
    let subtitle = gtk::Label::new(Some(&format!(
        "{} of {} connected  {}",
        network.online_count,
        network.expected_count,
        short_text(&network.network_id, 12)
    )));
    {
        let network_id = network.id.clone();
        bind_live_label(app, &subtitle, move |state| {
            state.networks.iter().find(|network| network.id == network_id)
                .map(|network| format!("{} of {} connected  {}",
                    network.online_count, network.expected_count, short_text(&network.network_id, 12)))
                .unwrap_or_default()
        });
    }
    subtitle.add_css_class("caption");
    subtitle.add_css_class("dim-label");
    subtitle.set_xalign(0.0);
    text.append(&subtitle);
    header.append(&text);

    let activate = icon_text_button("Activate", "go-next-symbolic");
    {
        let app = app.clone();
        let network_id = network.id.clone();
        activate.connect_clicked(move |_| {
            dispatch(
                &app,
                NativeAppAction::SetNetworkEnabled {
                    network_id: network_id.clone(),
                    enabled: true,
                },
            );
        });
    }
    header.append(&activate);

    let remove = gtk::Button::from_icon_name("edit-delete-symbolic");
    remove.set_tooltip_text(Some("Remove network"));
    remove.add_css_class("destructive-action");
    connect_remove_network_confirmation(
        &remove,
        app,
        network.id.clone(),
        display_network_name(network),
    );
    header.append(&remove);
    expander.set_label_widget(Some(&header));

    let body = gtk::Box::new(gtk::Orientation::Vertical, 10);
    body.set_margin_top(10);

    let rename = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    rename.set_valign(gtk::Align::Center);
    let label = gtk::Label::new(Some("Name"));
    label.set_width_chars(10);
    label.set_xalign(0.0);
    label.add_css_class("dim-label");
    rename.append(&label);
    let input = entry("Network name", &display_network_name(network));
    input.set_sensitive(network.local_is_admin);
    rename.append(&input);
    let save = gtk::Button::with_label("Save");
    save.set_sensitive(network.local_is_admin);
    {
        let app = app.clone();
        let network_id = network.id.clone();
        let input = input.clone();
        save.connect_clicked(move |_| save_saved_network_name(&app, &network_id, &input));
    }
    {
        let app = app.clone();
        let network_id = network.id.clone();
        input.connect_activate(move |input| save_saved_network_name(&app, &network_id, input));
    }
    rename.append(&save);
    body.append(&rename);

    let mesh = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    mesh.set_valign(gtk::Align::Center);
    let label = gtk::Label::new(Some("Network ID"));
    label.set_width_chars(10);
    label.set_xalign(0.0);
    label.add_css_class("dim-label");
    mesh.append(&label);
    let mesh_id = gtk::Label::new(Some(&display_network_id(&network.network_id)));
    mesh_id.set_xalign(0.0);
    mesh_id.set_selectable(true);
    mesh_id.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    mesh_id.set_hexpand(true);
    mesh.append(&mesh_id);
    let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy.set_tooltip_text(Some("Copy network ID"));
    {
        let network_id = network.network_id.clone();
        copy.connect_clicked(move |_| copy_text(&network_id));
    }
    mesh.append(&copy);
    body.append(&mesh);

    switch_row_enabled(
        app,
        &body,
        "Allow join requests",
        network.join_requests_enabled,
        network.local_is_admin,
        {
            let network_id = network.id.clone();
            move |enabled| NativeAppAction::SetNetworkJoinRequestsEnabled {
                network_id: network_id.clone(),
                enabled,
            }
        },
    );

    section_header(&body, "Devices", "");
    let participants = sorted_participants(network, state);
    if participants.is_empty() {
        empty_row(&body, "No devices in this network");
    } else {
        for participant in participants {
            saved_network_participant_row(app, &body, network, &participant, state);
        }
    }

    expander.set_child(Some(&body));
    parent.append(&expander);
}

fn save_saved_network_name(app: &AppRef, network_id: &str, input: &gtk::Entry) {
    let name = input.text().trim().to_string();
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

fn saved_network_participant_row(
    app: &AppRef,
    parent: &gtk::Box,
    network: &NativeNetworkState,
    participant: &NativeParticipantState,
    state: &NativeAppState,
) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    row.set_valign(gtk::Align::Center);

    let dot = gtk::Box::new(gtk::Orientation::Vertical, 0);
    dot.add_css_class(if participant.reachable {
        "nvpn-peer-online"
    } else {
        "nvpn-peer-offline"
    });
    row.append(&dot);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 3);
    text.set_hexpand(true);
    let name = gtk::Label::new(Some(&device_name(participant)));
    name.add_css_class("heading");
    name.set_xalign(0.0);
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.append(&name);
    let subtitle = gtk::Label::new(Some(&device_subtitle(participant)));
    subtitle.add_css_class("caption");
    subtitle.add_css_class("dim-label");
    subtitle.set_xalign(0.0);
    subtitle.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    text.append(&subtitle);
    row.append(&text);

    row.append(&badge(
        &device_status_text(participant),
        if participant.reachable { "ok" } else { "muted" },
    ));
    if participant.is_admin {
        row.append(&badge("Admin", "muted"));
    }
    if participant.offers_exit_node {
        row.append(&badge(
            exit_node_badge_text(participant, state),
            exit_node_badge_style(participant, state),
        ));
    }

    let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy.set_tooltip_text(Some("Copy npub"));
    {
        let npub = participant.npub.clone();
        copy.connect_clicked(move |_| copy_text(&npub));
    }
    row.append(&copy);

    if network.local_is_admin {
        let alias = entry("Name", &participant.magic_dns_alias);
        alias.set_width_chars(14);
        alias.set_hexpand(false);
        row.append(&alias);

        let save_alias = gtk::Button::from_icon_name("object-select-symbolic");
        save_alias.set_tooltip_text(Some("Save name"));
        {
            let app = app.clone();
            let npub = participant.npub.clone();
            let alias = alias.clone();
            save_alias.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::SetParticipantAlias {
                        npub: npub.clone(),
                        alias: alias.text().trim().to_string(),
                    },
                );
            });
        }
        {
            let app = app.clone();
            let npub = participant.npub.clone();
            alias.connect_activate(move |alias| {
                dispatch(
                    &app,
                    NativeAppAction::SetParticipantAlias {
                        npub: npub.clone(),
                        alias: alias.text().trim().to_string(),
                    },
                );
            });
        }
        row.append(&save_alias);

        if !is_self(participant, state) {
            let admin = gtk::Button::from_icon_name(if participant.is_admin {
                "starred-symbolic"
            } else {
                "non-starred-symbolic"
            });
            admin.set_tooltip_text(Some(if participant.is_admin {
                "Remove admin"
            } else {
                "Make admin"
            }));
            {
                let app = app.clone();
                let network_id = network.id.clone();
                let npub = participant.npub.clone();
                let is_admin = participant.is_admin;
                admin.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        if is_admin {
                            NativeAppAction::RemoveAdmin {
                                network_id: network_id.clone(),
                                npub: npub.clone(),
                            }
                        } else {
                            NativeAppAction::AddAdmin {
                                network_id: network_id.clone(),
                                npub: npub.clone(),
                            }
                        },
                    );
                });
            }
            row.append(&admin);

            let remove = gtk::Button::from_icon_name("edit-delete-symbolic");
            remove.set_tooltip_text(Some("Remove device"));
            remove.add_css_class("destructive-action");
            connect_remove_participant_confirmation(
                &remove,
                app,
                network.id.clone(),
                participant.npub.clone(),
                device_name(participant),
            );
            row.append(&remove);
        }
    }

    parent.append(&row);
}

fn device_row(
    app: &AppRef,
    parent: &gtk::Box,
    network: &NativeNetworkState,
    participant: &NativeParticipantState,
    state: &NativeAppState,
    selected: bool,
) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    if let Some(label) = accepted_roster_accessibility_label(participant) {
        row.update_property(&[gtk::accessible::Property::Label(&label)]);
    }
    row.add_css_class("nvpn-device-row");
    if selected {
        row.add_css_class("selected");
    }
    row.set_valign(gtk::Align::Center);
    let click = gtk::GestureClick::new();
    {
        let app = app.clone();
        let key = participant_key(participant);
        click.connect_released(move |_, _, _, _| {
            app.borrow_mut().selected_device_pubkey = Some(key.clone());
            render(&app);
        });
    }
    row.add_controller(click);

    let dot = gtk::Box::new(gtk::Orientation::Vertical, 0);
    dot.add_css_class(if participant.reachable {
        "nvpn-peer-online"
    } else {
        "nvpn-peer-offline"
    });
    row.append(&dot);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 4);
    text.set_hexpand(true);

    let name_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let name = gtk::Label::new(Some(&device_name(participant)));
    name.add_css_class("heading");
    name.set_xalign(0.0);
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    name_row.append(&name);
    if participant.is_admin {
        name_row.append(&badge("Admin", "muted"));
    }
    if participant.offers_exit_node {
        name_row.append(&badge(
            exit_node_badge_text(participant, state),
            exit_node_badge_style(participant, state),
        ));
    }
    text.append(&name_row);

    let subtitle = gtk::Label::new(Some(&device_subtitle(participant)));
    subtitle.add_css_class("caption");
    subtitle.add_css_class("dim-label");
    subtitle.set_xalign(0.0);
    subtitle.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    text.append(&subtitle);
    row.append(&text);

    row.append(&badge(
        &device_status_text(participant),
        if participant.reachable { "ok" } else { "muted" },
    ));
    if matches!(fips_path_kind(participant), FipsPathKind::Routed) {
        row.append(&badge("via mesh", "muted"));
    }

    let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy.set_tooltip_text(Some("Copy npub"));
    {
        let npub = participant.npub.clone();
        copy.connect_clicked(move |_| copy_text(&npub));
    }
    row.append(&copy);

    if network.local_is_admin && !is_self(participant, state) {
        let admin = gtk::Button::from_icon_name(if participant.is_admin {
            "starred-symbolic"
        } else {
            "non-starred-symbolic"
        });
        admin.set_tooltip_text(Some(if participant.is_admin {
            "Remove admin"
        } else {
            "Make admin"
        }));
        {
            let app = app.clone();
            let network_id = network.id.clone();
            let npub = participant.npub.clone();
            let is_admin = participant.is_admin;
            admin.connect_clicked(move |_| {
                dispatch(
                    &app,
                    if is_admin {
                        NativeAppAction::RemoveAdmin {
                            network_id: network_id.clone(),
                            npub: npub.clone(),
                        }
                    } else {
                        NativeAppAction::AddAdmin {
                            network_id: network_id.clone(),
                            npub: npub.clone(),
                        }
                    },
                );
            });
        }
        row.append(&admin);

        let remove = gtk::Button::from_icon_name("edit-delete-symbolic");
        remove.set_tooltip_text(Some("Remove device"));
        remove.add_css_class("destructive-action");
        connect_remove_participant_confirmation(
            &remove,
            app,
            network.id.clone(),
            participant.npub.clone(),
            device_name(participant),
        );
        row.append(&remove);
    }

    parent.append(&row);
}
