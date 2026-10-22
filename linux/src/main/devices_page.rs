fn build_devices_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    build_network_hero(app, page, state);

    if !state.error.trim().is_empty() {
        let card = card();
        row_label(&card, "Status", &state.error, "dialog-warning-symbolic");
        page.append(&card);
    }

    let Some(network) = active_network(state).cloned() else {
        build_network_setup(app, page, state);
        return;
    };
    let selected_key = app.borrow().selected_device_pubkey.clone();

    let devices = card();
    devices.set_size_request(330, -1);
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    header.set_valign(gtk::Align::Center);
    let title = gtk::Label::new(Some("Devices"));
    title.add_css_class("title-3");
    title.set_xalign(0.0);
    title.set_hexpand(true);
    header.append(&title);
    let add = gtk::Button::from_icon_name("list-add-symbolic");
    add.set_tooltip_text(Some("Add device"));
    add.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-admin-open",
    )]);
    {
        let app = app.clone();
        add.connect_clicked(move |_| set_page(&app, Page::Share));
    }
    header.append(&add);
    devices.append(&header);

    let participants = sorted_participants(&network, state);

    if participants.is_empty() {
        empty_row(&devices, "No devices yet");
    } else {
        for participant in participants {
            let selected = selected_key
                .as_deref()
                .map(|key| participant_key(&participant) == key)
                .unwrap_or(false);
            device_row(app, &devices, &network, &participant, state, selected);
        }
    }

    if network.local_is_admin {
        let expander = gtk::Expander::new(Some("Manage devices"));
        let body = gtk::Box::new(gtk::Orientation::Vertical, 10);
        body.set_margin_top(10);

        let input_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let npub = entry("npub", &app.borrow().drafts.participant_npub);
        {
            let app = app.clone();
            npub.connect_changed(move |entry| {
                app.borrow_mut().drafts.participant_npub = entry.text().to_string();
            });
        }
        let alias = entry("Name", &app.borrow().drafts.participant_alias);
        alias.set_width_chars(16);
        {
            let app = app.clone();
            alias.connect_changed(move |entry| {
                app.borrow_mut().drafts.participant_alias = entry.text().to_string();
            });
        }
        let add = icon_text_button("Add", "list-add-symbolic");
        {
            let app = app.clone();
            let network_id = network.id.clone();
            add.connect_clicked(move |_| {
                let (npub, alias) = {
                    let model = app.borrow();
                    (
                        model.drafts.participant_npub.trim().to_string(),
                        model.drafts.participant_alias.trim().to_string(),
                    )
                };
                if npub.is_empty() {
                    return;
                }
                {
                    let mut model = app.borrow_mut();
                    model.drafts.participant_npub.clear();
                    model.drafts.participant_alias.clear();
                }
                dispatch(
                    &app,
                    NativeAppAction::AddParticipant {
                        network_id: network_id.clone(),
                        npub,
                        alias: (!alias.is_empty()).then_some(alias),
                    },
                );
            });
        }
        input_row.append(&npub);
        input_row.append(&alias);
        input_row.append(&add);
        body.append(&input_row);

        let scan_request = icon_text_button("Scan approval request", "camera-photo-symbolic");
        {
            let app = app.clone();
            scan_request.connect_clicked(move |button| scan_join_request_qr(&app, button));
        }
        body.append(&scan_request);

        for participant in &network.participants {
            let participant_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            participant_row.set_valign(gtk::Align::Center);

            let name = gtk::Label::new(Some(&device_name(participant)));
            name.set_width_chars(16);
            name.set_xalign(0.0);
            name.set_ellipsize(gtk::pango::EllipsizeMode::End);
            participant_row.append(&name);

            let alias = entry("Name", &participant.magic_dns_alias);
            alias.set_width_chars(18);
            participant_row.append(&alias);

            let save = gtk::Button::with_label("Save");
            {
                let app = app.clone();
                let npub = participant.npub.clone();
                let alias = alias.clone();
                save.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::SetParticipantAlias {
                            npub: npub.clone(),
                            alias: alias.text().trim().to_string(),
                        },
                    );
                });
            }
            participant_row.append(&save);

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
                participant_row.append(&admin);

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
                participant_row.append(&remove);
            }

            body.append(&participant_row);
        }

        expander.set_child(Some(&body));
        devices.append(&expander);
    }

    let split = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    split.set_hexpand(true);
    split.set_valign(gtk::Align::Start);
    split.append(&devices);

    let detail = device_detail_card(app, &network, state, selected_key.as_deref());
    detail.set_hexpand(true);
    split.append(&detail);
    page.append(&split);

    append_join_requests(app, page, &network);
}

fn scan_join_request_qr(app: &AppRef, button: &gtk::Button) {
    let parent = button
        .root()
        .and_then(|root| root.downcast::<gtk::Window>().ok());
    let app_for_result = app.clone();
    let app_for_error = app.clone();
    qr_scan::open_scanner(
        parent.as_ref(),
        move |request| {
            dispatch_with_completion(
                &app_for_result,
                NativeAppAction::ImportJoinRequest { request },
                |app, state| {
                    if state.error.trim().is_empty() {
                        set_page(app, Page::Devices);
                    }
                },
            );
        },
        move |error| set_notice(&app_for_error, error),
    );
}

fn append_join_requests(app: &AppRef, parent: &gtk::Box, network: &NativeNetworkState) {
    if network.inbound_join_requests.is_empty() {
        return;
    }

    let requests = card();
    section_header(&requests, "Join Requests", "contact-new-symbolic");
    for request in &network.inbound_join_requests {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        row.set_valign(gtk::Align::Center);

        let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let name = if request.requester_node_name.trim().is_empty() {
            "New device".to_string()
        } else {
            request.requester_node_name.clone()
        };
        let title = gtk::Label::new(Some(&name));
        title.set_xalign(0.0);
        title.add_css_class("heading");
        text.append(&title);
        let sub = gtk::Label::new(Some(&format!(
            "{}  {}",
            short_text(&request.requester_npub, 18),
            request.requested_at_text
        )));
        sub.add_css_class("caption");
        sub.add_css_class("dim-label");
        sub.set_xalign(0.0);
        text.append(&sub);
        text.set_hexpand(true);
        row.append(&text);

        let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
        copy.set_tooltip_text(Some("Copy npub"));
        {
            let npub = request.requester_npub.clone();
            copy.connect_clicked(move |_| copy_text(&npub));
        }
        row.append(&copy);

        let reject = icon_text_button("Reject", "");
        reject.add_css_class("destructive-action");
        {
            let app = app.clone();
            let network_id = network.id.clone();
            let requester_npub = request.requester_npub.clone();
            reject.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::RejectJoinRequest {
                        network_id: network_id.clone(),
                        requester_npub: requester_npub.clone(),
                    },
                );
            });
        }
        row.append(&reject);

        let accept = icon_text_button("Accept", "");
        accept.add_css_class("suggested-action");
        {
            let app = app.clone();
            let network_id = network.id.clone();
            let requester_npub = request.requester_npub.clone();
            accept.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::AcceptJoinRequest {
                        network_id: network_id.clone(),
                        requester_npub: requester_npub.clone(),
                    },
                );
            });
        }
        row.append(&accept);
        requests.append(&row);
    }
    parent.append(&requests);
}

fn device_detail_card(
    app: &AppRef,
    network: &NativeNetworkState,
    state: &NativeAppState,
    selected_key: Option<&str>,
) -> gtk::Box {
    let detail = card();

    let Some(participant) = selected_participant(network, state, selected_key) else {
        let title = gtk::Label::new(Some("Devices"));
        title.add_css_class("title-2");
        title.set_xalign(0.0);
        detail.append(&title);
        empty_row(&detail, "No devices yet");
        return detail;
    };

    let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    header.set_valign(gtk::Align::Start);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 8);
    text.set_hexpand(true);
    let name = gtk::Label::new(Some(&device_name(&participant)));
    name.add_css_class("title-2");
    name.set_xalign(0.0);
    name.set_wrap(true);
    text.append(&name);

    let badges = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    if is_self(&participant, state) {
        badges.append(&badge("This device", "ok"));
    }
    if participant.is_admin {
        badges.append(&badge("Admin", "muted"));
    }
    if participant.offers_exit_node {
        badges.append(&badge(
            exit_node_badge_text(&participant, state),
            exit_node_badge_style(&participant, state),
        ));
    }
    match fips_path_kind(&participant) {
        FipsPathKind::Direct => badges.append(&badge("direct connection", "ok")),
        FipsPathKind::Routed => badges.append(&badge("via mesh", "muted")),
        _ => {}
    }
    text.append(&badges);
    header.append(&text);

    let status = gtk::Box::new(gtk::Orientation::Horizontal, 7);
    status.set_valign(gtk::Align::Start);
    let dot = gtk::Box::new(gtk::Orientation::Vertical, 0);
    dot.add_css_class(if participant.reachable {
        "nvpn-peer-online"
    } else {
        "nvpn-peer-offline"
    });
    status.append(&dot);
    let status_label = gtk::Label::new(Some(&device_status_text(&participant)));
    status_label.add_css_class("dim-label");
    status.append(&status_label);
    header.append(&status);
    detail.append(&header);

    let participant_is_self = is_self(&participant, state);
    if network.local_is_admin {
        let manage = gtk::Box::new(gtk::Orientation::Vertical, 10);
        section_header(&manage, "Manage Device", "changes-allow-symbolic");

        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.set_valign(gtk::Align::Center);
        let label = gtk::Label::new(Some("Name"));
        label.add_css_class("dim-label");
        row.append(&label);

        let alias = entry("Name", &participant.magic_dns_alias);
        alias.set_hexpand(true);
        row.append(&alias);

        let save = gtk::Button::with_label("Save");
        {
            let app = app.clone();
            let npub = participant.npub.clone();
            let alias = alias.clone();
            save.connect_clicked(move |_| {
                dispatch(
                    &app,
                    NativeAppAction::SetParticipantAlias {
                        npub: npub.clone(),
                        alias: alias.text().trim().to_string(),
                    },
                );
            });
        }
        row.append(&save);

        if !participant_is_self {
            let hint_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            hint_row.set_valign(gtk::Align::Center);
            let hint_label = gtk::Label::new(Some("Hints"));
            hint_label.add_css_class("dim-label");
            hint_row.append(&hint_label);

            let hints = entry(
                "host or host:port",
                &participant.fips_endpoint_hints.join(", "),
            );
            hints.set_hexpand(true);
            hint_row.append(&hints);

            let save_hints = gtk::Button::with_label("Save");
            {
                let app = app.clone();
                let npub = participant.npub.clone();
                let hints = hints.clone();
                save_hints.connect_clicked(move |_| {
                    dispatch(
                        &app,
                        NativeAppAction::SetParticipantEndpointHints {
                            npub: npub.clone(),
                            endpoint_hints: parse_endpoint_hints(&hints.text()),
                        },
                    );
                });
            }
            hint_row.append(&save_hints);
            manage.append(&hint_row);

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
                device_name(&participant),
            );
            row.append(&remove);
        }
        manage.append(&row);
        detail.append(&manage);
    }

    let addresses = gtk::Box::new(gtk::Orientation::Vertical, 8);
    section_header(&addresses, "Addresses", "");
    detail_row(
        &addresses,
        "MagicDNS",
        &device_magic_dns_name(&participant, state),
    );
    detail_row(&addresses, "VPN IP", &clean_ip(&participant.tunnel_ip));
    detail_row(&addresses, "Device ID", &participant.npub);
    let copy = icon_text_button("Copy device ID", "edit-copy-symbolic");
    {
        let npub = participant.npub.clone();
        copy.connect_clicked(move |_| copy_text(&npub));
    }
    addresses.append(&copy);
    detail.append(&addresses);

    let connectivity = gtk::Box::new(gtk::Orientation::Vertical, 8);
    section_header(&connectivity, "Connectivity", "");
    let metrics = gtk::FlowBox::new();
    metrics.set_selection_mode(gtk::SelectionMode::None);
    metrics.set_max_children_per_line(3);
    metrics.set_min_children_per_line(2);
    for (title, value) in [
        ("Role", device_role_text(&participant, state)),
        ("State", device_status_text(&participant)),
        ("FIPS path", fips_path_text(&participant)),
        (
            "Address hints",
            if participant.fips_endpoint_hints.is_empty() {
                "-".to_string()
            } else {
                participant.fips_endpoint_hints.join(", ")
            },
        ),
        ("Last seen", non_empty_or(&participant.last_seen_text, "-")),
        ("Sent", format_bytes(participant.tx_bytes)),
        ("Received", format_bytes(participant.rx_bytes)),
    ] {
        let item = metric(title, &value);
        let network_id = network.id.clone();
        let key = participant_key(&participant);
        let label = item.last_child().unwrap().downcast::<gtk::Label>().unwrap();
        bind_live_label(app, &label, move |state| {
            let participant = state.networks.iter()
                .find(|network| network.id == network_id)
                .and_then(|network| network.participants.iter().find(|peer| participant_key(peer) == key));
            participant.map(|participant| match title {
                "Role" => device_role_text(participant, state),
                "State" => device_status_text(participant),
                "FIPS path" => fips_path_text(participant),
                "Address hints" => non_empty_or(&participant.fips_endpoint_hints.join(", "), "-"),
                "Last seen" => non_empty_or(&participant.last_seen_text, "-"),
                "Sent" => format_bytes(participant.tx_bytes),
                "Received" => format_bytes(participant.rx_bytes),
                _ => unreachable!(),
            }).unwrap_or_default()
        });
        metrics.insert(&item, -1);
    }
    connectivity.append(&metrics);
    if !participant.status_text.trim().is_empty() {
        let status = gtk::Label::new(Some(&participant.status_text));
        status.add_css_class("caption");
        status.add_css_class("dim-label");
        status.set_xalign(0.0);
        status.set_wrap(true);
        status.set_selectable(true);
        connectivity.append(&status);
    }
    detail.append(&connectivity);

    detail
}

fn build_network_hero(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let hero = card();
    hero.add_css_class("nvpn-hero");

    let top = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    top.set_valign(gtk::Align::Center);

    let status = gtk::Box::new(gtk::Orientation::Vertical, 0);
    status.add_css_class(if state.exit_node_blocked {
        "nvpn-status-blocked"
    } else if state.mesh_ready {
        "nvpn-status-ready"
    } else if state.vpn_active {
        "nvpn-status-active"
    } else {
        "nvpn-status-off"
    });
    status.set_valign(gtk::Align::Center);
    top.append(&status);

    let text = gtk::Box::new(gtk::Orientation::Vertical, 6);
    text.set_hexpand(true);
    let network = active_network(state);
    let network_name = network
        .map(display_network_name)
        .unwrap_or_else(|| "Nostr VPN".to_string());
    let title_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    title_row.set_valign(gtk::Align::Center);
    let title = gtk::Label::new(Some(&network_name));
    title.add_css_class("title-1");
    title.set_xalign(0.0);
    title.set_wrap(true);
    title_row.append(&title);
    if network.is_some_and(|network| network.local_is_admin) {
        title_row.append(&badge("Admin", "muted"));
    }
    text.append(&title_row);

    let subtitle = gtk::Label::new(Some(&hero_subtitle(state)));
    bind_live_label(app, &subtitle, hero_subtitle);
    subtitle.add_css_class("dim-label");
    subtitle.set_xalign(0.0);
    subtitle.set_wrap(true);
    text.append(&subtitle);

    let badges = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    badges.append(&badge(
        if state.vpn_active {
            "VPN on"
        } else {
            "VPN off"
        },
        if state.vpn_active { "ok" } else { "muted" },
    ));
    badges.append(&badge(
        if state.daemon_running {
            "Daemon"
        } else {
            "Daemon off"
        },
        if state.daemon_running { "ok" } else { "muted" },
    ));
    badges.append(&badge(
        if state.mesh_ready {
            "Mesh ready"
        } else {
            "Mesh pending"
        },
        if state.mesh_ready { "ok" } else { "muted" },
    ));
    if service_update_recommended(state) {
        badges.append(&badge("Update", "warn"));
    }
    if state.exit_node_blocked {
        badges.append(&badge("Internet blocked", "bad"));
    } else if state.exit_node_active && !state.exit_node_status_text.trim().is_empty() {
        badges.append(&badge(&state.exit_node_status_text, "ok"));
    }
    text.append(&badges);
    top.append(&text);

    hero.append(&top);

    let identity = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    identity.set_valign(gtk::Align::Center);
    identity.set_margin_top(8);
    let own = gtk::Label::new(Some(&format!(
        "This device  {}",
        non_empty_or(&short_text(&state.own_npub, 18), "-")
    )));
    own.add_css_class("caption");
    own.add_css_class("dim-label");
    own.set_xalign(0.0);
    own.set_selectable(true);
    own.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    own.set_hexpand(true);
    identity.append(&own);
    let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy.set_tooltip_text(Some("Copy npub"));
    copy.set_sensitive(!state.own_npub.is_empty());
    {
        let npub = state.own_npub.clone();
        copy.connect_clicked(move |_| copy_text(&npub));
    }
    identity.append(&copy);
    if !clean_ip(&state.tunnel_ip).is_empty() {
        identity.append(&badge(&clean_ip(&state.tunnel_ip), "muted"));
    }
    if !state.exit_node_status_text.trim().is_empty() {
        identity.append(&badge(
            &state.exit_node_status_text,
            if state.exit_node_blocked {
                "bad"
            } else if state.exit_node_active {
                "ok"
            } else {
                "warn"
            },
        ));
    }
    hero.append(&identity);

    page.append(&hero);
}
