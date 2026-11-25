fn build_devices_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    build_network_hero(app, page, state);

    let Some(network) = active_network(state).cloned() else {
        build_network_setup(app, page, state);
        return;
    };
    let selected_key = app.borrow().selected_device_pubkey.clone();

    let devices = card();
    devices.set_size_request(330, -1);
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    header.set_valign(gtk::Align::Center);
    let heading = gtk::Box::new(gtk::Orientation::Vertical, 2);
    heading.set_hexpand(true);
    let title = gtk::Label::new(Some("Devices"));
    title.add_css_class("title-3");
    title.set_xalign(0.0);
    heading.append(&title);
    let availability = gtk::Label::new(Some(&device_availability_text(&network)));
    {
        let network_id = network.id.clone();
        bind_live_label(app, &availability, move |state| {
            state
                .networks
                .iter()
                .find(|network| network.id == network_id)
                .map(device_availability_text)
                .unwrap_or_default()
        });
    }
    availability.add_css_class("caption");
    availability.add_css_class("dim-label");
    availability.set_xalign(0.0);
    heading.append(&availability);
    header.append(&heading);
    if network.local_is_admin {
        let add = icon_text_button("Link device", "list-add-symbolic");
        add.set_widget_name("nvpn-link-device");
        add.update_property(&[gtk::accessible::Property::Label(
            "nvpn-manual-join-admin-open",
        )]);
        let app = app.clone();
        add.connect_clicked(move |_| set_page(&app, Page::Share));
        header.append(&add);
    }
    devices.append(&header);

    let participants = sorted_participants(&network, state);

    if participants.is_empty() {
        empty_row(&devices, "No devices yet");
    } else {
        let search = (participants.len() > SEARCH_VISIBILITY_THRESHOLD).then(|| {
            let search = gtk::SearchEntry::new();
            search.set_placeholder_text(Some("Search"));
            search.set_widget_name("nvpn-device-search");
            devices.append(&search);
            search
        });
        let mut rows = Vec::new();
        for participant in participants {
            let selected = selected_key
                .as_deref()
                .map(|key| participant_key(&participant) == key)
                .unwrap_or(false);
            device_row(app, &devices, &participant, state, selected);
            let haystack = format!(
                "{} {} {}",
                device_name(&participant),
                participant.npub,
                clean_ip(&participant.tunnel_ip)
            )
            .to_lowercase();
            rows.push((devices.last_child().unwrap(), haystack));
        }
        if let Some(search) = search {
            // Filter in place: a re-render would drop focus while typing.
            let filter = move |query: &str| {
                let query = query.trim().to_lowercase();
                for (row, haystack) in &rows {
                    row.set_visible(query.is_empty() || haystack.contains(&query));
                }
            };
            let query = app.borrow().drafts.device_search.clone();
            search.set_text(&query);
            filter(&query);
            let app = app.clone();
            search.connect_search_changed(move |search| {
                let query = search.text().to_string();
                filter(&query);
                app.borrow_mut().drafts.device_search = query;
            });
        }
    }

    let split = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    split.set_hexpand(true);
    split.set_valign(gtk::Align::Start);
    split.append(&devices);

    let detail = device_detail_card(app, &network, state, selected_key.as_deref());
    detail.set_hexpand(true);
    split.append(&detail);
    page.append(&split);
    build_file_transfers(app, page, state);

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
        move |request| confirm_join_request(&app_for_result, request),
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
        copy.set_tooltip_text(Some("Copy Device ID"));
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
    if !participant_is_self {
        let send = icon_text_button("Send files", "document-send-symbolic");
        send.set_sensitive(state.vpn_active && network.enabled && participant.reachable);
        send.set_tooltip_text(Some(if state.vpn_active { "Send files to this device" } else { "Connect VPN to send files" }));
        let app = app.clone();
        let npub = participant.npub.clone();
        let send_app = app.clone();
        send.connect_clicked(move |button| choose_transfer_files(&send_app, button, npub.clone()));
        detail.append(&send);
        if state.vpn_active && network.enabled && participant.reachable {
            let drop = gtk::DropTarget::new(gtk::gdk::FileList::static_type(), gtk::gdk::DragAction::COPY);
            let app = app.clone();
            let npub = participant.npub.clone();
            drop.connect_drop(move |_, value, _, _| {
                let Ok(files) = value.get::<gtk::gdk::FileList>() else { return false; };
                let paths: Option<Vec<_>> = files.files().iter().map(|file| file.path()).collect();
                if let Some(paths) = paths { stage_transfer_files(&app, npub.clone(), paths); true } else { false }
            });
            detail.add_controller(drop);
        }
    }
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
    for (title, value) in [
        ("MagicDNS", device_magic_dns_name(&participant, state)),
        ("VPN IP", clean_ip(&participant.tunnel_ip)),
        ("Device ID", participant.npub.clone()),
    ] {
        copy_detail_row(&addresses, title, &value);
    }
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
            "Latency age",
            format_duration_ms(participant.fips_srtt_age_ms),
        ),
        (
            "Control seen",
            non_empty_or(&participant.last_fips_control_seen_text, "-"),
        ),
        (
            "Data seen",
            non_empty_or(&participant.last_fips_data_seen_text, "-"),
        ),
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
                "Latency age" => format_duration_ms(participant.fips_srtt_age_ms),
                "Control seen" => non_empty_or(&participant.last_fips_control_seen_text, "-"),
                "Data seen" => non_empty_or(&participant.last_fips_data_seen_text, "-"),
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
    if network.is_some() {
        text.append(&badges);
    }
    top.append(&text);

    hero.append(&top);

    let identity = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    identity.set_valign(gtk::Align::Center);
    identity.set_margin_top(8);
    if network.is_some() && !clean_ip(&state.tunnel_ip).is_empty() {
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
    if identity.first_child().is_some() {
        hero.append(&identity);
    }

    page.append(&hero);
}
