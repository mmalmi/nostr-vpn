fn build_network_setup(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    match app.borrow().network_setup_mode {
        None => append_setup_choices(app, page),
        Some(NetworkSetupMode::Create) => {
            append_setup_back(app, page);
            append_create_network_card(app, page);
        }
        Some(NetworkSetupMode::Join) => {
            append_setup_back(app, page);
            append_join_network_card(app, page, state, active_network(state));
        }
    }
}

fn append_setup_choices(app: &AppRef, page: &gtk::Box) {
    let choices = card();
    let create = icon_text_button("Create Network", "list-add-symbolic");
    create.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-create-network-choice",
    )]);
    {
        let app = app.clone();
        create.connect_clicked(move |_| {
            app.borrow_mut().network_setup_mode = Some(NetworkSetupMode::Create);
            render(&app);
        });
    }
    choices.append(&create);
    let join = icon_text_button("Join Network", "go-down-symbolic");
    join.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-choose-join",
    )]);
    {
        let app = app.clone();
        join.connect_clicked(move |_| {
            app.borrow_mut().network_setup_mode = Some(NetworkSetupMode::Join);
            render(&app);
        });
    }
    choices.append(&join);
    page.append(&choices);
}

fn append_setup_back(app: &AppRef, page: &gtk::Box) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let back = icon_text_button("Back", "go-previous-symbolic");
    {
        let app = app.clone();
        back.connect_clicked(move |_| {
            app.borrow_mut().network_setup_mode = None;
            render(&app);
        });
    }
    row.append(&back);
    page.append(&row);
}

fn append_create_network_card(app: &AppRef, page: &gtk::Box) {
    let create_card = card();
    section_header(&create_card, "Create Network", "list-add-symbolic");
    let create_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let name = entry("Network name", &app.borrow().drafts.new_network_name);
    name.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-create-network-name",
    )]);
    {
        let app = app.clone();
        name.connect_changed(move |entry| {
            app.borrow_mut().drafts.new_network_name = entry.text().to_string();
        });
    }
    let create = icon_text_button("Create", "list-add-symbolic");
    create.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-create-network-submit",
    )]);
    {
        let app = app.clone();
        create.connect_clicked(move |_| {
            let name = {
                let mut model = app.borrow_mut();
                let name = model.drafts.new_network_name.trim().to_string();
                model.drafts.new_network_name.clear();
                name
            };
            let name = non_empty_or(&name, "Private network");
            dispatch_with_completion(&app, NativeAppAction::AddNetwork { name }, |app, state| {
                if state.error.trim().is_empty() {
                    app.borrow_mut().network_setup_mode = None;
                    set_page(app, Page::Devices);
                }
            });
        });
    }
    create_row.append(&name);
    create_row.append(&create);
    create_card.append(&create_row);
    page.append(&create_card);
}

fn append_join_network_card(
    app: &AppRef,
    page: &gtk::Box,
    state: &NativeAppState,
    request_network: Option<&NativeNetworkState>,
) {
    let request_network = request_network.or_else(|| {
        state.networks.iter().find(|network| {
            network.outbound_join_request.is_some()
                || !network.join_request_qr_code_or_link.is_empty()
        })
    });
    let join_request = if state.join_request_qr_code_or_link.is_empty() {
        request_network
            .map(|network| network.join_request_qr_code_or_link.as_str())
            .unwrap_or("")
    } else {
        &state.join_request_qr_code_or_link
    };

    let join_card = card();
    section_header(&join_card, "Join Network", "go-down-symbolic");
    if join_request.is_empty() {
        append_join_request_unavailable(app, &join_card, state);
    } else {
        let help = gtk::Label::new(Some("Show this QR to a network admin."));
        help.add_css_class("dim-label");
        join_card.append(&help);
        join_card.append(&qr::build(join_request, 220));
        let copy = icon_text_button("Copy Request", "edit-copy-symbolic");
        copy.set_halign(gtk::Align::Center);
        {
            let request = join_request.to_string();
            copy.connect_clicked(move |_| copy_text(&request));
        }
        join_card.append(&copy);
    }

    let manual = gtk::Expander::new(Some("Manual join"));
    manual.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-expander",
    )]);
    manual.set_expanded(app.borrow().manual_join_expanded);
    {
        let app = app.clone();
        manual.connect_expanded_notify(move |manual| {
            app.borrow_mut().manual_join_expanded = manual.is_expanded();
        });
    }
    let manual_body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let help = gtk::Label::new(Some(
        "Give the admin your Device ID. Enter their Device ID and Network ID here; they must add your Device ID too.",
    ));
    help.set_wrap(true);
    help.set_xalign(0.0);
    help.add_css_class("caption");
    help.add_css_class("dim-label");
    manual_body.append(&help);
    let own_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let own = gtk::Label::new(Some(&state.own_npub));
    own.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-joiner-device-id-value",
    )]);
    own.set_hexpand(true);
    own.set_xalign(0.0);
    own.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    own_row.append(&own);
    let copy_own = icon_text_button("Copy Device ID", "edit-copy-symbolic");
    {
        let value = state.own_npub.clone();
        copy_own.connect_clicked(move |_| copy_text(&value));
    }
    own_row.append(&copy_own);
    manual_body.append(&own_row);
    let admin = entry("Admin Device ID", &app.borrow().drafts.manual_admin_npub);
    admin.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-admin-id",
    )]);
    {
        let app = app.clone();
        admin.connect_changed(move |entry| {
            app.borrow_mut().drafts.manual_admin_npub = entry.text().to_string();
        });
    }
    manual_body.append(&admin);
    let admin_error = invalid_device_id_label();
    manual_body.append(&admin_error);
    let mesh = entry("Network ID", &app.borrow().drafts.manual_mesh_id);
    mesh.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-network-id",
    )]);
    {
        let app = app.clone();
        mesh.connect_changed(move |entry| {
            app.borrow_mut().drafts.manual_mesh_id = entry.text().to_string();
        });
    }
    manual_body.append(&mesh);
    let add_manual = icon_text_button("Add manually", "list-add-symbolic");
    add_manual.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-submit",
    )]);
    {
        let app = app.clone();
        let admin = admin.clone();
        let mesh = mesh.clone();
        add_manual.connect_clicked(move |_| {
            let admin_npub = admin.text().trim().to_string();
            let mesh_network_id = normalize_network_id_input(mesh.text().as_str());
            if !is_valid_device_id(&admin_npub) || mesh_network_id.is_empty() {
                set_notice(&app, "Enter a valid admin Device ID and Network ID".to_string());
                return;
            }
            dispatch_with_completion(
                &app,
                NativeAppAction::ManualAddNetwork {
                    admin_npub,
                    mesh_network_id,
                },
                |app, state| {
                    if state.error.trim().is_empty() {
                        {
                            let mut model = app.borrow_mut();
                            model.drafts.manual_admin_npub.clear();
                            model.drafts.manual_mesh_id.clear();
                            model.manual_join_expanded = false;
                        }
                        set_page(app, Page::Devices);
                    }
                },
            );
        });
    }
    manual_body.append(&add_manual);
    {
        let validate = {
            let (admin, mesh, add) = (admin.clone(), mesh.clone(), add_manual.clone());
            move || {
                let id = admin.text().trim().to_string();
                admin_error.set_visible(!id.is_empty() && !is_valid_device_id(&id));
                add.set_sensitive(
                    is_valid_device_id(&id)
                        && !normalize_network_id_input(mesh.text().as_str()).is_empty(),
                );
            }
        };
        validate();
        let validate = Rc::new(validate);
        for input in [&admin, &mesh] {
            let validate = validate.clone();
            input.connect_changed(move |_| validate());
        }
    }
    manual.set_child(Some(&manual_body));
    join_card.append(&manual);

    page.append(&join_card);
}

/// The desktop join request lives in the background service, so the QR
/// appears only while it runs. Say so and offer the one step that starts it.
fn append_join_request_unavailable(app: &AppRef, parent: &gtk::Box, state: &NativeAppState) {
    let install = ("Install Service", NativeAppAction::InstallSystemService);
    let enable = ("Enable Service", NativeAppAction::EnableSystemService);
    let (text, action) = if state.daemon_running {
        ("Preparing your join QR…", None)
    } else if state.service_supported && !state.service_installed {
        (
            "Install the background service to show your join QR.",
            Some(install),
        )
    } else if state.service_installed && state.service_disabled {
        (
            "Enable the background service to show your join QR.",
            Some(enable),
        )
    } else {
        ("Waiting for the background service…", None)
    };
    let label = gtk::Label::new(Some(text));
    label.set_wrap(true);
    label.set_xalign(0.0);
    label.add_css_class("dim-label");
    parent.append(&label);
    if let Some((title, action)) = action {
        let button = icon_text_button(title, "system-run-symbolic");
        button.set_halign(gtk::Align::Start);
        button.add_css_class("suggested-action");
        let app = app.clone();
        button.connect_clicked(move |_| dispatch(&app, action.clone()));
        parent.append(&button);
    }
}

fn build_share_page(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let Some(network) = active_network(state).cloned() else {
        return;
    };

    if network.local_is_admin {
        page_title(page, "Link Device", "contact-new-symbolic");
        append_link_device_card(app, page, &network);
        append_join_requests(app, page, &network);
        return;
    }

    page_title(page, "Join Network", "go-down-symbolic");
    append_join_network_card(app, page, state, None);
}

fn append_link_device_card(app: &AppRef, page: &gtk::Box, network: &NativeNetworkState) {
    let request_card = card();
    section_header(&request_card, "Add Join Request", "camera-photo-symbolic");
    let help = gtk::Label::new(Some(
        "Scan the joining device's request QR, or paste its join request. Valid links open confirmation automatically.",
    ));
    help.set_wrap(true);
    help.set_xalign(0.0);
    help.add_css_class("caption");
    help.add_css_class("dim-label");
    request_card.append(&help);
    let request_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let scan = icon_text_button("Scan QR", "camera-photo-symbolic");
    {
        let app = app.clone();
        scan.connect_clicked(move |button| scan_join_request_qr(&app, button));
    }
    request_row.append(&scan);
    let request = entry("nvpn://join-request/…", &app.borrow().drafts.join_request);
    {
        let app = app.clone();
        request.connect_changed(move |entry| {
            let text = entry.text().to_string();
            app.borrow_mut().drafts.join_request = text.clone();
            if looks_like_join_request(&text) {
                confirm_join_request(&app, text.trim().to_string());
            }
        });
    }
    request_row.append(&request);
    request_card.append(&request_row);
    page.append(&request_card);

    let link = card();
    section_header(&link, "For Manual Join", "contact-new-symbolic");
    let manual_help = gtk::Label::new(Some(
        "Share your Device ID and Network ID, then add the joining Device ID below.",
    ));
    manual_help.set_wrap(true);
    manual_help.set_xalign(0.0);
    manual_help.add_css_class("caption");
    manual_help.add_css_class("dim-label");
    link.append(&manual_help);
    for (label, selector, raw, shown) in [
        (
            "Admin Device ID",
            "nvpn-manual-join-admin-device-id-value",
            app.borrow().state.own_npub.clone(),
            app.borrow().state.own_npub.clone(),
        ),
        (
            "Network ID",
            "nvpn-manual-join-admin-network-id-value",
            network.network_id.clone(),
            display_network_id(&network.network_id),
        ),
    ] {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let value = gtk::Label::new(Some(&format!("{label}: {shown}")));
        value.update_property(&[gtk::accessible::Property::Label(selector)]);
        value.set_hexpand(true);
        value.set_xalign(0.0);
        value.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        row.append(&value);
        let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
        copy.add_css_class("flat");
        copy.set_tooltip_text(Some(&format!("Copy {label}")));
        copy.connect_clicked(move |_| copy_text(&raw));
        row.append(&copy);
        link.append(&row);
    }

    let manual = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let npub = entry("Joining Device ID", &app.borrow().drafts.participant_npub);
    npub.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-admin-device-id",
    )]);
    {
        let app = app.clone();
        npub.connect_changed(move |entry| {
            app.borrow_mut().drafts.participant_npub = entry.text().to_string();
        });
    }
    let alias = entry("Name", &app.borrow().drafts.participant_alias);
    alias.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-admin-device-name",
    )]);
    alias.set_width_chars(16);
    {
        let app = app.clone();
        alias.connect_changed(move |entry| {
            app.borrow_mut().drafts.participant_alias = entry.text().to_string();
        });
    }
    let add = icon_text_button("Add by Device ID", "list-add-symbolic");
    add.update_property(&[gtk::accessible::Property::Label(
        "nvpn-manual-join-admin-submit",
    )]);
    {
        let app = app.clone();
        let network_id = network.id.clone();
        let npub = npub.clone();
        let alias = alias.clone();
        add.connect_clicked(move |_| {
            add_participant(
                &app,
                network_id.clone(),
                npub.text().trim().to_string(),
                alias.text().trim().to_string(),
            );
        });
    }
    manual.append(&npub);
    manual.append(&alias);
    manual.append(&add);
    link.append(&manual);
    let npub_error = invalid_device_id_label();
    link.append(&npub_error);
    let validate = move |npub: &gtk::Entry| {
        let id = npub.text().trim().to_string();
        npub_error.set_visible(!id.is_empty() && !is_valid_device_id(&id));
        add.set_sensitive(is_valid_device_id(&id));
    };
    validate(&npub);
    npub.connect_changed(validate);

    page.append(&link);
}

fn invalid_device_id_label() -> gtk::Label {
    let label = gtk::Label::new(Some("Not a valid device ID"));
    label.add_css_class("caption");
    label.add_css_class("error");
    label.set_xalign(0.0);
    label.set_visible(false);
    label
}

fn looks_like_join_request(value: &str) -> bool {
    value.trim().starts_with("nvpn://join-request/")
}

/// Ask before adding a device from a pasted, scanned or opened request.
fn confirm_join_request(app: &AppRef, request: String) {
    let network_name = active_network(&app.borrow().state)
        .filter(|network| network.local_is_admin)
        .map(display_network_name);
    let Some(network_name) = network_name else {
        // The core explains why a non-admin or networkless device cannot add it.
        import_join_request(app, NativeAppAction::ImportJoinRequest { request });
        return;
    };
    let dialog = adw::AlertDialog::new(
        Some("Add device?"),
        Some(&format!(
            "Add the device from this join request to {network_name}?"
        )),
    );
    dialog.add_responses(&[("cancel", "Cancel"), ("add", "Add")]);
    dialog.set_close_response("cancel");
    dialog.set_default_response(Some("add"));
    dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);
    {
        let app = app.clone();
        dialog.connect_response(Some("add"), move |_, _| {
            import_join_request(
                &app,
                NativeAppAction::ImportJoinRequest {
                    request: request.clone(),
                },
            );
        });
    }
    let window = app.borrow().window.clone();
    dialog.present(Some(&window));
}

fn import_join_request(app: &AppRef, action: NativeAppAction) {
    dispatch_with_completion(app, action, |app, state| {
        if state.error.trim().is_empty() {
            {
                let mut model = app.borrow_mut();
                model.drafts.join_request.clear();
                model.notice.clear();
            }
            set_page(app, Page::Devices);
        }
    });
}

fn add_participant(app: &AppRef, network_id: String, npub: String, alias: String) {
    if npub.is_empty() {
        return;
    }
    dispatch_with_completion(
        app,
        NativeAppAction::AddParticipant {
            network_id: network_id.clone(),
            npub: npub.clone(),
            alias: (!alias.is_empty()).then_some(alias),
        },
        move |app, state| {
            if manual_participant_added(state, &network_id, &npub) {
                {
                    let mut model = app.borrow_mut();
                    model.drafts.participant_npub.clear();
                    model.drafts.participant_alias.clear();
                }
                set_page(app, Page::Devices);
            }
        },
    );
}

fn manual_participant_added(state: &NativeAppState, network_id: &str, npub: &str) -> bool {
    state.networks.iter().any(|network| {
        network.id == network_id
            && network
                .participants
                .iter()
                .any(|participant| participant.npub == npub)
    })
}
