fn refresh_header(app: &AppRef, state: &NativeAppState) {
    let (label, dot, switch) = {
        let model = app.borrow();
        (
            model.header_status_label.clone(),
            model.header_status_dot.clone(),
            model.header_vpn_switch.clone(),
        )
    };

    let model = app.borrow();
    let ready = model.core_ready;
    let busy = !model.pending_actions.is_empty();
    drop(model);
    let status = tray::vpn_status_text(state);
    label.set_text(if !ready {
        if state.error.is_empty() {
            "Starting…"
        } else {
            "Unavailable"
        }
    } else if busy {
        "Working…"
    } else {
        &status
    });

    let dot_visible =
        state.exit_node_blocked || state.exit_node_active || state.vpn_active || state.vpn_enabled;
    dot.set_visible(ready && dot_visible);
    for class in ["ok", "warn", "bad"] {
        dot.remove_css_class(class);
    }
    if state.exit_node_blocked {
        dot.add_css_class("bad");
    } else if state.exit_node_active || state.vpn_active {
        dot.add_css_class("ok");
    } else if state.vpn_enabled {
        dot.add_css_class("warn");
    }

    switch.set_sensitive(
        ready && !busy && state.vpn_control_supported && active_network(state).is_some(),
    );
    if switch.is_active() != state.vpn_enabled {
        switch.set_active(state.vpn_enabled);
    }
}

fn render_background_change(app: &AppRef) {
    let editing = gtk::prelude::GtkWindowExt::focus(&app.borrow().window)
        .is_some_and(|focus| {
            [
                gtk::Entry::static_type(),
                gtk::TextView::static_type(),
                gtk::DropDown::static_type(),
            ]
            .into_iter()
            .any(|kind| focus.type_().is_a(kind) || focus.ancestor(kind).is_some())
        });
    // GTK focuses the dropdown's button or popup row, not the DropDown itself.
    // Replacing it during polling closes the popup and discards keyboard input.
    if editing {
        app.borrow_mut().render_pending = true;
    } else {
        render(app);
    }
}

fn render(app: &AppRef) {
    app.borrow_mut().render_pending = false;
    app.borrow_mut().live_updates.clear();
    sync_selected_device(app);

    let (sidebar, update_bar, content, state, page, rendered_page) = {
        let model = app.borrow();
        (
            model.sidebar.clone(),
            model.update_bar.clone(),
            model.content.clone(),
            model.state.clone(),
            model.page,
            model.rendered_page,
        )
    };
    let current_scroll_offset = current_content_scroll_offset(&content);
    let scroll_offset = {
        let mut model = app.borrow_mut();
        model
            .scroll_offsets
            .set(rendered_page, current_scroll_offset);
        model.rendered_page = page;
        model.scroll_offsets.get(page)
    };

    refresh_header(app, &state);
    // Unset focus while the old controls are still alive. GTK can otherwise
    // reassign focus to a selectable label after removing the old page, with
    // its previous-focus pointer already pointing at a destroyed widget.
    let window = app.borrow().window.clone();
    if let Some(focus) = gtk::prelude::GtkWindowExt::focus(&window) {
        if focus.is_ancestor(&sidebar) || focus.is_ancestor(&update_bar) || focus.is_ancestor(&content) {
            gtk::prelude::GtkWindowExt::set_focus(&window, gtk::Widget::NONE);
        }
    }
    clear_box(&sidebar);
    clear_box(&update_bar);
    if !app.borrow().core_ready {
        clear_box(&content);
        let loading = gtk::Box::new(gtk::Orientation::Vertical, 12);
        loading.set_halign(gtk::Align::Center);
        loading.set_valign(gtk::Align::Center);
        loading.set_hexpand(true);
        loading.set_vexpand(true);
        let message = if state.error.is_empty() {
            let spinner = gtk::Spinner::new();
            spinner.start();
            loading.append(&spinner);
            "Starting Nostr VPN…"
        } else {
            &state.error
        };
        let label = gtk::Label::new(Some(message));
        label.set_wrap(true);
        loading.append(&label);
        content.append(&loading);
        return;
    }
    build_sidebar(app, &sidebar, &state, page);
    build_update_stripe(app, &update_bar, &state);

    // Keep the live scroll adjustment and layout across background refreshes.
    // Recreating the scroller starts it at zero before its new child is sized.
    let existing_scroll = (page == rendered_page)
        .then(|| content.first_child())
        .flatten()
        .and_then(|child| child.downcast::<gtk::ScrolledWindow>().ok());
    let scroll = existing_scroll.unwrap_or_else(|| {
        clear_box(&content);
        let scroll = gtk::ScrolledWindow::new();
        content.append(&scroll);
        scroll
    });
    scroll.set_hscrollbar_policy(gtk::PolicyType::Never);
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);

    let page_box = gtk::Box::new(gtk::Orientation::Vertical, 20);
    page_box.set_margin_top(28);
    page_box.set_margin_bottom(32);
    page_box.set_margin_start(28);
    page_box.set_margin_end(28);
    page_box.set_hexpand(true);
    page_box.set_valign(gtk::Align::Start);
    page_box.set_size_request(560, -1);
    page_box.set_sensitive(app.borrow().pending_actions.is_empty());

    match page {
        Page::Devices => build_devices_page(app, &page_box, &state),
        Page::Share => build_share_page(app, &page_box, &state),
        Page::ExitNodes => build_exit_nodes_page(app, &page_box, &state),
        Page::PaidRoutes => build_paid_routes_page(app, &page_box, &state),
        Page::SellInternet => build_paid_exit_seller_page(app, &page_box, &state),
        Page::Wallet => build_paid_route_wallet_page(app, &page_box, &state),
        Page::Settings => build_settings_page(app, &page_box, &state),
    }

    scroll.set_child(Some(&page_box));
    restore_scroll_offset(&scroll, scroll_offset);
}

fn build_update_stripe(app: &AppRef, parent: &gtk::Box, state: &NativeAppState) {
    let update = app.borrow().update.clone();
    if !update.available {
        return;
    }

    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.add_css_class("nvpn-update-stripe");
    row.set_valign(gtk::Align::Center);

    let title = gtk::Label::new(Some(&update_stripe_text(
        &update.version,
        &state.app_version,
    )));
    title.set_xalign(0.0);
    title.set_hexpand(true);
    title.set_ellipsize(gtk::pango::EllipsizeMode::End);
    row.append(&title);

    let auto_download = gtk::CheckButton::with_label("Download automatically");
    auto_download.set_active(update.auto_download);
    {
        let app = app.clone();
        auto_download.connect_toggled(move |button| {
            let enabled = button.is_active();
            {
                let mut model = app.borrow_mut();
                model.update.auto_download = enabled;
                save_update_preferences(&mut model.update);
            }
            let should_download = app.borrow().update.should_auto_download();
            if should_download {
                download_update(&app);
            } else {
                render(&app);
            }
        });
    }
    row.append(&auto_download);

    let install = icon_text_button(update.download_action_label(), "folder-download-symbolic");
    install.set_sensitive(
        update.available && update.asset.is_some() && !update.checking && !update.downloading,
    );
    {
        let app = app.clone();
        install.connect_clicked(move |_| show_or_download_update(&app));
    }
    row.append(&install);

    parent.append(&row);
}

fn update_stripe_text(version: &str, current: &str) -> String {
    let current = current.trim();
    if current.is_empty() {
        format!("Update available: {version}")
    } else {
        format!("Update available: {version} (you're on {current})")
    }
}

fn build_sidebar(app: &AppRef, sidebar: &gtk::Box, state: &NativeAppState, page: Page) {
    let has_incoming_join_requests = incoming_join_request_count(state) > 0;
    let mut pages = vec![
        (Page::Devices, "Devices".to_string(), ""),
        (Page::ExitNodes, "Internet".to_string(), ""),
    ];
    if paid_internet_available(state) {
        let wallet_title = if state
            .paid_route_market
            .wallet
            .navigation_balance_text
            .is_empty()
        {
            "Wallet".to_string()
        } else {
            format!(
                "Wallet {}",
                state.paid_route_market.wallet.navigation_balance_text
            )
        };
        pages.push((Page::Wallet, wallet_title, ""));
    }
    pages.push((Page::Settings, "Settings".to_string(), ""));
    for (target, title, icon) in pages {
        let button = nav_button(
            &title,
            icon,
            page == target,
            target == Page::Devices && has_incoming_join_requests,
        );
        let app = app.clone();
        button.connect_clicked(move |_| set_page(&app, target));
        sidebar.append(&button);
    }

    sidebar.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    if let Some(network) = active_network(state) {
        let summary = gtk::Box::new(gtk::Orientation::Vertical, 4);
        summary.add_css_class("nvpn-sidebar-summary");

        let name = gtk::Label::new(Some(&display_network_name(network)));
        name.add_css_class("caption-heading");
        name.set_xalign(0.0);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        summary.append(&name);

        let count = gtk::Label::new(Some(&format!(
            "{} of {} connected",
            state.connected_peer_count, state.expected_peer_count
        )));
        bind_live_label(app, &count, |state| format!(
            "{} of {} connected", state.connected_peer_count, state.expected_peer_count
        ));
        count.add_css_class("caption");
        count.add_css_class("dim-label");
        count.set_xalign(0.0);
        summary.append(&count);

        sidebar.append(&summary);
    }

    let spacer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    sidebar.append(&spacer);

    let status = gtk::Label::new(Some(&state.vpn_status));
    bind_live_label(app, &status, |state| state.vpn_status.clone());
    status.add_css_class("caption");
    status.add_css_class("dim-label");
    status.set_xalign(0.0);
    status.set_wrap(true);
    sidebar.append(&status);
}
