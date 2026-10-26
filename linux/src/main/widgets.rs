fn switch_row<F>(app: &AppRef, parent: &gtk::Box, title: &str, active: bool, action: F)
where
    F: Fn(bool) -> NativeAppAction + 'static,
{
    switch_row_enabled(app, parent, title, active, true, action);
}

fn switch_row_enabled<F>(
    app: &AppRef,
    parent: &gtk::Box,
    title: &str,
    active: bool,
    enabled: bool,
    action: F,
) where
    F: Fn(bool) -> NativeAppAction + 'static,
{
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_hexpand(true);
    row.append(&label);
    let switch = gtk::Switch::builder().active(active).build();
    switch.set_sensitive(enabled);
    {
        let app = app.clone();
        switch.connect_active_notify(move |switch| {
            dispatch(&app, action(switch.is_active()));
        });
    }
    row.append(&switch);
    parent.append(&row);
}

fn row_label(parent: &gtk::Box, title: &str, body: &str, icon_name: &str) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Start);
    if !icon_name.is_empty() {
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.add_css_class("dim-label");
        row.append(&icon);
    }
    let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
    text.set_hexpand(true);
    let title = gtk::Label::new(Some(title));
    title.add_css_class("heading");
    title.set_xalign(0.0);
    text.append(&title);
    let body = gtk::Label::new(Some(body));
    body.add_css_class("caption");
    body.add_css_class("dim-label");
    body.set_xalign(0.0);
    body.set_wrap(true);
    body.set_selectable(true);
    text.append(&body);
    row.append(&text);
    parent.append(&row);
}

fn detail_row(parent: &gtk::Box, title: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_hexpand(true);
    let title_label = gtk::Label::new(Some(title));
    title_label.add_css_class("caption");
    title_label.add_css_class("dim-label");
    title_label.set_xalign(0.0);
    title_label.set_width_chars(13);
    row.append(&title_label);

    let value_label = gtk::Label::new(Some(value));
    value_label.set_xalign(0.0);
    value_label.set_selectable(true);
    value_label.set_hexpand(true);
    value_label.set_wrap(true);
    value_label.set_wrap_mode(gtk::pango::WrapMode::Char);
    row.append(&value_label);
    parent.append(&row);
}

fn public_fips_address(own_npub: &str) -> String {
    let trimmed = own_npub.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}.fips")
    }
}

fn connect_remove_participant_confirmation(
    button: &gtk::Button,
    app: &AppRef,
    network_id: String,
    npub: String,
    device_name: String,
) {
    let app = app.clone();
    button.connect_clicked(move |_| {
        confirm_remove_participant(&app, network_id.clone(), npub.clone(), device_name.clone());
    });
}

fn connect_remove_network_confirmation(
    button: &gtk::Button,
    app: &AppRef,
    network_id: String,
    network_name: String,
) {
    let app = app.clone();
    button.connect_clicked(move |_| {
        confirm_remove_network(&app, network_id.clone(), network_name.clone());
    });
}

fn confirm_remove_network(app: &AppRef, network_id: String, network_name: String) {
    let dialog = adw::AlertDialog::new(
        Some(&format!("Remove {network_name}?")),
        Some("This deletes the network from this device."),
    );
    dialog.add_responses(&[("cancel", "Cancel"), ("remove", "Remove")]);
    dialog.set_close_response("cancel");
    dialog.set_default_response(Some("cancel"));
    dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
    {
        let app = app.clone();
        dialog.connect_response(Some("remove"), move |_, _| {
            dispatch(
                &app,
                NativeAppAction::RemoveNetwork {
                    network_id: network_id.clone(),
                },
            );
        });
    }
    let window = app.borrow().window.clone();
    dialog.present(Some(&window));
}

fn confirm_remove_participant(app: &AppRef, network_id: String, npub: String, device_name: String) {
    let dialog = adw::AlertDialog::new(
        Some(&format!("Remove {device_name}?")),
        Some("This removes the device from the network's roster. They keep the network locally but won't be in this roster anymore."),
    );
    dialog.add_responses(&[("cancel", "Cancel"), ("remove", "Remove")]);
    dialog.set_close_response("cancel");
    dialog.set_default_response(Some("cancel"));
    dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
    {
        let app = app.clone();
        dialog.connect_response(Some("remove"), move |_, _| {
            dispatch(
                &app,
                NativeAppAction::RemoveParticipant {
                    network_id: network_id.clone(),
                    npub: npub.clone(),
                },
            );
        });
    }
    let window = app.borrow().window.clone();
    dialog.present(Some(&window));
}

fn metric(title: &str, value: &str) -> gtk::Box {
    let metric = gtk::Box::new(gtk::Orientation::Vertical, 2);
    metric.add_css_class("nvpn-metric");
    metric.set_size_request(170, -1);

    let title_label = gtk::Label::new(Some(title));
    title_label.add_css_class("caption");
    title_label.add_css_class("dim-label");
    title_label.set_xalign(0.0);
    metric.append(&title_label);

    let value_label = gtk::Label::new(Some(value));
    value_label.add_css_class("heading");
    value_label.set_xalign(0.0);
    value_label.set_selectable(true);
    value_label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    metric.append(&value_label);

    metric
}

fn page_title(parent: &gtk::Box, title: &str, icon_name: &str) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    row.set_valign(gtk::Align::Center);
    if !icon_name.is_empty() {
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.add_css_class("accent");
        row.append(&icon);
    }
    let label = gtk::Label::new(Some(title));
    label.add_css_class("title-1");
    label.set_xalign(0.0);
    row.append(&label);
    parent.append(&row);
}

fn section_header(parent: &gtk::Box, title: &str, icon_name: &str) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    row.set_valign(gtk::Align::Center);
    if !icon_name.is_empty() {
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.add_css_class("dim-label");
        row.append(&icon);
    }
    let label = gtk::Label::new(Some(title));
    label.add_css_class("title-3");
    label.set_xalign(0.0);
    row.append(&label);
    parent.append(&row);
}

fn empty_row(parent: &gtk::Box, text: &str) {
    let label = gtk::Label::new(Some(text));
    label.add_css_class("dim-label");
    label.set_xalign(0.0);
    label.set_margin_top(4);
    parent.append(&label);
}

fn card() -> gtk::Box {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 12);
    card.add_css_class("nvpn-card");
    card.set_hexpand(true);
    card.set_margin_bottom(2);
    card
}

fn nav_button(title: &str, icon_name: &str, active: bool, attention: bool) -> gtk::Button {
    let button = gtk::Button::new();
    button.add_css_class("flat");
    button.add_css_class("nvpn-nav-button");
    button.set_hexpand(true);
    if active {
        button.add_css_class("active");
    }
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 7);
    row.set_valign(gtk::Align::Center);
    row.set_hexpand(true);
    if !icon_name.is_empty() {
        let icon = gtk::Image::from_icon_name(icon_name);
        row.append(&icon);
    }
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    label.set_hexpand(true);
    row.append(&label);
    if attention {
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        row.append(&spacer);
        let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        dot.set_size_request(8, 8);
        dot.add_css_class("nvpn-attention-dot");
        row.append(&dot);
    }
    button.set_child(Some(&row));
    button
}

fn icon_text_button(title: &str, icon_name: &str) -> gtk::Button {
    let button = gtk::Button::new();
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 7);
    row.set_valign(gtk::Align::Center);
    if !icon_name.is_empty() {
        let icon = gtk::Image::from_icon_name(icon_name);
        row.append(&icon);
    }
    let label = gtk::Label::new(Some(title));
    label.set_xalign(0.0);
    row.append(&label);
    button.set_child(Some(&row));
    button
}

fn entry(placeholder: &str, value: &str) -> gtk::Entry {
    let entry = gtk::Entry::new();
    entry.set_placeholder_text(Some(placeholder));
    entry.set_text(value);
    entry.set_hexpand(true);
    entry
}

fn badge(text: &str, style: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.add_css_class("nvpn-badge");
    label.add_css_class(style);
    label
}

fn clear_box(parent: &gtk::Box) {
    while let Some(child) = parent.first_child() {
        parent.remove(&child);
    }
}

// These callbacks only update presentation. They must not dispatch actions or
// own the app model. Clear them when replacing the page, not on each poll.
fn bind_live_label(
    app: &AppRef,
    label: &gtk::Label,
    text: impl Fn(&NativeAppState) -> String + 'static,
) {
    let label = label.downgrade();
    app.borrow_mut().live_updates.push(Rc::new(move |state| {
        if let Some(label) = label.upgrade() {
            let text = text(state);
            if label.text().as_str() != text {
                label.set_text(&text);
            }
        }
    }));
}

fn refresh_live_widgets(app: &AppRef, state: &NativeAppState) {
    refresh_header(app, state);
    let updates = app.borrow().live_updates.clone();
    for update in updates {
        update(state);
    }
}

fn live_metric(
    app: &AppRef,
    title: &str,
    text: impl Fn(&NativeAppState) -> String + 'static,
) -> gtk::Box {
    let value = text(&app.borrow().state);
    let item = metric(title, &value);
    let label = item.last_child().unwrap().downcast::<gtk::Label>().unwrap();
    bind_live_label(app, &label, text);
    item
}

fn live_detail_row(
    app: &AppRef,
    parent: &gtk::Box,
    title: &str,
    text: impl Fn(&NativeAppState) -> String + 'static,
) {
    let value = non_empty_or(&text(&app.borrow().state), "-");
    detail_row(parent, title, &value);
    let label = parent.last_child().unwrap().last_child().unwrap()
        .downcast::<gtk::Label>().unwrap();
    bind_live_label(app, &label, move |state| non_empty_or(&text(state), "-"));
}

fn current_content_scroll_offset(content: &gtk::Box) -> f64 {
    content
        .first_child()
        .and_then(|child| child.downcast::<gtk::ScrolledWindow>().ok())
        .map(|scroll| scroll.vadjustment().value())
        .unwrap_or(0.0)
}

fn restore_scroll_offset(scroll: &gtk::ScrolledWindow, offset: f64) {
    if !offset.is_finite() || offset <= 0.0 {
        return;
    }
    let adjustment = scroll.vadjustment();
    set_scroll_adjustment_value(&adjustment, offset);
    glib::idle_add_local_once(move || {
        set_scroll_adjustment_value(&adjustment, offset);
    });
}

fn set_scroll_adjustment_value(adjustment: &gtk::Adjustment, offset: f64) {
    let lower = adjustment.lower();
    let max = (adjustment.upper() - adjustment.page_size()).max(lower);
    adjustment.set_value(offset.clamp(lower, max));
}
