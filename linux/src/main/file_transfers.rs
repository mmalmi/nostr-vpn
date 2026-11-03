fn choose_transfer_files(app: &AppRef, button: &gtk::Button, npub: String) {
    let parent = button
        .root()
        .and_then(|root| root.downcast::<gtk::Window>().ok());
    let dialog = gtk::FileDialog::builder()
        .title("Send files")
        .accept_label("Send")
        .build();
    let app = app.clone();
    dialog.open_multiple(parent.as_ref(), gio::Cancellable::NONE, move |result| {
        let Ok(files) = result else {
            return;
        };
        let mut paths = Vec::new();
        for index in 0..files.n_items() {
            let Some(path) = files
                .item(index)
                .and_downcast::<gio::File>()
                .and_then(|file| file.path())
            else {
                set_notice(&app, "Choose local files to send");
                return;
            };
            paths.push(path);
        }
        stage_transfer_files(&app, npub.clone(), paths);
    });
}

fn stage_transfer_files(app: &AppRef, npub: String, sources: Vec<PathBuf>) {
    if sources.is_empty() {
        return;
    }
    if !app.borrow().state.vpn_active {
        set_notice(app, "Connect VPN to send files");
        return;
    }
    if sources.len() > 32 {
        set_notice(app, "Choose up to 32 files at a time");
        return;
    }
    let config = PathBuf::from(&app.borrow().state.config_path);
    let dialog = gtk::Window::builder()
        .title("Preparing files")
        .transient_for(&app.borrow().window)
        .modal(true)
        .default_width(360)
        .build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(20);
    content.set_margin_bottom(20);
    content.set_margin_start(20);
    content.set_margin_end(20);
    let detail = gtk::Label::new(Some("Preparing files…"));
    detail.set_wrap(true);
    let progress = gtk::ProgressBar::new();
    let cancel = gtk::Button::with_label("Cancel");
    content.append(&detail);
    content.append(&progress);
    content.append(&cancel);
    dialog.set_child(Some(&content));
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let closing = cancelled.clone();
    dialog.connect_close_request(move |_| {
        closing.store(true, std::sync::atomic::Ordering::Relaxed);
        glib::Propagation::Proceed
    });
    let closing = dialog.clone();
    cancel.connect_clicked(move |_| closing.close());
    let (sender, receiver) = mpsc::channel();
    let (updates, progress_updates) = mpsc::channel();
    let preparation_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        let mut paths = Vec::new();
        let total = sources
            .iter()
            .filter_map(|path| std::fs::metadata(path).ok())
            .map(|meta| meta.len())
            .sum::<u64>();
        let result = (|| -> Result<Vec<String>, String> {
            let mut prepared = 0u64;
            for source in sources {
                let name = source
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let mut last_update = Instant::now() - Duration::from_secs(1);
                let mut file_bytes = 0;
                let path = nostr_vpn_core::file_transfers::stage_source_with_progress(
                    &config,
                    &source,
                    |bytes| {
                        file_bytes = bytes;
                        if last_update.elapsed() >= Duration::from_millis(150) {
                            let _ =
                                updates.send((name.clone(), prepared.saturating_add(bytes), total));
                            last_update = Instant::now();
                        }
                        !cancelled.load(std::sync::atomic::Ordering::Relaxed)
                    },
                )
                .map_err(|error| error.to_string())?;
                prepared = prepared.saturating_add(file_bytes);
                paths.push(path.to_string_lossy().into_owned());
            }
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("File preparation cancelled".into());
            }
            Ok(paths.clone())
        })();
        if result.is_err() {
            for path in paths {
                let _ = nostr_vpn_core::file_transfers::discard_staged(
                    &config,
                    std::path::Path::new(&path),
                );
            }
        }
        let _ = sender.send(result);
    });
    dialog.present();
    let app = app.clone();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        if let Some((name, bytes, total)) = progress_updates.try_iter().last() {
            detail.set_text(&format!(
                "Preparing {name} · {} of {}",
                format_bytes(bytes),
                format_bytes(total)
            ));
            progress.set_fraction(if total == 0 {
                0.0
            } else {
                (bytes as f64 / total as f64).clamp(0.0, 1.0)
            });
        }
        match receiver.try_recv() {
            Ok(result) => {
                let was_cancelled =
                    preparation_cancelled.load(std::sync::atomic::Ordering::Relaxed);
                dialog.close();
                match result {
                    Ok(paths) if was_cancelled => {
                        let config = PathBuf::from(&app.borrow().state.config_path);
                        for path in paths {
                            let _ = nostr_vpn_core::file_transfers::discard_staged(
                                &config,
                                std::path::Path::new(&path),
                            );
                        }
                        set_notice(&app, "File preparation cancelled");
                    }
                    Ok(paths) => {
                        set_page(&app, Page::Devices);
                        dispatch(
                            &app,
                            NativeAppAction::SendFiles {
                                npub: npub.clone(),
                                paths,
                            },
                        );
                    }
                    Err(error) => set_notice(&app, error),
                }
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(_) => {
                dialog.close();
                set_notice(&app, "Could not prepare files");
                glib::ControlFlow::Break
            }
        }
    });
}

fn build_file_transfers(app: &AppRef, page: &gtk::Box, state: &NativeAppState) {
    let transfers = card();
    section_header(&transfers, "Files", "folder-download-symbolic");
    let received = gtk::Button::with_label("Received files");
    received.set_halign(gtk::Align::Start);
    let received_app = app.clone();
    received.connect_clicked(move |_| {
        let config = PathBuf::from(&received_app.borrow().state.config_path);
        let Some(parent) = config.parent().filter(|path| !path.as_os_str().is_empty()) else {
            set_notice(&received_app, "Received files are not available yet");
            return;
        };
        let folder = parent.join("file-transfers").join("inbox");
        match std::fs::metadata(&folder) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                set_notice(
                    &received_app,
                    "Could not open received files: the folder is unavailable",
                );
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                set_notice(&received_app, "No received files yet");
                return;
            }
            Err(error) => {
                set_notice(
                    &received_app,
                    format!("Could not open received files: {error}"),
                );
                return;
            }
        }
        let uri = gio::File::for_path(folder).uri();
        if let Err(error) = gio::AppInfo::launch_default_for_uri(&uri, gio::AppLaunchContext::NONE)
        {
            set_notice(
                &received_app,
                format!("Could not open received files: {error}"),
            );
        }
    });
    transfers.append(&received);
    if !state.vpn_active && !state.file_transfers.is_empty() {
        empty_row(&transfers, "Connect VPN to continue transfers");
    }
    let focused = app.borrow().focused_transfer_id.clone();
    let mut ordered: Vec<_> = state.file_transfers.iter().collect();
    ordered.sort_by_key(|transfer| {
        (
            focused.as_ref() != Some(&transfer.id),
            transfer.status != "offered",
            transfer.status == "completed",
        )
    });
    for transfer in ordered {
        if transfer.status == "unavailable" {
            row_label(
                &transfers,
                "Files unavailable",
                transfer
                    .error
                    .as_deref()
                    .unwrap_or("Connect VPN to transfer files"),
                "dialog-warning-symbolic",
            );
            continue;
        }
        let row = gtk::Box::new(gtk::Orientation::Vertical, 6);
        let title = gtk::Label::new(Some(&format!(
            "{}{}",
            transfer
                .files
                .first()
                .map(|file| file.name.as_str())
                .unwrap_or("Files"),
            if transfer.files.len() > 1 {
                format!(" + {} files", transfer.files.len() - 1)
            } else {
                String::new()
            }
        )));
        title.set_xalign(0.0);
        title.set_wrap(true);
        row.append(&title);
        let detail = gtk::Label::new(Some(&format!(
            "{} {} · {}",
            if transfer.is_sender { "To" } else { "From" },
            transfer.peer_name,
            file_transfer_status(&transfer.status, transfer.is_sender)
        )));
        detail.set_xalign(0.0);
        detail.add_css_class("dim-label");
        row.append(&detail);
        let progress = gtk::ProgressBar::new();
        progress.set_show_text(true);
        let update: LiveUpdate = {
            let id = transfer.id.clone();
            let progress = progress.clone();
            Rc::new(move |state| {
                if let Some(transfer) = state
                    .file_transfers
                    .iter()
                    .find(|transfer| transfer.id == id)
                {
                    progress.set_fraction(if transfer.total_bytes == 0 {
                        0.0
                    } else {
                        (transfer.transferred_bytes as f64 / transfer.total_bytes as f64)
                            .clamp(0.0, 1.0)
                    });
                    progress.set_text(Some(&format!(
                        "{} of {}",
                        format_bytes(transfer.transferred_bytes),
                        format_bytes(transfer.total_bytes)
                    )));
                }
            })
        };
        update(state);
        app.borrow_mut().live_updates.push(update);
        row.append(&progress);
        if let Some(error) = &transfer.error {
            empty_row(&row, error);
        }
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let mut actions = Vec::new();
        if !transfer.is_sender && transfer.status == "offered" {
            actions.push((
                "Accept",
                NativeAppAction::AcceptFileTransfer {
                    id: transfer.id.clone(),
                },
            ));
            actions.push((
                "Decline",
                NativeAppAction::DeclineFileTransfer {
                    id: transfer.id.clone(),
                },
            ));
        }
        if transfer.status == "paused" {
            actions.push((
                "Resume",
                NativeAppAction::ResumeFileTransfer {
                    id: transfer.id.clone(),
                },
            ));
        }
        if matches!(
            transfer.status.as_str(),
            "queued" | "offered" | "preparing" | "connecting" | "transferring" | "paused"
        ) && (transfer.is_sender || transfer.status != "offered")
        {
            actions.push((
                "Cancel",
                NativeAppAction::CancelFileTransfer {
                    id: transfer.id.clone(),
                },
            ));
        }
        for (label, action) in actions {
            let button = gtk::Button::with_label(label);
            button.set_sensitive(state.vpn_active || matches!(label, "Cancel" | "Decline"));
            let app = app.clone();
            button.connect_clicked(move |_| dispatch(&app, action.clone()));
            buttons.append(&button);
        }
        if !transfer.is_sender && transfer.status == "completed" {
            if let Some(path) = transfer
                .files
                .iter()
                .find_map(|file| file.local_path.as_ref())
            {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let uri = gio::File::for_path(parent).uri();
                    let button = gtk::Button::with_label("Show files");
                    let app = app.clone();
                    button.connect_clicked(move |_| {
                        if let Err(error) =
                            gio::AppInfo::launch_default_for_uri(&uri, gio::AppLaunchContext::NONE)
                        {
                            set_notice(&app, format!("Could not open files: {error}"));
                        }
                    });
                    buttons.append(&button);
                }
            }
        }
        row.append(&buttons);
        transfers.append(&row);
    }
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_max_content_height(320);
    scroll.set_propagate_natural_height(true);
    scroll.set_child(Some(&transfers));
    page.append(&scroll);
}

fn file_transfer_status(status: &str, sender: bool) -> &'static str {
    match status {
        "queued" => "Waiting to send",
        "cancelling" => "Cancelling…",
        "declining" => "Declining…",
        "offered" if sender => "Waiting for acceptance",
        "offered" => "Wants to send you files",
        "preparing" => "Preparing files…",
        "connecting" => "Connecting…",
        "transferring" if sender => "Sending",
        "transferring" => "Receiving",
        "paused" => "Paused",
        "completed" if sender => "Sent",
        "completed" => "Received",
        "declined" => "Declined",
        "cancelled" => "Cancelled",
        "failed" => "Could not transfer files",
        _ => "Waiting",
    }
}

fn file_peer_identity(value: &str) -> String {
    if value.len() > 18 {
        format!("{}…{}", &value[..10], &value[value.len() - 6..])
    } else {
        value.into()
    }
}

fn choose_file_recipient(app: &AppRef, paths: Vec<PathBuf>) {
    let dialog = gtk::Window::builder()
        .title("Send files")
        .transient_for(&app.borrow().window)
        .modal(true)
        .default_width(380)
        .build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_start(20);
    content.set_margin_end(20);
    content.set_margin_top(20);
    content.set_margin_bottom(20);
    let first = paths
        .first()
        .and_then(|path| path.file_name())
        .unwrap_or_default()
        .to_string_lossy();
    let total = paths
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.len())
        .sum();
    let summary = gtk::Label::new(Some(&format!(
        "{first}{} · {}",
        if paths.len() > 1 {
            format!(" + {} files", paths.len() - 1)
        } else {
            String::new()
        },
        format_bytes(total)
    )));
    summary.set_wrap(true);
    content.append(&summary);
    let status = gtk::Label::new(None);
    status.set_wrap(true);
    content.append(&status);
    let peers_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let scroll = gtk::ScrolledWindow::builder()
        .max_content_height(300)
        .propagate_natural_height(true)
        .child(&peers_box)
        .build();
    content.append(&scroll);
    let connect = gtk::Button::with_label("Connect and send");
    content.append(&connect);
    let change = gtk::Button::with_label("Choose another device");
    change.set_visible(false);
    content.append(&change);
    let cancel = gtk::Button::with_label("Cancel");
    content.append(&cancel);
    dialog.set_child(Some(&content));
    let requested: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let selected: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    {
        let requested = requested.clone();
        change.connect_clicked(move |_| *requested.borrow_mut() = None);
    }
    let last_peers = RefCell::new(String::new());
    let open = Rc::new(Cell::new(true));
    let closed = open.clone();
    dialog.connect_close_request(move |_| {
        closed.set(false);
        glib::Propagation::Proceed
    });
    let close = dialog.clone();
    cancel.connect_clicked(move |_| close.close());
    {
        let app = app.clone();
        let requested = requested.clone();
        let selected = selected.clone();
        connect.connect_clicked(move |_| {
            *requested.borrow_mut() = selected.borrow().clone();
            if !app.borrow().state.vpn_enabled {
                let action = { vpn_toggle_action(&app.borrow().state) };
                dispatch(&app, action);
            }
        });
    }
    let app = app.clone();
    dialog.present();
    let refresh: Rc<dyn Fn() -> bool> = Rc::new(move || {
        if !open.get() {
            return false;
        }
        let state = app.borrow().state.clone();
        let mut seen = std::collections::HashSet::new();
        let mut peers: Vec<_> = state
            .networks
            .iter()
            .filter(|network| network.enabled)
            .flat_map(|network| &network.participants)
            .filter(|peer| {
                !is_self(peer, &state) && peer.roster_accepted && seen.insert(peer.npub.clone())
            })
            .collect();
        peers.sort_by_key(|peer| (!peer.reachable, device_name(peer)));
        if let Some(npub) = requested.borrow().clone() {
            if state.vpn_active && peers.iter().any(|peer| peer.npub == npub && peer.reachable) {
                dialog.close();
                stage_transfer_files(&app, npub, paths.clone());
                return false;
            }
        }
        let signature = format!(
            "{:?}|{}",
            requested.borrow(),
            peers
                .iter()
                .map(|peer| format!("{}|{}|{}", peer.npub, peer.reachable, device_name(peer)))
                .collect::<Vec<_>>()
                .join(";")
        );
        if *last_peers.borrow() != signature {
            *last_peers.borrow_mut() = signature;
            while let Some(child) = peers_box.first_child() {
                peers_box.remove(&child);
            }
            let mut group: Option<gtk::CheckButton> = None;
            for peer in &peers {
                let label = format!(
                    "{} · {} · {}",
                    device_name(peer),
                    file_peer_identity(&peer.npub),
                    if peer.reachable { "Online" } else { "Offline" }
                );
                let button = gtk::CheckButton::with_label(&label);
                if let Some(label) = button.child().and_downcast::<gtk::Label>() {
                    label.set_wrap(true);
                    label.set_xalign(0.0);
                }
                button.set_group(group.as_ref());
                if group.is_none() {
                    group = Some(button.clone());
                }
                button.set_active(selected.borrow().as_ref() == Some(&peer.npub));
                button.set_sensitive(requested.borrow().is_none());
                let selected = selected.clone();
                let npub = peer.npub.clone();
                let connect = connect.clone();
                button.connect_toggled(move |button| {
                    if button.is_active() {
                        *selected.borrow_mut() = Some(npub.clone());
                        connect.set_sensitive(true);
                    }
                });
                peers_box.append(&button);
            }
        }
        change.set_visible(requested.borrow().is_some());
        connect.set_label(if state.vpn_active {
            "Send"
        } else {
            "Connect and send"
        });
        connect.set_sensitive(selected.borrow().is_some() && requested.borrow().is_none());
        status.set_text(if requested.borrow().is_some() {
            "Waiting for the device… Keep this window open."
        } else if peers.is_empty() {
            "Add another device to your network to send files."
        } else if !state.vpn_active {
            "Choose a device. Your selected files will stay here while VPN connects."
        } else {
            "Choose a device. Offline devices can be selected while you wait."
        });
        true
    });
    refresh();
    glib::timeout_add_seconds_local(1, move || {
        if refresh() {
            glib::ControlFlow::Continue
        } else {
            glib::ControlFlow::Break
        }
    });
}

fn install_file_notification_actions(application: &adw::Application, app: &AppRef) {
    for action_name in ["show-files", "accept-files", "decline-files"] {
        let action = gio::SimpleAction::new(action_name, Some(glib::VariantTy::STRING));
        let app = app.clone();
        action.connect_activate(move |_, parameter| {
            let Some(id) = parameter.and_then(|value| value.str()).map(str::to_owned) else {
                return;
            };
            app.borrow_mut().focused_transfer_id = Some(id.clone());
            set_page(&app, Page::Devices);
            show_window(&app);
            if action_name != "show-files" {
                let allowed = {
                    let state = &app.borrow().state;
                    (state.vpn_active || action_name == "decline-files")
                        && state.file_transfers.iter().any(|transfer| {
                            transfer.id == id && !transfer.is_sender && transfer.status == "offered"
                        })
                };
                if allowed {
                    dispatch(
                        &app,
                        if action_name == "accept-files" {
                            NativeAppAction::AcceptFileTransfer { id }
                        } else {
                            NativeAppAction::DeclineFileTransfer { id }
                        },
                    );
                }
            }
        });
        application.add_action(&action);
    }
}

fn notify_file_transfers(app: &AppRef, state: &NativeAppState) {
    let model = app.borrow();
    let Some(application) = model.window.application() else {
        return;
    };
    for transfer in state
        .file_transfers
        .iter()
        .filter(|transfer| !transfer.is_sender)
    {
        let previous = model
            .state
            .file_transfers
            .iter()
            .find(|old| old.id == transfer.id);
        if previous.map(|old| old.status.as_str()) == Some(transfer.status.as_str()) {
            continue;
        }
        let notification_id = format!("file-{}", transfer.id);
        if transfer.status != "offered" && !(transfer.status == "completed" && previous.is_some()) {
            application.withdraw_notification(&notification_id);
            continue;
        }
        let title = if transfer.status == "offered" {
            format!("Files from {}", transfer.peer_name)
        } else {
            "Files received".into()
        };
        let notification = gio::Notification::new(&title);
        notification.set_icon(&gio::ThemedIcon::new("nostr-vpn"));
        notification.set_body(Some(&format!(
            "{} · {}",
            transfer
                .files
                .first()
                .map(|file| file.name.as_str())
                .unwrap_or("Files"),
            format_bytes(transfer.total_bytes)
        )));
        let target = transfer.id.to_variant();
        notification.set_default_action_and_target_value("app.show-files", Some(&target));
        if transfer.status == "offered" {
            notification.add_button_with_target_value("Accept", "app.accept-files", Some(&target));
            notification.add_button_with_target_value(
                "Decline",
                "app.decline-files",
                Some(&target),
            );
        } else {
            notification.add_button_with_target_value(
                "Show files",
                "app.show-files",
                Some(&target),
            );
        }
        application.send_notification(Some(&notification_id), &notification);
    }
}
