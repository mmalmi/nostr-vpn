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
    let (sender, receiver) = mpsc::channel();
    set_notice(app, "Preparing files");
    std::thread::spawn(move || {
        let mut paths = Vec::new();
        let result = (|| -> Result<Vec<String>, String> {
            for source in sources {
                let path = nostr_vpn_core::file_transfers::stage_source(&config, &source)
                    .map_err(|error| error.to_string())?;
                paths.push(path.to_string_lossy().into_owned());
            }
            Ok(paths.clone())
        })();
        if result.is_err() {
            for path in paths {
                let _ = std::fs::remove_file(&path);
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }
        let _ = sender.send(result);
    });
    let app = app.clone();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        match receiver.try_recv() {
            Ok(Ok(paths)) => {
                dispatch(
                    &app,
                    NativeAppAction::SendFiles {
                        npub: npub.clone(),
                        paths,
                    },
                );
                glib::ControlFlow::Break
            }
            Ok(Err(error)) => {
                set_notice(&app, format!("Could not prepare files: {error}"));
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(_) => {
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
    for transfer in &state.file_transfers {
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
        let title = gtk::Label::new(Some(
            &transfer
                .files
                .iter()
                .map(|file| file.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ));
        title.set_xalign(0.0);
        title.set_wrap(true);
        row.append(&title);
        let detail = gtk::Label::new(Some(&format!(
            "{} {} · {}",
            if transfer.is_sender { "To" } else { "From" },
            transfer.peer_name,
            if transfer.status == "preparing" {
                "Preparing…"
            } else {
                &transfer.status
            }
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
                        "{} / {} bytes",
                        transfer.transferred_bytes, transfer.total_bytes
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
            "offered" | "preparing" | "connecting" | "transferring" | "paused"
        ) {
            actions.push((
                "Cancel",
                NativeAppAction::CancelFileTransfer {
                    id: transfer.id.clone(),
                },
            ));
        }
        for (label, action) in actions {
            let button = gtk::Button::with_label(label);
            button.set_sensitive(state.vpn_active);
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

fn choose_file_recipient(app: &AppRef, paths: Vec<PathBuf>) {
    let model = app.borrow();
    let mut seen = std::collections::HashSet::new();
    let peers: Vec<_> = model
        .state
        .networks
        .iter()
        .filter(|network| network.enabled)
        .flat_map(|network| &network.participants)
        .filter(|peer| {
            !is_self(peer, &model.state)
                && peer.reachable
                && peer.roster_accepted
                && seen.insert(peer.npub.clone())
        })
        .cloned()
        .collect();
    if !model.state.vpn_active || peers.is_empty() {
        drop(model);
        set_notice(
            app,
            "Connect VPN with an online device, then try Send To again",
        );
        return;
    }
    let dialog = gtk::Window::builder()
        .title("Send files")
        .transient_for(&model.window)
        .modal(true)
        .default_width(340)
        .build();
    drop(model);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_start(20);
    content.set_margin_end(20);
    content.set_margin_top(20);
    content.set_margin_bottom(20);
    content.append(&gtk::Label::new(Some("Choose a device")));
    for peer in peers {
        let button = gtk::Button::with_label(&device_name(&peer));
        let app = app.clone();
        let paths = paths.clone();
        let dialog = dialog.clone();
        button.connect_clicked(move |_| {
            dialog.close();
            stage_transfer_files(&app, peer.npub.clone(), paths.clone());
        });
        content.append(&button);
    }
    dialog.set_child(Some(&content));
    dialog.present();
}
