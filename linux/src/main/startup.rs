fn main() -> glib::ExitCode {
    if let Some(exit_code) = run_update_e2e_from_args() {
        return exit_code;
    }

    bootstrap_session_bus();

    let runtime = AppRuntime::default();
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE)
        .build();
    app.connect_startup(|_| {
        install_css();
        gtk::Window::set_default_icon_name("nostr-vpn");
    });
    {
        let runtime = runtime.clone();
        app.connect_activate(move |app| {
            build_ui(app, &runtime, true);
        });
    }
    {
        let runtime = runtime.clone();
        app.connect_command_line(move |app, command_line| {
            let mut present = true;
            let mut urls = Vec::new();
            for arg in command_line.arguments() {
                let arg = arg.to_string_lossy();
                if arg == "--hidden" {
                    present = false;
                }
                if arg.starts_with("nvpn://") {
                    urls.push(arg.into_owned());
                    present = true;
                }
            }
            runtime.pending_urls.borrow_mut().extend(urls);
            build_ui(app, &runtime, present);
            drain_pending_urls(&runtime);
            glib::ExitCode::SUCCESS.into()
        });
    }
    app.run()
}

fn run_update_e2e_from_args() -> Option<glib::ExitCode> {
    let args = std::env::args().collect::<Vec<_>>();
    if !args.iter().any(|arg| arg == "--nvpn-e2e-update-check") {
        return None;
    }

    let result = run_update_e2e(args.iter().any(|arg| arg == "--nvpn-e2e-install-update"));
    let output_path = std::env::var("NVPN_UPDATE_E2E_RESULT_PATH").ok();
    let success = result
        .as_ref()
        .map(|value| value["ok"].as_bool().unwrap_or(false))
        .unwrap_or(false);
    match (output_path, result) {
        (Some(path), Ok(value)) => {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(error) = std::fs::write(
                &path,
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()),
            ) {
                eprintln!("failed to write update e2e result {path}: {error}");
                return Some(glib::ExitCode::FAILURE);
            }
        }
        (Some(path), Err(error)) => {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let value = serde_json::json!({
                "ok": false,
                "platform": "linux",
                "error": error,
            });
            let _ = std::fs::write(
                &path,
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string()),
            );
        }
        (None, Ok(value)) => {
            println!("{value}");
        }
        (None, Err(error)) => {
            eprintln!("{error}");
        }
    }

    Some(if success {
        glib::ExitCode::SUCCESS
    } else {
        glib::ExitCode::FAILURE
    })
}

fn run_update_e2e(install: bool) -> Result<serde_json::Value, String> {
    let current_version = std::env::var("NVPN_UPDATE_E2E_CURRENT_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let config_path = PathBuf::from(default_data_dir()).join("config.toml");
    let config_path = config_path.to_string_lossy();
    let check = updater::check_blocking(&current_version, &config_path)?;
    let mut downloaded_path = None;
    let mut executable = None;
    if install {
        let asset = check
            .asset
            .as_ref()
            .ok_or_else(|| "no Linux update asset selected".to_string())?;
        let path = updater::download_blocking(asset, &config_path)?.path;
        executable = std::fs::metadata(&path).ok().map(|metadata| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                let _ = metadata;
                false
            }
        });
        downloaded_path = Some(path.display().to_string());
    }

    Ok(serde_json::json!({
        "ok": true,
        "platform": "linux",
        "available": check.newer,
        "tag": check.tag,
        "assetName": check.asset.as_ref().map(|asset| asset.name.clone()),
        "assetUrl": check.asset.as_ref().map(|asset| asset.url.clone()),
        "downloadedPath": downloaded_path,
        "downloadedExecutable": executable,
    }))
}

fn build_ui(app: &adw::Application, runtime: &AppRuntime, present: bool) {
    if let Some(window) = app
        .active_window()
        .or_else(|| app.windows().into_iter().next())
    {
        if present {
            window.present();
        }
        drain_pending_urls(runtime);
        return;
    }

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .default_width(1040)
        .default_height(720)
        .title("Nostr VPN")
        .build();
    window.add_css_class("nvpn-root");

    let header = adw::HeaderBar::new();
    let title = gtk::Label::new(Some("Nostr VPN"));
    title.add_css_class("heading");
    title.set_halign(gtk::Align::Start);
    header.set_title_widget(Some(&title));

    let header_vpn_switch = gtk::Switch::new();
    header_vpn_switch.set_valign(gtk::Align::Center);
    header_vpn_switch.set_tooltip_text(Some("Toggle VPN"));
    header_vpn_switch.update_property(&[gtk::accessible::Property::Label("nvpn-service-toggle")]);
    header.pack_end(&header_vpn_switch);

    let header_status_dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    header_status_dot.add_css_class("nvpn-header-dot");
    header_status_dot.set_valign(gtk::Align::Center);
    header_status_dot.set_visible(false);
    header.pack_end(&header_status_dot);

    let header_status_label = gtk::Label::new(None);
    header_status_label.add_css_class("nvpn-header-status");
    header_status_label.add_css_class("dim-label");
    header_status_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    header_status_label.set_max_width_chars(28);
    header.pack_end(&header_status_label);

    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 10);
    sidebar.add_css_class("nvpn-sidebar");
    sidebar.set_width_request(210);
    sidebar.set_margin_top(14);
    sidebar.set_margin_bottom(14);
    sidebar.set_margin_start(14);
    sidebar.set_margin_end(10);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.set_hexpand(true);
    content.set_vexpand(true);
    content.add_css_class("nvpn-content");

    let update_bar = gtk::Box::new(gtk::Orientation::Vertical, 0);
    update_bar.add_css_class("nvpn-update-bar-host");

    let shell = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    shell.set_hexpand(true);
    shell.set_vexpand(true);
    shell.append(&sidebar);
    shell.append(&content);

    let main = gtk::Box::new(gtk::Orientation::Vertical, 0);
    main.set_hexpand(true);
    main.set_vexpand(true);
    main.append(&update_bar);
    main.append(&shell);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&main));
    window.set_content(Some(&toolbar));

    let model = Rc::new(RefCell::new(AppModel::new(
        window.clone(),
        sidebar.clone(),
        update_bar.clone(),
        content.clone(),
        header_status_label.clone(),
        header_status_dot.clone(),
        header_vpn_switch.clone(),
    )));
    *runtime.model.borrow_mut() = Some(model.clone());
    if model.borrow().tray_available {
        update_tray_application_hold(true, window.application());
    }
    {
        let model = model.clone();
        header_vpn_switch.connect_active_notify(move |sw| {
            let target = sw.is_active();
            let current = model.borrow().state.vpn_enabled;
            if target == current {
                return;
            }
            let action = {
                let state = &model.borrow().state;
                vpn_toggle_action(state)
            };
            dispatch(&model, action);
        });
    }
    {
        let model = model.clone();
        window.connect_close_request(move |window| {
            let model = model.borrow();
            if should_close_to_tray(
                model.state.close_to_tray_on_close,
                model.tray.is_available(),
                model.allow_close,
            ) {
                update_tray_application_hold(true, window.application());
                window.set_visible(false);
                glib::Propagation::Stop
            } else {
                release_tray_application_hold();
                glib::Propagation::Proceed
            }
        });
    }

    render(&model);

    {
        let model = model.clone();
        schedule_state_refresh(&model);
    }
    {
        let model = model.clone();
        let runtime = runtime.clone();
        glib::timeout_add_local(Duration::from_millis(250), move || {
            drain_core_results(&model);
            drain_pending_urls(&runtime);
            drain_tray_commands(&model);
            drain_update_events(&model);
            glib::ControlFlow::Continue
        });
    }
    {
        let model = model.clone();
        glib::timeout_add_seconds_local(update_poll_interval_secs(), move || {
            check_updates_if_due(&model);
            glib::ControlFlow::Continue
        });
    }

    check_updates_if_due(&model);

    if present {
        window.present();
    }
    drain_pending_urls(runtime);
}

// Full refreshes shell out to the nvpn CLI, so the cadence follows the macOS
// app: 1s while an action, service settlement, update or pending join approval
// is in flight, 10s with a live paid route, 15s with the VPN on, and 30s once
// idle. Each firing schedules the next timeout from the state it observed.
// Until the worker has produced its first state the tick retries at 1s;
// refresh_now skips it, so it costs no CLI spawn.
fn schedule_state_refresh(model: &AppRef) {
    let interval = {
        let model = model.borrow();
        if model.core_ready {
            refresh_interval_secs(
                !model.pending_actions.is_empty(),
                model.service_settling,
                model.update.checking || model.update.downloading,
                &model.state,
            )
        } else {
            1
        }
    };
    let model = model.clone();
    glib::timeout_add_seconds_local(interval, move || {
        refresh_now(&model);
        schedule_state_refresh(&model);
        glib::ControlFlow::Break
    });
}
