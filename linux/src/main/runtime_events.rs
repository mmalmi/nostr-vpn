fn sync_launch_on_startup_setting(app: &AppRef) {
    let enabled = {
        let model = app.borrow();
        model.state.startup_settings_supported && model.state.launch_on_startup
    };
    if let Err(error) = configure_launch_on_startup(enabled) {
        set_notice(app, error);
    }
}

fn set_state(app: &AppRef, state: NativeAppState) {
    let mut model = app.borrow_mut();
    if state.health.len() > model.state.health.len() {
        model.diagnostics_expanded = true;
    }
    model.tray.update(&state);
    model.state = state;
}

fn state_needs_render(previous: &NativeAppState, next: &NativeAppState) -> bool {
    if previous == next {
        return false;
    }
    // Local status updates have live bindings (or are not displayed). Everything
    // else, including permissions, configuration and roster changes, still rebuilds
    // the page so action callbacks cannot retain obsolete state.
    fn structure(mut state: NativeAppState) -> NativeAppState {
        state.rev = 0;
        state.vpn_status.clear();
        state.runtime_status_detail.clear();
        state.connected_peer_count = 0;
        state.expected_peer_count = 0;
        state.fips_connected_peer_count = 0;
        state.fips_roster_peer_count = 0;
        state.non_fips_roster_peer_count = 0;
        state.magic_dns_status.clear();
        state.network = Default::default();
        state.port_mapping = Default::default();
        for relay in &mut state.relays {
            relay.status.clear();
        }
        for network in &mut state.networks {
            network.online_count = 0;
            network.expected_count = 0;
            for participant in &mut network.participants {
                participant.tx_bytes = 0;
                participant.rx_bytes = 0;
                participant.fips_srtt_ms = 0;
                participant.fips_srtt_age_ms = 0;
                participant.fips_packets_sent = 0;
                participant.fips_packets_recv = 0;
                participant.fips_bytes_sent = 0;
                participant.fips_bytes_recv = 0;
                participant.fips_direct_probe_after_ms = 0;
                participant.fips_direct_probe_expires_at_ms = 0;
                participant.last_fips_control_seen_text.clear();
                participant.last_fips_data_seen_text.clear();
                participant.last_seen_text.clear();
            }
        }
        state
    }
    structure(previous.clone()) != structure(next.clone())
}

fn drain_tray_commands(app: &AppRef) {
    if sync_tray_status(app) {
        render_background_change(app);
    }

    let commands = app.borrow_mut().tray.drain();
    for command in commands {
        if !app.borrow().core_ready
            && !matches!(
                &command,
                tray::TrayCommand::ShowWindow | tray::TrayCommand::Quit
            )
        {
            continue;
        }
        match command {
            tray::TrayCommand::ShowWindow => show_window(app),
            tray::TrayCommand::ToggleVpn => {
                let action = {
                    let state = &app.borrow().state;
                    vpn_toggle_action(state)
                };
                dispatch(app, action);
            }
            tray::TrayCommand::ToggleExitOffer => {
                let enabled = !app.borrow().state.advertise_exit_node;
                dispatch(
                    app,
                    NativeAppAction::UpdateSettings {
                        patch: SettingsPatch {
                            advertise_exit_node: Some(enabled),
                            ..SettingsPatch::default()
                        },
                    },
                );
            }
            tray::TrayCommand::CopyDeviceId => {
                let value = app.borrow().state.own_npub.clone();
                if !value.trim().is_empty() {
                    copy_text(&value);
                }
            }
            tray::TrayCommand::CopyPeer(npub) => copy_text(&npub),
            tray::TrayCommand::SetInternetSource(source) => {
                dispatch(
                    app,
                    NativeAppAction::UpdateSettings {
                        patch: SettingsPatch {
                            internet_source: Some(source),
                            ..SettingsPatch::default()
                        },
                    },
                );
            }
            tray::TrayCommand::SetExitNode(npub) => {
                dispatch(
                    app,
                    NativeAppAction::UpdateSettings {
                        patch: SettingsPatch {
                            internet_source: Some("private_vpn".to_string()),
                            exit_node: Some(npub),
                            ..SettingsPatch::default()
                        },
                    },
                );
            }
            tray::TrayCommand::Quit => quit_app(app),
        }
    }
}

fn check_updates(app: &AppRef, manual: bool) {
    let (current_version, config_path, sender) = {
        let mut model = app.borrow_mut();
        if !model.core_ready || model.update.checking || model.update.downloading {
            return;
        }
        if manual {
            model
                .update_policy
                .note_manual_check_started(Instant::now());
        }
        model.update.checking = true;
        if manual {
            model.update.status = "Checking for updates".to_string();
        }
        (
            model.state.app_version.clone(),
            model.state.config_path.clone(),
            model.update_sender.clone(),
        )
    };
    render(app);
    updater::check(current_version, config_path, manual, sender);
}

fn check_updates_if_due(app: &AppRef) {
    let due = {
        let mut model = app.borrow_mut();
        if !model.core_ready {
            return;
        }
        model.update_policy.should_start_check(true, Instant::now())
    };
    if due {
        check_updates(app, false);
    }
}

fn download_update(app: &AppRef) {
    let (asset, config_path, sender) = {
        let mut model = app.borrow_mut();
        if model.update.checking
            || model.update.downloading
            || model.update.downloaded_path().is_some()
        {
            return;
        }
        let Some(asset) = model.update.asset.clone() else {
            model.update.status = "No Linux update asset found".to_string();
            drop(model);
            render(app);
            return;
        };
        model.update.downloading = true;
        model.update.status = format!("Downloading {}", model.update.version);
        (
            asset,
            model.state.config_path.clone(),
            model.update_sender.clone(),
        )
    };
    render_background_change(app);
    updater::download(asset, config_path, sender);
}

fn show_or_download_update(app: &AppRef) {
    let downloaded = app.borrow().update.downloaded_path().map(PathBuf::from);
    let Some(path) = downloaded else {
        download_update(app);
        return;
    };
    if let Some(parent) = path.parent() {
        let uri = gio::File::for_path(parent).uri();
        if let Err(error) =
            gio::AppInfo::launch_default_for_uri(&uri, None::<&gio::AppLaunchContext>)
        {
            app.borrow_mut().update.status = format!("Could not show downloaded update: {error}");
            render(app);
        }
    }
}

fn drain_update_events(app: &AppRef) {
    let events = {
        let model = app.borrow();
        model.update_receiver.try_iter().collect::<Vec<_>>()
    };
    if events.is_empty() {
        return;
    }

    let mut auto_download = false;
    {
        let mut model = app.borrow_mut();
        for event in events {
            match event {
                updater::UpdateEvent::Checked { manual, result } => {
                    model.update.checking = false;
                    match result {
                        Ok(check) => {
                            model.update.available = check.newer;
                            model.update.version = check.tag.clone();
                            model.update.asset = if check.newer { check.asset } else { None };
                            if check.newer {
                                model.update.status = if !check.verified {
                                    format!(
                                        "Update {} found from unverified {}; download disabled",
                                        check.tag, check.source
                                    )
                                } else if model.update.downloaded_path().is_some() {
                                    format!("Update {} downloaded; ready to install", check.tag)
                                } else if model.update.asset.is_some() {
                                    format!("Update {} available", check.tag)
                                } else {
                                    format!(
                                        "Update {} found without a Linux desktop asset",
                                        check.tag
                                    )
                                };
                                auto_download = model.update.should_auto_download();
                            } else if manual {
                                model.update.status = "Up to date".to_string();
                            } else {
                                model.update.status.clear();
                            }
                        }
                        Err(error) => {
                            if manual {
                                model.update.status = error;
                            } else {
                                model.update.status.clear();
                            }
                        }
                    }
                }
                updater::UpdateEvent::Downloaded(result) => {
                    model.update.downloading = false;
                    match result {
                        Ok(download) => {
                            model.update.status = format!(
                                "Downloaded {}; open the download folder to install it",
                                download
                                    .path
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("update")
                            );
                            model.update.downloaded = Some(download);
                            save_update_preferences(&mut model.update);
                        }
                        Err(error) => {
                            model.update.status = error;
                        }
                    }
                }
            }
        }
    }

    if auto_download {
        download_update(app);
    } else {
        render_background_change(app);
    }
}

fn show_window(app: &AppRef) {
    let window = app.borrow().window.clone();
    window.set_visible(true);
    window.present();
}

fn quit_app(app: &AppRef) {
    let window = {
        let mut model = app.borrow_mut();
        model.allow_close = true;
        model.window.clone()
    };
    release_tray_application_hold();
    if let Some(application) = window.application() {
        application.quit();
    }
}

fn should_close_to_tray(
    close_to_tray_on_close: bool,
    tray_available: bool,
    allow_close: bool,
) -> bool {
    close_to_tray_on_close && tray_available && !allow_close
}

fn sync_tray_status(app: &AppRef) -> bool {
    let (changed, available, application) = {
        let mut model = app.borrow_mut();
        let available = model.tray.is_available();
        let error = model.tray.last_error();
        let changed = available != model.tray_available || error != model.tray_error;
        if changed {
            model.tray_available = available;
            model.tray_error = error;
        }
        (changed, available, model.window.application())
    };

    if changed {
        update_tray_application_hold(available, application);
    }

    changed
}

fn update_tray_application_hold(available: bool, application: Option<gtk::Application>) {
    TRAY_APP_HOLD.with(|hold| {
        let mut hold = hold.borrow_mut();
        if available {
            if hold.is_none() {
                if let Some(application) = application {
                    *hold = Some(application.hold());
                }
            }
        } else {
            hold.take();
        }
    });
}

fn release_tray_application_hold() {
    TRAY_APP_HOLD.with(|hold| {
        hold.borrow_mut().take();
    });
}

fn start_service_settlement_polling(app: &AppRef) {
    app.borrow_mut().service_settling = true;
    render(app);

    let app = app.clone();
    let attempts = Rc::new(Cell::new(0));
    glib::timeout_add_local(Duration::from_millis(700), move || {
        refresh_now(&app);
        let next = attempts.get() + 1;
        attempts.set(next);
        if next >= 8 {
            app.borrow_mut().service_settling = false;
            render(&app);
            glib::ControlFlow::Break
        } else {
            glib::ControlFlow::Continue
        }
    });
}

fn drain_pending_urls(runtime: &AppRuntime) {
    let Some(app) = runtime.model.borrow().clone() else {
        return;
    };
    if !app.borrow().core_ready {
        return;
    }
    let urls: Vec<String> = runtime.pending_urls.borrow_mut().drain(..).collect();
    for url in urls {
        handle_deep_link(&app, &url);
    }
}

fn handle_deep_link(app: &AppRef, raw: &str) {
    match deep_link::parse(raw) {
        Some(deep_link::DeepLink::JoinRequest(request)) => {
            dispatch(app, NativeAppAction::ImportJoinRequest { request });
        }
        #[cfg(debug_assertions)]
        Some(deep_link::DeepLink::Debug(deep_link::DebugAction::Tick)) => {
            dispatch(app, NativeAppAction::Tick);
        }
        #[cfg(debug_assertions)]
        Some(deep_link::DeepLink::Debug(deep_link::DebugAction::AcceptJoin {
            network_id,
            requester_npub,
        })) => {
            let (network_id, requester_npub) = {
                let state = app.borrow().state.clone();
                let network_id = resolve_network_id(&state, network_id);
                let requester_npub = requester_npub.or_else(|| {
                    network_id
                        .as_deref()
                        .and_then(|id| {
                            state
                                .networks
                                .iter()
                                .find(|network| network.id == id || network.network_id == id)
                        })
                        .or_else(|| active_network(&state))
                        .and_then(|network| network.inbound_join_requests.first())
                        .map(|request| request.requester_npub.clone())
                });
                (network_id, requester_npub)
            };
            if let (Some(network_id), Some(requester_npub)) = (network_id, requester_npub) {
                dispatch(
                    app,
                    NativeAppAction::AcceptJoinRequest {
                        network_id,
                        requester_npub,
                    },
                );
            }
        }
        None => {}
    }
}

fn create_network(app: &AppRef, name: String) {
    let name = non_empty_or(&name, "Private network");
    dispatch(app, NativeAppAction::AddNetwork { name });
}

fn set_notice(app: &AppRef, notice: impl Into<String>) {
    app.borrow_mut().notice = notice.into();
    render(app);
}

fn set_page(app: &AppRef, page: Page) {
    {
        let mut model = app.borrow_mut();
        if model.page == Page::Share && page != Page::Share {
            model.add_network_join_status.clear();
        }
        model.page = page;
    }
    render(app);
}
