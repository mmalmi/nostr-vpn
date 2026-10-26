#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_refresh_preserves_expanders_and_settings_scroll() {
        if std::env::var_os("NVPN_MANAGE_DEVICES_UI_TEST").is_none() {
            let directory = std::env::temp_dir()
                .join(format!("nvpn-manage-devices-test-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::background_refresh_preserves_expanders_and_settings_scroll",
                    "--nocapture",
                ])
                .env("NVPN_MANAGE_DEVICES_UI_TEST", "1")
                .env("NVPN_APP_DATA_DIR", &directory)
                .env("NVPN_CLI_PATH", "/bin/false")
                .env("G_DEBUG", "fatal-criticals")
                .status();
            std::fs::remove_dir_all(directory).unwrap();
            assert!(result.unwrap().success());
            return;
        }

        fn find_expander(widget: &gtk::Widget) -> Option<gtk::Expander> {
            if let Some(expander) = widget.downcast_ref::<gtk::Expander>() {
                if expander.label().as_deref() == Some("Manage devices") {
                    return Some(expander.clone());
                }
            }
            let mut child = widget.first_child();
            while let Some(widget) = child {
                if let Some(expander) = find_expander(&widget) {
                    return Some(expander);
                }
                child = widget.next_sibling();
            }
            None
        }

        fn contains_label(widget: &gtk::Widget, text: &str) -> bool {
            if let Some(expander) = widget.downcast_ref::<gtk::Expander>() {
                if expander.child().is_some_and(|child| contains_label(&child, text)) {
                    return true;
                }
            }
            if widget.downcast_ref::<gtk::Label>().is_some_and(|label| label.text() == text) {
                return true;
            }
            let mut child = widget.first_child();
            while let Some(widget) = child {
                if contains_label(&widget, text) {
                    return true;
                }
                child = widget.next_sibling();
            }
            false
        }

        adw::init().unwrap();
        let application = adw::Application::new(
            Some("fi.siriusbusiness.nvpn.tests"),
            gio::ApplicationFlags::NON_UNIQUE,
        );
        application.register(gio::Cancellable::NONE).unwrap();
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let mut model = AppModel::new(
            adw::ApplicationWindow::new(&application),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            content.clone(),
            gtk::Label::new(None),
            gtk::Box::new(gtk::Orientation::Vertical, 0),
            gtk::Switch::new(),
        );
        let (results, receiver) = mpsc::channel();
        model.core_results = receiver;
        model.core_ready = true;
        model.state = NativeAppState {
            networks: vec![NativeNetworkState {
                id: "test-network".to_string(),
                enabled: true,
                local_is_admin: true,
                participants: vec![NativeParticipantState {
                    npub: "npub1testpeer".to_string(),
                    magic_dns_alias: "test-peer".to_string(),
                    ..NativeParticipantState::default()
                }],
                ..NativeNetworkState::default()
            }],
            ..NativeAppState::default()
        };
        let app = Rc::new(RefCell::new(model));
        render(&app);
        let expander = find_expander(content.upcast_ref()).unwrap();
        assert!(!expander.is_expanded());
        expander.set_expanded(true);

        for expanded in [true, true, false, false] {
            let expander = find_expander(content.upcast_ref()).unwrap();
            expander.set_expanded(expanded);
            let mut state = app.borrow().state.clone();
            state.rev += 1;
            state.vpn_status = format!("Refresh {}", state.rev);
            state.networks[0].participants[0].tx_bytes = state.rev * 1024;
            state.networks[0].participants[0].last_seen_text = format!("Seen {}", state.rev);
            let sent = format_bytes(state.networks[0].participants[0].tx_bytes);
            let last_seen = state.networks[0].participants[0].last_seen_text.clone();
            results
                .send(CoreResult {
                    is_action: false,
                    state,
                })
                .unwrap();
            drain_core_results(&app);
            assert_eq!(
                find_expander(content.upcast_ref()).unwrap(),
                expander,
                "Routine polling replaced the Manage devices widget"
            );
            assert!(contains_label(content.upcast_ref(), &sent), "Traffic counter did not update");
            assert!(contains_label(content.upcast_ref(), &last_seen), "Last-seen text did not update");
            assert_eq!(
                find_expander(content.upcast_ref()).unwrap().is_expanded(),
                expanded,
                "Manage devices lost its state during a background refresh"
            );
        }

        let window = app.borrow().window.clone();
        window.set_default_size(900, 600);
        window.set_content(Some(&content));
        window.present();
        let context = glib::MainContext::default();
        {
            fn find_row(widget: &gtk::Widget) -> Option<gtk::Widget> {
                if widget.has_css_class("nvpn-device-row") {
                    return Some(widget.clone());
                }
                let mut child = widget.first_child();
                while let Some(widget) = child {
                    if let Some(row) = find_row(&widget) {
                        return Some(row);
                    }
                    child = widget.next_sibling();
                }
                None
            }
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                context.iteration(false);
                std::thread::sleep(Duration::from_millis(5));
            }
            let window_id = std::process::Command::new("xdotool")
                .args(["search", "--onlyvisible", "--pid", &std::process::id().to_string()])
                .output().expect("xdotool is required for the GTK mouse regression test");
            assert!(window_id.status.success());
            let window_id = String::from_utf8(window_id.stdout).unwrap();
            let window_id = window_id.lines().next().unwrap();
            for _ in 0..3 {
                let row = find_row(content.upcast_ref()).unwrap();
                let bounds = row.compute_bounds(&window).unwrap();
                let x = (bounds.x() + 20.0).to_string();
                let y = (bounds.y() + bounds.height() / 2.0).to_string();
                drop(row);
                app.borrow_mut().selected_device_pubkey = None;
                assert!(std::process::Command::new("xdotool")
                    .args(["mousemove", "--window", window_id, &x, &y, "click", "1"]).status().unwrap().success());
                let deadline = Instant::now() + Duration::from_millis(200);
                while Instant::now() < deadline {
                    context.iteration(false);
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(app.borrow().selected_device_pubkey.as_deref(), Some("npub1testpeer"));
            }
        }
        app.borrow_mut().page = Page::Settings;
        render(&app);
        let scroll = content
            .first_child()
            .unwrap()
            .downcast::<gtk::ScrolledWindow>()
            .unwrap();
        let adjustment = scroll.vadjustment();
        let settings_page = scroll.child().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while adjustment.upper() <= adjustment.page_size() {
            assert!(Instant::now() < deadline, "Settings did not become scrollable");
            context.iteration(false);
            std::thread::sleep(Duration::from_millis(5));
        }
        // Settle initial window focus/scroll animations before simulating a
        // user's scroll followed by a background refresh.
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            context.iteration(false);
            std::thread::sleep(Duration::from_millis(5));
        }
        gtk::prelude::GtkWindowExt::set_focus(&window, Some(&scroll));
        adjustment.set_value(200.0);
        let offset = adjustment.value();
        assert!(offset > 0.0);
        for refresh in 1..=3 {
            let mut state = app.borrow().state.clone();
            state.rev += 1;
            state.vpn_status = format!("Settings refresh {refresh}");
            state.runtime_status_detail = format!("Runtime refresh {refresh}");
            state.network.changed_at += 1;
            state.port_mapping.good_until += 1;
            results.send(CoreResult { is_action: false, state }).unwrap();
            drain_core_results(&app);
            assert_eq!(
                scroll.child().unwrap(), settings_page,
                "Routine polling replaced the Settings controls"
            );
            assert!(contains_label(content.upcast_ref(), &format!("Runtime refresh {refresh}")),
                "Runtime telemetry did not update in place");
            assert!(contains_label(app.borrow().sidebar.upcast_ref(), &format!("Settings refresh {refresh}")),
                "Sidebar status did not update in place");
            assert_eq!(
                content.first_child().unwrap(),
                scroll.clone().upcast::<gtk::Widget>(),
                "Background refresh replaced the scroller, resetting its layout and scroll position"
            );
            assert_eq!(adjustment.value(), offset);
            let deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < deadline {
                context.iteration(false);
                assert_eq!(adjustment.value(), offset, "Settings scroll jumped during layout");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        drop(settings_page);
        fn find_button(widget: &gtk::Widget) -> Option<gtk::Button> {
            if let Some(button) = widget.downcast_ref::<gtk::Button>() {
                return Some(button.clone());
            }
            let mut child = widget.first_child();
            while let Some(widget) = child {
                if let Some(button) = find_button(&widget) {
                    return Some(button);
                }
                child = widget.next_sibling();
            }
            None
        }
        // A real action or configuration change still rebuilds controls. Do
        // not leave GTK's scroller focus tracking pointed into a removed page.
        for _ in 0..3 {
            let button = find_button(scroll.child().unwrap().upcast_ref()).unwrap();
            button.grab_focus();
            drop(button);
            render(&app);
            let deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < deadline {
                context.iteration(false);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        window.close();
    }

    #[test]
    fn page_scroll_offsets_track_pages_independently() {
        let mut offsets = PageScrollOffsets::default();

        offsets.set(Page::Settings, 640.0);
        offsets.set(Page::Devices, 120.0);
        offsets.set(Page::ExitNodes, 260.0);
        offsets.set(Page::PaidRoutes, 300.0);
        offsets.set(Page::SellInternet, 420.0);

        assert_eq!(offsets.get(Page::Settings), 640.0);
        assert_eq!(offsets.get(Page::Devices), 120.0);
        assert_eq!(offsets.get(Page::ExitNodes), 260.0);
        assert_eq!(offsets.get(Page::PaidRoutes), 300.0);
        assert_eq!(offsets.get(Page::SellInternet), 420.0);
        assert_eq!(offsets.get(Page::Share), 0.0);
    }

    #[test]
    fn close_to_tray_requires_setting_tray_and_non_quit_close() {
        assert!(should_close_to_tray(true, true, false));
        assert!(!should_close_to_tray(false, true, false));
        assert!(!should_close_to_tray(true, false, false));
        assert!(!should_close_to_tray(true, true, true));
    }

    #[test]
    fn autostart_desktop_entry_launches_gui_hidden() {
        let entry = autostart_desktop_entry(std::path::Path::new("/opt/Nostr VPN/nostr-vpn"));

        assert!(entry.contains("Exec=/opt/Nostr\\ VPN/nostr-vpn --hidden\n"));
    }

    #[test]
    fn state_needs_render_ignores_revision_only_refreshes() {
        let previous = NativeAppState {
            rev: 40,
            vpn_status: "Connected".to_string(),
            ..NativeAppState::default()
        };
        let next = NativeAppState {
            rev: 41,
            vpn_status: "Connected".to_string(),
            ..previous.clone()
        };

        assert!(!state_needs_render(&previous, &next));
    }

    #[test]
    fn state_needs_render_detects_configuration_changes() {
        let previous = NativeAppState {
            rev: 40,
            vpn_status: "Connected".to_string(),
            ..NativeAppState::default()
        };
        let next = NativeAppState {
            rev: 41,
            node_name: "New device name".to_string(),
            ..previous.clone()
        };

        assert!(state_needs_render(&previous, &next));
    }

    #[test]
    fn live_telemetry_does_not_rebuild_but_roster_and_permissions_do() {
        let previous = NativeAppState {
            relays: vec![nostr_vpn_app_core::native_state::NativeRelayState {
                url: "wss://relay.example.com".to_string(),
                enabled: true,
                ..Default::default()
            }],
            networks: vec![NativeNetworkState {
                id: "test".to_string(),
                participants: vec![NativeParticipantState::default()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut next = previous.clone();
        next.rev = 1;
        next.connected_peer_count = 2;
        next.runtime_status_detail = "Running".to_string();
        next.magic_dns_status = "Ready".to_string();
        next.relays[0].status = "connected".to_string();
        next.network.primary_ipv4 = "192.0.2.1".to_string();
        next.port_mapping.good_until = 100;
        next.networks[0].online_count = 2;
        next.networks[0].participants[0].tx_bytes = 1024;
        next.networks[0].participants[0].fips_srtt_ms = 42;
        next.networks[0].participants[0].last_seen_text = "Just now".to_string();
        assert!(!state_needs_render(&previous, &next));

        next.networks[0].local_is_admin = true;
        assert!(state_needs_render(&previous, &next));
        next.networks[0].local_is_admin = false;
        next.networks[0].participants.push(NativeParticipantState::default());
        assert!(state_needs_render(&previous, &next));
    }

    #[test]
    fn vpn_toggle_installs_missing_service_before_connecting() {
        let missing = NativeAppState {
            service_supported: true,
            service_installed: false,
            vpn_enabled: false,
            ..NativeAppState::default()
        };
        assert!(matches!(
            vpn_toggle_action(&missing),
            NativeAppAction::InstallSystemService
        ));

        let installed = NativeAppState {
            service_supported: true,
            service_installed: true,
            vpn_enabled: false,
            ..NativeAppState::default()
        };
        assert!(matches!(
            vpn_toggle_action(&installed),
            NativeAppAction::ConnectVpn
        ));

        let enabled = NativeAppState {
            service_supported: true,
            service_installed: true,
            vpn_enabled: true,
            ..NativeAppState::default()
        };
        assert!(matches!(
            vpn_toggle_action(&enabled),
            NativeAppAction::DisconnectVpn
        ));
    }

    #[test]
    fn accepted_roster_selector_is_absent_while_manual_join_is_pending() {
        let pending = NativeParticipantState {
            npub: "npub1pending".to_string(),
            roster_accepted: false,
            state: "online".to_string(),
            ..NativeParticipantState::default()
        };
        assert_eq!(accepted_roster_accessibility_label(&pending), None);

        let accepted = NativeParticipantState {
            roster_accepted: true,
            state: "pending".to_string(),
            ..pending
        };
        assert_eq!(
            accepted_roster_accessibility_label(&accepted).as_deref(),
            Some("nvpn-roster-participant-accepted-npub1pending")
        );
    }

    #[test]
    fn completed_manual_add_is_shown_while_confirmation_and_connection_are_pending() {
        let npub = "npub1joined";
        let state = NativeAppState {
            error: "nvpn start failed".to_string(),
            networks: vec![NativeNetworkState {
                id: "home".to_string(),
                participants: vec![NativeParticipantState {
                    npub: npub.to_string(),
                    roster_accepted: false,
                    state: "pending".to_string(),
                    ..NativeParticipantState::default()
                }],
                ..NativeNetworkState::default()
            }],
            ..NativeAppState::default()
        };

        assert!(manual_participant_added(&state, "home", npub));
    }

    #[test]
    fn paid_exit_seller_drafts_build_one_validated_settings_patch() {
        assert_eq!(normalize_paid_route_country_input("f!iX"), "FI");
        assert_eq!(normalize_paid_route_country_input("12"), "");

        let state = NativeAppState {
            paid_exit_seller: NativePaidExitSellerState {
                price_msat_per_gb: 25_000,
                country_code: "FI".to_string(),
                accepted_mints: vec![
                    "https://mint-a.example".to_string(),
                    "https://mint-b.example".to_string(),
                ],
                ..NativePaidExitSellerState::default()
            },
            ..NativeAppState::default()
        };
        let mut drafts = Drafts::default();
        drafts.sync_from_state(&state);

        assert_eq!(drafts.paid_exit_price_msat_per_gb, "25000");
        assert_eq!(drafts.paid_exit_country_code, "FI");
        assert_eq!(
            drafts.paid_exit_accepted_mints,
            "https://mint-a.example, https://mint-b.example"
        );
        let patch = paid_exit_seller_settings_patch(&drafts).expect("valid seller settings");
        assert_eq!(patch.paid_exit_price_msat_per_gb, Some(25_000));
        assert_eq!(patch.paid_exit_country_code.as_deref(), Some("FI"));
        assert_eq!(
            patch.paid_exit_accepted_mints.as_deref(),
            Some("https://mint-a.example, https://mint-b.example")
        );

        drafts.paid_exit_price_msat_per_gb = "2.5".to_string();
        assert_eq!(
            paid_exit_seller_settings_patch(&drafts),
            Err(PAID_EXIT_PRICE_ERROR)
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn resolves_debug_network_ids_to_internal_ids() {
        let state = NativeAppState {
            networks: vec![NativeNetworkState {
                id: "internal-id".to_string(),
                network_id: "mesh-id".to_string(),
                enabled: true,
                ..NativeNetworkState::default()
            }],
            ..NativeAppState::default()
        };

        assert_eq!(
            resolve_network_id(&state, Some("mesh-id".to_string())).as_deref(),
            Some("internal-id")
        );
        assert_eq!(
            resolve_network_id(&state, None).as_deref(),
            Some("internal-id")
        );
    }
}

fn active_network(state: &NativeAppState) -> Option<&NativeNetworkState> {
    state
        .networks
        .iter()
        .find(|network| network.enabled)
        .or_else(|| state.networks.first())
}

fn incoming_join_request_count(state: &NativeAppState) -> usize {
    state
        .networks
        .iter()
        .map(|network| network.inbound_join_requests.len())
        .sum()
}

fn sync_selected_device(app: &AppRef) {
    let mut model = app.borrow_mut();
    let current = model.selected_device_pubkey.clone();
    let next = {
        let state = &model.state;
        active_network(state).and_then(|network| {
            let participants = sorted_participants(network, state);
            if let Some(current) = current.as_deref() {
                if participants
                    .iter()
                    .any(|participant| participant_key(participant) == current)
                {
                    Some(current.to_string())
                } else {
                    participants.first().map(participant_key)
                }
            } else {
                participants.first().map(participant_key)
            }
        })
    };
    model.selected_device_pubkey = next;
}

fn sorted_participants(
    network: &NativeNetworkState,
    state: &NativeAppState,
) -> Vec<NativeParticipantState> {
    let mut participants = network.participants.clone();
    participants.sort_by_key(|participant| {
        (
            !is_self(participant, state),
            !participant.reachable,
            device_name(participant).to_ascii_lowercase(),
        )
    });
    participants
}

fn selected_participant(
    network: &NativeNetworkState,
    state: &NativeAppState,
    selected_key: Option<&str>,
) -> Option<NativeParticipantState> {
    let participants = sorted_participants(network, state);
    if let Some(selected_key) = selected_key {
        if let Some(selected) = participants
            .iter()
            .find(|participant| participant_key(participant) == selected_key)
        {
            return Some(selected.clone());
        }
    }
    participants.first().cloned()
}

fn participant_key(participant: &NativeParticipantState) -> String {
    if participant.pubkey_hex.trim().is_empty() {
        participant.npub.clone()
    } else {
        participant.pubkey_hex.clone()
    }
}

fn accepted_roster_accessibility_label(participant: &NativeParticipantState) -> Option<String> {
    (!participant.npub.trim().is_empty() && participant.roster_accepted)
        .then(|| format!("nvpn-roster-participant-accepted-{}", participant.npub))
}

#[cfg(debug_assertions)]
fn resolve_network_id(state: &NativeAppState, requested: Option<String>) -> Option<String> {
    if let Some(requested) = requested {
        if let Some(network) = state
            .networks
            .iter()
            .find(|network| network.id == requested || network.network_id == requested)
        {
            return Some(network.id.clone());
        }
        return Some(requested);
    }
    active_network(state).map(|network| network.id.clone())
}

fn display_network_name(network: &NativeNetworkState) -> String {
    if network.name.trim().is_empty() {
        "Network".to_string()
    } else {
        network.name.clone()
    }
}

fn device_name(participant: &NativeParticipantState) -> String {
    for value in [
        participant.magic_dns_name.as_str(),
        participant.alias.as_str(),
        participant.magic_dns_alias.as_str(),
    ] {
        if !value.trim().is_empty() {
            return value.to_string();
        }
    }
    short_text(&participant.npub, 18)
}

fn parse_endpoint_hints(input: &str) -> Vec<String> {
    let mut hints = input
        .split([',', '\n', '\r', '\t', ' '])
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    hints.sort();
    hints.dedup();
    hints
}

fn device_magic_dns_name(participant: &NativeParticipantState, state: &NativeAppState) -> String {
    if !participant.magic_dns_name.trim().is_empty() {
        return participant.magic_dns_name.clone();
    }
    if is_self(participant, state) && !state.self_magic_dns_name.trim().is_empty() {
        return state.self_magic_dns_name.clone();
    }
    if !participant.magic_dns_alias.trim().is_empty() && !state.magic_dns_suffix.trim().is_empty() {
        return format!(
            "{}.{}",
            participant.magic_dns_alias.trim(),
            state.magic_dns_suffix.trim()
        );
    }
    String::new()
}

fn device_role_text(participant: &NativeParticipantState, state: &NativeAppState) -> String {
    let mut roles = Vec::new();
    if is_self(participant, state) {
        roles.push("This device");
    }
    if participant.is_admin {
        roles.push("Admin");
    }
    if participant.offers_exit_node {
        roles.push(exit_node_badge_text(participant, state));
    }
    if roles.is_empty() {
        "Member".to_string()
    } else {
        roles.join(", ")
    }
}

fn device_subtitle(participant: &NativeParticipantState) -> String {
    let ip = clean_ip(&participant.tunnel_ip);
    let id = short_text(&participant.npub, 18);
    if ip.is_empty() {
        id
    } else {
        format!("{id}  {ip}")
    }
}

fn device_status_text(participant: &NativeParticipantState) -> String {
    match participant.state.as_str() {
        "off" => "Off".to_string(),
        "local" | "online" | "present" => "Online".to_string(),
        "pending" => "Connecting".to_string(),
        "offline" => "Offline".to_string(),
        _ if participant.reachable => "Online".to_string(),
        _ => "Unknown".to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FipsPathKind {
    Local,
    Direct,
    Routed,
    Offline,
}

fn fips_path_kind(participant: &NativeParticipantState) -> FipsPathKind {
    if participant.state == "local" {
        FipsPathKind::Local
    } else if participant.reachable && !participant.fips_transport_addr.trim().is_empty() {
        FipsPathKind::Direct
    } else if participant.reachable {
        FipsPathKind::Routed
    } else {
        FipsPathKind::Offline
    }
}

fn fips_path_text(participant: &NativeParticipantState) -> String {
    match fips_path_kind(participant) {
        FipsPathKind::Local => "This device".to_string(),
        FipsPathKind::Direct => {
            let transport = if participant.fips_transport_type.trim().is_empty() {
                String::new()
            } else {
                format!(" ({})", participant.fips_transport_type.to_uppercase())
            };
            if participant.fips_srtt_ms > 0 {
                format!(
                    "Direct connection{}, {} ms",
                    transport, participant.fips_srtt_ms
                )
            } else {
                format!("Direct connection{}", transport)
            }
        }
        FipsPathKind::Routed => {
            if participant.fips_srtt_ms > 0 {
                format!("Via mesh, {} ms", participant.fips_srtt_ms)
            } else {
                "Via mesh".to_string()
            }
        }
        FipsPathKind::Offline => "Offline".to_string(),
    }
}

fn exit_node_candidates(
    network: &NativeNetworkState,
    state: &NativeAppState,
) -> Vec<NativeParticipantState> {
    let mut candidates = network
        .participants
        .iter()
        .filter(|participant| participant.offers_exit_node && !is_self(participant, state))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(device_name);
    candidates
}

fn is_self(participant: &NativeParticipantState, state: &NativeAppState) -> bool {
    (!state.own_npub.is_empty() && participant.npub == state.own_npub)
        || (!state.own_pubkey_hex.is_empty() && participant.pubkey_hex == state.own_pubkey_hex)
}

fn is_active_exit_participant(
    participant: &NativeParticipantState,
    state: &NativeAppState,
) -> bool {
    state.exit_node_active && !state.exit_node.is_empty() && participant.npub == state.exit_node
}

fn exit_node_badge_text(
    participant: &NativeParticipantState,
    state: &NativeAppState,
) -> &'static str {
    if is_active_exit_participant(participant, state) {
        "Exit active"
    } else {
        "Exit offered"
    }
}

fn exit_node_badge_style(
    participant: &NativeParticipantState,
    state: &NativeAppState,
) -> &'static str {
    if is_active_exit_participant(participant, state) {
        "ok"
    } else {
        "warn"
    }
}

fn hero_subtitle(state: &NativeAppState) -> String {
    if state.vpn_active {
        format!(
            "{} of {} devices connected",
            state.connected_peer_count, state.expected_peer_count
        )
    } else if state.vpn_control_supported {
        "Ready to connect this device to your private network".to_string()
    } else {
        non_empty_or(&state.runtime_status_detail, "VPN control is unavailable")
    }
}
