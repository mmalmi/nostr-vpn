#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_devices_stays_expanded_across_refreshes() {
        if std::env::var_os("NVPN_MANAGE_DEVICES_UI_TEST").is_none() {
            let directory = std::env::temp_dir()
                .join(format!("nvpn-manage-devices-test-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::manage_devices_stays_expanded_across_refreshes",
                    "--nocapture",
                ])
                .env("NVPN_MANAGE_DEVICES_UI_TEST", "1")
                .env("NVPN_APP_DATA_DIR", &directory)
                .env("NVPN_CLI_PATH", "/bin/false")
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
            results
                .send(CoreResult {
                    is_action: false,
                    state,
                })
                .unwrap();
            drain_core_results(&app);
            assert_eq!(
                find_expander(content.upcast_ref()).unwrap().is_expanded(),
                expanded,
                "Manage devices lost its state during a background refresh"
            );
        }
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
    fn state_needs_render_detects_visible_changes() {
        let previous = NativeAppState {
            rev: 40,
            vpn_status: "Connected".to_string(),
            ..NativeAppState::default()
        };
        let next = NativeAppState {
            rev: 41,
            vpn_status: "Disconnected".to_string(),
            ..previous.clone()
        };

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
