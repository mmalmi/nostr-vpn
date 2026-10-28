fn clean_ip(value: &str) -> String {
    value.split('/').next().unwrap_or(value).trim().to_string()
}

fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;
    while value >= 1024.0 && unit_index < units.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", units[unit_index])
    }
}

fn save_update_preferences(update: &mut updater::UpdateState) {
    if let Err(error) = updater::save_preferences(&update_preferences_path(), update) {
        update.status = format!("Could not save update preferences: {error}");
    }
}

fn update_poll_interval_secs() -> u32 {
    std::env::var("NVPN_UPDATE_POLL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(|seconds| seconds.min(u32::MAX as u64) as u32)
        .unwrap_or(DEFAULT_UPDATE_POLL_INTERVAL_SECS)
}

// Same cadence as the macOS app: stay at 1s while something is in flight or a
// join approval is outstanding, 10s while a paid route is live, 15s with the
// VPN connected, and 30s when idle.
fn refresh_interval_secs(
    actions_in_flight: bool,
    service_settling: bool,
    update_busy: bool,
    state: &NativeAppState,
) -> u32 {
    let pending_roster = state.vpn_enabled
        && active_network(state).is_some_and(|network| {
            network
                .participants
                .iter()
                .any(|participant| !participant.roster_accepted)
        });
    if actions_in_flight || service_settling || update_busy || pending_roster {
        return 1;
    }
    if paid_route_live_refresh_wanted(state) {
        return 10;
    }
    if state.vpn_enabled {
        return 15;
    }
    30
}

fn paid_route_live_refresh_wanted(state: &NativeAppState) -> bool {
    if state.paid_route_market.wallet.last_action.kind == "topup" {
        return true;
    }
    if !state.paid_exit_seller.sessions.is_empty() {
        return true;
    }
    state.paid_route_market.sessions.iter().any(|session| {
        session.allow_routing
            || matches!(
                session.lifecycle_status.as_str(),
                "opening" | "probing" | "active" | "paused"
            )
            || matches!(
                session.access_state.as_str(),
                "paid" | "free_probe" | "grace" | "suspended"
            )
    })
}

fn update_preferences_path() -> PathBuf {
    PathBuf::from(default_data_dir()).join("desktop-updates.conf")
}

fn short_text(value: &str, keep: usize) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= keep * 2 + 3 {
        return trimmed.to_string();
    }
    format!(
        "{}...{}",
        &trimmed[..keep],
        &trimmed[trimmed.len() - keep..]
    )
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn display_network_id(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 4 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return trimmed.to_string();
    }
    trimmed
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn normalize_network_id_input(value: &str) -> String {
    let trimmed = value.trim();
    let compact = trimmed
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect::<String>();
    if compact.is_empty() && trimmed.chars().all(|ch| ch.is_whitespace() || ch == '-') {
        return String::new();
    }
    if !compact.is_empty() && compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        compact.to_ascii_lowercase()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_device_id(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() != 63 || !trimmed.starts_with("npub1") {
        return false;
    }
    trimmed[5..]
        .chars()
        .all(|ch| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(ch))
}

fn first_non_empty(values: &[&str]) -> Option<String> {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn service_update_recommended(state: &NativeAppState) -> bool {
    state.service_installed
        && !state.service_binary_version.is_empty()
        && !state.expected_service_binary_version.is_empty()
        && state.service_binary_version != state.expected_service_binary_version
}

fn vpn_toggle_action(state: &NativeAppState) -> NativeAppAction {
    if state.vpn_enabled {
        NativeAppAction::DisconnectVpn
    } else if state.service_supported && !state.service_installed {
        NativeAppAction::InstallSystemService
    } else {
        NativeAppAction::ConnectVpn
    }
}

fn system_version_label(state: &NativeAppState) -> String {
    let app = state.app_version.trim();
    let daemon = state.daemon_binary_version.trim();
    match (app.is_empty(), daemon.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!("gui v{app}"),
        (true, false) => format!("daemon v{daemon}"),
        (false, false) if app == daemon => format!("v{app}"),
        (false, false) => format!("gui v{app} · daemon v{daemon}"),
    }
}

fn copy_text(value: &str) {
    if let Some(display) = gtk::gdk::Display::default() {
        display.clipboard().set_text(value);
    }
}

fn configure_launch_on_startup(enabled: bool) -> Result<(), String> {
    let path = autostart_desktop_path().ok_or_else(|| "Autostart path unavailable".to_string())?;
    if enabled {
        let executable = std::env::current_exe()
            .map_err(|error| format!("App executable not found: {error}"))?;
        let parent = path
            .parent()
            .ok_or_else(|| "Autostart path unavailable".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create autostart directory: {error}"))?;
        std::fs::write(&path, autostart_desktop_entry(&executable))
            .map_err(|error| format!("Could not write autostart entry: {error}"))?;
    } else if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|error| format!("Could not remove autostart entry: {error}"))?;
    }
    Ok(())
}

fn autostart_desktop_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|config| config.join("autostart").join(format!("{}.desktop", crate::APP_ID)))
}

fn autostart_desktop_entry(executable: &std::path::Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=Nostr VPN\nExec={} --hidden\nIcon=nostr-vpn\nTerminal=false\nCategories=Network;Security;\nX-GNOME-Autostart-enabled=true\n",
        desktop_exec_escape(&executable.to_string_lossy())
    )
}

fn desktop_exec_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            ' ' | '\t'
                | '\n'
                | '"'
                | '\''
                | '\\'
                | '>'
                | '<'
                | '~'
                | '|'
                | '&'
                | ';'
                | '$'
                | '*'
                | '?'
                | '#'
                | '('
                | ')'
                | '`'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn default_data_dir() -> String {
    if let Some(data_dir) = std::env::var_os("NVPN_APP_DATA_DIR") {
        return PathBuf::from(data_dir).to_string_lossy().to_string();
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(data_home)
            .join("nostr-vpn")
            .to_string_lossy()
            .to_string();
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("nostr-vpn")
            .to_string_lossy()
            .to_string();
    }
    "nostr-vpn".to_string()
}

fn bootstrap_session_bus() {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return;
    }
    let socket = "/tmp/nostr-vpn-dbus.sock";
    if std::path::Path::new(socket).exists() {
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={socket}"));
    }
}

fn install_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

const CSS: &str = r#"
.nvpn-root,
.nvpn-content,
.nvpn-content viewport {
    background: @window_bg_color;
}

.nvpn-sidebar {
    padding: 8px;
    border-radius: 8px;
    background: alpha(@card_bg_color, 0.58);
}

.nvpn-sidebar-summary {
    padding: 8px 10px;
}

.nvpn-nav-button {
    padding: 8px 10px;
    border-radius: 8px;
}

.nvpn-nav-button.active {
    background: alpha(@accent_color, 0.14);
    color: @window_fg_color;
}

.nvpn-attention-dot {
    min-width: 8px;
    min-height: 8px;
    border-radius: 999px;
    background: @error_color;
}

.nvpn-card {
    padding: 16px;
    border-radius: 8px;
    background: @card_bg_color;
    box-shadow: inset 0 0 0 1px alpha(@window_fg_color, 0.08);
}

.nvpn-header-dot {
    min-width: 8px;
    min-height: 8px;
    border-radius: 999px;
    background: alpha(@window_fg_color, 0.4);
}

.nvpn-header-dot.ok {
    background: @success_color;
}

.nvpn-header-dot.warn {
    background: @warning_color;
}

.nvpn-header-dot.bad {
    background: @error_color;
}

.nvpn-header-status {
    font-size: 0.85em;
}

.nvpn-update-stripe {
    padding: 6px 16px;
    background: alpha(@window_fg_color, 0.05);
    box-shadow: inset 0 -1px 0 alpha(@window_fg_color, 0.08);
}

.nvpn-update-stripe label {
    font-size: 0.95em;
}

.nvpn-hero {
    padding: 20px;
}

.nvpn-status-ready,
.nvpn-status-active,
.nvpn-status-off,
.nvpn-status-blocked,
.nvpn-peer-online,
.nvpn-peer-offline {
    min-width: 14px;
    min-height: 14px;
    border-radius: 999px;
}

.nvpn-status-ready {
    min-width: 12px;
    min-height: 12px;
    background: @success_color;
}

.nvpn-status-active {
    min-width: 12px;
    min-height: 12px;
    background: @accent_color;
}

.nvpn-status-off {
    min-width: 12px;
    min-height: 12px;
    background: alpha(@window_fg_color, 0.22);
}

.nvpn-status-blocked {
    min-width: 12px;
    min-height: 12px;
    background: @error_color;
}

.nvpn-peer-online {
    background: @success_color;
}

.nvpn-peer-offline {
    background: alpha(@window_fg_color, 0.24);
}

.nvpn-device-row {
    padding: 10px;
    border-radius: 8px;
}

.nvpn-device-row.selected {
    background: alpha(@accent_color, 0.14);
}

.nvpn-route-choice {
    padding: 0;
}

.nvpn-route-choice > box {
    padding: 10px;
    border-radius: 8px;
    background: alpha(@window_fg_color, 0.04);
}

.nvpn-badge {
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 0.78em;
}

.nvpn-badge.ok {
    background: alpha(@success_color, 0.16);
    color: @success_color;
}

.nvpn-badge.warn {
    background: alpha(@warning_color, 0.16);
    color: @warning_color;
}

.nvpn-badge.bad {
    background: alpha(@error_color, 0.14);
    color: @error_color;
}

.nvpn-badge.muted {
    background: alpha(@window_fg_color, 0.08);
    color: alpha(@window_fg_color, 0.72);
}

.nvpn-metric {
    padding: 8px 10px;
    border-radius: 8px;
    background: alpha(@window_fg_color, 0.04);
}

.success,
.accent {
    color: @success_color;
}
"#;
