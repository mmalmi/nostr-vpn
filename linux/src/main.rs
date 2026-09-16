mod deep_link;
mod qr;
mod qr_scan;
mod tray;
mod updater;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib};
use nostr_vpn_app_core::native_state::{
    NativePaidExitSellerState, NativePaidRouteOfferState, NativePaidRouteSessionState,
    NativePaidRouteWalletMintState,
};
use nostr_vpn_app_core::{
    FfiApp, NativeAppAction, NativeAppState, NativeNetworkState, NativeParticipantState,
    SettingsPatch, UpdateAutoCheckPolicy,
};

pub(crate) const APP_ID: &str = "fi.siriusbusiness.nvpn";
const DEFAULT_UPDATE_POLL_INTERVAL_SECS: u32 = 6 * 60 * 60;
const SEARCH_VISIBILITY_THRESHOLD: usize = 7;

thread_local! {
    static TRAY_APP_HOLD: RefCell<Option<gio::ApplicationHoldGuard>> = const { RefCell::new(None) };
}

type AppRef = Rc<RefCell<AppModel>>;

#[derive(Clone, Default)]
struct AppRuntime {
    model: Rc<RefCell<Option<AppRef>>>,
    pending_urls: Rc<RefCell<Vec<String>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Devices,
    Share,
    ExitNodes,
    PaidRoutes,
    SellInternet,
    Wallet,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkSetupMode {
    Create,
    Join,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct PageScrollOffsets {
    devices: f64,
    share: f64,
    exit_nodes: f64,
    paid_routes: f64,
    sell_internet: f64,
    wallet: f64,
    settings: f64,
}

impl PageScrollOffsets {
    fn get(self, page: Page) -> f64 {
        match page {
            Page::Devices => self.devices,
            Page::Share => self.share,
            Page::ExitNodes => self.exit_nodes,
            Page::PaidRoutes => self.paid_routes,
            Page::SellInternet => self.sell_internet,
            Page::Wallet => self.wallet,
            Page::Settings => self.settings,
        }
    }

    fn set(&mut self, page: Page, offset: f64) {
        match page {
            Page::Devices => self.devices = offset,
            Page::Share => self.share = offset,
            Page::ExitNodes => self.exit_nodes = offset,
            Page::PaidRoutes => self.paid_routes = offset,
            Page::SellInternet => self.sell_internet = offset,
            Page::Wallet => self.wallet = offset,
            Page::Settings => self.settings = offset,
        }
    }
}

#[derive(Clone, Default)]
struct Drafts {
    join_request: String,
    manual_admin_npub: String,
    manual_mesh_id: String,
    participant_npub: String,
    participant_alias: String,
    network_name: String,
    mesh_id: String,
    new_network_name: String,
    node_name: String,
    endpoint: String,
    tunnel_ip: String,
    listen_port: String,
    relay_input: String,
    fips_host_inbound_tcp_ports: String,
    advertised_routes: String,
    exit_search: String,
    wireguard_exit_config: String,
    exit_dns_mode: String,
    exit_dns_doh_provider: String,
    exit_dns_custom_doh_url: String,
    exit_dns_custom_doh_bootstrap_ips: String,
    exit_dns_through_exit_servers: String,
    paid_route_country: String,
    manual_paid_exit_provider: String,
    paid_exit_price_msat_per_gb: String,
    paid_exit_country_code: String,
    paid_exit_network_class: String,
    paid_exit_accepted_mints: String,
    paid_route_mint_url: String,
    paid_route_top_up_amount: String,
    paid_route_send_amount: String,
    paid_route_token: String,
    paid_route_withdraw_invoice: String,
}

impl Drafts {
    fn sync_from_state(&mut self, state: &NativeAppState) {
        self.node_name = state.node_name.clone();
        self.endpoint = state.endpoint.clone();
        self.tunnel_ip = state.tunnel_ip.clone();
        self.listen_port = state.listen_port.to_string();
        self.fips_host_inbound_tcp_ports = state.fips_host_inbound_tcp_ports.clone();
        self.advertised_routes = state.advertised_routes.join(", ");
        self.wireguard_exit_config = state.wireguard_exit_config.clone();
        self.exit_dns_mode = state.exit_dns_mode.clone();
        self.exit_dns_doh_provider = state.exit_dns_doh_provider.clone();
        self.exit_dns_custom_doh_url = state.exit_dns_custom_doh_url.clone();
        self.exit_dns_custom_doh_bootstrap_ips = state.exit_dns_custom_doh_bootstrap_ips.clone();
        self.exit_dns_through_exit_servers = state.exit_dns_through_exit_servers.clone();
        self.manual_paid_exit_provider = state.paid_route_market.manual_provider_link.clone();
        self.paid_exit_price_msat_per_gb = state.paid_exit_seller.price_msat_per_gb.to_string();
        self.paid_exit_country_code = state.paid_exit_seller.country_code.clone();
        self.paid_exit_network_class = state.paid_exit_seller.network_class.clone();
        self.paid_exit_accepted_mints = state.paid_exit_seller.accepted_mints.join(", ");
        if let Some(network) = active_network(state) {
            self.network_name = display_network_name(network);
            self.mesh_id = display_network_id(&network.network_id);
        } else {
            self.network_name = "Nostr VPN".to_string();
            self.mesh_id.clear();
        }
    }
}

struct AppModel {
    core: Arc<FfiApp>,
    state: NativeAppState,
    window: adw::ApplicationWindow,
    page: Page,
    rendered_page: Page,
    scroll_offsets: PageScrollOffsets,
    sidebar: gtk::Box,
    update_bar: gtk::Box,
    content: gtk::Box,
    header_status_label: gtk::Label,
    header_status_dot: gtk::Box,
    header_vpn_switch: gtk::Switch,
    selected_device_pubkey: Option<String>,
    drafts: Drafts,
    notice: String,
    tray: tray::TrayRuntime,
    tray_available: bool,
    tray_error: Option<String>,
    update: updater::UpdateState,
    update_policy: UpdateAutoCheckPolicy,
    update_sender: Sender<updater::UpdateEvent>,
    update_receiver: Receiver<updater::UpdateEvent>,
    add_network_join_status: String,
    network_setup_mode: Option<NetworkSetupMode>,
    allow_close: bool,
    service_settling: bool,
    render_pending: bool,
    manual_join_expanded: bool,
    diagnostics_expanded: bool,
}

impl AppModel {
    fn new(
        window: adw::ApplicationWindow,
        sidebar: gtk::Box,
        update_bar: gtk::Box,
        content: gtk::Box,
        header_status_label: gtk::Label,
        header_status_dot: gtk::Box,
        header_vpn_switch: gtk::Switch,
    ) -> Self {
        // Pass empty so the FFI falls back to its own CARGO_PKG_VERSION
        // (workspace-inherited). The linux crate is excluded from the workspace
        // so its CARGO_PKG_VERSION drifts from nostr-vpn-app-core's.
        let core = FfiApp::new(default_data_dir(), String::new());
        let state = core.state();
        let mut drafts = Drafts::default();
        drafts.sync_from_state(&state);
        let tray = tray::TrayRuntime::start(&state);
        let tray_available = tray.is_available();
        let tray_error = tray.last_error();
        let diagnostics_expanded = !state.health.is_empty();
        let (update_sender, update_receiver) = mpsc::channel();
        let update = updater::UpdateState {
            auto_install: load_auto_install_updates(),
            ..updater::UpdateState::default()
        };
        let update_policy =
            UpdateAutoCheckPolicy::new(Duration::from_secs(update_poll_interval_secs() as u64));
        Self {
            core,
            state,
            window,
            page: Page::Devices,
            rendered_page: Page::Devices,
            scroll_offsets: PageScrollOffsets::default(),
            sidebar,
            update_bar,
            content,
            header_status_label,
            header_status_dot,
            header_vpn_switch,
            selected_device_pubkey: None,
            drafts,
            notice: String::new(),
            tray,
            tray_available,
            tray_error,
            update,
            update_policy,
            update_sender,
            update_receiver,
            add_network_join_status: String::new(),
            network_setup_mode: None,
            allow_close: false,
            service_settling: false,
            render_pending: false,
            manual_join_expanded: false,
            diagnostics_expanded,
        }
    }
}

include!("main/startup.rs");
include!("main/runtime_events.rs");
include!("main/shell.rs");
include!("main/devices_page.rs");
include!("main/share_page.rs");
include!("main/exit_nodes_page.rs");
include!("main/paid_routes_page.rs");
include!("main/settings_page.rs");
include!("main/saved_networks.rs");
include!("main/widgets.rs");
include!("main/tests_and_selection.rs");
include!("main/utilities.rs");
