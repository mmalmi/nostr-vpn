use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};

use glib::variant::ToVariant;
use nostr_vpn_app_core::{NativeAppState, NativeNetworkState, NativeParticipantState};

use crate::APP_ID;

mod icons;
use icons::{
    dot_png, empty_pixmaps, internet_indicator, selling_indicator, sni_status, tray_icon,
    tray_indicator, Indicator,
};

const SNI_BUS_NAME_PREFIX: &str = "org.kde.StatusNotifierItem";
const SNI_OBJECT_PATH: &str = "/StatusNotifierItem";
const MENU_OBJECT_PATH: &str = "/StatusNotifierItem/Menu";
const SNI_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";

const SNI_XML: &str = r#"<node><interface name='org.kde.StatusNotifierItem'>
  <property name='Category' type='s' access='read'/>
  <property name='Id' type='s' access='read'/>
  <property name='Title' type='s' access='read'/>
  <property name='Status' type='s' access='read'/>
  <property name='WindowId' type='u' access='read'/>
  <property name='IconName' type='s' access='read'/>
  <property name='IconPixmap' type='a(iiay)' access='read'/>
  <property name='OverlayIconName' type='s' access='read'/>
  <property name='OverlayIconPixmap' type='a(iiay)' access='read'/>
  <property name='AttentionIconName' type='s' access='read'/>
  <property name='AttentionIconPixmap' type='a(iiay)' access='read'/>
  <property name='AttentionMovieName' type='s' access='read'/>
  <property name='ToolTip' type='(sa(iiay)ss)' access='read'/>
  <property name='ItemIsMenu' type='b' access='read'/>
  <property name='Menu' type='o' access='read'/>
  <method name='ContextMenu'><arg type='i' name='x' direction='in'/><arg type='i' name='y' direction='in'/></method>
  <method name='Activate'><arg type='i' name='x' direction='in'/><arg type='i' name='y' direction='in'/></method>
  <method name='SecondaryActivate'><arg type='i' name='x' direction='in'/><arg type='i' name='y' direction='in'/></method>
  <method name='Scroll'><arg type='i' name='delta' direction='in'/><arg type='s' name='orientation' direction='in'/></method>
  <signal name='NewTitle'/><signal name='NewIcon'/><signal name='NewAttentionIcon'/>
  <signal name='NewOverlayIcon'/><signal name='NewToolTip'/>
  <signal name='NewStatus'><arg type='s' name='status'/></signal>
</interface></node>"#;

const MENU_XML: &str = r#"<node><interface name='com.canonical.dbusmenu'>
  <method name='GetLayout'>
    <arg type='i' name='parentId' direction='in'/><arg type='i' name='recursionDepth' direction='in'/>
    <arg type='as' name='propertyNames' direction='in'/><arg type='u' name='revision' direction='out'/>
    <arg type='(ia{sv}av)' name='layout' direction='out'/>
  </method>
  <method name='GetGroupProperties'>
    <arg type='ai' name='ids' direction='in'/><arg type='as' name='propertyNames' direction='in'/>
    <arg type='a(ia{sv})' name='properties' direction='out'/>
  </method>
  <method name='GetProperty'>
    <arg type='i' name='id' direction='in'/><arg type='s' name='name' direction='in'/>
    <arg type='v' name='value' direction='out'/>
  </method>
  <method name='Event'>
    <arg type='i' name='id' direction='in'/><arg type='s' name='eventId' direction='in'/>
    <arg type='v' name='data' direction='in'/><arg type='u' name='timestamp' direction='in'/>
  </method>
  <method name='AboutToShow'>
    <arg type='i' name='id' direction='in'/><arg type='b' name='needUpdate' direction='out'/>
  </method>
  <signal name='ItemsPropertiesUpdated'>
    <arg type='a(ia{sv})' name='updatedProps'/><arg type='a(ias)' name='removedProps'/>
  </signal>
  <signal name='LayoutUpdated'>
    <arg type='u' name='revision'/><arg type='i' name='parent'/>
  </signal>
</interface></node>"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayCommand {
    ShowWindow,
    ToggleVpn,
    ToggleExitOffer,
    CopyDeviceId,
    CopyPeer(String),
    SetInternetSource(String),
    SetExitNode(String),
    OpenSellSettings,
    Quit,
}

/// Everything the D-Bus handlers serve, derived once per state change.
struct TraySnapshot {
    indicator: Indicator,
    icon: glib::Variant,
    tooltip: String,
    menu: MenuNode,
}

impl TraySnapshot {
    fn capture(state: &NativeAppState, previous: Option<&TraySnapshot>) -> Self {
        let indicator = tray_indicator(state);
        let icon = match previous {
            Some(previous) if previous.indicator == indicator => previous.icon.clone(),
            _ => tray_icon(indicator),
        };
        Self {
            indicator,
            icon,
            tooltip: tray_tooltip(state),
            menu: build_menu(state),
        }
    }
}

pub struct TrayRuntime {
    snapshot: Rc<RefCell<TraySnapshot>>,
    receiver: Receiver<TrayCommand>,
    connection: Option<gio::DBusConnection>,
    sni_registration: Option<gio::RegistrationId>,
    menu_registration: Option<gio::RegistrationId>,
    owner_id: Option<gio::OwnerId>,
    menu_revision: Rc<Cell<u32>>,
    last_error: Rc<RefCell<Option<String>>>,
    watcher_registered: Rc<Cell<bool>>,
}

fn dbus_interface(xml: &str, name: &str) -> Option<gio::DBusInterfaceInfo> {
    gio::DBusNodeInfo::for_xml(xml)
        .ok()
        .and_then(|node| node.lookup_interface(name))
}

fn emit_signal(
    connection: &gio::DBusConnection,
    path: &str,
    interface: &str,
    signal: &str,
    params: Option<&glib::Variant>,
) {
    let _ = connection.emit_signal(None, path, interface, signal, params);
}

impl TrayRuntime {
    pub fn start(state: &NativeAppState) -> Self {
        let (sender, receiver) = mpsc::channel();
        let snapshot = Rc::new(RefCell::new(TraySnapshot::capture(state, None)));
        let menu_revision = Rc::new(Cell::new(1));
        let last_error = Rc::new(RefCell::new(None));
        let watcher_registered = Rc::new(Cell::new(false));
        let mut runtime = Self {
            snapshot: snapshot.clone(),
            receiver,
            connection: None,
            sni_registration: None,
            menu_registration: None,
            owner_id: None,
            menu_revision: menu_revision.clone(),
            last_error: last_error.clone(),
            watcher_registered: watcher_registered.clone(),
        };

        let connection = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
            Ok(connection) => connection,
            Err(error) => {
                *last_error.borrow_mut() = Some(format!("session bus unavailable: {error}"));
                return runtime;
            }
        };
        let Some(sni_info) = dbus_interface(SNI_XML, SNI_INTERFACE) else {
            *last_error.borrow_mut() = Some("status notifier interface unavailable".to_string());
            return runtime;
        };
        let Some(menu_info) = dbus_interface(MENU_XML, MENU_INTERFACE) else {
            *last_error.borrow_mut() = Some("tray menu interface unavailable".to_string());
            return runtime;
        };

        let sni_registration =
            register_sni_object(&connection, &sni_info, snapshot.clone(), sender.clone())
                .map_err(|error| {
                    *last_error.borrow_mut() = Some(format!("tray registration failed: {error}"));
                })
                .ok();
        let menu_registration =
            register_menu_object(&connection, &menu_info, snapshot, menu_revision, sender)
                .map_err(|error| {
                    *last_error.borrow_mut() =
                        Some(format!("tray menu registration failed: {error}"));
                })
                .ok();

        let bus_name = format!("{SNI_BUS_NAME_PREFIX}-{}-1", std::process::id());
        let owner_id = {
            let bus_name_for_register = bus_name.clone();
            let last_error = last_error.clone();
            let watcher_registered = watcher_registered.clone();
            gio::bus_own_name_on_connection(
                &connection,
                &bus_name,
                gio::BusNameOwnerFlags::NONE,
                move |connection, _name| {
                    let parameters = (bus_name_for_register.as_str(),).to_variant();
                    match connection.call_sync(
                        Some("org.kde.StatusNotifierWatcher"),
                        "/StatusNotifierWatcher",
                        "org.kde.StatusNotifierWatcher",
                        "RegisterStatusNotifierItem",
                        Some(&parameters),
                        None,
                        gio::DBusCallFlags::NONE,
                        1000,
                        gio::Cancellable::NONE,
                    ) {
                        Ok(_) => watcher_registered.set(true),
                        Err(error) => {
                            watcher_registered.set(false);
                            *last_error.borrow_mut() =
                                Some(format!("status notifier watcher unavailable: {error}"));
                        }
                    }
                },
                |_connection, _name| {},
            )
        };

        runtime.connection = Some(connection);
        runtime.sni_registration = sni_registration;
        runtime.menu_registration = menu_registration;
        runtime.owner_id = Some(owner_id);
        runtime
    }

    /// Signals only what changed: a layout update makes hosts rebuild the
    /// menu, which closes a submenu the user has open.
    pub fn update(&self, state: &NativeAppState) {
        let next = TraySnapshot::capture(state, Some(&self.snapshot.borrow()));
        let previous = self.snapshot.replace(next);
        let next = self.snapshot.borrow();
        let Some(connection) = &self.connection else {
            return;
        };
        if previous.indicator != next.indicator {
            let status = (sni_status(next.indicator),).to_variant();
            emit_signal(
                connection,
                SNI_OBJECT_PATH,
                SNI_INTERFACE,
                "NewStatus",
                Some(&status),
            );
            emit_signal(connection, SNI_OBJECT_PATH, SNI_INTERFACE, "NewIcon", None);
        }
        if previous.tooltip != next.tooltip {
            emit_signal(
                connection,
                SNI_OBJECT_PATH,
                SNI_INTERFACE,
                "NewToolTip",
                None,
            );
        }
        if previous.menu != next.menu {
            let revision = self.menu_revision.get().wrapping_add(1).max(1);
            self.menu_revision.set(revision);
            let params = (revision, 0i32).to_variant();
            emit_signal(
                connection,
                MENU_OBJECT_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                Some(&params),
            );
        }
    }

    pub fn drain(&mut self) -> Vec<TrayCommand> {
        self.receiver.try_iter().collect()
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.borrow().clone()
    }

    pub fn is_available(&self) -> bool {
        self.connection.is_some()
            && self.sni_registration.is_some()
            && self.menu_registration.is_some()
            && self.owner_id.is_some()
            && self.watcher_registered.get()
    }
}

impl Drop for TrayRuntime {
    fn drop(&mut self) {
        if let Some(owner_id) = self.owner_id.take() {
            gio::bus_unown_name(owner_id);
        }
        if let Some(connection) = &self.connection {
            if let Some(registration) = self.sni_registration.take() {
                let _ = connection.unregister_object(registration);
            }
            if let Some(registration) = self.menu_registration.take() {
                let _ = connection.unregister_object(registration);
            }
        }
    }
}

fn register_sni_object(
    connection: &gio::DBusConnection,
    interface_info: &gio::DBusInterfaceInfo,
    snapshot: Rc<RefCell<TraySnapshot>>,
    sender: Sender<TrayCommand>,
) -> Result<gio::RegistrationId, glib::Error> {
    connection
        .register_object(SNI_OBJECT_PATH, interface_info)
        .method_call({
            let sender = sender.clone();
            move |_connection, _sender_name, _path, _interface, method, _parameters, invocation| {
                match method {
                    "Activate" | "ContextMenu" => {
                        let _ = sender.send(TrayCommand::ShowWindow);
                    }
                    "SecondaryActivate" => {
                        let _ = sender.send(TrayCommand::ToggleVpn);
                    }
                    _ => {}
                }
                invocation.return_value(None);
            }
        })
        .property(
            move |_connection, _sender_name, _path, _interface, property| {
                let snapshot = snapshot.borrow();
                match property {
                    "Category" => "ApplicationStatus".to_variant(),
                    "Id" => APP_ID.to_variant(),
                    "Title" => "Nostr VPN".to_variant(),
                    "Status" => sni_status(snapshot.indicator).to_variant(),
                    "WindowId" => 0u32.to_variant(),
                    // Hosts prefer a themed icon name over pixmaps, which would
                    // hide the status dot drawn into the pixmap.
                    "IconName" | "OverlayIconName" | "AttentionIconName" | "AttentionMovieName" => {
                        String::new().to_variant()
                    }
                    "IconPixmap" | "AttentionIconPixmap" => snapshot.icon.clone(),
                    "OverlayIconPixmap" => empty_pixmaps(),
                    "ToolTip" => glib::Variant::tuple_from_iter([
                        String::new().to_variant(),
                        empty_pixmaps(),
                        "Nostr VPN".to_variant(),
                        glib::markup_escape_text(&snapshot.tooltip).to_variant(),
                    ]),
                    "ItemIsMenu" => false.to_variant(),
                    "Menu" => glib::variant::ObjectPath::try_from(MENU_OBJECT_PATH)
                        .expect("menu object path")
                        .to_variant(),
                    _ => glib::Variant::from_none(glib::VariantTy::VARIANT),
                }
            },
        )
        .build()
}

fn register_menu_object(
    connection: &gio::DBusConnection,
    interface_info: &gio::DBusInterfaceInfo,
    snapshot: Rc<RefCell<TraySnapshot>>,
    revision: Rc<Cell<u32>>,
    sender: Sender<TrayCommand>,
) -> Result<gio::RegistrationId, glib::Error> {
    connection
        .register_object(MENU_OBJECT_PATH, interface_info)
        .method_call(move |_, _, _, _, method, parameters, invocation| {
            let snapshot = snapshot.borrow();
            let root = &snapshot.menu;
            match method {
                "GetLayout" => {
                    let node = find_menu_node(root, parameters.child_get::<i32>(0)).unwrap_or(root);
                    // A Rust tuple holding a Variant serializes as `v`; build explicitly.
                    invocation.return_value(Some(&glib::Variant::tuple_from_iter([
                        revision.get().to_variant(),
                        menu_node_layout(node),
                    ])));
                }
                "GetGroupProperties" => {
                    let ids = parameters.child_get::<Vec<i32>>(0);
                    let mut items = Vec::new();
                    if ids.is_empty() {
                        collect_menu_group_properties(root, &mut items);
                    } else {
                        items.extend(
                            ids.into_iter()
                                .filter_map(|id| find_menu_node(root, id))
                                .map(menu_group_entry),
                        );
                    }
                    let item_type = glib::VariantTy::new("(ia{sv})").expect("menu item type");
                    let properties = glib::Variant::array_from_iter_with_type(item_type, items);
                    invocation.return_value(Some(&glib::Variant::tuple_from_iter([properties])));
                }
                "GetProperty" => {
                    let id = parameters.child_get::<i32>(0);
                    let name = parameters.child_get::<String>(1);
                    let value = find_menu_node(root, id)
                        .and_then(|node| menu_properties(node).remove(&name))
                        .unwrap_or_else(|| false.to_variant());
                    invocation.return_value(Some(&(value,).to_variant()));
                }
                "Event" => {
                    let id = parameters.child_get::<i32>(0);
                    if parameters.child_get::<String>(1) == "clicked" {
                        if let Some(command) =
                            find_menu_node(root, id).and_then(|node| node.command.clone())
                        {
                            let _ = sender.send(command);
                        }
                    }
                    invocation.return_value(None);
                }
                "AboutToShow" => invocation.return_value(Some(&(false,).to_variant())),
                _ => invocation.return_value(None),
            }
        })
        .build()
}

#[derive(Clone, PartialEq)]
struct MenuNode {
    id: i32,
    label: String,
    enabled: bool,
    separator: bool,
    /// Display as a checkmark toggle (`None` = no toggle indicator).
    toggle: Option<bool>,
    /// Cached PNG shown beside the label, used for status dots.
    icon: Option<&'static [u8]>,
    command: Option<TrayCommand>,
    children: Vec<MenuNode>,
}

/// Mirrors macOS `TrayController`: the VPN toggle, this device, the network,
/// where internet comes from, then private sharing and public selling kept apart.
fn build_menu(state: &NativeAppState) -> MenuNode {
    let network = active_network(state);
    let mut children = vec![
        toggle_item(
            1,
            "Nostr VPN",
            state.vpn_control_supported,
            state.vpn_enabled,
            TrayCommand::ToggleVpn,
        ),
        label_node(2, &vpn_status_text(state)),
        separator(3),
        label_node(4, &device_display_name(state)),
        item(
            5,
            "Copy Device ID",
            !state.own_npub.is_empty(),
            TrayCommand::CopyDeviceId,
        ),
        separator(6),
    ];

    if let Some(network) = network {
        let peers = network
            .participants
            .iter()
            .enumerate()
            .map(|(index, p)| {
                item(
                    1000 + index as i32,
                    &participant_menu_title(p),
                    !p.npub.is_empty(),
                    TrayCommand::CopyPeer(p.npub.clone()),
                )
            })
            .collect();
        children.push(submenu(20, &display_network_name(network), peers));
    }

    let source_toggle = |id, label, enabled, source: &str| {
        toggle_item(
            id,
            label,
            enabled,
            state.internet_source == source,
            TrayCommand::SetInternetSource(source.to_string()),
        )
    };
    let mut internet = vec![
        label_node(31, &internet_status(state)),
        separator(32),
        source_toggle(33, "This Device", true, "direct"),
    ];
    if state.paid_route_market.supported {
        internet.push(source_toggle(
            34,
            "Paid Internet · Automatic · Experimental",
            true,
            "paid_automatic",
        ));
        internet.push(source_toggle(
            35,
            "Paid Internet · Manual",
            true,
            "paid_manual",
        ));
    }
    internet.push(source_toggle(
        36,
        "WireGuard",
        state.wireguard_exit_configured,
        "wireguard",
    ));
    let exits = exit_candidates(state);
    if !exits.is_empty() {
        internet.push(separator(37));
        internet.extend(exits.iter().enumerate().map(|(index, p)| {
            toggle_item(
                2000 + index as i32,
                &exit_node_label(p),
                true,
                state.internet_source == "private_vpn" && state.exit_node == p.npub,
                TrayCommand::SetExitNode(p.npub.clone()),
            )
        }));
    }
    let mut internet = submenu(
        30,
        &format!("Internet · {}", internet_title(state)),
        internet,
    );
    internet.icon = dot_png(internet_indicator(state));
    children.push(internet);

    children.push(separator(40));
    children.push(toggle_item(
        41,
        &share_label(network),
        true,
        state.advertise_exit_node,
        TrayCommand::ToggleExitOffer,
    ));
    let seller = &state.paid_exit_seller;
    if seller.supported {
        let mut sell = submenu(
            50,
            "Sell Internet Publicly",
            vec![
                label_node(51, "Anyone can pay to use this connection"),
                label_node(52, &seller_status_text(seller)),
                label_node(
                    53,
                    &format!(
                        "Uplink: {}",
                        non_empty(&seller.internet_text, "This device")
                    ),
                ),
                separator(54),
                item(55, "Settings…", true, TrayCommand::OpenSellSettings),
            ],
        );
        sell.icon = dot_png(selling_indicator(state));
        children.push(sell);
    }

    children.extend([
        separator(8),
        item(9, "Open Nostr VPN", true, TrayCommand::ShowWindow),
        item(10, "Quit", true, TrayCommand::Quit),
    ]);

    let mut root = submenu(0, "", children);
    root.enabled = true;
    root
}

fn share_label(network: Option<&NativeNetworkState>) -> String {
    match network.map(|network| network.name.trim()) {
        Some(name) if !name.is_empty() => format!("Share Internet with {name}"),
        _ => "Share Internet with Trusted Devices".to_string(),
    }
}

fn exit_candidates(state: &NativeAppState) -> Vec<&NativeParticipantState> {
    active_network(state)
        .map(|network| {
            network
                .participants
                .iter()
                .filter(|participant| participant.offers_exit_node && !is_self(participant, state))
                .collect()
        })
        .unwrap_or_default()
}

fn is_self(participant: &NativeParticipantState, state: &NativeAppState) -> bool {
    (!state.own_npub.is_empty() && participant.npub == state.own_npub)
        || (!state.own_pubkey_hex.is_empty() && participant.pubkey_hex == state.own_pubkey_hex)
        || participant.mesh_state == "local"
}

fn item(id: i32, label: &str, enabled: bool, command: TrayCommand) -> MenuNode {
    MenuNode {
        id,
        label: label.to_string(),
        enabled,
        separator: false,
        toggle: None,
        icon: None,
        command: Some(command),
        children: Vec::new(),
    }
}

fn toggle_item(id: i32, label: &str, enabled: bool, on: bool, command: TrayCommand) -> MenuNode {
    MenuNode {
        toggle: Some(on),
        ..item(id, label, enabled, command)
    }
}

fn submenu(id: i32, label: &str, children: Vec<MenuNode>) -> MenuNode {
    MenuNode {
        command: None,
        children,
        ..item(id, label, true, TrayCommand::ShowWindow)
    }
}

fn separator(id: i32) -> MenuNode {
    MenuNode {
        separator: true,
        ..label_node(id, "")
    }
}

fn label_node(id: i32, label: &str) -> MenuNode {
    MenuNode {
        command: None,
        ..item(id, label, false, TrayCommand::ShowWindow)
    }
}

fn menu_node_layout(node: &MenuNode) -> glib::Variant {
    let children = node
        .children
        .iter()
        .map(|c| menu_node_layout(c).to_variant())
        .collect::<Vec<_>>();
    glib::Variant::tuple_from_iter([
        node.id.to_variant(),
        menu_properties(node).to_variant(),
        glib::Variant::array_from_iter::<glib::Variant>(children),
    ])
}

fn menu_group_entry(node: &MenuNode) -> glib::Variant {
    glib::Variant::tuple_from_iter([node.id.to_variant(), menu_properties(node).to_variant()])
}

fn collect_menu_group_properties(node: &MenuNode, values: &mut Vec<glib::Variant>) {
    values.push(menu_group_entry(node));
    for child in &node.children {
        collect_menu_group_properties(child, values);
    }
}

fn menu_properties(node: &MenuNode) -> HashMap<String, glib::Variant> {
    let mut props = HashMap::from([
        ("visible".to_string(), true.to_variant()),
        ("enabled".to_string(), node.enabled.to_variant()),
    ]);
    if node.separator {
        props.insert("type".to_string(), "separator".to_variant());
    } else {
        // dbusmenu treats `_` as a mnemonic marker; device names may contain it.
        props.insert(
            "label".to_string(),
            node.label.replace('_', "__").to_variant(),
        );
    }
    if let Some(icon) = node.icon {
        props.insert("icon-data".to_string(), icon.to_variant());
    }
    if let Some(on) = node.toggle {
        props.insert("toggle-type".to_string(), "checkmark".to_variant());
        props.insert("toggle-state".to_string(), i32::from(on).to_variant());
    }
    if !node.children.is_empty() {
        props.insert("children-display".to_string(), "submenu".to_variant());
    }
    props
}

fn find_menu_node(node: &MenuNode, id: i32) -> Option<&MenuNode> {
    if node.id == id {
        Some(node)
    } else {
        node.children
            .iter()
            .find_map(|child| find_menu_node(child, id))
    }
}

/// Mirrors `AppManager.vpnStatusText` on macOS so the header and tray
/// surface the same status string.
pub fn vpn_status_text(state: &NativeAppState) -> String {
    if state.exit_node_blocked {
        return non_empty(&state.exit_node_status_text, "Internet blocked");
    }
    if state.exit_node_active && !state.exit_node_status_text.trim().is_empty() {
        return state.exit_node_status_text.clone();
    }
    if state.vpn_active {
        return non_empty(&state.vpn_status, "VPN on");
    }
    if state.vpn_enabled {
        return non_empty(&state.vpn_status, "Turning on");
    }
    if state.error.trim().is_empty()
        && state.service_running
        && state.vpn_status.trim() == "Background service starting"
    {
        return state.vpn_status.clone();
    }
    "Off".to_string()
}

fn first_non_empty<'a>(candidates: &[&'a str], fallback: &'a str) -> &'a str {
    candidates
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
}

fn device_display_name(state: &NativeAppState) -> String {
    let tunnel_ip = match state.tunnel_ip.trim() {
        "" | "-" => "",
        value => value,
    };
    first_non_empty(
        &[&state.self_magic_dns_name, &state.node_name, tunnel_ip],
        "This Device",
    )
    .to_string()
}

fn exit_node_label(participant: &NativeParticipantState) -> String {
    first_non_empty(
        &[
            &participant.magic_dns_name,
            &participant.alias,
            &participant.magic_dns_alias,
        ],
        "Device",
    )
    .to_string()
}

fn active_network(state: &NativeAppState) -> Option<&NativeNetworkState> {
    state
        .networks
        .iter()
        .find(|network| network.enabled)
        .or_else(|| state.networks.first())
}

fn display_network_name(network: &NativeNetworkState) -> String {
    non_empty(&network.name, "Network Devices")
}

fn participant_menu_title(participant: &NativeParticipantState) -> String {
    let name = first_non_empty(
        &[
            &participant.magic_dns_name,
            &participant.alias,
            &participant.magic_dns_alias,
            &participant.npub,
        ],
        "Device",
    );
    let tunnel_ip = participant.tunnel_ip.trim();
    if tunnel_ip.is_empty() || tunnel_ip == "-" {
        name.to_string()
    } else {
        format!("{name} ({tunnel_ip})")
    }
}

fn internet_title(state: &NativeAppState) -> String {
    match state.internet_source.as_str() {
        "wireguard" => "WireGuard".to_string(),
        "private_vpn" => exit_candidates(state)
            .into_iter()
            .find(|participant| participant.npub == state.exit_node)
            .map(exit_node_label)
            .unwrap_or_else(|| "Private VPN".to_string()),
        "paid_automatic" => "Automatic".to_string(),
        "paid_manual" => "Paid VPN".to_string(),
        _ => "Direct".to_string(),
    }
}

fn internet_status(state: &NativeAppState) -> String {
    if !state.exit_node_status_text.trim().is_empty() {
        state.exit_node_status_text.clone()
    } else if state.internet_source == "direct" {
        "Using device internet".to_string()
    } else {
        vpn_status_text(state)
    }
}

fn seller_status_text(
    seller: &nostr_vpn_app_core::native_state::NativePaidExitSellerState,
) -> String {
    if !seller.enabled {
        "Off".to_string()
    } else {
        non_empty(
            &seller.status_text,
            if seller.ready { "Ready" } else { "Waiting" },
        )
    }
}

fn non_empty(value: &str, fallback: &str) -> String {
    first_non_empty(&[value], fallback).to_string()
}

fn tray_tooltip(state: &NativeAppState) -> String {
    let mut tooltip = format!(
        "VPN: {}\nInternet: {} · {}",
        vpn_status_text(state),
        internet_title(state),
        internet_status(state)
    );
    if state.advertise_exit_node {
        tooltip.push_str("\nSharing internet with trusted devices");
    }
    let seller = &state.paid_exit_seller;
    if seller.enabled {
        tooltip.push_str(&format!(
            "\nSelling internet · {}",
            seller_status_text(seller)
        ));
    }
    tooltip
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(node: &MenuNode, out: &mut Vec<i32>) {
        out.push(node.id);
        node.children.iter().for_each(|child| ids(child, out));
    }

    #[test]
    fn menu_layout_has_unique_ids_and_keeps_private_sharing_apart_from_selling() {
        let mut state = NativeAppState::default();
        state.paid_exit_seller.supported = true;
        let root = build_menu(&state);
        assert_eq!(menu_node_layout(&root).type_().as_str(), "(ia{sv}av)");
        let reply = glib::Variant::tuple_from_iter([1u32.to_variant(), menu_node_layout(&root)]);
        assert_eq!(reply.type_().as_str(), "(u(ia{sv}av))");

        let mut all = Vec::new();
        ids(&root, &mut all);
        let count = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), count, "dbusmenu ids must be unique");

        let share = root
            .children
            .iter()
            .find(|node| node.command == Some(TrayCommand::ToggleExitOffer))
            .expect("private sharing is a top-level toggle");
        assert_eq!(share.label, "Share Internet with Trusted Devices");
        for submenu in root
            .children
            .iter()
            .filter(|node| !node.children.is_empty())
        {
            assert!(submenu
                .children
                .iter()
                .all(|node| node.command != Some(TrayCommand::ToggleExitOffer)));
        }
        assert!(root
            .children
            .iter()
            .any(|node| node.label == "Sell Internet Publicly"));
    }
}
