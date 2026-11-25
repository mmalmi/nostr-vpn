use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};

use glib::variant::ToVariant;
use image::{Rgba, RgbaImage};
use nostr_vpn_app_core::{NativeAppState, NativeNetworkState, NativeParticipantState};

use crate::APP_ID;

const SNI_BUS_NAME_PREFIX: &str = "org.kde.StatusNotifierItem";
const SNI_OBJECT_PATH: &str = "/StatusNotifierItem";
const MENU_OBJECT_PATH: &str = "/StatusNotifierItem/Menu";
const SNI_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";

const SNI_XML: &str = r#"
<node>
  <interface name='org.kde.StatusNotifierItem'>
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
    <method name='ContextMenu'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='Activate'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='SecondaryActivate'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='Scroll'>
      <arg type='i' name='delta' direction='in'/>
      <arg type='s' name='orientation' direction='in'/>
    </method>
    <signal name='NewTitle'/>
    <signal name='NewIcon'/>
    <signal name='NewAttentionIcon'/>
    <signal name='NewOverlayIcon'/>
    <signal name='NewToolTip'/>
    <signal name='NewStatus'>
      <arg type='s' name='status'/>
    </signal>
  </interface>
</node>
"#;

const MENU_XML: &str = r#"
<node>
  <interface name='com.canonical.dbusmenu'>
    <method name='GetLayout'>
      <arg type='i' name='parentId' direction='in'/>
      <arg type='i' name='recursionDepth' direction='in'/>
      <arg type='as' name='propertyNames' direction='in'/>
      <arg type='u' name='revision' direction='out'/>
      <arg type='(ia{sv}av)' name='layout' direction='out'/>
    </method>
    <method name='GetGroupProperties'>
      <arg type='ai' name='ids' direction='in'/>
      <arg type='as' name='propertyNames' direction='in'/>
      <arg type='a(ia{sv})' name='properties' direction='out'/>
    </method>
    <method name='GetProperty'>
      <arg type='i' name='id' direction='in'/>
      <arg type='s' name='name' direction='in'/>
      <arg type='v' name='value' direction='out'/>
    </method>
    <method name='Event'>
      <arg type='i' name='id' direction='in'/>
      <arg type='s' name='eventId' direction='in'/>
      <arg type='v' name='data' direction='in'/>
      <arg type='u' name='timestamp' direction='in'/>
    </method>
    <method name='AboutToShow'>
      <arg type='i' name='id' direction='in'/>
      <arg type='b' name='needUpdate' direction='out'/>
    </method>
    <signal name='ItemsPropertiesUpdated'>
      <arg type='a(ia{sv})' name='updatedProps'/>
      <arg type='a(ias)' name='removedProps'/>
    </signal>
    <signal name='LayoutUpdated'>
      <arg type='u' name='revision'/>
      <arg type='i' name='parent'/>
    </signal>
  </interface>
</node>
"#;

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

        let sni_info = match gio::DBusNodeInfo::for_xml(SNI_XML)
            .ok()
            .and_then(|node| node.lookup_interface(SNI_INTERFACE))
        {
            Some(info) => info,
            None => {
                *last_error.borrow_mut() =
                    Some("status notifier interface unavailable".to_string());
                return runtime;
            }
        };
        let menu_info = match gio::DBusNodeInfo::for_xml(MENU_XML)
            .ok()
            .and_then(|node| node.lookup_interface(MENU_INTERFACE))
        {
            Some(info) => info,
            None => {
                *last_error.borrow_mut() = Some("tray menu interface unavailable".to_string());
                return runtime;
            }
        };

        let sni_registration =
            register_sni_object(&connection, &sni_info, snapshot.clone(), sender.clone())
                .map_err(|error| {
                    *last_error.borrow_mut() = Some(format!("tray registration failed: {error}"));
                })
                .ok();

        let menu_registration = register_menu_object(
            &connection,
            &menu_info,
            snapshot,
            menu_revision.clone(),
            sender,
        )
        .map_err(|error| {
            *last_error.borrow_mut() = Some(format!("tray menu registration failed: {error}"));
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
                    if let Err(error) = connection.call_sync(
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
                        watcher_registered.set(false);
                        *last_error.borrow_mut() =
                            Some(format!("status notifier watcher unavailable: {error}"));
                    } else {
                        watcher_registered.set(true);
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
            let _ = connection.emit_signal(
                None,
                SNI_OBJECT_PATH,
                SNI_INTERFACE,
                "NewStatus",
                Some(&(sni_status(next.indicator),).to_variant()),
            );
            let _ = connection.emit_signal(None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewIcon", None);
        }
        if previous.tooltip != next.tooltip {
            let _ =
                connection.emit_signal(None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewToolTip", None);
        }
        if previous.menu != next.menu {
            let revision = self.menu_revision.get().wrapping_add(1).max(1);
            self.menu_revision.set(revision);
            let _ = connection.emit_signal(
                None,
                MENU_OBJECT_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                Some(&(revision, 0i32).to_variant()),
            );
        }
    }

    pub fn drain(&mut self) -> Vec<TrayCommand> {
        let mut commands = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            commands.push(command);
        }
        commands
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
        .method_call(
            move |_connection, _sender_name, _path, _interface, method, parameters, invocation| {
                let snapshot = snapshot.borrow();
                let root = &snapshot.menu;
                match method {
                    "GetLayout" => {
                        let parent = parameters.child_get::<i32>(0);
                        let node = find_menu_node(root, parent).unwrap_or(root);
                        // A Rust tuple holding a Variant serializes as `v`;
                        // build the reply tuple so the layout keeps its type.
                        invocation.return_value(Some(&glib::Variant::tuple_from_iter([
                            revision.get().to_variant(),
                            menu_node_layout(node),
                        ])));
                    }
                    "GetGroupProperties" => {
                        let ids = parameters.child_get::<Vec<i32>>(0);
                        let items = if ids.is_empty() {
                            menu_group_properties(root)
                        } else {
                            ids.into_iter()
                                .filter_map(|id| {
                                    find_menu_node(root, id).map(|node| {
                                        glib::Variant::tuple_from_iter([
                                            id.to_variant(),
                                            menu_properties(node).to_variant(),
                                        ])
                                    })
                                })
                                .collect::<Vec<_>>()
                        };
                        let item_type = glib::VariantTy::new("(ia{sv})").expect("menu item type");
                        let properties = glib::Variant::array_from_iter_with_type(item_type, items);
                        invocation
                            .return_value(Some(&glib::Variant::tuple_from_iter([properties])));
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
                        let event = parameters.child_get::<String>(1);
                        if event == "clicked" {
                            if let Some(command) =
                                find_menu_node(root, id).and_then(|node| node.command.clone())
                            {
                                let _ = sender.send(command);
                            }
                        }
                        invocation.return_value(None);
                    }
                    "AboutToShow" => {
                        invocation.return_value(Some(&(false,).to_variant()));
                    }
                    _ => invocation.return_value(None),
                }
            },
        )
        .build()
}

#[derive(Clone, PartialEq)]
struct MenuNode {
    id: i32,
    label: String,
    enabled: bool,
    separator: bool,
    /// Display as a checkmark toggle (None = no toggle indicator).
    /// Renders via dbusmenu `toggle-type=checkmark` + `toggle-state`.
    toggle: Option<bool>,
    /// PNG shown beside the label, used for status dots.
    icon: Option<Vec<u8>>,
    command: Option<TrayCommand>,
    children: Vec<MenuNode>,
}

/// Mirrors macOS `TrayController`: the VPN toggle, this device, the network,
/// where internet comes from, then private sharing and public selling kept
/// apart so it is clear who can use this device's connection.
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
        children.push(submenu(
            20,
            &display_network_name(network),
            network
                .participants
                .iter()
                .enumerate()
                .map(|(index, participant)| {
                    item(
                        1000 + index as i32,
                        &participant_menu_title(participant),
                        !participant.npub.is_empty(),
                        TrayCommand::CopyPeer(participant.npub.clone()),
                    )
                })
                .collect(),
        ));
    }

    let mut internet = vec![
        label_node(31, &internet_status(state)),
        separator(32),
        toggle_item(
            33,
            "This Device",
            true,
            state.internet_source == "direct",
            TrayCommand::SetInternetSource("direct".to_string()),
        ),
    ];
    if state.paid_route_market.supported {
        internet.push(toggle_item(
            34,
            "Paid Internet · Automatic · Experimental",
            true,
            state.internet_source == "paid_automatic",
            TrayCommand::SetInternetSource("paid_automatic".to_string()),
        ));
        internet.push(toggle_item(
            35,
            "Paid Internet · Manual",
            true,
            state.internet_source == "paid_manual",
            TrayCommand::SetInternetSource("paid_manual".to_string()),
        ));
    }
    internet.push(toggle_item(
        36,
        "WireGuard",
        state.wireguard_exit_configured,
        state.internet_source == "wireguard",
        TrayCommand::SetInternetSource("wireguard".to_string()),
    ));
    let exits = exit_candidates(state);
    if !exits.is_empty() {
        internet.push(separator(37));
        internet.extend(exits.iter().enumerate().map(|(index, participant)| {
            toggle_item(
                2000 + index as i32,
                &exit_node_label(participant),
                true,
                state.internet_source == "private_vpn" && state.exit_node == participant.npub,
                TrayCommand::SetExitNode(participant.npub.clone()),
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
    let child_variants = node
        .children
        .iter()
        .map(|child| menu_node_layout(child).to_variant())
        .collect::<Vec<_>>();
    glib::Variant::tuple_from_iter([
        node.id.to_variant(),
        menu_properties(node).to_variant(),
        glib::Variant::array_from_iter::<glib::Variant>(child_variants),
    ])
}

fn menu_group_properties(root: &MenuNode) -> Vec<glib::Variant> {
    let mut values = Vec::new();
    collect_menu_group_properties(root, &mut values);
    values
}

fn collect_menu_group_properties(node: &MenuNode, values: &mut Vec<glib::Variant>) {
    values.push(glib::Variant::tuple_from_iter([
        node.id.to_variant(),
        menu_properties(node).to_variant(),
    ]));
    for child in &node.children {
        collect_menu_group_properties(child, values);
    }
}

fn menu_properties(node: &MenuNode) -> HashMap<String, glib::Variant> {
    let mut properties = HashMap::new();
    properties.insert("visible".to_string(), true.to_variant());
    properties.insert("enabled".to_string(), node.enabled.to_variant());
    if node.separator {
        properties.insert("type".to_string(), "separator".to_variant());
    } else {
        // dbusmenu treats `_` as a mnemonic marker; device names may contain it.
        properties.insert(
            "label".to_string(),
            node.label.replace('_', "__").to_variant(),
        );
    }
    if let Some(icon) = &node.icon {
        properties.insert("icon-data".to_string(), icon.to_variant());
    }
    if let Some(on) = node.toggle {
        properties.insert("toggle-type".to_string(), "checkmark".to_variant());
        properties.insert(
            "toggle-state".to_string(),
            (if on { 1i32 } else { 0i32 }).to_variant(),
        );
    }
    if !node.children.is_empty() {
        properties.insert("children-display".to_string(), "submenu".to_variant());
    }
    properties
}

fn find_menu_node(node: &MenuNode, id: i32) -> Option<&MenuNode> {
    if node.id == id {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_menu_node(child, id))
}

/// Mirrors `AppManager.vpnStatusText` on macOS so the header and tray
/// surface the same status string. Linux currently has no dispatch-action
/// status field, so the actionInFlight branch is omitted.
pub fn vpn_status_text(state: &NativeAppState) -> String {
    if state.exit_node_blocked {
        return if state.exit_node_status_text.trim().is_empty() {
            "Internet blocked".to_string()
        } else {
            state.exit_node_status_text.clone()
        };
    }
    if state.exit_node_active && !state.exit_node_status_text.trim().is_empty() {
        return state.exit_node_status_text.clone();
    }
    if state.vpn_active {
        return if state.vpn_status.trim().is_empty() {
            "VPN on".to_string()
        } else {
            state.vpn_status.clone()
        };
    }
    if state.vpn_enabled {
        return if state.vpn_status.trim().is_empty() {
            "Turning on".to_string()
        } else {
            state.vpn_status.clone()
        };
    }
    if daemon_starting_status(state) {
        return state.vpn_status.clone();
    }
    "Off".to_string()
}

fn daemon_starting_status(state: &NativeAppState) -> bool {
    state.error.trim().is_empty()
        && state.service_running
        && state.vpn_status.trim() == "Background service starting"
}

fn device_display_name(state: &NativeAppState) -> String {
    if !state.self_magic_dns_name.trim().is_empty() {
        return state.self_magic_dns_name.clone();
    }
    if !state.node_name.trim().is_empty() {
        return state.node_name.clone();
    }
    let tunnel_ip = state.tunnel_ip.trim();
    if !tunnel_ip.is_empty() && tunnel_ip != "-" {
        return tunnel_ip.to_string();
    }
    "This Device".to_string()
}

fn exit_node_label(participant: &NativeParticipantState) -> String {
    if !participant.magic_dns_name.trim().is_empty() {
        return participant.magic_dns_name.clone();
    }
    if !participant.alias.trim().is_empty() {
        return participant.alias.clone();
    }
    if !participant.magic_dns_alias.trim().is_empty() {
        return participant.magic_dns_alias.clone();
    }
    "Device".to_string()
}

fn active_network(state: &NativeAppState) -> Option<&NativeNetworkState> {
    state
        .networks
        .iter()
        .find(|network| network.enabled)
        .or_else(|| state.networks.first())
}

fn display_network_name(network: &NativeNetworkState) -> String {
    if network.name.trim().is_empty() {
        "Network Devices".to_string()
    } else {
        network.name.clone()
    }
}

fn participant_menu_title(participant: &NativeParticipantState) -> String {
    let name = [
        participant.magic_dns_name.as_str(),
        participant.alias.as_str(),
        participant.magic_dns_alias.as_str(),
        participant.npub.as_str(),
    ]
    .into_iter()
    .find(|value| !value.trim().is_empty())
    .unwrap_or("Device");
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
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
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

/// Same states and colors as macOS `InternetExitIndicator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Indicator {
    Hidden,
    Connecting,
    Connected,
    Attention,
}

impl Indicator {
    fn color(self) -> Option<Rgba<u8>> {
        match self {
            Self::Hidden => None,
            Self::Connecting => Some(Rgba([255, 149, 0, 255])),
            Self::Connected => Some(Rgba([52, 199, 89, 255])),
            Self::Attention => Some(Rgba([255, 59, 48, 255])),
        }
    }
}

fn internet_indicator(state: &NativeAppState) -> Indicator {
    if !state.vpn_enabled || state.internet_source == "direct" {
        Indicator::Hidden
    } else if state.exit_node_needs_attention || state.exit_node_blocked {
        Indicator::Attention
    } else if state.exit_node_active {
        Indicator::Connected
    } else {
        Indicator::Connecting
    }
}

fn selling_indicator(state: &NativeAppState) -> Indicator {
    match (state.paid_exit_seller.enabled, state.paid_exit_seller.ready) {
        (false, _) => Indicator::Hidden,
        (true, true) => Indicator::Connected,
        (true, false) => Indicator::Connecting,
    }
}

fn tray_indicator(state: &NativeAppState) -> Indicator {
    let connection = internet_indicator(state);
    let selling = selling_indicator(state);
    if connection == Indicator::Attention {
        Indicator::Attention
    } else if connection == Indicator::Connecting
        || selling == Indicator::Connecting
        || (state.vpn_enabled && !state.vpn_active)
    {
        Indicator::Connecting
    } else if connection == Indicator::Connected
        || selling == Indicator::Connected
        || (state.vpn_enabled && state.vpn_active)
    {
        Indicator::Connected
    } else {
        Indicator::Hidden
    }
}

/// Keeps the icon visible in hosts that hide passive items (Waybar does by
/// default), as on macOS and Windows.
fn sni_status(indicator: Indicator) -> &'static str {
    if indicator == Indicator::Attention {
        "NeedsAttention"
    } else {
        "Active"
    }
}

fn empty_pixmaps() -> glib::Variant {
    glib::Variant::array_from_iter_with_type(
        glib::VariantTy::new("(iiay)").expect("icon pixmap type"),
        std::iter::empty::<glib::Variant>(),
    )
}

fn tray_icon(indicator: Indicator) -> glib::Variant {
    let icon_type = glib::VariantTy::new("(iiay)").expect("icon pixmap type");
    glib::Variant::array_from_iter_with_type(
        icon_type,
        [
            include_bytes!("../resources/nostr-vpn-tray-24.png").as_slice(),
            include_bytes!("../resources/nostr-vpn-tray-48.png").as_slice(),
        ]
        .into_iter()
        .map(|bytes| tray_icon_pixmap(bytes, indicator)),
    )
}

fn tray_icon_pixmap(bytes: &[u8], indicator: Indicator) -> glib::Variant {
    let mut image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("bundled tray icon is a valid PNG")
        .into_rgba8();
    if let Some(color) = indicator.color() {
        draw_badge(&mut image, color);
    }
    let (width, height) = image.dimensions();
    // StatusNotifierItem pixmaps are ARGB32 in network byte order.
    let mut data = image.into_vec();
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    glib::Variant::tuple_from_iter([
        (width as i32).to_variant(),
        (height as i32).to_variant(),
        data.to_variant(),
    ])
}

/// Status dot in the bottom-right corner. A transparent ring separates it
/// from the logo so the color reads on light and dark panels.
fn draw_badge(image: &mut RgbaImage, color: Rgba<u8>) {
    let size = image.width().min(image.height()) as f32;
    let radius = size * 0.2;
    let gap = (size / 16.0).max(1.5);
    paint_dot(image, size - radius - 0.5, radius, gap, color);
}

/// Antialiased dot at (center, center), clearing `gap` pixels around it.
fn paint_dot(image: &mut RgbaImage, center: f32, radius: f32, gap: f32, color: Rgba<u8>) {
    for y in 0..image.height() {
        for x in 0..image.width() {
            let dx = x as f32 + 0.5 - center;
            let dy = y as f32 + 0.5 - center;
            let distance = (dx * dx + dy * dy).sqrt();
            let pixel = image.get_pixel_mut(x, y);
            let keep = (distance - radius - gap + 0.5).clamp(0.0, 1.0);
            pixel[3] = (f32::from(pixel[3]) * keep).round() as u8;
            let fill = (radius + 0.5 - distance).clamp(0.0, 1.0);
            if fill > 0.0 {
                let alpha = f32::from(pixel[3]) / 255.0;
                let out = fill + alpha * (1.0 - fill);
                for channel in 0..3 {
                    pixel[channel] = ((f32::from(color[channel]) * fill
                        + f32::from(pixel[channel]) * alpha * (1.0 - fill))
                        / out)
                        .round() as u8;
                }
                pixel[3] = (out * 255.0).round() as u8;
            }
        }
    }
}

/// Small colored dot for menu items, matching the macOS submenu images.
fn dot_png(indicator: Indicator) -> Option<Vec<u8>> {
    let color = indicator.color()?;
    let mut image = RgbaImage::new(12, 12);
    paint_dot(&mut image, 6.0, 4.0, 0.0, color);
    let mut bytes = Vec::new();
    image
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .ok()?;
    Some(bytes)
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
            assert!(
                submenu
                    .children
                    .iter()
                    .all(|node| node.command != Some(TrayCommand::ToggleExitOffer))
            );
        }
        assert!(
            root.children
                .iter()
                .any(|node| node.label == "Sell Internet Publicly")
        );
    }
}
