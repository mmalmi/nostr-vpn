use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};

use glib::variant::ToVariant;
use image::{GenericImageView, Rgba, RgbaImage};
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

#[derive(Debug, Clone)]
pub enum TrayCommand {
    ShowWindow,
    ToggleVpn,
    ToggleExitOffer,
    CopyDeviceId,
    CopyPeer(String),
    SetInternetSource(String),
    SetExitNode(String),
    Quit,
}

pub struct TrayRuntime {
    state: Rc<RefCell<NativeAppState>>,
    receiver: Receiver<TrayCommand>,
    connection: Option<gio::DBusConnection>,
    sni_registration: Option<gio::RegistrationId>,
    menu_registration: Option<gio::RegistrationId>,
    owner_id: Option<gio::OwnerId>,
    menu_revision: Rc<RefCell<u32>>,
    last_error: Rc<RefCell<Option<String>>>,
    watcher_registered: Rc<Cell<bool>>,
}

impl TrayRuntime {
    pub fn start(state: &NativeAppState) -> Self {
        let (sender, receiver) = mpsc::channel();
        let state = Rc::new(RefCell::new(state.clone()));
        let menu_revision = Rc::new(RefCell::new(1));
        let last_error = Rc::new(RefCell::new(None));
        let watcher_registered = Rc::new(Cell::new(false));
        let mut runtime = Self {
            state: state.clone(),
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
            register_sni_object(&connection, &sni_info, state.clone(), sender.clone())
                .map_err(|error| {
                    *last_error.borrow_mut() = Some(format!("tray registration failed: {error}"));
                })
                .ok();

        let menu_registration = register_menu_object(
            &connection,
            &menu_info,
            state.clone(),
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

    pub fn update(&self, state: &NativeAppState) {
        self.state.replace(state.clone());
        let next_revision = self.menu_revision.borrow().wrapping_add(1).max(1);
        *self.menu_revision.borrow_mut() = next_revision;
        if let Some(connection) = &self.connection {
            let _ = connection.emit_signal(
                None,
                SNI_OBJECT_PATH,
                SNI_INTERFACE,
                "NewStatus",
                Some(&(sni_status(state),).to_variant()),
            );
            let _ = connection.emit_signal(None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewIcon", None);
            let _ =
                connection.emit_signal(None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewToolTip", None);
            let _ = connection.emit_signal(
                None,
                MENU_OBJECT_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                Some(&(*self.menu_revision.borrow(), 0i32).to_variant()),
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
    state: Rc<RefCell<NativeAppState>>,
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
                let state = state.borrow();
                let icon = tray_icon(state.exit_node_blocked);
                match property {
                    "Category" => "ApplicationStatus".to_variant(),
                    "Id" => APP_ID.to_variant(),
                    "Title" => "Nostr VPN".to_variant(),
                    "Status" => sni_status(&state).to_variant(),
                    "WindowId" => 0u32.to_variant(),
                    "IconName" => "nostr-vpn".to_variant(),
                    "IconPixmap" | "OverlayIconPixmap" | "AttentionIconPixmap" => icon.clone(),
                    "OverlayIconName" | "AttentionIconName" | "AttentionMovieName" => {
                        String::new().to_variant()
                    }
                    "ToolTip" => glib::Variant::tuple_from_iter([
                        "nostr-vpn".to_variant(),
                        icon.clone(),
                        "Nostr VPN".to_variant(),
                        tray_status(&state).to_variant(),
                    ]),
                    "ItemIsMenu" => false.to_variant(),
                    "Menu" => MENU_OBJECT_PATH.to_variant(),
                    _ => glib::Variant::from_none(glib::VariantTy::VARIANT),
                }
            },
        )
        .build()
}

fn register_menu_object(
    connection: &gio::DBusConnection,
    interface_info: &gio::DBusInterfaceInfo,
    state: Rc<RefCell<NativeAppState>>,
    revision: Rc<RefCell<u32>>,
    sender: Sender<TrayCommand>,
) -> Result<gio::RegistrationId, glib::Error> {
    connection
        .register_object(MENU_OBJECT_PATH, interface_info)
        .method_call(
            move |_connection, _sender_name, _path, _interface, method, parameters, invocation| {
                let state = state.borrow();
                let root = build_menu(&state);
                match method {
                    "GetLayout" => {
                        invocation.return_value(Some(
                            &(*revision.borrow(), menu_node_layout(&root)).to_variant(),
                        ));
                    }
                    "GetGroupProperties" => {
                        let ids = parameters.child_get::<Vec<i32>>(0);
                        let items = if ids.is_empty() {
                            menu_group_properties(&root)
                        } else {
                            ids.into_iter()
                                .filter_map(|id| {
                                    find_menu_node(&root, id).map(|node| {
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
                        invocation.return_value(Some(&(properties,).to_variant()));
                    }
                    "GetProperty" => {
                        let id = parameters.child_get::<i32>(0);
                        let name = parameters.child_get::<String>(1);
                        let value = find_menu_node(&root, id)
                            .and_then(|node| menu_properties(node).remove(&name))
                            .unwrap_or_else(|| false.to_variant());
                        invocation.return_value(Some(&(value,).to_variant()));
                    }
                    "Event" => {
                        let id = parameters.child_get::<i32>(0);
                        let event = parameters.child_get::<String>(1);
                        if event == "clicked" {
                            if let Some(command) =
                                find_menu_node(&root, id).and_then(|node| node.command.clone())
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

#[derive(Clone)]
struct MenuNode {
    id: i32,
    label: String,
    enabled: bool,
    separator: bool,
    /// Display as a checkmark toggle (None = no toggle indicator).
    /// Renders via dbusmenu `toggle-type=checkmark` + `toggle-state`.
    toggle: Option<bool>,
    command: Option<TrayCommand>,
    children: Vec<MenuNode>,
}

fn build_menu(state: &NativeAppState) -> MenuNode {
    // 1. VPN toggle (first), 2. device-name section, 3. network/exit submenus,
    // 4. open/quit. See macOS TrayController.swift for the canonical layout.
    let mut children = vec![
        toggle_item(
            1,
            "Nostr VPN",
            state.vpn_control_supported,
            state.vpn_enabled,
            TrayCommand::ToggleVpn,
        ),
        // Status subtitle right below the toggle, mirrors macOS subtitle line.
        label_node(2, &vpn_status_text(state), false),
        separator(3),
        label_node(4, &device_display_name(state), false),
        item(
            5,
            "Copy Device ID",
            !state.own_npub.is_empty(),
            TrayCommand::CopyDeviceId,
        ),
        separator(6),
    ];

    if let Some(network) = active_network(state) {
        children.push(MenuNode {
            id: 20,
            label: display_network_name(network),
            enabled: true,
            separator: false,
            toggle: None,
            command: None,
            children: network
                .participants
                .iter()
                .enumerate()
                .map(|(index, participant)| {
                    item(
                        100 + index as i32,
                        &participant_menu_title(participant),
                        !participant.npub.is_empty(),
                        TrayCommand::CopyPeer(participant.npub.clone()),
                    )
                })
                .collect(),
        });

        let mut exit_children: Vec<MenuNode> = Vec::new();
        let status = tray_status(state);
        if !status.is_empty() {
            exit_children.push(label_node(29, &status, false));
        }
        exit_children.push(toggle_item(
            30,
            "Share This Device",
            true,
            state.advertise_exit_node,
            TrayCommand::ToggleExitOffer,
        ));
        exit_children.push(separator(31));
        exit_children.push(radio_item(
            32,
            "This Device",
            state.internet_source == "direct",
            TrayCommand::SetInternetSource("direct".to_string()),
        ));
        if state.paid_route_market.supported {
            exit_children.push(radio_item(
                34,
                "Paid Internet · Automatic",
                state.internet_source == "paid_automatic",
                TrayCommand::SetInternetSource("paid_automatic".to_string()),
            ));
            exit_children.push(radio_item(
                35,
                "Paid Internet · Manual",
                state.internet_source == "paid_manual",
                TrayCommand::SetInternetSource("paid_manual".to_string()),
            ));
        }
        exit_children.push(toggle_item(
            36,
            "WireGuard VPN",
            state.wireguard_exit_configured,
            state.internet_source == "wireguard",
            TrayCommand::SetInternetSource("wireguard".to_string()),
        ));
        exit_children.extend(
            network
                .participants
                .iter()
                .filter(|participant| participant.offers_exit_node && !is_self(participant, state))
                .enumerate()
                .map(|(index, participant)| {
                    radio_item(
                        200 + index as i32,
                        &exit_node_label(participant),
                        state.internet_source == "private_vpn"
                            && state.exit_node == participant.npub,
                        TrayCommand::SetExitNode(participant.npub.clone()),
                    )
                }),
        );
        children.push(MenuNode {
            id: 33,
            label: "Internet Source".to_string(),
            enabled: true,
            separator: false,
            toggle: None,
            command: None,
            children: exit_children,
        });
    }

    children.extend([
        separator(8),
        item(9, "Open Nostr VPN", true, TrayCommand::ShowWindow),
        item(10, "Quit", true, TrayCommand::Quit),
    ]);

    MenuNode {
        id: 0,
        label: String::new(),
        enabled: true,
        separator: false,
        toggle: None,
        command: None,
        children,
    }
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
        command: Some(command),
        children: Vec::new(),
    }
}

fn toggle_item(id: i32, label: &str, enabled: bool, on: bool, command: TrayCommand) -> MenuNode {
    MenuNode {
        id,
        label: label.to_string(),
        enabled,
        separator: false,
        toggle: Some(on),
        command: Some(command),
        children: Vec::new(),
    }
}

fn radio_item(id: i32, label: &str, on: bool, command: TrayCommand) -> MenuNode {
    // Reuse checkmark rendering for the exit-node selection list — most
    // dbusmenu hosts render `toggle-type=radio` identically, but checkmarks
    // are universally supported.
    toggle_item(id, label, true, on, command)
}

fn separator(id: i32) -> MenuNode {
    MenuNode {
        id,
        label: String::new(),
        enabled: false,
        separator: true,
        toggle: None,
        command: None,
        children: Vec::new(),
    }
}

fn label_node(id: i32, label: &str, enabled: bool) -> MenuNode {
    MenuNode {
        id,
        label: label.to_string(),
        enabled,
        separator: false,
        toggle: None,
        command: None,
        children: Vec::new(),
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
        properties.insert("label".to_string(), node.label.to_variant());
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

fn tray_status(state: &NativeAppState) -> String {
    if !state.exit_node_status_text.trim().is_empty() {
        return state.exit_node_status_text.clone();
    }
    if state.vpn_active {
        format!(
            "{} of {} devices connected",
            state.connected_peer_count, state.expected_peer_count
        )
    } else if !state.vpn_status.trim().is_empty() {
        state.vpn_status.clone()
    } else {
        "Disconnected".to_string()
    }
}

fn sni_status(state: &NativeAppState) -> &'static str {
    if state.exit_node_blocked {
        return "NeedsAttention";
    }
    if state.vpn_enabled {
        "Active"
    } else {
        "Passive"
    }
}

fn tray_icon(blocked: bool) -> glib::Variant {
    let icon_type = glib::VariantTy::new("(iiay)").expect("icon pixmap type");
    glib::Variant::array_from_iter_with_type(
        icon_type,
        [
            tray_icon_pixmap(
                include_bytes!("../resources/nostr-vpn-tray-24.png"),
                blocked,
            ),
            tray_icon_pixmap(
                include_bytes!("../resources/nostr-vpn-tray-48.png"),
                blocked,
            ),
        ],
    )
}

fn tray_icon_pixmap(bytes: &[u8], blocked: bool) -> glib::Variant {
    let mut image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("bundled tray icon is a valid PNG");
    if blocked {
        draw_blocked_dot(&mut image);
    }
    let (width, height) = image.dimensions();
    let mut data = image.into_rgba8().into_vec();
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    glib::Variant::tuple_from_iter([
        (width as i32).to_variant(),
        (height as i32).to_variant(),
        data.to_variant(),
    ])
}

fn draw_blocked_dot(image: &mut image::DynamicImage) {
    let mut rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    let radius = (width.min(height) / 5).max(3);
    let center_x = width.saturating_sub(radius + 1);
    let center_y = radius + 1;
    draw_filled_circle(
        &mut rgba,
        center_x,
        center_y,
        radius,
        Rgba([220, 38, 38, 255]),
    );
    *image = image::DynamicImage::ImageRgba8(rgba);
}

fn draw_filled_circle(
    image: &mut RgbaImage,
    center_x: u32,
    center_y: u32,
    radius: u32,
    color: Rgba<u8>,
) {
    let radius_squared = i64::from(radius) * i64::from(radius);
    let min_x = center_x.saturating_sub(radius);
    let max_x = (center_x + radius).min(image.width().saturating_sub(1));
    let min_y = center_y.saturating_sub(radius);
    let max_y = (center_y + radius).min(image.height().saturating_sub(1));
    for y in min_y..=max_y {
        for x in min_x..=max_x {
            let dx = i64::from(x) - i64::from(center_x);
            let dy = i64::from(y) - i64::from(center_y);
            if dx * dx + dy * dy <= radius_squared {
                image.put_pixel(x, y, color);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_layout_has_dbusmenu_type() {
        let state = NativeAppState::default();
        let root = build_menu(&state);
        let layout = menu_node_layout(&root);
        assert_eq!(layout.type_().as_str(), "(ia{sv}av)");
    }
}
