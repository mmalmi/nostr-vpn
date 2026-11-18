use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

#[test]
fn c_abi_returns_json_state_and_action_errors() {
    let data_dir = temp_data_dir();
    let data_dir = CString::new(data_dir.to_string_lossy().as_bytes()).expect("data dir");
    let version = CString::new("test").expect("version");
    let handle = nostr_vpn_app_new(data_dir.as_ptr(), version.as_ptr());
    assert!(!handle.is_null());

    let state_json = take_string(nostr_vpn_app_state_json(handle));
    let state: serde_json::Value = serde_json::from_str(&state_json).expect("state JSON");
    assert!(state.get("rev").is_some());
    assert!(state.get("ownNpub").is_some());

    let bad_action = CString::new(r#"{"type":"missing"}"#).expect("action");
    let state_json = take_string(nostr_vpn_app_dispatch_json(handle, bad_action.as_ptr()));
    let state: serde_json::Value = serde_json::from_str(&state_json).expect("error state JSON");
    assert!(
        state["error"]
            .as_str()
            .is_some_and(|error| error.contains("invalid native action JSON"))
    );

    unsafe {
        nostr_vpn_app_free(handle);
    }
}

#[test]
fn c_abi_manual_join_contract_reaches_both_real_native_actions() {
    let admin_dir = temp_data_dir();
    let joiner_dir = temp_data_dir();
    let version = CString::new("test").expect("version");
    let admin_data = CString::new(admin_dir.to_string_lossy().as_bytes()).expect("admin data dir");
    let joiner_data =
        CString::new(joiner_dir.to_string_lossy().as_bytes()).expect("joiner data dir");
    let admin = nostr_vpn_app_new(admin_data.as_ptr(), version.as_ptr());
    let joiner = nostr_vpn_app_new(joiner_data.as_ptr(), version.as_ptr());
    assert!(!admin.is_null());
    assert!(!joiner.is_null());

    let admin_state = state_value(admin);
    let joiner_state = state_value(joiner);
    let admin_npub = admin_state["ownNpub"].as_str().expect("admin npub");
    let joiner_npub = joiner_state["ownNpub"].as_str().expect("joiner npub");

    let created = dispatch_value(
        admin,
        &serde_json::json!({
            "type": "add_network",
            "name": "Manual join contract",
        }),
    );
    assert_eq!(created["networks"].as_array().map(Vec::len), Some(1));
    let network_entry_id = created["networks"][0]["id"]
        .as_str()
        .expect("network entry id");
    let mesh_network_id = created["networks"][0]["networkId"]
        .as_str()
        .expect("mesh network id");

    let configured_joiner = dispatch_value(
        joiner,
        &serde_json::json!({
            "type": "manual_add_network",
            "adminNpub": admin_npub,
            "meshNetworkId": mesh_network_id,
        }),
    );
    assert_eq!(
        configured_joiner["networks"][0]["networkId"].as_str(),
        Some(mesh_network_id),
        "joiner-side production action must persist the out-of-band network identity"
    );
    assert_eq!(
        configured_joiner["networks"][0]["joinRequestAdminNpub"].as_str(),
        Some(admin_npub),
        "joiner-side production action must persist the trusted admin identity"
    );

    let approved = dispatch_value(
        admin,
        &serde_json::json!({
            "type": "add_participant",
            "networkId": network_entry_id,
            "npub": joiner_npub,
            "alias": "Android",
        }),
    );
    assert!(
        approved["networks"][0]["participants"]
            .as_array()
            .is_some_and(|participants| participants
                .iter()
                .any(|participant| participant["npub"].as_str() == Some(joiner_npub))),
        "admin-side production action must add the joining identity to the signed roster"
    );

    unsafe {
        nostr_vpn_app_free(admin);
        nostr_vpn_app_free(joiner);
    }
    let _ = fs::remove_dir_all(admin_dir);
    let _ = fs::remove_dir_all(joiner_dir);
}

#[test]
fn qr_matrix_reports_cells_for_join_request_text() {
    let text = CString::new("nvpn://join-request/example").expect("text");
    let json = take_string(nostr_vpn_qr_matrix_json(text.as_ptr()));
    let value: serde_json::Value = serde_json::from_str(&json).expect("matrix JSON");
    let width = value["width"].as_u64().expect("width");
    assert!(width > 0);
    assert_eq!(
        value["cells"].as_array().expect("cells").len(),
        usize::try_from(width * width).expect("matrix cell count fits usize")
    );
    assert_eq!(value["error"], "");
}

#[test]
fn decode_qr_image_reads_generated_join_request() {
    let request = "nvpn://join-request/example";
    let code = QrCode::new(request.as_bytes()).expect("QR code");
    let module_count = u32::try_from(code.width()).expect("QR width fits u32");
    let scale = 8;
    let quiet_zone = 4;
    let image_width = (module_count + quiet_zone * 2) * scale;
    let mut image = image::GrayImage::from_pixel(image_width, image_width, image::Luma([255]));

    for (index, color) in code.to_colors().into_iter().enumerate() {
        if !matches!(color, qrcode::Color::Dark) {
            continue;
        }
        let x = u32::try_from(index % code.width()).expect("QR x fits u32");
        let y = u32::try_from(index / code.width()).expect("QR y fits u32");
        for dy in 0..scale {
            for dx in 0..scale {
                image.put_pixel(
                    (x + quiet_zone) * scale + dx,
                    (y + quiet_zone) * scale + dy,
                    image::Luma([0]),
                );
            }
        }
    }

    let dir = temp_data_dir();
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("join-request.png");
    image.save(&path).expect("save QR image");

    let decoded = decode_qr_image(path.to_str().expect("UTF-8 path")).expect("decode QR");
    assert_eq!(decoded, request);
}

fn temp_data_dir() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("nostr-vpn-c-abi-{}-{stamp}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn state_value(handle: *const NvpnAppHandle) -> serde_json::Value {
    let json = take_string(nostr_vpn_app_state_json(handle));
    serde_json::from_str(&json).expect("state JSON")
}

fn dispatch_value(handle: *const NvpnAppHandle, action: &serde_json::Value) -> serde_json::Value {
    let action = CString::new(action.to_string()).expect("action JSON");
    let json = take_string(nostr_vpn_app_dispatch_json(handle, action.as_ptr()));
    serde_json::from_str(&json).expect("action state JSON")
}

fn take_string(value: *mut c_char) -> String {
    assert!(!value.is_null());
    let text = unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        nostr_vpn_string_free(value);
    }
    text
}
