#[cfg(any(target_os = "android", target_os = "ios"))]
use std::ffi::c_void;
use std::ffi::{CStr, CString, c_char};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;
#[cfg(target_os = "android")]
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use image::ImageReader;
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{GlobalRef, JClass, JObject, JString};
#[cfg(target_os = "android")]
use jni::sys::{jboolean, jint, jlong, jstring};
#[cfg(feature = "updater")]
use nostr_vpn_core::updater::{
    ProductUpdateMode, ProductUpdateResult, ProductUpdateSource, check_product_update_blocking,
    check_product_update_blocking_with_config, download_product_update_blocking,
    download_product_update_blocking_with_config,
};
use qrcode::QrCode;
use serde::Serialize;

use crate::mobile_tunnel::{
    MobileTunnel, mobile_debug_log, tunnel_config_json, tunnel_provider_options_config_json,
};
use crate::{FfiApp, NativeAppAction, NativeAppState};

pub struct NvpnAppHandle {
    app: Arc<FfiApp>,
}

pub struct NvpnMobileTunnelHandle {
    tunnel: MobileTunnel,
}

include!("c_abi/mobile_network.rs");
include!("c_abi/lan_discovery.rs");
#[cfg(target_os = "ios")]
include!("c_abi/ios_packet_flow.rs");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QrMatrixResult {
    width: usize,
    cells: Vec<bool>,
    error: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct QrDecodeResult {
    value: String,
    error: String,
}

#[cfg(feature = "updater")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateJsonError {
    error: String,
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_app_new(
    data_dir: *const c_char,
    app_version: *const c_char,
) -> *mut NvpnAppHandle {
    // Both mobile callers already treat a null handle as their failure path.
    catch_panic("app new", ptr::null_mut(), || {
        let data_dir = c_string_lossy(data_dir);
        let app_version = c_string_lossy(app_version);
        Box::into_raw(Box::new(NvpnAppHandle {
            app: FfiApp::new(data_dir, app_version),
        }))
    })
}

/// # Safety
///
/// `handle` must be null or a pointer returned by `nostr_vpn_app_new` that has not already been
/// freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_app_free(handle: *mut NvpnAppHandle) {
    if handle.is_null() {
        return;
    }
    catch_panic("app free", (), || unsafe {
        drop(Box::from_raw(handle));
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_app_state_json(handle: *const NvpnAppHandle) -> *mut c_char {
    let state = catch_panic(
        "app state json",
        error_state("app state json panicked".to_string()),
        || {
            app_from_handle(handle).map_or_else(
                |error| error_state(error.to_string()),
                |handle| handle.app.state(),
            )
        },
    );
    json_string(&state)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_app_refresh_json(handle: *const NvpnAppHandle) -> *mut c_char {
    let state = catch_panic(
        "app refresh json",
        error_state("app refresh json panicked".to_string()),
        || {
            app_from_handle(handle).map_or_else(
                |error| error_state(error.to_string()),
                |handle| handle.app.refresh(),
            )
        },
    );
    json_string(&state)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_app_dispatch_json(
    handle: *const NvpnAppHandle,
    action_json: *const c_char,
) -> *mut c_char {
    let state = catch_panic(
        "app dispatch json",
        error_state("app dispatch json panicked".to_string()),
        || {
            app_from_handle(handle).map_or_else(
                |error| error_state(error.to_string()),
                |handle| {
                    let action_json = c_string_lossy(action_json);
                    match serde_json::from_str::<NativeAppAction>(&action_json) {
                        Ok(action) => handle.app.dispatch(action),
                        Err(error) => {
                            let mut state = handle.app.state();
                            state.error = format!("invalid native action JSON: {error}");
                            state
                        }
                    }
                },
            )
        },
    );
    json_string(&state)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_qr_matrix_json(text: *const c_char) -> *mut c_char {
    let result = catch_panic(
        "qr matrix json",
        Err(anyhow!("qr matrix json panicked")),
        || qr_matrix(&c_string_lossy(text)),
    )
    .unwrap_or_else(|error| QrMatrixResult {
        width: 0,
        cells: Vec::new(),
        error: error.to_string(),
    });
    json_string(&result)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_decode_qr_image_json(path: *const c_char) -> *mut c_char {
    let result = catch_panic(
        "decode qr image json",
        Err(anyhow!("decode qr image json panicked")),
        || decode_qr_image(&c_string_lossy(path)),
    )
    .map_or_else(
        |error| QrDecodeResult {
            value: String::new(),
            error: error.to_string(),
        },
        |value| QrDecodeResult {
            value,
            error: String::new(),
        },
    );
    json_string(&result)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_mobile_tunnel_config_json(data_dir: *const c_char) -> *mut c_char {
    let config_json = catch_panic("mobile tunnel config json", String::new(), || {
        tunnel_config_json(&c_string_lossy(data_dir))
    });
    json_raw_string(&config_json)
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_mobile_tunnel_provider_options_config_json(
    data_dir: *const c_char,
) -> *mut c_char {
    let config_json = catch_panic(
        "mobile tunnel provider options config json",
        String::new(),
        || tunnel_provider_options_config_json(&c_string_lossy(data_dir)),
    );
    json_raw_string(&config_json)
}

/// # Safety
///
/// `handle` must be a live mobile tunnel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_runtime_state_json(
    handle: *const NvpnMobileTunnelHandle,
) -> *mut c_char {
    if handle.is_null() {
        return json_raw_string(r#"{"error":"mobile tunnel stopped"}"#);
    }
    let tunnel = unsafe { &*handle };
    let json = catch_panic(
        "mobile tunnel runtime state json",
        Err(anyhow!("mobile tunnel runtime state json panicked")),
        || tunnel.tunnel.runtime_state_json(),
    );
    match json {
        Ok(json) => json_raw_string(&json),
        Err(error) => {
            let json = serde_json::json!({ "error": error.to_string() }).to_string();
            json_raw_string(&json)
        }
    }
}

/// # Safety
///
/// `handle` must be a live mobile tunnel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_take_app_config_toml(
    handle: *const NvpnMobileTunnelHandle,
) -> *mut c_char {
    if handle.is_null() {
        return json_raw_string("");
    }
    let tunnel = unsafe { &*handle };
    let toml = catch_panic(
        "mobile tunnel app config toml",
        Err(anyhow!("mobile tunnel app config read panicked")),
        || tunnel.tunnel.take_app_config_toml(),
    );
    match toml {
        Ok(toml) => json_raw_string(&toml),
        Err(error) => json_raw_string(&format!("# failed to read mobile app config: {error}\n")),
    }
}

/// Acknowledges that the containing app durably persisted the exact config
/// returned by `nostr_vpn_mobile_tunnel_take_app_config_toml`.
///
/// # Safety
///
/// `handle` must be a live mobile tunnel handle and `expected_toml` must be a
/// valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_ack_app_config_toml(
    handle: *const NvpnMobileTunnelHandle,
    expected_toml: *const c_char,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let tunnel = unsafe { &*handle };
    let expected_toml = c_string_lossy(expected_toml);
    catch_panic("mobile tunnel ack app config toml", false, || {
        tunnel
            .tunnel
            .acknowledge_app_config_toml(&expected_toml)
            .unwrap_or(false)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_mobile_tunnel_new(
    config_json: *const c_char,
) -> *mut NvpnMobileTunnelHandle {
    let config_json = c_string_lossy(config_json);
    catch_panic("mobile tunnel new", ptr::null_mut(), || {
        start_mobile_tunnel_handle(&config_json)
    })
}

#[cfg(feature = "updater")]
#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_update_check_json(
    current_version: *const c_char,
    mode: *const c_char,
    source: *const c_char,
) -> *mut c_char {
    let result = catch_panic(
        "update check json",
        Err(anyhow!("update check panicked")),
        || {
            check_product_update_blocking(
                &c_string_lossy(current_version),
                parse_update_mode(&c_string_lossy(mode)),
                parse_update_source(&c_string_lossy(source)),
            )
        },
    );
    update_result_json(result)
}

#[cfg(feature = "updater")]
#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_update_check_with_config_json(
    current_version: *const c_char,
    mode: *const c_char,
    source: *const c_char,
    config_path: *const c_char,
) -> *mut c_char {
    let config_path = c_string_lossy(config_path);
    let result = catch_panic(
        "update check with config json",
        Err(anyhow!("update check panicked")),
        || {
            check_product_update_blocking_with_config(
                &c_string_lossy(current_version),
                parse_update_mode(&c_string_lossy(mode)),
                parse_update_source(&c_string_lossy(source)),
                Some(std::path::Path::new(&config_path)),
            )
        },
    );
    update_result_json(result)
}

#[cfg(feature = "updater")]
#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_update_download_json(
    current_version: *const c_char,
    mode: *const c_char,
    source: *const c_char,
    download_dir: *const c_char,
) -> *mut c_char {
    let download_dir = c_string_lossy(download_dir);
    let download_dir =
        (!download_dir.trim().is_empty()).then(|| std::path::Path::new(&download_dir));
    let result = catch_panic(
        "update download json",
        Err(anyhow!("update download panicked")),
        || {
            download_product_update_blocking(
                &c_string_lossy(current_version),
                parse_update_mode(&c_string_lossy(mode)),
                parse_update_source(&c_string_lossy(source)),
                download_dir,
            )
        },
    );
    update_result_json(result)
}

#[cfg(feature = "updater")]
#[unsafe(no_mangle)]
pub extern "C" fn nostr_vpn_update_download_with_config_json(
    current_version: *const c_char,
    mode: *const c_char,
    source: *const c_char,
    download_dir: *const c_char,
    config_path: *const c_char,
) -> *mut c_char {
    let download_dir = c_string_lossy(download_dir);
    let download_dir =
        (!download_dir.trim().is_empty()).then(|| std::path::Path::new(&download_dir));
    let config_path = c_string_lossy(config_path);
    let result = catch_panic(
        "update download with config json",
        Err(anyhow!("update download panicked")),
        || {
            download_product_update_blocking_with_config(
                &c_string_lossy(current_version),
                parse_update_mode(&c_string_lossy(mode)),
                parse_update_source(&c_string_lossy(source)),
                download_dir,
                Some(std::path::Path::new(&config_path)),
            )
        },
    );
    update_result_json(result)
}

/// # Safety
///
/// `handle` must be null or a pointer returned by `nostr_vpn_mobile_tunnel_new` that has not
/// already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_free(handle: *mut NvpnMobileTunnelHandle) {
    if handle.is_null() {
        return;
    }
    catch_panic("mobile tunnel free", (), || unsafe {
        drop(Box::from_raw(handle));
    });
}

#[cfg(target_os = "android")]
fn reject_unattached_mobile_tun_fd(fd: std::os::raw::c_int) {
    unsafe {
        libc::close(fd);
    }
}

/// Resolved IPv4 `/32` route for the userspace WG upstream UDP endpoint.
/// iOS adds this to `NEIPv4Settings.excludedRoutes` so encrypted UDP
/// continues to escape after the packet tunnel installs `0.0.0.0/0`.
/// Returns an empty string when WG upstream is not running or resolved
/// to an IPv6 endpoint.
///
/// # Safety
///
/// `handle` must be a live mobile tunnel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_wg_excluded_route(
    handle: *const NvpnMobileTunnelHandle,
) -> *mut c_char {
    if handle.is_null() {
        return json_raw_string("");
    }
    let tunnel = unsafe { &*handle };
    let route = catch_panic("mobile tunnel wg excluded route", String::new(), || {
        tunnel
            .tunnel
            .wg_upstream_excluded_route()
            .unwrap_or_default()
    });
    json_raw_string(&route)
}

/// # Safety
///
/// `value` must be null or a pointer returned by this library that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    catch_panic("string free", (), || unsafe {
        drop(CString::from_raw(value));
    });
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_initializeAndroidContext(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) {
    catch_panic("jni initializeAndroidContext", (), || {
        static ANDROID_CONTEXT: OnceLock<Option<GlobalRef>> = OnceLock::new();
        ANDROID_CONTEXT.get_or_init(|| match env.new_global_ref(&context) {
            Ok(global) => {
                let Ok(vm) = env.get_java_vm() else {
                    return None;
                };
                unsafe {
                    ndk_context::initialize_android_context(
                        vm.get_java_vm_pointer() as *mut c_void,
                        global.as_obj().as_raw() as *mut c_void,
                    );
                }
                Some(global)
            }
            Err(_) => None,
        });
    })
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_appNew(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
    app_version: JString<'_>,
) -> jlong {
    // A zero handle is the failure value the Kotlin caller already checks.
    catch_panic("jni appNew", 0, || {
        let data_dir = jni_string_lossy(&mut env, &data_dir);
        let app_version = jni_string_lossy(&mut env, &app_version);
        Box::into_raw(Box::new(NvpnAppHandle {
            app: FfiApp::new(data_dir, app_version),
        })) as jlong
    })
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_appFree(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    catch_panic("jni appFree", (), || unsafe {
        drop(Box::from_raw(handle as *mut NvpnAppHandle));
    });
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_stateJson(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    jni_state_json(env, handle, "stateJson", |handle| handle.app.state())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_refreshJson(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    jni_state_json(env, handle, "refreshJson", |handle| handle.app.refresh())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_dispatchJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    action_json: JString<'_>,
) -> jstring {
    let state = catch_panic(
        "jni dispatchJson",
        error_state("jni dispatchJson panicked".to_string()),
        || {
            app_from_jlong(handle).map_or_else(
                |error| error_state(error.to_string()),
                |handle| {
                    let action_json = jni_string_lossy(&mut env, &action_json);
                    match serde_json::from_str::<NativeAppAction>(&action_json) {
                        Ok(action) => handle.app.dispatch(action),
                        Err(error) => {
                            let mut state = handle.app.state();
                            state.error = format!("invalid native action JSON: {error}");
                            state
                        }
                    }
                },
            )
        },
    );
    jni_json_string(env, &state)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_qrMatrixJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    text: JString<'_>,
) -> jstring {
    let text = jni_string_lossy(&mut env, &text);
    let result = catch_panic(
        "jni qrMatrixJson",
        Err(anyhow!("qr matrix json panicked")),
        || qr_matrix(&text),
    )
    .unwrap_or_else(|error| QrMatrixResult {
        width: 0,
        cells: Vec::new(),
        error: error.to_string(),
    });
    jni_json_string(env, &result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_decodeQrImageJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) -> jstring {
    let path = jni_string_lossy(&mut env, &path);
    let result = catch_panic(
        "jni decodeQrImageJson",
        Err(anyhow!("decode qr image json panicked")),
        || decode_qr_image(&path),
    )
    .map_or_else(
        |error| QrDecodeResult {
            value: String::new(),
            error: error.to_string(),
        },
        |value| QrDecodeResult {
            value,
            error: String::new(),
        },
    );
    jni_json_string(env, &result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelConfigJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    data_dir: JString<'_>,
) -> jstring {
    let data_dir = jni_string_lossy(&mut env, &data_dir);
    let config_json = catch_panic("jni mobileTunnelConfigJson", String::new(), || {
        tunnel_config_json(&data_dir)
    });
    jni_raw_string(env, config_json)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelNew(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config_json: JString<'_>,
) -> jlong {
    let config_json = jni_string_lossy(&mut env, &config_json);
    catch_panic("jni mobileTunnelNew", 0, || {
        start_mobile_tunnel_handle(&config_json) as jlong
    })
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelFree(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    catch_panic("jni mobileTunnelFree", (), || unsafe {
        drop(Box::from_raw(handle as *mut NvpnMobileTunnelHandle));
    });
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelAttachTunFd(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    fd: jint,
) -> jboolean {
    if fd < 0 {
        return 0;
    }
    let Some(tunnel) = tunnel_from_jlong_mut(handle) else {
        reject_unattached_mobile_tun_fd(fd);
        return 0;
    };
    catch_panic("jni mobileTunnelAttachTunFd", 0, || {
        u8::from(tunnel.tunnel.attach_tun_fd(fd).is_ok())
    })
}

/// Returns the raw fd of the userspace WG upstream UDP socket so the
/// VpnService can call `protect(fd)` on it. Returns -1 when WG
/// upstream isn't running on this tunnel.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelWgSocketFd(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    let Some(tunnel) = tunnel_from_jlong(handle) else {
        return -1;
    };
    catch_panic("jni mobileTunnelWgSocketFd", -1, || {
        tunnel.tunnel.wg_upstream_socket_fd()
    })
}

fn app_from_handle<'a>(handle: *const NvpnAppHandle) -> Result<&'a NvpnAppHandle> {
    if handle.is_null() {
        return Err(anyhow!("native app handle is null"));
    }
    Ok(unsafe { &*handle })
}

#[cfg(target_os = "android")]
fn app_from_jlong<'a>(handle: jlong) -> Result<&'a NvpnAppHandle> {
    if handle == 0 {
        return Err(anyhow!("native app handle is null"));
    }
    Ok(unsafe { &*(handle as *const NvpnAppHandle) })
}

#[cfg(target_os = "android")]
fn tunnel_from_jlong<'a>(handle: jlong) -> Option<&'a NvpnMobileTunnelHandle> {
    if handle == 0 {
        return None;
    }
    Some(unsafe { &*(handle as *const NvpnMobileTunnelHandle) })
}

#[cfg(target_os = "android")]
fn tunnel_from_jlong_mut<'a>(handle: jlong) -> Option<&'a mut NvpnMobileTunnelHandle> {
    if handle == 0 {
        return None;
    }
    Some(unsafe { &mut *(handle as *mut NvpnMobileTunnelHandle) })
}

fn c_string_lossy(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(target_os = "android")]
fn jni_string_lossy(env: &mut JNIEnv<'_>, value: &JString<'_>) -> String {
    env.get_string(value).map_or_else(
        |_| String::new(),
        |value| value.to_string_lossy().into_owned(),
    )
}

#[cfg(target_os = "android")]
fn jni_state_json(
    env: JNIEnv<'_>,
    handle: jlong,
    context: &str,
    state: impl FnOnce(&NvpnAppHandle) -> NativeAppState,
) -> jstring {
    let state = catch_panic(context, error_state(format!("{context} panicked")), || {
        app_from_jlong(handle).map_or_else(
            |error| error_state(error.to_string()),
            |handle| state(handle),
        )
    });
    jni_json_string(env, &state)
}

#[cfg(target_os = "android")]
fn jni_json_string(env: JNIEnv<'_>, value: &impl Serialize) -> jstring {
    let json =
        serde_json::to_string(value).unwrap_or_else(|error| format!(r#"{{"error":"{error}"}}"#));
    jni_raw_string(env, json)
}

#[cfg(target_os = "android")]
fn jni_raw_string(env: JNIEnv<'_>, value: String) -> jstring {
    env.new_string(value)
        .map_or(ptr::null_mut(), |value| value.into_raw())
}

fn start_mobile_tunnel_handle(config_json: &str) -> *mut NvpnMobileTunnelHandle {
    mobile_debug_log("mobile tunnel start enter");
    match panic::catch_unwind(AssertUnwindSafe(|| MobileTunnel::start(config_json))) {
        Ok(Ok(tunnel)) => {
            mobile_debug_log("mobile tunnel start success");
            Box::into_raw(Box::new(NvpnMobileTunnelHandle { tunnel }))
        }
        Ok(Err(error)) => {
            mobile_debug_log(format!("mobile tunnel start error: {error:#}"));
            ptr::null_mut()
        }
        Err(payload) => {
            mobile_debug_log(format!(
                "mobile tunnel start panic: {}",
                panic_payload_message(&payload)
            ));
            ptr::null_mut()
        }
    }
}

/// Runs `body`, turning a panic into `fallback` so no unwind crosses the
/// C/JNI boundary, where it would abort the whole app or tunnel process.
fn catch_panic<T>(context: &str, fallback: T, body: impl FnOnce() -> T) -> T {
    match panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            mobile_debug_log(format!(
                "{context} panic: {}",
                panic_payload_message(&payload)
            ));
            fallback
        }
    }
}

fn json_string(value: &impl Serialize) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(json) => into_c_string(&json),
        Err(error) => into_c_string(&format!(r#"{{"error":"{error}"}}"#)),
    }
}

fn json_raw_string(value: &str) -> *mut c_char {
    into_c_string(value)
}

#[cfg(feature = "updater")]
fn update_result_json(result: Result<ProductUpdateResult>) -> *mut c_char {
    match result {
        Ok(result) => json_string(&result),
        Err(error) => json_string(&UpdateJsonError {
            error: error.to_string(),
        }),
    }
}

#[cfg(feature = "updater")]
fn parse_update_mode(value: &str) -> ProductUpdateMode {
    if value.eq_ignore_ascii_case("app") {
        ProductUpdateMode::App
    } else {
        ProductUpdateMode::Cli
    }
}

#[cfg(feature = "updater")]
fn parse_update_source(value: &str) -> ProductUpdateSource {
    if value.eq_ignore_ascii_case("github") {
        ProductUpdateSource::Github
    } else if value.eq_ignore_ascii_case("hashtree") || value.eq_ignore_ascii_case("htree") {
        ProductUpdateSource::Hashtree
    } else {
        ProductUpdateSource::Auto
    }
}

fn into_c_string(value: &str) -> *mut c_char {
    match CString::new(value.replace('\0', "")) {
        Ok(value) => value.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn error_state(error: String) -> NativeAppState {
    NativeAppState {
        error,
        ..NativeAppState::default()
    }
}

fn qr_matrix(text: &str) -> Result<QrMatrixResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(QrMatrixResult {
            width: 0,
            cells: Vec::new(),
            error: String::new(),
        });
    }

    let code = QrCode::new(trimmed.as_bytes()).context("failed to encode QR text")?;
    let width = code.width();
    let cells = code
        .to_colors()
        .into_iter()
        .map(|color| matches!(color, qrcode::Color::Dark))
        .collect();
    Ok(QrMatrixResult {
        width,
        cells,
        error: String::new(),
    })
}

fn decode_qr_image(path: &str) -> Result<String> {
    let image = ImageReader::open(path)
        .with_context(|| format!("failed to open QR image {path}"))?
        .decode()
        .with_context(|| format!("failed to decode QR image {path}"))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let grids = prepared.detect_grids();
    for grid in grids {
        let (_, content) = grid.decode().context("failed to read QR payload")?;
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!("no QR code found in image"))
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
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
        let admin_data =
            CString::new(admin_dir.to_string_lossy().as_bytes()).expect("admin data dir");
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

    #[test]
    fn catch_panic_returns_failure_value_instead_of_unwinding() {
        let value = catch_panic("test guard", String::from("failure"), || -> String {
            panic!("deliberate test panic");
        });
        assert_eq!(value, "failure");

        let value = catch_panic("test guard", String::from("unused"), || {
            String::from("success")
        });
        assert_eq!(value, "success");
    }

    fn temp_data_dir() -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nostr-vpn-c-abi-{}-{stamp}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn state_value(handle: *const NvpnAppHandle) -> serde_json::Value {
        let json = take_string(nostr_vpn_app_state_json(handle));
        serde_json::from_str(&json).expect("state JSON")
    }

    fn dispatch_value(
        handle: *const NvpnAppHandle,
        action: &serde_json::Value,
    ) -> serde_json::Value {
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
}
