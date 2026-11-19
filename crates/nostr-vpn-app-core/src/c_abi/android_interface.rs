/// Moves the running tunnel onto a VPN interface the service re-established
/// with updated routes. Rust owns `fd` after this call and closes it on
/// failure; the service then restarts the tunnel behind a descriptor of the
/// interface it kept.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelReplaceTunFd(
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
    match tunnel.tunnel.replace_tun_fd(fd) {
        Ok(()) => 1,
        Err(error) => {
            mobile_debug_log(format!("mobile: Android TUN replacement failed: {error:#}"));
            0
        }
    }
}

/// Returns the routes and resolvers the running tunnel applies as JSON, or
/// an object with an `error` field.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelInterfaceSettingsJson(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    let json = match tunnel_from_jlong(handle) {
        Some(tunnel) => tunnel
            .tunnel
            .interface_settings_json()
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() }).to_string()),
        None => r#"{"error":"mobile tunnel stopped"}"#.to_string(),
    };
    jni_raw_string(env, json)
}
