/// Refreshes the live `WireGuard` upstream and FIPS carriers after the containing
/// OS reports that its physical underlay changed. The mobile tunnel and its
/// authenticated end-to-end sessions stay alive.
///
/// # Safety
///
/// `handle` must be a live mobile tunnel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_network_changed(
    handle: *const NvpnMobileTunnelHandle,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let tunnel = unsafe { &*handle };
    match tunnel.tunnel.handle_underlay_network_change() {
        Ok(outcome) => {
            mobile_debug_log(format!(
                "mobile: network change rebound {} FIPS carrier(s), refreshed {} peer path(s), \
                 WireGuard handshake initiated={}",
                outcome.rebound_transports,
                outcome.refreshed_peers,
                outcome.wireguard_handshake_initiated
            ));
            true
        }
        Err(error) => {
            mobile_debug_log(format!("mobile: network path refresh failed: {error:#}"));
            false
        }
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelNetworkChanged(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jboolean {
    let Some(tunnel) = tunnel_from_jlong(handle) else {
        return 0;
    };
    u8::from(tunnel.tunnel.handle_underlay_network_change().is_ok())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelHasPendingJoinReceipts(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jboolean {
    let Some(tunnel) = tunnel_from_jlong(handle) else {
        return 0;
    };
    u8::from(tunnel.tunnel.has_pending_join_receipts())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nostrvpn_app_core_NativeCore_mobileTunnelWireGuardUnderlayReady(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jboolean {
    let Some(tunnel) = tunnel_from_jlong(handle) else {
        return 0;
    };
    u8::from(tunnel.tunnel.handle_wireguard_underlay_ready().is_ok())
}
