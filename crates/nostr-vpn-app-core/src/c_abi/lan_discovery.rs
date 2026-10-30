/// # Safety
/// `handle` must be a live mobile tunnel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_lan_discovery_info_json(
    handle: *const NvpnMobileTunnelHandle,
) -> *mut c_char {
    if handle.is_null() {
        return json_raw_string("");
    }
    let tunnel = unsafe { &*handle };
    let json = catch_panic(
        "mobile tunnel lan discovery info json",
        String::new(),
        || tunnel.tunnel.lan_discovery_info_json().unwrap_or_default(),
    );
    json_raw_string(&json)
}

/// # Safety
/// `handle` must be live, and both strings must be valid NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_observe_lan_peer(
    handle: *const NvpnMobileTunnelHandle,
    npub: *const c_char,
    addresses_json: *const c_char,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let tunnel = unsafe { &*handle };
    catch_panic("mobile tunnel observe lan peer", false, || {
        tunnel
            .tunnel
            .observe_lan_peer(&c_string_lossy(npub), &c_string_lossy(addresses_json))
            .is_ok()
    })
}
