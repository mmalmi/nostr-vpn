/// Connects the supported `NEPacketTunnelFlow` packet writer to the Rust
/// tunnel. Rust owns `context` after this call and invokes `release` exactly
/// once, including when attachment fails.
///
/// # Safety
///
/// `handle` must be null or a live mobile tunnel handle. `context` and each
/// callback must remain valid until Rust invokes `release`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_packet_flow_start(
    handle: *mut NvpnMobileTunnelHandle,
    context: *mut c_void,
    write: Option<crate::mobile_tunnel::IosPacketFlowWriteCallback>,
    failure: Option<crate::mobile_tunnel::IosPacketFlowFailureCallback>,
    release: Option<crate::mobile_tunnel::IosPacketFlowReleaseCallback>,
) -> bool {
    let callbacks =
        match crate::mobile_tunnel::IosPacketFlowCallbacks::new(context, write, failure, release) {
            Ok(callbacks) => callbacks,
            Err(error) => {
                mobile_debug_log(format!(
                    "mobile: invalid iOS packet flow callbacks: {error:#}"
                ));
                if !context.is_null()
                    && let Some(release) = release
                {
                    unsafe {
                        release(context);
                    }
                }
                return false;
            }
        };
    if handle.is_null() {
        drop(callbacks);
        return false;
    }
    let tunnel = unsafe { &mut *handle };
    match tunnel.tunnel.attach_packet_flow(callbacks) {
        Ok(()) => true,
        Err(error) => {
            mobile_debug_log(format!("mobile: iOS packet flow attach failed: {error:#}"));
            false
        }
    }
}

/// Sends one batch returned by `NEPacketTunnelFlow.readPackets` into the Rust
/// mobile tunnel. The bounded channel accepts it immediately or counts and
/// drops an overloaded batch. A stopped channel fails without blocking
/// tunnel shutdown.
///
/// # Safety
///
/// `handle` must be a live mobile tunnel handle. `bytes` must reference
/// `byte_count` bytes and `lengths` must reference `packet_count` values for
/// the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nostr_vpn_mobile_tunnel_packet_flow_send(
    handle: *const NvpnMobileTunnelHandle,
    bytes: *const u8,
    byte_count: usize,
    lengths: *const usize,
    packet_count: usize,
) -> bool {
    if handle.is_null()
        || bytes.is_null()
        || byte_count == 0
        || lengths.is_null()
        || packet_count == 0
    {
        return false;
    }
    let tunnel = unsafe { &*handle };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, byte_count) };
    let lengths = unsafe { std::slice::from_raw_parts(lengths, packet_count) };
    match tunnel.tunnel.send_packet_flow_batch(bytes, lengths) {
        Ok(()) => true,
        Err(error) => {
            mobile_debug_log(format!("mobile: iOS packet flow send failed: {error:#}"));
            false
        }
    }
}
