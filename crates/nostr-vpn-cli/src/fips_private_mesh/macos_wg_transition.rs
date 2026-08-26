#[cfg(any(target_os = "macos", test))]
fn macos_endpoint_bypass_underlay_refresh_required(
    current_routes: &[String],
    current_underlay: Option<&crate::MacosRouteSpec>,
    desired_routes: &[String],
    current_routes_present: bool,
) -> bool {
    current_underlay.is_none() || current_routes != desired_routes || !current_routes_present
}

#[cfg(target_os = "macos")]
fn macos_direct_underlay_restore_needed(
    previous_exit_requested: bool,
    next_exit_requested: bool,
) -> bool {
    previous_exit_requested && !next_exit_requested
}

#[cfg(all(test, target_os = "macos"))]
mod macos_wg_transition_tests {
    use super::{FipsPrivateTunnelRuntime, macos_direct_underlay_restore_needed};

    #[test]
    fn stale_wireguard_is_removed_before_fips_routes_change() {
        assert!(FipsPrivateTunnelRuntime::macos_wg_upstream_needs_cleanup(
            false,
            Some(true)
        ));
        assert!(FipsPrivateTunnelRuntime::macos_wg_upstream_needs_cleanup(
            true,
            Some(false)
        ));
        assert!(!FipsPrivateTunnelRuntime::macos_wg_upstream_needs_cleanup(
            true,
            Some(true)
        ));
        assert!(!FipsPrivateTunnelRuntime::macos_wg_upstream_needs_cleanup(
            false, None
        ));
    }

    #[test]
    fn only_an_exit_to_direct_transition_repairs_the_underlay_default() {
        assert!(macos_direct_underlay_restore_needed(true, false));
        assert!(!macos_direct_underlay_restore_needed(false, false));
        assert!(!macos_direct_underlay_restore_needed(true, true));
    }
}
