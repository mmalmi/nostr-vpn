#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosOwnedGlobalGatewayRouteTransition {
    AlreadyDesired,
    ChangeOwned,
    MissingOrUnowned,
}

#[cfg(any(target_os = "macos", test))]
fn macos_owned_global_gateway_route_transition(
    output: &str,
    current: &MacosManagedRoute,
    desired: &MacosManagedRoute,
) -> MacosOwnedGlobalGatewayRouteTransition {
    if current.target != desired.target
        || current.gateway.is_none()
        || current.interface.is_none()
        || desired.gateway.is_none()
        || desired.interface.is_none()
    {
        return MacosOwnedGlobalGatewayRouteTransition::MissingOrUnowned;
    }
    if macos_global_managed_route_present(
        output,
        &desired.target,
        desired.gateway.as_deref(),
        desired.interface.as_deref(),
    ) {
        return MacosOwnedGlobalGatewayRouteTransition::AlreadyDesired;
    }
    if macos_global_managed_route_present(
        output,
        &current.target,
        current.gateway.as_deref(),
        current.interface.as_deref(),
    ) {
        return MacosOwnedGlobalGatewayRouteTransition::ChangeOwned;
    }
    MacosOwnedGlobalGatewayRouteTransition::MissingOrUnowned
}

#[cfg(any(target_os = "macos", test))]
fn macos_global_gateway_route_args(
    action: &str,
    target: &str,
    gateway: &str,
    interface: Option<&str>,
) -> Vec<String> {
    let mut args = macos_gateway_route_args(action, target, gateway, None);
    if let Some(interface) = interface {
        // `-ifp` selects the physical interface without setting RTF_IFSCOPE.
        // The route therefore remains a global /32 that beats both tunnel
        // /1s, even when two active underlays use the same gateway address.
        args.push("-ifp".to_string());
        args.push(interface.to_string());
    }
    args
}

#[cfg(target_os = "macos")]
pub(super) fn migrate_macos_owned_global_gateway_route(
    current: &MacosManagedRoute,
    desired: &MacosManagedRoute,
) -> Result<bool> {
    let before = macos_ipv4_route_table().context("inspect global macOS route before handoff")?;
    match macos_owned_global_gateway_route_transition(&before, current, desired) {
        MacosOwnedGlobalGatewayRouteTransition::AlreadyDesired => return Ok(true),
        MacosOwnedGlobalGatewayRouteTransition::MissingOrUnowned => return Ok(false),
        MacosOwnedGlobalGatewayRouteTransition::ChangeOwned => {}
    }

    let gateway = desired
        .gateway
        .as_deref()
        .expect("transition checked gateway");
    let interface = desired
        .interface
        .as_deref()
        .expect("transition checked interface");
    let mut change = ProcessCommand::new("route");
    change.args(macos_global_gateway_route_args(
        "change",
        &desired.target,
        gateway,
        Some(interface),
    ));
    let change_result = run_checked(&mut change);
    let after = macos_ipv4_route_table().context("verify global macOS route after handoff")?;
    if macos_owned_global_gateway_route_transition(&after, current, desired)
        == MacosOwnedGlobalGatewayRouteTransition::AlreadyDesired
    {
        return Ok(true);
    }
    match change_result {
        Ok(()) => Err(anyhow!(
            "macOS route {} did not move to its requested interface after change",
            desired.target
        )),
        Err(error) => Err(error.context(format!(
            "change owned macOS route {} to interface {interface}",
            desired.target
        ))),
    }
}
