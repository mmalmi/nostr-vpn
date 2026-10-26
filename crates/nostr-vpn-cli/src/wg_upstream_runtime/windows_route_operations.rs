#[cfg(any(test, target_os = "windows"))]
fn combine_windows_route_results(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(anyhow!("{first:#}; {second:#}")),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn ensure_windows_route(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
) -> Result<bool> {
    if runner.route_exists(route)? {
        return Ok(false);
    }
    if runner.route_identity_exists(route)? {
        return Err(anyhow!(
            "Windows route identity {} interface={} nexthop={} exists with unowned attributes",
            route.prefix,
            route.interface_index,
            route.next_hop
        ));
    }
    runner.add_route(route)?;
    Ok(true)
}

#[cfg(any(test, target_os = "windows"))]
fn ensure_tracked_windows_route(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
    owned: bool,
) -> Result<bool> {
    if runner.route_exists(route)? {
        return Ok(false);
    }
    if runner.route_identity_exists(route)? {
        if !owned {
            return Err(anyhow!(
                "unowned Windows route identity {} changed attributes",
                route.prefix
            ));
        }
        runner.set_route(route)?;
        return Ok(true);
    }
    runner.add_route(route)?;
    Ok(true)
}

#[cfg(any(test, target_os = "windows"))]
fn delete_windows_route_with_retry(
    runner: &mut impl WindowsRouteCommandRunner,
    route: &WindowsRouteSpec,
) -> Result<()> {
    let mut last_error = None;
    for _ in 0..WINDOWS_ROUTE_CLEANUP_ATTEMPTS {
        match runner.route_exists(route) {
            Ok(false) => match runner.route_identity_exists(route) {
                Ok(false) => return runner.finish_route_cleanup(route),
                Ok(true) => {}
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            },
            Ok(true) => {
                // The exact desired attributes still exist.
            }
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        }
        if !route.is_identityless_legacy_tunnel_route()
            && let Err(error) = runner.verify_interface_identity(route)
        {
            last_error = Some(error);
            continue;
        }
        match runner.delete_route(route) {
            Ok(()) => match runner.finish_route_cleanup(route) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            },
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("cleanup attempt count is non-zero"))
}

#[cfg(any(test, target_os = "windows"))]
fn validate_windows_underlay(
    underlay: &WindowsDefaultRoute,
    excluded_tunnel_interfaces: &[u32],
) -> Result<()> {
    if excluded_tunnel_interfaces.contains(&underlay.interface_index) {
        return Err(anyhow!(
            "captured Windows default route points at excluded tunnel interface {}",
            underlay.interface_index
        ));
    }
    underlay
        .gateway
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("invalid Windows underlay gateway {}", underlay.gateway))?;
    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn with_windows_route_rollback(error: anyhow::Error, rollback: Result<()>) -> anyhow::Error {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => anyhow!("{error:#}; rollback failed: {rollback_error:#}"),
    }
}
