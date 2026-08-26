#[cfg(any(target_os = "macos", test))]
fn apply_macos_endpoint_bypass_route_changes<Apply>(
    current_routes: &mut Vec<String>,
    current_underlay: &mut Option<crate::MacosRouteSpec>,
    desired_routes: &[String],
    desired_underlay: Option<&crate::MacosRouteSpec>,
    force_reapply: bool,
    mut apply: Apply,
) -> Vec<(String, anyhow::Error)>
where
    Apply: FnMut(&str, Option<&str>) -> Result<()>,
{
    let underlay_changed = current_underlay.as_ref() != desired_underlay;
    let mut failures = Vec::new();
    if underlay_changed || force_reapply {
        current_routes.clear();
    } else {
        current_routes.retain(|route| desired_routes.contains(route));
    }
    if let Some(underlay) = desired_underlay {
        let missing = desired_routes
            .iter()
            .filter(|route| underlay_changed || force_reapply || !current_routes.contains(*route))
            .cloned()
            .collect::<Vec<_>>();
        for route in missing {
            if let Err(error) = apply(&route, underlay.gateway.as_deref()) {
                failures.push((route, error));
            } else {
                current_routes.push(route);
            }
        }
    }

    current_routes.sort();
    current_routes.dedup();
    // Track only exact routes whose install was verified. Missing desired
    // routes keep the production reconciler active without losing ownership
    // of successful siblings needed for crash cleanup.
    *current_underlay = if current_routes.is_empty() {
        None
    } else {
        desired_underlay.cloned()
    };
    failures
}
