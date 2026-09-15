fn publish_fips_active_network_roster_to(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    extra_recipients: &[String],
    pending_recipients: &mut HashSet<String>,
) -> Result<usize> {
    if app.active_network_opt().is_none() {
        return Ok(0);
    }
    let own_pubkey = match app.own_nostr_pubkey_hex() {
        Ok(pubkey) => pubkey,
        Err(_) => return Ok(0),
    };

    let Some(signed_roster) = active_signed_roster_for_sync(app, config_path, false)? else {
        return Ok(0);
    };
    let removals = load_signed_rosters(&signed_rosters_file_path(config_path))?
        .removals
        .remove(&normalize_runtime_network_id(&signed_roster.network_id()?))
        .unwrap_or_default();
    let mut recipients = app.active_network_signal_pubkeys_hex();
    recipients.extend(extra_recipients.iter().cloned());
    recipients.extend(pending_recipients.drain());
    recipients.retain(|recipient| recipient != &own_pubkey);
    recipients.sort();
    recipients.dedup();

    let awaiting_approval = nostr_vpn_core::join_delivery::load_join_rosters(config_path)
        .into_iter()
        .map(|(_, delivery)| delivery.recipient_npub)
        .collect();
    let (ready_recipients, mut retry) =
        split_ready_fips_roster_recipients(recipients, &awaiting_approval);
    let mut sent = 0usize;
    for recipient in ready_recipients {
        let roster = removals.get(&recipient).unwrap_or(&signed_roster);
        match runtime.enqueue_roster(&recipient, roster.clone()) {
            Ok(()) => sent += 1,
            Err(error) => {
                eprintln!("fips: roster send to {recipient} failed: {error}");
                retry.insert(recipient);
            }
        }
    }
    *pending_recipients = retry;
    Ok(sent)
}

fn persist_join_roster(
    app: &mut AppConfig,
    config_path: &Path,
    control: &JoinRosterControl,
    vpn_status: &mut String,
) -> Result<Option<String>> {
    let Some(applied_network_id) =
        nostr_vpn_core::join_roster_persistence::apply_join_roster_durably(
            app,
            config_path,
            control,
            unix_timestamp(),
        )?
    else {
        return Ok(None);
    };
    let network_name = app
        .networks
        .iter()
        .find(|network| {
            normalize_runtime_network_id(&network.network_id)
                == normalize_runtime_network_id(&applied_network_id)
        })
        .map(|network| network.name.clone())
        .unwrap_or(applied_network_id);
    *vpn_status = format!("Join approved for {network_name}.");
    Ok(Some(network_name))
}

fn join_roster_is_durably_persisted(
    config_path: &Path,
    control: &JoinRosterControl,
) -> Result<bool> {
    nostr_vpn_core::join_roster_persistence::join_roster_is_durably_persisted(config_path, control)
}

fn split_ready_fips_roster_recipients(
    recipients: Vec<String>,
    awaiting_approval: &HashSet<String>,
) -> (Vec<String>, HashSet<String>) {
    // Do not gate roster sends on nvpn presence. A stale-roster peer may drop
    // Ping/Pong from newly added peers as unknown until this signed roster
    // reaches it, while FIPS can still route/discover the control message.
    // A generic roster can reconfigure a joining peer before its approval
    // receipt returns. Keep that peer pending until the durable outbox clears.
    let (pending, ready): (Vec<_>, Vec<_>) = recipients
        .into_iter()
        .partition(|recipient| awaiting_approval.contains(recipient));
    (ready, pending.into_iter().collect())
}

include!("runtime_endpoint_helpers.rs");
