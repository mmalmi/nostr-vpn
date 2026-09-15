fn wireguard_exit_status_json(app: &AppConfig) -> serde_json::Value {
    json!({
        "enabled": app.wireguard_exit.enabled,
        "configured": app.wireguard_exit.configured(),
        "interface": &app.wireguard_exit.interface,
        "address": &app.wireguard_exit.address,
        "endpoint": &app.wireguard_exit.endpoint,
        "allowed_ips": &app.wireguard_exit.allowed_ips,
        "dns": &app.wireguard_exit.dns,
        "mtu": app.wireguard_exit.mtu,
        "persistent_keepalive_secs": app.wireguard_exit.persistent_keepalive_secs,
    })
}

fn apply_cached_active_network_roster(app: &mut AppConfig, path: &Path) -> Result<bool> {
    let Some(network) = app.active_network_opt() else {
        return Ok(false);
    };
    let network_id = network.network_id.clone();
    let Some(signed_roster) = load_signed_rosters(&signed_rosters_file_path(path))?
        .latest_for(&network_id)
        .cloned()
    else {
        return Ok(false);
    };
    app.apply_verified_admin_signed_shared_roster(&signed_roster)
}

fn runtime_local_tunnel_ip(app: &AppConfig, network_id: &str) -> String {
    if let Ok(own_pubkey) = app.own_nostr_pubkey_hex()
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(network_id, &own_pubkey)
    {
        return tunnel_ip;
    }
    app.node.tunnel_ip.clone()
}

fn runtime_peer_tunnel_ips(app: &AppConfig, network_id: &str) -> Vec<String> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut ips = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| derive_mesh_tunnel_ip(network_id, &participant))
        .collect::<Vec<_>>();
    ips.sort();
    ips.dedup();
    ips
}

fn configured_fips_peer_announcements(app: &AppConfig, network_id: &str) -> Vec<PeerAnnouncement> {
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut peers = app
        .participant_pubkeys_hex()
        .into_iter()
        .filter(|participant| Some(participant) != own_pubkey.as_ref())
        .filter_map(|participant| {
            let tunnel_ip = derive_mesh_tunnel_ip(network_id, &participant)?;
            let node_id = app
                .magic_dns_name_for_participant(&participant)
                .or_else(|| app.peer_alias(&participant))
                .unwrap_or_else(|| participant.clone());
            Some(PeerAnnouncement {
                node_id,
                public_key: participant,
                endpoint: "fips".to_string(),
                local_endpoint: None,
                public_endpoint: None,
                tunnel_ip,
                advertised_routes: Vec::new(),
                timestamp: 0,
            })
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    peers
}

pub(crate) fn shared_roster_publish_allowed(
    app: &AppConfig,
    network_id: &str,
    own_pubkey: &str,
    signed_by: &str,
) -> bool {
    let Ok(own_pubkey) = normalize_nostr_pubkey(own_pubkey) else {
        return false;
    };
    if !app.is_network_admin(network_id, &own_pubkey) {
        return false;
    }

    let signed_by = normalize_nostr_pubkey(signed_by).unwrap_or_default();
    signed_by.is_empty() || signed_by == own_pubkey
}

fn network_roster_from_shared(shared: &SharedNetworkRoster) -> NetworkRoster {
    NetworkRoster {
        network_name: shared.name.clone(),
        devices: shared.devices.clone(),
        admins: shared.admins.clone(),
        aliases: shared.aliases.clone(),
        signed_at: if shared.updated_at > 0 {
            shared.updated_at
        } else {
            unix_timestamp()
        },
    }
}

fn signed_roster_matches_shared(
    signed_roster: &SignedRoster,
    shared: &SharedNetworkRoster,
) -> bool {
    let Ok(signed_network_id) = signed_roster.network_id() else {
        return false;
    };
    if normalize_runtime_network_id(&signed_network_id)
        != normalize_runtime_network_id(&shared.network_id)
    {
        return false;
    }

    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    let shared_signed_by = normalize_nostr_pubkey(&shared.signed_by).unwrap_or_default();
    if shared_signed_by.is_empty() || shared_signed_by != signed_by {
        return false;
    }

    let Ok(roster) = signed_roster.roster() else {
        return false;
    };
    roster == network_roster_from_shared(shared)
}

fn active_signed_roster_for_sync(
    app: &AppConfig,
    config_path: &Path,
    allow_forwarded: bool,
) -> Result<Option<SignedRoster>> {
    let Some(network) = app.active_network_opt() else {
        return Ok(None);
    };
    let shared = app.shared_network_roster(&network.id)?;
    let store_path = signed_rosters_file_path(config_path);
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let mut store = load_signed_rosters(&store_path)?;
    if let Some(stored) = store
        .latest_for(&shared.network_id)
        .filter(|stored| signed_roster_matches_shared(stored, &shared))
        .filter(|stored| {
            allow_forwarded
                || own_pubkey.as_deref().is_some_and(|own_pubkey| {
                    stored.signer_pubkey_hex().ok().as_deref() == Some(own_pubkey)
                })
        })
        .cloned()
    {
        if store.record_removals(&stored, &network.removed_devices)? {
            nostr_vpn_core::signed_rosters::write_signed_rosters(&store_path, &store)?;
        }
        return Ok(Some(stored));
    }

    let Some(own_pubkey) = own_pubkey else {
        return Ok(None);
    };
    if !shared_roster_publish_allowed(app, &network.id, &own_pubkey, &shared.signed_by) {
        return Ok(None);
    }

    let signed_roster = SignedRoster::sign(
        &shared.network_id,
        network_roster_from_shared(&shared),
        &app.nostr_keys()?,
    )?;
    store.upsert(signed_roster.clone())?;
    store.record_removals(&signed_roster, &network.removed_devices)?;
    nostr_vpn_core::signed_rosters::write_signed_rosters(&store_path, &store)?;
    Ok(Some(signed_roster))
}

fn signed_roster_is_current_for_app(
    app: &AppConfig,
    network_id: &str,
    signed_roster: &SignedRoster,
) -> bool {
    let Ok(signed_by) = signed_roster.signer_pubkey_hex() else {
        return false;
    };
    app.networks.iter().any(|network| {
        normalize_runtime_network_id(&network.network_id)
            == normalize_runtime_network_id(network_id)
            && network.shared_roster_updated_at == signed_roster.signed_at()
            && normalize_nostr_pubkey(&network.shared_roster_signed_by)
                .is_ok_and(|value| value == signed_by)
    })
}
const FIPS_ROSTER_RESEND_SECS: u64 = 60;
#[derive(Default)]
struct FipsRosterSyncState {
    sent_by_peer: HashMap<String, FipsRosterSentState>,
    source: Option<(String, u64, String)>,
    roster: Option<SignedRoster>,
    removal_rosters: HashMap<String, SignedRoster>,
    removal_sends: HashMap<String, FipsRosterRemovalSend>,
}
struct FipsRosterRemovalSend {
    hash: String,
    attempted_at: u64,
    delivered: bool,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for FipsRosterRemovalSend {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
struct FipsRosterSentState {
    hash: String,
    sent_at: u64,
}
async fn sync_fips_roster_with_connected_peers(
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    state: &mut FipsRosterSyncState,
) -> Result<usize> {
    let source = app.active_network_opt().map(|network| {
        (
            normalize_runtime_network_id(&network.network_id),
            network.shared_roster_updated_at,
            network.shared_roster_signed_by.clone(),
        )
    });
    if state.source != source {
        state.roster = active_signed_roster_for_sync(app, config_path, true)?;
        let mut store = load_signed_rosters(&signed_rosters_file_path(config_path))?;
        state.removal_rosters = source
            .as_ref()
            .and_then(|(network_id, _, _)| store.removals.remove(network_id))
            .unwrap_or_default();
        state.removal_sends.retain(|peer, sent| {
            state
                .removal_rosters
                .get(peer)
                .is_some_and(|roster| roster.content_hash() == sent.hash)
        });
        state.source = state.roster.as_ref().map(|_| source).unwrap_or_default();
    }
    let Some(signed_roster) = state.roster.clone() else {
        return Ok(0);
    };
    let now = unix_timestamp();
    let roster_hash = signed_roster.content_hash();
    let own_pubkey = app.own_nostr_pubkey_hex().ok();
    let roster_peers = app
        .active_network_signal_pubkeys_hex()
        .into_iter()
        .collect::<HashSet<_>>();
    let connected = runtime
        .peer_statuses()
        .into_iter()
        .filter(|status| status.connected)
        .filter(|status| own_pubkey.as_deref() != Some(status.pubkey.as_str()))
        .map(|status| status.pubkey)
        .collect::<HashSet<_>>();

    // A removed member no longer appears in the private roster, but its
    // authenticated FIPS connection can still receive its signed removal.
    // Wait for TCP acknowledgement off the daemon loop, retry failed sends,
    // and stop after delivery. Never send it later roster revisions.
    for (peer, roster) in &state.removal_rosters {
        if let Some(sent) = state.removal_sends.get_mut(peer) {
            if sent.task.as_ref().is_some_and(|task| task.is_finished()) {
                match sent.task.take().unwrap().await {
                    Ok(Ok(())) => sent.delivered = true,
                    Ok(Err(error)) => eprintln!("fips: removal roster delivery failed: {error}"),
                    Err(error) => eprintln!("fips: removal roster delivery task failed: {error}"),
                }
            }
            if sent.delivered
                || sent.task.is_some()
                || now.saturating_sub(sent.attempted_at) < FIPS_ROSTER_RESEND_SECS
            {
                continue;
            }
        }
        if connected.contains(peer) {
            let delivery = runtime.roster_delivery(peer.clone(), roster.clone())?;
            state.removal_sends.insert(
                peer.clone(),
                FipsRosterRemovalSend {
                    hash: roster.content_hash(),
                    attempted_at: now,
                    delivered: false,
                    task: Some(tokio::spawn(delivery)),
                },
            );
        }
    }

    let awaiting_approval = nostr_vpn_core::join_delivery::load_join_rosters(config_path)
        .into_iter()
        .map(|(_, queued)| queued.recipient_npub)
        .collect();
    let (connected, _) = split_ready_fips_roster_recipients(
        connected
            .into_iter()
            .filter(|peer| roster_peers.contains(peer))
            .collect(),
        &awaiting_approval,
    );

    state
        .sent_by_peer
        .retain(|peer, _| connected.contains(peer));

    let mut sent = 0usize;
    for peer in connected {
        if state.sent_by_peer.get(&peer).is_some_and(|sent| {
            sent.hash == roster_hash && now.saturating_sub(sent.sent_at) < FIPS_ROSTER_RESEND_SECS
        }) {
            continue;
        }
        runtime.enqueue_roster(&peer, signed_roster.clone())?;
        state.sent_by_peer.insert(
            peer,
            FipsRosterSentState {
                hash: roster_hash.clone(),
                sent_at: now,
            },
        );
        sent += 1;
    }
    Ok(sent)
}
