use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use nostr_vpn_core::config::{AppConfig, normalize_nostr_pubkey};
use nostr_vpn_core::identity_bridge::{
    NostrIdentityDeviceApprovalBootstrap, parse_nostr_identity_device_approval_bootstrap,
};
use nostr_vpn_core::join_delivery::queue_join_roster;
use nostr_vpn_core::join_requests::{
    commit_join_approval, prepare_join_approval, prepare_manual_join_delivery,
};
use serde_json::{Value, json};

use crate::network_signaling::{reload_running_daemon_after_save, resume_running_daemon_for_join};

#[derive(Debug, Args)]
pub(crate) struct JoinRequestsArgs {
    /// Admin configuration; list and approve use its active network.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Print machine-readable output without request secrets.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: JoinRequestsCommand,
}

#[derive(Debug, Subcommand)]
enum JoinRequestsCommand {
    /// List requests received by the daemon for the active network.
    List,
    /// Read a shared join link without approving it or changing configuration.
    Inspect {
        /// File containing one nvpn://join-request/ link; use - for stdin.
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Sign and queue approval for exactly one device in the active network.
    Approve {
        /// File containing the reviewed join link; use - for stdin.
        #[arg(long, required_unless_present = "device", conflicts_with = "device")]
        request_file: Option<PathBuf>,
        /// Device ID of a pending request shown by list (npub or hex).
        #[arg(long, required_unless_present = "request_file")]
        device: Option<String>,
    },
}

pub(crate) fn run(args: JoinRequestsArgs) -> Result<()> {
    let value = match args.command {
        JoinRequestsCommand::Inspect { request_file } => {
            let request = read_request(&request_file)?;
            json!({
                "device_id": normalize_nostr_pubkey(&request.device_app_key_npub)?,
                "request_id": normalize_nostr_pubkey(&request.request_npub)?,
                "name": request.label,
                "approved": false,
            })
        }
        command => {
            let config_path = args.config.unwrap_or_else(crate::default_config_path);
            let app = AppConfig::load(&config_path)
                .with_context(|| format!("failed to load {}", config_path.display()))?;
            let network = app
                .active_network_opt()
                .ok_or_else(|| anyhow!("create or join a network first"))?;
            match command {
                JoinRequestsCommand::List => json!({
                    "network_id": network.network_id,
                    "network_name": network.name,
                    "requests": network.inbound_join_requests,
                }),
                JoinRequestsCommand::Approve {
                    request_file,
                    device,
                } => {
                    let network_entry_id = network.id.clone();
                    let signer = app.own_nostr_pubkey_hex()?;
                    if !network.admins.contains(&signer) {
                        return Err(anyhow!("active network is not administered by this device"));
                    }
                    let (updated, recipient, roster) = if let Some(path) = request_file {
                        let request = read_request(&path)?;
                        let recipient = normalize_nostr_pubkey(&request.device_app_key_npub)?;
                        let prepared = prepare_join_approval(
                            &app,
                            &network_entry_id,
                            &request,
                            crate::unix_timestamp(),
                        )?;
                        (prepared.updated_config, recipient, prepared.join_roster)
                    } else {
                        let recipient = normalize_nostr_pubkey(
                            device
                                .as_deref()
                                .ok_or_else(|| anyhow!("select one request"))?,
                        )?;
                        let pending = network
                            .inbound_join_requests
                            .iter()
                            .find(|request| request.requester == recipient)
                            .ok_or_else(|| anyhow!("no pending join request from this device"))?;
                        let mut updated = app.clone();
                        updated.add_participant_to_network(&network_entry_id, &recipient)?;
                        if !pending.requester_node_name.trim().is_empty() {
                            let _ =
                                updated.set_peer_alias(&recipient, &pending.requester_node_name);
                        }
                        updated
                            .network_by_id_mut(&network_entry_id)
                            .ok_or_else(|| anyhow!("network not found"))?
                            .inbound_join_requests
                            .retain(|request| request.requester != recipient);
                        let roster =
                            prepare_manual_join_delivery(&updated, &network_entry_id, &recipient)?;
                        (updated, recipient, roster)
                    };
                    // Match native approval: one serialized read-modify-write
                    // reloads the on-disk roster, queues the durable outbox
                    // entry, and saves under a cross-process lock so a second
                    // concurrent approval cannot pass the same check.
                    commit_join_approval(&config_path, &app, &network_entry_id, || {
                        queue_join_roster(&config_path, &recipient, &roster)?;
                        updated.save(&config_path)
                    })?;
                    reload_running_daemon_after_save(&config_path)?;
                    resume_running_daemon_for_join(&config_path)?;
                    json!({
                        "network_id": roster.signed_roster.network_id()?,
                        "device_id": recipient,
                        "approved": true,
                        "delivery": "queued",
                        "roster_event_id": roster.signed_roster.event.id.to_hex(),
                    })
                }
                JoinRequestsCommand::Inspect { .. } => unreachable!(),
            }
        }
    };
    print_result(&value, args.json)
}

fn read_request(path: &Path) -> Result<NostrIdentityDeviceApprovalBootstrap> {
    const MAX_LINK_BYTES: u64 = 16 * 1024;
    let input: Box<dyn Read> = if path == Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path).context("failed to open join request file")?)
    };
    let mut link = String::new();
    input
        .take(MAX_LINK_BYTES + 1)
        .read_to_string(&mut link)
        .context("failed to read join request link")?;
    if link.len() as u64 > MAX_LINK_BYTES {
        return Err(anyhow!("join request link exceeds 16 KiB"));
    }
    parse_nostr_identity_device_approval_bootstrap(
        link.trim(),
        &[crate::pairing_qr::JOIN_REQUEST_LINK_PREFIX],
    )
    .context("invalid join request link")?
    .ok_or_else(|| anyhow!("unsupported join request link"))
}

fn print_result(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else if let Some(requests) = value.get("requests").and_then(Value::as_array) {
        println!(
            "Network: {}",
            value["network_name"].as_str().unwrap_or_default()
        );
        for request in requests {
            println!(
                "{}  {}",
                request["requester"].as_str().unwrap_or_default(),
                request["requester_node_name"].as_str().unwrap_or_default()
            );
        }
        if requests.is_empty() {
            println!("No pending requests. To review a shared link, use join-requests inspect.");
        }
    } else {
        println!(
            "Device: {}",
            value["device_id"].as_str().unwrap_or_default()
        );
        if value["approved"] == true {
            println!(
                "Approved; delivery queued. Keep both daemons connected until the joining device confirms approval."
            );
        } else {
            println!("Name: {}", value["name"].as_str().unwrap_or_default());
            println!("Not approved. Verify the device ID with the person or agent joining.");
        }
    }
    Ok(())
}
