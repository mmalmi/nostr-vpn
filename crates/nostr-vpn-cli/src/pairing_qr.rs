#[cfg(not(unix))]
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use nostr_vpn_core::config::AppConfig;

#[cfg(not(unix))]
use crate::maybe_reload_running_daemon;
use crate::{
    DaemonRuntimeState, JoinRequestArgs, daemon_state_file_path, default_config_path,
    read_daemon_state, unix_timestamp,
};

pub(crate) const JOIN_REQUEST_LINK_PREFIX: &str = "nvpn://join-request/";
const REQUEST_REACHABILITY_MAX_AGE_SECS: u64 = crate::DAEMON_STATE_PERSIST_INTERVAL_SECS * 3;

#[cfg(all(test, not(unix)))]
pub(crate) fn pending_pairing_uri(config_path: &Path) -> Result<String> {
    let app = AppConfig::load(config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    app.pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
        .context("config has no valid pending device-approval request")
}

pub(crate) fn render_pairing_output(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes()).context("failed to encode pairing QR code")?;
    let qr = code.render::<Dense1x2>().quiet_zone(true).build();
    Ok(format!("{qr}\n\n{uri}\n"))
}

pub(crate) async fn run_join_request(args: JoinRequestArgs) -> Result<()> {
    let config_path = args.config.unwrap_or_else(default_config_path);
    #[cfg(unix)]
    let uri = crate::join_request_ipc::request_daemon_join_request_link(&config_path, args.reset)
        .await
        .context("the nVPN daemon must be running to create an ephemeral join request")?;
    #[cfg(not(unix))]
    let app = ensure_pending_join_request_and_reload(
        &config_path,
        args.reset,
        maybe_reload_running_daemon,
    )?;
    #[cfg(not(unix))]
    let uri = app
        .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
        .context("config has no valid pending device-approval request")?;
    if args.no_qr {
        println!("{uri}");
    } else {
        print!("{}", render_pairing_output(&uri)?);
    }

    let state_path = daemon_state_file_path(&config_path);
    let mut reachability = request_reachability(read_daemon_state(&state_path)?.as_ref());
    println!("{}", reachability.message());
    if args.no_wait {
        return Ok(());
    }
    println!("Waiting for an admin to approve this join request (Ctrl-C to stop waiting).");

    let mut poll = tokio::time::interval(Duration::from_millis(500));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to wait for Ctrl-C")?;
                println!("Stopped waiting; the existing join request remains valid.");
                return Ok(());
            }
            _ = poll.tick() => {
                #[cfg(unix)]
                if AppConfig::load(&config_path)
                    .is_ok_and(|app| app.active_network_has_confirmed_local_identity())
                {
                    println!("Join request accepted.");
                    return Ok(());
                }
                #[cfg(not(unix))]
                let app = AppConfig::load(&config_path)
                    .with_context(|| format!("failed to reload {}", config_path.display()))?;
                #[cfg(unix)]
                if crate::join_request_ipc::request_daemon_join_request_link(&config_path, false)
                    .await
                    .is_ok_and(|current| current != uri)
                {
                    println!("Join request accepted.");
                    return Ok(());
                }
                #[cfg(not(unix))]
                if app.active_network_has_confirmed_local_identity() {
                    println!("Join approved for network {}.", app.effective_network_id());
                    return Ok(());
                }
                let next = request_reachability(read_daemon_state(&state_path)?.as_ref());
                if next != reachability {
                    reachability = next;
                    println!("{}", reachability.message());
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn ensure_pending_join_request_and_reload(
    config_path: &Path,
    reset: bool,
    reload_running_daemon: impl FnOnce(&Path),
) -> Result<AppConfig> {
    let app = ensure_pending_join_request(config_path, reset)?;
    if !app.active_network_has_confirmed_local_identity() {
        reload_running_daemon(config_path);
    }
    Ok(app)
}

#[cfg(not(unix))]
fn ensure_pending_join_request(config_path: &Path, reset: bool) -> Result<AppConfig> {
    let exists = config_path
        .try_exists()
        .with_context(|| format!("failed to inspect {}", config_path.display()))?;
    let mut app = if exists {
        AppConfig::load(config_path)
            .with_context(|| format!("failed to load {}", config_path.display()))?
    } else {
        AppConfig::generated_without_networks()
    };
    app.ensure_defaults();
    if app.active_network_has_confirmed_local_identity() {
        if reset {
            return Err(anyhow::anyhow!(
                "cannot reset a join request after this device has been approved"
            ));
        }
        return Ok(app);
    }
    if reset {
        app.clear_pending_nostr_join_request();
    }
    let changed = app.ensure_pending_nostr_join_request(unix_timestamp())?;
    if !exists || changed || reset {
        app.save(config_path)
            .with_context(|| format!("failed to save {}", config_path.display()))?;
    }
    Ok(app)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestReachability {
    DaemonUnavailable,
    NoFipsPeers,
    FipsReachable,
}

impl RequestReachability {
    fn message(self) -> &'static str {
        match self {
            Self::DaemonUnavailable => {
                "nVPN daemon status is unavailable; the join request is still ready to share."
            }
            Self::NoFipsPeers => {
                "No active FIPS connections; an admin cannot deliver approval yet. The join request is still ready to share."
            }
            Self::FipsReachable => {
                "FIPS connection active; approval can be delivered immediately after an admin accepts."
            }
        }
    }
}

fn request_reachability(state: Option<&DaemonRuntimeState>) -> RequestReachability {
    request_reachability_at(state, unix_timestamp())
}

fn request_reachability_at(state: Option<&DaemonRuntimeState>, now: u64) -> RequestReachability {
    let Some(state) = state else {
        return RequestReachability::DaemonUnavailable;
    };
    // The daemon persists status every five seconds. Give it several write
    // intervals so the waiting UI does not alternate between reachable and
    // unavailable between ordinary state-file updates.
    if now.saturating_sub(state.updated_at) > REQUEST_REACHABILITY_MAX_AGE_SECS {
        return RequestReachability::DaemonUnavailable;
    }
    let connected =
        state.fips_other_peer_count > 0 || state.peers.iter().any(|peer| peer.reachable);
    if connected {
        RequestReachability::FipsReachable
    } else {
        RequestReachability::NoFipsPeers
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(unix))]
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn reachability_stays_stable_across_the_daemon_state_write_interval() {
        let state = DaemonRuntimeState {
            updated_at: 100,
            fips_other_peer_count: 1,
            ..DaemonRuntimeState::default()
        };

        assert_eq!(
            request_reachability_at(Some(&state), 105),
            RequestReachability::FipsReachable,
            "the five-second daemon state cadence must not flap to unavailable"
        );
    }

    #[test]
    fn terminal_output_contains_dense_qr_and_exact_uri() {
        let uri = "nvpn://join-request/eyJkZXZpY2VBcHBLZXlOcHViIjoibnB1YjE";
        let output = render_pairing_output(uri).expect("render pairing output");

        assert!(output.lines().any(|line| line.contains('█')));
        assert!(output.lines().any(|line| line.contains('▀')));
        assert_eq!(output.lines().filter(|line| *line == uri).count(), 1);
        assert!(output.ends_with(&format!("\n\n{uri}\n")));
    }

    #[cfg(not(unix))]
    #[test]
    fn reads_the_canonical_pending_bootstrap_from_config() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nvpn-pairing-qr-{}-{nonce}.toml",
            std::process::id()
        ));
        let mut app = AppConfig::generated();
        app.ensure_pending_nostr_join_request(1_789_000_000)
            .expect("pending request");
        app.save(&path).expect("save config");

        let expected = app
            .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
            .expect("expected URI");
        assert_eq!(pending_pairing_uri(&path).expect("loaded URI"), expected);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(unix))]
    #[test]
    fn pending_request_is_reused_until_explicit_reset() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-request-reset-{}-{nonce}.toml",
            std::process::id()
        ));

        let first = ensure_pending_join_request(&path, false).expect("first request");
        let first_uri = first
            .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
            .expect("first URI");
        let reused = ensure_pending_join_request(&path, false).expect("reused request");
        let reused_uri = reused
            .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
            .expect("reused URI");
        let reset = ensure_pending_join_request(&path, true).expect("reset request");
        let reset_uri = reset
            .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
            .expect("reset URI");

        assert_eq!(first_uri, reused_uri);
        assert_ne!(first_uri, reset_uri);
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete secrets");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(unix))]
    #[test]
    fn pending_request_reload_is_requested_after_the_request_is_persisted() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-request-reload-{}-{nonce}.toml",
            std::process::id()
        ));
        let mut reloads = 0;

        let app = ensure_pending_join_request_and_reload(&path, false, |reload_path| {
            reloads += 1;
            assert_eq!(reload_path, path);
            let persisted = AppConfig::load(reload_path).expect("persisted pending request");
            assert!(
                persisted
                    .pending_nostr_join_request_link(JOIN_REQUEST_LINK_PREFIX)
                    .is_ok()
            );
        })
        .expect("prepare pending request");

        assert_eq!(reloads, 1);
        assert!(!app.active_network_has_confirmed_local_identity());
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete secrets");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(unix))]
    #[test]
    fn approved_request_does_not_reload_the_daemon() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nvpn-approved-join-request-reload-{}-{nonce}.toml",
            std::process::id()
        ));
        let mut approved = AppConfig::generated_without_networks();
        let network_id = approved.add_owned_network("Approved network");
        let own_pubkey = approved.own_nostr_pubkey_hex().expect("own public key");
        approved
            .network_by_id_mut(&network_id)
            .expect("owned network")
            .devices
            .push(own_pubkey);
        approved
            .set_network_enabled(&network_id, true)
            .expect("enable owned network");
        assert!(approved.active_network_has_confirmed_local_identity());
        approved.save(&path).expect("save approved config");
        let mut reloads = 0;

        let app = ensure_pending_join_request_and_reload(&path, false, |_| reloads += 1)
            .expect("load approved request state");

        assert!(app.active_network_has_confirmed_local_identity());
        assert_eq!(reloads, 0);
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete secrets");
        let _ = std::fs::remove_file(path);
    }
}
