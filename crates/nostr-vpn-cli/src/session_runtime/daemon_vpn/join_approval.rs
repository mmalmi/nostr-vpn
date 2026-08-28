use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::join_delivery::{
    join_roster_delivery_expired, load_join_rosters, record_join_roster_attempt,
};

use crate::fips_private_mesh::FipsPrivateTunnelRuntime;
use crate::{broadcast_local_fips_capabilities, publish_fips_active_network_roster};

static IN_FLIGHT_JOIN_ROSTERS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

const JOIN_ROSTER_DELIVERY_WAIT_GRACE: Duration = Duration::from_secs(1);

fn in_flight_join_rosters() -> &'static Mutex<HashSet<PathBuf>> {
    IN_FLIGHT_JOIN_ROSTERS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub(super) fn respond_to_join_request(
    app: &mut AppConfig,
    request: crate::DaemonJoinRequestIpcRequest,
) {
    let response = if app.active_network_has_confirmed_local_identity() {
        Err("this device is already approved for its active network".to_string())
    } else {
        if request.reset {
            app.clear_pending_nostr_join_request();
        }
        app.ensure_pending_nostr_join_request(crate::unix_timestamp())
            .and_then(|_| {
                app.pending_nostr_join_request_link(crate::pairing_qr::JOIN_REQUEST_LINK_PREFIX)
            })
            .map_err(|error| error.to_string())
    };
    let _ = request.response.send(response);
}

pub(super) async fn publish_fips_control_updates(
    runtime: &FipsPrivateTunnelRuntime,
    app: &AppConfig,
    config_path: &Path,
    pending_roster_recipients: &mut HashSet<String>,
    fips_sync_succeeded: bool,
    fips_runtime_replaced: bool,
) {
    if fips_sync_succeeded {
        let delivery_tasks = if fips_runtime_replaced {
            start_queued_join_roster_deliveries(runtime, config_path)
        } else {
            Vec::new()
        };
        wait_for_join_roster_delivery_tasks(
            delivery_tasks,
            crate::fips_private_mesh::JOIN_ROSTER_DELIVERY_TIMEOUT
                + JOIN_ROSTER_DELIVERY_WAIT_GRACE,
        )
        .await;
    }
    if let Err(error) =
        publish_fips_active_network_roster(runtime, app, config_path, pending_roster_recipients)
    {
        eprintln!("fips: roster publish failed after control request: {error}");
    }
    if let Err(error) = broadcast_local_fips_capabilities(runtime, app).await {
        eprintln!("fips: capabilities broadcast failed after control request: {error}");
    }
}

pub(super) async fn finish_join_roster_deliveries_before_runtime_sync(
    delivery_tasks: Vec<tokio::task::JoinHandle<bool>>,
) {
    wait_for_join_roster_delivery_tasks(
        delivery_tasks,
        crate::fips_private_mesh::JOIN_ROSTER_DELIVERY_TIMEOUT + JOIN_ROSTER_DELIVERY_WAIT_GRACE,
    )
    .await;
}

fn claim_join_roster_delivery(path: &Path) -> bool {
    in_flight_join_rosters()
        .lock()
        .is_ok_and(|mut paths| paths.insert(path.to_path_buf()))
}

fn release_join_roster_delivery(path: &Path) {
    if let Ok(mut paths) = in_flight_join_rosters().lock() {
        paths.remove(path);
    }
}

async fn wait_for_join_roster_delivery_tasks(
    tasks: Vec<tokio::task::JoinHandle<bool>>,
    timeout: Duration,
) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut delivered = 0;
    for mut task in tasks {
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(true)) => delivered += 1,
            Ok(Ok(false) | Err(_)) => {}
            Err(_) => {
                task.abort();
                let _ = task.await;
            }
        }
    }
    delivered
}

struct JoinRosterDeliveryClaim(PathBuf);

impl Drop for JoinRosterDeliveryClaim {
    fn drop(&mut self) {
        release_join_roster_delivery(&self.0);
    }
}

fn track_join_roster_delivery(
    path: PathBuf,
    participant: String,
    delivery: crate::fips_private_mesh::FipsJoinRosterDelivery,
) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        let _claim = JoinRosterDeliveryClaim(path.clone());
        let result = delivery.await;
        finish_join_roster_delivery(&path, &participant, result)
    })
}

pub(super) fn start_queued_join_roster_deliveries(
    runtime: &FipsPrivateTunnelRuntime,
    config_path: &Path,
) -> Vec<tokio::task::JoinHandle<bool>> {
    // The outbox is committed before the UI asks the daemon to reload. Read
    // the authoritative persisted roster here so a heartbeat holding the old
    // in-memory snapshot cannot reject or claim the new approval first.
    let participants = match AppConfig::load(config_path) {
        Ok(app) => app.participant_pubkeys_hex(),
        Err(error) => {
            eprintln!("join roster delivery is waiting for readable config: {error:#}");
            return Vec::new();
        }
    };
    let mut deliveries = Vec::new();
    for (path, mut queued) in load_join_rosters(config_path) {
        if !claim_join_roster_delivery(&path) {
            continue;
        }
        if join_roster_delivery_expired(&queued, crate::unix_timestamp()) {
            release_join_roster_delivery(&path);
            consume_join_roster(&path);
            eprintln!(
                "expired queued join approval for {}; removed it from the outbox",
                queued.recipient_npub
            );
            continue;
        }
        if !participants.contains(&queued.recipient_npub) {
            release_join_roster_delivery(&path);
            finish_join_roster_delivery(
                &path,
                &queued.recipient_npub,
                Err(anyhow::anyhow!(
                    "recipient {} is not in the roster",
                    queued.recipient_npub
                )),
            );
            continue;
        }
        let participant = queued.recipient_npub.clone();
        let delivery =
            match runtime.join_roster_delivery(participant.clone(), queued.join_roster.clone()) {
                Ok(delivery) => delivery,
                Err(error) => {
                    release_join_roster_delivery(&path);
                    finish_join_roster_delivery(&path, &participant, Err(error));
                    continue;
                }
            };
        if let Err(error) = record_join_roster_attempt(&path, &mut queued, crate::unix_timestamp())
        {
            release_join_roster_delivery(&path);
            finish_join_roster_delivery(&path, &participant, Err(error));
            continue;
        }

        deliveries.push(track_join_roster_delivery(path, participant, delivery));
    }
    deliveries
}

fn finish_join_roster_delivery(path: &Path, recipient: &str, delivery: anyhow::Result<()>) -> bool {
    match delivery {
        Ok(()) => {
            consume_join_roster(path);
            eprintln!(
                "delivered and applied one signed join roster over FIPS-TCP to {}",
                recipient
            );
            true
        }
        Err(error) => {
            eprintln!(
                "join roster was not durably applied over FIPS-TCP ({error:#}); retaining it for retry"
            );
            false
        }
    }
}

fn consume_join_roster(path: &Path) {
    if let Err(error) = fs::remove_file(path) {
        eprintln!("failed to remove join roster {}: {error}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_join_route_delivery_fits_the_public_ui_completion_deadline() {
        const PUBLIC_UI_COMPLETION_DEADLINE_SECS: u64 = 15;
        let existing_route_delivery_budget = crate::fips_private_mesh::JOIN_ROSTER_DELIVERY_TIMEOUT
            .as_secs()
            + JOIN_ROSTER_DELIVERY_WAIT_GRACE.as_secs();

        assert!(existing_route_delivery_budget <= PUBLIC_UI_COMPLETION_DEADLINE_SECS);
        assert!(crate::fips_private_mesh::JOIN_ROSTER_DELIVERY_TIMEOUT >= Duration::from_secs(10));
    }

    #[test]
    fn approved_device_ipc_does_not_create_another_join_request() {
        let mut app = AppConfig::generated_without_networks();
        let network_id = app.add_owned_network("Approved network");
        let own_pubkey = app.own_nostr_pubkey_hex().expect("own public key");
        app.network_by_id_mut(&network_id)
            .expect("owned network")
            .devices
            .push(own_pubkey);
        app.set_network_enabled(&network_id, true)
            .expect("enable approved network");
        assert!(app.active_network_has_confirmed_local_identity());
        assert!(app.pending_nostr_join_request.is_none());
        let (response, received) = tokio::sync::oneshot::channel();

        respond_to_join_request(
            &mut app,
            crate::DaemonJoinRequestIpcRequest {
                reset: false,
                response,
            },
        );

        let error = received
            .blocking_recv()
            .expect("daemon response")
            .expect_err("approved device must not receive a new request");
        assert!(error.contains("already"), "unexpected IPC error: {error}");
        assert!(app.pending_nostr_join_request.is_none());
    }

    #[test]
    fn failed_join_roster_delivery_keeps_outbox_file_for_retry() {
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-roster-retry-{}-{}",
            std::process::id(),
            crate::unix_timestamp()
        ));
        fs::write(&path, b"queued").expect("write queued roster");

        finish_join_roster_delivery(&path, "recipient", Err(anyhow::anyhow!("offline")));
        assert!(path.exists(), "failed delivery must retain the outbox file");

        finish_join_roster_delivery(&path, "recipient", Ok(()));
        assert!(
            !path.exists(),
            "durable receipt may consume the outbox file"
        );
    }

    #[tokio::test]
    async fn pre_sync_join_delivery_remains_claimed_through_post_sync_retry() {
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-roster-background-{}-{}",
            std::process::id(),
            crate::unix_timestamp()
        ));
        fs::write(&path, b"queued").expect("write queued roster");
        assert!(claim_join_roster_delivery(&path));

        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        let delivery_task = track_join_roster_delivery(
            path.clone(),
            "recipient".to_string(),
            Box::pin(async move {
                complete_rx.await.expect("release delivery");
                Ok(())
            }),
        );

        assert!(path.exists(), "the slow delivery must still be pending");
        assert!(
            !claim_join_roster_delivery(&path),
            "the post-sync retry must not duplicate the pre-sync delivery"
        );
        complete_tx.send(()).expect("complete delivery");
        wait_for_join_roster_delivery_tasks(vec![delivery_task], Duration::from_secs(1)).await;
        assert!(!path.exists(), "background delivery did not finish");
        assert!(claim_join_roster_delivery(&path));
        release_join_roster_delivery(&path);
    }

    #[tokio::test]
    async fn existing_route_join_delivery_finishes_before_runtime_sync() {
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-roster-convergence-{}-{}",
            std::process::id(),
            crate::unix_timestamp()
        ));
        fs::write(&path, b"queued").expect("write queued roster");
        assert!(claim_join_roster_delivery(&path));

        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        let delivery_task = track_join_roster_delivery(
            path.clone(),
            "recipient".to_string(),
            Box::pin(async move {
                complete_rx.await.expect("release delivery");
                Ok(())
            }),
        );
        let waiter = tokio::spawn(finish_join_roster_deliveries_before_runtime_sync(vec![
            delivery_task,
        ]));

        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "runtime sync must wait for the existing route's durable receipt"
        );
        complete_tx.send(()).expect("complete delivery");
        waiter.await.expect("delivery waiter");
        assert!(!path.exists(), "durable receipt did not consume outbox");
    }

    #[tokio::test]
    async fn timed_out_reload_handoff_releases_delivery_for_current_runtime() {
        let path = std::env::temp_dir().join(format!(
            "nvpn-join-roster-handoff-timeout-{}-{}",
            std::process::id(),
            crate::unix_timestamp()
        ));
        fs::write(&path, b"queued").expect("write queued roster");
        assert!(claim_join_roster_delivery(&path));

        let delivery_task = track_join_roster_delivery(
            path.clone(),
            "recipient".to_string(),
            Box::pin(std::future::pending()),
        );
        assert_eq!(
            wait_for_join_roster_delivery_tasks(vec![delivery_task], Duration::from_millis(10))
                .await,
            0
        );

        assert!(
            claim_join_roster_delivery(&path),
            "timed-out old runtime retained the outbox claim"
        );
        release_join_roster_delivery(&path);
        fs::remove_file(path).expect("remove queued roster");
    }
}
