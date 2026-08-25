use super::*;

const PAID_EXIT_MANUAL_HEALTH_TIMEOUT_SECS: u64 = 30;

#[derive(Default)]
pub(crate) struct PaidExitManualBuyer {
    generation: u64,
    session_id: String,
    selected_at: u64,
    probe_succeeded: bool,
    probe: Option<PaidExitManualProbe>,
}

struct PaidExitManualProbe {
    generation: u64,
    task: tokio::task::JoinHandle<Result<PaidRouteProbeMeasurement>>,
}

impl PaidExitManualBuyer {
    fn cancel(&mut self) {
        if let Some(probe) = self.probe.take() {
            probe.task.abort();
        }
        self.generation = self.generation.wrapping_add(1);
        self.session_id.clear();
        self.selected_at = 0;
        self.probe_succeeded = false;
    }

    fn select(&mut self, session_id: &str, now_unix: u64) {
        self.cancel();
        self.session_id = session_id.to_string();
        self.selected_at = now_unix;
    }
}

pub(crate) async fn update_manual_paid_exit(
    manual: &mut PaidExitManualBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    now_unix: u64,
) -> Result<bool> {
    if app.internet_source != nostr_vpn_core::config::InternetSource::PaidManual {
        manual.cancel();
        return Ok(false);
    }
    let Some(seller_pubkey) = app.public_paid_exit_node_pubkey_hex() else {
        manual.cancel();
        return Ok(false);
    };
    let store_path = paid_route_store_file_path(config_path);
    let store = load_paid_route_store(&store_path)?;
    let session_id = store.selected_buyer_session_id.trim().to_string();
    if session_id.is_empty() {
        manual.cancel();
        return Ok(false);
    }
    if manual.session_id != session_id {
        manual.select(&session_id, now_unix);
    }
    if manual.probe_succeeded {
        return Ok(false);
    }

    let seller_admitted = store.buyer_session_is_seller_admitted(&session_id)?;
    let seller_authenticated = runtime.peer_statuses().iter().any(|status| {
        status.connected
            && normalize_nostr_pubkey(&status.pubkey).ok().as_deref()
                == Some(seller_pubkey.as_str())
    });
    if manual.probe.is_none() && seller_admitted && seller_authenticated {
        let probe_app = app.clone();
        manual.probe = Some(PaidExitManualProbe {
            generation: manual.generation,
            task: tokio::spawn(async move {
                paid_exit_route_probe_measurement(&probe_app, now_unix).await
            }),
        });
        eprintln!("paid-exit: checking selected manual seller Internet egress");
    }

    if manual
        .probe
        .as_ref()
        .is_some_and(|probe| probe.task.is_finished())
    {
        let probe = manual.probe.take().expect("finished manual probe exists");
        let generation = probe.generation;
        let result = match probe.task.await {
            Ok(result) => result,
            Err(error) => {
                return fail_manual_paid_exit(
                    manual,
                    app,
                    config_path,
                    &format!("Seller Internet health-check task failed: {error}"),
                    now_unix,
                );
            }
        };
        if generation == manual.generation {
            match result {
                Ok(measurement) => {
                    record_paid_exit_probe(config_path, &session_id, measurement, now_unix)?;
                    manual.probe_succeeded = true;
                    eprintln!("paid-exit: selected manual seller Internet egress is healthy");
                    return Ok(false);
                }
                Err(error) => {
                    return fail_manual_paid_exit(
                        manual,
                        app,
                        config_path,
                        &format!("Seller Internet health check failed: {error}"),
                        now_unix,
                    );
                }
            }
        }
    }

    if now_unix.saturating_sub(manual.selected_at) >= PAID_EXIT_MANUAL_HEALTH_TIMEOUT_SECS {
        return fail_manual_paid_exit(
            manual,
            app,
            config_path,
            "Seller Internet did not become usable within 30 seconds",
            now_unix,
        );
    }
    Ok(false)
}

pub(super) fn fail_manual_paid_exit(
    manual: &mut PaidExitManualBuyer,
    app: &mut AppConfig,
    config_path: &Path,
    reason: &str,
    now_unix: u64,
) -> Result<bool> {
    update_paid_route_store(&paid_route_store_file_path(config_path), |store| {
        store.fail_selected_buyer_session(reason, now_unix)?;
        Ok(())
    })?;
    eprintln!("paid-exit: {reason}; falling back to direct Internet");
    app.set_internet_source(nostr_vpn_core::config::InternetSource::Direct);
    app.save(config_path)?;
    manual.cancel();
    Ok(true)
}
