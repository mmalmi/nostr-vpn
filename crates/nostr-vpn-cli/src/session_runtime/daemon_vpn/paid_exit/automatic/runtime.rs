use super::*;

pub(crate) async fn paid_exit_route_probe_measurement(
    app: &AppConfig,
    now_unix: u64,
) -> Result<PaidRouteProbeMeasurement> {
    let args = PaidExitProbeArgs {
        config: None,
        session: String::new(),
        ip_url: None,
        stun_servers: Vec::new(),
        no_stun: false,
        geoip_url_template: None,
        no_geoip: true,
        download_url: None,
        upload_url: None,
        bandwidth_bytes: DEFAULT_PAID_ROUTE_BANDWIDTH_BYTES,
        no_bandwidth: false,
        samples: 1,
        timeout_secs: 5,
        no_reload_daemon: true,
        json: false,
    };
    let (measurement, _, bandwidth_error) =
        paid_exit_probe_measurement(&args, app, now_unix).await?;
    if let Some(error) = bandwidth_error {
        eprintln!("paid-exit: automatic bandwidth sample incomplete: {error}");
    }
    if !automatic_probe_observed_public_ip(&measurement) {
        return Err(anyhow!(
            "paid exit free probe did not observe a public exit IP"
        ));
    }
    Ok(measurement)
}

pub(super) fn automatic_probe_observed_public_ip(measurement: &PaidRouteProbeMeasurement) -> bool {
    measurement.realized_exit_ip.is_some() && measurement.success_count() > 0
}

pub(crate) async fn update_automatic_paid_exit(
    automatic: &mut PaidExitAutomaticBuyer,
    runtime: &crate::fips_private_mesh::FipsPrivateTunnelRuntime,
    app: &mut AppConfig,
    config_path: &Path,
    buyer_delta: &PaidRouteUsage,
    now_unix: u64,
) -> Result<bool> {
    automatic.cancel_if_disabled(app);
    if !PaidExitAutomaticBuyer::enabled(app) {
        return Ok(false);
    }

    if let Some(candidate) = automatic.candidate.as_mut() {
        candidate.observe_presence(&runtime.peer_statuses(), now_unix);
        candidate.observe_usage(buyer_delta, now_unix);
    }

    if automatic.probe.is_none()
        && automatic.candidate.as_ref().is_some_and(|candidate| {
            candidate.probe_started_at.is_none()
                && candidate.last_authenticated_at.is_some_and(|observed| {
                    now_unix.saturating_sub(observed) <= PAID_EXIT_AUTO_HEALTH_TTL_SECS
                })
        })
    {
        let probe_app = app.clone();
        if let Some(candidate) = automatic.candidate.as_mut() {
            candidate.probe_started_at = Some(now_unix);
            candidate.last_tx_at = None;
            candidate.last_rx_at = None;
        }
        automatic.probe = Some(PaidExitAutomaticProbe {
            generation: automatic.generation,
            task: tokio::spawn(async move {
                paid_exit_route_probe_measurement(&probe_app, now_unix).await
            }),
        });
    }

    if automatic
        .probe
        .as_ref()
        .is_some_and(|probe| probe.task.is_finished())
    {
        let probe = automatic.probe.take().expect("finished probe exists");
        let result = probe
            .task
            .await
            .map_err(|error| anyhow!("automatic paid exit probe task failed: {error}"))?;
        if probe.generation == automatic.generation {
            match result {
                Ok(measurement) => {
                    let session_id = automatic
                        .candidate
                        .as_ref()
                        .map(|candidate| candidate.session_id.clone())
                        .ok_or_else(|| anyhow!("automatic paid exit probe lost its candidate"))?;
                    record_paid_exit_probe(config_path, &session_id, measurement, now_unix)?;
                    if let Some(candidate) = automatic.candidate.as_mut() {
                        candidate.probe_succeeded = true;
                        if candidate.health_evidence_fresh(now_unix) {
                            candidate.last_healthy_at = Some(now_unix);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("paid-exit: automatic free probe failed: {error}");
                    if let Some(candidate) = automatic.candidate.as_mut() {
                        candidate.failed = true;
                    }
                }
            }
        }
    }

    let fund = automatic.candidate.as_ref().is_some_and(|candidate| {
        !candidate.failed
            && !candidate.funding_attempted
            && candidate.health_evidence_fresh(now_unix)
    });
    if fund {
        let session_id = automatic
            .candidate
            .as_ref()
            .map(|candidate| candidate.session_id.clone())
            .expect("funding candidate exists");
        if let Some(candidate) = automatic.candidate.as_mut() {
            candidate.funding_attempted = true;
        }
        match fund_automatic_paid_exit(app, config_path, &session_id, now_unix).await {
            Ok(envelope) => {
                if let Some(candidate) = automatic.candidate.as_mut() {
                    candidate.funded = true;
                    candidate.last_healthy_at = Some(now_unix);
                }
                if let Err(error) = queue_paid_exit_payment(app, config_path, &envelope) {
                    eprintln!("paid-exit: automatic channel-open queue failed: {error}");
                    if let Some(candidate) = automatic.candidate.as_mut() {
                        candidate.failed = true;
                    }
                }
            }
            Err(error) => {
                eprintln!("paid-exit: automatic funding failed: {error}");
                if let Some(candidate) = automatic.candidate.as_mut() {
                    candidate.failed = true;
                }
            }
        }
    }

    if automatic
        .candidate
        .as_ref()
        .is_some_and(|candidate| candidate.should_failover(now_unix))
    {
        suspend_automatic_paid_exit(automatic, runtime, config_path, now_unix)?;
        if !PaidExitAutomaticBuyer::enabled(app) {
            return Ok(false);
        }
        app.set_internet_source(nostr_vpn_core::config::InternetSource::PaidAutomatic);
        app.save(config_path)?;
        automatic.cancel_candidate(true, now_unix);
        return Ok(true);
    }

    Ok(false)
}

pub(crate) fn record_paid_exit_probe(
    config_path: &Path,
    session_id: &str,
    measurement: PaidRouteProbeMeasurement,
    now_unix: u64,
) -> Result<()> {
    let store_path = paid_route_store_file_path(config_path);
    update_paid_route_store(&store_path, |store| {
        store.update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: session_id.to_string(),
            realized_exit_ip: measurement.realized_exit_ip,
            observed_country_code: measurement.observed_country_code,
            observed_asn: measurement.observed_asn,
            quality: Some(measurement.quality),
            now_unix,
        })?;
        Ok(())
    })
}
