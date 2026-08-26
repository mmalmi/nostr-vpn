
struct PaidExitRecordProbeResult {
    store_path: PathBuf,
    probe: UpdatePaidRouteSessionProbeResult,
}

struct PaidExitProbeResult {
    store_path: PathBuf,
    measurement: PaidRouteProbeMeasurement,
    probe: UpdatePaidRouteSessionProbeResult,
    geoip_error: Option<String>,
    bandwidth_error: Option<String>,
}

async fn paid_exit_probe_command(args: PaidExitProbeArgs) -> Result<()> {
    let json_output = args.json;
    let result = paid_exit_probe_once(args).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_probe_result_json(&result))?
        );
    } else {
        print_paid_exit_probe_result(&result);
    }

    Ok(())
}

async fn paid_exit_probe_once(args: PaidExitProbeArgs) -> Result<PaidExitProbeResult> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let app = load_or_default_config(&config_path)?;
    let now_unix = unix_timestamp();
    let (measurement, geoip_error, bandwidth_error) =
        paid_exit_probe_measurement(&args, &app, now_unix, None).await?;
    let record = paid_exit_record_probe_once(PaidExitRecordProbeArgs {
        config: Some(config_path.clone()),
        session: args.session,
        realized_exit_ip: measurement.realized_exit_ip.clone(),
        observed_country_code: measurement.observed_country_code.clone(),
        observed_asn: measurement.observed_asn,
        latency_ms: measurement.quality.latency_ms,
        jitter_ms: measurement.quality.jitter_ms,
        packet_loss_ppm: measurement.quality.packet_loss_ppm,
        down_bps: measurement.quality.down_bps,
        up_bps: measurement.quality.up_bps,
        uptime_secs: measurement.quality.uptime_secs,
        last_seen_unix: measurement.quality.last_seen_unix,
        no_reload_daemon: args.no_reload_daemon,
        json: false,
    })?;

    Ok(PaidExitProbeResult {
        store_path: record.store_path,
        measurement,
        probe: record.probe,
        geoip_error,
        bandwidth_error,
    })
}

async fn paid_exit_probe_measurement(
    args: &PaidExitProbeArgs,
    app: &AppConfig,
    now_unix: u64,
    bind_interface: Option<&str>,
) -> Result<(PaidRouteProbeMeasurement, Option<String>, Option<String>)> {
    let timeout = Duration::from_secs(args.timeout_secs.max(1));
    let client = paid_exit_probe_http_client(timeout, bind_interface)?;
    let ip_url = args
        .ip_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PAID_ROUTE_PUBLIC_IP_URL);
    let stun_servers = paid_exit_probe_stun_servers(args, app);
    let sample_count = args.samples.clamp(1, 10);
    let mut samples = Vec::with_capacity(usize::from(sample_count));

    for sample_index in 0..sample_count {
        let stun_server = if stun_servers.is_empty() {
            None
        } else {
            Some(stun_servers[usize::from(sample_index) % stun_servers.len()].as_str())
        };
        samples.push(paid_exit_probe_public_ip_sample(&client, ip_url, stun_server, timeout).await);
    }

    let realized_ip = samples
        .iter()
        .rev()
        .find_map(|sample| sample.realized_exit_ip.as_deref());
    let (observed_country_code, observed_asn, geoip_error) =
        if args.no_geoip {
            (None, None, None)
        } else if let Some(realized_ip) = realized_ip {
            let template = args
                .geoip_url_template
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(DEFAULT_PAID_ROUTE_GEOIP_URL_TEMPLATE);
            let url = paid_route_geoip_url(template, realized_ip);
            match paid_exit_probe_fetch_text(&client, &url).await {
                Ok(body) => {
                    let (country, asn) = parse_paid_route_geoip_response(&body);
                    (country, asn, None)
                }
                Err(error) => (None, None, Some(error.to_string())),
            }
        } else {
            (None, None, None)
        };

    let mut measurement =
        build_paid_route_probe_measurement(samples, observed_country_code, observed_asn, now_unix)?;
    let bandwidth_error = paid_exit_probe_bandwidth(&client, args, &mut measurement).await;
    Ok((measurement, geoip_error, bandwidth_error))
}

fn paid_exit_probe_http_client(
    timeout: Duration,
    bind_interface: Option<&str>,
) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(timeout);
    // Daemon health gates bind to the paid tunnel so a route refresh cannot
    // let an in-flight probe escape over the physical underlay and produce a
    // false "Connected" result. The interactive CLI probe intentionally uses
    // the ordinary routing table by passing None.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    let builder = if let Some(interface) = bind_interface {
        builder.interface(interface)
    } else {
        builder
    };
    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    )))]
    let _ = bind_interface;
    builder
        .build()
        .context("failed to build paid exit probe HTTP client")
}

fn paid_exit_probe_stun_servers(args: &PaidExitProbeArgs, app: &AppConfig) -> Vec<String> {
    if args.no_stun {
        return Vec::new();
    }

    let configured = if args.stun_servers.is_empty() {
        &app.nat.stun_servers
    } else {
        &args.stun_servers
    };
    configured
        .iter()
        .map(|server| server.trim())
        .filter(|server| !server.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn paid_exit_probe_public_ip_sample(
    client: &reqwest::Client,
    ip_url: &str,
    stun_server: Option<&str>,
    timeout: Duration,
) -> PaidRouteProbeSample {
    let mut stun_error = None;
    if let Some(stun_server) = stun_server {
        let started = Instant::now();
        match paid_exit_probe_stun_public_ip(stun_server, timeout).await {
            Ok(ip) => return PaidRouteProbeSample::success(ip, elapsed_ms_u32(started.elapsed())),
            Err(error) => stun_error = Some(error.to_string()),
        }
    }

    let started = Instant::now();
    match paid_exit_probe_fetch_text(client, ip_url).await {
        Ok(body) => match parse_paid_route_public_ip_response(&body) {
            Some(ip) => PaidRouteProbeSample::success(ip, elapsed_ms_u32(started.elapsed())),
            None => {
                let message = "public IP response did not contain an IP";
                if let Some(stun_error) = stun_error {
                    PaidRouteProbeSample::failure(format!("stun: {stun_error}; https: {message}"))
                } else {
                    PaidRouteProbeSample::failure(message)
                }
            }
        },
        Err(error) => {
            if let Some(stun_error) = stun_error {
                PaidRouteProbeSample::failure(format!("stun: {stun_error}; https: {error}"))
            } else {
                PaidRouteProbeSample::failure(error.to_string())
            }
        }
    }
}

async fn paid_exit_probe_stun_public_ip(server: &str, timeout: Duration) -> Result<String> {
    let server = server.to_string();
    tokio::task::spawn_blocking(move || paid_exit_probe_stun_public_ip_blocking(&server, timeout))
        .await
        .context("paid exit STUN probe task failed")?
}

fn paid_exit_probe_stun_public_ip_blocking(server: &str, timeout: Duration) -> Result<String> {
    let addr = paid_exit_stun_socket_addr(server)?;
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).context("failed to bind paid exit STUN probe socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set paid exit STUN read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set paid exit STUN write timeout")?;

    let transaction_id = paid_route_stun_transaction_id();
    let request = paid_route_stun_binding_request(transaction_id);
    socket
        .send_to(&request, addr)
        .with_context(|| format!("failed to send paid exit STUN probe to {server}"))?;

    let mut response = [0_u8; 1500];
    let (len, _) = socket
        .recv_from(&mut response)
        .with_context(|| format!("failed to receive paid exit STUN response from {server}"))?;
    parse_paid_route_stun_binding_response(&response[..len], transaction_id)
}

fn paid_exit_stun_socket_addr(server: &str) -> Result<SocketAddr> {
    let (host, port) = paid_route_stun_host_port(server)
        .ok_or_else(|| anyhow!("invalid paid exit STUN server '{server}'"))?;
    (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve paid exit STUN server {server}"))?
        .next()
        .ok_or_else(|| anyhow!("paid exit STUN server {server} did not resolve"))
}

async fn paid_exit_probe_bandwidth(
    client: &reqwest::Client,
    args: &PaidExitProbeArgs,
    measurement: &mut PaidRouteProbeMeasurement,
) -> Option<String> {
    if args.no_bandwidth || args.bandwidth_bytes == 0 {
        return None;
    }

    let bytes = args.bandwidth_bytes;
    let download_base = args
        .download_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PAID_ROUTE_DOWNLOAD_URL);
    let download_url = paid_route_download_url(download_base, bytes);
    let mut errors = Vec::new();

    match paid_exit_probe_download_bps(client, &download_url).await {
        Ok(bps) => measurement.quality.down_bps = Some(bps),
        Err(error) => errors.push(format!("download: {error}")),
    }

    let upload_url = args
        .upload_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PAID_ROUTE_UPLOAD_URL);
    match paid_exit_probe_upload_bps(client, upload_url, bytes).await {
        Ok(bps) => measurement.quality.up_bps = Some(bps),
        Err(error) => errors.push(format!("upload: {error}")),
    }

    if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    }
}

async fn paid_exit_probe_download_bps(client: &reqwest::Client, url: &str) -> Result<u64> {
    let started = Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("paid exit bandwidth endpoint returned an error for {url}"))?;
    let body = response
        .bytes()
        .await
        .with_context(|| format!("failed to read bandwidth response from {url}"))?;
    paid_route_bandwidth_bps(body.len() as u64, started.elapsed())
        .ok_or_else(|| anyhow!("download bandwidth sample was empty or too fast"))
}

async fn paid_exit_probe_upload_bps(
    client: &reqwest::Client,
    url: &str,
    bytes: u64,
) -> Result<u64> {
    let len = usize::try_from(bytes).context("paid exit bandwidth byte count is too large")?;
    let body = vec![0_u8; len];
    let started = Instant::now();
    client
        .post(url)
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to upload to {url}"))?
        .error_for_status()
        .with_context(|| format!("paid exit upload endpoint returned an error for {url}"))?;
    paid_route_bandwidth_bps(bytes, started.elapsed())
        .ok_or_else(|| anyhow!("upload bandwidth sample was empty or too fast"))
}

async fn paid_exit_probe_fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("paid exit probe endpoint returned an error for {url}"))?;
    response
        .text()
        .await
        .with_context(|| format!("failed to read response from {url}"))
}

fn elapsed_ms_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

fn paid_exit_probe_result_json(result: &PaidExitProbeResult) -> serde_json::Value {
    json!({
        "store_path": result.store_path.display().to_string(),
        "measurement": result.measurement,
        "probe": result.probe,
        "geoip_error": result.geoip_error,
        "bandwidth_error": result.bandwidth_error,
    })
}

fn print_paid_exit_probe_result(result: &PaidExitProbeResult) {
    println!("paid_exit_probe_session: {}", result.probe.session_id);
    println!("store: {}", result.store_path.display());
    println!("changed: {}", result.probe.changed);
    println!(
        "realized_exit_ip: {}",
        display_or_none(
            result
                .measurement
                .realized_exit_ip
                .as_deref()
                .unwrap_or_default()
        )
    );
    println!(
        "observed_country: {}",
        display_or_none(
            result
                .measurement
                .observed_country_code
                .as_deref()
                .unwrap_or_default()
        )
    );
    println!(
        "observed_asn: {}",
        result
            .measurement
            .observed_asn
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "quality: {}",
        paid_exit_quality_text(Some(&result.measurement.quality))
    );
    println!(
        "samples: {} ok, {} failed",
        result.measurement.success_count(),
        result.measurement.failure_count()
    );
    if let Some(error) = result.geoip_error.as_deref() {
        println!("geoip_error: {error}");
    }
    if let Some(error) = result.bandwidth_error.as_deref() {
        println!("bandwidth_error: {error}");
    }
}

fn paid_exit_record_probe_command(args: PaidExitRecordProbeArgs) -> Result<()> {
    let json_output = args.json;
    let result = paid_exit_record_probe_once(args)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&paid_exit_record_probe_result_json(&result))?
        );
    } else {
        print_paid_exit_record_probe_result(&result);
    }

    Ok(())
}

fn paid_exit_record_probe_once(args: PaidExitRecordProbeArgs) -> Result<PaidExitRecordProbeResult> {
    let config_path = args.config.clone().unwrap_or_else(default_config_path);
    let store_path = paid_route_store_file_path(&config_path);
    let quality = paid_exit_probe_quality_from_args(&args);
    let result = update_paid_route_store(&store_path, |store| {
        store.update_session_probe(UpdatePaidRouteSessionProbeRequest {
            session_id: args.session,
            realized_exit_ip: args.realized_exit_ip,
            observed_country_code: args.observed_country_code,
            observed_asn: args.observed_asn,
            quality,
            now_unix: unix_timestamp(),
        })
    })?;

    if result.changed && !args.no_reload_daemon {
        maybe_reload_running_daemon(&config_path);
    }

    Ok(PaidExitRecordProbeResult {
        store_path,
        probe: result,
    })
}

fn paid_exit_probe_quality_from_args(
    args: &PaidExitRecordProbeArgs,
) -> Option<PaidRouteQualityMetrics> {
    let quality = PaidRouteQualityMetrics {
        latency_ms: args.latency_ms,
        jitter_ms: args.jitter_ms,
        packet_loss_ppm: args.packet_loss_ppm,
        down_bps: args.down_bps,
        up_bps: args.up_bps,
        uptime_secs: args.uptime_secs,
        last_seen_unix: args.last_seen_unix,
    };
    if quality.is_empty() {
        None
    } else {
        Some(quality)
    }
}

fn paid_exit_record_probe_result_json(result: &PaidExitRecordProbeResult) -> serde_json::Value {
    json!({
        "store_path": result.store_path.display().to_string(),
        "probe": result.probe,
    })
}

fn print_paid_exit_record_probe_result(result: &PaidExitRecordProbeResult) {
    println!("paid_exit_probe_session: {}", result.probe.session_id);
    println!("store: {}", result.store_path.display());
    println!("changed: {}", result.probe.changed);
    println!(
        "realized_exit_ip: {}",
        display_or_none(result.probe.realized_exit_ip.as_deref().unwrap_or_default())
    );
    println!(
        "observed_country: {}",
        display_or_none(
            result
                .probe
                .observed_country_code
                .as_deref()
                .unwrap_or_default()
        )
    );
    println!(
        "observed_asn: {}",
        result
            .probe
            .observed_asn
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "quality: {}",
        paid_exit_quality_text(result.probe.quality.as_ref())
    );
}
