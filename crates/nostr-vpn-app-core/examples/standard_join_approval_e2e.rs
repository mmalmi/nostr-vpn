use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use nostr_vpn_app_core::join_approval::deliver_queued_join_rosters;
use nostr_vpn_app_core::join_request_link::parse_join_request_qr_code_or_link;
use nostr_vpn_app_core::{FfiApp, NativeAppAction};
use nostr_vpn_core::config::{AppConfig, normalize_nostr_pubkey};
use nostr_vpn_core::join_delivery::load_join_rosters;
use serde_json::json;

const DEFAULT_NETWORK_NAME: &str = "Standard join e2e";

struct Args {
    data_dir: PathBuf,
    join_request: String,
    nvpn_bin: Option<PathBuf>,
    timeout: Duration,
    network_name: String,
    fips_websocket_seed_urls: Vec<String>,
}

fn parse_args() -> Result<Args> {
    let mut values = env::args().skip(1);
    let mut data_dir = None;
    let mut join_request = None;
    let mut nvpn_bin = None;
    let mut timeout_secs = 30_u64;
    let mut network_name = DEFAULT_NETWORK_NAME.to_string();
    let mut fips_websocket_seed_urls = Vec::new();
    while let Some(flag) = values.next() {
        let mut value = || {
            values
                .next()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(value()?)),
            "--join-request" => join_request = Some(value()?),
            "--nvpn-bin" => nvpn_bin = Some(PathBuf::from(value()?)),
            "--timeout-secs" => timeout_secs = value()?.parse().context("invalid timeout")?,
            "--network-name" => network_name = value()?,
            "--fips-websocket-seed-url" => fips_websocket_seed_urls.push(value()?),
            _ => bail!("unknown argument {flag}"),
        }
    }
    Ok(Args {
        data_dir: data_dir.context("--data-dir is required")?,
        join_request: join_request.context("--join-request is required")?,
        nvpn_bin,
        timeout: Duration::from_secs(timeout_secs.max(1)),
        network_name,
        fips_websocket_seed_urls,
    })
}

fn initialize_or_load_admin(
    config_path: &Path,
    network_name: &str,
    fips_websocket_seed_urls: &[String],
) -> Result<AppConfig> {
    if config_path.exists() {
        let mut config = AppConfig::load(config_path)?;
        let mut changed = false;
        if config.autoconnect {
            config.autoconnect = false;
            changed = true;
        }
        if !fips_websocket_seed_urls.is_empty()
            && config.fips_websocket_seed_urls != fips_websocket_seed_urls
        {
            config.fips_websocket_seed_urls = fips_websocket_seed_urls.to_vec();
            config.ensure_defaults();
            changed = true;
        }
        if changed {
            config.save(config_path)?;
        }
        return Ok(config);
    }
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create isolated data directory {}", parent.display()))?;
    }
    let mut config = AppConfig::generated_without_networks();
    config.node_name = "standard-join-admin".to_string();
    let network_id = config.add_owned_network(network_name);
    config.set_network_enabled(&network_id, true)?;
    config.set_network_join_requests_enabled(&network_id, true)?;
    config.autoconnect = false;
    config.fips_websocket_seed_urls = fips_websocket_seed_urls.to_vec();
    config.ensure_defaults();
    config.save(config_path)?;
    Ok(config)
}

fn run() -> Result<()> {
    let args = parse_args()?;
    let parsed = parse_join_request_qr_code_or_link(&args.join_request)
        .map_err(|error| anyhow!("{error:#}"))?;
    let recipient = normalize_nostr_pubkey(&parsed.bootstrap.device_app_key_npub)?;
    let config_path = args.data_dir.join("config.toml");
    let websocket = fips_core::config::WebSocketConfig {
        seed_urls: args.fips_websocket_seed_urls.clone(),
        ..Default::default()
    };
    websocket
        .validate()
        .map_err(|error| anyhow!("invalid FIPS WebSocket seed: {error}"))?;
    let admin = initialize_or_load_admin(
        &config_path,
        &args.network_name,
        &args.fips_websocket_seed_urls,
    )?;
    let network_id = admin
        .active_network_opt()
        .context("isolated admin has no active network")?
        .id
        .clone();
    let runtime = FfiApp::new_with_config_path(
        config_path.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        args.nvpn_bin,
    );
    let state = runtime.dispatch(NativeAppAction::ImportJoinRequest {
        request: args.join_request,
    });
    if !state.error.is_empty() {
        bail!("normal ImportJoinRequest action failed: {}", state.error);
    }
    let approved = AppConfig::load(&config_path)?;
    let network = approved
        .network_by_id(&network_id)
        .context("approved network disappeared")?;
    if !network.devices.iter().any(|device| device == &recipient) {
        bail!("normal ImportJoinRequest action did not add the requested device");
    }
    let initial_queue = load_join_rosters(&config_path);
    if initial_queue.is_empty() {
        bail!("normal ImportJoinRequest action did not queue roster delivery");
    }
    emit(&json!({
        "ok": true,
        "event": "approved",
        "configPath": config_path,
        "networkId": network_id,
        "recipient": recipient,
        "queueDepth": initial_queue.len(),
    }));

    let delivered = deliver_queued_join_rosters(&config_path, args.timeout)
        .map_err(|error| anyhow!("{error:#}"))?;
    if !load_join_rosters(&config_path).is_empty() {
        bail!("ordinary queued roster delivery did not drain");
    }
    emit(&json!({
        "ok": true,
        "event": "delivered",
        "configPath": config_path,
        "networkId": network_id,
        "recipient": recipient,
        "delivered": delivered,
        "queueDrained": true,
        "vpnStatus": runtime.state().vpn_status,
    }));
    Ok(())
}

fn emit(value: &serde_json::Value) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{value}");
    let _ = stdout.flush();
}

fn init_tracing() {
    let Ok(filter) = env::var("NVPN_STANDARD_JOIN_RUST_LOG") else {
        return;
    };
    if filter.trim().is_empty() || filter.trim().eq_ignore_ascii_case("off") {
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(io::stderr)
        .try_init();
}

fn main() -> ExitCode {
    init_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit(&json!({"ok": false, "event": "error", "error": format!("{error:#}")}));
            ExitCode::FAILURE
        }
    }
}
