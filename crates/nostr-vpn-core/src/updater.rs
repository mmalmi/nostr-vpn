#[cfg(target_os = "macos")]
use crate::macos_file_io as fs;
#[cfg(not(target_os = "macos"))]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{AppConfig, split_peer_transport_addr};
use anyhow::{Context, Result, anyhow, ensure};
use fips_core::config::{
    PeerAddress, PeerConfig, RoutingMode, TransportInstances, UdpConfig, WebSocketConfig,
};
use fips_core::{Config as FipsConfig, FipsEndpoint};
use hashtree_updater::{
    ProductAssetPolicy, SecurePubsubBlossomConfig, SecurePubsubBlossomSelection, UpdateAsset,
    UpdateManifest, build_secure_pubsub_blossom_updater, current_archive_target, dedupe_nonempty,
    download_product_selection, env_csv, platform_app_asset_suffixes,
    preferred_app_asset_for_suffixes, preferred_cli_asset_for_target, select_product_update,
    selected_download_path as shared_selected_download_path, update_ref_from_override,
};
pub use hashtree_updater::{
    ProductUpdateMode, SECURE_SOURCE_NAME, UpdateAutoCheckPolicy, UpdateEventCache, UpdateRef,
};
use nostr_pubsub::NostrEventSubscriber;
use nostr_pubsub_fips::{FipsPubsubClient, FipsPubsubClientOptions};
use serde::{Deserialize, Serialize};

mod cache;

pub const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/mmalmi/nostr-vpn/releases/latest";
pub const HTREE_MANIFEST_URL: &str = "https://upload.iris.to/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/releases%2Fnostr-vpn/latest/release.json";
pub const HTREE_UPDATE_REF: &str = "htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/releases%2Fnostr-vpn/latest";
pub const LEGACY_HTREE_SOURCE_NAME: &str = "legacy-htree-url";
pub const GITHUB_SOURCE_NAME: &str = "github";

const UPDATE_CONNECT_TIMEOUT_SECS: &str = "4";
const UPDATE_MANIFEST_TIMEOUT_SECS: &str = "8";
const UPDATE_DOWNLOAD_TIMEOUT_SECS: &str = "180";
const UPDATE_USER_AGENT: &str = "nvpn-updater";
const DEFAULT_BLOSSOM_READ_SERVERS: &[&str] = &[
    "https://cdn.iris.to",
    "https://upload.iris.to",
    "https://blossom.primal.net",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductUpdateSource {
    Auto,
    Github,
    Hashtree,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductUpdateResult {
    pub available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub tag: String,
    pub asset: String,
    pub source: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    #[serde(alias = "tag_name")]
    tag: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    #[serde(alias = "browser_download_url")]
    path: String,
}

struct LegacySelection {
    manifest: ReleaseManifest,
    asset: ReleaseAsset,
    asset_url: String,
    source_name: &'static str,
    update_available: bool,
}

enum UpdateSelection {
    Secure(Box<SecurePubsubBlossomSelection>),
    Legacy(LegacySelection),
}

pub fn check_product_update_blocking(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
) -> Result<ProductUpdateResult> {
    check_product_update_blocking_with_config(current_version, mode, source, None)
}

pub fn check_product_update_blocking_with_config(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    config_path: Option<&Path>,
) -> Result<ProductUpdateResult> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start update runtime")?;
    runtime.block_on(check_product_update_with_config(
        current_version,
        mode,
        source,
        config_path,
    ))
}

pub async fn check_product_update(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
) -> Result<ProductUpdateResult> {
    check_product_update_with_config(current_version, mode, source, None).await
}

pub async fn check_product_update_with_config(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    config_path: Option<&Path>,
) -> Result<ProductUpdateResult> {
    let selection = select_update(current_version, mode, source, config_path).await?;
    Ok(result_from_selection(current_version, &selection, None))
}

pub fn download_product_update_blocking(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    download_dir: Option<&Path>,
) -> Result<ProductUpdateResult> {
    download_product_update_blocking_with_config(current_version, mode, source, download_dir, None)
}

pub fn download_product_update_blocking_with_config(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    download_dir: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<ProductUpdateResult> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start update runtime")?;
    runtime.block_on(download_product_update_with_config(
        current_version,
        mode,
        source,
        download_dir,
        config_path,
    ))
}

pub async fn download_product_update(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    download_dir: Option<&Path>,
) -> Result<ProductUpdateResult> {
    download_product_update_with_config(current_version, mode, source, download_dir, None).await
}

pub async fn download_product_update_with_config(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    download_dir: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<ProductUpdateResult> {
    let selection = select_update(current_version, mode, source, config_path).await?;
    let destination = download_selection(&selection, download_dir).await?;
    Ok(result_from_selection(
        current_version,
        &selection,
        Some(&destination),
    ))
}

async fn select_update(
    current_version: &str,
    mode: ProductUpdateMode,
    source: ProductUpdateSource,
    config_path: Option<&Path>,
) -> Result<UpdateSelection> {
    if !should_use_secure_hashtree(source) {
        return legacy_selection(current_version, source, mode).map(UpdateSelection::Legacy);
    }

    let secure = secure_selection(current_version, mode, config_path).await;
    let selection = match secure {
        Ok(selection) => selection,
        Err(error) if should_try_github_fallback(source, false) => {
            return legacy_selection(current_version, ProductUpdateSource::Github, mode)
                .map(UpdateSelection::Legacy)
                .with_context(|| format!("secure hashtree update check failed: {error}"));
        }
        Err(error) => return Err(error),
    };

    if should_try_github_fallback(source, selection.update_available)
        && let Ok(legacy) = legacy_selection(current_version, ProductUpdateSource::Github, mode)
        && legacy.update_available
    {
        return Ok(UpdateSelection::Legacy(legacy));
    }

    Ok(UpdateSelection::Secure(Box::new(selection)))
}

fn result_from_selection(
    current_version: &str,
    selection: &UpdateSelection,
    path: Option<&Path>,
) -> ProductUpdateResult {
    match selection {
        UpdateSelection::Secure(selection) => ProductUpdateResult {
            available: selection.update_available,
            current_version: current_version.to_string(),
            latest_version: selection.tag.trim_start_matches('v').to_string(),
            tag: selection.tag.clone(),
            asset: selection.asset.name.clone(),
            source: SECURE_SOURCE_NAME.to_string(),
            verified: true,
            url: None,
            path: path.map(|value| value.display().to_string()),
        },
        UpdateSelection::Legacy(selection) => ProductUpdateResult {
            available: selection.update_available,
            current_version: current_version.to_string(),
            latest_version: selection.manifest.tag.trim_start_matches('v').to_string(),
            tag: selection.manifest.tag.clone(),
            asset: selection.asset.name.clone(),
            source: selection.source_name.to_string(),
            verified: false,
            url: Some(selection.asset_url.clone()),
            path: path.map(|value| value.display().to_string()),
        },
    }
}

async fn secure_selection(
    current_version: &str,
    mode: ProductUpdateMode,
    config_path: Option<&Path>,
) -> Result<SecurePubsubBlossomSelection> {
    let reference = configured_update_ref()?;
    let app = match config_path {
        Some(path) if path.exists() => AppConfig::load(path)?,
        _ => AppConfig::default(),
    };
    ensure!(app.nostr.pubsub.enabled(), "Nostr pubsub is disabled");
    let (endpoint, client) = tokio::time::timeout(Duration::from_secs(4), update_pubsub(&app))
        .await
        .context("timed out starting update pubsub")??;
    let selection = secure_selection_with_pubsub(
        current_version,
        mode,
        Arc::new(client.fresh_subscriber()),
        reference,
        config_path,
    )
    .await;
    client.shutdown_shared().await;
    endpoint
        .shutdown()
        .await
        .context("failed to stop update pubsub endpoint")?;
    selection
}

/// Check signed announcements with an application's existing pubsub provider.
/// The provider must freshly query its peers instead of replaying a local cache.
pub async fn check_product_update_with_pubsub(
    current_version: &str,
    mode: ProductUpdateMode,
    provider: Arc<dyn NostrEventSubscriber>,
) -> Result<ProductUpdateResult> {
    let selection = secure_selection_with_pubsub(
        current_version,
        mode,
        provider,
        configured_update_ref()?,
        None,
    )
    .await?;
    Ok(result_from_selection(
        current_version,
        &UpdateSelection::Secure(Box::new(selection)),
        None,
    ))
}

async fn secure_selection_with_pubsub(
    current_version: &str,
    mode: ProductUpdateMode,
    provider: Arc<dyn NostrEventSubscriber>,
    reference: UpdateRef,
    config_path: Option<&Path>,
) -> Result<SecurePubsubBlossomSelection> {
    let updater = build_secure_pubsub_blossom_updater(
        provider,
        SecurePubsubBlossomConfig {
            manifest_timeout: Duration::from_secs(8),
            download_timeout: Duration::from_secs(180),
            blossom_read_servers: blossom_read_servers(),
        },
    )
    .await?;
    for event in cache::update_watermark(&reference, config_path, None)?.resolver_events() {
        updater.resolver().ingest_event(event).await?;
    }
    if let Some(config_path) = config_path {
        let path = crate::control_pubsub::control_pubsub_store_path(config_path);
        match cached_update_events(&path) {
            Ok(events) => {
                for event in events {
                    // A verified cached root prevents rollback; only a fresh
                    // peer response can make this update check conclusive.
                    let _ = updater.resolver().ingest_event(event).await;
                }
            }
            Err(error) => tracing::warn!(%error, "ignored invalid update announcement cache"),
        }
    }
    let resolver = updater.resolver().clone();
    let selection = select_product_update(
        updater,
        reference.clone(),
        current_version,
        mode,
        &asset_policy(),
    )
    .await
    .context("failed to resolve a fresh signed hashtree release over pubsub");
    // Retain authenticated observations even if freshness or content retrieval
    // failed, so the next independently built updater cannot accept an older root.
    if let Some(event) = resolver.latest_event(&reference.resolver_key()).await? {
        let observed = event.id;
        let saved = cache::update_watermark(&reference, config_path, Some(event))?;
        ensure!(
            saved
                .latest()
                .is_some_and(|latest| latest.as_event().id == observed),
            "update check inconclusive: a newer release announcement was observed concurrently"
        );
    }
    selection
}

fn cached_update_events(path: &Path) -> Result<Vec<nostr_sdk::Event>> {
    #[derive(Deserialize)]
    struct CachedEvents {
        events: Vec<nostr_sdk::Event>,
    }
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice::<CachedEvents>(&bytes)?.events),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

pub fn configured_update_ref() -> Result<UpdateRef> {
    update_ref_from_override(None, Some("NVPN_UPDATE_HTREE_REF"), HTREE_UPDATE_REF)
        .context("invalid update hashtree ref")
}

// Standalone CLI/desktop checks have no VPN runtime in this process. Join the
// same FIPS mesh with an ephemeral identity, without a tunnel or relay client.
async fn update_pubsub(app: &AppConfig) -> Result<(Arc<FipsEndpoint>, Arc<FipsPubsubClient>)> {
    let endpoint = Arc::new(
        FipsEndpoint::builder()
            .config(update_endpoint_config(app))
            .local_rendezvous()
            .without_system_tun()
            .bind()
            .await?,
    );
    let client = FipsPubsubClient::start(
        Arc::clone(&endpoint),
        FipsPubsubClientOptions {
            fanout: app.nostr.pubsub.fanout,
            max_hops: app.nostr.pubsub.max_hops,
            max_frame_bytes: app
                .nostr
                .pubsub
                .max_event_bytes
                .saturating_add(4 * 1024)
                .min(crate::control_pubsub::CONTROL_PUBSUB_MAX_WIRE_BYTES),
            ..FipsPubsubClientOptions::default()
        },
    )
    .await?;
    Ok((endpoint, Arc::new(client)))
}

fn update_endpoint_config(app: &AppConfig) -> FipsConfig {
    let mut config = FipsConfig::new();
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.dns.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        accept_connections: Some(false),
        outbound_only: Some(true),
        ..UdpConfig::default()
    });
    config.transports.tcp = TransportInstances::Single(Default::default());
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        seed_urls: if app.fips_bootstrap_enabled {
            app.fips_websocket_seed_urls.clone()
        } else {
            Vec::new()
        },
        ..WebSocketConfig::default()
    });
    let mut peers = app
        .fips_bootstrap_peer_endpoints()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    for (npub, addresses) in app.fips_static_peer_endpoints() {
        peers.entry(npub).or_default().extend(addresses);
    }
    config.peers = peers
        .into_iter()
        .map(|(npub, addresses)| PeerConfig {
            npub,
            addresses: addresses
                .iter()
                .map(|address| {
                    let (transport, address) = split_peer_transport_addr(address);
                    PeerAddress::new(transport, address)
                })
                .collect(),
            ..PeerConfig::default()
        })
        .collect();
    config
}

fn legacy_selection(
    current_version: &str,
    source: ProductUpdateSource,
    mode: ProductUpdateMode,
) -> Result<LegacySelection> {
    let (manifest_url, manifest) = fetch_first_manifest(source)?;
    let newer = version_is_newer(&manifest.tag, current_version);
    let asset = preferred_asset(&manifest, mode).ok_or_else(|| {
        anyhow!(
            "release {} has no {} asset for {}",
            manifest.tag,
            asset_policy().noun(mode),
            current_target()
        )
    })?;
    let asset_url = manifest_asset_url(&manifest_url, &asset.path);
    let source_name = if manifest_url.contains("api.github.com") {
        GITHUB_SOURCE_NAME
    } else {
        LEGACY_HTREE_SOURCE_NAME
    };

    Ok(LegacySelection {
        manifest,
        asset,
        asset_url,
        source_name,
        update_available: newer,
    })
}

async fn download_selection(
    selection: &UpdateSelection,
    download_dir: Option<&Path>,
) -> Result<PathBuf> {
    match selection {
        UpdateSelection::Secure(selection) => {
            download_product_selection(selection, download_dir, &asset_policy())
                .await
                .with_context(|| {
                    format!(
                        "failed to download verified hashtree asset {}",
                        selection.asset.name
                    )
                })
        }
        UpdateSelection::Legacy(selection) => {
            let destination = selected_download_path(download_dir, &selection.asset.name)?;
            download_asset(&selection.asset_url, &destination)?;
            Ok(destination)
        }
    }
}

fn should_use_secure_hashtree(source: ProductUpdateSource) -> bool {
    std::env::var("NVPN_UPDATE_MANIFEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_none()
        && !matches!(source, ProductUpdateSource::Github)
}

#[must_use]
pub fn should_try_github_fallback(source: ProductUpdateSource, secure_available: bool) -> bool {
    matches!(source, ProductUpdateSource::Auto) && !secure_available
}

fn blossom_read_servers() -> Vec<String> {
    env_csv("NVPN_UPDATE_BLOSSOM_SERVERS").unwrap_or_else(|| {
        dedupe_nonempty(
            DEFAULT_BLOSSOM_READ_SERVERS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        )
    })
}

fn asset_policy() -> ProductAssetPolicy {
    ProductAssetPolicy::new("nvpn", "nvpn CLI", "Nostr VPN app")
        .with_app_asset_suffixes(platform_app_asset_suffixes().iter().copied())
        .with_download_file_name_fallback("nvpn-update-archive")
}

fn current_target() -> &'static str {
    current_archive_target()
}

fn legacy_update_manifest(manifest: &ReleaseManifest) -> UpdateManifest {
    UpdateManifest {
        tag: Some(manifest.tag.clone()),
        assets: manifest
            .assets
            .iter()
            .map(|asset| UpdateAsset {
                name: asset.name.clone(),
                path: asset.path.clone(),
                ..UpdateAsset::default()
            })
            .collect(),
        ..UpdateManifest::default()
    }
}

fn release_asset_from_update_asset(asset: UpdateAsset) -> ReleaseAsset {
    ReleaseAsset {
        name: asset.name,
        path: asset.path,
    }
}

fn preferred_asset(manifest: &ReleaseManifest, mode: ProductUpdateMode) -> Option<ReleaseAsset> {
    match mode {
        ProductUpdateMode::Cli => preferred_cli_asset(manifest),
        ProductUpdateMode::App => preferred_legacy_app_asset(manifest),
    }
}

fn preferred_cli_asset(manifest: &ReleaseManifest) -> Option<ReleaseAsset> {
    let update_manifest = legacy_update_manifest(manifest);
    preferred_cli_asset_for_target(&update_manifest, "nvpn", current_target())
        .map(release_asset_from_update_asset)
}

fn preferred_legacy_app_asset(manifest: &ReleaseManifest) -> Option<ReleaseAsset> {
    let update_manifest = legacy_update_manifest(manifest);
    preferred_app_asset_for_suffixes(&update_manifest, platform_app_asset_suffixes())
        .map(release_asset_from_update_asset)
}

fn selected_download_path(download_dir: Option<&Path>, asset_name: &str) -> Result<PathBuf> {
    shared_selected_download_path(download_dir, asset_name, "nvpn-update-archive")
        .with_context(|| format!("failed to choose update download path for {asset_name}"))
}

fn fetch_first_manifest(source: ProductUpdateSource) -> Result<(String, ReleaseManifest)> {
    let mut last_error = None;
    for url in manifest_urls(source) {
        match fetch_manifest(&url) {
            Ok(manifest) => return Ok((url, manifest)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("no update manifest URL configured")))
}

fn manifest_urls(source: ProductUpdateSource) -> Vec<String> {
    manifest_urls_for(
        source,
        std::env::var("NVPN_UPDATE_MANIFEST_URL")
            .ok()
            .filter(|value| !value.trim().is_empty()),
    )
}

fn manifest_urls_for(source: ProductUpdateSource, override_url: Option<String>) -> Vec<String> {
    if let Some(override_url) = override_url.filter(|value| !value.trim().is_empty()) {
        return vec![override_url];
    }

    match source {
        ProductUpdateSource::Auto => vec![
            HTREE_MANIFEST_URL.to_string(),
            GITHUB_LATEST_RELEASE_URL.to_string(),
        ],
        ProductUpdateSource::Github => vec![GITHUB_LATEST_RELEASE_URL.to_string()],
        ProductUpdateSource::Hashtree => vec![HTREE_MANIFEST_URL.to_string()],
    }
}

fn fetch_manifest(url: &str) -> Result<ReleaseManifest> {
    let mut command = Command::new("curl");
    command.args([
        "-fsSL",
        "--connect-timeout",
        UPDATE_CONNECT_TIMEOUT_SECS,
        "--max-time",
        UPDATE_MANIFEST_TIMEOUT_SECS,
    ]);
    if url.contains("api.github.com") {
        command
            .arg("-H")
            .arg("Accept: application/vnd.github+json")
            .arg("-H")
            .arg(format!("User-Agent: {UPDATE_USER_AGENT}"));
    }
    let output = command
        .arg(url)
        .output()
        .with_context(|| format!("failed to run curl for {url}"))?;
    if !output.status.success() {
        return Err(anyhow!("{}", command_error("update check failed", &output)));
    }
    serde_json::from_slice(&output.stdout).context("failed to parse release manifest")
}

fn manifest_asset_url(manifest_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") || path.starts_with("file://") {
        return path.to_string();
    }
    let base = manifest_url
        .rsplit_once('/')
        .map(|(base, _)| base)
        .unwrap_or(manifest_url);
    format!("{}/{}", base, path.trim_start_matches('/'))
}

fn download_asset(url: &str, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let output = Command::new("curl")
        .arg("-fL")
        .arg("--connect-timeout")
        .arg(UPDATE_CONNECT_TIMEOUT_SECS)
        .arg("--max-time")
        .arg(UPDATE_DOWNLOAD_TIMEOUT_SECS)
        .arg("-o")
        .arg(destination)
        .arg(url)
        .output()
        .with_context(|| format!("failed to run curl for {url}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            command_error("update download failed", &output)
        ));
    }
    Ok(())
}

fn command_error(prefix: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stderr.is_empty() {
        format!("{prefix}: {stderr}")
    } else if !stdout.is_empty() {
        format!("{prefix}: {stdout}")
    } else {
        format!("{prefix}: exit {}", output.status)
    }
}

#[must_use]
pub fn version_is_newer(candidate: &str, current: &str) -> bool {
    let left = version_parts(candidate);
    let right = version_parts(current);
    for index in 0..left.len().max(right.len()) {
        let left_value = left.get(index).copied().unwrap_or_default();
        let right_value = right.get(index).copied().unwrap_or_default();
        if left_value != right_value {
            return left_value > right_value;
        }
    }
    false
}

fn version_parts(value: &str) -> Vec<u32> {
    value
        .trim_matches(|ch: char| ch == 'v' || ch == 'V' || ch.is_whitespace())
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u32>().unwrap_or_default())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_source_checks_htree_before_github() {
        assert_eq!(
            manifest_urls_for(ProductUpdateSource::Auto, None),
            vec![
                HTREE_MANIFEST_URL.to_string(),
                GITHUB_LATEST_RELEASE_URL.to_string(),
            ]
        );
    }

    #[test]
    fn auto_source_can_cross_check_github_when_secure_hashtree_is_not_newer() {
        assert!(should_try_github_fallback(ProductUpdateSource::Auto, false));
        assert!(!should_try_github_fallback(ProductUpdateSource::Auto, true));
        assert!(!should_try_github_fallback(
            ProductUpdateSource::Hashtree,
            false
        ));
        assert!(!should_try_github_fallback(
            ProductUpdateSource::Github,
            false
        ));
    }

    #[test]
    fn compares_semver_like_tags() {
        assert!(version_is_newer("v4.0.55", "4.0.52"));
        assert!(version_is_newer("v4.0.13", "4.0.12"));
        assert!(!version_is_newer("v4.0.12", "4.0.12"));
        assert!(!version_is_newer("v4.0.11", "4.0.12"));
    }

    #[test]
    fn resolves_relative_manifest_asset_urls() {
        assert_eq!(
            manifest_asset_url(
                "https://example.invalid/latest/release.json",
                "assets/nvpn.tgz"
            ),
            "https://example.invalid/latest/assets/nvpn.tgz"
        );
    }

    #[tokio::test]
    async fn updater_discovers_signed_roots_from_configured_websocket_seed_without_vpn_or_relays() {
        use nostr_pubsub::{EventBus, EventSource, VerifiedEvent};
        use nostr_sdk::prelude::{EventBuilder, Filter, Keys, Kind, Tag, TagKind};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("seed port");
        let address = listener.local_addr().expect("seed address");
        drop(listener);
        let mut app = AppConfig::default();
        app.fips_bootstrap_enabled = false;
        app.fips_websocket_seed_urls = vec!["ws://unused.invalid/fips".to_string()];
        let mut seed_config = update_endpoint_config(&app);
        assert!(!seed_config.node.discovery.nostr.enabled);
        assert!(!seed_config.dns.enabled);
        assert!(!seed_config.node.control.enabled);
        assert!(seed_config.peers.is_empty());
        seed_config.transports.websocket = TransportInstances::Single(WebSocketConfig {
            bind_addr: Some(address.to_string()),
            ..WebSocketConfig::default()
        });
        let seed = Arc::new(
            FipsEndpoint::builder()
                .config(seed_config)
                .without_system_tun()
                .bind()
                .await
                .expect("seed endpoint"),
        );
        let publisher =
            FipsPubsubClient::start(Arc::clone(&seed), FipsPubsubClientOptions::default())
                .await
                .expect("seed pubsub");
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(30_064), "")
            .tags([
                Tag::identifier("releases/test-update"),
                Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
                Tag::custom(TagKind::Custom("hash".into()), ["ab".repeat(32)]),
            ])
            .sign_with_keys(&keys)
            .expect("signed release root");
        publisher
            .publish(
                VerifiedEvent::try_from(event.clone()).expect("verified root"),
                EventSource::local_index("release-publisher"),
            )
            .await
            .expect("retain root at seed");
        app.fips_peer_endpoints.insert(
            seed.npub().to_string(),
            vec![format!("websocket:ws://{address}/fips")],
        );
        let (endpoint, client) = update_pubsub(&app)
            .await
            .expect("standalone updater network");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let subscription = client
            .fresh_subscriber()
            .subscribe(
                vec![
                    Filter::new()
                        .author(keys.public_key())
                        .kind(Kind::Custom(30_064))
                        .identifier("releases/test-update"),
                ],
                Arc::new(move |delivery| {
                    let _ = tx.send(delivery);
                }),
            )
            .await
            .expect("fresh update subscription");
        let delivery = tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .expect("seed replay before deadline")
            .expect("signed update received");
        assert_eq!(delivery.event.as_event().id, event.id);
        assert!(
            endpoint
                .relay_statuses()
                .await
                .expect("relay status")
                .is_empty()
        );
        subscription.close().await.expect("close subscription");
        client.shutdown_shared().await;
        endpoint.shutdown().await.expect("stop updater endpoint");
        publisher.shutdown().await;
        seed.shutdown().await.expect("stop seed");
    }

    #[tokio::test]
    async fn cached_root_without_live_peers_cannot_claim_current_version_is_latest() {
        use nostr_sdk::prelude::{EventBuilder, Keys, Kind, Tag, TagKind, ToBech32};
        let keys = Keys::generate();
        let directory = std::env::temp_dir().join(format!("nvpn-update-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("cache directory");
        let config_path = directory.join("config.toml");
        let cached = EventBuilder::new(Kind::Custom(30_064), "")
            .tags([
                Tag::identifier("releases/offline-test"),
                Tag::custom(TagKind::Custom("l".into()), ["hashtree"]),
                Tag::custom(TagKind::Custom("hash".into()), ["ab".repeat(32)]),
            ])
            .sign_with_keys(&keys)
            .expect("cached signed root");
        fs::write(
            crate::control_pubsub::control_pubsub_store_path(&config_path),
            serde_json::to_vec(&serde_json::json!({ "events": [cached] })).expect("cache JSON"),
        )
        .expect("write cached root");
        let mut app = AppConfig::default();
        app.fips_bootstrap_enabled = false;
        let (endpoint, client) = update_pubsub(&app).await.expect("offline updater network");
        let result = secure_selection_with_pubsub(
            "9999.0.0",
            ProductUpdateMode::Cli,
            Arc::new(client.fresh_subscriber()),
            UpdateRef {
                npub: keys.public_key().to_bech32().expect("release publisher"),
                tree_name: "releases/offline-test".to_string(),
                path: Some("latest".to_string()),
            },
            Some(&config_path),
        )
        .await;
        assert!(
            result.is_err(),
            "cached root must not make an offline check conclusive"
        );
        client.shutdown_shared().await;
        endpoint.shutdown().await.expect("stop updater endpoint");
        std::fs::remove_dir_all(directory).expect("remove test cache");
    }
}
