use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::thread;

use nostr_vpn_core::updater::{
    check_product_update_blocking_with_config, download_product_update_blocking_with_config,
    ProductUpdateMode, ProductUpdateSource,
};

mod preferences;
pub use preferences::{load_preferences, save_preferences, DownloadedUpdate};

#[derive(Clone, Debug, Default)]
pub struct UpdateState {
    pub checking: bool,
    pub downloading: bool,
    pub available: bool,
    pub auto_download: bool,
    pub version: String,
    pub status: String,
    pub asset: Option<ReleaseAsset>,
    pub downloaded: Option<DownloadedUpdate>,
}

#[derive(Clone, Debug)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
    pub source: String,
    pub verified: bool,
}

#[derive(Debug)]
pub enum UpdateEvent {
    Checked {
        manual: bool,
        result: Result<UpdateCheck, String>,
    },
    Downloaded(Result<DownloadedUpdate, String>),
}

#[derive(Debug)]
pub struct UpdateCheck {
    pub tag: String,
    pub asset: Option<ReleaseAsset>,
    pub newer: bool,
    pub source: String,
    pub verified: bool,
}

pub fn check(
    current_version: String,
    config_path: String,
    manual: bool,
    sender: Sender<UpdateEvent>,
) {
    thread::spawn(move || {
        let result =
            check_blocking(&current_version, &config_path).map_err(|error| error.to_string());
        let _ = sender.send(UpdateEvent::Checked { manual, result });
    });
}

pub fn download(asset: ReleaseAsset, config_path: String, sender: Sender<UpdateEvent>) {
    thread::spawn(move || {
        let result = download_blocking(&asset, &config_path).map_err(|error| error.to_string());
        let _ = sender.send(UpdateEvent::Downloaded(result));
    });
}

pub fn check_blocking(current_version: &str, config_path: &str) -> Result<UpdateCheck, String> {
    let result = check_product_update_blocking_with_config(
        current_version,
        ProductUpdateMode::App,
        ProductUpdateSource::Auto,
        Some(Path::new(config_path)),
    )
    .map_err(|error| format!("{error:#}"))?;
    let source = result.source.clone();
    let verified = result.verified;
    let asset = (!result.asset.trim().is_empty() && verified).then(|| ReleaseAsset {
        name: result.asset,
        url: result.url.unwrap_or_else(|| source.clone()),
        source: source.clone(),
        verified,
    });
    Ok(UpdateCheck {
        tag: result.tag,
        asset,
        newer: result.available,
        source,
        verified,
    })
}

pub fn download_blocking(
    asset: &ReleaseAsset,
    config_path: &str,
) -> Result<DownloadedUpdate, String> {
    if !asset.verified {
        return Err(format!(
            "Refusing to install unverified update from {}",
            asset.source
        ));
    }
    let download_dir = update_download_dir();
    let result = download_product_update_blocking_with_config(
        "0.0.0",
        ProductUpdateMode::App,
        ProductUpdateSource::Auto,
        Some(&download_dir),
        Some(Path::new(config_path)),
    )
    .map_err(|error| format!("{error:#}"))?;
    if !result.verified {
        return Err(format!(
            "Refusing to install unverified update from {}",
            result.source
        ));
    }
    if result.asset != asset.name {
        return Err(format!(
            "Latest release changed from {} to {}; please check again",
            asset.name, result.asset
        ));
    }
    let destination = result
        .path
        .map(PathBuf::from)
        .ok_or_else(|| "Updater did not return a downloaded file".to_string())?;
    prepare_download(&destination, &asset.name)?;
    Ok(DownloadedUpdate {
        asset_name: asset.name.clone(),
        source: asset.source.clone(),
        path: destination,
    })
}

fn prepare_download(destination: &Path, asset_name: &str) -> Result<(), String> {
    if asset_name.ends_with(".AppImage") {
        let mut permissions = fs::metadata(destination)
            .map_err(|error| format!("Downloaded update unavailable: {error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(destination, permissions)
            .map_err(|error| format!("Could not make AppImage executable: {error}"))?;
    }

    Ok(())
}

fn update_download_dir() -> PathBuf {
    std::env::var("NVPN_UPDATE_DOWNLOAD_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| download_dir_under(&crate::default_data_dir()))
}

fn download_dir_under(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("update-downloads")
}

#[cfg(test)]
mod tests;
