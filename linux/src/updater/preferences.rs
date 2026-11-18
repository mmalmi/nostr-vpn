use super::{ReleaseAsset, UpdateState};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DownloadedUpdate {
    pub asset_name: String,
    pub source: String,
    pub path: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatePreferences {
    pub auto_download: bool,
    pub downloaded: Option<DownloadedUpdate>,
}

impl DownloadedUpdate {
    fn matches(&self, asset: &ReleaseAsset) -> bool {
        asset.verified
            && self.asset_name == asset.name
            && self.source == asset.source
            && self.path.is_file()
    }
}

impl UpdateState {
    pub fn downloaded_path(&self) -> Option<&Path> {
        let asset = self.asset.as_ref()?;
        self.downloaded
            .as_ref()
            .filter(|download| download.matches(asset))
            .map(|download| download.path.as_path())
    }

    pub fn should_auto_download(&self) -> bool {
        self.auto_download
            && self.available
            && !self.checking
            && !self.view.busy
            && self.asset.as_ref().is_some_and(|asset| asset.verified)
            && self.downloaded_path().is_none()
    }
}

pub fn load_preferences(path: &Path) -> UpdatePreferences {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return UpdatePreferences::default();
    };
    serde_json::from_str(&raw).unwrap_or_else(|_| UpdatePreferences {
        // Earlier versions called downloading and opening a package "install".
        auto_download: raw.lines().any(|line| line.trim() == "auto_install=true"),
        downloaded: None,
    })
}

pub fn save_preferences(path: &Path, state: &UpdateState) -> Result<(), String> {
    let prefs = UpdatePreferences {
        auto_download: state.auto_download,
        downloaded: state.downloaded.clone(),
    };
    let raw = serde_json::to_vec_pretty(&prefs).map_err(|error| error.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    nostr_vpn_core::config::write_private_file_preserving_user_owner(path, &raw)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_downloads_survive_restart_and_do_not_repeat_until_the_asset_changes_or_disappears()
    {
        let dir = std::env::temp_dir().join(format!(
            "nvpn-updater-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("release.pkg.tar.zst");
        let prefs = dir.join("desktop-updates.conf");
        std::fs::write(&file, b"fixture").unwrap();
        std::fs::write(&prefs, "auto_install=true\n").unwrap();
        assert!(load_preferences(&prefs).auto_download);
        let mut state = UpdateState {
            auto_download: true,
            available: true,
            asset: Some(ReleaseAsset {
                name: "release.pkg.tar.zst".into(),
                url: "https://update.example/asset".into(),
                source: "signed-release".into(),
                verified: true,
            }),
            ..Default::default()
        };
        assert!(state.should_auto_download());
        state.downloaded = Some(DownloadedUpdate {
            asset_name: "release.pkg.tar.zst".into(),
            source: "signed-release".into(),
            path: file.clone(),
        });
        save_preferences(&prefs, &state).unwrap();
        let saved = load_preferences(&prefs);
        state.downloaded = saved.downloaded;
        state.auto_download = saved.auto_download;
        for _ in 0..3 {
            assert!(!state.should_auto_download());
        }
        state.asset.as_mut().unwrap().name = "next-release.pkg.tar.zst".into();
        assert!(state.should_auto_download());
        state.asset.as_mut().unwrap().name = "release.pkg.tar.zst".into();
        state.asset.as_mut().unwrap().source = "other-source".into();
        assert!(state.should_auto_download());
        state.asset.as_mut().unwrap().source = "signed-release".into();
        std::fs::remove_file(&file).unwrap();
        assert!(state.should_auto_download());
        state.asset.as_mut().unwrap().verified = false;
        assert!(!state.should_auto_download());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
