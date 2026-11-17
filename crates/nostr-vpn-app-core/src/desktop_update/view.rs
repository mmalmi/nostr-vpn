use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const RELEASES_URL: &str = "https://github.com/mmalmi/nostr-vpn/releases/latest";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopPlatform {
    Macos,
    Windows,
    Linux,
}

impl DesktopPlatform {
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateStep {
    Idle,
    Fetching,
    Downloading { received: u64, total: Option<u64> },
    Verifying,
    Installing,
    Restarting,
    /// Linux stops here: the user installs the package themselves.
    Downloaded,
    UpToDate,
    Updated,
    Failed(UpdateFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateFailure {
    NotFound,
    FindTimedOut,
    DownloadFailed,
    DownloadStalled,
    Damaged,
    NoPermission,
    InstallFailed,
    DidNotClose,
    DidNotFinish,
    ShowFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSnapshot {
    pub step: UpdateStep,
    /// Release tag being installed, such as `v4.1.23`. Empty until found.
    pub version: String,
    /// The underlying error, for Settings and tooltips.
    pub detail: String,
    /// The verified download, used by the fallback action.
    pub download: Option<PathBuf>,
}

impl Default for UpdateSnapshot {
    fn default() -> Self {
        Self {
            step: UpdateStep::Idle,
            version: String::new(),
            detail: String::new(),
            download: None,
        }
    }
}

/// What a shell renders. Shells never compose update wording themselves.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopUpdateView {
    pub step: String,
    /// The update banner must stay visible (busy, failed, done).
    pub active: bool,
    pub busy: bool,
    pub title: String,
    pub detail: String,
    /// 0.0 to 1.0 while the size is known.
    pub progress: Option<f64>,
    pub primary_action: String,
    pub primary_label: String,
    pub secondary_action: String,
    pub secondary_label: String,
    /// The installer is waiting for this app to exit.
    pub quit: bool,
    /// The verified download, once there is one.
    pub download_path: String,
}

pub const ACTION_INSTALL: &str = "install";
pub const ACTION_RETRY: &str = "retry";
pub const ACTION_OPEN_INSTALLER: &str = "open_installer";
pub const ACTION_SHOW_FILE: &str = "show_file";
pub const ACTION_OPEN_WEBSITE: &str = "open_website";

#[must_use]
pub fn install_label(platform: DesktopPlatform) -> &'static str {
    match platform {
        DesktopPlatform::Linux => "Download update",
        DesktopPlatform::Macos | DesktopPlatform::Windows => "Install",
    }
}

#[must_use]
pub fn desktop_update_view(snapshot: &UpdateSnapshot, platform: DesktopPlatform) -> DesktopUpdateView {
    let version = display_version(&snapshot.version);
    let mut view = DesktopUpdateView {
        step: step_name(&snapshot.step).to_string(),
        active: true,
        busy: false,
        detail: snapshot.detail.clone(),
        download_path: snapshot
            .download
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        ..DesktopUpdateView::default()
    };
    match &snapshot.step {
        UpdateStep::Idle => {
            view.active = false;
            set_primary(&mut view, ACTION_INSTALL, install_label(platform));
        }
        UpdateStep::Fetching => {
            view.busy = true;
            view.title = "Finding the update…".to_string();
        }
        UpdateStep::Downloading { received, total } => {
            view.busy = true;
            match total.filter(|total| *total > 0) {
                Some(total) => {
                    // Release assets are far below 2^52 bytes, so f64 is exact.
                    #[allow(clippy::cast_precision_loss)]
                    let fraction = (*received as f64 / total as f64).clamp(0.0, 1.0);
                    view.progress = Some(fraction);
                    view.title = format!("Downloading {version}… {:.0}%", fraction * 100.0);
                    view.detail = format!("{} of {}", megabytes(*received), megabytes(total));
                }
                None => {
                    view.title = format!("Downloading {version}… {}", megabytes(*received));
                }
            }
        }
        UpdateStep::Verifying => {
            view.busy = true;
            view.progress = Some(1.0);
            view.title = "Checking the download…".to_string();
        }
        UpdateStep::Installing => {
            view.busy = true;
            view.title = format!("Installing {version}…");
        }
        UpdateStep::Restarting => {
            view.busy = true;
            view.quit = true;
            view.title = "Restarting to finish the update…".to_string();
        }
        UpdateStep::Downloaded => {
            view.title = format!("{version} is downloaded. Install it from the file.");
            set_primary(&mut view, ACTION_SHOW_FILE, "Show download");
        }
        UpdateStep::UpToDate => {
            view.title = "Nostr VPN is up to date".to_string();
        }
        UpdateStep::Updated => {
            view.title = format!("Updated to {version}");
        }
        UpdateStep::Failed(failure) => {
            view.title = failure_title(*failure, &version);
            set_primary(&mut view, ACTION_RETRY, "Retry");
            let (action, label) = fallback(*failure, platform, snapshot.download.is_some());
            view.secondary_action = action.to_string();
            view.secondary_label = label.to_string();
        }
    }
    view
}

fn set_primary(view: &mut DesktopUpdateView, action: &str, label: &str) {
    view.primary_action = action.to_string();
    view.primary_label = label.to_string();
}

fn step_name(step: &UpdateStep) -> &'static str {
    match step {
        UpdateStep::Idle => "idle",
        UpdateStep::Fetching => "fetching",
        UpdateStep::Downloading { .. } => "downloading",
        UpdateStep::Verifying => "verifying",
        UpdateStep::Installing => "installing",
        UpdateStep::Restarting => "restarting",
        UpdateStep::Downloaded => "downloaded",
        UpdateStep::UpToDate => "up_to_date",
        UpdateStep::Updated => "updated",
        UpdateStep::Failed(_) => "failed",
    }
}

fn failure_title(failure: UpdateFailure, version: &str) -> String {
    match failure {
        UpdateFailure::NotFound => "Couldn't find a verified copy of the update.".to_string(),
        UpdateFailure::FindTimedOut => "Finding the update took too long.".to_string(),
        UpdateFailure::DownloadFailed => "The download failed.".to_string(),
        UpdateFailure::DownloadStalled => "The download stopped.".to_string(),
        UpdateFailure::Damaged => "The download was damaged, so it wasn't installed.".to_string(),
        UpdateFailure::NoPermission => "Nostr VPN can't replace itself in this folder.".to_string(),
        UpdateFailure::InstallFailed => "Couldn't install the update.".to_string(),
        UpdateFailure::DidNotClose => {
            "Nostr VPN didn't close, so the update couldn't finish.".to_string()
        }
        UpdateFailure::DidNotFinish => {
            if version.is_empty() {
                "The update didn't finish.".to_string()
            } else {
                format!("The update to {version} didn't finish.")
            }
        }
        UpdateFailure::ShowFailed => "Couldn't open the download folder.".to_string(),
    }
}

fn fallback(
    failure: UpdateFailure,
    platform: DesktopPlatform,
    downloaded: bool,
) -> (&'static str, &'static str) {
    let damaged = matches!(failure, UpdateFailure::Damaged);
    if !downloaded || damaged {
        return (ACTION_OPEN_WEBSITE, "Download page");
    }
    match platform {
        DesktopPlatform::Macos => (ACTION_SHOW_FILE, "Show in Finder"),
        DesktopPlatform::Windows => (ACTION_OPEN_INSTALLER, "Open installer"),
        DesktopPlatform::Linux => (ACTION_OPEN_WEBSITE, "Download page"),
    }
}

fn display_version(tag: &str) -> String {
    let tag = tag.trim();
    if tag.is_empty() {
        "the update".to_string()
    } else if tag.starts_with('v') || tag.starts_with('V') {
        tag.to_string()
    } else {
        format!("v{tag}")
    }
}

#[allow(clippy::cast_precision_loss)]
fn megabytes(bytes: u64) -> String {
    let mb = bytes as f64 / 1_000_000.0;
    if mb < 10.0 {
        format!("{mb:.1} MB")
    } else {
        format!("{mb:.0} MB")
    }
}
