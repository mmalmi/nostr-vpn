//! Desktop app self-update: each step's state and wording, shared by the
//! macOS, Windows and Linux shells, which only render the view.

mod flow;
mod install;
#[cfg(test)]
mod tests;
mod view;

use std::path::Path;
use std::sync::{Arc, OnceLock};

pub use flow::{
    DownloadResult, InstallOutcome, Progress, ProgressSink, StepError, Timeouts, UpdateBackend,
    UpdateFlow, UpdateRequest,
};
pub use view::{
    ACTION_INSTALL, ACTION_OPEN_INSTALLER, ACTION_OPEN_WEBSITE, ACTION_RETRY, ACTION_SHOW_FILE,
    DesktopPlatform, DesktopUpdateView, RELEASES_URL, UpdateFailure, UpdateSnapshot, UpdateStep,
    desktop_update_view, install_label,
};

/// Ask for the current view without changing anything.
pub const ACTION_VIEW: &str = "view";
/// Report how an install that restarted the app ended. Call once at launch.
pub const ACTION_RESUME: &str = "resume";

fn flow() -> &'static UpdateFlow {
    static FLOW: OnceLock<UpdateFlow> = OnceLock::new();
    FLOW.get_or_init(|| UpdateFlow::new(Arc::new(install::SystemBackend), Timeouts::default()))
}

fn current_view() -> DesktopUpdateView {
    desktop_update_view(&flow().snapshot(), DesktopPlatform::current())
}

/// Run `action` (install, retry, a fallback, resume or view) and return the
/// view to render. Busy views change over time: poll with `ACTION_VIEW`.
#[must_use]
pub fn desktop_update(action: &str, request: &UpdateRequest) -> DesktopUpdateView {
    match action {
        ACTION_VIEW | "" => {}
        ACTION_RESUME => flow().resume(request),
        _ => flow().perform(action, request),
    }
    current_view()
}

/// Show a verified download remembered from an earlier run (Linux).
#[must_use]
pub fn desktop_update_restore_download(tag: &str, path: &Path) -> DesktopUpdateView {
    flow().restore_download(tag, path);
    current_view()
}

/// JSON form of [`desktop_update`] for the C ABI shells.
#[must_use]
pub fn desktop_update_json(action: &str, request_json: &str) -> String {
    let request = serde_json::from_str::<UpdateRequest>(request_json).unwrap_or_default();
    serde_json::to_string(&desktop_update(action, &request)).unwrap_or_else(|_| "{}".to_string())
}
