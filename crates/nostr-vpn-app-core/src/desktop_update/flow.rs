use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::view::{
    ACTION_INSTALL, ACTION_OPEN_INSTALLER, ACTION_OPEN_WEBSITE, ACTION_RETRY, ACTION_SHOW_FILE,
    UpdateFailure, UpdateSnapshot, UpdateStep,
};

const PENDING_MARKER: &str = "update-pending.json";
const UPDATED_NOTICE: Duration = Duration::from_secs(20);
const WATCH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Until the signed release is known.
    pub find: Duration,
    /// Between download progress events.
    pub stall: Duration,
    pub verify: Duration,
    pub install: Duration,
    /// For this app to exit once the installer waits for it.
    pub close: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            find: Duration::from_mins(1),
            stall: Duration::from_secs(45),
            verify: Duration::from_mins(2),
            install: Duration::from_mins(2),
            close: Duration::from_secs(65),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateRequest {
    pub current_version: String,
    pub config_path: String,
}

impl UpdateRequest {
    fn data_dir(&self) -> Option<PathBuf> {
        Path::new(self.config_path.trim())
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(Path::to_path_buf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    Found { tag: String },
    Bytes { received: u64, total: Option<u64> },
}

pub type ProgressSink = Arc<dyn Fn(Progress) + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadResult {
    UpToDate { tag: String },
    Downloaded { tag: String, path: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// A helper waits for this app to exit, installs, then starts the new app.
    Restart,
    /// The user installs the verified file themselves.
    Downloaded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepError {
    pub failure: UpdateFailure,
    pub detail: String,
}

impl StepError {
    pub fn new(failure: UpdateFailure, detail: impl Into<String>) -> Self {
        Self {
            failure,
            detail: detail.into(),
        }
    }
}

pub trait UpdateBackend: Send + Sync + 'static {
    fn download(
        &self,
        request: &UpdateRequest,
        progress: ProgressSink,
    ) -> Result<DownloadResult, StepError>;
    /// Returns what `install` should use, such as an unpacked app bundle.
    fn verify(&self, download: &Path, tag: &str) -> Result<PathBuf, StepError>;
    fn install(&self, verified: &Path, tag: &str) -> Result<InstallOutcome, StepError>;
    fn open(&self, action: &str, download: Option<&Path>) -> Result<(), String>;
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingMarker {
    version: String,
    #[serde(default)]
    download: Option<PathBuf>,
}

struct Inner {
    snapshot: UpdateSnapshot,
    attempt: u64,
    deadline: Option<(Instant, UpdateFailure, &'static str)>,
    updated_until: Option<Instant>,
    marker: Option<PathBuf>,
}

pub struct UpdateFlow {
    inner: Arc<Mutex<Inner>>,
    backend: Arc<dyn UpdateBackend>,
    timeouts: Timeouts,
}

impl UpdateFlow {
    pub fn new(backend: Arc<dyn UpdateBackend>, timeouts: Timeouts) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                snapshot: UpdateSnapshot::default(),
                attempt: 0,
                deadline: None,
                updated_until: None,
                marker: None,
            })),
            backend,
            timeouts,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> UpdateSnapshot {
        let mut inner = lock(&self.inner);
        if inner.snapshot.step == UpdateStep::Updated
            && inner.updated_until.is_some_and(|until| Instant::now() >= until)
        {
            inner.snapshot = UpdateSnapshot::default();
            inner.updated_until = None;
        }
        inner.snapshot.clone()
    }

    /// Report how an install that restarted this app ended. Call once at launch.
    pub fn resume(&self, request: &UpdateRequest) {
        let Some(path) = request.data_dir().map(|dir| dir.join(PENDING_MARKER)) else {
            return;
        };
        let Ok(raw) = fs::read(&path) else {
            return;
        };
        let _ = fs::remove_file(&path);
        let Ok(marker) = serde_json::from_slice::<PendingMarker>(&raw) else {
            return;
        };
        let mut inner = lock(&self.inner);
        if is_busy(&inner.snapshot.step) {
            return;
        }
        let finished =
            !nostr_vpn_core::updater::version_is_newer(&marker.version, &request.current_version);
        inner.snapshot = UpdateSnapshot {
            step: if finished {
                UpdateStep::Updated
            } else {
                UpdateStep::Failed(UpdateFailure::DidNotFinish)
            },
            version: marker.version,
            detail: String::new(),
            download: marker.download.filter(|path| path.exists()),
        };
        inner.updated_until = finished.then(|| Instant::now() + UPDATED_NOTICE);
    }

    /// Show a verified download remembered from an earlier run.
    pub fn restore_download(&self, tag: &str, path: &Path) {
        let mut inner = lock(&self.inner);
        if is_busy(&inner.snapshot.step) || !path.is_file() {
            return;
        }
        inner.snapshot = UpdateSnapshot {
            step: UpdateStep::Downloaded,
            version: tag.to_string(),
            detail: String::new(),
            download: Some(path.to_path_buf()),
        };
    }

    pub fn perform(&self, action: &str, request: &UpdateRequest) {
        match action {
            ACTION_INSTALL | ACTION_RETRY => self.start(request),
            ACTION_SHOW_FILE | ACTION_OPEN_INSTALLER | ACTION_OPEN_WEBSITE => {
                let download = lock(&self.inner).snapshot.download.clone();
                if let Err(error) = self.backend.open(action, download.as_deref()) {
                    let mut inner = lock(&self.inner);
                    if !is_busy(&inner.snapshot.step) {
                        inner.snapshot.step = UpdateStep::Failed(UpdateFailure::ShowFailed);
                        inner.snapshot.detail = error;
                    }
                }
            }
            _ => {}
        }
    }

    pub fn start(&self, request: &UpdateRequest) {
        let attempt = {
            let mut inner = lock(&self.inner);
            if is_busy(&inner.snapshot.step) {
                return;
            }
            inner.attempt += 1;
            inner.snapshot = UpdateSnapshot {
                step: UpdateStep::Fetching,
                ..UpdateSnapshot::default()
            };
            inner.updated_until = None;
            inner.marker = request.data_dir().map(|dir| dir.join(PENDING_MARKER));
            inner.deadline = Some((
                Instant::now() + self.timeouts.find,
                UpdateFailure::FindTimedOut,
                "No verified release arrived in time",
            ));
            inner.attempt
        };
        let worker = Worker {
            inner: Arc::clone(&self.inner),
            backend: Arc::clone(&self.backend),
            timeouts: self.timeouts.clone(),
            attempt,
        };
        let watchdog = worker.clone();
        let request = request.clone();
        thread::Builder::new()
            .name("nvpn-update".to_string())
            .spawn(move || worker.run(&request))
            .expect("spawn update worker");
        thread::Builder::new()
            .name("nvpn-update-watch".to_string())
            .spawn(move || watchdog.watch())
            .expect("spawn update watchdog");
    }
}

#[derive(Clone)]
struct Worker {
    inner: Arc<Mutex<Inner>>,
    backend: Arc<dyn UpdateBackend>,
    timeouts: Timeouts,
    attempt: u64,
}

impl Worker {
    fn run(&self, request: &UpdateRequest) {
        let sink = self.progress_sink();
        let (tag, download) = match self.backend.download(request, sink) {
            Ok(DownloadResult::Downloaded { tag, path }) => (tag, path),
            Ok(DownloadResult::UpToDate { tag }) => {
                self.update(|inner| {
                    inner.snapshot.version = tag;
                    inner.snapshot.step = UpdateStep::UpToDate;
                    inner.deadline = None;
                });
                return;
            }
            Err(error) => return self.fail(error),
        };
        let verify_deadline = Instant::now() + self.timeouts.verify;
        self.update(|inner| {
            inner.snapshot.version.clone_from(&tag);
            inner.snapshot.download = Some(download.clone());
            inner.snapshot.step = UpdateStep::Verifying;
            inner.deadline = Some((
                verify_deadline,
                UpdateFailure::InstallFailed,
                "Checking the download took too long",
            ));
        });
        let verified = match self.backend.verify(&download, &tag) {
            Ok(verified) => verified,
            Err(error) => return self.fail(error),
        };
        let install_deadline = Instant::now() + self.timeouts.install;
        self.update(|inner| {
            inner.snapshot.download = Some(verified.clone());
            inner.snapshot.step = UpdateStep::Installing;
            inner.deadline = Some((
                install_deadline,
                UpdateFailure::InstallFailed,
                "Installing took too long",
            ));
        });
        let outcome = match self.backend.install(&verified, &tag) {
            Ok(outcome) => outcome,
            Err(error) => return self.fail(error),
        };
        let close_deadline = Instant::now() + self.timeouts.close;
        self.update(|inner| match outcome {
            InstallOutcome::Downloaded => {
                inner.snapshot.step = UpdateStep::Downloaded;
                inner.deadline = None;
            }
            InstallOutcome::Restart => {
                if let Some(marker) = &inner.marker {
                    write_marker(marker, &inner.snapshot);
                }
                inner.snapshot.step = UpdateStep::Restarting;
                inner.deadline = Some((
                    close_deadline,
                    UpdateFailure::DidNotClose,
                    "The app was still running when the installer gave up",
                ));
            }
        });
    }

    fn progress_sink(&self) -> ProgressSink {
        let worker = self.clone();
        Arc::new(move |progress| {
            let stall = Instant::now() + worker.timeouts.stall;
            worker.update(|inner| {
                match progress {
                    Progress::Found { tag } => {
                        inner.snapshot.version = tag;
                        inner.snapshot.step = UpdateStep::Downloading {
                            received: 0,
                            total: None,
                        };
                    }
                    Progress::Bytes { received, total } => {
                        inner.snapshot.step = UpdateStep::Downloading { received, total };
                    }
                }
                inner.deadline = Some((
                    stall,
                    UpdateFailure::DownloadStalled,
                    "No data arrived for a while",
                ));
            });
        })
    }

    fn watch(&self) {
        loop {
            thread::sleep(WATCH_INTERVAL);
            let mut inner = lock(&self.inner);
            if inner.attempt != self.attempt || !is_busy(&inner.snapshot.step) {
                return;
            }
            let Some((deadline, failure, detail)) = inner.deadline else {
                continue;
            };
            if Instant::now() < deadline {
                continue;
            }
            if failure == UpdateFailure::DidNotClose
                && let Some(marker) = &inner.marker
            {
                let _ = fs::remove_file(marker);
            }
            inner.snapshot.step = UpdateStep::Failed(failure);
            inner.snapshot.detail = detail.to_string();
            inner.deadline = None;
            return;
        }
    }

    fn fail(&self, error: StepError) {
        self.update(|inner| {
            inner.snapshot.step = UpdateStep::Failed(error.failure);
            inner.snapshot.detail = error.detail;
            inner.deadline = None;
        });
    }

    /// Apply a change unless a timeout or a newer attempt has replaced this one.
    fn update(&self, change: impl FnOnce(&mut Inner)) {
        let mut inner = lock(&self.inner);
        if inner.attempt == self.attempt && is_busy(&inner.snapshot.step) {
            change(&mut inner);
        }
    }
}

fn write_marker(path: &Path, snapshot: &UpdateSnapshot) {
    let marker = PendingMarker {
        version: snapshot.version.clone(),
        download: snapshot.download.clone(),
    };
    if let Ok(raw) = serde_json::to_vec(&marker) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, raw);
    }
}

fn is_busy(step: &UpdateStep) -> bool {
    matches!(
        step,
        UpdateStep::Fetching
            | UpdateStep::Downloading { .. }
            | UpdateStep::Verifying
            | UpdateStep::Installing
            | UpdateStep::Restarting
    )
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
