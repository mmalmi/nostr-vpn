use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::view::{ACTION_SHOW_FILE, DesktopPlatform, desktop_update_view};
use super::*;

/// One scripted download: progress events, each released by the test, then
/// a result.
struct Script {
    events: Vec<Progress>,
    result: Result<DownloadResult, StepError>,
}

struct FakeBackend {
    scripts: Mutex<Vec<Script>>,
    release: Mutex<Receiver<()>>,
    verify: Mutex<Vec<Result<PathBuf, StepError>>>,
    install: Mutex<Vec<Result<InstallOutcome, StepError>>>,
    opened: Mutex<Vec<(String, Option<PathBuf>)>>,
}

impl UpdateBackend for FakeBackend {
    fn download(
        &self,
        _request: &UpdateRequest,
        progress: ProgressSink,
    ) -> Result<DownloadResult, StepError> {
        let script = self.scripts.lock().unwrap().remove(0);
        for event in script.events {
            if self.release.lock().unwrap().recv().is_err() {
                break;
            }
            progress(event);
        }
        let _ = self.release.lock().unwrap().recv();
        script.result
    }

    fn verify(&self, download: &Path, _tag: &str) -> Result<PathBuf, StepError> {
        let mut verify = self.verify.lock().unwrap();
        if verify.is_empty() {
            Ok(download.with_extension("verified"))
        } else {
            verify.remove(0)
        }
    }

    fn install(&self, _verified: &Path, _tag: &str) -> Result<InstallOutcome, StepError> {
        let mut install = self.install.lock().unwrap();
        if install.is_empty() {
            Ok(InstallOutcome::Restart)
        } else {
            install.remove(0)
        }
    }

    fn open(&self, action: &str, download: Option<&Path>) -> Result<(), String> {
        self.opened
            .lock()
            .unwrap()
            .push((action.to_string(), download.map(Path::to_path_buf)));
        Ok(())
    }
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct Harness {
    flow: UpdateFlow,
    backend: Arc<FakeBackend>,
    step: Sender<()>,
    request: UpdateRequest,
    dir: PathBuf,
}

impl Harness {
    fn new(scripts: Vec<Script>, timeouts: Timeouts) -> Self {
        let (step, release) = channel();
        let backend = Arc::new(FakeBackend {
            scripts: Mutex::new(scripts),
            release: Mutex::new(release),
            verify: Mutex::new(Vec::new()),
            install: Mutex::new(Vec::new()),
            opened: Mutex::new(Vec::new()),
        });
        let dir = std::env::temp_dir().join(format!(
            "nvpn-desktop-update-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let request = UpdateRequest {
            current_version: "4.1.22".to_string(),
            config_path: dir.join("config.toml").display().to_string(),
        };
        Self {
            flow: UpdateFlow::new(backend.clone(), timeouts),
            backend,
            step,
            request,
            dir,
        }
    }

    fn view(&self, platform: DesktopPlatform) -> DesktopUpdateView {
        desktop_update_view(&self.flow.snapshot(), platform)
    }

    /// Release the backend's next event and wait for `title` to show.
    fn advance_to(&self, title: &str) -> DesktopUpdateView {
        self.step.send(()).unwrap();
        self.wait_for(title)
    }

    fn wait_for(&self, title: &str) -> DesktopUpdateView {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let view = self.view(DesktopPlatform::Macos);
            if view.title == title {
                return view;
            }
            assert!(
                Instant::now() < deadline,
                "expected {title:?}, still showing {view:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn marker(&self) -> PathBuf {
        self.dir.join("update-pending.json")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn found() -> Progress {
    Progress::Found {
        tag: "v4.1.23".to_string(),
    }
}

fn bytes(received: u64) -> Progress {
    Progress::Bytes {
        received,
        total: Some(69_000_000),
    }
}

fn downloaded() -> DownloadResult {
    DownloadResult::Downloaded {
        tag: "v4.1.23".to_string(),
        path: PathBuf::from("/downloads/nostr-vpn-v4.1.23-macos-arm64.app.tar.gz"),
    }
}

fn quick_timeouts() -> Timeouts {
    Timeouts {
        find: Duration::from_secs(5),
        stall: Duration::from_secs(5),
        verify: Duration::from_secs(5),
        install: Duration::from_secs(5),
        close: Duration::from_millis(300),
    }
}

#[test]
fn install_shows_every_step_then_restarts_and_reports_the_result_after_relaunch() {
    let harness = Harness::new(
        vec![Script {
            events: vec![found(), bytes(0), bytes(29_000_000)],
            result: Ok(downloaded()),
        }],
        Timeouts::default(),
    );
    let idle = harness.view(DesktopPlatform::Macos);
    assert!(!idle.active && !idle.busy);
    assert_eq!(
        (idle.primary_action.as_str(), idle.primary_label.as_str()),
        ("install", "Install")
    );

    harness.flow.start(&harness.request);
    let fetching = harness.wait_for("Finding the update…");
    assert!(fetching.busy && fetching.active && fetching.primary_action.is_empty());

    let started = harness.advance_to("Downloading v4.1.23… 0.0 MB");
    assert_eq!(started.progress, None);
    let zero = harness.advance_to("Downloading v4.1.23… 0%");
    assert_eq!(zero.progress, Some(0.0));
    let partial = harness.advance_to("Downloading v4.1.23… 42%");
    assert_eq!(partial.detail, "29 MB of 69 MB");
    assert!(partial.busy && !partial.quit);

    harness.flow.start(&harness.request);
    assert_eq!(
        harness.view(DesktopPlatform::Macos).title,
        "Downloading v4.1.23… 42%",
        "pressing Install again while busy must not restart the download"
    );

    let restarting = harness.advance_to("Restarting to finish the update…");
    assert!(restarting.busy && restarting.quit);
    assert!(restarting.download_path.ends_with(".verified"));
    assert!(
        harness.marker().exists(),
        "the relaunched app needs the marker"
    );

    let relaunched = UpdateFlow::new(harness.backend.clone(), Timeouts::default());
    let mut new_version = harness.request.clone();
    new_version.current_version = "4.1.23".to_string();
    relaunched.resume(&new_version);
    let updated = desktop_update_view(&relaunched.snapshot(), DesktopPlatform::Macos);
    assert_eq!(updated.title, "Updated to v4.1.23");
    assert!(updated.active && !updated.busy && updated.primary_action.is_empty());
    assert!(!harness.marker().exists(), "the result is reported once");
}

#[test]
fn an_install_that_did_not_finish_offers_retry_and_the_download_after_relaunch() {
    let harness = Harness::new(
        vec![Script {
            events: vec![found()],
            result: Ok(downloaded()),
        }],
        Timeouts::default(),
    );
    harness.flow.start(&harness.request);
    harness.wait_for("Finding the update…");
    harness.advance_to("Downloading v4.1.23… 0.0 MB");
    harness.advance_to("Restarting to finish the update…");

    let relaunched = UpdateFlow::new(harness.backend.clone(), Timeouts::default());
    relaunched.resume(&harness.request);
    let snapshot = relaunched.snapshot();
    // The fake download path does not exist on disk, so only the website is offered.
    let view = desktop_update_view(&snapshot, DesktopPlatform::Macos);
    assert_eq!(view.title, "The update to v4.1.23 didn't finish.");
    assert_eq!(
        (view.primary_action.as_str(), view.primary_label.as_str()),
        ("retry", "Retry")
    );
    assert_eq!(view.secondary_label, "Download page");

    let with_file = UpdateSnapshot {
        download: Some(PathBuf::from("/downloads/setup.exe")),
        ..snapshot
    };
    let windows = desktop_update_view(&with_file, DesktopPlatform::Windows);
    assert_eq!(
        (
            windows.secondary_action.as_str(),
            windows.secondary_label.as_str()
        ),
        ("open_installer", "Open installer")
    );
    let mac = desktop_update_view(&with_file, DesktopPlatform::Macos);
    assert_eq!(mac.secondary_label, "Show in Finder");
}

#[test]
fn a_stalled_download_fails_plainly_and_retry_starts_over() {
    let harness = Harness::new(
        vec![
            Script {
                events: vec![found(), bytes(1_000_000)],
                result: Ok(downloaded()),
            },
            Script {
                events: vec![found()],
                result: Ok(downloaded()),
            },
        ],
        Timeouts {
            stall: Duration::from_millis(300),
            ..quick_timeouts()
        },
    );
    harness.flow.start(&harness.request);
    harness.wait_for("Finding the update…");
    harness.advance_to("Downloading v4.1.23… 0.0 MB");
    harness.advance_to("Downloading v4.1.23… 1%");

    let stalled = harness.wait_for("The download stopped.");
    assert!(!stalled.busy && stalled.active);
    assert_eq!(stalled.primary_label, "Retry");
    assert_eq!(stalled.secondary_action, "open_website");

    harness.flow.perform(ACTION_RETRY, &harness.request);
    // The first attempt's late result must not overwrite the retry.
    harness.step.send(()).unwrap();
    harness.wait_for("Finding the update…");
    harness.advance_to("Downloading v4.1.23… 0.0 MB");
    harness.advance_to("Restarting to finish the update…");
}

#[test]
fn finding_the_release_times_out_with_retry() {
    let harness = Harness::new(
        vec![Script {
            events: vec![found()],
            result: Ok(downloaded()),
        }],
        Timeouts {
            find: Duration::from_millis(200),
            ..quick_timeouts()
        },
    );
    harness.flow.start(&harness.request);
    let failed = harness.wait_for("Finding the update took too long.");
    assert_eq!(failed.primary_action, "retry");
    assert_eq!(failed.detail, "No verified release arrived in time");
}

#[test]
fn each_failed_step_says_what_went_wrong() {
    let not_found = Harness::new(
        vec![Script {
            events: vec![],
            result: Err(StepError::new(
                UpdateFailure::NotFound,
                "Update check inconclusive: no current peer observation",
            )),
        }],
        quick_timeouts(),
    );
    not_found.flow.start(&not_found.request);
    let view = not_found.advance_to("Couldn't find a verified copy of the update.");
    assert!(view.detail.contains("no current peer observation"));
    assert_eq!(view.secondary_label, "Download page");

    let damaged = Harness::new(
        vec![Script {
            events: vec![found()],
            result: Ok(downloaded()),
        }],
        quick_timeouts(),
    );
    damaged
        .backend
        .verify
        .lock()
        .unwrap()
        .push(Err(StepError::new(
            UpdateFailure::Damaged,
            "codesign failed",
        )));
    damaged.flow.start(&damaged.request);
    damaged.wait_for("Finding the update…");
    damaged.advance_to("Downloading v4.1.23… 0.0 MB");
    let view = damaged.advance_to("The download was damaged, so it wasn't installed.");
    assert_eq!(
        view.secondary_label, "Download page",
        "never offer a damaged file"
    );

    let read_only = Harness::new(
        vec![Script {
            events: vec![found()],
            result: Ok(downloaded()),
        }],
        quick_timeouts(),
    );
    read_only
        .backend
        .install
        .lock()
        .unwrap()
        .push(Err(StepError::new(
            UpdateFailure::NoPermission,
            "/Applications is not writable",
        )));
    read_only.flow.start(&read_only.request);
    read_only.wait_for("Finding the update…");
    read_only.advance_to("Downloading v4.1.23… 0.0 MB");
    let view = read_only.advance_to("Nostr VPN can't replace itself in this folder.");
    assert_eq!(view.secondary_label, "Show in Finder");
    read_only
        .flow
        .perform(&view.secondary_action, &read_only.request);
    assert_eq!(
        read_only.backend.opened.lock().unwrap().as_slice(),
        [(
            "show_file".to_string(),
            Some(PathBuf::from(
                "/downloads/nostr-vpn-v4.1.23-macos-arm64.app.tar.verified"
            ))
        )]
    );
}

#[test]
fn an_app_that_does_not_close_reports_it_and_clears_the_marker() {
    let harness = Harness::new(
        vec![Script {
            events: vec![found()],
            result: Ok(downloaded()),
        }],
        quick_timeouts(),
    );
    harness.flow.start(&harness.request);
    harness.wait_for("Finding the update…");
    harness.advance_to("Downloading v4.1.23… 0.0 MB");
    harness.advance_to("Restarting to finish the update…");
    let failed = harness.wait_for("Nostr VPN didn't close, so the update couldn't finish.");
    assert!(!failed.quit && failed.primary_action == "retry");
    assert!(!harness.marker().exists());
}

#[test]
fn linux_stops_at_a_verified_download_the_user_installs() {
    let harness = Harness::new(
        vec![Script {
            events: vec![found(), bytes(69_000_000)],
            result: Ok(downloaded()),
        }],
        quick_timeouts(),
    );
    harness
        .backend
        .install
        .lock()
        .unwrap()
        .push(Ok(InstallOutcome::Downloaded));
    assert_eq!(
        harness.view(DesktopPlatform::Linux).primary_label,
        "Download update"
    );
    harness.flow.start(&harness.request);
    harness.wait_for("Finding the update…");
    harness.advance_to("Downloading v4.1.23… 0.0 MB");
    harness.advance_to("Downloading v4.1.23… 100%");
    harness.advance_to("v4.1.23 is downloaded. Install it from the file.");
    let view = harness.view(DesktopPlatform::Linux);
    assert_eq!(
        (view.primary_action.as_str(), view.primary_label.as_str()),
        (ACTION_SHOW_FILE, "Show download")
    );
    assert!(!view.busy && !harness.marker().exists());
}

#[test]
fn installing_when_already_current_says_so() {
    let harness = Harness::new(
        vec![Script {
            events: vec![],
            result: Ok(DownloadResult::UpToDate {
                tag: "v4.1.22".to_string(),
            }),
        }],
        quick_timeouts(),
    );
    harness.flow.start(&harness.request);
    let view = harness.advance_to("Nostr VPN is up to date");
    assert!(!view.busy && view.primary_action.is_empty());
}

#[cfg(target_os = "macos")]
mod macos_swap {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::super::install::platform::{SWAP_SCRIPT, install_bundle};
    use super::super::view::UpdateFailure;

    fn app(dir: &std::path::Path, name: &str, version: &str) -> std::path::PathBuf {
        let app = dir.join(name);
        fs::create_dir_all(app.join("Contents")).unwrap();
        fs::write(app.join("Contents/version"), version).unwrap();
        app
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nvpn-swap-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_bundle_is_swapped_only_after_the_app_exits() {
        let dir = temp("ok");
        let current = app(&dir, "Nostr VPN.app", "old");
        let staged = app(&dir, ".Nostr VPN.app.update", "new");
        let mut running = Command::new("/bin/sleep").arg("0.6").spawn().unwrap();
        let pid = running.id();
        // Reap the stand-in app as soon as it exits, as launchd would.
        let reaper = std::thread::spawn(move || running.wait());
        let started = Instant::now();
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(SWAP_SCRIPT)
            .arg("swap")
            .arg(pid.to_string())
            .arg(&current)
            .arg(&staged)
            .env("NVPN_UPDATE_SKIP_OPEN", "1")
            .status()
            .unwrap();
        reaper.join().unwrap().unwrap();
        assert!(status.success());
        assert!(started.elapsed() >= Duration::from_millis(500));
        assert_eq!(
            fs::read_to_string(current.join("Contents/version")).unwrap(),
            "new"
        );
        assert!(!staged.exists() && !dir.join("Nostr VPN.app.previous").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_app_that_keeps_running_is_left_untouched() {
        let dir = temp("busy");
        let current = app(&dir, "Nostr VPN.app", "old");
        let staged = app(&dir, ".Nostr VPN.app.update", "new");
        let mut running = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(SWAP_SCRIPT)
            .arg("swap")
            .arg(running.id().to_string())
            .arg(&current)
            .arg(&staged)
            .env("NVPN_UPDATE_SKIP_OPEN", "1")
            .env("NVPN_UPDATE_CLOSE_WAIT_TICKS", "3")
            .status()
            .unwrap();
        running.kill().unwrap();
        running.wait().unwrap();
        assert!(!status.success());
        assert_eq!(
            fs::read_to_string(current.join("Contents/version")).unwrap(),
            "old"
        );
        assert!(!staged.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_read_only_folder_is_reported_before_anything_changes() {
        let dir = temp("readonly");
        let apps = dir.join("Applications");
        fs::create_dir_all(&apps).unwrap();
        let current = app(&apps, "Nostr VPN.app", "old");
        let new_app = app(&dir, "new.app", "new");
        fs::set_permissions(&apps, fs::Permissions::from_mode(0o555)).unwrap();
        let error = install_bundle(&new_app, &current, std::process::id()).unwrap_err();
        fs::set_permissions(&apps, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(error.failure, UpdateFailure::NoPermission);
        assert_eq!(
            fs::read_to_string(current.join("Contents/version")).unwrap(),
            "old"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
