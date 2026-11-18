use std::ffi::OsStr;
use std::fs;
#[cfg(not(target_os = "macos"))]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nostr_vpn_core::updater::{
    DownloadCallback, DownloadEvent, VerifiedAppDownload, VerifiedAppRelease,
    download_verified_app_update_blocking,
};

use super::flow::{
    DownloadResult, InstallOutcome, Progress, ProgressSink, StepError, UpdateBackend,
    UpdateRequest,
};
use super::view::{
    ACTION_OPEN_INSTALLER, ACTION_OPEN_WEBSITE, ACTION_SHOW_FILE, RELEASES_URL, UpdateFailure,
};

/// Downloads signed releases and installs them on this computer.
pub struct SystemBackend;

impl UpdateBackend for SystemBackend {
    fn download(
        &self,
        request: &UpdateRequest,
        progress: ProgressSink,
    ) -> Result<DownloadResult, StepError> {
        let found = Arc::new(AtomicBool::new(false));
        let on_found = {
            let found = Arc::clone(&found);
            let progress = Arc::clone(&progress);
            Box::new(move |release: &VerifiedAppRelease| {
                found.store(true, Ordering::SeqCst);
                progress(Progress::Found {
                    tag: release.tag.clone(),
                });
            })
        };
        let total = Arc::new(AtomicU64::new(0));
        let on_event: DownloadCallback = Arc::new(move |event| {
            let (received, size) = match event {
                DownloadEvent::Started { content_length } => {
                    total.store(content_length.unwrap_or_default(), Ordering::SeqCst);
                    (0, content_length)
                }
                DownloadEvent::Progress { downloaded, .. } => {
                    let size = total.load(Ordering::SeqCst);
                    (downloaded, (size > 0).then_some(size))
                }
                DownloadEvent::Finished { total } => (total, Some(total)),
            };
            progress(Progress::Bytes {
                received,
                total: size,
            });
        });
        let config = PathBuf::from(request.config_path.trim());
        let config = (!config.as_os_str().is_empty()).then_some(config);
        let download_dir = download_dir();
        match download_verified_app_update_blocking(
            &request.current_version,
            config.as_deref(),
            Some(&download_dir),
            on_found,
            on_event,
        ) {
            Ok(VerifiedAppDownload::UpToDate { tag }) => Ok(DownloadResult::UpToDate { tag }),
            Ok(VerifiedAppDownload::Downloaded { release, path }) => Ok(DownloadResult::Downloaded {
                tag: release.tag,
                path,
            }),
            Err(error) => {
                let failure = if found.load(Ordering::SeqCst) {
                    UpdateFailure::DownloadFailed
                } else {
                    UpdateFailure::NotFound
                };
                Err(StepError::new(failure, format!("{error:#}")))
            }
        }
    }

    fn verify(&self, download: &Path, _tag: &str) -> Result<PathBuf, StepError> {
        platform::verify(download)
    }

    fn install(&self, verified: &Path, _tag: &str) -> Result<InstallOutcome, StepError> {
        platform::install(verified)
    }

    fn open(&self, action: &str, download: Option<&Path>) -> Result<(), String> {
        match (action, download) {
            (ACTION_OPEN_WEBSITE, _) => platform::open(OsStr::new(RELEASES_URL)),
            (ACTION_SHOW_FILE, Some(path)) => platform::reveal(path),
            (ACTION_OPEN_INSTALLER, Some(path)) => platform::open(path.as_os_str()),
            _ => Err("The download is no longer available".to_string()),
        }
    }
}

fn download_dir() -> PathBuf {
    std::env::var_os("NVPN_UPDATE_DOWNLOAD_DIR")
        .filter(|value| !value.is_empty())
        .map_or_else(|| std::env::temp_dir().join("NostrVpnDownloads"), PathBuf::from)
}

fn damaged(detail: impl Into<String>) -> StepError {
    StepError::new(UpdateFailure::Damaged, detail)
}

fn install_failed(detail: impl Into<String>) -> StepError {
    StepError::new(UpdateFailure::InstallFailed, detail)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(not(target_os = "macos"))]
fn read_magic(path: &Path, len: usize) -> Result<Vec<u8>, StepError> {
    let mut file =
        fs::File::open(path).map_err(|error| damaged(format!("{}: {error}", path.display())))?;
    let mut magic = vec![0; len];
    file.read_exact(&mut magic)
        .map_err(|error| damaged(format!("{}: {error}", path.display())))?;
    Ok(magic)
}

#[cfg(not(target_os = "windows"))]
fn run(program: &str, args: &[&OsStr]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        Ok(stderr)
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if stderr.is_empty() { stdout } else { stderr };
        Err(format!("{program} failed: {message}"))
    }
}

/// Whether this process can create files in `dir`.
#[cfg(target_os = "macos")]
fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".nvpn-update-probe-{}", std::process::id()));
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
pub(super) mod platform {
    use std::os::unix::process::CommandExt;

    use super::{
        Command, InstallOutcome, OsStr, Path, PathBuf, StepError, Stdio, UpdateFailure, damaged,
        dir_writable, file_name, fs, install_failed, run,
    };

    pub(in super::super) const SWAP_SCRIPT: &str = r#"#!/bin/sh
# Replace the app bundle once the running copy has exited, then open it.
pid="$1"
app="$2"
staged="$3"
backup="$app.previous"
waited=0
while kill -0 "$pid" 2>/dev/null; do
  if [ "$waited" -ge "${NVPN_UPDATE_CLOSE_WAIT_TICKS:-600}" ]; then
    rm -rf "$staged"
    exit 1
  fi
  sleep 0.1
  waited=$((waited + 1))
done
rm -rf "$backup"
if mv "$app" "$backup"; then
  if mv "$staged" "$app"; then
    rm -rf "$backup"
  else
    mv "$backup" "$app"
    rm -rf "$staged"
  fi
else
  rm -rf "$staged"
fi
[ -n "${NVPN_UPDATE_SKIP_OPEN:-}" ] || open "$app"
"#;

    pub fn verify(download: &Path) -> Result<PathBuf, StepError> {
        let name = file_name(download);
        if !name.ends_with(".app.tar.gz") {
            return Err(damaged(format!("Expected a macOS app archive, got {name}")));
        }
        let unpack = download.with_file_name(format!(
            "{}-unpacked",
            name.trim_end_matches(".app.tar.gz")
        ));
        let _ = fs::remove_dir_all(&unpack);
        fs::create_dir_all(&unpack).map_err(|error| install_failed(error.to_string()))?;
        run(
            "/usr/bin/tar",
            &[
                OsStr::new("-xzf"),
                download.as_os_str(),
                OsStr::new("-C"),
                unpack.as_os_str(),
            ],
        )
        .map_err(damaged)?;
        let app = find_app_bundle(&unpack)
            .ok_or_else(|| damaged("The archive has no Nostr VPN app"))?;
        run(
            "/usr/bin/codesign",
            &[
                OsStr::new("--verify"),
                OsStr::new("--deep"),
                OsStr::new("--strict"),
                app.as_os_str(),
            ],
        )
        .map_err(damaged)?;
        if let Some(current) = current_app_bundle() {
            if let Some(team) = team_identifier(&current)
                && team_identifier(&app).as_deref() != Some(team.as_str())
            {
                return Err(damaged(format!(
                    "The new app is not signed by team {team}"
                )));
            }
            let expected = bundle_identifier(&current);
            if expected.is_some() && bundle_identifier(&app) != expected {
                return Err(damaged("The new app has a different bundle identifier"));
            }
        }
        Ok(app)
    }

    pub fn install(new_app: &Path) -> Result<InstallOutcome, StepError> {
        let current = current_app_bundle()
            .ok_or_else(|| install_failed("This copy of Nostr VPN is not inside an app bundle"))?;
        install_bundle(new_app, &current, std::process::id())?;
        Ok(InstallOutcome::Restart)
    }

    /// Stage `new_app` next to `current` and start a helper that swaps them
    /// after `pid` exits.
    pub(in super::super) fn install_bundle(
        new_app: &Path,
        current: &Path,
        pid: u32,
    ) -> Result<(), StepError> {
        let parent = current
            .parent()
            .ok_or_else(|| install_failed("The app has no parent folder"))?;
        if !dir_writable(parent) {
            return Err(StepError::new(
                UpdateFailure::NoPermission,
                format!("{} is not writable", parent.display()),
            ));
        }
        let staged = parent.join(format!(".{}.update", file_name(current)));
        let _ = fs::remove_dir_all(&staged);
        run("/usr/bin/ditto", &[new_app.as_os_str(), staged.as_os_str()])
            .map_err(install_failed)?;
        let script = std::env::temp_dir().join(format!("nostr-vpn-swap-update-{pid}.sh"));
        fs::write(&script, SWAP_SCRIPT).map_err(|error| install_failed(error.to_string()))?;
        Command::new("/bin/sh")
            .arg(&script)
            .arg(pid.to_string())
            .arg(current)
            .arg(&staged)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|error| install_failed(format!("Could not start the installer: {error}")))?;
        Ok(())
    }

    pub fn reveal(path: &Path) -> Result<(), String> {
        run("/usr/bin/open", &[OsStr::new("-R"), path.as_os_str()]).map(|_| ())
    }

    pub fn open(target: &OsStr) -> Result<(), String> {
        run("/usr/bin/open", &[target]).map(|_| ())
    }

    fn current_app_bundle() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        exe.ancestors()
            .find(|path| path.extension().is_some_and(|ext| ext == "app"))
            .map(Path::to_path_buf)
    }

    fn find_app_bundle(dir: &Path) -> Option<PathBuf> {
        let mut pending = vec![dir.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir).ok()?.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "app") {
                    return Some(path);
                }
                if path.is_dir() {
                    pending.push(path);
                }
            }
        }
        None
    }

    fn team_identifier(app: &Path) -> Option<String> {
        let details = run("/usr/bin/codesign", &[OsStr::new("-dv"), app.as_os_str()]).ok()?;
        details
            .lines()
            .find_map(|line| line.strip_prefix("TeamIdentifier="))
            .map(str::trim)
            .filter(|team| !team.is_empty() && *team != "not set")
            .map(str::to_string)
    }

    fn bundle_identifier(app: &Path) -> Option<String> {
        let plist = app.join("Contents/Info.plist");
        let output = Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", "Print :CFBundleIdentifier"])
            .arg(plist)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

#[cfg(target_os = "windows")]
pub(super) mod platform {
    use std::os::windows::process::CommandExt;

    use super::{
        Command, InstallOutcome, OsStr, Path, PathBuf, StepError, Stdio, damaged, file_name, fs,
        install_failed, read_magic,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    const INSTALL_SCRIPT: &str = r"param([int]$AppPid, [string]$Setup, [string]$App)
# Run the installer once the running app has exited, then start the new app.
$deadline = (Get-Date).AddSeconds(60)
while (Get-Process -Id $AppPid -ErrorAction SilentlyContinue) {
  if ((Get-Date) -gt $deadline) { exit 1 }
  Start-Sleep -Milliseconds 200
}
$installer = Start-Process -FilePath $Setup -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
Start-Process -FilePath $App
exit $installer.ExitCode
";

    pub fn verify(download: &Path) -> Result<PathBuf, StepError> {
        let name = file_name(download);
        if !name.to_ascii_lowercase().ends_with(".exe") {
            return Err(damaged(format!("Expected a Windows installer, got {name}")));
        }
        if read_magic(download, 2)? != b"MZ" {
            return Err(damaged(format!("{name} is not a Windows program")));
        }
        Ok(download.to_path_buf())
    }

    pub fn install(setup: &Path) -> Result<InstallOutcome, StepError> {
        let app = std::env::current_exe().map_err(|error| install_failed(error.to_string()))?;
        let script = setup.with_file_name("nostr-vpn-install-update.ps1");
        fs::write(&script, INSTALL_SCRIPT).map_err(|error| install_failed(error.to_string()))?;
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
            ])
            .arg(&script)
            .arg("-AppPid")
            .arg(std::process::id().to_string())
            .arg("-Setup")
            .arg(setup)
            .arg("-App")
            .arg(&app)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map_err(|error| install_failed(format!("Could not start the installer: {error}")))?;
        Ok(InstallOutcome::Restart)
    }

    pub fn reveal(path: &Path) -> Result<(), String> {
        let mut select = std::ffi::OsString::from("/select,");
        select.push(path.as_os_str());
        Command::new("explorer.exe")
            .arg(select)
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn open(target: &OsStr) -> Result<(), String> {
        Command::new("cmd.exe")
            .args(["/C", "start", ""])
            .arg(target)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(super) mod platform {
    use std::os::unix::fs::PermissionsExt;

    use super::{
        InstallOutcome, OsStr, Path, PathBuf, StepError, damaged, file_name, fs, install_failed,
        read_magic, run,
    };

    fn extension(path: &Path) -> String {
        path.extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
    }

    pub fn verify(download: &Path) -> Result<PathBuf, StepError> {
        let name = file_name(download);
        let expected: &[u8] = match extension(download).as_str() {
            "deb" => b"!<arch>\n",
            "rpm" => &[0xed, 0xab, 0xee, 0xdb],
            "zst" => &[0x28, 0xb5, 0x2f, 0xfd],
            "appimage" => b"\x7fELF",
            _ => &[],
        };
        if read_magic(download, expected.len().max(1))?.starts_with(expected) {
            Ok(download.to_path_buf())
        } else {
            Err(damaged(format!("{name} is not a valid package")))
        }
    }

    pub fn install(package: &Path) -> Result<InstallOutcome, StepError> {
        if extension(package) == "appimage" {
            let mut permissions = fs::metadata(package)
                .map_err(|error| install_failed(error.to_string()))?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(package, permissions)
                .map_err(|error| install_failed(error.to_string()))?;
        }
        Ok(InstallOutcome::Downloaded)
    }

    pub fn reveal(path: &Path) -> Result<(), String> {
        let folder = path.parent().unwrap_or(path);
        open(folder.as_os_str())
    }

    pub fn open(target: &OsStr) -> Result<(), String> {
        run("xdg-open", &[target]).map(|_| ())
    }
}
