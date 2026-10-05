use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use nostr_vpn_core::updater::{
    ProductUpdateMode, ProductUpdateResult, ProductUpdateSource, check_product_update_with_config,
    download_product_update_with_config,
};

use super::{PRODUCT_VERSION, UpdateArgs, UpdateSource, default_config_path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateMode {
    Cli,
    App,
}

impl UpdateMode {
    fn from_args(args: &UpdateArgs) -> Self {
        if args.app { Self::App } else { Self::Cli }
    }

    fn core(self) -> ProductUpdateMode {
        match self {
            Self::Cli => ProductUpdateMode::Cli,
            Self::App => ProductUpdateMode::App,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Cli => "nvpn CLI",
            Self::App => "Nostr VPN app",
        }
    }
}

pub(crate) async fn run_update(args: UpdateArgs) -> Result<()> {
    let mode = UpdateMode::from_args(&args);
    let source = core_source(args.source);
    #[cfg(target_os = "macos")]
    let helper_update = if mode == UpdateMode::Cli && !args.check && !args.download_only {
        let destination = args
            .path
            .clone()
            .map(Ok)
            .unwrap_or_else(std::env::current_exe)?;
        let helper = crate::macos_privileged_files::helper_destination(&destination).is_some();
        if helper {
            crate::macos_privileged_files::require_root()?;
        }
        helper
    } else {
        false
    };
    let config_path = default_config_path();

    let check =
        check_product_update_with_config(PRODUCT_VERSION, mode.core(), source, Some(&config_path))
            .await?;
    if args.check {
        print_update_check(mode, &check, args.json)?;
        return Ok(());
    }
    if !check.available && !args.force {
        print_up_to_date(mode, &check, args.json)?;
        return Ok(());
    }

    let temp_dir = create_temp_dir("nvpn-update")?;
    let download_parent = args.download_dir.as_deref().unwrap_or(&temp_dir);
    #[cfg(target_os = "macos")]
    if helper_update {
        crate::macos_privileged_files::protected_directory(download_parent, false)?;
    }
    let download = download_product_update_with_config(
        PRODUCT_VERSION,
        mode.core(),
        source,
        Some(download_parent),
        Some(&config_path),
    )
    .await?;
    let archive_path = download
        .path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("updater did not return a downloaded file"))?;

    if args.download_only || mode == UpdateMode::App {
        print_downloaded(&download, args.json)?;
        return Ok(());
    }

    ensure_verified_for_install(&download)?;
    install_cli_archive(&archive_path, &temp_dir, args.path.as_deref())?;
    let _ = fs::remove_dir_all(&temp_dir);

    println!(
        "updated nvpn at {} from {PRODUCT_VERSION} to {}",
        args.path
            .as_deref()
            .map_or_else(current_exe_display, |path| path.display().to_string()),
        download.tag
    );
    Ok(())
}

fn core_source(source: UpdateSource) -> ProductUpdateSource {
    match source {
        UpdateSource::Auto => ProductUpdateSource::Auto,
        UpdateSource::Github => ProductUpdateSource::Github,
        UpdateSource::Hashtree => ProductUpdateSource::Hashtree,
    }
}

fn print_update_check(mode: UpdateMode, result: &ProductUpdateResult, json: bool) -> Result<()> {
    if json {
        print_update_json(result)?;
        return Ok(());
    }

    if result.available {
        println!(
            "update available: {} -> {}",
            result.current_version, result.tag
        );
    } else {
        println!("{} {} is up to date", mode.noun(), result.current_version);
    }
    println!("asset={}", result.asset);
    println!("source={}", result.source);
    println!("verified={}", result.verified);
    if let Some(url) = result.url.as_deref() {
        println!("url={url}");
    }
    if let Some(path) = result.path.as_deref() {
        println!("path={path}");
    }
    Ok(())
}

fn print_downloaded(result: &ProductUpdateResult, json: bool) -> Result<()> {
    if json {
        print_update_json(result)?;
        return Ok(());
    }
    println!("downloaded {}", result.asset);
    if let Some(path) = result.path.as_deref() {
        println!("path={path}");
    }
    println!("source={}", result.source);
    println!("verified={}", result.verified);
    if let Some(url) = result.url.as_deref() {
        println!("url={url}");
    }
    Ok(())
}

fn print_up_to_date(mode: UpdateMode, result: &ProductUpdateResult, json: bool) -> Result<()> {
    if json {
        print_update_json(result)?;
        return Ok(());
    }
    println!("{} {} is up to date", mode.noun(), result.current_version);
    Ok(())
}

fn print_update_json(output: &ProductUpdateResult) -> Result<()> {
    println!("{}", serde_json::to_string(output)?);
    Ok(())
}

fn ensure_verified_for_install(result: &ProductUpdateResult) -> Result<()> {
    if result.verified {
        return Ok(());
    }
    Err(anyhow!(
        "refusing to install unverified update from {}; use --download-only to inspect it manually",
        result.source
    ))
}

fn install_cli_archive(
    archive_path: &Path,
    temp_dir: &Path,
    destination: Option<&Path>,
) -> Result<()> {
    extract_archive(archive_path, temp_dir)?;
    let binary = find_nvpn_binary(temp_dir)?;
    let destination = destination
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(|| {
            std::env::current_exe().context("failed to resolve current executable")
        })?;
    install_parent(&destination)?;
    install_bundled_helpers(&binary, &destination)?;
    install_binary(&binary, &destination)
}

fn current_exe_display() -> String {
    std::env::current_exe().map_or_else(
        |_| "<current executable>".to_string(),
        |path| path.display().to_string(),
    )
}

fn extract_archive(archive_path: &Path, destination: &Path) -> Result<()> {
    let mut command = Command::new("tar");
    if archive_path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.ends_with(".tar.gz") || name.ends_with(".tgz"))
    {
        command.arg("-xzf");
    } else {
        command.arg("-xf");
    }
    let output = command
        .arg(archive_path)
        .arg("-C")
        .arg(destination)
        .output()
        .with_context(|| format!("failed to extract {}", archive_path.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{}",
            command_error("archive extraction failed", &output)
        ));
    }
    Ok(())
}

fn find_nvpn_binary(root: &Path) -> Result<PathBuf> {
    let binary_name = if cfg!(target_os = "windows") {
        "nvpn.exe"
    } else {
        "nvpn"
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in
            fs::read_dir(&path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file()
                && path.file_name().and_then(|value| value.to_str()) == Some(binary_name)
            {
                return Ok(path);
            }
        }
    }
    Err(anyhow!("downloaded archive did not contain {binary_name}"))
}

fn install_binary(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(destination) = crate::macos_privileged_files::helper_destination(destination) {
        return crate::macos_privileged_files::install_executable(source, &destination);
    }
    let parent = install_parent(destination)?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let temp_path = parent.join(format!(
        ".nvpn-update-{}-{}{}",
        std::process::id(),
        unix_timestamp(),
        std::env::consts::EXE_SUFFIX
    ));
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }
    fs::copy(source, &temp_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            temp_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755)).with_context(|| {
            format!(
                "failed to set executable permissions on {}",
                temp_path.display()
            )
        })?;
    }
    #[cfg(target_os = "windows")]
    if destination.exists() {
        fs::remove_file(destination)
            .with_context(|| format!("failed to replace {}", destination.display()))?;
    }
    fs::rename(&temp_path, destination).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp_path.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn install_parent(destination: &Path) -> Result<&Path> {
    if destination.as_os_str().is_empty() {
        return Err(anyhow!("install path must not be empty"));
    }
    if destination.is_dir() {
        return Err(anyhow!(
            "install path points to a directory: {}",
            destination.display()
        ));
    }
    destination.parent().ok_or_else(|| {
        anyhow!(
            "install path must include parent directory: {}",
            destination.display()
        )
    })
}

#[cfg(target_os = "windows")]
fn install_bundled_helpers(source_binary: &Path, destination_binary: &Path) -> Result<()> {
    let Some(source_dir) = bundled_helper_source_dir(source_binary) else {
        return Ok(());
    };
    let destination_dir = install_parent(destination_binary)?.join("binaries");
    install_bundled_helper_dir(&source_dir, &destination_dir)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn install_bundled_helpers(_source_binary: &Path, _destination_binary: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn bundled_helper_source_dir(source_binary: &Path) -> Option<PathBuf> {
    source_binary
        .parent()
        .map(|parent| parent.join("binaries"))
        .filter(|path| path.is_dir())
}

#[cfg(any(target_os = "windows", test))]
fn install_bundled_helper_dir(source_dir: &Path, destination_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut installed = Vec::new();
    let mut stack = vec![source_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let relative = path
                .strip_prefix(source_dir)
                .with_context(|| format!("failed to relativize {}", path.display()))?;
            let destination = destination_dir.join(relative);
            install_helper_file(&path, &destination)?;
            installed.push(destination);
        }
    }
    Ok(installed)
}

#[cfg(any(target_os = "windows", test))]
fn install_helper_file(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "helper install path must include parent directory: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("helper");
    let temp_path = destination.with_file_name(format!(
        ".nvpn-update-{}-{}-{file_name}",
        std::process::id(),
        unix_timestamp(),
    ));
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }
    fs::copy(source, &temp_path).with_context(|| {
        format!(
            "failed to copy helper {} to {}",
            source.display(),
            temp_path.display()
        )
    })?;
    if destination.exists() {
        fs::remove_file(destination)
            .with_context(|| format!("failed to replace {}", destination.display()))?;
    }
    fs::rename(&temp_path, destination).with_context(|| {
        format!(
            "failed to move helper {} into {}",
            temp_path.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn create_temp_dir(prefix: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    #[cfg(target_os = "macos")]
    let base = if unsafe { libc::geteuid() } == 0 {
        let base = PathBuf::from("/Library/Application Support/nvpn/updates");
        crate::macos_privileged_files::protected_directory(&base, true)?;
        base
    } else {
        base
    };
    for attempt in 0..128u32 {
        let path = base.join(format!(
            "{prefix}-{}-{}-{attempt}",
            std::process::id(),
            unix_timestamp()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to create {}", path.display()));
            }
        }
    }
    Err(anyhow!("failed to allocate temporary update directory"))
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

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("nvpn-updater-{label}-{nonce}"))
    }

    #[test]
    fn helper_source_dir_is_next_to_downloaded_binary() {
        let root = unique_temp_dir("helper-source");
        let binary = root.join("archive").join("nvpn.exe");
        let helper_dir = binary.parent().expect("binary parent").join("binaries");
        fs::create_dir_all(&helper_dir).expect("create helper dir");
        fs::write(&binary, b"exe").expect("write binary placeholder");
        fs::write(helper_dir.join("wintun.dll"), b"dll").expect("write helper placeholder");

        assert_eq!(bundled_helper_source_dir(&binary), Some(helper_dir));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn installs_bundled_helper_files_recursively() {
        let root = unique_temp_dir("helper-install");
        let source_dir = root.join("source").join("binaries");
        let destination_dir = root.join("install").join("binaries");
        fs::create_dir_all(source_dir.join("drivers")).expect("create source dirs");
        fs::create_dir_all(&destination_dir).expect("create destination dir");
        fs::write(source_dir.join("wintun.dll"), b"new").expect("write wintun helper");
        fs::write(source_dir.join("drivers").join("extra.dll"), b"extra")
            .expect("write nested helper");
        fs::write(destination_dir.join("wintun.dll"), b"old").expect("write old helper");

        let installed = install_bundled_helper_dir(&source_dir, &destination_dir)
            .expect("install bundled helpers");

        assert!(installed.contains(&destination_dir.join("wintun.dll")));
        assert!(installed.contains(&destination_dir.join("drivers").join("extra.dll")));
        assert_eq!(
            fs::read(destination_dir.join("wintun.dll")).expect("read installed wintun"),
            b"new"
        );
        assert_eq!(
            fs::read(destination_dir.join("drivers").join("extra.dll"))
                .expect("read installed nested helper"),
            b"extra"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
