use std::{
    env,
    ffi::OsString,
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    if let Ok(target) = env::var("TARGET") {
        println!("cargo:rustc-env=NVPN_GUI_TARGET={target}");
    }

    register_sidecar_dependencies();

    if let Err(err) = prepare_sidecar() {
        panic!("failed to prepare nvpn sidecar: {err}");
    }

    tauri_build::build();
}

fn register_sidecar_dependencies() {
    for path in [
        "../scripts/prepare-sidecar.mjs",
        "../package.json",
        "../../nostr-vpn-cli/Cargo.toml",
        "../../nostr-vpn-cli/src",
        "../../nostr-vpn-wintun/Cargo.toml",
        "../../nostr-vpn-wintun/build.rs",
        "../../nostr-vpn-wintun/src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn prepare_sidecar() -> Result<(), Box<dyn std::error::Error>> {
    let target = env::var("TARGET")?;
    if !is_desktop_target(&target) {
        return Ok(());
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = workspace_root(&manifest_dir)?;
    let profile = build_profile_name();
    let sidecar_target_dir = sidecar_target_dir(&workspace_root);
    let sidecar_dir = manifest_dir.join("binaries");

    fs::create_dir_all(&sidecar_dir)?;
    build_nvpn_binary(&workspace_root, &sidecar_target_dir, &target)?;

    let output_dir = sidecar_target_dir.join(&target).join(&profile);
    let built_binary = output_dir.join(binary_name("nvpn", &target));
    if !built_binary.exists() {
        return Err(format!("expected sidecar binary at {}", built_binary.display()).into());
    }

    let sidecar_binary = sidecar_dir.join(binary_name_with_target("nvpn", &target));
    fs::copy(&built_binary, &sidecar_binary)?;
    set_executable_if_needed(&sidecar_binary)?;

    if is_windows_target(&target) {
        let built_wintun = output_dir.join("wintun.dll");
        if !built_wintun.exists() {
            return Err(format!("expected wintun.dll at {}", built_wintun.display()).into());
        }
        fs::copy(built_wintun, sidecar_dir.join("wintun.dll"))?;
    }

    Ok(())
}

fn build_nvpn_binary(
    workspace_root: &Path,
    sidecar_target_dir: &Path,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .arg("build")
        .arg("--bin")
        .arg("nvpn")
        .arg("-p")
        .arg("nostr-vpn-cli")
        .arg("--target")
        .arg(target)
        .arg("--target-dir")
        .arg(sidecar_target_dir);

    if env::var("PROFILE").as_deref() == Ok("release") {
        cmd.arg("--release");
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("cargo build exited with status {status}").into());
    }

    Ok(())
}

fn workspace_root(manifest_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .canonicalize()?)
}

fn build_profile_name() -> String {
    match env::var("PROFILE").as_deref() {
        Ok("release") => "release".to_owned(),
        _ => "debug".to_owned(),
    }
}

fn sidecar_target_dir(workspace_root: &Path) -> PathBuf {
    if let Some(path) = env::var_os("NVPN_SIDECAR_TARGET_DIR") {
        return PathBuf::from(path);
    }

    // Keep the nested cargo target on a local filesystem; Parallels shared folders
    // can break Rust's archive temp-file handling for sidecar builds.
    let mut hasher = DefaultHasher::new();
    workspace_root.hash(&mut hasher);
    env::temp_dir().join(format!("nostr-vpn-sidecar-{:016x}", hasher.finish()))
}

fn is_desktop_target(target: &str) -> bool {
    if target.contains("android") || target.contains("ios") {
        return false;
    }

    target.contains("windows") || target.contains("darwin") || target.contains("linux")
}

fn is_windows_target(target: &str) -> bool {
    target.contains("windows")
}

fn binary_name(base: &str, target: &str) -> String {
    if is_windows_target(target) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

fn binary_name_with_target(base: &str, target: &str) -> String {
    if is_windows_target(target) {
        format!("{base}-{target}.exe")
    } else {
        format!("{base}-{target}")
    }
}

fn set_executable_if_needed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}
