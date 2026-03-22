#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use anyhow::{Context, Result, anyhow};

#[cfg(test)]
use anyhow::{Result, anyhow};

#[cfg(target_os = "windows")]
pub use wintun::Wintun;

#[cfg(any(target_os = "windows", test))]
fn resolve_wintun_dll_path_for_layout(exe: Option<&Path>, built_path: &Path) -> Result<PathBuf> {
    if let Some(exe) = exe
        && let Some(dir) = exe.parent()
    {
        let mut candidates = vec![dir.join("wintun.dll")];
        candidates.push(dir.join("binaries").join("wintun.dll"));
        if let Some(parent) = dir.parent() {
            candidates.push(parent.join("wintun.dll"));
            candidates.push(parent.join("resources").join("wintun.dll"));
            candidates.push(parent.join("Resources").join("wintun.dll"));
            candidates.push(parent.join("resources").join("binaries").join("wintun.dll"));
            candidates.push(parent.join("Resources").join("binaries").join("wintun.dll"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("Resources").join("wintun.dll"));
                candidates.push(
                    grandparent
                        .join("Resources")
                        .join("binaries")
                        .join("wintun.dll"),
                );
            }
        }

        for candidate in candidates {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    if built_path.is_file() {
        return Ok(built_path.to_path_buf());
    }

    Err(anyhow!(
        "wintun.dll not found next to executable or in build output"
    ))
}

#[cfg(target_os = "windows")]
pub fn resolve_wintun_dll_path() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let built_path = PathBuf::from(env!("NOSTR_VPN_WINTUN_DLL_SOURCE"));
    resolve_wintun_dll_path_for_layout(current_exe.as_deref(), &built_path)
}

#[cfg(target_os = "windows")]
pub fn load_wintun() -> Result<Wintun> {
    let dll_path = resolve_wintun_dll_path()?;
    // The path is constrained to a bundled wintun.dll location we control.
    unsafe { wintun::load_from_path(&dll_path) }
        .with_context(|| format!("failed to load wintun.dll from {}", dll_path.display()))
}

#[cfg(test)]
mod tests {
    use super::resolve_wintun_dll_path_for_layout;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("nostr-vpn-wintun-{label}-{nonce}"))
    }

    #[test]
    fn resolve_wintun_dll_path_supports_nsis_installed_layout() {
        let root = unique_temp_dir("nsis-layout");
        let exe_path = root.join("nvpn.exe");
        let bundled_dll = root.join("binaries").join("wintun.dll");
        fs::create_dir_all(
            bundled_dll
                .parent()
                .expect("bundled wintun path should have parent"),
        )
        .expect("create bundled binaries dir");
        fs::write(&exe_path, b"exe").expect("write exe placeholder");
        fs::write(&bundled_dll, b"dll").expect("write wintun placeholder");

        let resolved = resolve_wintun_dll_path_for_layout(Some(&exe_path), Path::new("missing"))
            .expect("resolve wintun for installed layout");

        assert_eq!(resolved, bundled_dll);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wintun_dll_path_falls_back_to_built_path() {
        let root = unique_temp_dir("built-fallback");
        let built_dll = root.join("wintun.dll");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(&built_dll, b"dll").expect("write built wintun placeholder");

        let resolved = resolve_wintun_dll_path_for_layout(None, &built_dll)
            .expect("resolve wintun from built path");

        assert_eq!(resolved, built_dll);

        let _ = fs::remove_dir_all(&root);
    }
}
