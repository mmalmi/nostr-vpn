#[cfg(target_os = "linux")]
mod platform {
    use std::fs::{self, File, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow};

    use super::{ConfigSecret, hydrate_config_secret_fields};

    pub(super) const REDACTED_SECRET_MARKER: &str = "stored-in-private-secret-file";

    pub(super) fn store_name() -> &'static str {
        "a private Linux secret sidecar"
    }

    pub(super) fn allows_plaintext_fallback() -> bool {
        false
    }

    pub(super) fn hydrate_config_secrets(
        path: &Path,
        config: &mut crate::config::AppConfig,
    ) -> Result<()> {
        hydrate_config_secret_fields(path, config)
    }

    pub(super) fn read_secret(path: &Path, kind: ConfigSecret) -> Result<Option<String>> {
        let path = secret_path(path, kind);
        let Some(mut file) = open_secret_for_read(&path)? else {
            return Ok(None);
        };
        let mut value = String::new();
        file.read_to_string(&mut value)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Some(value))
    }

    pub(super) fn write_secret(path: &Path, kind: ConfigSecret, value: &str) -> Result<()> {
        let secret_path = secret_path(path, kind);
        if let Some(parent) = secret_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        validate_existing_secret_path(&secret_path)?;
        crate::config::write_private_file_preserving_user_owner(&secret_path, value.as_bytes())
            .with_context(|| format!("failed to write {}", secret_path.display()))
    }

    pub(super) fn delete_secret(path: &Path, kind: ConfigSecret) -> Result<()> {
        match fs::remove_file(secret_path(path, kind)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to delete Linux secret sidecar"),
        }
    }

    fn secret_path(path: &Path, kind: ConfigSecret) -> PathBuf {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("config.toml");
        parent.join(format!(".{file_name}.{}.secret", kind.account_suffix()))
    }

    fn open_secret_for_read(path: &Path) -> Result<Option<File>> {
        match validate_existing_secret_path(path)? {
            false => Ok(None),
            true => OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map(Some)
                .with_context(|| format!("failed to open {}", path.display())),
        }
    }

    fn validate_existing_secret_path(path: &Path) -> Result<bool> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(anyhow!(
                "refusing to use non-regular Linux secret sidecar {}",
                path.display()
            ));
        }
        Ok(true)
    }
}
