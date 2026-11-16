#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow};
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
        SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };

    use super::{ConfigSecret, hydrate_config_secret_fields};

    pub(super) const REDACTED_SECRET_MARKER: &str = "stored-in-windows-dpapi";

    pub(super) fn store_name() -> &'static str {
        "a Windows DPAPI-protected sidecar"
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
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let plaintext = dpapi_unprotect(&bytes)
            .with_context(|| format!("failed to decrypt {}", path.display()))?;
        String::from_utf8(plaintext)
            .with_context(|| {
                format!(
                    "{} in {} is not valid UTF-8",
                    kind.display_name(),
                    path.display()
                )
            })
            .map(Some)
    }

    pub(super) fn write_secret(path: &Path, kind: ConfigSecret, value: &str) -> Result<()> {
        let secret_path = secret_path(path, kind);
        if let Some(parent) = secret_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let encrypted = dpapi_protect(value.as_bytes())?;
        fs::write(&secret_path, encrypted)
            .with_context(|| format!("failed to write {}", secret_path.display()))?;
        restrict_machine_config_sidecar_acl(&secret_path)
    }

    pub(super) fn delete_secret(path: &Path, kind: ConfigSecret) -> Result<()> {
        match fs::remove_file(secret_path(path, kind)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to delete Windows secret sidecar"),
        }
    }

    // Machine-scope DPAPI blobs are decryptable by any account that can read
    // them. The machine sidecars must stay machine-scoped because the
    // LocalSystem daemon service and user-session management share one set of
    // blobs under C:\ProgramData\Nostr VPN, so the file DACL is the at-rest
    // control. ProgramData inheritance grants read to every interactive user,
    // so each sidecar write replaces the inherited DACL with a protected one
    // held only by SYSTEM and Administrators. Sidecars outside the machine
    // config root keep their location's own ACL (per-user config directories
    // already exclude other accounts). A freshly created sidecar inherits the
    // directory ACL for the instant between file creation and this call.
    fn restrict_machine_config_sidecar_acl(secret_path: &Path) -> Result<()> {
        if !secret_path_shares_machine_config_root(
            secret_path,
            std::env::var_os("PROGRAMDATA").as_deref(),
        ) {
            return Ok(());
        }

        let trustee_sids = [
            ("S-1-5-18", TRUSTEE_IS_WELL_KNOWN_GROUP),
            ("S-1-5-32-544", TRUSTEE_IS_GROUP),
        ];
        let mut sid_handles: Vec<PSID> = Vec::with_capacity(trustee_sids.len());
        let mut entries = Vec::with_capacity(trustee_sids.len());
        for (sid_string, trustee_type) in trustee_sids {
            let mut sid: PSID = std::ptr::null_mut();
            let sid_wide: Vec<u16> = sid_string.encode_utf16().chain(Some(0)).collect();
            let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) };
            if ok == 0 {
                free_sid_handles(&sid_handles);
                return Err(anyhow!(std::io::Error::last_os_error())
                    .context(format!("resolve SID {sid_string}")));
            }
            sid_handles.push(sid);
            entries.push(EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: trustee_type,
                    ptstrName: sid.cast(),
                },
            });
        }

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let status = unsafe {
            SetEntriesInAclW(
                u32::try_from(entries.len()).context("too many trustee entries")?,
                entries.as_ptr(),
                std::ptr::null(),
                &mut dacl,
            )
        };
        if status != ERROR_SUCCESS {
            free_sid_handles(&sid_handles);
            return Err(anyhow!(std::io::Error::from_raw_os_error(status as i32))
                .context("build restrictive sidecar DACL"));
        }

        let mut wide_path: Vec<u16> = secret_path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        unsafe { LocalFree(dacl.cast()) };
        free_sid_handles(&sid_handles);
        if status != ERROR_SUCCESS {
            return Err(anyhow!(std::io::Error::from_raw_os_error(status as i32))
                .context("restrict sidecar DACL to SYSTEM and Administrators"));
        }
        Ok(())
    }

    fn free_sid_handles(sid_handles: &[PSID]) {
        for sid in sid_handles {
            unsafe { LocalFree((*sid).cast()) };
        }
    }

    pub(super) fn secret_path_shares_machine_config_root(
        secret_path: &Path,
        program_data_dir: Option<&OsStr>,
    ) -> bool {
        let Some(machine_config) =
            crate::platform_paths::windows_machine_config_path_from_program_data_dir(
                program_data_dir.map(Path::new),
            )
        else {
            return false;
        };
        let (Some(machine_root), Some(secret_root)) =
            (machine_config.parent(), secret_path.parent())
        else {
            return false;
        };
        secret_root
            .to_string_lossy()
            .eq_ignore_ascii_case(machine_root.to_string_lossy().as_ref())
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
        parent.join(format!(".{file_name}.{}.dpapi", kind.account_suffix()))
    }

    fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(plaintext.len()).context("secret is too large for DPAPI")?,
            pbData: plaintext.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(anyhow!(std::io::Error::last_os_error()));
        }
        let bytes = unsafe { blob_to_vec_and_free(output) };
        Ok(bytes)
    }

    fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(ciphertext.len()).context("secret is too large for DPAPI")?,
            pbData: ciphertext.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(anyhow!(std::io::Error::last_os_error()));
        }
        let bytes = unsafe { blob_to_vec_and_free(output) };
        Ok(bytes)
    }

    unsafe fn blob_to_vec_and_free(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
        unsafe {
            LocalFree(blob.pbData.cast());
        }
        bytes
    }
}
