use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::AsyncWriteExt;
use tokio::process::Command as TokioCommand;

pub const CASHU_HELPER_ENV: &str = "CASHU_SERVICE_HELPER";
pub const CARGO_HELPER_ENV: &str = "CARGO_BIN_EXE_cashu-service-helper";
pub const LEGACY_CASHU_HELPER_ENV: &str = "HTREE_CASHU_HELPER";
pub const LEGACY_CARGO_HELPER_ENV: &str = "CARGO_BIN_EXE_htree-cashu";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuSentPayment {
    pub mint_url: String,
    pub unit: String,
    pub amount_sat: u64,
    pub send_fee_sat: u64,
    pub operation_id: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuReceivedPayment {
    pub mint_url: String,
    pub unit: String,
    pub amount_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuMintBalance {
    pub mint_url: String,
    pub unit: String,
    pub balance_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuLightningPayment {
    pub mint_url: String,
    pub unit: String,
    pub amount_sat: u64,
    pub fee_paid_sat: u64,
    pub quote_id: String,
    pub preimage: String,
}

#[async_trait]
pub trait CashuPaymentClient: Send + Sync {
    async fn send_payment(&self, mint_url: &str, amount_sat: u64) -> Result<CashuSentPayment>;
    async fn receive_payment(&self, encoded_token: &str) -> Result<CashuReceivedPayment>;
    async fn revoke_payment(&self, mint_url: &str, operation_id: &str) -> Result<()>;
    async fn mint_balance(&self, mint_url: &str) -> Result<CashuMintBalance>;
}

#[derive(Debug, Clone)]
pub struct CashuHelperClient {
    helper_path: PathBuf,
    data_dir: PathBuf,
}

impl CashuHelperClient {
    pub fn discover(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let current_exe =
            std::env::current_exe().context("Failed to determine current executable path")?;
        let helper_path = helper_binary_path(&current_exe)?;
        Ok(Self {
            helper_path,
            data_dir: data_dir.into(),
        })
    }

    pub fn helper_path(&self) -> &Path {
        &self.helper_path
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    async fn run_json<T: DeserializeOwned>(
        &self,
        extra_args: &[OsString],
        stdin: Option<&str>,
    ) -> Result<T> {
        let mut cmd = TokioCommand::new(&self.helper_path);
        cmd.args(base_helper_args(&self.data_dir));
        cmd.args(extra_args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "Failed to launch Cashu helper at {}",
                self.helper_path.display()
            )
        })?;

        if let Some(input) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .context("Cashu helper stdin unavailable")?;
            child_stdin
                .write_all(input.as_bytes())
                .await
                .context("Failed writing Cashu helper stdin")?;
            child_stdin
                .shutdown()
                .await
                .context("Failed to close Cashu helper stdin")?;
        }

        let output = child
            .wait_with_output()
            .await
            .context("Failed waiting for Cashu helper output")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "Cashu helper exited with status {}",
                    output.status.code().unwrap_or_default()
                );
            }
            bail!("Cashu helper failed: {detail}");
        }

        serde_json::from_slice(&output.stdout)
            .context("Failed to decode JSON from Cashu helper output")
    }
}

#[async_trait]
impl CashuPaymentClient for CashuHelperClient {
    async fn send_payment(&self, mint_url: &str, amount_sat: u64) -> Result<CashuSentPayment> {
        self.run_json(
            &[
                OsString::from("internal"),
                OsString::from("send"),
                OsString::from(amount_sat.to_string()),
                OsString::from("--mint"),
                OsString::from(mint_url),
            ],
            None,
        )
        .await
    }

    async fn receive_payment(&self, encoded_token: &str) -> Result<CashuReceivedPayment> {
        self.run_json(
            &[
                OsString::from("internal"),
                OsString::from("receive"),
                OsString::from("--token-stdin"),
            ],
            Some(encoded_token),
        )
        .await
    }

    async fn revoke_payment(&self, mint_url: &str, operation_id: &str) -> Result<()> {
        let _: serde_json::Value = self
            .run_json(
                &[
                    OsString::from("internal"),
                    OsString::from("revoke"),
                    OsString::from("--mint"),
                    OsString::from(mint_url),
                    OsString::from("--operation-id"),
                    OsString::from(operation_id),
                ],
                None,
            )
            .await?;
        Ok(())
    }

    async fn mint_balance(&self, mint_url: &str) -> Result<CashuMintBalance> {
        self.run_json(
            &[
                OsString::from("internal"),
                OsString::from("balance"),
                OsString::from("--mint"),
                OsString::from(mint_url),
            ],
            None,
        )
        .await
    }
}

pub fn run_helper_status(helper_path: &Path, args: &[OsString]) -> Result<()> {
    let status = Command::new(helper_path)
        .args(args)
        .status()
        .with_context(|| format!("Failed to launch Cashu helper at {}", helper_path.display()))?;
    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => bail!("Cashu helper exited with status code {code}"),
        None => bail!("Cashu helper terminated by signal"),
    }
}

pub fn base_helper_args(data_dir: &Path) -> [OsString; 2] {
    [
        OsString::from("--data-dir"),
        data_dir.as_os_str().to_os_string(),
    ]
}

pub fn helper_binary_path(current_exe: &Path) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(CASHU_HELPER_ENV) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os(CARGO_HELPER_ENV) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os(LEGACY_CASHU_HELPER_ENV) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os(LEGACY_CARGO_HELPER_ENV) {
        return Ok(PathBuf::from(path));
    }

    let helper_name = helper_binary_name();
    let legacy_helper_name = legacy_helper_binary_name();
    let mut candidates = Vec::new();
    if let Some(parent) = current_exe.parent() {
        candidates.push(parent.join(helper_name));
        candidates.push(parent.join(legacy_helper_name));
        if let Some(grandparent) = parent.parent() {
            candidates.push(grandparent.join(helper_name));
            candidates.push(grandparent.join(legacy_helper_name));
        }
    }

    if let Some(path) = candidates.into_iter().find(|path| path.exists()) {
        return Ok(path);
    }

    bail!(
        "Cashu helper executable not found. Install `cashu-service-helper` next to the calling binary, or set {CASHU_HELPER_ENV}."
    )
}

pub fn helper_binary_name() -> &'static str {
    if cfg!(windows) {
        "cashu-service-helper.exe"
    } else {
        "cashu-service-helper"
    }
}

pub fn legacy_helper_binary_name() -> &'static str {
    if cfg!(windows) {
        "htree-cashu.exe"
    } else {
        "htree-cashu"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_helper_args_uses_data_dir() {
        let args = base_helper_args(Path::new("/tmp/cashu-service"));
        assert_eq!(args[0], OsString::from("--data-dir"));
        assert_eq!(args[1], OsString::from("/tmp/cashu-service"));
    }
}
