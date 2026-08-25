use anyhow::{bail, Context, Result};
use cdk::cdk_database::WalletDatabase;
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MeltQuoteState, MintQuoteState, PaymentMethod, Proof, State, Token};
use cdk::wallet::{types::ProofInfo, ReceiveOptions, WalletRepository};
use cdk::Amount;
use cdk_sqlite::WalletSqliteDatabase;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

use crate::helper::{CashuLightningPayment, CashuMintBalance, CashuReceivedPayment};

mod cross_mint;
pub use cross_mint::*;

mod persistence;
pub use persistence::*;

mod runtime;
pub use runtime::*;

mod send;
pub use send::send_payment_token;
#[cfg(test)]
use send::{proofs_require_keyset_consolidation, refresh_active_keyset_id};

pub const CASHU_WALLET_SEED_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CashuWalletSeedFile {
    pub version: u32,
    pub seed_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashuWalletEntry {
    pub mint_url: String,
    pub unit: String,
    pub balance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashuUnitTotal {
    pub unit: String,
    pub balance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CashuWalletOverview {
    pub totals: Vec<CashuUnitTotal>,
    pub entries: Vec<CashuWalletEntry>,
    pub warnings: Vec<String>,
    pub legacy_state_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashuTopupQuote {
    pub mint_url: String,
    pub unit: String,
    pub amount: u64,
    pub quote_id: String,
    pub payment_request: String,
    pub expiry_unix: u64,
}

const K_WALLET_ACTIVITY_PRIMARY_NAMESPACE: &str = "iris_wallet";
const K_WALLET_ACTIVITY_SECONDARY_NAMESPACE: &str = "activity";
const K_WALLET_ACTIVITY_KEY: &str = "entries";
const K_MAX_WALLET_ACTIVITY_ENTRIES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CashuWalletActivityKind {
    TopUp,
    LightningPayment,
    TokenSend,
    TokenReceive,
    ChannelCollect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CashuWalletActivityStatus {
    Pending,
    Complete,
    Reclaimed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CashuWalletActivityEntry {
    pub id: String,
    pub kind: CashuWalletActivityKind,
    pub status: CashuWalletActivityStatus,
    pub mint_url: String,
    pub unit: String,
    pub amount_sat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_sat: Option<u64>,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub fn cashu_wallet_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("cashu")
}

pub fn cashu_wallet_db_path(data_dir: &Path) -> PathBuf {
    cashu_wallet_dir(data_dir).join("wallet.sqlite")
}

pub fn cashu_wallet_seed_path(data_dir: &Path) -> PathBuf {
    cashu_wallet_dir(data_dir).join("seed.json")
}

pub fn legacy_cashu_wallet_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("cashu-wallet.json")
}

fn wallet_activity_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn wallet_activity_id() -> String {
    let mut suffix = [0_u8; 4];
    rand::thread_rng().fill_bytes(&mut suffix);
    format!("{}-{}", wallet_activity_now_unix(), hex::encode(suffix))
}

fn sort_wallet_activity_entries(entries: &mut Vec<CashuWalletActivityEntry>) {
    entries.sort_by(|left, right| {
        right
            .created_at_unix
            .cmp(&left.created_at_unix)
            .then_with(|| right.id.cmp(&left.id))
    });
    if entries.len() > K_MAX_WALLET_ACTIVITY_ENTRIES {
        entries.truncate(K_MAX_WALLET_ACTIVITY_ENTRIES);
    }
}

async fn load_wallet_activity_entries_from_store(
    localstore: &WalletSqliteDatabase,
) -> Result<Vec<CashuWalletActivityEntry>> {
    let stored = localstore
        .kv_read(
            K_WALLET_ACTIVITY_PRIMARY_NAMESPACE,
            K_WALLET_ACTIVITY_SECONDARY_NAMESPACE,
            K_WALLET_ACTIVITY_KEY,
        )
        .await
        .context("Failed to read Cashu wallet activity")?;
    let mut entries = match stored {
        Some(bytes) if !bytes.is_empty() => {
            serde_json::from_slice(&bytes).context("Failed to parse Cashu wallet activity")?
        }
        _ => Vec::new(),
    };
    sort_wallet_activity_entries(&mut entries);
    Ok(entries)
}

async fn save_wallet_activity_entries_to_store(
    localstore: &WalletSqliteDatabase,
    entries: &mut Vec<CashuWalletActivityEntry>,
) -> Result<()> {
    sort_wallet_activity_entries(entries);
    let encoded = serde_json::to_vec(entries).context("Failed to encode Cashu wallet activity")?;
    localstore
        .kv_write(
            K_WALLET_ACTIVITY_PRIMARY_NAMESPACE,
            K_WALLET_ACTIVITY_SECONDARY_NAMESPACE,
            K_WALLET_ACTIVITY_KEY,
            &encoded,
        )
        .await
        .context("Failed to write Cashu wallet activity")?;
    Ok(())
}

async fn append_wallet_activity_entry(
    localstore: &WalletSqliteDatabase,
    entry: CashuWalletActivityEntry,
) -> Result<()> {
    let mut entries = load_wallet_activity_entries_from_store(localstore).await?;
    entries.push(entry);
    save_wallet_activity_entries_to_store(localstore, &mut entries).await
}

async fn mark_wallet_activity_reclaimed(
    localstore: &WalletSqliteDatabase,
    operation_id: &str,
) -> Result<()> {
    let mut entries = load_wallet_activity_entries_from_store(localstore).await?;
    let mut changed = false;
    for entry in &mut entries {
        if entry.kind == CashuWalletActivityKind::TokenSend
            && entry.operation_id.as_deref() == Some(operation_id)
            && entry.status != CashuWalletActivityStatus::Reclaimed
        {
            entry.status = CashuWalletActivityStatus::Reclaimed;
            changed = true;
        }
    }
    if changed {
        save_wallet_activity_entries_to_store(localstore, &mut entries).await?;
    }
    Ok(())
}

pub async fn load_wallet_activity(data_dir: &Path) -> Result<Vec<CashuWalletActivityEntry>> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .load_wallet_activity()
        .await
}

impl CashuWalletService {
    pub async fn load_wallet_activity(&self) -> Result<Vec<CashuWalletActivityEntry>> {
        let _guard = self.lock_operation().await;
        let localstore = self.localstore().as_ref();
        let mut entries = load_wallet_activity_entries_from_store(localstore).await?;
        if entries.is_empty() {
            return Ok(entries);
        }

        let repository = self.repository();
        let mut wallets_by_mint = HashMap::new();
        let mut mint_quotes_by_id = HashMap::new();

        for wallet in repository.get_wallets().await {
            for quote in wallet
                .localstore
                .get_mint_quotes()
                .await
                .context("Failed to load Cashu mint quotes for activity")?
            {
                mint_quotes_by_id.insert(quote.id.clone(), quote);
            }
            wallets_by_mint.insert(wallet.mint_url.to_string(), wallet);
        }

        let now_unix = wallet_activity_now_unix();
        let mut changed = false;
        for entry in &mut entries {
            match entry.kind {
                CashuWalletActivityKind::TopUp => {
                    let next_status = if let Some(quote_id) = entry.quote_id.as_deref() {
                        match mint_quotes_by_id.get(quote_id) {
                            Some(quote)
                                if quote.state == MintQuoteState::Issued
                                    || quote.state == MintQuoteState::Paid =>
                            {
                                CashuWalletActivityStatus::Complete
                            }
                            Some(quote)
                                if quote.state == MintQuoteState::Unpaid
                                    && quote.expiry != 0
                                    && quote.expiry < now_unix =>
                            {
                                CashuWalletActivityStatus::Expired
                            }
                            Some(_) => CashuWalletActivityStatus::Pending,
                            None if entry
                                .expires_at_unix
                                .is_some_and(|expiry| expiry != 0 && expiry < now_unix) =>
                            {
                                CashuWalletActivityStatus::Expired
                            }
                            None => entry.status.clone(),
                        }
                    } else {
                        entry.status.clone()
                    };

                    if entry.status != next_status {
                        entry.status = next_status;
                        changed = true;
                    }
                }
                CashuWalletActivityKind::TokenSend
                    if entry.status == CashuWalletActivityStatus::Pending =>
                {
                    let Some(operation_id) = entry.operation_id.as_deref() else {
                        continue;
                    };
                    let Some(wallet) = wallets_by_mint.get(&entry.mint_url) else {
                        continue;
                    };
                    let Ok(operation_uuid) = Uuid::parse_str(operation_id) else {
                        continue;
                    };
                    let saga = wallet
                        .localstore
                        .get_saga(&operation_uuid)
                        .await
                        .context("Failed to load Cashu send saga for activity")?;
                    if saga.is_none() {
                        entry.status = CashuWalletActivityStatus::Complete;
                        changed = true;
                    }
                }
                _ => {}
            }
        }

        if changed {
            save_wallet_activity_entries_to_store(localstore, &mut entries).await?;
        }

        Ok(entries)
    }
}

pub fn normalize_mint_url(raw: &str) -> Result<String> {
    let mut url = Url::parse(raw).with_context(|| format!("Invalid mint URL: {raw}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => bail!("Unsupported mint URL scheme: {scheme}"),
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("Mint URL must not include query or fragment");
    }

    let trimmed_path = url.path().trim_end_matches('/').to_string();
    if trimmed_path.is_empty() {
        url.set_path("");
    } else {
        url.set_path(&trimmed_path);
    }

    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn read_wallet_seed(path: &Path) -> Result<[u8; 64]> {
    let content = fs::read_to_string(path).context("Failed to read Cashu wallet seed")?;
    let seed_file: CashuWalletSeedFile =
        serde_json::from_str(&content).context("Failed to parse Cashu wallet seed")?;
    let seed_bytes = hex::decode(seed_file.seed_hex).context("Invalid Cashu wallet seed")?;
    seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Cashu wallet seed must be 64 bytes"))
}

pub fn load_or_create_wallet_seed(path: &Path) -> Result<[u8; 64]> {
    if path.exists() {
        return read_wallet_seed(path);
    }

    let mut seed = [0_u8; 64];
    rand::thread_rng().fill_bytes(&mut seed);
    write_wallet_seed(path, &seed)?;
    Ok(seed)
}

pub async fn load_wallet_overview(
    data_dir: &Path,
    refresh_quotes: bool,
) -> Result<CashuWalletOverview> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .load_wallet_overview(refresh_quotes)
        .await
}

impl CashuWalletService {
    pub async fn load_wallet_overview(&self, refresh_quotes: bool) -> Result<CashuWalletOverview> {
        let _guard = self.lock_operation().await;
        let repository = self.repository();
        let mut warnings = Vec::new();

        if refresh_quotes {
            for wallet in repository.get_wallets().await {
                let mint_label = format!("{} ({})", wallet.mint_url, wallet.unit);
                if let Err(err) = wallet.recover_incomplete_sagas().await {
                    warnings.push(format!(
                        "Failed to recover wallet state for {mint_label}: {err}"
                    ));
                    continue;
                }
                if let Err(err) = wallet.mint_unissued_quotes().await {
                    warnings.push(format!(
                        "Failed to refresh pending mint quotes for {mint_label}: {err}"
                    ));
                }
            }
        }

        let totals = repository
            .total_balance()
            .await
            .context("Failed to load Cashu wallet totals")?
            .into_iter()
            .map(|(unit, amount)| CashuUnitTotal {
                unit: unit.to_string(),
                balance: amount.to_u64(),
            })
            .collect();

        let entries = repository
            .get_balances()
            .await
            .context("Failed to load Cashu wallet balances")?
            .into_iter()
            .map(|(key, amount)| CashuWalletEntry {
                mint_url: key.mint_url.to_string(),
                unit: key.unit.to_string(),
                balance: amount.to_u64(),
            })
            .collect();

        Ok(CashuWalletOverview {
            totals,
            entries,
            warnings,
            legacy_state_detected: legacy_cashu_wallet_state_path(self.data_dir()).exists(),
        })
    }
}

pub async fn create_topup_quote(
    data_dir: &Path,
    mint_url: &str,
    amount_sat: u64,
) -> Result<CashuTopupQuote> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .create_topup_quote(mint_url, amount_sat)
        .await
}

impl CashuWalletService {
    pub async fn create_topup_quote(
        &self,
        mint_url: &str,
        amount_sat: u64,
    ) -> Result<CashuTopupQuote> {
        if amount_sat == 0 {
            bail!("Cashu topup amount must be greater than zero");
        }

        let _guard = self.lock_operation().await;

        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;

        wallet
            .recover_incomplete_sagas()
            .await
            .context("Failed to recover Cashu wallet state before creating quote")?;
        wallet
            .mint_unissued_quotes()
            .await
            .context("Failed to refresh pending Cashu mint quotes before creating quote")?;

        let quote = wallet
            .mint_quote(
                PaymentMethod::BOLT11,
                Some(Amount::from(amount_sat)),
                None,
                None,
            )
            .await
            .context("Failed to create Cashu mint quote")?;

        let topup_quote = CashuTopupQuote {
            mint_url: normalized_mint,
            unit: CurrencyUnit::Sat.to_string(),
            amount: amount_sat,
            quote_id: quote.id,
            payment_request: quote.request,
            expiry_unix: quote.expiry,
        };

        append_wallet_activity_entry(
            self.localstore().as_ref(),
            CashuWalletActivityEntry {
                id: wallet_activity_id(),
                kind: CashuWalletActivityKind::TopUp,
                status: CashuWalletActivityStatus::Pending,
                mint_url: topup_quote.mint_url.clone(),
                unit: topup_quote.unit.clone(),
                amount_sat,
                fee_sat: None,
                created_at_unix: wallet_activity_now_unix(),
                expires_at_unix: Some(topup_quote.expiry_unix),
                quote_id: Some(topup_quote.quote_id.clone()),
                operation_id: None,
                payment_request: Some(topup_quote.payment_request.clone()),
                token: None,
            },
        )
        .await
        .context("Failed to record Cashu top-up activity")?;

        Ok(topup_quote)
    }
}

pub async fn load_mint_balance(data_dir: &Path, mint_url: &str) -> Result<CashuMintBalance> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .load_mint_balance(mint_url)
        .await
}

impl CashuWalletService {
    pub async fn load_mint_balance(&self, mint_url: &str) -> Result<CashuMintBalance> {
        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let _guard = self.lock_operation().await;
        ensure_sat_wallet(self.repository(), &mint_url).await?;

        let balance_sat = self
            .repository()
            .get_balances()
            .await
            .context("Failed to load Cashu wallet balances")?
            .into_iter()
            .find_map(|(key, amount)| {
                (key.mint_url == mint_url && key.unit == CurrencyUnit::Sat)
                    .then_some(amount.to_u64())
            })
            .unwrap_or_default();

        Ok(CashuMintBalance {
            mint_url: normalized_mint,
            unit: CurrencyUnit::Sat.to_string(),
            balance_sat,
        })
    }
}

pub async fn send_lightning_payment(
    data_dir: &Path,
    mint_url: &str,
    payment_request: &str,
) -> Result<CashuLightningPayment> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .send_lightning_payment(mint_url, payment_request)
        .await
}

impl CashuWalletService {
    pub async fn send_lightning_payment(
        &self,
        mint_url: &str,
        payment_request: &str,
    ) -> Result<CashuLightningPayment> {
        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let _guard = self.lock_operation().await;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;

        let mut payment = send_lightning_payment_with_wallet(&wallet, payment_request).await?;
        payment.mint_url = normalized_mint;
        append_wallet_activity_entry(
            self.localstore().as_ref(),
            CashuWalletActivityEntry {
                id: wallet_activity_id(),
                kind: CashuWalletActivityKind::LightningPayment,
                status: CashuWalletActivityStatus::Complete,
                mint_url: payment.mint_url.clone(),
                unit: payment.unit.clone(),
                amount_sat: payment.amount_sat,
                fee_sat: Some(payment.fee_paid_sat),
                created_at_unix: wallet_activity_now_unix(),
                expires_at_unix: None,
                quote_id: Some(payment.quote_id.clone()),
                operation_id: None,
                payment_request: Some(payment_request.to_string()),
                token: None,
            },
        )
        .await
        .context("Failed to record Cashu Lightning payment activity")?;
        Ok(payment)
    }
}

pub async fn receive_payment_token(
    data_dir: &Path,
    encoded_token: &str,
) -> Result<CashuReceivedPayment> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .receive_payment_token(encoded_token)
        .await
}

impl CashuWalletService {
    pub async fn receive_payment_token(&self, encoded_token: &str) -> Result<CashuReceivedPayment> {
        let token = Token::from_str(encoded_token).context("Failed to parse Cashu token")?;
        let mint_url = token
            .mint_url()
            .context("Cashu token must contain exactly one mint")?;
        let unit = token.unit().unwrap_or_default();
        if unit != CurrencyUnit::Sat {
            bail!("Unsupported Cashu token unit: {unit}");
        }
        let normalized_mint = normalize_mint_url(&mint_url.to_string())?;

        let _guard = self.lock_operation().await;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;
        wallet
            .recover_incomplete_sagas()
            .await
            .context("Failed to recover Cashu wallet state before receiving payment")?;

        let amount_received = wallet
            .receive(encoded_token, ReceiveOptions::default())
            .await
            .context("Failed to receive Cashu payment token")?;

        let payment = CashuReceivedPayment {
            mint_url: normalized_mint,
            unit: CurrencyUnit::Sat.to_string(),
            amount_sat: amount_received.to_u64(),
        };

        append_wallet_activity_entry(
            self.localstore().as_ref(),
            CashuWalletActivityEntry {
                id: wallet_activity_id(),
                kind: CashuWalletActivityKind::TokenReceive,
                status: CashuWalletActivityStatus::Complete,
                mint_url: payment.mint_url.clone(),
                unit: payment.unit.clone(),
                amount_sat: payment.amount_sat,
                fee_sat: None,
                created_at_unix: wallet_activity_now_unix(),
                expires_at_unix: None,
                quote_id: None,
                operation_id: None,
                payment_request: None,
                token: None,
            },
        )
        .await
        .context("Failed to record Cashu receive activity")?;

        Ok(payment)
    }
}

pub async fn import_payment_proofs(
    data_dir: &Path,
    mint_url: &str,
    unit: &str,
    proofs_json: &str,
) -> Result<CashuReceivedPayment> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .import_payment_proofs(mint_url, unit, proofs_json)
        .await
}

impl CashuWalletService {
    pub async fn import_payment_proofs(
        &self,
        mint_url: &str,
        unit: &str,
        proofs_json: &str,
    ) -> Result<CashuReceivedPayment> {
        let unit = unit.trim();
        if unit != CurrencyUnit::Sat.to_string() {
            bail!("Unsupported Cashu proof unit: {unit}");
        }

        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let proofs: Vec<Proof> =
            serde_json::from_str(proofs_json).context("Failed to parse Cashu payment proofs")?;

        let _guard = self.lock_operation().await;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;
        wallet
            .recover_incomplete_sagas()
            .await
            .context("Failed to recover Cashu wallet state before importing proofs")?;

        let mut proof_infos = Vec::with_capacity(proofs.len());
        for proof in proofs {
            proof_infos.push(
                ProofInfo::new(proof, mint_url.clone(), State::Unspent, CurrencyUnit::Sat)
                    .context("Failed to prepare Cashu proof import")?,
            );
        }

        let existing_ys = wallet
            .localstore
            .get_proofs_by_ys(proof_infos.iter().map(|proof| proof.y).collect())
            .await
            .context("Failed to check existing Cashu proofs")?
            .into_iter()
            .map(|proof| proof.y.to_string())
            .collect::<HashSet<_>>();

        let mut imported_amount_sat = 0_u64;
        let proof_infos = proof_infos
            .into_iter()
            .filter(|proof| !existing_ys.contains(&proof.y.to_string()))
            .inspect(|proof| {
                imported_amount_sat =
                    imported_amount_sat.saturating_add(proof.proof.amount.to_u64());
            })
            .collect::<Vec<_>>();

        if !proof_infos.is_empty() {
            wallet
                .localstore
                .update_proofs(proof_infos, vec![])
                .await
                .context("Failed to import Cashu proofs into wallet")?;

            append_wallet_activity_entry(
                self.localstore().as_ref(),
                CashuWalletActivityEntry {
                    id: wallet_activity_id(),
                    kind: CashuWalletActivityKind::ChannelCollect,
                    status: CashuWalletActivityStatus::Complete,
                    mint_url: normalized_mint.clone(),
                    unit: CurrencyUnit::Sat.to_string(),
                    amount_sat: imported_amount_sat,
                    fee_sat: None,
                    created_at_unix: wallet_activity_now_unix(),
                    expires_at_unix: None,
                    quote_id: None,
                    operation_id: None,
                    payment_request: None,
                    token: None,
                },
            )
            .await
            .context("Failed to record Cashu channel collection activity")?;
        }

        Ok(CashuReceivedPayment {
            mint_url: normalized_mint,
            unit: CurrencyUnit::Sat.to_string(),
            amount_sat: imported_amount_sat,
        })
    }
}

pub async fn revoke_pending_payment(
    data_dir: &Path,
    mint_url: &str,
    operation_id: &str,
) -> Result<u64> {
    CashuWalletService::open_file_backed(data_dir)
        .await?
        .revoke_pending_payment(mint_url, operation_id)
        .await
}

impl CashuWalletService {
    pub async fn revoke_pending_payment(&self, mint_url: &str, operation_id: &str) -> Result<u64> {
        let normalized_mint = normalize_mint_url(mint_url)?;
        let mint_url =
            MintUrl::from_str(&normalized_mint).context("Failed to parse normalized mint URL")?;
        let _guard = self.lock_operation().await;
        let wallet = ensure_sat_wallet(self.repository(), &mint_url).await?;
        wallet
            .recover_incomplete_sagas()
            .await
            .context("Failed to recover Cashu wallet state before revoking payment")?;

        let normalized_operation_id = operation_id.to_string();
        let operation_id = normalized_operation_id
            .parse()
            .context("Invalid Cashu send operation id")?;
        let amount = wallet
            .revoke_send(operation_id)
            .await
            .context("Failed to revoke Cashu payment token")?;
        mark_wallet_activity_reclaimed(self.localstore().as_ref(), &normalized_operation_id)
            .await
            .context("Failed to record reclaimed Cashu token")?;
        Ok(amount.to_u64())
    }
}

fn write_wallet_seed(path: &Path, seed: &[u8; 64]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create Cashu wallet directory")?;
    }

    let seed_file = CashuWalletSeedFile {
        version: CASHU_WALLET_SEED_VERSION,
        seed_hex: hex::encode(seed),
    };
    let content =
        serde_json::to_string_pretty(&seed_file).context("Failed to encode Cashu wallet seed")?;
    fs::write(path, content).context("Failed to write Cashu wallet seed")?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .context("Failed to secure Cashu wallet seed permissions")?;
    }
    Ok(())
}

async fn ensure_sat_wallet(
    repository: &WalletRepository,
    mint_url: &MintUrl,
) -> Result<cdk::wallet::Wallet> {
    let wallet = if repository.has_wallet(mint_url, &CurrencyUnit::Sat).await {
        repository
            .get_wallet(mint_url, &CurrencyUnit::Sat)
            .await
            .context("Failed to load existing Cashu sat wallet")?
    } else {
        repository
            .create_wallet(mint_url.clone(), CurrencyUnit::Sat, None)
            .await
            .context("Failed to create Cashu sat wallet")?
    };

    wallet
        .localstore
        .add_mint(mint_url.clone(), None)
        .await
        .context("Failed to persist Cashu mint metadata")?;

    Ok(wallet)
}

async fn send_lightning_payment_with_wallet(
    wallet: &cdk::wallet::Wallet,
    payment_request: &str,
) -> Result<CashuLightningPayment> {
    wallet
        .recover_incomplete_sagas()
        .await
        .context("Failed to recover Cashu wallet state before sending Lightning payment")?;

    let quote = wallet
        .melt_quote(PaymentMethod::BOLT11, payment_request, None, None)
        .await
        .context("Failed to create Cashu Lightning melt quote")?;
    let prepared = wallet
        .prepare_melt(&quote.id, HashMap::new())
        .await
        .context("Failed to prepare Cashu Lightning payment")?;
    let finalized = prepared
        .confirm()
        .await
        .context("Failed to execute Cashu Lightning payment")?;

    if finalized.state() != MeltQuoteState::Paid {
        bail!(
            "Cashu Lightning payment finished in unexpected state {}",
            finalized.state()
        );
    }

    let preimage = finalized
        .payment_proof()
        .filter(|proof| !proof.is_empty())
        .map(str::to_owned)
        .context("Cashu Lightning payment completed without a preimage")?;

    Ok(CashuLightningPayment {
        mint_url: wallet.mint_url.to_string(),
        unit: wallet.unit.to_string(),
        amount_sat: finalized.amount().to_u64(),
        fee_paid_sat: finalized.fee_paid().to_u64(),
        quote_id: finalized.quote_id().to_string(),
        preimage,
    })
}

#[cfg(test)]
mod tests;
