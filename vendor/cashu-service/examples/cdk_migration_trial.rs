//! Cross-version trial. Build this against the baseline and candidate separately.
//! The baseline hosts a loopback mint with simulated Lightning and invokes the
//! candidate against temporary, synthetic wallet and channel files only.
use anyhow::{ensure, Context, Result};
use cashu_service::{simulation::*, *};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
struct Fixture {
    request: StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    channel: StreamingRouteOpenCashuSpilmanChannelResult,
    pending_operation: String,
    available: u64,
}

fn migrations(data_dir: &Path) -> Result<Vec<String>> {
    let connection = rusqlite::Connection::open_with_flags(
        cashu_wallet_db_path(data_dir),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut query = connection.prepare("SELECT name FROM migrations ORDER BY name")?;
    let rows = query.query_map([], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), destination.join(entry.file_name()))?;
        }
    }
    Ok(())
}

async fn host(candidate: &Path) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let network = PaymentNetwork::new(42, 0, Arc::new(VirtualClock::new(now)));
    let mint =
        LocalMint::start(root, network.clone(), "migration", IssuerMode::Withdrawable).await?;
    let buyer = root.join("buyer");
    let seller = root.join("seller");
    let quote = create_topup_quote(&buyer, mint.url(), 256).await?;
    network
        .orchestrator_funding()
        .settle_external(&quote.payment_request)?;
    let wallet = CashuWalletService::open_file_backed(&buyer).await?;
    let overview = wallet.load_wallet_overview(true).await?;
    ensure!(
        overview.warnings.is_empty(),
        "funding warnings: {:?}",
        overview.warnings
    );
    ensure!(wallet.load_mint_balance(mint.url()).await?.balance_sat == 256);
    let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
        &seller,
        FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let request = StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
        mint_url: mint.url().to_string(),
        receiver_pubkey_hex: receiver.receiver_pubkey_hex().to_string(),
        capacity_sat: 64,
        expiry_unix: now + 3600,
        max_amount_per_output: 0,
        unit: "sat".into(),
        opening_paid_msat: 0,
        keyset_id: None,
        keyset_info_json: None,
        client_request_id: Some("migration-existing-channel".into()),
        route_created_at_unix: Some(now),
    };
    let opened = wallet
        .open_streaming_route_cashu_spilman_channel(request.clone())
        .await?;
    receiver
        .process_cashu_spilman_payment(&opened.channel.payment, &"migration".into())
        .map_err(anyhow::Error::msg)?;
    let pending = wallet.send_payment_token(mint.url(), 16).await?;
    let fixture = Fixture {
        request,
        channel: opened.channel,
        pending_operation: pending.operation_id,
        available: wallet.load_mint_balance(mint.url()).await?.balance_sat,
    };
    ensure!(
        fixture.available == 176,
        "unexpected baseline balance {}",
        fixture.available
    );
    drop(wallet);
    drop(receiver);
    std::fs::write(root.join("fixture.json"), serde_json::to_vec(&fixture)?)?;
    copy_tree(&buyer, &root.join("backup"))?;
    println!("BASELINE: 256 synthetic sat; 64 in channel; 16 pending; 176 available");
    let status = Command::new(candidate).arg("upgrade").arg(root).status()?;
    ensure!(status.success(), "candidate failed: {status}");
    // The candidate has exited, so every SQLite writer is closed before copying.
    copy_tree(&buyer, &root.join("migrated-copy"))?;
    let old = std::env::current_exe()?;
    let migrated = Command::new(&old)
        .arg("probe")
        .arg(root.join("migrated-copy"))
        .status()?;
    println!("OLD_BINARY_REOPEN_MIGRATED: {migrated}");
    let backup = Command::new(&old)
        .arg("probe")
        .arg(root.join("backup"))
        .status()?;
    ensure!(
        backup.success(),
        "old binary could not open untouched pre-upgrade backup"
    );
    println!("BACKUP: old binary reopened untouched pre-upgrade snapshot; do not spend it after candidate operations");
    ensure!(network.accounting()?.is_conserved());
    Ok(())
}

async fn upgrade(root: &Path) -> Result<()> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(root.join("fixture.json"))?)?;
    let buyer = root.join("buyer");
    let seller = root.join("seller");
    let mint = &fixture.request.mint_url;
    let before = migrations(&buyer)?;
    let wallet = CashuWalletService::open_file_backed(&buyer).await?;
    let after = migrations(&buyer)?;
    let applied: Vec<_> = after.iter().filter(|name| !before.contains(name)).collect();
    println!(
        "SCHEMA: {} -> {} migrations; applied {applied:?}",
        before.len(),
        after.len()
    );
    ensure!(wallet.load_mint_balance(mint).await?.balance_sat == fixture.available);
    let recovered = recover_streaming_route_cashu_spilman_channel_from_wallet_request(
        &buyer,
        &fixture.request,
    )?
    .context("existing channel missing after migration")?;
    ensure!(
        recovered == fixture.channel,
        "persisted channel identity or funding changed"
    );
    let failed = wallet.send_payment_token(mint, 257).await;
    ensure!(
        failed.is_err(),
        "oversized preparation unexpectedly succeeded"
    );
    ensure!(wallet.load_mint_balance(mint).await?.balance_sat == fixture.available);
    ensure!(
        wallet
            .revoke_pending_payment(mint, &fixture.pending_operation)
            .await?
            == 16
    );
    ensure!(wallet.load_mint_balance(mint).await?.balance_sat == 192);
    let signer = FileSpilmanPaymentSigner::load(&buyer).map_err(anyhow::Error::msg)?;
    let payment = signer
        .sign_cashu_spilman_payment(&fixture.channel.channel_id, 20, false)
        .map_err(anyhow::Error::msg)?;
    drop(signer);
    let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
        &seller,
        FileSpilmanPaymentReceiverConfig::new([mint.to_string()]),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    receiver
        .process_cashu_spilman_payment(&payment, &"migration".into())
        .map_err(anyhow::Error::msg)?;
    let closed = receiver
        .close_cashu_spilman_channel(&fixture.channel.channel_id)
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        closed.receiver_sum == 20 && closed.sender_sum == 44,
        "unexpected close split"
    );
    import_payment_proofs(&seller, mint, "sat", &closed.receiver_proofs_json).await?;
    drop(wallet);
    let refund =
        restore_streaming_route_cashu_spilman_refund(&buyer, &fixture.channel.channel_id).await?;
    ensure!(
        refund.complete && refund.imported_amount_sat == 44,
        "unexpected refund: {refund:?}"
    );
    let retry =
        restore_streaming_route_cashu_spilman_refund(&buyer, &fixture.channel.channel_id).await?;
    ensure!(retry.complete && retry.imported_amount_sat == 0);
    ensure!(load_mint_balance(&buyer, mint).await?.balance_sat == 236);
    ensure!(load_mint_balance(&seller, mint).await?.balance_sat == 20);
    println!("CANDIDATE: identity/funding unchanged; failed prepare unchanged; pending 16 reclaimed; paid/closed 20; refund 44 exactly once; balances 236 + 20 = 256");
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args
        .get(1)
        .context("expected host, upgrade or probe")?
        .to_string_lossy();
    let path = Path::new(
        args.get(2)
            .context("expected candidate executable or fixture directory")?,
    );
    match mode.as_ref() {
        "host" => host(path).await,
        "upgrade" => upgrade(path).await,
        "probe" => {
            let wallet = CashuWalletService::open_file_backed(path).await?;
            let overview = wallet.load_wallet_overview(false).await?;
            println!(
                "PROBE: opened; total available = {}",
                overview.totals.iter().map(|v| v.balance).sum::<u64>()
            );
            Ok(())
        }
        _ => anyhow::bail!("expected host, upgrade or probe"),
    }
}
