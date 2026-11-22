use super::*;
use crate::fips_private_mesh::tests::{
    available_udp_port, direct_udp_endpoint_config_many, wait_for_fips_peer,
};
use nostr_sdk::prelude::{Keys, ToBech32};
use nostr_vpn_core::fips_mesh::FipsMeshPeerConfig;

#[test]
fn credit_exit_two_private_peers_open_meter_and_settle() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(sale())
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
}
#[cfg(unix)]
async fn check_wallet_setup(dir: &Path) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let socket = dir.join("test-wallet.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let policy = LocalPolicy {
        receiving_rpc_socket: Some(socket),
        ..Default::default()
    };
    nostr_vpn_core::config::write_private_file_preserving_user_owner(
        &dir.join(POLICY),
        &serde_json::to_vec(&policy)?,
    )?;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            tokio::io::BufReader::new(read)
                .read_line(&mut line)
                .await
                .unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(req["method"], "getinfo");
            let key: Keypair = "07".repeat(32).parse().unwrap();
            let mut reply=json!({"id":req["id"],"jsonrpc":"2.0","result":{"network":"regtest","id":key.public_key().to_string()}}).to_string();
            reply.push_str("\n\n");
            write.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let wallet = execute(dir, Command::ConnectWallet).await?;
    ensure!(
        wallet["network"] == "regtest" && wallet["auto_cashout"].is_null(),
        "setup must be read-only"
    );
    let invalid = fips_credit_link::AutoCashout {
        min_sat: 21,
        max_sat: 0,
        max_fee_sat: 0,
        interval_secs: 60,
    };
    ensure!(
        execute(
            dir,
            Command::AutoCashout {
                policy: Some(invalid)
            }
        )
        .await
        .is_err(),
        "invalid automation accepted"
    );
    ensure!(
        load_policy(dir)?.auto_cashout.is_none(),
        "rejected settings were saved"
    );
    let auto = fips_credit_link::AutoCashout {
        min_sat: 21,
        max_sat: 30,
        max_fee_sat: 0,
        interval_secs: 60,
    };
    execute(
        dir,
        Command::AutoCashout {
            policy: Some(auto.clone()),
        },
    )
    .await?;
    ensure!(
        load_policy(dir)?.auto_cashout == Some(auto),
        "cash-out schedule was not persisted"
    );
    execute(dir, Command::AutoCashout { policy: None }).await?;
    ensure!(
        load_policy(dir)?.auto_cashout.is_none(),
        "cash-out schedule still active"
    );
    server.await?;
    Ok(())
}

async fn sale() -> Result<()> {
    let base = std::env::temp_dir().join(format!("nvpn-credit-test-{}", uuid::Uuid::new_v4()));
    let buyer_dir = base.join("buyer");
    let seller_dir = base.join("seller");
    std::fs::create_dir_all(&buyer_dir)?;
    std::fs::create_dir_all(&seller_dir)?;
    let buyer = Keys::generate();
    let seller = Keys::generate();
    let buyer_hex = buyer.public_key().to_hex();
    let seller_hex = seller.public_key().to_hex();
    let buyer_npub = buyer.public_key().to_bech32()?;
    let seller_npub = seller.public_key().to_bech32()?;
    let bn = buyer.secret_key().to_bech32()?;
    let sn = seller.secret_key().to_bech32()?;
    initialize(&buyer_dir, &bn, &[], 100, 10, None)?;
    initialize(
        &seller_dir,
        &sn,
        std::slice::from_ref(&buyer_hex),
        100,
        10,
        None,
    )?;
    let bp = available_udp_port();
    let sp = available_udp_port();
    let network = "private-credit-test";
    let expiry = 3600;
    let buyer_ip = tunnel_address(network, &buyer_hex)?;
    let seller_ip = tunnel_address(network, &seller_hex)?;
    ensure!(buyer_ip != seller_ip, "fixture address collision");
    let br = Arc::new(
        FipsPrivateMeshRuntime::bind_with_config_scoped(
            bn.clone(),
            Some(network.to_owned()),
            vec![FipsMeshPeerConfig {
                participant_pubkey: seller_hex.clone(),
                endpoint_npub: seller_npub.clone(),
                allowed_ips: vec!["0.0.0.0/0".into()],
            }],
            direct_udp_endpoint_config_many(bp, &[(&seller_npub, sp, true)]),
            vec![format!("{buyer_ip}/32")],
            vec![],
            vec![],
        )
        .await?,
    );
    let sr = Arc::new(
        FipsPrivateMeshRuntime::bind_with_config_scoped(
            sn.clone(),
            Some(network.to_owned()),
            vec![],
            direct_udp_endpoint_config_many(sp, &[(&buyer_npub, bp, false)]),
            vec!["0.0.0.0/0".into(), format!("{seller_ip}/32")],
            vec![],
            vec![],
        )
        .await?,
    );
    bind(&br, &buyer_dir, &bn, network).await?;
    bind(&sr, &seller_dir, &sn, network).await?;
    *sr.credit_policy.lock().unwrap() = Some(ExitPolicy {
        upstream_peer: None,
        network: network.into(),
        max_sat: 10,
        max_lifetime: expiry,
        price_msat_per_gb: 1000,
    });
    wait_for_fips_peer(&br, &seller_npub).await;
    wait_for_fips_peer(&sr, &buyer_npub).await;
    let buy = execute(
        &buyer_dir,
        Command::BuyExit {
            provider: seller_hex.clone(),
            bytes: 4096,
            price_msat_per_gb: 1000,
            max_amount_sat: 1,
            duration_secs: 60,
        },
    )
    .await?;
    ensure!(buy["state"] == "open", "purchase failed: {buy}");
    let id = buy["agreement_id"].as_str().unwrap();
    let IpAddr::V4(ip) = buyer_ip else {
        unreachable!()
    };
    let mut packet = vec![0u8; 64];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&64u16.to_be_bytes());
    packet[12..16].copy_from_slice(&ip.octets());
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    br.note_paid_route_outbound_packet(Some(&seller_hex), None, &packet)?;
    br.note_paid_route_outbound_packet(Some(&seller_hex), None, &packet)?; // one upload lost
    let source = fips_endpoint::PeerIdentity::from_npub(&buyer_npub)?;
    ensure!(
        sr.mesh
            .load()
            .receive_endpoint_data_owned_with_source_node_addr(
                source.node_addr().as_bytes(),
                packet
            )
            .is_some(),
        "upload refused"
    );
    let ack = execute(
        &buyer_dir,
        Command::SettleExit {
            agreement_id: id.into(),
        },
    )
    .await?;
    ensure!(
        ack["state"] == "settled" && ack["upload_bytes"] == 64,
        "incorrect final meter: {ack}"
    );
    ensure!(
        execute(&seller_dir, Command::Balance).await?["earned_credit_sat"] == 1,
        "missing earned credit"
    );
    ensure!(
        execute(
            &buyer_dir,
            Command::SettleExit {
                agreement_id: id.into()
            }
        )
        .await?["state"]
            == "settled",
        "receipt replay failed"
    );
    ensure!(
        execute(&seller_dir, Command::Balance).await?["earned_credit_sat"] == 1,
        "replay doubled credit"
    );
    #[cfg(unix)]
    check_wallet_setup(&seller_dir).await?;
    drop(br);
    drop(sr);
    std::fs::remove_dir_all(base)?;
    Ok(())
}
