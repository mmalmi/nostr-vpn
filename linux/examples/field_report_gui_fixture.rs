//! Prepare signed, unfunded offers for the desktop interaction regression.
use std::error::Error;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nostr_vpn_core::config::AppConfig;
use nostr_vpn_core::paid_route_store::{
    load_paid_route_store, paid_route_store_file_path, upsert_paid_route_offer,
};
use nostr_vpn_core::paid_routes::{signed_paid_exit_offer_from_config, PaidExitConfig};

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("expected fresh data directory")?,
    );
    std::fs::create_dir(&directory)?;
    let config_path = directory.join("config.toml");
    let mut buyer = AppConfig::generated_without_networks();
    buyer.add_owned_network("Desktop regression");
    buyer.node_name = "Desktop regression".into();
    buyer.node.endpoint = "198.51.100.10:51820".into();
    buyer.autoconnect = false;
    buyer.launch_on_startup = false;
    buyer.lan_discovery_enabled = false;
    buyer.fips_bootstrap_enabled = false;
    buyer.fips_nostr_discovery_enabled = false;
    buyer.wallet_fiat_enabled = false;
    buyer.save(&config_path)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let store_path = paid_route_store_file_path(&config_path);
    let mints = ["https://first-mint.invalid", "http://second-mint.invalid"];
    for (id, price) in [
        ("paid-desktop-regression", 25_000),
        ("free-desktop-regression", 0),
    ] {
        let seller = AppConfig::generated_without_networks();
        let mut settings = PaidExitConfig::default();
        settings.enabled = true;
        settings.pricing.price_msat_per_gb = price;
        settings.channel.accepted_mints = if price == 0 {
            Vec::new()
        } else {
            mints.iter().map(|value| (*value).to_string()).collect()
        };
        let signed =
            signed_paid_exit_offer_from_config(id, &seller.nostr_keys()?, &settings, None, now)?;
        upsert_paid_route_offer(&store_path, signed, Vec::new(), now)?;
    }
    let store = load_paid_route_store(&store_path)?;
    assert_eq!(store.offers.len(), 2);
    assert!(store.wallet.mints.is_empty());
    assert!(store.channels.is_empty() && store.sessions.is_empty());
    for record in store.offers.values() {
        record.signed_offer.verify()?;
        assert!(record.signed_offer.is_live_at(now));
    }
    println!(
        "{}",
        serde_json::json!({"signed_offers": 2, "mints": mints, "funded_channels": 0})
    );
    Ok(())
}
