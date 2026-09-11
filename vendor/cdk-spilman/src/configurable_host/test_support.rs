use super::*;

/// A deterministic secret key for tests (same as dev servers).
pub(super) const TEST_SECRET_KEY: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub(super) const TEST_YAML: &str = r#"
mints:
  "http://localhost:3338": [sat, msat, usd]
min_expiry_seconds: 3600

pricing:
  sat:
    min_capacity: 10
    variables:
      chars: 1
      requests: 5
  msat:
    min_capacity: 10000
    variables:
      chars: 1000
      requests: 5000
  usd:
    min_capacity: 10
    max_amount_per_output: 64
    variables:
      chars: 1
      requests: 5
"#;

pub(super) fn make_host() -> ConfigurableHost {
    ConfigurableHost::from_yaml(TEST_YAML, TEST_SECRET_KEY).unwrap()
}

/// Seed a channel with funding only (no balance, no usage).
pub(super) fn seed_channel(host: &ConfigurableHost, channel_id: &str, unit: &str) {
    let params_json = serde_json::json!({
        "unit": unit,
        "capacity": 1000,
    })
    .to_string();
    host.storage()
        .save_funding(
            channel_id,
            ChannelFunding {
                params_json,
                funding_proofs_json: "[]".to_string(),
                channel_secret_hex: "deadbeef".to_string(),
                keyset_info_json: "{}".to_string(),
            },
        )
        .unwrap();
}
