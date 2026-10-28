#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows",
    target_os = "linux"
)))]
mod platform {
    use std::path::Path;

    use anyhow::Result;

    use super::{ConfigSecret, hydrate_config_secret_fields};

    pub(super) const REDACTED_SECRET_MARKER: &str = "stored-in-private-secret-file";

    pub(super) fn store_name() -> &'static str {
        "the platform secret store"
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

    pub(super) fn read_secret(_path: &Path, _kind: ConfigSecret) -> Result<Option<String>> {
        Ok(None)
    }

    pub(super) fn write_secret(_path: &Path, _kind: ConfigSecret, _value: &str) -> Result<()> {
        anyhow::bail!("platform secret storage is not available")
    }

    pub(super) fn delete_secret(_path: &Path, _kind: ConfigSecret) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_redacted_secret;
    use crate::config::AppConfig;
    use nostr_sdk::prelude::Keys;

    #[test]
    fn recognizes_all_secret_markers() {
        for marker in [
            "stored-in-ios-keychain",
            "stored-in-android-keystore",
            "stored-in-windows-dpapi",
            "stored-in-private-secret-file",
        ] {
            assert!(is_redacted_secret(marker));
        }
    }

    #[test]
    fn keychain_access_group_ignores_blank_values() {
        assert_eq!(
            super::normalize_keychain_access_group(Some(" team.bundle ")),
            Some("team.bundle")
        );
        assert_eq!(super::normalize_keychain_access_group(Some("   ")), None);
        assert_eq!(super::normalize_keychain_access_group(None), None);
    }

    #[test]
    fn selects_the_legacy_nostr_secret_matching_the_configured_identity() {
        let expected = Keys::generate();
        let unrelated = Keys::generate();
        let expected_secret = expected.secret_key().to_secret_hex();

        assert_eq!(
            super::select_nostr_secret_for_public_key(
                &expected.public_key().to_hex(),
                [unrelated.secret_key().to_secret_hex(), expected_secret.clone()],
            )
            .expect("select matching secret"),
            Some(expected_secret)
        );
    }

    #[test]
    fn unjoined_ios_config_adopts_the_identity_available_in_secure_storage() {
        let stored = Keys::generate();
        let stale = Keys::generate();
        let mut config = AppConfig::generated_without_networks();
        config.nostr.public_key = stale.public_key().to_hex();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending join request");

        assert!(super::adopt_stored_nostr_identity_for_unjoined_config(
            &mut config,
            &stored.public_key().to_hex(),
        ));
        assert_eq!(config.nostr.public_key, stored.public_key().to_hex());
        assert!(config.pending_nostr_join_request.is_none());
    }

    #[test]
    fn joined_ios_config_refuses_to_change_identity() {
        let stored = Keys::generate();
        let original_public_key = Keys::generate().public_key().to_hex();
        let mut config = AppConfig::generated();
        config.nostr.public_key.clone_from(&original_public_key);

        assert!(!super::adopt_stored_nostr_identity_for_unjoined_config(
            &mut config,
            &stored.public_key().to_hex(),
        ));
        assert_eq!(config.nostr.public_key, original_public_key);
    }

    #[cfg(feature = "cashu-wallet")]
    #[test]
    fn cashu_wallet_seed_decoder_requires_exact_64_bytes() {
        let seed = [42_u8; 64];
        assert_eq!(super::decode_cashu_wallet_seed(&hex::encode(seed)).unwrap(), seed);
        assert!(super::decode_cashu_wallet_seed(&hex::encode([42_u8; 63])).is_err());
        assert!(super::decode_cashu_wallet_seed("not hex").is_err());
    }
}
