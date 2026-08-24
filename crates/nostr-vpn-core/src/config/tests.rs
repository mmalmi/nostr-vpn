#[cfg(test)]
mod tests {
    use super::{
        AdminSignedSharedRosterUpdate, AppConfig, CLOUDFLARE_DOH_URL, ExitDnsConfig,
        ExitDnsMode, ExitDnsResolverConfig, ExitDohProvider, InternetSource,
        PaidExitSellerEgress, PendingOutboundJoinRequest, QUAD9_DOH_URL, WireGuardExitConfig,
        effective_fips_nostr_relays, normalize_nostr_pubkey, npub_for_pubkey_hex,
        parse_wireguard_exit_config, split_peer_transport_addr, wireguard_exit_config_text,
    };
    use crate::config_defaults::generate_nostr_identity;

    const TEST_WG_PRIVATE_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TEST_WG_PUBLIC_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const TEST_WG_PRESHARED_KEY: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("nvpn-{name}-{}-{nonce}", std::process::id()))
    }

    fn temp_config_dir(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = temp_path(name);
        std::fs::create_dir_all(&dir).expect("create config directory");
        let path = dir.join("config.toml");
        (dir, path)
    }

    #[test]
    fn split_peer_transport_addr_preserves_webrtc_transport() {
        let route = format!("webrtc:02{}", "ab".repeat(32));

        assert_eq!(
            split_peer_transport_addr(&route),
            ("webrtc".to_string(), format!("02{}", "ab".repeat(32)))
        );
    }

    #[test]
    fn split_peer_transport_addr_preserves_websocket_transport() {
        assert_eq!(
            split_peer_transport_addr("websocket:wss://seed.example/fips"),
            ("websocket".to_string(), "wss://seed.example/fips".to_string())
        );
    }

    #[test]
    fn generated_native_config_uses_identity_pinned_public_udp_seeds() {
        let config = AppConfig::generated_without_networks();

        assert!(config.fips_bootstrap_enabled);
        assert_eq!(config.fips_bootstrap_peers.len(), 2);
        assert!(config.fips_websocket_seed_urls.is_empty());
        assert_eq!(
            config
                .fips_bootstrap_peers
                .get("npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd"),
            Some(&vec![
                "fips1.iris.to:51820".to_string(),
                "websocket:wss://fips1.iris.to/fips".to_string(),
            ])
        );
        assert_eq!(
            config
                .fips_bootstrap_peers
                .get("npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh"),
            Some(&vec![
                "fips2.iris.to:51820".to_string(),
                "websocket:wss://fips2.iris.to/fips".to_string(),
            ])
        );
        assert!(config
            .fips_bootstrap_peers
            .values()
            .all(|addresses| {
                addresses.len() == 2
                    && !addresses[0].contains("://")
                    && addresses[1].starts_with("websocket:wss://")
            }));
    }

    #[test]
    fn existing_custom_bootstraps_gain_missing_public_udp_with_websocket_fallback_seeds() {
        let mut config = AppConfig::generated_without_networks();
        let (_, custom_npub) = generate_nostr_identity();
        config.fips_bootstrap_peers = std::collections::HashMap::from([(
            custom_npub.clone(),
            vec!["203.0.113.9:51820".to_string()],
        )]);

        config.ensure_defaults();

        assert_eq!(config.fips_bootstrap_peers.len(), 3);
        assert_eq!(
            config.fips_bootstrap_peers.get(&custom_npub),
            Some(&vec!["203.0.113.9:51820".to_string()])
        );
        assert!(config.fips_bootstrap_peers.contains_key(
            "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd"
        ));
        assert!(config.fips_bootstrap_peers.contains_key(
            "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh"
        ));
    }

    #[test]
    fn legacy_public_websocket_bootstraps_migrate_to_native_udp() {
        let mut config = AppConfig::generated_without_networks();
        config.fips_websocket_seed_urls = vec![
            "wss://fips1.iris.to/fips".to_string(),
            "wss://fips2.iris.to/fips".to_string(),
        ];
        config.fips_bootstrap_peers = std::collections::HashMap::from([
            (
                "npub1927ye6w57stma7yntatltdphes2fugdn8ktqdmp72225crrvgwqq4p7rkd"
                    .to_string(),
                vec!["websocket:wss://fips1.iris.to/fips".to_string()],
            ),
            (
                "npub1zv3qmj7xz7znehyqwzpc26fcjxtcf7tpxeevxx93ymgm6kw7gjpqp9npvh"
                    .to_string(),
                vec!["websocket:wss://fips2.iris.to/fips".to_string()],
            ),
        ]);

        config.ensure_defaults();

        assert_eq!(
            config.fips_bootstrap_peers,
            super::default_fips_bootstrap_peers()
        );
        assert!(config.fips_websocket_seed_urls.is_empty());
    }

    #[test]
    fn bootstrap_editor_preserves_valid_wss_identity_pins_and_rejects_remote_ws() {
        let mut config = AppConfig::generated_without_networks();
        let (_, seed_npub) = generate_nostr_identity();

        config.set_fips_bootstrap_peers(std::collections::HashMap::from([(
            seed_npub.clone(),
            vec![
                "websocket:wss://seed.example/fips".to_string(),
                "websocket:ws://seed.example/fips".to_string(),
            ],
        )]));

        assert_eq!(
            config.fips_bootstrap_peers.get(&seed_npub),
            Some(&vec![
                "websocket:wss://seed.example/fips".to_string()
            ])
        );
    }

    #[test]
    fn bootstrap_endpoints_never_include_own_identity() {
        let mut config = AppConfig::generated_without_networks();
        let own_npub = npub_for_pubkey_hex(
            &config
                .own_nostr_pubkey_hex()
                .expect("generated identity public key"),
        );
        config
            .fips_bootstrap_peers
            .insert(own_npub.clone(), vec!["127.0.0.1:51820".to_string()]);

        let endpoints = config.fips_bootstrap_peer_endpoints();

        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().all(|(npub, _)| npub != &own_npub));
    }

    #[test]
    fn websocket_seed_urls_are_trimmed_deduplicated_and_preserved_as_multiple_seeds() {
        let mut config = AppConfig::generated();
        config.fips_websocket_seed_urls = vec![
            " wss://seed-b.example/fips ".to_string(),
            "wss://seed-a.example/fips\nwss://seed-b.example/fips".to_string(),
        ];

        config.ensure_defaults();

        assert_eq!(
            config.fips_websocket_seed_urls,
            [
                "wss://seed-a.example/fips",
                "wss://seed-b.example/fips"
            ]
        );
    }

    #[test]
    fn empty_application_relay_list_uses_fips_discovery_defaults() {
        let relays = effective_fips_nostr_relays(&[]);

        assert!(!relays.is_empty());
        assert_eq!(
            effective_fips_nostr_relays(&["  wss://relay.example  ".to_string()]),
            vec!["wss://relay.example"]
        );
    }

    #[test]
    fn successful_roster_join_rotates_the_device_approval_request() {
        let mut config = AppConfig::generated_without_networks();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending link request");
        let prior_request_pubkey = config
            .pending_nostr_join_request
            .as_ref()
            .expect("pending link request")
            .request
            .request_pubkey
            .clone();
        let own_pubkey = config.own_nostr_pubkey_hex().expect("own pubkey");
        let (_, admin_npub) = generate_nostr_identity();
        let admin_pubkey = normalize_nostr_pubkey(&admin_npub).expect("admin pubkey");
        let network_entry_id = config.add_network("Home");
        let network = config
            .network_by_id_mut(&network_entry_id)
            .expect("imported network");
        network.enabled = true;
        network.network_id = "8d4f34f5425bc50e".to_string();
        network.admins = vec![admin_pubkey.clone()];
        network.outbound_join_request = Some(PendingOutboundJoinRequest {
            recipient: admin_pubkey.clone(),
            requested_at: 1_778_998_001,
        });
        assert!(
            !config.active_network_has_confirmed_local_identity(),
            "an automatic join must remain pending until its signed roster arrives"
        );

        assert!(
            config
                .apply_admin_signed_shared_roster(AdminSignedSharedRosterUpdate {
                    network_id: "8d4f34f5425bc50e".to_string(),
                    network_name: "Home".to_string(),
                    devices: vec![own_pubkey],
                    admins: vec![admin_pubkey.clone()],
                    aliases: Default::default(),
                    signed_at: 1_778_998_002,
                    signed_by: admin_pubkey,
                })
                .expect("apply accepted roster")
        );

        assert_ne!(
            config
                .pending_nostr_join_request
                .as_ref()
                .expect("rotated device approval request")
                .request
                .request_pubkey,
            prior_request_pubkey
        );
        assert!(config.active_network().outbound_join_request.is_none());
    }

    #[test]
    fn invalid_legacy_device_approval_request_is_rotated() {
        let mut config = AppConfig::generated_without_networks();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending link request");
        let prior_request_pubkey = config
            .pending_nostr_join_request
            .as_ref()
            .expect("pending link request")
            .request
            .request_pubkey
            .clone();
        config
            .pending_nostr_join_request
            .as_mut()
            .expect("pending link request")
            .version = 0;

        assert!(
            config
                .ensure_pending_nostr_join_request(1_778_998_100)
                .expect("rotate invalid request")
        );
        let pending = config
            .pending_nostr_join_request
            .as_ref()
            .expect("replacement approval request");
        assert_ne!(pending.request.request_pubkey, prior_request_pubkey);
        pending
            .validate_for_device(&config.own_nostr_pubkey_hex().expect("own pubkey"))
            .expect("replacement request is valid");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn loading_a_legacy_device_approval_allows_startup_to_rotate_it() {
        let (dir, path) = temp_config_dir("load-legacy-device-approval");
        let mut config = AppConfig::generated_without_networks();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending link request");
        config
            .pending_nostr_join_request
            .as_mut()
            .expect("pending link request")
            .version = 0;
        std::fs::write(
            &path,
            config.plaintext_toml().expect("encode legacy config"),
        )
        .expect("write legacy config");

        let mut loaded = AppConfig::load(&path).expect("load recoverable legacy config");
        assert!(loaded.pending_nostr_join_request.is_none());
        assert!(
            loaded
                .ensure_pending_nostr_join_request(1_778_998_100)
                .expect("rotate legacy approval during startup")
        );
        loaded
            .pending_nostr_join_request
            .as_ref()
            .expect("replacement approval request")
            .validate_for_device(&loaded.own_nostr_pubkey_hex().expect("own pubkey"))
            .expect("replacement request is valid");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn clearing_join_request_deletes_its_persisted_secret() {
        let (dir, path) = temp_config_dir("cleared-join-request-secret");
        let mut config = AppConfig::generated_without_networks();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending request");

        config.save(&path).expect("persist pending request");
        let pending_config = std::fs::read_to_string(&path).expect("read pending config");
        assert!(pending_config.contains("pending_nostr_join_request"));

        config.clear_pending_nostr_join_request();
        config.save(&path).expect("persist completed join");

        let raw = std::fs::read_to_string(&path).expect("read completed config");
        assert!(!raw.contains("pending_nostr_join_request"));
        std::fs::write(&path, pending_config).expect("restore stale public request metadata");
        let error = AppConfig::load(&path)
            .expect_err("cleared request secret must not be recoverable")
            .to_string();
        assert!(error.contains("no matching secret exists"), "{error}");
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete persisted secrets");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn desktop_unix_never_persists_ephemeral_join_request_material() {
        let (dir, path) = temp_config_dir("ephemeral-join-request");
        let mut config = AppConfig::generated_without_networks();
        config
            .ensure_pending_nostr_join_request(1_778_998_000)
            .expect("pending request");
        let pending = config
            .pending_nostr_join_request
            .as_ref()
            .expect("in-memory request")
            .clone();

        config.save(&path).expect("save config");

        let raw = std::fs::read_to_string(&path).expect("read config");
        assert!(!raw.contains("pending_nostr_join_request"));
        assert!(!raw.contains(&pending.request.request_secret));
        assert!(!raw.contains(&pending.request_private_key));
        let loaded = AppConfig::load(&path).expect("reload config");
        assert!(loaded.pending_nostr_join_request.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn plaintext_toml_preserves_config_secrets() {
        let mut config = AppConfig::generated();
        config.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.to_string();
        config.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.to_string();
        config.wireguard_exit.peer_preshared_key = TEST_WG_PRESHARED_KEY.to_string();

        let raw = config.plaintext_toml().expect("encode plaintext config");

        assert!(raw.contains(&config.nostr.secret_key));
        assert!(raw.contains(TEST_WG_PRIVATE_KEY));
        assert!(raw.contains(TEST_WG_PRESHARED_KEY));
    }

    #[test]
    fn save_plaintext_does_not_write_config_secrets_inline() {
        let path = temp_path("save-plaintext").with_extension("toml");
        let mut config = AppConfig::generated();
        config.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.to_string();
        config.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.to_string();
        config.wireguard_exit.peer_preshared_key = TEST_WG_PRESHARED_KEY.to_string();

        config.save_plaintext(&path).expect("save plaintext config");
        let raw = std::fs::read_to_string(&path).expect("read plaintext config");
        let loaded = AppConfig::load(&path).expect("load protected config");

        assert!(!raw.contains(&config.nostr.secret_key));
        assert!(!raw.contains(TEST_WG_PRIVATE_KEY));
        assert!(!raw.contains(TEST_WG_PRESHARED_KEY));
        #[cfg(target_os = "macos")]
        {
            assert!(raw.contains("stored-in-private-secret-file"));
            let file_name = path.file_name().and_then(|value| value.to_str()).unwrap();
            let parent = path.parent().unwrap();
            assert!(
                parent
                    .join(format!(".{file_name}.nostr-secret-key.secret"))
                    .exists()
            );
            assert!(
                parent
                    .join(format!(".{file_name}.wireguard-exit-private-key.secret"))
                    .exists()
            );
            assert!(
                parent
                    .join(format!(
                        ".{file_name}.wireguard-exit-peer-preshared-key.secret"
                    ))
                    .exists()
            );
        }
        assert_eq!(loaded.nostr.secret_key, config.nostr.secret_key);
        assert_eq!(loaded.wireguard_exit.private_key, TEST_WG_PRIVATE_KEY);
        assert_eq!(
            loaded.wireguard_exit.peer_preshared_key,
            TEST_WG_PRESHARED_KEY
        );
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete persisted secrets");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn save_plaintext_rejects_symlinked_secret_sidecar() {
        use std::os::unix::fs::symlink;

        let (dir, path) = temp_config_dir("secret-sidecar-symlink");
        let target = dir.join("target-secret");
        let sidecar = dir.join(".config.toml.nostr-secret-key.secret");
        std::fs::write(&target, "do-not-overwrite").expect("write target");
        symlink(&target, &sidecar).expect("create secret sidecar symlink");

        let error = AppConfig::generated()
            .save_plaintext(&path)
            .expect_err("symlinked secret sidecar should be rejected");

        assert!(error.to_string().contains("failed to store Nostr secret key"));
        assert_eq!(
            std::fs::read_to_string(&target).expect("read target"),
            "do-not-overwrite"
        );
        assert!(
            std::fs::symlink_metadata(&sidecar)
                .expect("sidecar metadata")
                .file_type()
                .is_symlink()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_persisted_secrets_rewrites_plaintext_config_secrets() {
        let path = temp_path("migrate-secrets").with_extension("toml");
        let mut config = AppConfig::generated();
        config.wireguard_exit.private_key = TEST_WG_PRIVATE_KEY.to_string();
        config.wireguard_exit.peer_public_key = TEST_WG_PUBLIC_KEY.to_string();
        config.wireguard_exit.peer_preshared_key = TEST_WG_PRESHARED_KEY.to_string();
        let nostr_secret = config.nostr.secret_key.clone();
        let raw = config.plaintext_toml().expect("encode plaintext config");
        std::fs::write(&path, raw).expect("write plaintext config");

        assert!(
            AppConfig::config_file_needs_secret_migration(&path).expect("inspect plaintext config")
        );
        assert!(AppConfig::migrate_persisted_secrets(&path).expect("migrate secrets"));
        assert!(
            !AppConfig::config_file_needs_secret_migration(&path).expect("inspect migrated config")
        );
        let migrated = std::fs::read_to_string(&path).expect("read migrated config");
        let loaded = AppConfig::load(&path).expect("load migrated config");
        AppConfig::delete_persisted_secrets_for_path(&path).expect("delete migrated secrets");
        let _ = std::fs::remove_file(&path);

        assert!(!migrated.contains(&nostr_secret));
        assert!(!migrated.contains(TEST_WG_PRIVATE_KEY));
        assert!(!migrated.contains(TEST_WG_PRESHARED_KEY));
        assert!(migrated.contains("stored-in-"));
        assert_eq!(loaded.nostr.secret_key, nostr_secret);
        assert_eq!(loaded.wireguard_exit.private_key, TEST_WG_PRIVATE_KEY);
        assert_eq!(
            loaded.wireguard_exit.peer_preshared_key,
            TEST_WG_PRESHARED_KEY
        );
    }

    #[test]
    fn minimal_seeded_config_does_not_need_secret_migration() {
        let path = temp_path("seeded-config-no-secret-migration").with_extension("toml");
        std::fs::write(&path, "node_name = \"iPhone\"\n").expect("write seeded config");

        assert!(
            !AppConfig::config_file_needs_secret_migration(&path)
                .expect("inspect seeded config")
        );
        assert!(
            !AppConfig::migrate_persisted_secrets(&path).expect("migration should be skipped")
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read seeded config"),
            "node_name = \"iPhone\"\n"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn load_rejects_mismatched_nostr_secret_sidecar() {
        let (dir, path) = temp_config_dir("mismatched-nostr-secret");
        let sidecar = dir.join(".config.toml.nostr-secret-key.secret");
        let config = AppConfig::generated();
        let (wrong_secret, _) = generate_nostr_identity();

        config.save_plaintext(&path).expect("save protected config");
        std::fs::write(&sidecar, wrong_secret).expect("replace sidecar secret");

        let error = AppConfig::load(&path).expect_err("mismatched sidecar should fail");

        assert!(
            error
                .to_string()
                .contains("mismatched Nostr identity"),
            "{error}"
        );
        let _ = AppConfig::delete_persisted_secrets_for_path(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_rejects_unsupported_secret_markers() {
        let path = temp_path("unsupported-secret-marker").with_extension("toml");
        let mut config = AppConfig::generated();
        config.nostr.secret_key = "stored-in-macos-keychain".to_string();

        let error = config.save(&path).expect_err("unsupported marker fails");

        assert!(
            error
                .to_string()
                .contains("unsupported secret storage marker")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ensure_defaults_keeps_existing_public_identity_without_parsing_secret_key() {
        let (_, public_key) = generate_nostr_identity();
        let public_key_hex = normalize_nostr_pubkey(&public_key).expect("valid public key");
        let mut config = AppConfig::default();
        config.nostr.secret_key = "not-a-secret-key".to_string();
        config.nostr.public_key = public_key.clone();

        config.ensure_defaults();

        assert_eq!(
            normalize_nostr_pubkey(&config.nostr.public_key).expect("valid public key"),
            public_key_hex
        );
        assert_eq!(config.nostr.secret_key, "not-a-secret-key");
    }

    #[test]
    fn wireguard_exit_defaults_and_normalization_are_stable() {
        let mut config = AppConfig::default();
        config.wireguard_exit.enabled = true;
        config.wireguard_exit.interface = "  ".to_string();
        config.wireguard_exit.address = " 10.200.0.2/32 ".to_string();
        config.wireguard_exit.private_key = " private ".to_string();
        config.wireguard_exit.peer_public_key = " peer ".to_string();
        config.wireguard_exit.endpoint = " 198.51.100.20:51830 ".to_string();
        config.wireguard_exit.allowed_ips = vec![
            "0.0.0.0/0".to_string(),
            "bad-route".to_string(),
            "0.0.0.0/0".to_string(),
        ];
        config.wireguard_exit.dns = vec![" 9.9.9.9 ".to_string(), "9.9.9.9".to_string()];

        config.ensure_defaults();

        assert!(config.wireguard_exit.enabled);
        assert_eq!(config.wireguard_exit.interface, "nvpn-wg-exit");
        assert_eq!(config.wireguard_exit.address, "10.200.0.2/32");
        assert_eq!(config.wireguard_exit.private_key, "private");
        assert_eq!(config.wireguard_exit.peer_public_key, "peer");
        assert_eq!(config.wireguard_exit.endpoint, "198.51.100.20:51830");
        assert_eq!(config.wireguard_exit.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(config.wireguard_exit.dns, vec!["9.9.9.9"]);
        assert!(config.wireguard_exit.configured());
    }

    #[test]
    fn exit_dns_defaults_to_automatic_and_uses_profile_dns_when_available() {
        let config: AppConfig = toml::from_str("").expect("legacy config parses");
        assert_eq!(config.exit_dns, ExitDnsConfig::default());

        let wireguard = WireGuardExitConfig {
            dns: vec!["10.64.0.1".to_string()],
            ..WireGuardExitConfig::default()
        };
        assert_eq!(
            config
                .exit_dns
                .resolver_config(Some(&wireguard))
                .expect("automatic resolver"),
            ExitDnsResolverConfig::ThroughExit {
                servers: vec!["10.64.0.1".parse().unwrap()]
            }
        );
        assert!(matches!(
            config.exit_dns.resolver_config(None).unwrap(),
            ExitDnsResolverConfig::Doh { ref url, .. } if url == CLOUDFLARE_DOH_URL
        ));
    }

    #[test]
    fn explicit_encrypted_dns_overrides_wireguard_profile_dns() {
        let exit_dns = ExitDnsConfig {
            mode: ExitDnsMode::Encrypted,
            doh_provider: ExitDohProvider::Quad9,
            ..ExitDnsConfig::default()
        };
        let wireguard = WireGuardExitConfig {
            dns: vec!["10.64.0.1".to_string()],
            ..WireGuardExitConfig::default()
        };

        assert!(matches!(
            exit_dns.resolver_config(Some(&wireguard)).unwrap(),
            ExitDnsResolverConfig::Doh { ref url, ref bootstrap_ips }
                if url == QUAD9_DOH_URL && bootstrap_ips.contains(&"9.9.9.9".parse().unwrap())
        ));
    }

    #[test]
    fn custom_exit_dns_requires_strict_complete_addresses() {
        let custom_doh = ExitDnsConfig {
            mode: ExitDnsMode::Encrypted,
            doh_provider: ExitDohProvider::Custom,
            custom_doh_url: "https://resolver.example/dns-query".to_string(),
            ..ExitDnsConfig::default()
        };
        assert!(
            custom_doh
                .resolver_config(Some(&WireGuardExitConfig::default()))
                .unwrap_err()
                .to_string()
                .contains("at least one IP")
        );

        let through_exit = ExitDnsConfig {
            mode: ExitDnsMode::ThroughExit,
            through_exit_servers: vec!["resolver.example".to_string()],
            ..ExitDnsConfig::default()
        };
        assert!(
            through_exit
                .resolver_config(None)
                .unwrap_err()
                .to_string()
                .contains("invalid DNS-through-exit")
        );

        #[cfg(feature = "secure-dns")]
        {
            let insecure_doh = ExitDnsConfig {
                mode: ExitDnsMode::Encrypted,
                doh_provider: ExitDohProvider::Custom,
                custom_doh_url: "http://resolver.example/dns-query".to_string(),
                custom_doh_bootstrap_ips: vec!["192.0.2.53".to_string()],
                ..ExitDnsConfig::default()
            };
            assert!(
                insecure_doh
                    .resolver_config(None)
                    .unwrap_err()
                    .to_string()
                    .contains("must use https")
            );
        }
    }

    #[test]
    fn legacy_exit_flags_migrate_to_one_internet_source() {
        let private_peer = generate_nostr_identity().1;
        let mut private: AppConfig = toml::from_str(&format!("exit_node = \"{private_peer}\""))
            .expect("parse legacy private exit config");
        private.apply_load_migrations();
        private.ensure_defaults();
        assert_eq!(private.internet_source, InternetSource::PrivateVpn);

        let seller = generate_nostr_identity().1;
        let mut paid: AppConfig = toml::from_str(&format!(
            "exit_node = \"{seller}\"\nexit_node_public_paid_exit = true\nconnect_to_non_roster_fips_peers = true\n"
        ))
        .expect("parse legacy paid exit config");
        paid.apply_load_migrations();
        paid.ensure_defaults();
        assert_eq!(paid.internet_source, InternetSource::PaidManual);

        let mut wireguard: AppConfig =
            toml::from_str("[wireguard_exit]\nenabled = true\n")
                .expect("parse legacy WireGuard exit config");
        wireguard.apply_load_migrations();
        wireguard.ensure_defaults();
        assert_eq!(wireguard.internet_source, InternetSource::WireGuard);
    }

    #[test]
    fn internet_source_switches_are_atomic() {
        let peer = generate_nostr_identity().1;
        let seller = generate_nostr_identity().1;
        let mut config = AppConfig::default();

        config
            .select_private_exit_node(&peer)
            .expect("select private exit");
        assert_eq!(config.internet_source, InternetSource::PrivateVpn);
        assert!(!config.exit_node_public_paid_exit);

        config.set_internet_source(InternetSource::PaidAutomatic);
        assert!(config.exit_node.is_empty());
        config
            .select_public_paid_exit_node(&seller)
            .expect("select automatic paid exit");
        assert_eq!(config.internet_source, InternetSource::PaidAutomatic);
        assert!(config.exit_node_public_paid_exit);

        config.set_internet_source(InternetSource::WireGuard);
        assert!(config.wireguard_exit.enabled);
        assert!(config.exit_node.is_empty());

        config.set_internet_source(InternetSource::Direct);
        assert!(!config.wireguard_exit.enabled);
        assert!(config.exit_node.is_empty());
    }

    #[test]
    fn paid_exit_seller_egress_follows_the_selected_internet_source() {
        let peer = normalize_nostr_pubkey(&generate_nostr_identity().1).expect("peer pubkey");
        let buyer = normalize_nostr_pubkey(&generate_nostr_identity().1).expect("buyer pubkey");
        let mut config = AppConfig::generated();
        config
            .set_active_network_id("paid-exit-seller-test")
            .expect("activate generated network");
        config.networks[0].devices.push(peer.clone());

        assert_eq!(
            config.paid_exit_seller_egress().expect("direct egress"),
            PaidExitSellerEgress::Direct
        );
        config.set_internet_source(InternetSource::WireGuard);
        assert_eq!(
            config.paid_exit_seller_egress().expect("WireGuard egress"),
            PaidExitSellerEgress::WireGuard
        );
        config
            .select_private_exit_node(&peer)
            .expect("select private exit");
        assert_eq!(
            config.paid_exit_seller_egress().expect("private egress"),
            PaidExitSellerEgress::PrivatePeer {
                pubkey: peer.clone()
            }
        );
        assert_eq!(
            config
                .paid_exit_seller_egress()
                .expect("private egress")
                .offer_upstream(),
            crate::paid_routes::PaidExitUpstream::HostDefault
        );
        assert!(config.validate_paid_exit_seller_buyer(&peer).is_err());
        assert_eq!(
            config
                .validate_paid_exit_seller_buyer(&buyer)
                .expect("independent buyer"),
            buyer
        );
    }

    #[test]
    fn paid_exit_seller_rejects_paid_upstream_chains() {
        let mut config = AppConfig::generated();
        config.set_internet_source(InternetSource::PaidAutomatic);
        assert!(config.paid_exit_seller_egress().is_err());
        config.set_internet_source(InternetSource::PaidManual);
        assert!(config.paid_exit_seller_egress().is_err());
    }

    #[test]
    fn wireguard_exit_import_accepts_provider_config() {
        let imported = parse_wireguard_exit_config(
            r#"
            # Provider export
            [Interface]
            PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            Address = 10.64.70.195/32, fc00:bbbb:bbbb:bb01::1:46c2/128
            DNS = 10.64.0.1, 1.1.1.1
            MTU = 1380

            [Peer]
            PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
            PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = vpn.example.test:51820
            PersistentKeepalive = 20
            "#,
        )
        .expect("provider config parses");

        assert_eq!(imported.address, "10.64.70.195/32");
        assert_eq!(imported.private_key, TEST_WG_PRIVATE_KEY);
        assert_eq!(imported.peer_public_key, TEST_WG_PUBLIC_KEY);
        assert_eq!(imported.peer_preshared_key, TEST_WG_PRESHARED_KEY);
        assert_eq!(imported.endpoint, "vpn.example.test:51820");
        assert_eq!(imported.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(imported.dns, vec!["1.1.1.1", "10.64.0.1"]);
        assert_eq!(imported.mtu, 1380);
        assert_eq!(imported.persistent_keepalive_secs, 20);
        assert!(wireguard_exit_config_text(&imported).contains("[Peer]"));
    }

    #[test]
    fn wireguard_exit_import_rejects_shell_hooks() {
        let error = parse_wireguard_exit_config(
            r#"
            [Interface]
            PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            Address = 10.64.70.195/32
            PostUp = echo unsafe

            [Peer]
            PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.test:51820
            "#,
        )
        .expect_err("shell hooks are rejected")
        .to_string();

        assert!(error.contains("hook directive"), "{error}");
    }

    #[test]
    fn wireguard_exit_import_rejects_invalid_key_material() {
        let error = parse_wireguard_exit_config(
            r#"
            [Interface]
            PrivateKey = not-a-wireguard-key
            Address = 10.64.70.195/32

            [Peer]
            PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.test:51820
            "#,
        )
        .expect_err("bad keys are rejected")
        .to_string();

        assert!(error.contains("PrivateKey"), "{error}");
    }

    #[test]
    fn fips_peer_endpoints_normalize_and_exclude_self() {
        let (_, own_public_key) = generate_nostr_identity();
        let (_, peer_public_key) = generate_nostr_identity();
        let peer_public_key_hex =
            normalize_nostr_pubkey(&peer_public_key).expect("valid peer public key");
        let mut config = AppConfig::default();
        config.nostr.secret_key = "not-a-secret-key".to_string();
        config.nostr.public_key = own_public_key.clone();
        config.fips_peer_endpoints.insert(
            peer_public_key_hex,
            vec![
                " 10.203.0.12:51820 ".to_string(),
                "10.203.0.12:51820".to_string(),
                "198.51.100.10:51820".to_string(),
                format!("{peer_public_key}:51820"),
                "fips".to_string(),
            ],
        );
        config
            .fips_peer_endpoints
            .insert(own_public_key, vec!["10.203.0.10:51820".to_string()]);

        config.ensure_defaults();

        assert_eq!(
            config.fips_static_peer_endpoints(),
            vec![(
                peer_public_key,
                vec!["10.203.0.12:51820".to_string(), "fips:51820".to_string()]
            )]
        );
        assert!(config.has_fips_static_peer_endpoints());
    }

    #[test]
    fn set_fips_peer_endpoint_hints_replaces_and_removes_peer_hints() {
        let (_, peer_public_key) = generate_nostr_identity();
        let peer_public_key_hex =
            normalize_nostr_pubkey(&peer_public_key).expect("valid peer public key");
        let mut config = AppConfig::default();

        config
            .set_fips_peer_endpoint_hints(
                &peer_public_key,
                &[
                    " peer.example.com ".to_string(),
                    "192.168.1.23".to_string(),
                    "peer.example.com:51820".to_string(),
                    "[fd00::23]".to_string(),
                ],
            )
            .expect("set hints");

        assert_eq!(
            config.fips_peer_endpoint_hints(&peer_public_key_hex),
            vec![
                "192.168.1.23:51820".to_string(),
                "[fd00::23]:51820".to_string(),
                "peer.example.com:51820".to_string()
            ]
        );

        let error = config
            .set_fips_peer_endpoint_hints(&peer_public_key, &["198.51.100.10:51820".to_string()])
            .expect_err("documentation endpoint is rejected")
            .to_string();
        assert!(error.contains("host:port"), "{error}");
        assert_eq!(
            config.fips_peer_endpoint_hints(&peer_public_key),
            vec![
                "192.168.1.23:51820".to_string(),
                "[fd00::23]:51820".to_string(),
                "peer.example.com:51820".to_string()
            ]
        );

        config
            .set_fips_peer_endpoint_hints(&peer_public_key, &[])
            .expect("clear hints");
        assert!(config.fips_peer_endpoint_hints(&peer_public_key).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn private_files_prefer_user_owned_parent_over_stale_root_owned_file() {
        assert_eq!(
            super::preferred_private_file_owner(Some((0, 0)), Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(Some((502, 20)), Some((501, 20))),
            Some((502, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(None, Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(None, Some((0, 0))),
            None
        );
    }
}
