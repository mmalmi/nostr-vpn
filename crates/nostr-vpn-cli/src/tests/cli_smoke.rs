use clap::{CommandFactory, Parser, error::ErrorKind};

#[cfg(feature = "paid-exit")]
use crate::PaidExitCommand;
use crate::{Cli, Command, PubsubCommand};

#[test]
fn explicit_config_path_environment_value_is_preserved() {
    assert_eq!(
        crate::config_bootstrap::configured_config_path(Some("/var/lib/nvpn/config.toml".into())),
        Some("/var/lib/nvpn/config.toml".into())
    );
    assert_eq!(
        crate::config_bootstrap::configured_config_path(Some("".into())),
        None
    );
}

#[test]
fn clap_binary_name_is_nvpn() {
    let command = Cli::command();
    assert_eq!(command.get_name(), "nvpn");
}

#[test]
fn clap_supports_root_version_flag() {
    let error = Cli::command()
        .try_get_matches_from(["nvpn", "--version"])
        .expect_err("--version should display version and exit");
    assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    assert!(
        error
            .to_string()
            .contains(&format!("nvpn {}", env!("CARGO_PKG_VERSION"))),
        "version output should include binary name and package version"
    );
}

#[test]
fn clap_parses_join_request_wait_controls() {
    let cli = Cli::parse_from([
        "nvpn",
        "join-request",
        "--config",
        "/var/lib/nvpn/config.toml",
        "--no-wait",
        "--no-qr",
        "--reset",
    ]);
    let Command::JoinRequest(args) = cli.command else {
        panic!("expected join-request command");
    };
    assert_eq!(
        args.config.expect("config").to_string_lossy(),
        "/var/lib/nvpn/config.toml"
    );
    assert!(args.no_wait);
    assert!(args.no_qr);
    assert!(args.reset);
}

#[tokio::test]
async fn manual_join_command_persists_the_admin_and_network_for_the_joiner() {
    use nostr_sdk::prelude::{Keys, ToBech32};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("nvpn-manual-join-cli-{nonce}"));
    let config_path = directory.join("config.toml");
    let admin_npub = Keys::generate()
        .public_key()
        .to_bech32()
        .expect("admin npub");
    let admin_hex =
        nostr_vpn_core::config::normalize_nostr_pubkey(&admin_npub).expect("normalize admin");

    let cli = Cli::parse_from([
        "nvpn",
        "join-manual",
        "--admin-device-id",
        &admin_npub,
        "--network-id",
        "8d4f-34f5-425b-c50e",
        "--config",
        config_path.to_str().expect("config path"),
        "--json",
    ]);
    crate::run_command(cli.command)
        .await
        .expect("run manual join command");

    let saved = nostr_vpn_core::config::AppConfig::load(&config_path).expect("load config");
    let network = saved.active_network();
    assert_eq!(network.network_id, "8d4f34f5425bc50e");
    assert_eq!(network.devices, vec![admin_hex.clone()]);
    assert_eq!(network.admins, vec![admin_hex]);
    assert!(network.outbound_join_request.is_none());
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn daemon_parses_paired_fips_ethernet_options() {
    let cli = Cli::parse_from([
        "nvpn",
        "daemon",
        "--fips-ethernet-interface",
        "eth0",
        "--fips-ethernet-discovery-scope",
        "local-pairing",
    ]);
    let Command::Daemon(args) = cli.command else {
        panic!("expected daemon command");
    };
    assert_eq!(args.fips_ethernet_interface.as_deref(), Some("eth0"));
    assert_eq!(
        args.fips_ethernet_discovery_scope.as_deref(),
        Some("local-pairing")
    );
}

#[test]
fn daemon_rejects_unpaired_fips_ethernet_options() {
    let error = Cli::try_parse_from(["nvpn", "daemon", "--fips-ethernet-interface", "eth0"])
        .expect_err("Ethernet interface must require its discovery scope");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn daemon_accepts_multiple_valid_fips_websocket_seeds() {
    let cli = Cli::parse_from([
        "nvpn",
        "daemon",
        "--fips-websocket-seed-url",
        "wss://seed-a.example/fips",
        "--fips-websocket-seed-url",
        "wss://seed-b.example/fips",
    ]);
    let Command::Daemon(args) = cli.command else {
        panic!("expected daemon command");
    };
    assert_eq!(
        args.fips_websocket_seed_urls,
        ["wss://seed-a.example/fips", "wss://seed-b.example/fips"]
    );
}

#[test]
fn daemon_rejects_invalid_or_remote_plaintext_fips_websocket_seeds() {
    for value in [
        "bootstrap garbage",
        "https://seed.example/fips",
        "ws://seed.example/fips",
    ] {
        let error = Cli::try_parse_from(["nvpn", "daemon", "--fips-websocket-seed-url", value])
            .expect_err("invalid FIPS WebSocket seed must be rejected");
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }
}

#[test]
fn daemon_instance_is_an_explicit_validated_server_scope() {
    let cli = Cli::parse_from(["nvpn", "daemon", "--daemon-instance", "seed-a"]);
    let Command::Daemon(args) = cli.command else {
        panic!("expected daemon command");
    };
    assert_eq!(args.daemon_instance.as_deref(), Some("seed-a"));

    for invalid in ["Seed", "-seed", "seed/other"] {
        let argument = format!("--daemon-instance={invalid}");
        let error = Cli::try_parse_from(["nvpn", "daemon", argument.as_str()])
            .expect_err("invalid daemon instance must be rejected");
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }
}

#[test]
fn set_parses_explicit_lan_discovery_disable() {
    let cli = Cli::parse_from([
        "nvpn",
        "set",
        "--lan-discovery-enabled=false",
        "--config",
        "/var/lib/nvpn/config.toml",
    ]);
    let Command::Set(args) = cli.command else {
        panic!("expected set command");
    };
    assert_eq!(args.lan_discovery_enabled, Some(false));
}

#[test]
fn build_reports_fips_core_component_version() {
    let version = crate::fips_core_build_version();
    assert!(!version.trim().is_empty());
    assert!(version.starts_with(fips_core::version::VERSION));
}

#[test]
fn clap_includes_tailscale_style_commands() {
    let command = Cli::command();
    for name in [
        "start",
        "stop",
        "repair-network",
        "reload",
        "pause",
        "resume",
        "connect",
        "join-request",
        "join-manual",
        "status",
        "set",
        "ping",
        "doctor",
        "ip",
        "whois",
        "pubsub",
        "install-cli",
        "uninstall-cli",
        "service",
        "version",
    ] {
        assert!(
            command
                .get_subcommands()
                .any(|subcommand| subcommand.get_name() == name),
            "missing subcommand {name}"
        );
    }
}

#[test]
fn clap_parses_control_pubsub_publish_event_file() {
    let cli = Cli::parse_from([
        "nvpn",
        "pubsub",
        "publish",
        "--event",
        "/tmp/control-event.json",
        "--config",
        "/tmp/nvpn.toml",
        "--json",
    ]);
    let Command::Pubsub(args) = cli.command else {
        panic!("expected pubsub command");
    };
    let PubsubCommand::Publish(args) = args.command;
    assert_eq!(args.event.to_string_lossy(), "/tmp/control-event.json");
    assert_eq!(
        args.config.expect("config").to_string_lossy(),
        "/tmp/nvpn.toml"
    );
    assert!(args.json);
}

#[tokio::test]
async fn control_pubsub_publish_command_queues_a_signed_event() {
    use nostr_sdk::prelude::{EventBuilder, Keys, Kind};

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("nvpn-pubsub-cli-{nonce}"));
    let config_path = directory.join("config.toml");
    let event_path = directory.join("event.json");
    let app = nostr_vpn_core::config::AppConfig::generated();
    app.save(&config_path).expect("save config");
    let event = EventBuilder::new(Kind::Custom(37_196), "paid exit offer")
        .sign_with_keys(&Keys::generate())
        .expect("signed event");
    std::fs::write(&event_path, serde_json::to_vec(&event).expect("event JSON"))
        .expect("write event");

    let cli = Cli::parse_from([
        "nvpn",
        "pubsub",
        "publish",
        "--event",
        event_path.to_str().expect("event path"),
        "--config",
        config_path.to_str().expect("config path"),
        "--json",
    ]);
    crate::run_command(cli.command)
        .await
        .expect("queue event through CLI dispatch");

    assert!(
        crate::control_pubsub_runtime::control_pubsub_outbox_directory(&config_path)
            .join(format!("{}.json", event.id.to_hex()))
            .exists()
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[cfg(feature = "paid-exit")]
#[test]
fn clap_includes_paid_exit_command_when_enabled() {
    let command = Cli::command();
    assert!(
        command
            .get_subcommands()
            .any(|subcommand| subcommand.get_name() == "paid-exit"),
        "missing paid-exit subcommand"
    );
}

#[cfg(feature = "paid-exit")]
#[test]
fn clap_paid_exit_buy_supports_best_rated_selector() {
    let cli = Cli::parse_from(["nvpn", "paid-exit", "buy", "--best-rated"]);
    let Command::PaidExit(args) = cli.command else {
        panic!("expected paid-exit command");
    };
    let PaidExitCommand::Buy(args) = args.command else {
        panic!("expected buy command");
    };
    assert!(args.best_rated);
    assert_eq!(args.offer, None);
}

#[cfg(not(feature = "paid-exit"))]
#[test]
fn clap_omits_paid_exit_command_by_default() {
    let command = Cli::command();
    assert!(
        !command
            .get_subcommands()
            .any(|subcommand| subcommand.get_name() == "paid-exit"),
        "paid-exit subcommand should require the paid-exit feature"
    );
}

#[test]
fn clap_roster_device_commands_keep_participant_aliases() {
    Cli::command()
        .try_get_matches_from(["nvpn", "add-device", "--device", "npub1example"])
        .expect("new device command parses");
    Cli::command()
        .try_get_matches_from(["nvpn", "add-participant", "--participant", "npub1example"])
        .expect("legacy participant command parses");
}

#[test]
fn clap_set_supports_autoconnect_flag() {
    let command = Cli::command();
    let set = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "set")
        .expect("set subcommand exists");
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("autoconnect")),
        "missing --autoconnect on set command"
    );
}

#[test]
fn clap_set_supports_join_request_listener_flag() {
    let command = Cli::command();
    let set = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "set")
        .expect("set subcommand exists");
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("join-requests-enabled")),
        "missing --join-requests-enabled on set command"
    );
}

#[test]
fn clap_set_supports_route_advertisement_flags() {
    let command = Cli::command();
    let set = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "set")
        .expect("set subcommand exists");
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("advertise-routes")),
        "missing --advertise-routes on set command"
    );
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("advertise-exit-node")),
        "missing --advertise-exit-node on set command"
    );
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("exit-node")),
        "missing --exit-node on set command"
    );
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("internet-source")),
        "missing --internet-source on set command"
    );
    assert!(
        set.get_arguments()
            .any(|argument| argument.get_long() == Some("exit-node-leak-protection")),
        "missing --exit-node-leak-protection on set command"
    );
}

#[cfg(feature = "paid-exit")]
#[test]
fn clap_set_supports_paid_exit_seller_flags() {
    let command = Cli::command();
    let set = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "set")
        .expect("set subcommand exists");
    for flag in [
        "paid-exit-enabled",
        "paid-exit-upstream",
        "paid-exit-price-msat-per-gb",
        "paid-exit-accepted-mints",
        "paid-exit-country-code",
        "paid-exit-asn",
        "paid-exit-max-channel-capacity-sat",
        "paid-exit-channel-expiry-secs",
        "paid-exit-free-probe-units",
        "paid-exit-grace-units",
    ] {
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some(flag)),
            "missing --{flag} on set command"
        );
    }
    let run = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "paid-exit")
        .and_then(|paid_exit| {
            paid_exit
                .get_subcommands()
                .find(|subcommand| subcommand.get_name() == "run")
        })
        .expect("paid-exit run subcommand exists");
    for removed_flag in ["ipv4", "ipv6"] {
        assert!(
            run.get_arguments()
                .all(|argument| argument.get_long() != Some(removed_flag)),
            "obsolete paid-exit run --{removed_flag} must stay removed"
        );
    }
    for removed_flag in [
        "paid-exit-meter",
        "paid-exit-price-msat",
        "paid-exit-per-units",
        "paid-exit-ipv4",
        "paid-exit-ipv6",
    ] {
        assert!(
            !set.get_arguments()
                .any(|argument| argument.get_long() == Some(removed_flag)),
            "obsolete --{removed_flag} must stay removed"
        );
    }
}

#[test]
fn clap_set_supports_wireguard_exit_flags() {
    let command = Cli::command();
    let set = command
        .get_subcommands()
        .find(|subcommand| subcommand.get_name() == "set")
        .expect("set subcommand exists");
    for flag in [
        "wireguard-exit-enabled",
        "wireguard-exit-address",
        "wireguard-exit-private-key",
        "wireguard-exit-peer-public-key",
        "wireguard-exit-endpoint",
        "wireguard-exit-allowed-ips",
        "wireguard-exit-config",
        "wireguard-exit-config-file",
    ] {
        assert!(
            set.get_arguments()
                .any(|argument| argument.get_long() == Some(flag)),
            "missing --{flag} on set command"
        );
    }
}
