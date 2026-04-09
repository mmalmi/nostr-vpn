use clap::CommandFactory;

use crate::Cli;

#[test]
fn clap_binary_name_is_nvpn() {
    let command = Cli::command();
    assert_eq!(command.get_name(), "nvpn");
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
        "up",
        "connect",
        "down",
        "status",
        "stats",
        "set",
        "ping",
        "netcheck",
        "doctor",
        "ip",
        "whois",
        "nat-discover",
        "hole-punch",
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
}
