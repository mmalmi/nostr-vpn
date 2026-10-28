# nvpn

CLI and daemon for Nostr VPN private mesh networks.

The `nvpn` binary initializes configuration, runs foreground or background VPN
sessions, manages system services on macOS, Linux, and Windows, and installs
published binary updates.

Install from crates.io:

```bash
cargo install nvpn
```

Run `nvpn --help` for the current command set.

## Endpoint recovery under a service manager

If local FIPS endpoint recovery fails after removing the old runtime, the daemon
runs its normal shutdown path and exits with an error. A service manager can then
restart the process rather than leave a running daemon without a VPN runtime.
Pending cleanup ownership and the configured egress-protection policy remain
subject to the existing shutdown and startup checks.

This does not restart the daemon merely because remote peers are offline. A
replacement-preparation error that leaves the existing runtime available is
logged without forcing a process restart.

## Source

https://github.com/mmalmi/nostr-vpn
