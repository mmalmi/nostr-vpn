# nostr-vpn

<p align="center">
  <img src="icon.svg" alt="nostr-vpn logo" width="112">
</p>

`nostr-vpn` is a Tailscale-style private mesh VPN with a [FIPS](https://github.com/jmcorgan/fips)-backed data plane. It also experiments with byte-metered public exit nodes paid in Bitcoin through Cashu.

Nostr identities and signed rosters control enrollment; peers connect directly when possible and route through FIPS neighbors when direct UDP is unavailable. MagicDNS, subnet routes, exit nodes, and WireGuard upstream egress are built in. The project includes the `nvpn` CLI and daemon plus native apps for macOS, Linux, Windows, Android, and iOS.

<p align="center">
  <img src="docs/images/desktop-gui-overview.png" alt="Nostr VPN desktop app showing a connected Home Mesh network, device status badges, and join request controls." width="900">
</p>

## Install

- Desktop apps and CLI archives: [git.iris.to releases](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn?tab=releases) or the [GitHub mirror](https://github.com/mmalmi/nostr-vpn/releases/latest)
- CLI: `cargo install nvpn`
- iOS: [App Store](https://apps.apple.com/app/nostr-vpn/id6785410348) or [TestFlight](https://testflight.apple.com/join/58sg4agv)
- Android: APK from the releases above or [Zapstore](https://zapstore.dev/apps/org.nostrvpn.app)
- Servers: signed [StartOS (Start9)](startos) `.s9pk` packages in the releases above, plus a multi-architecture [Umbrel](umbrel) image and app bundle

Desktop apps target Apple Silicon macOS and x64 Linux/Windows; mobile builds target arm64, and CLI archives also cover Linux arm64. StartOS and Umbrel support x86_64/amd64 and arm64. Intel macOS is source-only.

## CLI Quick Start

Create a network on the first device:

```bash
cargo install nvpn --force
nvpn init
MY_NPUB='<paste nostr_pubkey from nvpn init>'
nvpn set --participant "$MY_NPUB"
nvpn start --daemon --connect
```

To add another device, generate a signed join request and scan or paste it into a Nostr VPN app for admin approval:

```bash
nvpn init
nvpn join-request
```

The daemon lifecycle is:

```bash
nvpn start --daemon --connect
nvpn status
nvpn stop
```

For startup at boot, run `sudo nvpn service install`; on Windows, run `nvpn service install` from an elevated shell. Check it with `nvpn service status`.

## Paid Exits

Paid exits settle byte-metered usage through Cashu Spilman channels. Every buyer-to-exit IP packet is counted immediately; exit-to-buyer UDP is counted only for recent buyer-initiated flows, while TCP payload is counted only after the buyer acknowledges it, without double-counting retransmitted download data. Other inbound protocols are not billed.

Public DNS uses authenticated DNS-over-HTTPS by default, preventing the exit provider from reading or spoofing DNS questions and answers; MagicDNS names remain local. See [Exit DNS privacy](docs/protocol.md#exit-dns-privacy) for resolver options and limitations.

As with a Tor exit node, treat an unknown paid exit provider as an untrusted network. It can observe destination IPs and traffic metadata, and can read or modify plaintext HTTP and other traffic without end-to-end encryption. Use HTTPS or another authenticated, end-to-end encrypted protocol for sensitive traffic.

## Build and Verify

```bash
just build
just run
just verify-fast
```

Use `just run-macos` or `just run-linux` for a specific desktop target. See [verification tiers](docs/verification-tiers.md) for broader native, integration, and release checks.

## Documentation

- [Protocol](docs/protocol.md): enrollment, roster sync, routing, and DNS privacy
- [Contributing](CONTRIBUTING.md): contributor and package notes
- [Changelog](CHANGELOG.md): release history
- [Experiments](docs/EXPERIMENTS.md): performance and reliability results
- [Native UI parity](docs/native-ui-parity-matrix.md): platform implementation status

The canonical repository is [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn) (`htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn`); [GitHub](https://github.com/mmalmi/nostr-vpn) is a mirror.
