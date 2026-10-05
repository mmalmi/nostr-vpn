# nostr-vpn

<p align="center">
  <img src="icon.svg" alt="nostr-vpn logo" width="112">
</p>

`nostr-vpn` is a Tailscale-style private mesh VPN with a data plane powered by [our independently evolved FIPS implementation](https://github.com/mmalmi/fips), based on the [original FIPS project](https://github.com/jmcorgan/fips). It also includes an experimental marketplace for byte-metered public exit nodes paid in Bitcoin through Cashu.

Nostr identities and signed rosters control enrollment; peers connect directly when possible and route through FIPS neighbors when direct UDP is unavailable. MagicDNS, subnet routes, exit nodes, and WireGuard upstream egress are built in. The project includes the `nvpn` CLI and daemon plus native apps for macOS, Linux, Windows, Android, and iOS.

The fork is optimized for high-rate VPN traffic. In comparable direct-path benchmarks it delivers roughly three times the original implementation's throughput by keeping packet ownership, buffers, and session state together, batching I/O and cryptography, reusing packet storage, and avoiding packet-by-packet queue hops, allocations, copies, and repeated lookups. It preserves the FIPS protocol surface.

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

On Debian or Ubuntu, building the CLI with Cargo requires `pkg-config` and
`libdbus-1-dev` (`sudo apt install pkg-config libdbus-1-dev`). The prebuilt CLI
archives do not require these development packages.

## CLI Quick Start

Create a network on the first device:

```bash
nvpn init
DEVICE_ID='<paste nostr_pubkey from nvpn init>'
nvpn set --device "$DEVICE_ID"
nvpn start --daemon --connect
```

On another device, start its daemon, generate a signed join request, and scan or paste the request into an admin's Nostr VPN app:

```bash
nvpn init
nvpn start --daemon --connect
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

Buy or sell VPN bandwidth for Bitcoin. Providers can sell their own internet connection or a WireGuard VPN uplink. Providers advertise per-byte prices over Nostr; buyers fund Cashu Spilman channels and sign payment updates as they use bandwidth. Uploads count as sent; UDP replies and acknowledged TCP downloads count too, without double-billing TCP retransmissions. Choose a provider manually or automatically using connection quality, trusted ratings, and price.

By default, channels renew before a 12-hour service cutoff, when providers begin automatic collection. Buyers can reclaim uncollected funds after 24 hours, leaving a 12-hour window for collection retries. Existing funded refund deadlines are preserved.

DNS is encrypted by default, but exits still see destination IPs and unencrypted traffic. Use HTTPS for sensitive data. See [payment and privacy details](docs/protocol.md#paid-exits).

## Build and Verify

```bash
just build
just run
just verify-fast
```

Use `just run-macos` or `just run-linux` for a specific desktop target. See [verification tiers](docs/verification-tiers.md) for broader native, integration, and release checks.

## Documentation

- [Protocol](docs/protocol.md): enrollment, roster sync, routing, and DNS privacy
- [StartOS packaging](CONTRIBUTING.md): contributor build and validation notes
- [Changelog](CHANGELOG.md): release history
- [Experiments](docs/EXPERIMENTS.md): performance and reliability results
- [Native UI parity](docs/native-ui-parity-matrix.md): platform implementation status

The canonical repository is [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn) (`htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn`); [GitHub](https://github.com/mmalmi/nostr-vpn) is a mirror.
