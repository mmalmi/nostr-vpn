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

Providers publish byte-priced offers over Nostr, and buyers settle usage through Cashu Spilman channels. Uploads are counted immediately; matched UDP replies and buyer-acknowledged TCP downloads are also billed without double-counting TCP retransmissions.

Offers can declare `location.network_class` (`residential`, `datacenter`, `mobile`, `business`, or `unknown`), mirrored in the `network_class` Nostr tag. This is a provider claim, not a verified IP classification.

Exit feedback uses signed social-graph/social-memory `Rating` events with scope `vpn.exit`. The app automatically shares ratings, never raw probe measurements, destinations, session identifiers, or payment data. One latest assessment per author/provider counts; your follows and explicitly trusted authors determine whose ratings are used, and muted or unknown authors do not count. Service reviews do not grant general peer trust. Rating buttons appear only for providers this device has successfully connected through. Manual thumbs override automatic feedback. Thumbs down stops and avoids that provider while keeping paid mode and leak protection enabled; clearing the vote removes that exclusion without issuing a connection request.

Automatic selection excludes your downvotes and prefers your thumbs-up among providers with comparable connection health. Local measurements and trusted ratings rank candidates before price and announcement recency, within the existing spending and eligibility limits. **Try another** requests one switch without publishing an opinion or discarding channel funds. Opening Manual only shows the chooser: your current automatic, private, or WireGuard connection stays in place until you select a provider. The current paid provider is listed first.

The CLI equivalents are `nvpn paid-exit rate up|down|clear [--provider <npub>]` and `nvpn paid-exit reselect`. Use `nvpn paid-exit discover` to browse without changing routes, then `buy` or `use` to select a manual provider. Sellers can set `nvpn paid-exit run --network-class residential` (or another supported class).

Daemon probes keep ambiguous failures local. A healthy alternative within 60 seconds on the same connection can confirm a negative assessment, including retrospectively after switching providers. Network changes discard this temporary evidence. This is comparative evidence, not proof of provider fault. Repeated ratings are coalesced and rate limited; directly trusted colluding authors can still influence the result. Pending ratings survive offline periods and are retried through Nostr pubsub.

Public DNS uses authenticated DNS-over-HTTPS by default, preventing the exit provider from reading or spoofing DNS questions and answers; MagicDNS names remain local. See [Exit DNS and inbound safety](docs/protocol.md#exit-dns-and-inbound-safety) for resolver options and limitations.

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
- [StartOS packaging](CONTRIBUTING.md): contributor build and validation notes
- [Changelog](CHANGELOG.md): release history
- [Experiments](docs/EXPERIMENTS.md): performance and reliability results
- [Native UI parity](docs/native-ui-parity-matrix.md): platform implementation status

The canonical repository is [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn) (`htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn`); [GitHub](https://github.com/mmalmi/nostr-vpn) is a mirror.
