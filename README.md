# nostr-vpn

<p align="center">
  <img src="icon.svg" alt="nostr-vpn logo" width="112">
</p>

`nostr-vpn` is a Tailscale-style private mesh VPN with a data plane powered by [our independently evolved FIPS implementation](https://github.com/mmalmi/fips), based on the [original FIPS project](https://github.com/jmcorgan/fips). It also includes an experimental marketplace for byte-metered public exit nodes paid in Bitcoin through Cashu.

Nostr identities and signed rosters control enrollment; peers connect directly when possible and route through FIPS neighbors when direct UDP is unavailable. MagicDNS, subnet routes, exit nodes, and WireGuard upstream egress are built in. The project includes the `nvpn` CLI and daemon plus native apps for macOS, Linux, Windows, Android, and iOS.

Connect people, servers, and agent hosts without an email, phone number, or VPN
provider account. See [agent onboarding and headless approval](docs/agents.md)
and the [agent plugin](plugins/nostr-vpn/README.md).

The fork is optimized for high-rate VPN traffic. In comparable direct-path benchmarks it delivers roughly three times the original implementation's throughput by keeping packet ownership, buffers, and session state together, batching I/O and cryptography, reusing packet storage, and avoiding packet-by-packet queue hops, allocations, copies, and repeated lookups. It preserves the FIPS protocol surface.

<p align="center">
  <img src="docs/images/desktop-gui-overview.png" alt="Nostr VPN macOS app in dark mode showing the Home Mesh demo network with five online devices and internet-sharing controls." width="900">
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

On the admin device, open **Devices → Add Join Request**, scan or paste the
request, check the device details, and confirm **Add device**. Approval is not
automatic. The admin app signs and distributes the updated roster; this flow
does not need a separate `add-device --publish` command. Keep the joining
daemon running until it receives approval. For CLI inspection and approval,
see the [headless enrollment guide](docs/agents.md#review-and-approve-on-the-admin-host).

The daemon lifecycle is:

```bash
nvpn start --daemon --connect
nvpn status
nvpn stop
```

For startup at boot on Linux or macOS, pass the absolute path of the
configuration you initialized to `sudo nvpn service install --config <path>`.
Stop a separately started daemon with `nvpn stop` before installing the service.
Use the same `--config <path>` with `nvpn status`, `nvpn set`, and
`nvpn service status`; run these with `sudo` if the service owns the configuration
or state files. Without an explicit path, an elevated command can select a
different user's configuration and create a separate identity and network.
On Windows, run `nvpn service install` from an elevated shell and check it with
`nvpn service status`.

Linux update checks select packages for your distribution and architecture. Automatic downloads stay in the background and are remembered across app restarts. Choose **Show download** to open the folder and install the package; the app never opens an installer or browser automatically.

## Containers and headless nodes

Use a Linux CLI archive matching the container architecture. Persist the config
directory, including its key sidecars, and pass the same `--config` path to every
command. The [Umbrel image and Compose files](umbrel) provide an existing packaged
daemon and web interface; `Dockerfile.e2e` is a source-built test fixture.

- Run with root, `/dev/net/tun`, `NET_ADMIN`, and `iproute2`. Include `nftables`
  for exit protection and `iptables` for exit forwarding and legacy-rule cleanup.
  Version 4.1.18 also requires `iptables` for plain mesh startup. Current source
  skips the optional legacy sweep with a warning if the tool is missing; cleanup
  of forwarding rules owned by the session still requires it.
- Container restrictions can still block route cleanup: a read-only
  `/proc/sys/net/ipv4/route/flush` makes `ip route flush cache` fail. Privileged
  mode is a workaround for an isolated test container, not a universal production
  requirement. Host networking gives the daemon access to the host's routes and
  firewall; choose it only when that is intended.
- Without systemd-resolved, split MagicDNS may remain available only at the local
  address and port printed in the log (normally `127.0.0.1:1053`). That does not
  make names resolve through the system resolver automatically. Linux secure DNS
  is separate: in Docker it can manage `/etc/resolv.conf` and use port 53. See
  [#79](https://github.com/mmalmi/nostr-vpn/issues/79) for the existing-local-resolver
  conflict; a working mesh alone does not verify DNS.
- Use `nvpn start --daemon --connect` for `nvpn status --json` health checks.
  Require `status_source == "daemon"` before interpreting readiness. Foreground
  `nvpn connect` sessions do not publish daemon state; config-only readiness is
  unknown (`null` in JSON).

The quick start above works for headless enrollment. For a manually provisioned
two-node lab, `nvpn set --network-id` sets and enables the active network; editing
TOML with `sed` is unnecessary. Initialize each node separately, exchange its
public device ID, then run on each node with the appropriate values:

```bash
nvpn set --config "$CONFIG" --network-id "$NETWORK_ID" \
  --device "$LOCAL_DEVICE_ID" --device "$PEER_DEVICE_ID" \
  --endpoint "$LOCAL_ENDPOINT" --fips-peer-endpoint "$PEER_DEVICE_ID=$PEER_ENDPOINT" \
  --fips-host-tunnel-enabled true --fips-advertise-public-endpoint false \
  --fips-nostr-discovery-enabled false --fips-bootstrap-enabled false \
  --fips-webrtc-enabled false --lan-discovery-enabled false
nvpn start --config "$CONFIG" --daemon --connect
```

Use the same network ID and device roster on both nodes. Endpoints are reachable
`IP:port` pairs; their ports must match each node's listen port (51820 by default).
Keep the independently generated private keys on their respective nodes.

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
- [Contributing](CONTRIBUTING.md): small PRs, relevant checks, and StartOS packaging
- [Changelog](CHANGELOG.md): release history
- [Security reports](SECURITY.md): private vulnerability reporting
- [Experiments](docs/EXPERIMENTS.md): performance and reliability results
- [Native UI parity](docs/native-ui-parity-matrix.md): platform implementation status

The canonical repository is [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn) (`htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn`); [GitHub](https://github.com/mmalmi/nostr-vpn) is a mirror.
