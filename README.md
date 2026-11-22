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

Automatic mode renews channels before their credit or service time runs out. Manual purchases are one-time by default. Use `nvpn paid-exit buy <offer> --auto-renew` to authorize renewal with the same seller, mint, price per GB, and channel spending limit. Use `nvpn paid-exit stop-renewal` to turn it off, even while disconnected. Providers begin automatic collection at the 12-hour service cutoff. Buyers can reclaim uncollected funds after 24 hours, leaving a 12-hour window for collection retries. Existing funded refund deadlines are preserved.

DNS is encrypted by default, but exits still see destination IPs and unencrypted traffic. Use HTTPS for sensitive data. See [payment and privacy details](docs/protocol.md#paid-exits).

### Private peer credit

Peer credit uses FIPS service port **44748** inside the encrypted mesh. Your existing FIPS peer settings handle connectivity, including configured peers, LAN discovery and optional Nostr-assisted discovery. No extra firewall rule is needed for the credit service. Once you have earned credit, your node can ask the connected peer that owes you for a quote. That peer can forward the request along its own credit relationships. Payout peers can also send private offers directly to their creditors.

A desktop or server node can buy upload bytes from a connected VPN exit using signed credit. Enable an account with `nvpn paid-exit wallet enable-credit --trust <peer>` and restart the tunnel. The optional `--trial-peer-sat` and `--trial-pool-sat` flags allow small automatic trials for unfamiliar peers within a shared exposure limit. Trusted peers still share the account-wide ceiling. Both flags default to disabled.

Select the connected peer as the VPN exit using the usual internet-source settings. The seller must enable paid exit service and have working egress. Open a capped window with `nvpn paid-exit wallet buy-credit-exit <peer> --bytes <bytes> --price-msat-per-gb <price> --max-amount-sat <cap>`. The seller checks its own tariff and both endpoints meter public uploads. A window closes automatically at its cap or expiry while the tunnel is running. To close earlier, use `nvpn paid-exit wallet settle-credit-exit <agreement-id>`. A lost live meter before the final receipt leaves its reservation outstanding.

In the macOS wallet choose **Send → Earned credit**, scan or paste an invoice, review the cost and confirm. In the CLI, `nvpn paid-exit wallet withdraw <invoice> --credit` returns a quote. Confirm its exact JSON object with `--confirm-credit '<quote>'`. Check an uncertain payment using `nvpn paid-exit wallet payment-status <payment-hash>`. A payable path requires sufficient earned credit and a connected peer with a funded Lightning wallet willing to pay. Neighbours exchange requests privately, and the terminal receives the invoice when payment is confirmed.

To receive earnings automatically, open **Wallet → Earned credit → Connect my Lightning node** or run `nvpn paid-exit wallet connect-lightning`. This checks local Core Lightning without moving funds. Choose minimum, maximum, fee limit and interval, then enable automatic cash-out. In the CLI, use `nvpn paid-exit wallet auto-cashout --min-sat <min> --max-sat <max> --max-fee-sat <fee> --interval-secs <seconds>`. To stop, use `stop-auto-cashout`. A fixed `receiving_rpc_socket` in the private policy can select a particular wallet.

To operate a payout or forwarding node, place a private `peer-credit-policy.json` alongside the account with the same owner as the journal, and restart the tunnel. Set `forward_existing_credit` to allow forwarding against existing debts. The optional `lightning` object requires `rpc_socket`, `max_amount_sat`, `max_fee_msat`, `max_lifetime_payout_sat` and `max_lifetime_fees_msat`. The terminal pays Lightning routing fees. Optional `market.forward_fee_sat`, `market.payout_fee_sat` and `market.max_invoice_fee_sat` set the credit fees charged and the maximum total fee accepted for an invoice. The default is zero. It can privately signal availability with `nvpn paid-exit wallet offer-payout <creditor>`. For an invoice issued by your own Core Lightning wallet, configure `receiving_rpc_socket` and pass `--own-wallet` on confirmation and status checks to verify repayment at the receiver. Back up the account journal and its owner file as part of your node's state.

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
