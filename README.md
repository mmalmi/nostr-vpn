# nostr-vpn

<p align="center">
  <img src="icon.svg" alt="nostr-vpn logo" width="112">
</p>

> Canonical repository: [git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn) (`htree://npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn`). GitHub is a [mirror](https://github.com/mmalmi/nostr-vpn).

`nostr-vpn` is a Tailscale-style private mesh VPN built around a [FIPS]-backed data plane. It includes the `nvpn` CLI/daemon, a shared native app core, and native shells for desktop and mobile platforms.

## Downloads

- [Latest releases on git.iris.to](https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/nostr-vpn?tab=releases)
- [GitHub mirror releases](https://github.com/mmalmi/nostr-vpn/releases/latest)
- CLI from crates.io: `cargo install nvpn`
- [iOS App Store](https://apps.apple.com/app/nostr-vpn/id6785410348)
- [iOS TestFlight beta](https://testflight.apple.com/join/58sg4agv)

Release artifacts currently cover native Apple Silicon macOS, Linux x64, Windows x64, Android arm64, StartOS x86_64/aarch64 service packages, and headless CLI archives for Apple Silicon macOS, Windows x64, Linux x86_64, and Linux arm64. Intel macOS is source-only for now.

## Quick Start

```bash
cargo install nvpn --force
nvpn init
MY_NPUB='<paste nostr_pubkey from nvpn init>'
nvpn set --participant "$MY_NPUB"
nvpn start --daemon --connect
```

On a new device, generate its signed join request and show it to an admin in a Nostr VPN app:

```bash
nvpn init
nvpn join-request
```

The admin scans or pastes that request. Approval returns an admin-signed roster to the joining device. This signed request is the only join flow.

For the background daemon flow used by desktop apps:

```bash
nvpn start --daemon --connect
nvpn status
nvpn stop
```

For persistent startup:

```bash
sudo nvpn service install
nvpn service status
```

On Windows, run `nvpn service install` from an elevated shell instead of using `sudo`.

## Native Apps

The native apps share the Rust app-core state/action contract and use platform shells for macOS, Linux, Windows, Android, and iOS.

```bash
just build
just run
```

Use `just run-macos` or `just run-linux` when you want a specific desktop target.

<p align="center">
  <img src="docs/images/desktop-gui-overview.png" alt="Nostr VPN desktop app showing a connected Home Mesh network, device status badges, and join request controls." width="900">
</p>

## What Works Today

- Generates Nostr identity keys automatically
- Enrolls devices through signed join requests and admin-signed roster delivery
- Stores multiple named networks with one active network at a time
- Brings up [FIPS] private mesh tunnels for private network traffic
- Routes private traffic directly when possible and through [FIPS] neighbors when direct UDP is blocked
- Supports MagicDNS, authenticated DNS-over-HTTPS for exit routes, route advertisement, exit-node selection, and WireGuard upstream egress
- Exposes native desktop apps, JSON status, network diagnostics, doctor bundles, desktop updates, and Linux-focused Docker e2e coverage

Cashu paid exits settle byte-metered usage through a Spilman channel: every buyer-to-exit IP packet is counted immediately. Exit-to-buyer UDP is counted only for recent buyer-initiated flows, while TCP counts payload only after the buyer acknowledges it (without double-counting retransmitted download data); other inbound protocols are not billed.

## Platform Status

| Platform | Status |
| --- | --- |
| Apple Silicon macOS | Native SwiftUI/AppKit app, CLI tarball, signed/notarized release artifacts when credentials are configured |
| Linux x64 | Native GTK/libadwaita app, `.deb`, CLI tarballs, Docker e2e coverage |
| Windows x64 | Native WPF app, installer, CLI zip, WinTun tunnel path |
| Android arm64 | Native app-core UI, signed APK/AAB artifacts when signing is configured, VPN runtime still being hardened |
| iOS | Native SwiftUI app and NetworkExtension target available on the App Store; public TestFlight beta remains available |
| Umbrel / StartOS | Web control panels and service packages |
| Intel macOS | Source-only |

## Further Reading

- [Protocol](docs/protocol.md): join requests, admin roster sync, and the [FIPS] mesh data plane
- [Experiments](docs/EXPERIMENTS.md): chronological benchmark and reliability log
- [Native UI parity matrix](docs/native-ui-parity-matrix.md): native app rewrite status
- [Contributing](CONTRIBUTING.md): maintainer commands and package notes
- [Changelog](CHANGELOG.md): release history

## Maintainer Notes

This section is intentionally compact and command-oriented. Keep user-facing product detail above; keep agent/operator reference material here.

### Config Model

`nvpn init` creates the config and keys automatically. By default, config lives in the OS app config directory:

- Linux: `~/.config/nvpn/config.toml`
- macOS: `~/Library/Application Support/nvpn/config.toml`
- Fallback when no config dir is available: `./nvpn.toml`

The config contains global app settings, Nostr relay/identity settings, NAT settings, node settings, and a `[[networks]]` list. Each network has its own stable `network_id`; only the active network participates in the live runtime.

### Validation

Normal Rust gate:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Per-change core/contract verification:

```bash
just verify-fast
```

Managed native preflight and the nightly/release five-platform matrix:

```bash
just verify-health
just verify-full
```

See [verification tiers and managed native lab](docs/verification-tiers.md).

Release gate before version bumps and tags:

```bash
just release-gate
```

The gate overlaps its resource-isolated Windows and Docker-build lanes with
host validation, writes each lane to `artifacts/release-gate-logs`, and reuses
one candidate Docker image across functional and performance checks. NAT and
the kernel/userspace WireGuard fixtures also overlap on isolated subnets.
Roaming, throughput, host-pair, physical-device, and idle-CPU measurements
remain serial so concurrency cannot skew their results.

Useful focused checks:

```bash
pnpm --dir web/control-panel check
( cd linux && cargo check )
NVPN_E2E_ROAMING_SCENARIOS=latency ./scripts/e2e-fips-roaming-docker.sh
```

Run the Windows build from a checkout on the configured Windows dev VM:

```powershell
dotnet build windows\NostrVpn.Windows\NostrVpn.Windows.csproj -p:EnableWindowsTargeting=true
```

### Packages and E2E

- StartOS package: [`startos`](startos)
- Umbrel package: [`umbrel`](umbrel)
- Umbrel local web check:

```bash
docker compose -f umbrel/docker-compose.local.yml up --build
just e2e-umbrel-web
```

Focused security regression kit:

```bash
just security-regressions
```

Docker e2e and desktop updater scripts live under [`scripts`](scripts). The most common entrypoints are `scripts/e2e-docker.sh`, `scripts/e2e-fips-routed-udp-docker.sh`, `scripts/e2e-fips-nat-safe-mtu-docker.sh`, `scripts/e2e-wireguard-exit-docker.sh`, and `scripts/e2e-update-desktop.sh`.

### Release

1. Move `CHANGELOG.md` from `## Unreleased` to `## X.Y.Z - YYYY-MM-DD`.
2. Bump the root `[workspace.package].version` in `Cargo.toml`.
3. Run `node scripts/sync-versions.mjs`, verify with `node scripts/sync-versions.mjs --check`, and commit the release source.
4. From that exact clean commit, stage the complete release with `node scripts/local-release.mjs --stage-dir <stage-dir>`. Staging runs the mandatory release gate and binds its real-platform receipts.
5. Publish the immutable draft:

   ```bash
   node scripts/local-release.mjs \
     --publish-staged-draft \
     --stage-dir <stage-dir>
   ```

6. Publish the exact refs and wait for the immutable-draft workflow:

   ```bash
   node scripts/publish-release-refs.mjs \
     --stage-dir <stage-dir> \
     --tag vX.Y.Z \
     --draft-cid <immutable-draft-cid>
   ```

   This creates or verifies the lightweight local tag, rejects conflicting
   remote refs, replays the canonical mutation gate before each external
   phase, pushes without force, resumes an already visible exact GitHub Actions
   run on retry, and fails closed if duplicate exact runs exist.
7. Promote the same staged bytes with `node scripts/local-release.mjs --promote-draft --stage-dir <stage-dir>`. Promotion preflights and publishes Apple distribution, htree, the exact GitHub release, crates.io packages, Zapstore, and the multi-architecture Umbrel image. Umbrel publication records the pushed digest, verifies the public registry index anonymously for `linux/amd64` and `linux/arm64`, and writes a digest-pinned submission bundle under `dist/umbrel-vX.Y.Z`.

Direct `--publish` and `--final` modes are intentionally disabled. Every external release mutation replays the exact staged-source gate.

Private fleet rollout is a separate post-release operation. Prepare its frozen inventory and manifest with `scripts/prepare-fleet-release-canary.mjs`, inspect the plan with `scripts/fleet_release_canary.py plan`, and run the explicitly authorized `execute` mode only when the fleet should be updated.

### Workspace Layout

- [`crates/nostr-vpn-cli`](crates/nostr-vpn-cli): `nvpn` CLI and daemon implementation
- [`crates/nostr-vpn-core`](crates/nostr-vpn-core): config, [FIPS] control state, diagnostics, MagicDNS, and NAT helpers
- [`crates/nostr-vpn-app-core`](crates/nostr-vpn-app-core): native app state/action contract and UniFFI bridge
- [`macos`](macos), [`linux`](linux), [`windows`](windows), [`android`](android), [`ios`](ios): native platform shells
- [`umbrel`](umbrel), [`startos`](startos): packaged service/web-control-panel targets
- [`scripts`](scripts): build, release, Docker e2e, and desktop updater entrypoints

[FIPS]: https://github.com/jmcorgan/fips
