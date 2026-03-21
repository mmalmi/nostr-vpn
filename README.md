# nostr-vpn

`nostr-vpn` is a Rust workspace for a Tailscale-style mesh VPN control plane built on:

- Nostr relays for peer signaling and encrypted presence exchange
- `boringtun` for userspace WireGuard-compatible tunnel handling
- a CLI daemon and a Tauri desktop app that operate on the same config/runtime model

This repo is not just one binary. It currently ships:

| Component | Purpose |
| --- | --- |
| `nvpn` | Main CLI for config, daemon lifecycle, networking, diagnostics, and tunnel sessions |
| `nostr-vpn-gui` | Tauri + Svelte desktop app that manages the same `nvpn` daemon and config |
| `nostr-vpn-relay` | Minimal local websocket relay used for integration and e2e testing |
| `nvpn-reflector` | Minimal UDP reflector used for NAT discovery and hole-punch testing |
| `nostr-vpn-core` | Shared library for config, signaling, NAT helpers, diagnostics, MagicDNS, and WireGuard helpers |

## Downloads

Most people on macOS want the desktop app:

- [Download the latest macOS app (Apple Silicon)](https://github.com/mmalmi/nostr-vpn/releases/latest/download/nostr-vpn-macos-arm64.zip)
- [See the latest release notes and all assets](https://github.com/mmalmi/nostr-vpn/releases/latest)

If you want the headless CLI instead:

- [macOS Apple Silicon CLI](https://github.com/mmalmi/nostr-vpn/releases/latest/download/nvpn-aarch64-apple-darwin.tar.gz)
- [Linux x86_64 CLI](https://github.com/mmalmi/nostr-vpn/releases/latest/download/nvpn-x86_64-unknown-linux-musl.tar.gz)
- [Linux ARM64 CLI](https://github.com/mmalmi/nostr-vpn/releases/latest/download/nvpn-aarch64-unknown-linux-musl.tar.gz)

Prebuilt Intel macOS release artifacts have been sunset. Intel Mac users should build from source or use an older release.

The CLI release installer and auto-detect command are intended for Apple Silicon macOS and Linux. GitHub Releases currently publish CLI tarballs for macOS Apple Silicon, Linux x86_64, and Linux ARM64. The desktop GUI release is Apple Silicon macOS only.

## What the project does today

- Generates both Nostr identity keys and WireGuard keys automatically
- Stores a single app config with one or more named networks, each with participant allowlists and its own stable mesh ID
- Publishes and consumes private peer announcements over Nostr relays
- Brings up userspace WireGuard tunnels via `boringtun`
- Tracks peer endpoints, including NAT-discovered public endpoints and hole-punch attempts
- Supports route advertisement and exit-node selection
- Exposes JSON status, relay checks, network diagnostics, and doctor bundles
- Includes a desktop GUI with service-first session control, invite QR/import flows, tray integration, autostart, LAN discovery, MagicDNS controls, health reporting, and port-mapping status
- Includes Linux-focused Docker e2e coverage for signaling, mesh formation, NAT traversal, and exit-node routing

## Default relays

These are compiled into `nostr-vpn-core` and used when a config does not specify its own relay list:

- `wss://temp.iris.to`
- `wss://relay.damus.io`
- `wss://nos.lol`
- `wss://relay.primal.net`

## Config model

By default, `nvpn` uses the OS config directory:

- Linux: `~/.config/nvpn/config.toml`
- macOS: `~/Library/Application Support/nvpn/config.toml`
- Fallback when no config dir is available: `./nvpn.toml`

`nvpn init` creates that file if it does not exist and generates keys automatically.

The config contains:

- global app settings such as autoconnect, LAN discovery, tray behavior, and MagicDNS suffix
- Nostr settings including relay URLs and identity keys
- NAT settings including STUN servers, reflectors, and discovery timeout
- node settings including endpoint, tunnel IP, listen port, and advertised routes
- a `[[networks]]` list of named participant sets with one active network at a time

Each `[[networks]]` entry carries its own `network_id`, which is the mesh identity used for private signaling and auto-derived tunnel addressing. If an older config still only has the legacy top-level default, `nostr-vpn` promotes it into per-network stable IDs and then stops recomputing them on participant changes.

Nodes that should talk to each other must share the same `network_id` and list each other as participants. Only the active network participates in the live runtime; inactive networks stay saved for later activation.

## Build and validate

Prerequisites:

- Rust stable
- Node 22 + `corepack`/`pnpm` for the GUI
- OS permissions to create tunnel interfaces when running real sessions
- On Linux Docker e2e: Docker with Compose and `/dev/net/tun`

CI currently runs:

```bash
corepack enable
pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile
pnpm --dir crates/nostr-vpn-gui build

cargo fmt --check
cargo clippy --workspace --exclude nostr-vpn-gui --all-targets -- -D warnings
cargo test --workspace --exclude nostr-vpn-gui
```

Useful extra local validation when touching the Tauri shell:

```bash
cargo check -p nostr-vpn-gui
```

If you only want the CLI and test binaries:

```bash
cargo build -p nostr-vpn-cli -p nostr-vpn-relay
```

## Install `nvpn`

Quick install for released headless CLI builds on Apple Silicon macOS and Linux:

```bash
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) ASSET=nvpn-aarch64-apple-darwin.tar.gz ;;
  Linux/x86_64) ASSET=nvpn-x86_64-unknown-linux-musl.tar.gz ;;
  Linux/aarch64|Linux/arm64) ASSET=nvpn-aarch64-unknown-linux-musl.tar.gz ;;
  Darwin/x86_64)
    echo "Prebuilt Intel macOS releases have been sunset. Build from source or use an older release." >&2
    exit 1
    ;;
  *)
    echo "Unsupported platform: $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac
curl -fsSL "https://github.com/mmalmi/nostr-vpn/releases/latest/download/${ASSET}" | tar -xz && cd nvpn && ./install.sh
```

That auto-detect command is valid on Apple Silicon macOS and Linux. On Intel macOS it exits with a clear message instead of fetching a missing artifact. The bundled installer creates the target directory when needed and defaults to `/opt/homebrew/bin` on Apple Silicon macOS when that location is present or already in `PATH`; otherwise it uses `/usr/local/bin`.

From source:

```bash
cargo install --path crates/nostr-vpn-cli --bin nvpn
```

That source install path is the supported route on Intel macOS.

If you already have a packaged CLI release artifact, extract it and run:

```bash
./install.sh
```

You can also pass a custom destination directory to the bundled installer, for example `./install.sh ~/.local/bin`.

If you want the desktop app instead of the headless CLI flow, use the direct macOS download in the Downloads section above.

## CLI quickstart

Create or refresh config and generate keys:

```bash
nvpn init \
  --participant npub1...alice \
  --participant npub1...bob
```

Adjust persisted settings if needed:

```bash
nvpn set \
  --relay ws://127.0.0.1:8080 \
  --endpoint 192.0.2.10:51820 \
  --tunnel-ip 10.44.0.10/32
```

Run a full foreground session:

```bash
nvpn connect
```

If you only want to publish presence or bring the node down without running the full long-lived session, use:

```bash
nvpn up
nvpn down
```

Or run the daemonized flow the GUI also uses:

```bash
nvpn start --daemon --connect
nvpn pause
nvpn resume
nvpn stop
```

If you want persistent privileged startup without repeated prompts, install the system service once:

```bash
sudo nvpn service install
nvpn service status
```

On Windows, run `nvpn service install` from an elevated shell instead of using `sudo`.

The service implementation targets:

- macOS via `launchd`
- Linux via `systemd`
- Windows via the Service Control Manager (`sc.exe`)

`nvpn service enable` / `nvpn service disable` are currently implemented only on macOS. On Linux and Windows, `install` / `uninstall` handle the persistent service lifecycle directly.

Inspect runtime state:

```bash
nvpn status --json
nvpn netcheck --json
nvpn doctor --json
```

Write a support bundle:

```bash
nvpn doctor --write-bundle /tmp/nvpn-doctor
```

Advertise routes or use an exit node:

```bash
nvpn set --advertise-routes 10.0.0.0/24,192.168.0.0/24
nvpn set --advertise-exit-node true
nvpn set --exit-node npub1...peer
```

Clear exit-node selection:

```bash
nvpn set --exit-node off
```

Low-level helper commands are also available when you want to work below the daemon/session layer:

- `announce`
- `listen`
- `render-wg`
- `keygen`
- `init`
- `nat-discover`
- `hole-punch`
- `ping`
- `ip`
- `whois`

## Desktop GUI

The GUI lives in [`crates/nostr-vpn-gui`](crates/nostr-vpn-gui) and is a Tauri app backed by the same config and daemon used by `nvpn`.

<p align="center">
  <img src="docs/images/desktop-gui-overview.png" alt="Nostr VPN desktop app showing a connected network, device identity, status badges, and join controls." width="900">
</p>

Run it in development:

```bash
corepack enable
pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile
pnpm --dir crates/nostr-vpn-gui tauri:dev
```

Build a packaged app:

```bash
pnpm --dir crates/nostr-vpn-gui tauri:build
```

Important behavior:

- `tauri:dev` and `tauri:build` automatically prepare an `nvpn` sidecar binary
- the frontend does not run the VPN runtime itself; it shells out to `nvpn`
- the app is service-first on supported platforms: install the background service first, then use the app for normal on/off control
- the GUI exposes network membership, invite QR/import flows, relay state, session health, MagicDNS, exit-node selection, advertised routes, LAN discovery, autostart, and tray controls

You can override which CLI binary the GUI uses with `NVPN_CLI_PATH`.

## Local relay and NAT test binaries

For local integration testing without public infrastructure:

Run a websocket relay:

```bash
cargo run -p nostr-vpn-relay --bin nostr-vpn-relay -- --bind 127.0.0.1:8080
```

Run a UDP reflector:

```bash
cargo run -p nostr-vpn-relay --bin nvpn-reflector -- --bind 127.0.0.1:3478
```

The reflector is what `nvpn nat-discover` and `nvpn hole-punch` are designed to test against in local and Docker e2e setups.

## Docker end-to-end coverage

The repo includes several real integration paths under [`scripts/`](scripts):

- `./scripts/e2e-docker.sh`
  Verifies relay connectivity, `announce`/`listen`, manual `tunnel-up`, and ping across two containers.
- `./scripts/e2e-connect-docker.sh`
  Verifies config-driven `nvpn connect`, mesh formation, relay pause-on-mesh-ready behavior, and tunnel ping.
- `./scripts/e2e-active-network-docker.sh`
  Verifies that inactive saved networks do not change the active mesh identity, expected peer count, or auto-derived tunnel IP.
- `./scripts/e2e-divergent-roster-docker.sh`
  Verifies that peers with a shared mesh ID can still connect when one node has extra configured participants.
- `./scripts/e2e-nat-docker.sh`
  Verifies daemon mode across separate Docker NATs, public endpoint discovery, handshake success, and ping.
- `./scripts/e2e-exit-node-docker.sh`
  Verifies exit-node advertisement, selection, tunnel traffic to the chosen exit node, and default-route traffic crossing the exit path to an external target. Set `NVPN_EXIT_NODE_E2E_PUBLIC_IP=9.9.9.9` (or another reachable public IP) to also prove a real internet hop routes through the tunnel.
- `./scripts/e2e-tauri-driver-docker.sh`
  Builds the GUI in a Linux container, runs a Tauri-driver smoke test, and writes a screenshot to `artifacts/screenshots/tauri-driver-e2e.png`.

The Docker e2e flows are Linux-oriented because they require real tunnel devices and container networking privileges.

## Workspace layout

- [`Cargo.toml`](Cargo.toml): workspace definition
- [`crates/nostr-vpn-core`](crates/nostr-vpn-core): shared config, signaling, diagnostics, MagicDNS, NAT, and WireGuard helpers
- [`crates/nostr-vpn-cli`](crates/nostr-vpn-cli): `nvpn` CLI and daemon implementation
- [`crates/nostr-vpn-gui`](crates/nostr-vpn-gui): Tauri/Svelte desktop app
- [`crates/nostr-vpn-relay`](crates/nostr-vpn-relay): test relay and reflector binaries
- [`scripts`](scripts): Docker and GUI smoke-test entrypoints

## Release workflow notes

The release workflow in [`.github/workflows/release.yml`](.github/workflows/release.yml):

- runs on pushed `v*` tags or manual dispatch
- verifies frontend build, formatting, clippy, and tests before publishing artifacts
- publishes macOS and Linux CLI archives as `nvpn-<target>.tar.gz`
- publishes Apple Silicon macOS as `nostr-vpn-macos-arm64.zip` containing a signed, notarized `Nostr VPN.app`
- requires the macOS signing and notarization secrets to be configured before a release can publish the macOS app
- uses autogenerated GitHub release notes
