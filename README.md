# nostr-vpn

`nostr-vpn` is a Tailscale-style control plane on Nostr with:

- `nvpn`: multiplatform CLI
- `nostr-vpn-gui`: multiplatform desktop GUI (macOS-first UX)
- `nostr-vpn-core`: shared core logic (boringtun keying + Nostr signaling)

## What is implemented

- Boringtun key generation and handshake simulation (`boringtun::noise::Tunn`)
- Nostr relay signaling client and message envelope
- Network membership based on participant Nostr pubkeys (npub/hex allowlist)
- Deterministic network IDs derived from participant pubkeys
- Automatic key generation for both WireGuard and Nostr identities
- GUI with topbar controls + settings dialog
- Docker e2e that validates signaling + data-plane ping across 2 containers

## Default relays

Defaults match `~/src/hashtree`:

- `wss://temp.iris.to`
- `wss://relay.damus.io`
- `wss://nos.lol`
- `wss://relay.primal.net`
- `wss://offchain.pub`

## Quickstart

### 1. Build and test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### 2. Create config (auto-keygen)

```bash
nvpn init \
  --participant npub1...alice \
  --participant npub1...bob
```

This writes config to `~/.config/nvpn/config.toml`.

### 3. Bring node up

```bash
nvpn up --endpoint 203.0.113.10:51820 --tunnel-ip 10.44.0.2/32
```

### 4. Check status

```bash
nvpn status --json
```

### 5. Render WireGuard config

```bash
nvpn render-wg \
  --peer "<wg-pubkey>,10.44.0.3/32,198.51.100.20:51820"
```

### 6. Start GUI

```bash
cargo run -p nostr-vpn-gui
```

Use the topbar controls (`Menu`, `Connect`, `Announce`, `Settings`).

## CLI commands

`nvpn` includes these Tailscale-style commands:

- `up`
- `down`
- `status`
- `set`
- `ping`
- `netcheck`
- `ip`
- `whois`

Legacy control-plane commands are still available:

- `announce`
- `listen`
- `render-wg`
- `tunnel-up`
- `keygen`
- `init`

## Install from release

```bash
REPO=<owner>/<repo>
curl -fsSL "https://github.com/${REPO}/releases/latest/download/nvpn-$(uname -m | sed 's/arm64/aarch64/')-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/apple-darwin/' | sed 's/linux/unknown-linux-musl/').tar.gz" | tar -xz
cd nvpn && ./install.sh
```

## Docker e2e

Run a real cross-container signaling + tunnel check (relay + 2 nodes):

```bash
./scripts/e2e-docker.sh
```

What it validates:

- Relay container accepts Nostr websocket connections
- Two nodes exchange announcements over Nostr
- Both nodes bring up boringtun interfaces (`tunnel-up`)
- Tunnel data plane works (`ping` over `10.44.0.1 <-> 10.44.0.2`)

## GitHub release signing/notarization (optional)

The release workflow supports optional macOS signing + notarization when these secrets are set:

- `MACOS_SIGNING_IDENTITY`
- `MACOS_CERTIFICATE_P12`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD` (optional override)
- `MACOS_NOTARIZE_APPLE_ID`
- `MACOS_NOTARIZE_APP_PASSWORD`
- `MACOS_NOTARIZE_TEAM_ID`
