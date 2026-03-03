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
- Tauri + Svelte desktop GUI (single-pane settings UX)
- LAN multicast peer discovery helper (active when no participants are configured)
- GUI-managed boringtun tunnel orchestration on unix targets (applies peers from private Nostr announcements)
- Docker e2e that validates signaling + data-plane ping across 2 containers
- UDP NAT endpoint discovery + hole-punch helpers (reflector-based)

## Default relays

- `wss://temp.iris.to`
- `wss://relay.damus.io`
- `wss://nos.lol`
- `wss://relay.primal.net`
- `wss://offchain.pub`

## Quickstart

### 1. Build and test

```bash
cargo test --workspace --exclude nostr-vpn-gui
cargo clippy --workspace --exclude nostr-vpn-gui --all-targets -- -D warnings
pnpm --dir crates/nostr-vpn-gui install
pnpm --dir crates/nostr-vpn-gui build
cargo check -p nostr-vpn-gui
```

### 2. Install CLI locally (one-time)

```bash
cargo install --path crates/nostr-vpn-cli
```

### 3. Create config (auto-keygen)

```bash
nvpn init \
  --participant npub1...alice \
  --participant npub1...bob
```

This writes config to `~/.config/nvpn/config.toml`.

### 4. Bring node up

```bash
nvpn up
```

`nvpn up` auto-derives:

- tunnel IP from participant pubkeys
- endpoint from your local primary IP + listen port (when endpoint is still localhost)

You can still override with `--endpoint` / `--tunnel-ip` for advanced/manual setups.

### 5. Start a full tunnel session from config

```bash
nvpn connect
```

`nvpn connect` keeps running, consumes private peer announcements from your configured
participants, and applies boringtun interface/peer config automatically.

### 6. Check status

```bash
nvpn status --json
```

`status` reports relay policy and mesh progress, including whether
`auto_disconnect_relays_when_mesh_ready` is enabled (default: `true`).

### 7. Render WireGuard config

```bash
nvpn render-wg \
  --peer "<wg-pubkey>,10.44.0.3/32,198.51.100.20:51820"
```

### 8. Start GUI

```bash
pnpm --dir crates/nostr-vpn-gui install
pnpm --dir crates/nostr-vpn-gui tauri:dev
```

Note: bringing the tunnel interface up requires OS network privileges.
On Linux/macOS, run the app with permissions that allow interface/routing updates.

### 9. Run Tauri-driver UI smoke test (Docker)

```bash
./scripts/e2e-tauri-driver-docker.sh
```

This runs a Linux tauri-driver session against `nostr-vpn-gui`, performs core UI actions,
and writes a screenshot to `artifacts/screenshots/tauri-driver-smoke.png`.

## CLI commands

`nvpn` includes these Tailscale-style commands:

- `up`
- `connect`
- `down`
- `status`
- `set`
- `ping`
- `netcheck`
- `ip`
- `whois`
- `nat-discover`
- `hole-punch`

Legacy control-plane commands are still available:

- `announce`
- `listen`
- `render-wg`
- `keygen`
- `init`

## Install from release

```bash
REPO=<owner>/<repo>
curl -fsSL "https://github.com/${REPO}/releases/latest/download/nvpn-$(uname -m | sed 's/arm64/aarch64/')-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/apple-darwin/' | sed 's/linux/unknown-linux-musl/').tar.gz" | tar -xz
cd nvpn && ./install.sh
```

## Docker e2e

Requirements:

- Docker Engine with Compose plugin (`docker compose`)
- Linux environment with `/dev/net/tun` available

Run a real cross-container signaling + tunnel check (local relay + 2 nodes):

```bash
./scripts/e2e-docker.sh
```

Run config-driven CLI connect e2e (same `config.toml` flow GUI uses):

```bash
./scripts/e2e-connect-docker.sh
```

What it validates:

- Relay container accepts Nostr websocket connections
- Two nodes exchange announcements over Nostr
- Both nodes bring up boringtun interfaces (`tunnel-up`)
- Tunnel data plane works (`ping` over `10.44.0.1 <-> 10.44.0.2`)

## NAT traversal helpers

Discover the public UDP endpoint (through a reflector):

```bash
nvpn nat-discover --reflector 198.51.100.10:3478 --listen-port 51820
```

Send punch packets to a peer endpoint:

```bash
nvpn hole-punch --listen-port 51820 --peer-endpoint 198.51.100.20:51820
```

`tunnel-up` can pre-punch automatically:

```bash
nvpn tunnel-up ... \
  --hole-punch-attempts 40 \
  --hole-punch-interval-ms 120
```

Run NAT-focused docker e2e:

```bash
./scripts/e2e-nat-docker.sh
```

This e2e uses two NAT router containers with deterministic UDP/51820 mapping to verify:
private Nostr signaling, endpoint discovery, pre-punch, and boringtun tunnel ping.

## GitHub release signing/notarization (optional)

The release workflow supports optional macOS signing + notarization when these secrets are set:

- `MACOS_SIGNING_IDENTITY`
- `MACOS_CERTIFICATE_P12`
- `MACOS_CERTIFICATE_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD` (optional override)
- `MACOS_NOTARIZE_APPLE_ID`
- `MACOS_NOTARIZE_APP_PASSWORD`
- `MACOS_NOTARIZE_TEAM_ID`
