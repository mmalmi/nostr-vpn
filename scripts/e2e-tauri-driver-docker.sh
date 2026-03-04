#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="nostr-vpn-tauri-e2e"

cd "$ROOT_DIR"

docker build -f Dockerfile.tauri-driver-e2e -t "$IMAGE_NAME" .

docker rm -f "$IMAGE_NAME-run" >/dev/null 2>&1 || true

docker run --rm \
  --name "$IMAGE_NAME-run" \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "$ROOT_DIR:/work" \
  -w /work \
  "$IMAGE_NAME" \
  bash -c "set -euo pipefail; \
    export CI=true; \
    export TAURI_DRIVER_BIN=/usr/local/cargo/bin/tauri-driver; \
    export TAURI_APP=/work/target/debug/nostr-vpn-gui; \
    export NVPN_BIN=/work/target/debug/nvpn; \
    export NVPN_RELAY_BIN=/work/target/debug/nostr-vpn-relay; \
    pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile; \
    cargo build -p nostr-vpn-cli -p nostr-vpn-relay; \
    pnpm --dir crates/nostr-vpn-gui exec tauri build --debug --no-bundle; \
    mkdir -p artifacts/screenshots; \
    timeout 300s xvfb-run -a -s '-screen 0 1920x1080x24' node crates/nostr-vpn-gui/e2e-tauri/smoke.mjs"
