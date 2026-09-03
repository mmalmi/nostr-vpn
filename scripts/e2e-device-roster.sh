#!/usr/bin/env bash
# Native desktop-shell regression lane for accepting a phone-class join request.
# Transport-level desktop/mobile delivery and durable receipts are covered by
# the app-core cross-class tests in the release gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo test -p nostr-vpn-app-core websocket_seed_router_routes_new_recipient_without_preconverged_roster_peer
cargo test -p nostr-vpn-app-core two_websocket_seed_routers_route_new_recipient_without_preconverged_roster_peer

case "$(uname -s)" in
  Darwin)
    "$ROOT/scripts/e2e-desktop-roster-join.sh"
    "$ROOT/tools/run-linux" /workspace/nostr-vpn/scripts/e2e-desktop-roster-join.sh
    if ssh -o BatchMode=yes -o ConnectTimeout=5 "${NVPN_WINDOWS_SSH_HOST:-win11-dev}" hostname >/dev/null 2>&1; then
      "$ROOT/scripts/windows-vm-roster-e2e.sh"
    else
      echo "Skipping Windows roster GUI because its test VM is unavailable."
    fi
    ;;
  Linux)
    "$ROOT/tools/run-linux" /workspace/nostr-vpn/scripts/e2e-desktop-roster-join.sh
    ;;
  *)
    echo "Run scripts/e2e-desktop-roster-join.ps1 directly on Windows." >&2
    exit 2
    ;;
esac

echo "DEVICE_ROSTER_E2E_OK"
