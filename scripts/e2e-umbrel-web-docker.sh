#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="${NVPN_UMBREL_WEB_E2E_PROJECT:-nostr-vpn-e2e-umbrel-web}"
PORT="${NVPN_UMBREL_WEB_PORT:-38180}"
IMAGE="${NOSTR_VPN_IMAGE:-nostr-vpn-umbrel-web-e2e:local}"
DATA_DIR_CREATED=false

if [[ -n "${NVPN_UMBREL_WEB_DATA_DIR:-}" ]]; then
  DATA_DIR="$NVPN_UMBREL_WEB_DATA_DIR"
  mkdir -p "$DATA_DIR"
else
  DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nostr-vpn-umbrel-web-e2e.XXXXXX")"
  DATA_DIR_CREATED=true
fi

COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/umbrel/docker-compose.local.yml")
export NOSTR_VPN_IMAGE="$IMAGE"
export NOSTR_VPN_WEB_PORT="$PORT"
export NOSTR_VPN_DATA_DIR="$DATA_DIR"

dump_debug() {
  set +e
  echo "umbrel web e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  "${COMPOSE[@]}" logs --no-color --tail 200 web || true
  "${COMPOSE[@]}" exec -T web sh -lc 'cat /data/config/nvpn/config.toml 2>/dev/null || true' || true
}

cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    dump_debug
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$DATA_DIR_CREATED" == true ]]; then
    rm -rf "$DATA_DIR"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "umbrel web e2e failed: timed out waiting for $url" >&2
  return 1
}

read_temp_peer_npub() {
  "${COMPOSE[@]}" exec -T web sh -lc '
    rm -f /tmp/nvpn-web-peer.toml
    nvpn init --config /tmp/nvpn-web-peer.toml --force >/dev/null
    awk "
      /^\\[nostr\\]$/ { in_nostr = 1; next }
      /^\\[/ { in_nostr = 0 }
      in_nostr && /^public_key[[:space:]]*=/ {
        print \$3;
        exit
      }
    " /tmp/nvpn-web-peer.toml
  ' | tr -d '\r"'
}

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
case "${NVPN_UMBREL_WEB_E2E_SKIP_BUILD:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) "${COMPOSE[@]}" up -d web ;;
  *) "${COMPOSE[@]}" up --build -d web ;;
esac
wait_for_http "http://127.0.0.1:$PORT/api/health"

PEER_NPUB="$(read_temp_peer_npub)"
if [[ -z "$PEER_NPUB" ]]; then
  echo "umbrel web e2e failed: unable to generate temp peer npub" >&2
  exit 1
fi

env -u NO_COLOR pnpm --dir "$ROOT_DIR/web/control-panel" exec playwright install chromium

PLAYWRIGHT_ARGS=("$@")
if ((${#PLAYWRIGHT_ARGS[@]} == 0)); then
  PLAYWRIGHT_ARGS=(e2e/umbrel-web.spec.ts)
fi
NVPN_UMBREL_WEB_BASE_URL="http://127.0.0.1:$PORT" \
NVPN_UMBREL_WEB_PEER_NPUB="$PEER_NPUB" \
  env -u NO_COLOR pnpm --dir "$ROOT_DIR/web/control-panel" exec playwright test \
    "${PLAYWRIGHT_ARGS[@]}"

echo "umbrel web docker e2e passed: bundled UI loaded and API config actions matched the expected web control surface"
