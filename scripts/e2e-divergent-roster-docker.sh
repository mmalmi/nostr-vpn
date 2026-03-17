#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.e2e.yml")

NETWORK_ID="docker-divergent-roster"
RELAY_URL="ws://10.203.0.2:8080"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

"${COMPOSE[@]}" build >/dev/null
"${COMPOSE[@]}" up -d relay node-a node-b >/dev/null
sleep 3

ALICE_NPUB="$("${COMPOSE[@]}" exec -T node-a sh -lc \
  "nvpn init --force >/dev/null && grep -m1 '^public_key' /root/.config/nvpn/config.toml | cut -d '\"' -f 2")"
BOB_NPUB="$("${COMPOSE[@]}" exec -T node-b sh -lc \
  "nvpn init --force >/dev/null && grep -m1 '^public_key' /root/.config/nvpn/config.toml | cut -d '\"' -f 2")"
PHANTOM_NPUB="$("${COMPOSE[@]}" exec -T node-a sh -lc \
  "rm -f /tmp/phantom.toml && nvpn init --config /tmp/phantom.toml --force >/dev/null && grep -m1 '^public_key' /tmp/phantom.toml | cut -d '\"' -f 2")"

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" || -z "$PHANTOM_NPUB" ]]; then
  echo "divergent roster e2e failed: unable to resolve participant npubs" >&2
  exit 1
fi

"${COMPOSE[@]}" exec -T node-a nvpn set \
  --network-id "$NETWORK_ID" \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --participant "$PHANTOM_NPUB" \
  --relay "$RELAY_URL" \
  --endpoint 10.203.0.10:51820 >/dev/null

"${COMPOSE[@]}" exec -T node-b nvpn set \
  --network-id "$NETWORK_ID" \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --relay "$RELAY_URL" \
  --endpoint 10.203.0.11:51820 >/dev/null

ALICE_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-a nvpn ip)"
BOB_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-b nvpn ip)"

if [[ -z "$ALICE_TUNNEL_IP" || -z "$BOB_TUNNEL_IP" ]]; then
  echo "divergent roster e2e failed: auto tunnel IP lookup returned empty result" >&2
  exit 1
fi

"${COMPOSE[@]}" exec -T node-a sh -lc "nvpn connect > /tmp/connect.log 2>&1 &"
"${COMPOSE[@]}" exec -T node-b sh -lc "nvpn connect > /tmp/connect.log 2>&1 &"

for _ in $(seq 1 30); do
  ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
  BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

  if grep -q "mesh: 1/2 peers with presence" <<<"$ALICE_CONNECT_LOGS" \
    && grep -q "mesh: 1/1 peers with presence" <<<"$BOB_CONNECT_LOGS"; then
    break
  fi

  sleep 1
done

ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

if ! grep -q "mesh: 1/2 peers with presence" <<<"$ALICE_CONNECT_LOGS"; then
  echo "divergent roster e2e failed: alice did not report degraded 1/2 mesh state" >&2
  echo "$ALICE_CONNECT_LOGS"
  exit 1
fi

if ! grep -q "mesh: 1/1 peers with presence" <<<"$BOB_CONNECT_LOGS"; then
  echo "divergent roster e2e failed: bob did not report 1/1 mesh state" >&2
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

PING_OK=false
for _ in $(seq 1 20); do
  if "${COMPOSE[@]}" exec -T node-a ping -c 1 -W 2 "$BOB_TUNNEL_IP" >/tmp/ping-a.log 2>&1 \
    && "${COMPOSE[@]}" exec -T node-b ping -c 1 -W 2 "$ALICE_TUNNEL_IP" >/tmp/ping-b.log 2>&1; then
    PING_OK=true
    break
  fi

  sleep 1
done

if [[ "$PING_OK" != true ]]; then
  echo "divergent roster e2e failed: overlapping peers never established a tunnel" >&2
  echo "--- Alice connect log ---"
  echo "$ALICE_CONNECT_LOGS"
  echo "--- Bob connect log ---"
  echo "$BOB_CONNECT_LOGS"
  if [[ -f /tmp/ping-a.log ]]; then
    echo "--- Ping A -> B ---"
    cat /tmp/ping-a.log
  fi
  if [[ -f /tmp/ping-b.log ]]; then
    echo "--- Ping B -> A ---"
    cat /tmp/ping-b.log
  fi
  exit 1
fi

echo "--- Alice connect log ---"
echo "$ALICE_CONNECT_LOGS"
echo "--- Bob connect log ---"
echo "$BOB_CONNECT_LOGS"
echo "--- Alice tunnel IP ---"
echo "$ALICE_TUNNEL_IP"
echo "--- Bob tunnel IP ---"
echo "$BOB_TUNNEL_IP"
echo "--- Ping A -> B ---"
cat /tmp/ping-a.log
echo "--- Ping B -> A ---"
cat /tmp/ping-b.log

echo "divergent roster docker e2e passed: overlapping peers connected with a shared mesh ID while extra participants stayed degraded"
