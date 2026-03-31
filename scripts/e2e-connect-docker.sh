#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.e2e.yml")

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

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" ]]; then
  echo "connect e2e failed: unable to resolve node npubs from config" >&2
  exit 1
fi

"${COMPOSE[@]}" exec -T node-a nvpn set \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --relay "$RELAY_URL" \
  --endpoint 10.203.0.10:51820 \
  --tunnel-ip 10.44.0.10/32 >/dev/null

"${COMPOSE[@]}" exec -T node-b nvpn set \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --relay "$RELAY_URL" \
  --endpoint 10.203.0.11:51820 \
  --tunnel-ip 10.44.0.11/32 >/dev/null

"${COMPOSE[@]}" exec -T node-a sh -lc "nvpn connect > /tmp/connect.log 2>&1 &"
"${COMPOSE[@]}" exec -T node-b sh -lc "nvpn connect > /tmp/connect.log 2>&1 &"

for _ in $(seq 1 20); do
  ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
  BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

  if grep -q "mesh: 1/1 peers with presence" <<<"$ALICE_CONNECT_LOGS" \
    && grep -q "mesh: 1/1 peers with presence" <<<"$BOB_CONNECT_LOGS"; then
    break
  fi

  sleep 1
done

ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

if ! grep -q "mesh: 1/1 peers with presence" <<<"$ALICE_CONNECT_LOGS"; then
  echo "connect e2e failed: alice mesh did not reach 1/1" >&2
  echo "$ALICE_CONNECT_LOGS"
  exit 1
fi

if ! grep -q "mesh: 1/1 peers with presence" <<<"$BOB_CONNECT_LOGS"; then
  echo "connect e2e failed: bob mesh did not reach 1/1" >&2
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

sleep 2

if ! "${COMPOSE[@]}" exec -T node-a ping -c 3 -W 2 10.44.0.11 >/tmp/ping-a.log; then
  echo "connect e2e failed: ping A -> B failed" >&2
  echo "$ALICE_CONNECT_LOGS"
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

if ! "${COMPOSE[@]}" exec -T node-b ping -c 3 -W 2 10.44.0.10 >/tmp/ping-b.log; then
  echo "connect e2e failed: ping B -> A failed" >&2
  echo "$ALICE_CONNECT_LOGS"
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

if grep -q "Mesh ready (relays paused)" <<<"$ALICE_CONNECT_LOGS"; then
  echo "connect e2e failed: alice still paused relays after mesh became ready" >&2
  echo "$ALICE_CONNECT_LOGS"
  exit 1
fi

if grep -q "Mesh ready (relays paused)" <<<"$BOB_CONNECT_LOGS"; then
  echo "connect e2e failed: bob still paused relays after mesh became ready" >&2
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

echo "--- Alice connect log ---"
echo "$ALICE_CONNECT_LOGS"
echo "--- Bob connect log ---"
echo "$BOB_CONNECT_LOGS"
echo "--- Ping A -> B ---"
cat /tmp/ping-a.log
echo "--- Ping B -> A ---"
cat /tmp/ping-b.log

echo "connect docker e2e passed: config-driven nvpn connect kept relays available while the boringtun tunnel stayed up"
