#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.e2e.yml")

NETWORK_ID="docker-vpn"
RELAY_URL="ws://10.203.0.2:8080"

ALICE_WG_PRIVATE="9eUzwIuYiF1Au6fBSwSnMHuWp90mqFQZrsC3YH7qzb8="
ALICE_WG_PUBLIC="8VBKKEKhzF7lPlukFYvpMsZX42RcgClBcwI1FpFTIRE="
BOB_WG_PRIVATE="3DnM5OoFTb2DgGQ/BPAM0W8+xKUExtxA1l5jXloihO0="
BOB_WG_PUBLIC="czraiWsRqvnjWLMoww0riN8uZa6By7EJl6swa5mY5To="

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

"${COMPOSE[@]}" build >/dev/null
"${COMPOSE[@]}" up -d relay node-a node-b >/dev/null
sleep 3

"${COMPOSE[@]}" exec -T node-a sh -lc \
  "nvpn listen --network-id '$NETWORK_ID' --relay '$RELAY_URL' --limit 1 > /tmp/listen.log 2>&1 &"
"${COMPOSE[@]}" exec -T node-b sh -lc \
  "nvpn listen --network-id '$NETWORK_ID' --relay '$RELAY_URL' --limit 1 > /tmp/listen.log 2>&1 &"

sleep 2

"${COMPOSE[@]}" exec -T node-a nvpn announce \
  --network-id "$NETWORK_ID" \
  --relay "$RELAY_URL" \
  --node-id alice-node \
  --endpoint 10.203.0.10:51820 \
  --tunnel-ip 10.44.0.1/32 \
  --public-key "$ALICE_WG_PUBLIC" >/dev/null

"${COMPOSE[@]}" exec -T node-b nvpn announce \
  --network-id "$NETWORK_ID" \
  --relay "$RELAY_URL" \
  --node-id bob-node \
  --endpoint 10.203.0.11:51820 \
  --tunnel-ip 10.44.0.2/32 \
  --public-key "$BOB_WG_PUBLIC" >/dev/null

for _ in $(seq 1 20); do
  ALICE_LISTEN_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/listen.log 2>/dev/null || true')"
  BOB_LISTEN_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/listen.log 2>/dev/null || true')"

  if grep -Eq '"node_id"\s*:\s*"bob-node"' <<<"$ALICE_LISTEN_LOGS" \
    && grep -Eq '"node_id"\s*:\s*"alice-node"' <<<"$BOB_LISTEN_LOGS"; then
    break
  fi

  sleep 1
done

ALICE_LISTEN_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/listen.log 2>/dev/null || true')"
BOB_LISTEN_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/listen.log 2>/dev/null || true')"

if ! grep -Eq '"node_id"\s*:\s*"bob-node"' <<<"$ALICE_LISTEN_LOGS"; then
  echo "docker e2e failed: alice did not receive bob announcement" >&2
  echo "$ALICE_LISTEN_LOGS"
  exit 1
fi

if ! grep -Eq '"node_id"\s*:\s*"alice-node"' <<<"$BOB_LISTEN_LOGS"; then
  echo "docker e2e failed: bob did not receive alice announcement" >&2
  echo "$BOB_LISTEN_LOGS"
  exit 1
fi

"${COMPOSE[@]}" exec -T node-a sh -lc \
  "nvpn tunnel-up \
     --iface utun100 \
     --private-key '$ALICE_WG_PRIVATE' \
     --listen-port 51820 \
     --address 10.44.0.1/32 \
     --peer-public-key '$BOB_WG_PUBLIC' \
     --peer-endpoint 10.203.0.11:51820 \
     --peer-allowed-ip 10.44.0.2/32 \
     --keepalive-secs 1 > /tmp/tunnel.log 2>&1 &"

"${COMPOSE[@]}" exec -T node-b sh -lc \
  "nvpn tunnel-up \
     --iface utun100 \
     --private-key '$BOB_WG_PRIVATE' \
     --listen-port 51820 \
     --address 10.44.0.2/32 \
     --peer-public-key '$ALICE_WG_PUBLIC' \
     --peer-endpoint 10.203.0.10:51820 \
     --peer-allowed-ip 10.44.0.1/32 \
     --keepalive-secs 1 > /tmp/tunnel.log 2>&1 &"

sleep 5

"${COMPOSE[@]}" exec -T node-a ping -c 3 -W 2 10.44.0.2 >/tmp/ping-a.log
"${COMPOSE[@]}" exec -T node-b ping -c 3 -W 2 10.44.0.1 >/tmp/ping-b.log

echo "--- Alice listen log ---"
echo "$ALICE_LISTEN_LOGS"
echo "--- Bob listen log ---"
echo "$BOB_LISTEN_LOGS"
echo "--- Ping A -> B ---"
cat /tmp/ping-a.log
echo "--- Ping B -> A ---"
cat /tmp/ping-b.log

echo "docker e2e passed: announcements + boringtun tunnel data-plane ping succeeded"
