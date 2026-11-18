#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="nostr-vpn-e2e-basic"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.e2e.yml")

NETWORK_ID="docker-vpn"
FIPS_HOST_IFACE="utun100"
FIPS_HOST_MTU="1280"
FIPS_HOST_TCP_PORT="18080"
FIPS_HOST_BLOCKED_TCP_PORT="18081"
FIPS_HOST_TCP_PAYLOAD="alice-to-bob-fips-tcp"
FIPS_HOST_BLOCKED_TCP_PAYLOAD="blocked-fips-tcp"
FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT_NAME}_e2e" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    docker network inspect "${PROJECT_NAME}_e2e" >/dev/null 2>&1 || break
    sleep 1
  done
}
trap cleanup EXIT

wait_for_service() {
  local service="$1"
  local container_id=""
  for _ in $(seq 1 30); do
    container_id="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_id" ]] \
      && [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" == "true" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "docker e2e failed: service '$service' did not reach running state" >&2
  exit 1
}

nostr_pubkey_from_config() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -lc "
    awk '
      /^\\[nostr\\]$/ { in_nostr = 1; next }
      /^\\[/ { in_nostr = 0 }
      in_nostr && /^public_key[[:space:]]*=/ {
        print \$3;
        exit
      }
    ' /root/.config/nvpn/config.toml
  " | tr -d '\r\"'
}

fips_dns_aaaa() {
  local service="$1"
  local npub="$2"
  "${COMPOSE[@]}" exec -T "$service" sh -lc "dig +time=1 +tries=1 @127.0.0.55 -p 53 +short AAAA '${npub}.fips' 2>/dev/null | awk '/^[0-9A-Fa-f:]+$/ { print; exit }'" | tr -d '\r'
}

wait_for_fips_dns_aaaa() {
  local service="$1"
  local npub="$2"
  local resolved=""
  for _ in $(seq 1 20); do
    resolved="$(fips_dns_aaaa "$service" "$npub")"
    if [[ -n "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
    sleep 1
  done
  return 1
}

start_nvpn_connect() {
  local service="$1"
  local reset_log="${2:-false}"
  local command="nvpn connect > /tmp/connect.log 2>&1"

  if [[ "$reset_log" == "true" ]]; then
    command="rm -f /tmp/connect.log; $command"
  fi

  "${COMPOSE[@]}" exec -d \
    -e "NVPN_FIPS_NOSTR_DISCOVERY_POLICY=$FIPS_NOSTR_DISCOVERY_POLICY" \
    "$service" sh -lc "$command"
}

assert_fips_host_tunnel() {
  local service="$1"
  local peer_npub="$2"
  local fips_link fips_route resolved

  fips_link="$("${COMPOSE[@]}" exec -T "$service" ip link show dev "$FIPS_HOST_IFACE")"
  fips_route="$("${COMPOSE[@]}" exec -T "$service" ip -6 route show fd00::/8 || true)"

  if ! grep -q "mtu $FIPS_HOST_MTU" <<<"$fips_link"; then
    echo "docker e2e failed: $service integrated tunnel did not keep MTU $FIPS_HOST_MTU" >&2
    echo "$fips_link" >&2
    exit 1
  fi
  if ! grep -q "dev $FIPS_HOST_IFACE" <<<"$fips_route"; then
    echo "docker e2e failed: $service fd00::/8 route did not use $FIPS_HOST_IFACE" >&2
    echo "$fips_route" >&2
    exit 1
  fi
  resolved="$(wait_for_fips_dns_aaaa "$service" "$peer_npub" || true)"
  if [[ -z "$resolved" ]]; then
    echo "docker e2e failed: $service could not resolve ${peer_npub}.fips" >&2
    exit 1
  fi
}

assert_fips_firewall_rules() {
  local service="$1"
  local expected_tcp_port="${2:-}"
  local rules

  rules="$("${COMPOSE[@]}" exec -T "$service" nft list table inet nvpn_fips_host)"
  for expected in \
    "table inet nvpn_fips_host" \
    "iifname != \"$FIPS_HOST_IFACE\" return" \
    "oifname != \"$FIPS_HOST_IFACE\" return" \
    "ip6 saddr != fd00::/8 return" \
    "ip6 daddr != fd00::/8 return" \
    "meta l4proto tcp accept"; do
    if ! grep -q "$expected" <<<"$rules"; then
      echo "docker e2e failed: $service .fips firewall missing rule: $expected" >&2
      echo "$rules" >&2
      exit 1
    fi
  done

  if [[ -n "$expected_tcp_port" ]]; then
    if ! grep -q "tcp dport $expected_tcp_port accept" <<<"$rules"; then
      echo "docker e2e failed: $service .fips firewall missing inbound TCP port $expected_tcp_port" >&2
      echo "$rules" >&2
      exit 1
    fi
  elif grep -q "tcp dport .* accept" <<<"$rules"; then
    echo "docker e2e failed: $service .fips firewall unexpectedly allows inbound TCP ports" >&2
    echo "$rules" >&2
    exit 1
  fi
}

assert_fips_tcp_crosses() {
  local peer_npub="$1"
  local peer_fips_ip=""

  peer_fips_ip="$(wait_for_fips_dns_aaaa node-a "$peer_npub" || true)"
  if [[ -z "$peer_fips_ip" ]]; then
    echo "docker e2e failed: alice could not resolve bob .fips address for TCP check" >&2
    exit 1
  fi

  "${COMPOSE[@]}" exec -T node-b sh -lc 'rm -f /tmp/bob-fips-tcp.out'
  "${COMPOSE[@]}" exec -d node-b sh -lc "nc -6 -l -p '$FIPS_HOST_TCP_PORT' > /tmp/bob-fips-tcp.out"
  sleep 1

  for _ in $(seq 1 20); do
    printf '%s' "$FIPS_HOST_TCP_PAYLOAD" \
      | "${COMPOSE[@]}" exec -T node-a sh -lc "cat | nc -6 -w 3 '$peer_fips_ip' '$FIPS_HOST_TCP_PORT'" \
      >/dev/null 2>&1 || true
    if "${COMPOSE[@]}" exec -T node-b sh -lc "grep -q '$FIPS_HOST_TCP_PAYLOAD' /tmp/bob-fips-tcp.out 2>/dev/null"; then
      return 0
    fi
    sleep 1
  done

  echo "docker e2e failed: alice could not send TCP to bob over .fips" >&2
  echo "bob .fips address: $peer_fips_ip" >&2
  "${COMPOSE[@]}" exec -T node-a sh -lc "ip -6 route show fd00::/8; ip link show dev '$FIPS_HOST_IFACE'" >&2 || true
  "${COMPOSE[@]}" exec -T node-b sh -lc "ip -6 route show fd00::/8; ip link show dev '$FIPS_HOST_IFACE'; cat /tmp/bob-fips-tcp.out 2>/dev/null || true" >&2 || true
  exit 1
}

assert_fips_tcp_blocked() {
  local source_service="$1"
  local target_service="$2"
  local target_fips_ip="$3"
  local target_port="$4"
  local payload="$5"
  local output_path="/tmp/${target_service}-${target_port}-blocked.out"

  "${COMPOSE[@]}" exec -T "$target_service" sh -lc "rm -f '$output_path'"
  "${COMPOSE[@]}" exec -d "$target_service" sh -lc "nc -6 -l -p '$target_port' > '$output_path'"
  sleep 1

  printf '%s' "$payload" \
    | "${COMPOSE[@]}" exec -T "$source_service" sh -lc "cat | nc -6 -w 2 '$target_fips_ip' '$target_port'" \
    >/dev/null 2>&1 || true
  sleep 1

  if "${COMPOSE[@]}" exec -T "$target_service" sh -lc "grep -q '$payload' '$output_path' 2>/dev/null"; then
    echo "docker e2e failed: $source_service reached blocked .fips TCP port $target_port on $target_service" >&2
    "${COMPOSE[@]}" exec -T "$source_service" sh -lc "nft list table inet nvpn_fips_host; ip -6 route show fd00::/8" >&2 || true
    "${COMPOSE[@]}" exec -T "$target_service" sh -lc "nft list table inet nvpn_fips_host; ip -6 route show fd00::/8; cat '$output_path' 2>/dev/null || true" >&2 || true
    exit 1
  fi
}

assert_fips_firewall_blocks() {
  local alice_fips_ip bob_fips_ip

  alice_fips_ip="$(wait_for_fips_dns_aaaa node-b "$ALICE_NPUB" || true)"
  bob_fips_ip="$(wait_for_fips_dns_aaaa node-a "$BOB_NPUB" || true)"
  if [[ -z "$alice_fips_ip" || -z "$bob_fips_ip" ]]; then
    echo "docker e2e failed: could not resolve .fips addresses for firewall checks" >&2
    exit 1
  fi

  assert_fips_tcp_blocked node-a node-b "$bob_fips_ip" "$FIPS_HOST_BLOCKED_TCP_PORT" "$FIPS_HOST_BLOCKED_TCP_PAYLOAD"
  assert_fips_tcp_blocked node-b node-a "$alice_fips_ip" "$FIPS_HOST_TCP_PORT" "$FIPS_HOST_BLOCKED_TCP_PAYLOAD"

  if "${COMPOSE[@]}" exec -T node-a ping -6 -c 1 -W 1 "$bob_fips_ip" >/dev/null 2>&1; then
    echo "docker e2e failed: .fips firewall allowed non-TCP IPv6 ping" >&2
    "${COMPOSE[@]}" exec -T node-a sh -lc "nft list table inet nvpn_fips_host; ip -6 route show fd00::/8" >&2 || true
    "${COMPOSE[@]}" exec -T node-b sh -lc "nft list table inet nvpn_fips_host; ip -6 route show fd00::/8" >&2 || true
    exit 1
  fi
}

assert_fips_host_disabled() {
  local service="$1"
  local peer_npub="$2"
  local link route table dns

  for _ in $(seq 1 20); do
    link="$("${COMPOSE[@]}" exec -T "$service" sh -lc "ip link show dev '$FIPS_HOST_IFACE' 2>/dev/null || true")"
    route="$("${COMPOSE[@]}" exec -T "$service" sh -lc 'ip -6 route show fd00::/8 2>/dev/null || true')"
    table="$("${COMPOSE[@]}" exec -T "$service" sh -lc 'nft list table inet nvpn_fips_host >/dev/null 2>&1 && echo present || true')"
    dns="$(fips_dns_aaaa "$service" "$peer_npub" 2>/dev/null || true)"
    if [[ -n "$link" && -z "$route" && -z "$table" && -z "$dns" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "docker e2e failed: $service disabled .fips host tunnel left runtime state behind" >&2
  echo "--- link ---" >&2
  echo "$link" >&2
  echo "--- fd00::/8 route ---" >&2
  echo "$route" >&2
  echo "--- nft table ---" >&2
  echo "$table" >&2
  echo "--- dns ---" >&2
  echo "$dns" >&2
  exit 1
}

cleanup

"${COMPOSE[@]}" build >/dev/null
"${COMPOSE[@]}" up -d node-a node-b >/dev/null
for service in node-a node-b; do
  wait_for_service "$service"
done

"${COMPOSE[@]}" exec -T node-a nvpn init --force >/dev/null
"${COMPOSE[@]}" exec -T node-b nvpn init --force >/dev/null
ALICE_NPUB="$(nostr_pubkey_from_config node-a)"
BOB_NPUB="$(nostr_pubkey_from_config node-b)"

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" ]]; then
  echo "docker e2e failed: unable to resolve node npubs from config" >&2
  exit 1
fi

for service in node-a node-b; do
  "${COMPOSE[@]}" exec -T "$service" sh -lc \
    "sed -i '0,/enabled = false/s//enabled = true/; 0,/network_id = \"[^\"]*\"/s//network_id = \"$NETWORK_ID\"/' /root/.config/nvpn/config.toml"
done

"${COMPOSE[@]}" exec -T node-a nvpn set \
  --device "$ALICE_NPUB" \
  --device "$BOB_NPUB" \
  --endpoint "10.203.0.10:51820" \
  --listen-port 51820 \
  --fips-advertise-public-endpoint false \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false \
  --fips-host-tunnel-enabled true \
  --fips-peer-endpoint "$BOB_NPUB=10.203.0.11:51820" >/dev/null

"${COMPOSE[@]}" exec -T node-b nvpn set \
  --device "$ALICE_NPUB" \
  --device "$BOB_NPUB" \
  --endpoint "10.203.0.11:51820" \
  --listen-port 51820 \
  --fips-advertise-public-endpoint false \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false \
  --fips-host-tunnel-enabled true \
  --fips-peer-endpoint "$ALICE_NPUB=10.203.0.10:51820" \
  --fips-host-inbound-tcp-ports "$FIPS_HOST_TCP_PORT" >/dev/null

ALICE_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-a nvpn ip | tr -d '\r')"
BOB_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-b nvpn ip | tr -d '\r')"

start_nvpn_connect node-a
start_nvpn_connect node-b

for _ in $(seq 1 30); do
  ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
  BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

  if grep -q "mesh: 1/1 peers connected" <<<"$ALICE_CONNECT_LOGS" \
    && grep -q "mesh: 1/1 peers connected" <<<"$BOB_CONNECT_LOGS"; then
    break
  fi

  sleep 1
done

ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
BOB_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"

if ! grep -q "mesh: 1/1 peers connected" <<<"$ALICE_CONNECT_LOGS"; then
  echo "docker e2e failed: alice mesh did not reach 1/1" >&2
  echo "$ALICE_CONNECT_LOGS"
  exit 1
fi

if ! grep -q "mesh: 1/1 peers connected" <<<"$BOB_CONNECT_LOGS"; then
  echo "docker e2e failed: bob mesh did not reach 1/1" >&2
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

assert_fips_host_tunnel node-a "$BOB_NPUB"
assert_fips_host_tunnel node-b "$ALICE_NPUB"
assert_fips_firewall_rules node-a
assert_fips_firewall_rules node-b "$FIPS_HOST_TCP_PORT"
assert_fips_tcp_crosses "$BOB_NPUB"
assert_fips_firewall_blocks
"${COMPOSE[@]}" exec -T node-a nvpn set --fips-host-tunnel-enabled false >/dev/null
"${COMPOSE[@]}" exec -T node-a sh -lc 'pkill -TERM -x nvpn || true'
for _ in $(seq 1 10); do
  if ! "${COMPOSE[@]}" exec -T node-a sh -lc 'pgrep -x nvpn >/dev/null'; then
    break
  fi
  sleep 1
done
start_nvpn_connect node-a true
for _ in $(seq 1 30); do
  ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
  if grep -q "mesh: 1/1 peers connected" <<<"$ALICE_CONNECT_LOGS"; then
    break
  fi
  sleep 1
done
ALICE_CONNECT_LOGS="$("${COMPOSE[@]}" exec -T node-a sh -lc 'cat /tmp/connect.log 2>/dev/null || true')"
if ! grep -q "mesh: 1/1 peers connected" <<<"$ALICE_CONNECT_LOGS"; then
  echo "docker e2e failed: alice mesh did not recover after disabling .fips host tunnel" >&2
  echo "$ALICE_CONNECT_LOGS"
  exit 1
fi
assert_fips_host_disabled node-a "$BOB_NPUB"

if ! "${COMPOSE[@]}" exec -T node-a ping -c 3 -W 2 "$BOB_TUNNEL_IP" >/tmp/ping-a.log; then
  echo "docker e2e failed: ping A -> B failed" >&2
  echo "$ALICE_CONNECT_LOGS"
  echo "$BOB_CONNECT_LOGS"
  exit 1
fi

if ! "${COMPOSE[@]}" exec -T node-b ping -c 3 -W 2 "$ALICE_TUNNEL_IP" >/tmp/ping-b.log; then
  echo "docker e2e failed: ping B -> A failed" >&2
  echo "$ALICE_CONNECT_LOGS"
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

echo "docker e2e passed: FIPS private mesh established, .fips firewall enforced, disable removed IPv6 host state, resolver/tunnel carried TCP, and tunnel pings succeeded"
