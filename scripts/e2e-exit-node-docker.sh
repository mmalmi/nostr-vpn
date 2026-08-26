#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
GIT_COMMON_DIR="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
PRIMARY_CHECKOUT_DIR="$(dirname "$GIT_COMMON_DIR")"
PRIMARY_CHECKOUT_PARENT="$(dirname "$PRIMARY_CHECKOUT_DIR")"
PROJECT_NAME="${NVPN_EXIT_NODE_E2E_PROJECT_NAME:-nostr-vpn-e2e-exit-node}"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.exit-node-e2e.yml")

CONFIG_PATH="/root/.config/nvpn/config.toml"
NETWORK_ID="${NVPN_EXIT_NODE_E2E_NETWORK_ID:-docker-exit}"
PAID_EXIT_SELLER_NETWORK_ID="${NVPN_EXIT_NODE_E2E_SELLER_NETWORK_ID:-${NETWORK_ID}-seller}"
PAID_EXIT_BUYER_NETWORK_ID="${NVPN_EXIT_NODE_E2E_BUYER_NETWORK_ID:-${NETWORK_ID}-buyer}"
IDLE_CPU_MAX_PERCENT="${NVPN_E2E_IDLE_CPU_MAX_PERCENT:-80}"
MESH_REFRESH_SECS="${NVPN_EXIT_NODE_E2E_MESH_REFRESH_SECS:-5}"
NODE_A_PUBLIC_IP="${NVPN_E2E_NODE_A_PUBLIC_IP:-198.18.242.10}"
NAT_B_PUBLIC_IP="${NVPN_E2E_NAT_B_PUBLIC_IP:-198.18.242.11}"
PUBLIC_INTERNET_TARGET="${NVPN_EXIT_NODE_E2E_PUBLIC_IP:-198.18.242.100}"
NODE_B_PRIVATE_SUBNET="${NVPN_E2E_PRIVATE_B_SUBNET:-172.30.242.0/24}"
NODE_B_PRIVATE_PREFIX="${NODE_B_PRIVATE_SUBNET%.*}."
PRIVATE_B_GATEWAY_IP="${NVPN_E2E_PRIVATE_B_GATEWAY_IP:-172.30.242.1}"
NAT_B_PRIVATE_IP="${NVPN_E2E_NAT_B_PRIVATE_IP:-172.30.242.2}"
NODE_B_PRIVATE_IP="${NVPN_E2E_NODE_B_PRIVATE_IP:-172.30.242.3}"
NODE_B_PRIVATE_CIDR="$NODE_B_PRIVATE_IP/${NODE_B_PRIVATE_SUBNET#*/}"
CASHU_MINT_IP="${NVPN_E2E_CASHU_MINT_IP:-198.18.242.50}"
CASHU_MINT_URL="${NVPN_EXIT_NODE_E2E_CASHU_MINT_URL:-http://$CASHU_MINT_IP:3338}"
WG_UPSTREAM_IP="${NVPN_E2E_WG_UPSTREAM_IP:-198.18.242.20}"
WG_LISTEN_PORT=51821
PAID_EXIT_RESALE_TARGET="${NVPN_E2E_PAID_EXIT_RESALE_TARGET:-203.0.113.100}"
PAID_EXIT_MODE="${NVPN_EXIT_NODE_E2E_PAID:-0}"
PAID_EXIT_PAYMENT_MODE="${NVPN_EXIT_NODE_E2E_PAYMENT_MODE:-spilman}"
PAID_EXIT_SELECTION_MODE="${NVPN_EXIT_NODE_E2E_SELECTION_MODE:-manual}"
PAID_EXIT_MINT="${NVPN_EXIT_NODE_E2E_MINT:-}"
PAID_EXIT_PRICE_MSAT_PER_GB="${NVPN_EXIT_NODE_E2E_PRICE_MSAT_PER_GB:-1000000}"
PAID_EXIT_TOKEN_AMOUNT_SAT="${NVPN_EXIT_NODE_E2E_TOKEN_AMOUNT_SAT:-10}"
PAID_EXIT_TOKEN_PAID_MSAT="${NVPN_EXIT_NODE_E2E_TOKEN_PAID_MSAT:-10000}"
PAID_EXIT_TOKEN_FREE_PROBE_UNITS="${NVPN_EXIT_NODE_E2E_TOKEN_FREE_PROBE_UNITS:-65536}"
PAID_EXIT_LEASE_ID="${NVPN_EXIT_NODE_E2E_LEASE_ID:-lease-docker-paid-exit}"
PAID_EXIT_CHANNEL_ID="${NVPN_EXIT_NODE_E2E_CHANNEL_ID:-token-docker-paid-exit}"
PAID_EXIT_SPILMAN_CHANNEL_CAPACITY_SAT="${NVPN_EXIT_NODE_E2E_SPILMAN_CHANNEL_CAPACITY_SAT:-10}"
PAID_EXIT_SPILMAN_OPEN_PAID_MSAT="${NVPN_EXIT_NODE_E2E_SPILMAN_OPEN_PAID_MSAT:-0}"
PAID_EXIT_SPILMAN_WALLET_TOPUP_SAT="${NVPN_EXIT_NODE_E2E_SPILMAN_WALLET_TOPUP_SAT:-25}"
PAID_EXIT_SPILMAN_FREE_PROBE_UNITS="${NVPN_EXIT_NODE_E2E_SPILMAN_FREE_PROBE_UNITS:-0}"
PAID_EXIT_SPILMAN_GRACE_UNITS="${NVPN_EXIT_NODE_E2E_SPILMAN_GRACE_UNITS:-65536}"
PAID_EXIT_PROBE_PORT="${NVPN_EXIT_NODE_E2E_PROBE_PORT:-8080}"
FIXTURE_READY_DEADLINE_SECS=30
FIXTURE_CONNECT_TIMEOUT_SECS=2
PAID_EXIT_SESSION_ID=""
PAID_EXIT_PROBE_JSON=""

case "$PAID_EXIT_SELECTION_MODE" in
  manual|automatic) ;;
  *)
    echo "exit-node docker e2e failed: unsupported paid-exit selection mode '$PAID_EXIT_SELECTION_MODE'" >&2
    exit 2
    ;;
esac
if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" && "$PAID_EXIT_PAYMENT_MODE" != "spilman" ]]; then
  echo "exit-node docker e2e failed: automatic paid-exit selection requires the production Spilman wallet path" >&2
  exit 2
fi

cleanup() {
  COMPOSE_PROFILES=paid-exit \
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm \
    "${PROJECT_NAME}_internet" \
    "${PROJECT_NAME}_private-b" >/dev/null 2>&1 || true
  for network in "${PROJECT_NAME}_internet" "${PROJECT_NAME}_private-b"; do
    for _ in $(seq 1 20); do
      docker network inspect "$network" >/dev/null 2>&1 || break
      sleep 1
    done
  done
}

dump_debug() {
  set +e
  echo "exit-node docker e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  for service in cashu-mint internet-target nat-b node-a node-b wireguard-upstream; do
    echo "--- logs: $service ---"
    "${COMPOSE[@]}" logs --no-color --tail 120 "$service" || true
  done
  for node in node-a node-b; do
    echo "--- $node status ---"
    "${COMPOSE[@]}" exec -T "$node" nvpn status --json --discover-secs 0 || true
    echo "--- $node paid-exit status ---"
    "${COMPOSE[@]}" exec -T "$node" nvpn paid-exit status --json || true
    echo "--- $node daemon.state.json ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "cat /root/.config/nvpn/daemon.state.json 2>/dev/null || true" || true
    echo "--- $node daemon.log ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "tail -n 200 /root/.config/nvpn/daemon.log 2>/dev/null || true" || true
    echo "--- $node routes ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "ip route || true" || true
    echo "--- $node utun100 ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "ip addr show utun100 || true" || true
    echo "--- $node iptables ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "iptables -S || true; iptables -t nat -S || true" || true
  done
  echo "--- internet-target paid-exit probe fixture ---"
  "${COMPOSE[@]}" exec -T internet-target sh -lc "cat /tmp/nvpn-paid-exit-probe-fixture.log 2>/dev/null || true" || true
}

on_exit() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    dump_debug
  fi
  cleanup
  exit "$exit_code"
}
trap on_exit EXIT

compact_json() {
  tr -d '\n\r\t '
}

private_iface_for_ip() {
  local node="$1"
  local cidr="$2"
  "${COMPOSE[@]}" exec -T "$node" sh -lc \
    "ip -o -4 addr show | awk '\$4 == \"$cidr\" { print \$2; exit }'" | tr -d '\r'
}

nostr_pubkey_from_config() {
  local node="$1"
  "${COMPOSE[@]}" exec -T "$node" sh -lc "
    awk '
      /^\\[nostr\\]$/ { in_nostr = 1; next }
      /^\\[/ { in_nostr = 0 }
      in_nostr && /^public_key[[:space:]]*=/ {
        print \$3;
        exit
      }
    ' '$CONFIG_PATH'
  " | tr -d '\r\"'
}

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

  echo "exit-node docker e2e failed: service '$service' did not reach running state" >&2
  exit 1
}

wait_for_fixture_tcp() {
  local label="$1" host="$2" port="$3"
  echo "--- paid-exit fixture readiness: waiting for $label at $host:$port (${FIXTURE_READY_DEADLINE_SECS}s deadline) ---"
  # shellcheck disable=SC2016 # Positional parameters expand in the container.
  if "${COMPOSE[@]}" exec -T node-a \
    timeout "$FIXTURE_READY_DEADLINE_SECS" sh -c '
      host="$1"
      port="$2"
      connect_timeout="$3"
      until nc -z -w "$connect_timeout" "$host" "$port"; do sleep 1; done
    ' sh "$host" "$port" "$FIXTURE_CONNECT_TIMEOUT_SECS" \
    >/dev/null 2>&1
  then
    echo "--- paid-exit fixture readiness: $label ready ---"
    return 0
  fi
  echo "--- paid-exit fixture readiness: $label timed out ---" >&2
  return 1
}

wait_for_cashu_mint() {
  wait_for_fixture_tcp "Cashu test mint" "$CASHU_MINT_IP" 3338 && return 0
  echo "exit-node docker e2e failed: Cashu test mint did not become reachable at $CASHU_MINT_URL" >&2
  exit 1
}

start_paid_exit_probe_fixture() {
  "${COMPOSE[@]}" exec -T internet-target sh -lc "cat > /tmp/nvpn-paid-exit-probe-fixture.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import json
import os
import sys

EXIT_IP = os.environ.get('NVPN_PROBE_IP', '198.18.242.10')
COUNTRY = os.environ.get('NVPN_PROBE_COUNTRY', 'FI')
ASN = int(os.environ.get('NVPN_PROBE_ASN', '64500'))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(fmt % args + '\n')

    def send_body(self, body, content_type):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value):
        self.send_body(json.dumps(value).encode('utf-8'), 'application/json')

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/ip':
            self.send_json({'ip': EXIT_IP})
            return
        if parsed.path.startswith('/geoip/'):
            self.send_json({'country_code': COUNTRY, 'asn': ASN})
            return
        if parsed.path == '/down':
            raw = parse_qs(parsed.query).get('bytes', ['1024'])[0]
            try:
                count = max(1, min(int(raw), 1048576))
            except ValueError:
                count = 1024
            self.send_body(b'0' * count, 'application/octet-stream')
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != '/up':
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get('Content-Length', '0') or '0')
        if length:
            self.rfile.read(length)
        self.send_body(b'ok', 'text/plain')

port = int(sys.argv[1])
server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
server.serve_forever()
PY
NVPN_PROBE_IP='$NODE_A_PUBLIC_IP' NVPN_PROBE_COUNTRY='FI' NVPN_PROBE_ASN='64500' nohup python3 /tmp/nvpn-paid-exit-probe-fixture.py '$PAID_EXIT_PROBE_PORT' >/tmp/nvpn-paid-exit-probe-fixture.log 2>&1 </dev/null &"
}

wait_for_paid_exit_probe_fixture() {
  wait_for_fixture_tcp \
    "paid-exit probe" "$PUBLIC_INTERNET_TARGET" "$PAID_EXIT_PROBE_PORT" \
    && return 0
  echo "exit-node docker e2e failed: paid-exit probe fixture did not become reachable at $PUBLIC_INTERNET_TARGET:$PAID_EXIT_PROBE_PORT" >&2
  "${COMPOSE[@]}" exec -T internet-target sh -lc "cat /tmp/nvpn-paid-exit-probe-fixture.log 2>/dev/null || true" >&2 || true
  exit 1
}

assert_exact_paid_exit_offer() {
  local label="$1"
  local discovery_json="$2"
  if jq -e \
    --arg seller "$ALICE_NPUB" \
    --arg mint "$PAID_EXIT_MINT" \
    --argjson price "$PAID_EXIT_PRICE_MSAT_PER_GB" \
    --argjson capacity "$PAID_MAX_CHANNEL_CAPACITY_SAT" \
    'any(.offers[]?; .offer.offer_id == "internet-exit"
      and .offer.seller_npub == $seller
      and (.offer.receiver_pubkey_hex | length) == 66
      and .offer.pricing.price_msat_per_gb == $price
      and .offer.channel.max_channel_capacity_sat == $capacity
      and (.offer.channel.accepted_mints | index($mint)) != null)' \
    <<<"$discovery_json" >/dev/null
  then
    echo "paid-exit $label discovery passed: exact signed seller offer received"
    return 0
  fi
  echo "exit-node docker e2e failed: $label discovery did not return the seller's exact signed offer" >&2
  printf '%s\n' "$discovery_json" >&2
  exit 1
}

buyer_paid_session_persisted() {
  local status="$1"
  local session_id="$2"
  local realized_ip="$3"
  local initial_paid_msat="$4"
  jq -e \
    --arg sid "$session_id" \
    --arg ip "$realized_ip" \
    --argjson initial_paid_msat "$initial_paid_msat" '
      any(.sessions[]?;
        .session_id == $sid
        and .realized_exit_ip == $ip
        and .observed_country_code == "FI"
        and .observed_asn == 64500
        and .country_claim.status == "match"
        and .country_claim.matches == true
        and ((.quality.latency_ms | type) == "number")
        and ((.quality.jitter_ms | type) == "number")
        and .quality.packet_loss_ppm == 0
        and ((.quality.down_bps // 0) > 0)
        and ((.quality.up_bps // 0) > 0)
        and .payment.paid_msat > $initial_paid_msat
        and .payment.cashu_spilman != null
        and .routing.state == "paid"
        and .routing.allow_routing == true
      )
    ' <<<"$status" >/dev/null
}

automatic_buyer_paid_session_persisted() {
  local status="$1"
  local session_id="$2"
  local initial_paid_msat="$3"
  jq -e \
    --arg sid "$session_id" \
    --argjson initial_paid_msat "$initial_paid_msat" '
      any(.sessions[]?;
        .session_id == $sid
        and (.realized_exit_ip | type) == "string"
        and (.realized_exit_ip | length) > 0
        and ((.quality.latency_ms | type) == "number")
        and ((.quality.jitter_ms | type) == "number")
        and .quality.packet_loss_ppm == 0
        and .payment.paid_msat > $initial_paid_msat
        and .payment.cashu_spilman.has_funding == true
        and .payment.cashu_spilman.has_signature == true
        and .routing.state == "paid"
        and .routing.allow_routing == true
      )
    ' <<<"$status" >/dev/null
}

automatic_buyer_session_funded() {
  local status="$1"
  local session_id="$2"
  jq -e --arg sid "$session_id" '
    any(.sessions[]?;
      .session_id == $sid
      and .payment.cashu_spilman.has_funding == true
      and .payment.cashu_spilman.has_signature == true
      and .routing.allow_routing == true
    )
  ' <<<"$status" >/dev/null
}

ping_until_success() {
  local node="$1"
  local target="$2"
  local log_path="$3"
  for _ in $(seq 1 5); do
    if "${COMPOSE[@]}" exec -T "$node" ping -c 3 -W 2 "$target" >"$log_path"; then
      return 0
    fi
    sleep 2
  done

  return 1
}

assert_buyer_egress_source() {
  local expected_source="$1"
  local label="$2"
  local capture="/tmp/nvpn-paid-exit-${label}-egress.log"
  local ping_log="/tmp/nvpn-paid-exit-${label}-ping.log"
  local capture_pid

  "${COMPOSE[@]}" exec -T internet-target sh -lc \
    "timeout 12 tcpdump -ni any -c 1 'icmp and src host $expected_source and dst host $PAID_EXIT_RESALE_TARGET'" \
    >"$capture" 2>&1 &
  capture_pid=$!
  sleep 1
  if ! ping_until_success node-b "$PAID_EXIT_RESALE_TARGET" "$ping_log"; then
    wait "$capture_pid" 2>/dev/null || true
    echo "exit-node docker e2e failed: buyer could not use the $label seller upstream" >&2
    cat "$ping_log" >&2 || true
    exit 1
  fi
  if ! wait "$capture_pid" || ! grep -Fq "$expected_source > $PAID_EXIT_RESALE_TARGET" "$capture"; then
    echo "exit-node docker e2e failed: $label seller traffic did not use $expected_source" >&2
    cat "$capture" >&2 || true
    exit 1
  fi
}

assert_buyer_egress_blocked() {
  local label="$1"
  local consecutive_failures=0
  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T node-b ping -c 1 -W 1 "$PAID_EXIT_RESALE_TARGET" \
      >/dev/null 2>&1; then
      consecutive_failures=0
    else
      consecutive_failures="$((consecutive_failures + 1))"
      if ((consecutive_failures >= 3)); then
        return 0
      fi
    fi
    sleep 1
  done
  echo "exit-node docker e2e failed: buyer traffic leaked after the $label upstream failed" >&2
  exit 1
}

configure_paid_exit_wireguard_upstream() {
  "${COMPOSE[@]}" exec -T wireguard-upstream sh -eu -c '
    umask 077
    wg genkey > /tmp/server.key
    wg genkey > /tmp/client.key
    wg pubkey < /tmp/server.key > /tmp/server.pub
    wg pubkey < /tmp/client.key > /tmp/client.pub
  '
  local server_pub client_priv client_pub
  server_pub="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/server.pub | tr -d '\r\n')"
  client_priv="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/client.key | tr -d '\r\n')"
  client_pub="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/client.pub | tr -d '\r\n')"

  "${COMPOSE[@]}" exec -T wireguard-upstream sh -eu -c "
    iface=\"\$(ip -o -4 addr show | awk '\$4 == \"$WG_UPSTREAM_IP/24\" { print \$2; exit }')\"
    test -n \"\$iface\"
    ip link add dev wg0 type wireguard
    ip address add 10.99.99.1/24 dev wg0
    wg set wg0 listen-port $WG_LISTEN_PORT private-key /tmp/server.key
    wg set wg0 peer '$client_pub' allowed-ips 10.99.99.2/32,10.44.0.0/16
    ip link set wg0 up
    ip route replace 10.44.0.0/16 dev wg0
    iptables -P FORWARD ACCEPT
    iptables -t nat -A POSTROUTING -o \"\$iface\" -s 10.99.99.0/24 -j MASQUERADE
  "

  "${COMPOSE[@]}" exec -T node-a sh -lc 'cat > /tmp/paid-exit-wg.conf' <<EOF
[Interface]
PrivateKey = $client_priv
Address = 10.99.99.2/32

[Peer]
PublicKey = $server_pub
Endpoint = $WG_UPSTREAM_IP:$WG_LISTEN_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 1
EOF
  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --wireguard-exit-config-file /tmp/paid-exit-wg.conf \
    --wireguard-exit-enabled true >/dev/null

  local handshake
  for _ in $(seq 1 60); do
    handshake="$("${COMPOSE[@]}" exec -T node-a sh -lc \
      "wg show all latest-handshakes 2>/dev/null | awk '\$3 > 0 { print \$3; exit }'" | tr -d '\r')"
    [[ -n "$handshake" ]] && return 0
    "${COMPOSE[@]}" exec -T node-a ping -c 1 -W 1 "$PUBLIC_INTERNET_TARGET" \
      >/dev/null 2>&1 || true
    sleep 1
  done
  echo "exit-node docker e2e failed: seller WireGuard upstream never handshook" >&2
  exit 1
}

run_spilman_resale_matrix() {
  "${COMPOSE[@]}" exec -T internet-target ip address add "$PAID_EXIT_RESALE_TARGET/32" dev lo
  for node in node-a wireguard-upstream; do
    "${COMPOSE[@]}" exec -T "$node" ip route replace "$PAID_EXIT_RESALE_TARGET/32" \
      via "$PUBLIC_INTERNET_TARGET"
  done
  assert_buyer_egress_source "$NODE_A_PUBLIC_IP" direct

  "${COMPOSE[@]}" exec -T node-a ip route del "$PAID_EXIT_RESALE_TARGET/32"
  configure_paid_exit_wireguard_upstream
  "${COMPOSE[@]}" exec -T node-a ip route get "$PAID_EXIT_RESALE_TARGET" | grep -Fq 'dev nvpn-wg-exit'
  assert_buyer_egress_source "$WG_UPSTREAM_IP" wireguard

  "${COMPOSE[@]}" exec -T wireguard-upstream ip link del wg0
  assert_buyer_egress_blocked WireGuard

  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn init --force >/dev/null
  local upstream_npub
  upstream_npub="$(nostr_pubkey_from_config wireguard-upstream)"
  [[ -n "$upstream_npub" ]]
  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --participant "$upstream_npub" \
    --fips-peer-endpoint "$upstream_npub=$WG_UPSTREAM_IP:51820" >/dev/null
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn set \
    --network-id "$PAID_EXIT_SELLER_NETWORK_ID" \
    --participant "$ALICE_NPUB" \
    --endpoint "$WG_UPSTREAM_IP:51820" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --fips-bootstrap-enabled false \
    --fips-peer-endpoint "$ALICE_NPUB=$NODE_A_PUBLIC_IP:51820" \
    --advertise-exit-node >/dev/null
  "${COMPOSE[@]}" exec -T wireguard-upstream sh -lc \
    "sed -i 's|^discovery_timeout_secs = .*|discovery_timeout_secs = 2|' '$CONFIG_PATH'; sed -i '/^lan_discovery_enabled = /d' '$CONFIG_PATH'; sed -i '1ilan_discovery_enabled = false' '$CONFIG_PATH'"
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn start --daemon --connect \
    --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null

  local transition_capture=/tmp/nvpn-paid-exit-wireguard-private-handoff.log
  "${COMPOSE[@]}" exec -T internet-target sh -lc \
    "rm -f '$transition_capture'; timeout 90 tcpdump -lni any -c 1 'icmp and src host $NODE_A_PUBLIC_IP and dst host $PAID_EXIT_RESALE_TARGET' >'$transition_capture' 2>&1 & echo \$! >/tmp/nvpn-handoff-tcpdump.pid"
  "${COMPOSE[@]}" exec -d node-b sh -lc \
    "touch /tmp/nvpn-handoff-probe; while test -e /tmp/nvpn-handoff-probe; do ping -f -w 1 '$PAID_EXIT_RESALE_TARGET' >/dev/null 2>&1 || true; done"
  sleep 1
  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --exit-node "$upstream_npub" \
    --exit-node-leak-protection true >/dev/null

  local seller_route private_ready=0
  for _ in $(seq 1 80); do
    seller_route="$("${COMPOSE[@]}" exec -T node-a ip route get "$PAID_EXIT_RESALE_TARGET" | tr -d '\r')"
    if grep -Fq 'dev utun100' <<<"$seller_route"; then
      private_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$private_ready" != 1 ]]; then
    echo "exit-node docker e2e failed: private FIPS seller upstream did not become ready" >&2
    printf '%s\n' "$seller_route" >&2
    exit 1
  fi
  "${COMPOSE[@]}" exec -T node-b rm -f /tmp/nvpn-handoff-probe
  "${COMPOSE[@]}" exec -T internet-target sh -lc \
    "kill \$(cat /tmp/nvpn-handoff-tcpdump.pid) 2>/dev/null || true"
  if "${COMPOSE[@]}" exec -T internet-target grep -Fq \
    "$NODE_A_PUBLIC_IP > $PAID_EXIT_RESALE_TARGET" "$transition_capture"; then
    echo "exit-node docker e2e failed: WireGuard-to-private handoff leaked through Direct" >&2
    "${COMPOSE[@]}" exec -T internet-target cat "$transition_capture" >&2
    exit 1
  fi
  echo "WireGuard-to-private strict handoff emitted no Direct packets under flood probe"
  assert_buyer_egress_source "$WG_UPSTREAM_IP" private-fips

  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn stop --force >/dev/null
  assert_buyer_egress_blocked private-FIPS

  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --exit-node none \
    --exit-node-leak-protection false >/dev/null
  "${COMPOSE[@]}" exec -T node-a ip route replace "$PAID_EXIT_RESALE_TARGET/32" \
    via "$PUBLIC_INTERNET_TARGET"
  assert_buyer_egress_source "$NODE_A_PUBLIC_IP" direct-restored
  echo "paid-exit resale matrix passed: Direct, WireGuard, private FIPS, fail-closed, Direct restored"
}

assert_secure_exit_dns() {
  local dns_result doh_capture_status doh_packets doh_pid https_status no53_capture_status no53_packets no53_pid resolver_nameservers

  "${COMPOSE[@]}" exec -T node-b sh -lc \
    "rm -f /tmp/nvpn-secure-dns-no53.pcap /tmp/nvpn-secure-dns-doh.pcap"
  "${COMPOSE[@]}" exec -T node-b sh -lc \
    "timeout 6 tcpdump -ni any -U -w /tmp/nvpn-secure-dns-no53.pcap 'port 53 and not host 127.0.0.1' >/tmp/nvpn-secure-dns-no53.log 2>&1" &
  no53_pid=$!
  "${COMPOSE[@]}" exec -T node-b sh -lc \
    "timeout 6 tcpdump -ni any -U -c 1 -w /tmp/nvpn-secure-dns-doh.pcap 'tcp port 443 and (host 1.1.1.1 or host 1.0.0.1)' >/tmp/nvpn-secure-dns-doh.log 2>&1" &
  doh_pid=$!
  sleep 1

  dns_result="$("${COMPOSE[@]}" exec -T node-b dig +short +time=4 +tries=1 example.com A | tr -d '\r')"
  doh_capture_status=0
  wait "$doh_pid" || doh_capture_status=$?
  no53_capture_status=0
  wait "$no53_pid" || no53_capture_status=$?
  doh_packets="$("${COMPOSE[@]}" exec -T node-b sh -lc \
    "tcpdump -nn -r /tmp/nvpn-secure-dns-doh.pcap 2>/dev/null" | tr -d '\r')"
  no53_packets="$("${COMPOSE[@]}" exec -T node-b sh -lc \
    "tcpdump -nn -r /tmp/nvpn-secure-dns-no53.pcap 2>/dev/null" | tr -d '\r')"
  resolver_nameservers="$("${COMPOSE[@]}" exec -T node-b sh -lc \
    "awk '/^nameserver[[:space:]]/ { print \$2 }' /etc/resolv.conf" | tr -d '\r')"

  if [[ -z "$dns_result" ]]; then
    echo "exit-node docker e2e failed: secure DNS did not resolve example.com" >&2
    exit 1
  fi
  https_status="$("${COMPOSE[@]}" exec -T node-b curl --silent --show-error \
    --noproxy '*' --resolve cloudflare-dns.com:443:1.1.1.1 \
    --connect-timeout 4 --max-time 8 --output /dev/null --write-out '%{http_code}' \
    https://cloudflare-dns.com/cdn-cgi/trace | tr -d '\r')"
  if [[ "$https_status" != 200 ]]; then
    echo "exit-node docker e2e failed: HTTPS through the selected exit returned $https_status" >&2
    exit 1
  fi
  if [[ "$resolver_nameservers" != "127.0.0.1" ]]; then
    echo "exit-node docker e2e failed: buyer resolver was not pinned exclusively to localhost" >&2
    printf '%s\n' "$resolver_nameservers" >&2
    exit 1
  fi
  if [[ "$doh_capture_status" -ne 0 || -z "$doh_packets" ]]; then
    echo "exit-node docker e2e failed: buyer DNS did not use the authenticated DoH bootstrap" >&2
    "${COMPOSE[@]}" exec -T node-b sh -lc \
      "cat /tmp/nvpn-secure-dns-doh.log 2>/dev/null || true" >&2
    exit 1
  fi
  if [[ "$no53_capture_status" -ne 124 || -n "$no53_packets" ]]; then
    echo "exit-node docker e2e failed: buyer leaked plaintext DNS outside loopback" >&2
    printf '%s\n' "$no53_packets" >&2
    exit 1
  fi

  printf '%s\n' "$dns_result" >/tmp/nvpn-exit-node-secure-dns.log
  printf 'HTTPS status: %s\n' "$https_status" >>/tmp/nvpn-exit-node-secure-dns.log
  printf '%s\n' "$doh_packets" >>/tmp/nvpn-exit-node-secure-dns.log
}

truthy() {
  case "${1:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_paid_exit_payment_mode() {
  local raw="${1:-}"
  local normalized
  normalized="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$normalized" in
    token|cashu-token|cashu_token|cashu-token-lease|cashu_token_lease|fallback|dev)
      printf 'token\n'
      ;;
    spilman|cashu-spilman|cashu_spilman|streaming|channel)
      printf 'spilman\n'
      ;;
    *)
      echo "exit-node docker e2e failed: unsupported paid-exit payment mode '$raw'" >&2
      exit 1
      ;;
  esac
}

wait_for_paid_exit_wallet_balance() {
  local node="$1"
  local mint="$2"
  local minimum_sat="$3"
  local status=""
  local balance="0"

  for _ in $(seq 1 60); do
    status="$("${COMPOSE[@]}" exec -T "$node" env RUST_LOG=warn nvpn paid-exit wallet \
      --config "$CONFIG_PATH" \
      --json \
      show \
      --refresh | tr -d '\r')" || true
    if [[ -n "$status" ]]; then
      balance="$(jq -r --arg mint "$mint" '[.cashu.entries[]? | select(.mint_url == $mint and .unit == "sat") | .balance] | add // 0' <<<"$status" 2>/dev/null || printf '0')"
      if [[ "${balance:-0}" =~ ^[0-9]+$ ]] && (( balance >= minimum_sat )); then
        printf '%s\n' "$status"
        return 0
      fi
    fi
    sleep 1
  done

  echo "exit-node docker e2e failed: buyer wallet did not reach ${minimum_sat}sat at $mint (last balance ${balance:-0}sat)" >&2
  if [[ -n "$status" ]]; then
    printf '%s\n' "$status" >&2
  fi
  exit 1
}

assert_idle_cpu_below() {
  local node="$1"
  local pids
  pids="$("${COMPOSE[@]}" exec -T "$node" sh -lc 'pgrep -d, -x nvpn || true' | tr -d '\r')"
  if [[ -z "$pids" ]]; then
    echo "exit-node docker e2e failed: no nvpn process found on $node for idle CPU guard" >&2
    exit 1
  fi

  local max_cpu
  max_cpu="$("${COMPOSE[@]}" exec -T "$node" sh -lc \
    "top -b -n 3 -d 1 -p '$pids' | awk '\$12 == \"nvpn\" && \$9 + 0 > max { max = \$9 + 0 } END { printf \"%.1f\", max + 0 }'" \
    | tr -d '\r')"
  echo "--- $node idle nvpn CPU max: ${max_cpu}% ---"
  if awk -v max="$max_cpu" -v limit="$IDLE_CPU_MAX_PERCENT" 'BEGIN { exit !(max > limit) }'; then
    echo "exit-node docker e2e failed: $node idle nvpn CPU ${max_cpu}% exceeded ${IDLE_CPU_MAX_PERCENT}%" >&2
    exit 1
  fi
}

block_docker_nat_shortcuts() {
  "${COMPOSE[@]}" exec -T node-a sh -lc \
    "ip route replace blackhole '$NODE_B_PRIVATE_SUBNET'"
  "${COMPOSE[@]}" exec -T node-b sh -lc "
    iptables -I OUTPUT -p udp -d '$PRIVATE_B_GATEWAY_IP' --dport 51820 -j DROP
    iptables -I INPUT -p udp -s '$PRIVATE_B_GATEWAY_IP' --sport 51820 -j DROP
  "
}

assert_no_private_b_fips_shortcut() {
  local status="$1"
  local node="$2"
  local compact
  compact="$(printf '%s' "$status" | compact_json)"
  if grep -Fq "\"fips_transport_addr\":\"$NODE_B_PRIVATE_PREFIX" <<<"$compact"; then
    echo "exit-node docker e2e failed: $node used node-b's Docker-private subnet as its FIPS transport" >&2
    printf '%s\n' "$status" >&2
    exit 1
  fi
}

PAID_EXIT_PAYMENT_MODE="$(normalize_paid_exit_payment_mode "$PAID_EXIT_PAYMENT_MODE")"
PAID_EXIT_INDEPENDENT_NETWORKS=0
if truthy "$PAID_EXIT_MODE"; then
  PAID_EXIT_INDEPENDENT_NETWORKS=1
fi
if [[ -z "$PAID_EXIT_MINT" ]]; then
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    PAID_EXIT_MINT="$CASHU_MINT_URL"
  else
    PAID_EXIT_MINT="https://mint.example"
  fi
fi

if truthy "$PAID_EXIT_MODE" && [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]] && ! command -v jq >/dev/null 2>&1; then
  echo "exit-node docker e2e failed: jq is required for Spilman paid-exit e2e assertions" >&2
  exit 1
fi

cleanup

if truthy "$PAID_EXIT_MODE"; then
  export NVPN_EXIT_NODE_E2E_DOCKERFILE="${NVPN_EXIT_NODE_E2E_DOCKERFILE:-Dockerfile.paid-exit-e2e}"
  export NVPN_EXIT_NODE_E2E_IMAGE="${NVPN_EXIT_NODE_E2E_IMAGE:-nostr-vpn-paid-exit-e2e-node}"
  export NVPN_CASHU_SERVICE_REPO_PATH="${NVPN_CASHU_SERVICE_REPO_PATH:-$PRIMARY_CHECKOUT_PARENT/cashu-service}"
  export NVPN_CASHU_SPILMAN_CHANNELS_REPO_PATH="${NVPN_CASHU_SPILMAN_CHANNELS_REPO_PATH:-$PRIMARY_CHECKOUT_PARENT/cashu_spilman_channels}"
fi
if truthy "$PAID_EXIT_MODE" && [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
  export COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}paid-exit"
fi

SERVICES=(internet-target node-a nat-b)
if truthy "$PAID_EXIT_MODE" && [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
  SERVICES=(cashu-mint wireguard-upstream "${SERVICES[@]}")
fi

if ! truthy "${NVPN_EXIT_NODE_E2E_SKIP_BUILD:-0}"; then
  # Every service in this topology uses the same image. Building several
  # services concurrently makes BuildKit race while exporting that shared tag.
  "${COMPOSE[@]}" build node-a >/dev/null
fi

"${COMPOSE[@]}" up -d "${SERVICES[@]}" >/dev/null

for service in "${SERVICES[@]}"; do
  wait_for_service "$service"
done
if truthy "$PAID_EXIT_MODE" && [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
  wait_for_cashu_mint
  start_paid_exit_probe_fixture
  wait_for_paid_exit_probe_fixture
fi

"${COMPOSE[@]}" up -d node-b >/dev/null
wait_for_service node-b

NODE_B_PRIVATE_IFACE="$(private_iface_for_ip node-b "$NODE_B_PRIVATE_CIDR")"
[[ -n "$NODE_B_PRIVATE_IFACE" ]]

"${COMPOSE[@]}" exec -T node-b sh -lc \
  "ip route del default >/dev/null 2>&1 || true; ip route add default via $NAT_B_PRIVATE_IP dev $NODE_B_PRIVATE_IFACE; ip route replace $NODE_A_PUBLIC_IP via $NAT_B_PRIVATE_IP dev $NODE_B_PRIVATE_IFACE"
block_docker_nat_shortcuts

for node in node-a node-b; do
  "${COMPOSE[@]}" exec -T "$node" nvpn init --force >/dev/null
done

ALICE_NPUB="$(nostr_pubkey_from_config node-a)"
BOB_NPUB="$(nostr_pubkey_from_config node-b)"

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" ]]; then
  echo "exit-node docker e2e failed: unable to resolve node npubs" >&2
  exit 1
fi

if truthy "$PAID_EXIT_INDEPENDENT_NETWORKS"; then
  # A public paid seller and buyer are not members of one private roster and
  # must not derive addresses from one shared network id. The buyer knows the
  # advertised public endpoint; the seller must admit first contact long
  # enough to authenticate the paid session-open frame.
  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --network-id "$PAID_EXIT_SELLER_NETWORK_ID" \
    --endpoint "$NODE_A_PUBLIC_IP:51820" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --connect-to-non-roster-fips-peers true \
    --fips-nostr-discovery-enabled false \
    --fips-bootstrap-enabled false \
    --advertise-exit-node false >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn set \
    --network-id "$PAID_EXIT_BUYER_NETWORK_ID" \
    --endpoint "$NAT_B_PUBLIC_IP:51820" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --connect-to-non-roster-fips-peers true \
    --fips-nostr-discovery-enabled false \
    --fips-bootstrap-enabled false \
    --fips-peer-endpoint "$ALICE_NPUB=$NODE_A_PUBLIC_IP:51820" \
    --exit-node none >/dev/null
else
  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --participant "$BOB_NPUB" >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn set \
    --participant "$ALICE_NPUB" >/dev/null

  "${COMPOSE[@]}" exec -T node-a nvpn set \
    --network-id "$NETWORK_ID" \
    --endpoint "$NODE_A_PUBLIC_IP:51820" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --fips-nostr-discovery-enabled false \
    --fips-bootstrap-enabled false \
    --fips-peer-endpoint "$BOB_NPUB=$NAT_B_PUBLIC_IP:51820" \
    --advertise-exit-node >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn set \
    --network-id "$NETWORK_ID" \
    --endpoint "$NAT_B_PUBLIC_IP:51820" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --fips-nostr-discovery-enabled false \
    --fips-bootstrap-enabled false \
    --fips-peer-endpoint "$ALICE_NPUB=$NODE_A_PUBLIC_IP:51820" \
    --exit-node "$ALICE_NPUB" >/dev/null
fi

for node in node-a node-b; do
  "${COMPOSE[@]}" exec -T "$node" sh -lc \
    "sed -i 's|^discovery_timeout_secs = .*|discovery_timeout_secs = 2|' '$CONFIG_PATH'; sed -i '/^lan_discovery_enabled = /d' '$CONFIG_PATH'; sed -i '1ilan_discovery_enabled = false' '$CONFIG_PATH'"
done

if truthy "$PAID_EXIT_MODE"; then
  PAID_MAX_CHANNEL_CAPACITY_SAT="$PAID_EXIT_TOKEN_AMOUNT_SAT"
  PAID_FREE_PROBE_UNITS="$PAID_EXIT_TOKEN_FREE_PROBE_UNITS"
  PAID_GRACE_UNITS=0
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    PAID_MAX_CHANNEL_CAPACITY_SAT="$PAID_EXIT_SPILMAN_CHANNEL_CAPACITY_SAT"
    PAID_FREE_PROBE_UNITS="$PAID_EXIT_SPILMAN_FREE_PROBE_UNITS"
    PAID_GRACE_UNITS="$PAID_EXIT_SPILMAN_GRACE_UNITS"
  fi

  SELLER_RUN_JSON="$("${COMPOSE[@]}" exec -T node-a env RUST_LOG=warn nvpn paid-exit run \
    --config "$CONFIG_PATH" \
    --offer-id internet-exit \
    --price-msat-per-gb "$PAID_EXIT_PRICE_MSAT_PER_GB" \
    --accepted-mint "$PAID_EXIT_MINT" \
    --max-channel-capacity-sat "$PAID_MAX_CHANNEL_CAPACITY_SAT" \
    --channel-expiry-secs 3600 \
    --free-probe-units "$PAID_FREE_PROBE_UNITS" \
    --grace-units "$PAID_GRACE_UNITS" \
    --country-code FI \
    --no-reload-daemon \
    --json | tr -d '\r')"
  PAID_EXIT_PROVIDER_LINK="$(jq -r '.provider_link // empty' <<<"$SELLER_RUN_JSON")"
  if [[ -z "$PAID_EXIT_PROVIDER_LINK" ]]; then
    echo "exit-node docker e2e failed: seller did not produce a paid exit provider link" >&2
    printf '%s\n' "$SELLER_RUN_JSON" >&2
    exit 1
  fi

  "${COMPOSE[@]}" exec -T node-a nvpn start --daemon --connect \
    --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn start --daemon --connect \
    --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null

  "${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit wallet \
    --config "$CONFIG_PATH" \
    --json \
    add-mint "$PAID_EXIT_MINT" \
    --make-default >/dev/null
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    "${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit wallet \
      --config "$CONFIG_PATH" \
      --json \
      topup "$PAID_EXIT_SPILMAN_WALLET_TOPUP_SAT" \
      --mint "$PAID_EXIT_MINT" >/dev/null
    wait_for_paid_exit_wallet_balance node-b "$PAID_EXIT_MINT" "$PAID_EXIT_SPILMAN_WALLET_TOPUP_SAT" >/dev/null
  fi

  # Exercise a provider-link import over the production FIPS pubsub path. The
  # link only constrains the seller, ceiling, and mint; the signed offer remains
  # authoritative for the receiver and channel terms used below.
  DISCOVER_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit discover \
    --config "$CONFIG_PATH" \
    --duration-secs 20 \
    --json | tr -d '\r')"
  assert_exact_paid_exit_offer marketplace "$DISCOVER_JSON"

  PAID_EXIT_REJECT_MAX_MSAT_PER_GB="$((PAID_EXIT_PRICE_MSAT_PER_GB - 1))"
  PAID_EXIT_REJECT_PROVIDER_LINK="${PAID_EXIT_PROVIDER_LINK/maxMsatPerGb=${PAID_EXIT_PRICE_MSAT_PER_GB}/maxMsatPerGb=${PAID_EXIT_REJECT_MAX_MSAT_PER_GB}}"
  if [[ "$PAID_EXIT_REJECT_PROVIDER_LINK" == "$PAID_EXIT_PROVIDER_LINK" ]]; then
    echo "exit-node docker e2e failed: provider link omitted its price ceiling" >&2
    printf '%s\n' "$PAID_EXIT_PROVIDER_LINK" >&2
    exit 1
  fi
  DISCOVER_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit discover \
    --config "$CONFIG_PATH" \
    --duration-secs 20 \
    --provider "$PAID_EXIT_REJECT_PROVIDER_LINK" \
    --json | tr -d '\r')"
  if ! jq -e '.offers | length == 0' <<<"$DISCOVER_JSON" >/dev/null; then
    echo "exit-node docker e2e failed: targeted import accepted an offer above its price ceiling" >&2
    printf '%s\n' "$DISCOVER_JSON" >&2
    exit 1
  fi
  DISCOVER_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit discover \
    --config "$CONFIG_PATH" \
    --duration-secs 0 \
    --provider "$PAID_EXIT_PROVIDER_LINK" \
    --json | tr -d '\r')"
  assert_exact_paid_exit_offer provider-link "$DISCOVER_JSON"
  PAID_BUY_CAPACITY_SAT="$PAID_EXIT_TOKEN_AMOUNT_SAT"
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    PAID_BUY_CAPACITY_SAT="$PAID_EXIT_SPILMAN_CHANNEL_CAPACITY_SAT"
  fi
  if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]]; then
    "${COMPOSE[@]}" exec -T node-b nvpn set \
      --config "$CONFIG_PATH" \
      --internet-source paid_automatic >/dev/null
  else
    BUY_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit buy \
      --config "$CONFIG_PATH" \
      --mint "$PAID_EXIT_MINT" \
      --channel-capacity-sat "$PAID_BUY_CAPACITY_SAT" \
      --initial-paid-msat "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT" \
      --json \
      "$ALICE_NPUB:internet-exit" | tr -d '\r')"
    if ! PAID_EXIT_SESSION_ID="$(jq -r '.session.session_id // empty' <<<"$BUY_JSON" 2>/dev/null)"; then
      echo "exit-node docker e2e failed: buyer session output was not valid JSON" >&2
      printf '%s\n' "$BUY_JSON" >&2
      exit 1
    fi
    PAID_EXIT_CHANNEL_ID="$(jq -r '.session.channel_id // empty' <<<"$BUY_JSON")"
    PAID_EXIT_LEASE_ID="$(jq -r '.session.lease_id // empty' <<<"$BUY_JSON")"
    if [[ -z "$PAID_EXIT_SESSION_ID" || -z "$PAID_EXIT_CHANNEL_ID" || -z "$PAID_EXIT_LEASE_ID" ]]; then
      echo "exit-node docker e2e failed: buyer session identifiers were not created" >&2
      printf '%s\n' "$BUY_JSON" >&2
      exit 1
    fi
  fi

  if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]]; then
    : # The running daemon performs selection, health proof, and wallet funding.
  elif [[ "$PAID_EXIT_PAYMENT_MODE" == "token" ]]; then
    PAID_SENT_AT="$("${COMPOSE[@]}" exec -T node-a date +%s | tr -d '\r')"
    PAID_EXPIRES_AT="$((PAID_SENT_AT + 3600))"
    PAID_ENVELOPE="$(
      cat <<EOF
{"version":1,"service_id":"internet-exit","lease_id":"$PAID_EXIT_LEASE_ID","buyer":"$BOB_NPUB","seller":"$ALICE_NPUB","sent_at_unix":$PAID_SENT_AT,"payload":{"type":"cashu_token_lease","channel_id":"$PAID_EXIT_CHANNEL_ID","mint_url":"$PAID_EXIT_MINT","unit":"sat","amount":$PAID_EXIT_TOKEN_AMOUNT_SAT,"paid_msat":$PAID_EXIT_TOKEN_PAID_MSAT,"expires_unix":$PAID_EXPIRES_AT,"token":"cashuBdockerpaidexit"}}
EOF
    )"
    printf '%s' "$PAID_ENVELOPE" | "${COMPOSE[@]}" exec -T node-a nvpn paid-exit apply-payment \
      --config "$CONFIG_PATH" \
      --json \
      --envelope-stdin >/dev/null
    PAID_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
    PAID_COMPACT="$(printf '%s' "$PAID_STATUS" | compact_json)"
    grep -q '"mode":"cashu_token_lease"' <<<"$PAID_COMPACT"
    grep -q '"has_token":true' <<<"$PAID_COMPACT"
  else
    OPEN_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit create-payment \
      --config "$CONFIG_PATH" \
      "$PAID_EXIT_SESSION_ID" \
      --kind channel-open \
      --open-from-wallet \
      --mint "$PAID_EXIT_MINT" \
      --paid-msat "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT" \
      --json | tr -d '\r')"
    if ! OPEN_ENVELOPE="$(jq -c '.payment.envelope' <<<"$OPEN_JSON" 2>/dev/null)"; then
      echo "exit-node docker e2e failed: buyer channel-open output was not valid JSON" >&2
      printf '%s\n' "$OPEN_JSON" >&2
      exit 1
    fi
    if [[ -z "$OPEN_ENVELOPE" || "$OPEN_ENVELOPE" == "null" ]]; then
      echo "exit-node docker e2e failed: buyer channel-open did not include a payment envelope" >&2
      printf '%s\n' "$OPEN_JSON" >&2
      exit 1
    fi
    printf '%s' "$OPEN_ENVELOPE" | "${COMPOSE[@]}" exec -T node-a nvpn paid-exit apply-payment \
      --config "$CONFIG_PATH" \
      --json \
      --envelope-stdin >/dev/null

    PAID_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
    PAID_COMPACT="$(printf '%s' "$PAID_STATUS" | compact_json)"
    grep -q '"mode":"cashu_spilman"' <<<"$PAID_COMPACT"
  fi
  if [[ "$PAID_EXIT_SELECTION_MODE" != "automatic" ]] \
    && jq -e 'any(.seller_admissions[]?; .allow_routing == true)' \
      <<<"$PAID_STATUS" >/dev/null
  then
    echo "exit-node docker e2e failed: seller admitted a paid route before binding the buyer tunnel address" >&2
    printf '%s\n' "$PAID_STATUS" >&2
    exit 1
  fi
else
  "${COMPOSE[@]}" exec -T node-a nvpn start --daemon --connect --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn start --daemon --connect --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null
fi

if truthy "$PAID_EXIT_MODE"; then
  PAID_STATUS=""
  for _ in $(seq 1 80); do
    PAID_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
    if jq -e 'any(.seller_admissions[]?; .allow_routing == true)' <<<"$PAID_STATUS" >/dev/null; then
      break
    fi
    sleep 1
  done
  if ! jq -e 'any(.seller_admissions[]?; .allow_routing == true)' <<<"$PAID_STATUS" >/dev/null; then
    echo "exit-node docker e2e failed: authenticated paid session-open never admitted the buyer tunnel address" >&2
    printf '%s\n' "$PAID_STATUS" >&2
    exit 1
  fi
  if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]]; then
    BUYER_PAID_STATUS="$("${COMPOSE[@]}" exec -T node-b nvpn paid-exit status --json | tr -d '\r')"
    PAID_EXIT_SESSION_ID="$(jq -r \
      --arg seller "$ALICE_NPUB" \
      '[.sessions[]? as $session
        | .channels[]?
        | select(
            .channel_id == $session.channel_id
            and .role == "buyer"
            and .counterparty_npub == $seller
          )
        | $session
      ] | last | .session_id // empty' \
      <<<"$BUYER_PAID_STATUS")"
    if [[ -z "$PAID_EXIT_SESSION_ID" ]]; then
      echo "exit-node docker e2e failed: automatic selection admitted traffic without a persisted buyer session" >&2
      printf '%s\n' "$BUYER_PAID_STATUS" >&2
      exit 1
    fi
  fi
fi

ALICE_STATUS=""
BOB_STATUS=""
DEFAULT_ROUTE=""
for _ in $(seq 1 80); do
  ALICE_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn status --json --discover-secs 0 | tr -d '\r')"
  BOB_STATUS="$("${COMPOSE[@]}" exec -T node-b nvpn status --json --discover-secs 0 | tr -d '\r')"
  ALICE_COMPACT="$(printf '%s' "$ALICE_STATUS" | compact_json)"
  BOB_COMPACT="$(printf '%s' "$BOB_STATUS" | compact_json)"
  ALICE_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-a nvpn ip | tr -d '\r')"
  BOB_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-b nvpn ip | tr -d '\r')"
  DEFAULT_ROUTE="$("${COMPOSE[@]}" exec -T node-b sh -lc "ip route show default | head -n1 | tr -d '\r'")"
  ADVERTISED_EXIT_READY=0
  if truthy "$PAID_EXIT_MODE" \
    || grep -q '"effective_advertised_routes":\[[^]]*"0.0.0.0/0"' <<<"$ALICE_COMPACT"; then
    ADVERTISED_EXIT_READY=1
  fi
  FIPS_PEERS_READY=0
  if truthy "$PAID_EXIT_MODE"; then
    # The authenticated paid session and seller admission above are the paid
    # route readiness proof. Private-roster mesh readiness is intentionally
    # unrelated to a marketplace-selected exit.
    FIPS_PEERS_READY=1
  elif grep -q '"mesh_ready":true' <<<"$ALICE_COMPACT" \
    && grep -q '"mesh_ready":true' <<<"$BOB_COMPACT" \
    && grep -q '"connected_peer_count":1' <<<"$ALICE_COMPACT" \
    && grep -q '"connected_peer_count":1' <<<"$BOB_COMPACT" \
    && grep -q '"endpoint":"fips"' <<<"$ALICE_COMPACT" \
    && grep -q '"endpoint":"fips"' <<<"$BOB_COMPACT"; then
    FIPS_PEERS_READY=1
  fi

  if grep -q '"status_source":"daemon"' <<<"$ALICE_COMPACT" \
    && grep -q '"status_source":"daemon"' <<<"$BOB_COMPACT" \
    && grep -q '"running":true' <<<"$ALICE_COMPACT" \
    && grep -q '"running":true' <<<"$BOB_COMPACT" \
    && [[ "$FIPS_PEERS_READY" == 1 ]] \
    && [[ "$ADVERTISED_EXIT_READY" == 1 ]] \
    && grep -q 'dev utun100' <<<"$DEFAULT_ROUTE" \
    && [[ -n "$ALICE_TUNNEL_IP" ]] \
    && [[ -n "$BOB_TUNNEL_IP" ]]; then
    break
  fi
  sleep 1
done

printf 'ALICE STATUS\n%s\n' "$ALICE_STATUS"
printf 'BOB STATUS\n%s\n' "$BOB_STATUS"

ALICE_COMPACT="$(printf '%s' "$ALICE_STATUS" | compact_json)"
BOB_COMPACT="$(printf '%s' "$BOB_STATUS" | compact_json)"
grep -q '"status_source":"daemon"' <<<"$ALICE_COMPACT"
grep -q '"status_source":"daemon"' <<<"$BOB_COMPACT"
grep -q '"running":true' <<<"$ALICE_COMPACT"
grep -q '"running":true' <<<"$BOB_COMPACT"
if grep -q 'FIPS route refresh failed' <<<"$ALICE_STATUS$BOB_STATUS"; then
  echo "exit-node docker e2e failed: daemon reported FIPS route refresh failure" >&2
  exit 1
fi
if truthy "$PAID_EXIT_MODE"; then
  if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]]; then
    jq -e '.internet_source == "paid_automatic"' <<<"$BOB_STATUS" >/dev/null || {
      echo "exit-node docker e2e failed: automatic mode was not retained" >&2
      printf '%s\n' "$BOB_STATUS" >&2
      exit 1
    }
  fi
  PAID_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
  jq -e 'any(.seller_admissions[]?; .allow_routing == true)' <<<"$PAID_STATUS" >/dev/null
else
  grep -q '"mesh_ready":true' <<<"$ALICE_COMPACT"
  grep -q '"mesh_ready":true' <<<"$BOB_COMPACT"
  grep -q '"connected_peer_count":1' <<<"$ALICE_COMPACT"
  grep -q '"connected_peer_count":1' <<<"$BOB_COMPACT"
  grep -q '"endpoint":"fips"' <<<"$ALICE_COMPACT"
  grep -q '"endpoint":"fips"' <<<"$BOB_COMPACT"
fi
assert_no_private_b_fips_shortcut "$ALICE_STATUS" "node-a"
assert_no_private_b_fips_shortcut "$BOB_STATUS" "node-b"
if ! truthy "$PAID_EXIT_MODE"; then
  grep -q '"effective_advertised_routes":\[[^]]*"0.0.0.0/0"' <<<"$ALICE_COMPACT"
fi

if [[ -z "$ALICE_TUNNEL_IP" || -z "$BOB_TUNNEL_IP" ]]; then
  echo "exit-node docker e2e failed: unable to resolve node tunnel IPs from status output" >&2
  exit 1
fi

DEFAULT_ROUTE="$("${COMPOSE[@]}" exec -T node-b sh -lc "ip route show default | head -n1 | tr -d '\r'")"

if ! grep -q 'dev utun100' <<<"$DEFAULT_ROUTE"; then
  echo "exit-node docker e2e failed: default route did not switch to the tunnel" >&2
  echo "$DEFAULT_ROUTE"
  exit 1
fi

PUBLIC_ROUTE="$("${COMPOSE[@]}" exec -T node-b sh -lc "ip route get $PUBLIC_INTERNET_TARGET | tr -d '\r'")"

if ! grep -q 'dev utun100' <<<"$PUBLIC_ROUTE"; then
  echo "exit-node docker e2e failed: public internet route did not switch to the tunnel" >&2
  echo "$PUBLIC_ROUTE"
  exit 1
fi

REALIZED_IP_LOG="/tmp/nvpn-exit-node-realized-ip.log"
"${COMPOSE[@]}" exec -T internet-target sh -lc \
  "timeout 12 tcpdump -ni any -c 1 'icmp and src host $NODE_A_PUBLIC_IP and dst host $PUBLIC_INTERNET_TARGET'" \
  >"$REALIZED_IP_LOG" 2>&1 &
TCPDUMP_PID=$!
sleep 1

if ! ping_until_success node-b "$PUBLIC_INTERNET_TARGET" /tmp/nvpn-exit-node-public-ping.log; then
  echo "exit-node docker e2e failed: unable to reach public internet target '$PUBLIC_INTERNET_TARGET' through exit node" >&2
  if [[ -f /tmp/nvpn-exit-node-public-ping.log ]]; then
    cat /tmp/nvpn-exit-node-public-ping.log
  fi
  exit 1
fi
if ! wait "$TCPDUMP_PID"; then
  echo "exit-node docker e2e failed: public target did not observe ICMP from exit IP '$NODE_A_PUBLIC_IP'" >&2
  cat "$REALIZED_IP_LOG" 2>/dev/null || true
  exit 1
fi
grep -q "$NODE_A_PUBLIC_IP" "$REALIZED_IP_LOG"
if ! truthy "$PAID_EXIT_MODE"; then
  assert_secure_exit_dns
fi

if truthy "$PAID_EXIT_MODE"; then
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    PROBE_BASE_URL="http://$PUBLIC_INTERNET_TARGET:$PAID_EXIT_PROBE_PORT"
    if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]]; then
      AUTOMATIC_FUNDED_STATUS=""
      for _ in $(seq 1 30); do
        AUTOMATIC_FUNDED_STATUS="$("${COMPOSE[@]}" exec -T node-b nvpn paid-exit status --json | tr -d '\r')"
        if automatic_buyer_session_funded \
          "$AUTOMATIC_FUNDED_STATUS" "$PAID_EXIT_SESSION_ID"; then
          break
        fi
        sleep 1
      done
      if ! automatic_buyer_session_funded \
        "$AUTOMATIC_FUNDED_STATUS" "$PAID_EXIT_SESSION_ID"; then
        echo "exit-node docker e2e failed: automatic session was admitted but not funded and signed" >&2
        printf '%s\n' "$AUTOMATIC_FUNDED_STATUS" >&2
        exit 1
      fi
      "${COMPOSE[@]}" exec -T node-b python3 -c '
import sys
import time
import urllib.request

for _ in range(64):
    with urllib.request.urlopen(sys.argv[1], timeout=15) as response:
        body = response.read()
    if len(body) != 32768:
        raise SystemExit(f"unexpected paid-exit download length: {len(body)}")
    time.sleep(0.25)
' "$PROBE_BASE_URL/down?bytes=32768"
    else
      PAID_EXIT_PROBE_JSON="$("${COMPOSE[@]}" exec -T node-b env RUST_LOG=warn nvpn paid-exit probe \
        --config "$CONFIG_PATH" \
        "$PAID_EXIT_SESSION_ID" \
        --no-stun \
        --ip-url "$PROBE_BASE_URL/ip" \
        --geoip-url-template "$PROBE_BASE_URL/geoip/{ip}" \
        --download-url "$PROBE_BASE_URL/down?bytes={bytes}" \
        --upload-url "$PROBE_BASE_URL/up" \
        --bandwidth-bytes 1024 \
        --samples 2 \
        --timeout-secs 5 \
        --no-reload-daemon \
        --json | tr -d '\r')"
      if ! jq -e --arg ip "$NODE_A_PUBLIC_IP" '
        .measurement.realized_exit_ip == $ip
        and .measurement.observed_country_code == "FI"
        and .measurement.observed_asn == 64500
        and ((.measurement.quality.latency_ms | type) == "number")
        and ((.measurement.quality.jitter_ms | type) == "number")
        and .measurement.quality.packet_loss_ppm == 0
        and ((.measurement.quality.down_bps // 0) > 0)
        and ((.measurement.quality.up_bps // 0) > 0)
        and .geoip_error == null
        and .bandwidth_error == null
        and .probe.changed == true
      ' <<<"$PAID_EXIT_PROBE_JSON" >/dev/null; then
        echo "exit-node docker e2e failed: buyer paid-exit probe did not measure realized IP, GeoIP, and bandwidth" >&2
        printf '%s\n' "$PAID_EXIT_PROBE_JSON" >&2
        exit 1
      fi
    fi

    BUYER_PAID_STATUS=""
    for _ in $(seq 1 30); do
      BUYER_PAID_STATUS="$("${COMPOSE[@]}" exec -T node-b nvpn paid-exit status --json | tr -d '\r')"
      if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]] \
        && automatic_buyer_paid_session_persisted \
          "$BUYER_PAID_STATUS" \
          "$PAID_EXIT_SESSION_ID" \
          "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT"; then
        break
      fi
      if [[ "$PAID_EXIT_SELECTION_MODE" != "automatic" ]] \
        && buyer_paid_session_persisted \
          "$BUYER_PAID_STATUS" \
          "$PAID_EXIT_SESSION_ID" \
          "$NODE_A_PUBLIC_IP" \
          "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT"; then
        break
      fi
      sleep 1
    done
    BUYER_PAID_SESSION_READY=0
    if [[ "$PAID_EXIT_SELECTION_MODE" == "automatic" ]] \
      && automatic_buyer_paid_session_persisted \
        "$BUYER_PAID_STATUS" \
        "$PAID_EXIT_SESSION_ID" \
        "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT"; then
      BUYER_PAID_SESSION_READY=1
    elif [[ "$PAID_EXIT_SELECTION_MODE" != "automatic" ]] \
      && buyer_paid_session_persisted \
        "$BUYER_PAID_STATUS" \
        "$PAID_EXIT_SESSION_ID" \
        "$NODE_A_PUBLIC_IP" \
        "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT"; then
      BUYER_PAID_SESSION_READY=1
    fi
    if [[ "$BUYER_PAID_SESSION_READY" != 1 ]]; then
      echo "exit-node docker e2e failed: buyer session did not persist health, funding, and paid routing" >&2
      printf '%s\n' "$BUYER_PAID_STATUS" >&2
      exit 1
    fi

    PAID_AFTER_STATUS=""
    for _ in $(seq 1 30); do
      PAID_AFTER_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
      if jq -e --argjson initial_paid_msat "$PAID_EXIT_SPILMAN_OPEN_PAID_MSAT" '
        any(.channels[]?;
          .role == "seller"
          and .payment.mode == "cashu_spilman"
          and .payment.paid_msat > $initial_paid_msat
          and .payment.cashu_spilman.has_signature == true
        )
        and any(.sessions[]?;
          .routing.state == "paid"
          and .routing.allow_routing == true
        )
      ' <<<"$PAID_AFTER_STATUS" >/dev/null; then
        break
      fi
      sleep 1
    done
    PAID_AFTER_COMPACT="$(printf '%s' "$PAID_AFTER_STATUS" | compact_json)"
    grep -q '"mode":"cashu_spilman"' <<<"$PAID_AFTER_COMPACT"
    grep -q '"state":"paid"' <<<"$PAID_AFTER_COMPACT"
    grep -q '"allow_routing":true' <<<"$PAID_AFTER_COMPACT"
  else
    PAID_AFTER_STATUS=""
    for _ in $(seq 1 20); do
      PAID_AFTER_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn paid-exit status --json | tr -d '\r')"
      PAID_AFTER_COMPACT="$(printf '%s' "$PAID_AFTER_STATUS" | compact_json)"
      if grep -q '"mode":"cashu_token_lease"' <<<"$PAID_AFTER_COMPACT" \
        && grep -q '"state":"paid"' <<<"$PAID_AFTER_COMPACT" \
        && grep -q '"allow_routing":true' <<<"$PAID_AFTER_COMPACT"; then
        break
      fi
      sleep 1
    done
    PAID_AFTER_COMPACT="$(printf '%s' "$PAID_AFTER_STATUS" | compact_json)"
    grep -q '"mode":"cashu_token_lease"' <<<"$PAID_AFTER_COMPACT"
    grep -q '"state":"paid"' <<<"$PAID_AFTER_COMPACT"
    grep -q '"allow_routing":true' <<<"$PAID_AFTER_COMPACT"
  fi
fi

if truthy "$PAID_EXIT_MODE" && [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
  run_spilman_resale_matrix
fi

echo "--- Default route ---"
echo "$DEFAULT_ROUTE"
echo "--- Public internet route ---"
echo "$PUBLIC_ROUTE"
echo "--- Public internet ping ---"
cat /tmp/nvpn-exit-node-public-ping.log
if ! truthy "$PAID_EXIT_MODE"; then
  echo "--- Secure DNS through exit ---"
  cat /tmp/nvpn-exit-node-secure-dns.log
fi
echo "--- Realized exit IP capture ---"
cat "$REALIZED_IP_LOG"
if [[ -n "$PAID_EXIT_PROBE_JSON" ]]; then
  echo "--- Paid exit buyer probe ---"
  printf '%s\n' "$PAID_EXIT_PROBE_JSON"
fi

assert_idle_cpu_below node-a
assert_idle_cpu_below node-b

if truthy "$PAID_EXIT_MODE"; then
  if [[ "$PAID_EXIT_PAYMENT_MODE" == "spilman" ]]; then
    echo "paid-exit docker e2e passed: $PAID_EXIT_SELECTION_MODE selection and the automatically streamed Spilman balance update allowed paid tunnel traffic, and the public target observed exit IP $NODE_A_PUBLIC_IP"
  else
    echo "paid-exit docker e2e passed: token-lease admission allowed paid tunnel traffic, and the public target observed exit IP $NODE_A_PUBLIC_IP"
  fi
else
  echo "exit-node docker e2e passed: tunnel traffic reached the selected exit node, the default route switched into the tunnel, and the public target observed exit IP $NODE_A_PUBLIC_IP"
fi
