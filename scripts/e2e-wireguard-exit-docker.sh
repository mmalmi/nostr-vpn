#!/usr/bin/env bash
# Verifies that node-a's own internet traffic egresses through the WireGuard
# upstream tunnel (Mullvad/Proton-style) and not directly via its bridge IP.
#
# Topology:
#   internet (10.203.0.0/24)          public (203.0.113.0/24)
#     - wg-upstream  10.203.0.20        - wg-upstream    203.0.113.20
#     - node-a       10.203.0.10        - internet-target 203.0.113.100
#     - node-b       10.203.0.11
#
# 203.0.113.0/24 is reachable only via wg-upstream, so without the WG tunnel
# node-a has no path to internet-target at all. Any successful ping proves
# traffic is going through the WG upstream tunnel.
#
# Pass criteria:
#   - private-mesh traffic remains bidirectional while node-a uses the WG exit.
#   - node-a's source-policy table keeps the mesh CIDR on its FIPS tunnel.
#   - pings from node-a to internet-target arrive with source IP =
#     wg-upstream's public-side IP (after MASQUERADE), not node-a's bridge IP.
#   - a hostile/permissive upstream cannot initiate packets into node-b's
#     nvpn tunnel IP through node-a's WG client.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="nostr-vpn-e2e-wireguard-exit"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.wireguard-exit-e2e.yml")

CONFIG_PATH="/root/.config/nvpn/config.toml"
TARGET_IP="${NVPN_WG_EXIT_TARGET_IP:-203.0.113.100}"
WG_UPSTREAM_IP="${NVPN_WG_EXIT_UPSTREAM_IP:-10.203.0.20}"
WG_UPSTREAM_PUBLIC_IP="${NVPN_WG_EXIT_UPSTREAM_PUBLIC_IP:-203.0.113.20}"
NETWORK_ID="${NVPN_WG_EXIT_NETWORK_ID:-docker-wireguard-exit}"
NODE_A_IP="${NVPN_WG_EXIT_NODE_A_IP:-10.203.0.10}"
WG_LISTEN_PORT="51820"
WG_TUNNEL_NET="10.99.99.0/24"
WG_SERVER_TUNNEL_IP="10.99.99.1"
WG_CLIENT_TUNNEL_IP="10.99.99.2"
MESH_TUNNEL_NET="10.44.0.0/16"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm \
    "${PROJECT_NAME}_internet" \
    "${PROJECT_NAME}_public" >/dev/null 2>&1 || true
  for network in "${PROJECT_NAME}_internet" "${PROJECT_NAME}_public"; do
    for _ in $(seq 1 20); do
      docker network inspect "$network" >/dev/null 2>&1 || break
      sleep 1
    done
  done
}

dump_debug() {
  set +e
  echo "wireguard-exit e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  for service in internet-target wg-upstream node-a node-b; do
    echo "--- ${service}: ip addr ---"
    "${COMPOSE[@]}" exec -T "$service" sh -lc "ip -br addr || true" || true
    echo "--- ${service}: ip route ---"
    "${COMPOSE[@]}" exec -T "$service" sh -lc "ip route || true" || true
  done
  echo "--- node-a: ip rule ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "ip rule || true" || true
  echo "--- node-a: ip route show table 51888 ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "ip -4 route show table 51888 || true" || true
  echo "--- node-a: application egress policy routes ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "ip -4 route show table 20054 || true" || true
  echo "--- node-a: wg show ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "wg show || true" || true
  echo "--- node-a: iptables filter ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "iptables -S || true" || true
  echo "--- node-a: nvpn status ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "nvpn status --json --discover-secs 0 || true" || true
  echo "--- node-a: daemon log tail ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "tail -n 200 /root/.config/nvpn/daemon.log 2>/dev/null || true" || true
  echo "--- node-b: nvpn status ---"
  "${COMPOSE[@]}" exec -T node-b sh -lc "nvpn status --json --discover-secs 0 || true" || true
  echo "--- node-b: iptables filter ---"
  "${COMPOSE[@]}" exec -T node-b sh -lc "iptables -S || true; iptables -L nvpn-wg-ingress-counts -v -n -x || true" || true
  echo "--- wg-upstream: wg show ---"
  "${COMPOSE[@]}" exec -T wg-upstream sh -lc "wg show || true" || true
  echo "--- wg-upstream: iptables nat ---"
  "${COMPOSE[@]}" exec -T wg-upstream sh -lc "iptables -t nat -S || true" || true
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

  echo "wireguard-exit e2e failed: service '$service' did not reach running state" >&2
  exit 1
}

cleanup

case "${NVPN_E2E_SKIP_NODE_BUILD:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    ;;
  *)
    "${COMPOSE[@]}" build node-a >/dev/null
    ;;
esac
"${COMPOSE[@]}" up -d --no-build internet-target wg-upstream node-a node-b >/dev/null
for service in internet-target wg-upstream node-a node-b; do
  wait_for_service "$service"
done

# Step 1: generate WireGuard keys on the upstream server.
# (Use plain sh — the e2e image only ships dash, which does not support pipefail.)
"${COMPOSE[@]}" exec -T wg-upstream sh -eu -c '
umask 077
mkdir -p /etc/wireguard
[ -s /etc/wireguard/server.key ] || wg genkey > /etc/wireguard/server.key
[ -s /etc/wireguard/client.key ] || wg genkey > /etc/wireguard/client.key
wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
wg pubkey < /etc/wireguard/client.key > /etc/wireguard/client.pub
' >/dev/null

SERVER_PRIV="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/server.key | tr -d '\r\n')"
SERVER_PUB="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/server.pub | tr -d '\r\n')"
CLIENT_PRIV="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/client.key | tr -d '\r\n')"
CLIENT_PUB="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/client.pub | tr -d '\r\n')"

# Step 2: bring up the WG server interface on wg-upstream and enable
# masquerading so decrypted client traffic can reach the internet-target.
"${COMPOSE[@]}" exec -T wg-upstream sh -eu -c "
# wg-upstream is dual-homed: 'internet' eth (where WG clients arrive) and
# 'public' eth (where the upstream forwards plaintext traffic to the
# internet-target). MASQUERADE on the public eth so return traffic finds us.
public_iface=\"\$(ip -o -4 addr show | awk '\$4 == \"${WG_UPSTREAM_PUBLIC_IP}/24\" { print \$2; exit }')\"
[ -n \"\$public_iface\" ]

ip link del wg0 2>/dev/null || true
ip link add dev wg0 type wireguard
ip address add ${WG_SERVER_TUNNEL_IP}/24 dev wg0
wg set wg0 listen-port ${WG_LISTEN_PORT} private-key /etc/wireguard/server.key
wg set wg0 peer ${CLIENT_PUB} allowed-ips ${WG_CLIENT_TUNNEL_IP}/32,${MESH_TUNNEL_NET}
ip link set wg0 up
ip route replace ${MESH_TUNNEL_NET} dev wg0

iptables -P FORWARD ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT
iptables -t nat -C POSTROUTING -o \"\$public_iface\" -s ${WG_TUNNEL_NET} -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o \"\$public_iface\" -s ${WG_TUNNEL_NET} -j MASQUERADE
" >/dev/null

# Step 3: provision the two mesh nodes. Node B exists only so node-a has a
# real participant in its roster — the daemon's reconcile loop drives the
# WG upstream code path and we want it to actually run.
for node in node-a node-b; do
  "${COMPOSE[@]}" exec -T "$node" nvpn init --force >/dev/null
done

ALICE_NPUB="$(nostr_pubkey_from_config node-a)"
BOB_NPUB="$(nostr_pubkey_from_config node-b)"

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" ]]; then
  echo "wireguard-exit e2e failed: unable to resolve node npubs" >&2
  exit 1
fi

WG_CONFIG="[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${WG_CLIENT_TUNNEL_IP}/32
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${WG_UPSTREAM_IP}:${WG_LISTEN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"

# Plain `nvpn set --wireguard-exit-config "$WG_CONFIG"` chokes on multiline
# values, so write the config to a file inside the container and import it.
"${COMPOSE[@]}" exec -T node-a sh -lc 'cat > /tmp/wg-upstream.conf' <<<"$WG_CONFIG"

"${COMPOSE[@]}" exec -T node-a nvpn set \
  --network-id "$NETWORK_ID" \
  --participant "$BOB_NPUB" \
  --endpoint "${NODE_A_IP}:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false \
  --fips-peer-endpoint "$BOB_NPUB=10.203.0.11:51820" \
  --wireguard-exit-config-file /tmp/wg-upstream.conf \
  --wireguard-exit-enabled true >/dev/null
"${COMPOSE[@]}" exec -T node-b nvpn set \
  --network-id "$NETWORK_ID" \
  --participant "$ALICE_NPUB" \
  --endpoint "10.203.0.11:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false \
  --fips-peer-endpoint "$ALICE_NPUB=${NODE_A_IP}:51820" >/dev/null

for node in node-a node-b; do
  "${COMPOSE[@]}" exec -T "$node" sh -lc \
    "sed -i 's|^discovery_timeout_secs = .*|discovery_timeout_secs = 2|' '$CONFIG_PATH'"
done

"${COMPOSE[@]}" exec -T node-a nvpn start --daemon --connect >/dev/null
"${COMPOSE[@]}" exec -T node-b nvpn start --daemon --connect >/dev/null

# Step 4: wait for node-a to bring up wg-mullvad-exit and replace its
# default route. The reconcile loop runs every few seconds; allow up to ~60s.
WG_IFACE=""
for _ in $(seq 1 60); do
  WG_IFACE="$("${COMPOSE[@]}" exec -T node-a sh -lc 'wg show interfaces 2>/dev/null' | tr -d '\r' | awk '{ print $1 }' | head -n1)"
  if [[ -n "$WG_IFACE" ]]; then
    HANDSHAKE="$("${COMPOSE[@]}" exec -T node-a sh -lc "wg show \"$WG_IFACE\" latest-handshakes 2>/dev/null | awk '{ print \$2 }'" | tr -d '\r' || true)"
    if [[ -n "$HANDSHAKE" && "$HANDSHAKE" != "0" ]]; then
      break
    fi
  fi
  # Trigger a packet to provoke the WG handshake.
  "${COMPOSE[@]}" exec -T node-a sh -lc "ping -c 1 -W 1 ${TARGET_IP} >/dev/null 2>&1 || true" || true
  sleep 1
done

if [[ -z "$WG_IFACE" ]]; then
  echo "wireguard-exit e2e failed: node-a never created the wg-mullvad-exit interface" >&2
  exit 1
fi

ALICE_STATUS=""
BOB_STATUS=""
ALICE_TUNNEL_IP=""
BOB_TUNNEL_IP=""
for _ in $(seq 1 80); do
  ALICE_STATUS="$("${COMPOSE[@]}" exec -T node-a nvpn status --json --discover-secs 0 | tr -d '\r')"
  BOB_STATUS="$("${COMPOSE[@]}" exec -T node-b nvpn status --json --discover-secs 0 | tr -d '\r')"
  ALICE_COMPACT="$(printf '%s' "$ALICE_STATUS" | compact_json)"
  BOB_COMPACT="$(printf '%s' "$BOB_STATUS" | compact_json)"
  ALICE_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-a nvpn ip | tr -d '\r')"
  BOB_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-b nvpn ip | tr -d '\r')"

  if grep -q '"status_source":"daemon"' <<<"$ALICE_COMPACT" \
    && grep -q '"status_source":"daemon"' <<<"$BOB_COMPACT" \
    && grep -q '"running":true' <<<"$ALICE_COMPACT" \
    && grep -q '"running":true' <<<"$BOB_COMPACT" \
    && grep -q '"mesh_ready":true' <<<"$ALICE_COMPACT" \
    && grep -q '"mesh_ready":true' <<<"$BOB_COMPACT" \
    && [[ -n "$ALICE_TUNNEL_IP" ]] \
    && [[ -n "$BOB_TUNNEL_IP" ]]; then
    break
  fi
  sleep 1
done

printf 'NODE-A STATUS\n%s\n' "$ALICE_STATUS"
printf 'NODE-B STATUS\n%s\n' "$BOB_STATUS"

ALICE_COMPACT="$(printf '%s' "$ALICE_STATUS" | compact_json)"
BOB_COMPACT="$(printf '%s' "$BOB_STATUS" | compact_json)"
grep -q '"status_source":"daemon"' <<<"$ALICE_COMPACT"
grep -q '"status_source":"daemon"' <<<"$BOB_COMPACT"
grep -q '"running":true' <<<"$ALICE_COMPACT"
grep -q '"running":true' <<<"$BOB_COMPACT"
grep -q '"mesh_ready":true' <<<"$ALICE_COMPACT"
grep -q '"mesh_ready":true' <<<"$BOB_COMPACT"
if [[ -z "$BOB_TUNNEL_IP" ]]; then
  echo "wireguard-exit e2e failed: unable to resolve node-b tunnel IP" >&2
  exit 1
fi

MESH_REPLY_ROUTE="$("${COMPOSE[@]}" exec -T node-a sh -lc \
  "ip -4 route get '$BOB_TUNNEL_IP' from '$ALICE_TUNNEL_IP'" | tr -d '\r')"
FIPS_IFACE="$(awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<<"$MESH_REPLY_ROUTE")"
MESH_POLICY_ROUTE="$("${COMPOSE[@]}" exec -T node-a sh -lc \
  "ip -4 route show table 51888 exact '$MESH_TUNNEL_NET'" | tr -d '\r')"
if [[ -z "$FIPS_IFACE" ]] \
  || ! grep -Fq "$MESH_TUNNEL_NET dev $FIPS_IFACE" <<<"$MESH_POLICY_ROUTE" \
  || ! grep -Fq "dev $FIPS_IFACE" <<<"$MESH_REPLY_ROUTE"; then
  echo "wireguard-exit e2e failed: mesh-sourced replies do not stay on the FIPS tunnel" >&2
  echo "FIPS interface: ${FIPS_IFACE:-unavailable}" >&2
  echo "policy-table mesh route: ${MESH_POLICY_ROUTE:-unavailable}" >&2
  echo "mesh reply route: ${MESH_REPLY_ROUTE:-unavailable}" >&2
  exit 1
fi
# A local network inside the mesh source range, such as a container or VM
# bridge, must keep its own routes while the WG exit policy is installed.
"${COMPOSE[@]}" exec -T node-a sh -lc '
  set -e
  ip link add nvpn-e2e-lan type veth peer name nvpn-e2e-lanp
  ip addr add 10.44.0.1/24 dev nvpn-e2e-lan
  ip link set nvpn-e2e-lanp up
  ip link set nvpn-e2e-lan up'
LOCAL_NET_ROUTE="$("${COMPOSE[@]}" exec -T node-a sh -lc \
  'ip -4 route get 10.44.0.5 from 10.44.0.1' | tr -d '\r')"
"${COMPOSE[@]}" exec -T node-a ip link del nvpn-e2e-lan
LOCAL_NET_IFACE="$(awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' <<<"$LOCAL_NET_ROUTE")"
if [[ "$LOCAL_NET_IFACE" != "nvpn-e2e-lan" ]]; then
  echo "wireguard-exit e2e failed: the WG exit policy captured a local network in the mesh range" >&2
  echo "local network route: ${LOCAL_NET_ROUTE:-unavailable}" >&2
  exit 1
fi
if ! "${COMPOSE[@]}" exec -T node-a ping -I "$ALICE_TUNNEL_IP" -c 5 -W 2 "$BOB_TUNNEL_IP" \
  >/tmp/nvpn-wg-exit-mesh-a-to-b.log; then
  echo "wireguard-exit e2e failed: node-a could not reach node-b while the WG exit was active" >&2
  cat /tmp/nvpn-wg-exit-mesh-a-to-b.log >&2 || true
  exit 1
fi
if ! "${COMPOSE[@]}" exec -T node-b ping -I "$BOB_TUNNEL_IP" -c 5 -W 2 "$ALICE_TUNNEL_IP" \
  >/tmp/nvpn-wg-exit-mesh-b-to-a.log; then
  echo "wireguard-exit e2e failed: node-b could not reach node-a while the WG exit was active" >&2
  cat /tmp/nvpn-wg-exit-mesh-b-to-a.log >&2 || true
  exit 1
fi

# The egress guard owns table 20054, while the network manager keeps the
# physical default in main for protected carrier sockets. Inspect the policy
# default and effective application lookup instead of requiring a main-table
# mutation that would break the carrier's underlay route.
DEFAULT_ROUTE="$("${COMPOSE[@]}" exec -T node-a sh -lc "ip -4 route show table 20054 default | tr -d '\r'")"
if ! grep -q "dev $WG_IFACE" <<<"$DEFAULT_ROUTE"; then
  echo "wireguard-exit e2e failed: node-a application policy default does not use the WG upstream" >&2
  echo "policy default route: $DEFAULT_ROUTE"
  exit 1
fi

PUBLIC_ROUTE="$("${COMPOSE[@]}" exec -T node-a sh -lc "ip route get ${TARGET_IP} | tr -d '\r'")"
if ! grep -q "dev $WG_IFACE" <<<"$PUBLIC_ROUTE"; then
  echo "wireguard-exit e2e failed: node-a route to internet target does not use WG upstream" >&2
  echo "route: $PUBLIC_ROUTE"
  exit 1
fi

# Step 5: install per-source ICMP packet counters on internet-target so we can
# tell whether incoming pings arrived from the WG-upstream's public IP
# (MASQUERADEd, which means the tunnel is actually carrying the traffic) or
# from node-a's bridge IP (which would mean the traffic leaked outside the
# tunnel — though in this topology that path is unreachable anyway, the
# counter is a belt-and-suspenders check).
"${COMPOSE[@]}" exec -T internet-target sh -lc "
iptables -F nvpn-wg-counts 2>/dev/null || iptables -N nvpn-wg-counts
iptables -A nvpn-wg-counts -s ${WG_UPSTREAM_PUBLIC_IP} -p icmp -j RETURN
iptables -A nvpn-wg-counts -s ${NODE_A_IP} -p icmp -j RETURN
iptables -C INPUT -j nvpn-wg-counts 2>/dev/null || iptables -I INPUT -j nvpn-wg-counts
iptables -Z nvpn-wg-counts
" >/dev/null

if ! "${COMPOSE[@]}" exec -T node-a ping -c 5 -W 2 "${TARGET_IP}" >/tmp/nvpn-wg-exit-ping.log; then
  echo "wireguard-exit e2e failed: ping from node-a to ${TARGET_IP} did not succeed" >&2
  cat /tmp/nvpn-wg-exit-ping.log || true
  exit 1
fi

COUNT_VIA_WG="$("${COMPOSE[@]}" exec -T internet-target sh -lc "iptables -L nvpn-wg-counts -v -n -x | awk -v ip='${WG_UPSTREAM_PUBLIC_IP}' '\$0 ~ ip { print \$1 }'" | tr -d '\r')"
COUNT_DIRECT="$("${COMPOSE[@]}" exec -T internet-target sh -lc "iptables -L nvpn-wg-counts -v -n -x | awk -v ip='${NODE_A_IP}' '\$0 ~ ip { print \$1 }'" | tr -d '\r')"

echo "--- node-a application policy default route ---"
echo "$DEFAULT_ROUTE"
echo "--- node-a route to ${TARGET_IP} ---"
echo "$PUBLIC_ROUTE"
echo "--- node-a mesh policy route ---"
echo "$MESH_POLICY_ROUTE"
echo "--- node-a mesh reply route ---"
echo "$MESH_REPLY_ROUTE"
echo "--- bidirectional mesh pings with WG exit active ---"
cat /tmp/nvpn-wg-exit-mesh-a-to-b.log
cat /tmp/nvpn-wg-exit-mesh-b-to-a.log
echo "--- ping log ---"
cat /tmp/nvpn-wg-exit-ping.log
echo "--- ICMP packet counts at internet-target ---"
"${COMPOSE[@]}" exec -T internet-target iptables -L nvpn-wg-counts -v -n -x | tr -d '\r'

if [[ -z "$COUNT_VIA_WG" || "$COUNT_VIA_WG" == "0" ]]; then
  echo "wireguard-exit e2e failed: internet-target saw 0 ICMP packets from the WG upstream" >&2
  exit 1
fi

if [[ -n "$COUNT_DIRECT" && "$COUNT_DIRECT" != "0" ]]; then
  echo "wireguard-exit e2e failed: internet-target saw ${COUNT_DIRECT} ICMP packets directly from node-a (traffic leaked outside the WG tunnel)" >&2
  exit 1
fi

# Step 6: security regression guard. Simulate the worst case: a permissive
# local forward policy and a hostile upstream that routes the whole nvpn mesh
# range toward node-a's WG client. Even then, packets initiated by the upstream
# must not enter the mesh or reach node-b.
"${COMPOSE[@]}" exec -T node-a sh -lc "
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -P FORWARD ACCEPT
iptables -S FORWARD | grep -q 'nvpn-wg-upstream-inbound-drop'
" >/dev/null

"${COMPOSE[@]}" exec -T node-b sh -lc "
iptables -F nvpn-wg-ingress-counts 2>/dev/null || iptables -N nvpn-wg-ingress-counts
iptables -A nvpn-wg-ingress-counts -s ${WG_SERVER_TUNNEL_IP} -d ${BOB_TUNNEL_IP} -p icmp -j RETURN
iptables -C INPUT -j nvpn-wg-ingress-counts 2>/dev/null || iptables -I INPUT -j nvpn-wg-ingress-counts
iptables -Z nvpn-wg-ingress-counts
" >/dev/null

"${COMPOSE[@]}" exec -T wg-upstream ping \
  -c 5 \
  -W 1 \
  -I "${WG_SERVER_TUNNEL_IP}" \
  "${BOB_TUNNEL_IP}" >/tmp/nvpn-wg-ingress-ping.log 2>&1 || true

COUNT_UPSTREAM_TO_B="$("${COMPOSE[@]}" exec -T node-b sh -lc "iptables -L nvpn-wg-ingress-counts -v -n -x | awk -v ip='${WG_SERVER_TUNNEL_IP}' '\$0 ~ ip { print \$1 }' | head -n1" | tr -d '\r')"

echo "--- upstream -> node-b tunnel ping log (expected to fail) ---"
cat /tmp/nvpn-wg-ingress-ping.log
echo "--- node-a WG inbound guard rule ---"
"${COMPOSE[@]}" exec -T node-a sh -lc "iptables -S FORWARD | grep 'nvpn-wg-upstream-inbound-drop'" | tr -d '\r'
echo "--- node-b ingress packet counts ---"
"${COMPOSE[@]}" exec -T node-b iptables -L nvpn-wg-ingress-counts -v -n -x | tr -d '\r'

if [[ -z "$COUNT_UPSTREAM_TO_B" ]]; then
  echo "wireguard-exit e2e failed: unable to read node-b ingress packet counter" >&2
  exit 1
fi

if [[ "$COUNT_UPSTREAM_TO_B" != "0" ]]; then
  echo "wireguard-exit e2e failed: node-b saw ${COUNT_UPSTREAM_TO_B} ICMP packets initiated by the WG upstream" >&2
  exit 1
fi

echo "wireguard-exit docker e2e passed: private mesh remained bidirectional, node-a egressed via WG (${COUNT_VIA_WG} icmp pkts), and WG upstream ingress could not reach node-b"
