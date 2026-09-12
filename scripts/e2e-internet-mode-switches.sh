#!/usr/bin/env bash
# Sourced by the paid-exit Docker fixture after its initial funded route check.
run_internet_mode_switch_matrix() {
  local upstream_npub server_pub client_priv client_pub
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn init --force >/dev/null
  use_fips_only_control_pubsub wireguard-upstream
  upstream_npub="$(nostr_pubkey_from_config wireguard-upstream)"
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn set \
    --network-id "$PAID_EXIT_BUYER_NETWORK_ID" --participant "$BOB_NPUB" \
    --endpoint "$WG_UPSTREAM_IP:51820" --listen-port 51820 \
    --fips-advertise-endpoint true --advertise-exit-node \
    --fips-bootstrap-public-peers false --fips-nostr-discovery-enabled false \
    --internet-source direct --exit-node-leak-protection false \
    --fips-peer-endpoint "$BOB_NPUB=$NAT_B_PUBLIC_IP:51820" >/dev/null
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn start --daemon --connect \
    --mesh-refresh-interval-secs "$MESH_REFRESH_SECS" >/dev/null
  "${COMPOSE[@]}" exec -T node-b nvpn set --participant "$upstream_npub" \
    --fips-peer-endpoint "$upstream_npub=$WG_UPSTREAM_IP:51820" >/dev/null

  "${COMPOSE[@]}" exec -T wireguard-upstream sh -eu -c '
    umask 077
    wg genkey > /tmp/modes-server.key
    wg genkey > /tmp/modes-client.key
    wg pubkey < /tmp/modes-server.key > /tmp/modes-server.pub
    wg pubkey < /tmp/modes-client.key > /tmp/modes-client.pub
  '
  server_pub="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/modes-server.pub)"
  client_priv="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/modes-client.key)"
  client_pub="$("${COMPOSE[@]}" exec -T wireguard-upstream cat /tmp/modes-client.pub)"
  "${COMPOSE[@]}" exec -T wireguard-upstream sh -eu -c "
    ip link add wg0 type wireguard
    ip address add 10.99.98.1/24 dev wg0
    wg set wg0 listen-port $WG_LISTEN_PORT private-key /tmp/modes-server.key
    wg set wg0 peer '$client_pub' allowed-ips 10.99.98.2/32
    ip link set wg0 up
    iptables -t nat -A POSTROUTING -s 10.99.98.0/24 -j MASQUERADE
  "
  "${COMPOSE[@]}" exec -T node-b sh -c 'umask 077; cat > /tmp/modes-wg.conf' <<EOF
[Interface]
PrivateKey = $client_priv
Address = 10.99.98.2/32
[Peer]
PublicKey = $server_pub
Endpoint = $WG_UPSTREAM_IP:$WG_LISTEN_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 1
EOF
  "${COMPOSE[@]}" exec -T node-b nvpn set \
    --wireguard-exit-config-file /tmp/modes-wg.conf --wireguard-exit-enabled false >/dev/null
  "${COMPOSE[@]}" exec -T node-b python3 - \
    "$PROBE_BASE_URL" "$NODE_A_PUBLIC_IP" "$NAT_B_PUBLIC_IP" "$WG_UPSTREAM_IP" \
    "$upstream_npub" "$PAID_EXIT_MINT" "$PAID_EXIT_SELECTION_MODE" \
    < "$ROOT_DIR/scripts/e2e-internet-mode-switches.py"
  "${COMPOSE[@]}" pause cashu-mint >/dev/null
  "${COMPOSE[@]}" exec -T node-b python3 - pending "$PAID_EXIT_MINT" \
    "$PAID_EXIT_SELECTION_MODE" "$PROBE_BASE_URL" "$NODE_A_PUBLIC_IP" \
    < "$ROOT_DIR/scripts/e2e-internet-mode-funding.py"
  "${COMPOSE[@]}" unpause cashu-mint >/dev/null
  "${COMPOSE[@]}" exec -T node-b python3 - completed "$PAID_EXIT_MINT" \
    "$PAID_EXIT_SELECTION_MODE" "$PROBE_BASE_URL" "$NODE_A_PUBLIC_IP" \
    < "$ROOT_DIR/scripts/e2e-internet-mode-funding.py"
  "${COMPOSE[@]}" exec -T wireguard-upstream nvpn stop --force >/dev/null
  "${COMPOSE[@]}" exec -T wireguard-upstream ip link del wg0
}
