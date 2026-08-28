#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="nostr-vpn-e2e-fips-roaming"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.e2e.yml")
PRIMARY_NETWORK_NAME="${PROJECT_NAME}_e2e"

NETWORK_ID="docker-fips-roaming"
CONFIG_PATH="/root/.config/nvpn/config.toml"
UDP_PORT=45454
SAFE_TUNNEL_MTU=1150
PING_PAYLOAD_SIZE=1000
UNDERLAY_PREFIX="${NVPN_E2E_UNDERLAY_PREFIX:-10.203.0}"
export NVPN_E2E_UNDERLAY_SUBNET="${NVPN_E2E_UNDERLAY_SUBNET:-$UNDERLAY_PREFIX.0/24}"
export NVPN_E2E_NODE_A_UNDERLAY_IP="${NVPN_E2E_NODE_A_UNDERLAY_IP:-$UNDERLAY_PREFIX.10}"
export NVPN_E2E_NODE_B_UNDERLAY_IP="${NVPN_E2E_NODE_B_UNDERLAY_IP:-$UNDERLAY_PREFIX.11}"
export NVPN_E2E_NODE_C_UNDERLAY_IP="${NVPN_E2E_NODE_C_UNDERLAY_IP:-$UNDERLAY_PREFIX.12}"
MIGRATED_NODE_A_IP="${NVPN_E2E_MIGRATED_NODE_A_IP:-$UNDERLAY_PREFIX.20}"
# A target-signed fallback response should move the established payload owner
# before normal 30s link-dead detection. Leave enough room for Docker
# scheduling and status polling without allowing link-dead to hide a stalled
# authenticated handoff.
FALLBACK_DEADLINE_SECS="${NVPN_E2E_ROAMING_FALLBACK_SECS:-20}"
# Consecutive flaps can meet a draining rekey and several bounded direct-probe
# retries. Active-path retries are paced at 2-4s, and repeated production-image
# runs restore bidirectional direct payload in 5-13s. Fail at 20s instead of
# hiding a stuck recovery behind a minute-long allowance.
DIRECT_RECOVERY_DEADLINE_SECS="${NVPN_E2E_DIRECT_RECOVERY_SECS:-20}"
FALLBACK_HOLD_SECS="${NVPN_E2E_ROAMING_FALLBACK_HOLD_SECS:-12}"
# Direct-path promotion deliberately requires several authenticated payload
# packets in a bounded window. Exercise that production validation with a real
# sustained payload stream instead of balancing on a one-second timer boundary.
PAYLOAD_PROBE_INTERVAL_SECS="${NVPN_E2E_ROAMING_PAYLOAD_PROBE_INTERVAL_SECS:-0.2}"
PAYLOAD_RECOVERY_DEADLINE_SECS="${NVPN_E2E_ROAMING_PAYLOAD_RECOVERY_SECS:-10}"
NETWORK_CHANGE_RECOVERY_DEADLINE_SECS="${NVPN_E2E_NETWORK_CHANGE_RECOVERY_SECS:-30}"
NETWORK_CHANGE_MAX_CONSECUTIVE_PAYLOAD_FAILURES="${NVPN_E2E_NETWORK_CHANGE_MAX_CONSECUTIVE_PAYLOAD_FAILURES:-4}"
LOCAL_ROUTE_HANDSHAKE_FAILURE_MAX="${NVPN_E2E_LOCAL_ROUTE_HANDSHAKE_FAILURE_MAX:-2}"
FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}"
FIPS_RUST_LOG="${NVPN_E2E_FIPS_RUST_LOG:-info}"
LOADED_LATENCY_ENABLED="${NVPN_E2E_ROAMING_LOADED_LATENCY:-1}"
LOADED_LATENCY_DURATION_SECS="${NVPN_E2E_ROAMING_LOADED_LATENCY_DURATION_SECS:-15}"
LOADED_LATENCY_PING_INTERVAL_SECS="${NVPN_E2E_ROAMING_LOADED_LATENCY_PING_INTERVAL_SECS:-0.1}"
LOADED_LATENCY_MAX_P99_MS="${NVPN_E2E_ROAMING_LOADED_LATENCY_MAX_P99_MS:-500}"
LOADED_LATENCY_MAX_GT1000="${NVPN_E2E_ROAMING_LOADED_LATENCY_MAX_GT1000:-0}"
LOADED_LATENCY_MIN_MBPS="${NVPN_E2E_ROAMING_LOADED_LATENCY_MIN_MBPS:-5}"
LOADED_LATENCY_MIN_PING_REPLY_PERCENT="${NVPN_E2E_ROAMING_LOADED_LATENCY_MIN_PING_REPLY_PERCENT:-98}"
SCENARIOS="${NVPN_E2E_ROAMING_SCENARIOS:-all}"

case "$SCENARIOS" in
  all|fallback|network-change|latency) ;;
  *)
    echo "fips roaming e2e failed: NVPN_E2E_ROAMING_SCENARIOS must be 'all', 'fallback', 'network-change', or 'latency'" >&2
    exit 2
    ;;
esac

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "$PRIMARY_NETWORK_NAME" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    docker network inspect "$PRIMARY_NETWORK_NAME" >/dev/null 2>&1 || break
    sleep 1
  done
}

dump_debug() {
  set +e
  echo "fips roaming e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  for service in node-a node-b node-c; do
    echo "--- logs: $service ---"
    "${COMPOSE[@]}" logs --no-color --tail 160 "$service" || true
  done
  for node in node-a node-b node-c; do
    echo "--- $node status ---"
    "${COMPOSE[@]}" exec -T "$node" nvpn status --json --discover-secs 0 || true
    echo "--- $node daemon.state.json ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "cat /root/.config/nvpn/daemon.state.json 2>/dev/null || true" || true
    echo "--- $node daemon.log ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "tail -n 320 /root/.config/nvpn/daemon.log 2>/dev/null || true" || true
    echo "--- $node routes ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "ip route || true" || true
    echo "--- $node utun100 ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "ip addr show utun100 || true" || true
    echo "--- $node iptables ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "iptables -S || true" || true
  done
}

on_exit() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    dump_debug
    if [[ "${NVPN_E2E_KEEP_CONTAINERS_ON_FAIL:-}" == "1" ]]; then
      echo "NVPN_E2E_KEEP_CONTAINERS_ON_FAIL=1, leaving docker containers running for inspection" >&2
      exit "$exit_code"
    fi
  fi
  cleanup
  exit "$exit_code"
}
trap on_exit EXIT

compact_json() {
  tr -d '\n\r\t '
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

  echo "fips roaming e2e failed: service '$service' did not reach running state" >&2
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
    ' '$CONFIG_PATH'
  " | tr -d '\r\"'
}

replace_peer_aliases() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -s -- \
    "$CONFIG_PATH" "$ALICE_NPUB" "$BOB_NPUB" "$CHARLIE_NPUB" <<'SH'
set -eu
config="$1"
alice="$2"
bob="$3"
charlie="$4"
tmp="$(mktemp)"
awk '
  /^\[peer_aliases\]$/ { skip = 1; next }
  /^\[/ { skip = 0 }
  !skip { print }
' "$config" > "$tmp"
{
  cat "$tmp"
  printf '\n[peer_aliases]\n'
  printf '"%s" = "alice"\n' "$alice"
  printf '"%s" = "bob"\n' "$bob"
  printf '"%s" = "charlie"\n' "$charlie"
} > "$config"
rm -f "$tmp"
SH
}

disable_nat_discovery() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -lc '
    config=/root/.config/nvpn/config.toml
    tmp="$(mktemp)"
    awk "
      /^\\[nat\\]$/ { in_nat = 1; print; next }
      /^\\[/ { in_nat = 0 }
      in_nat && /^enabled[[:space:]]*=/ { print \"enabled = false\"; next }
      { print }
    " "$config" > "$tmp"
    mv "$tmp" "$config"
  '
}

start_nvpn_daemon() {
  local node="$1"
  "${COMPOSE[@]}" exec -T "$node" env \
    RUST_LOG="$FIPS_RUST_LOG" \
    NVPN_FIPS_NOSTR_DISCOVERY_POLICY="$FIPS_NOSTR_DISCOVERY_POLICY" \
    NVPN_MESH_MTU_PROFILE=safe \
    NVPN_MESH_UNDERLAY_UDP_MTU=1280 \
    NVPN_MESH_TUNNEL_MTU="$SAFE_TUNNEL_MTU" \
    nvpn start --daemon --connect >/dev/null
}

block_direct_alice_bob_udp() {
  "${COMPOSE[@]}" exec -T node-a sh -s -- "$NVPN_E2E_NODE_B_UNDERLAY_IP" <<'SH'
set -eu
peer_ip="$1"
# Drop inbound packets only. OUTPUT DROP and unreachable routes can make Linux
# cache EPERM on an existing UDP socket after the rule/route is restored, which
# tests a poisoned local socket rather than a mobile/Wi-Fi path outage.
iptables -C INPUT -p udp -s "$peer_ip" -j DROP 2>/dev/null || iptables -I INPUT -p udp -s "$peer_ip" -j DROP
SH
  "${COMPOSE[@]}" exec -T node-b sh -s -- "$NVPN_E2E_NODE_A_UNDERLAY_IP" <<'SH'
set -eu
peer_ip="$1"
iptables -C INPUT -p udp -s "$peer_ip" -j DROP 2>/dev/null || iptables -I INPUT -p udp -s "$peer_ip" -j DROP
SH
}

unblock_direct_alice_bob_udp() {
  "${COMPOSE[@]}" exec -T node-a sh -s -- "$NVPN_E2E_NODE_B_UNDERLAY_IP" <<'SH'
set -eu
peer_ip="$1"
while iptables -D INPUT -p udp -s "$peer_ip" -j DROP 2>/dev/null; do :; done
SH
  "${COMPOSE[@]}" exec -T node-b sh -s -- "$NVPN_E2E_NODE_A_UNDERLAY_IP" <<'SH'
set -eu
peer_ip="$1"
while iptables -D INPUT -p udp -s "$peer_ip" -j DROP 2>/dev/null; do :; done
SH
}

wait_for_mesh() {
  local node="$1"
  local expected="$2"
  local status compact
  for _ in $(seq 1 100); do
    status="$("${COMPOSE[@]}" exec -T "$node" nvpn status --json --discover-secs 0 | tr -d '\r')"
    compact="$(printf '%s' "$status" | compact_json)"
    if grep -q '"status_source":"daemon"' <<<"$compact" \
      && grep -q '"running":true' <<<"$compact" \
      && grep -q '"mesh_ready":true' <<<"$compact" \
      && grep -q "\"connected_peer_count\":$expected" <<<"$compact"; then
      printf '%s\n' "$status"
      return 0
    fi
    sleep 1
  done

  printf '%s\n' "$status"
  return 1
}

status_json() {
  local node="$1"
  "${COMPOSE[@]}" exec -T "$node" nvpn status --json --discover-secs 0 | tr -d '\r'
}

peer_matches_direct_addr() {
  local status="$1"
  local peer_key="$2"
  local direct_addr="$3"
  local after_data_seen_at="${4:-0}"
  jq -e --arg peer_key "$peer_key" --arg direct_addr "$direct_addr" \
    --argjson after_data_seen_at "$after_data_seen_at" '
    .daemon.state.peers
    | any(
      (.participant_pubkey == $peer_key or .fips_endpoint_npub == $peer_key)
      and .reachable == true
      and (
        $after_data_seen_at == 0
        or ((.last_fips_data_seen_at? // 0) > $after_data_seen_at)
      )
      and (.direct_probe_pending? != true)
      and (.direct_probe_after_ms? == null)
      and ((.runtime_endpoint? // "") != "fips")
      and (
        ((.runtime_endpoint? // "") | contains($direct_addr))
        or ((.fips_transport_addr? // "") | contains($direct_addr))
      )
    )
  ' >/dev/null <<<"$status"
}

peer_matches_fallback_with_probe() {
  local status="$1"
  local peer_key="$2"
  local _direct_addr="$3"
  local after_data_seen_at="${4:-0}"
  jq -e --arg peer_key "$peer_key" --argjson after_data_seen_at "$after_data_seen_at" '
    .daemon.state.peers
    | any(
      (.participant_pubkey == $peer_key or .fips_endpoint_npub == $peer_key)
      and .reachable == true
      and (.direct_probe_pending == true or (.direct_probe_after_ms? != null))
      and ((.last_fips_data_seen_at? // 0) > $after_data_seen_at)
    )
  ' >/dev/null <<<"$status"
}

wait_for_direct_peer() {
  local node="$1"
  local peer_key="$2"
  local direct_addr="$3"
  local label="$4"
  local deadline="$5"
  local after_data_seen_at="${6:-0}"
  local status=""
  local end=$(( $(date +%s) + deadline ))
  while [[ "$(date +%s)" -le "$end" ]]; do
    status="$(status_json "$node")"
    if peer_matches_direct_addr "$status" "$peer_key" "$direct_addr" "$after_data_seen_at"; then
      printf '%s\n' "$status"
      return 0
    fi
    sleep 1
  done

  echo "fips roaming e2e failed: $label did not use direct UDP $direct_addr within ${deadline}s" >&2
  printf '%s\n' "$status" >&2
  exit 1
}

wait_for_fallback_probe_peer() {
  local node="$1"
  local peer_key="$2"
  local direct_addr="$3"
  local label="$4"
  local deadline="$5"
  local after_data_seen_at="${6:-0}"
  local status=""
  local end=$(( $(date +%s) + deadline ))
  while [[ "$(date +%s)" -le "$end" ]]; do
    status="$(status_json "$node")"
    if peer_matches_fallback_with_probe "$status" "$peer_key" "$direct_addr" "$after_data_seen_at"; then
      printf '%s\n' "$status"
      return 0
    fi
    sleep 1
  done

  echo "fips roaming e2e failed: $label did not show fallback traffic with direct probing within ${deadline}s" >&2
  printf '%s\n' "$status" >&2
  exit 1
}

start_payload_probe() {
  local node="$1"
  local target_ip="$2"
  local output="$3"
  "${COMPOSE[@]}" exec -T "$node" sh -s -- \
    "$target_ip" "$PING_PAYLOAD_SIZE" "$PAYLOAD_PROBE_INTERVAL_SECS" "$output" <<'SH'
set -eu
target_ip="$1"
payload_size="$2"
interval="$3"
output="$4"
rm -f "$output" "${output}.pid"
(
  while :; do
    ts="$(date +%s)"
    if ping -M do -s "$payload_size" -c 1 -W 1 "$target_ip" >/dev/null 2>&1; then
      printf '%s ok\n' "$ts"
    else
      printf '%s fail\n' "$ts"
    fi
    sleep "$interval"
  done
) >"$output" 2>&1 &
printf '%s\n' "$!" >"${output}.pid"
SH
}

stop_payload_probe() {
  local node="$1"
  local output="$2"
  "${COMPOSE[@]}" exec -T "$node" sh -s -- "$output" <<'SH'
set -eu
output="$1"
if [ -s "${output}.pid" ]; then
  kill "$(cat "${output}.pid")" 2>/dev/null || true
  rm -f "${output}.pid"
fi
cat "$output" 2>/dev/null || true
SH
}

assert_payload_probe_success_since() {
  local node="$1"
  local output="$2"
  local since="$3"
  local label="$4"
  local deadline="${5:-$PAYLOAD_RECOVERY_DEADLINE_SECS}"
  local end=$(( $(date +%s) + deadline ))
  while [[ "$(date +%s)" -le "$end" ]]; do
    if "${COMPOSE[@]}" exec -T "$node" sh -s -- "$output" "$since" <<'SH'
set -eu
output="$1"
since="$2"
awk -v since="$since" '$1 >= since && $2 == "ok" { found = 1 } END { exit found ? 0 : 1 }' "$output"
SH
    then
      return 0
    fi
    sleep "$PAYLOAD_PROBE_INTERVAL_SECS"
  done

  echo "fips roaming e2e failed: $label did not recover tunnel payload after churn within ${deadline}s" >&2
  "${COMPOSE[@]}" exec -T "$node" sh -lc "cat '$output' 2>/dev/null || true" >&2 || true
  exit 1
}

daemon_process_id() {
  local node="$1"
  "${COMPOSE[@]}" exec -T "$node" sh -lc 'pgrep -o -x nvpn' | tr -d '\r'
}

wait_for_network_change_rebind_after_marker() {
  local node="$1"
  local marker="$2"
  local label="$3"
  local end=$(( $(date +%s) + NETWORK_CHANGE_RECOVERY_DEADLINE_SECS ))
  while [[ "$(date +%s)" -le "$end" ]]; do
    if "${COMPOSE[@]}" exec -T "$node" sh -s -- "$marker" <<'SH'
set -eu
marker="$1"
awk -v marker="$marker" '
  $0 ~ "NVPN_E2E_MARKER " marker { seen = 1; next }
  seen && /network change detected; refreshing FIPS endpoint state/ { changed = 1 }
  changed && /underlay carrier\(s\) rebound.*after network change \([1-9][0-9]*\)/ { rebound = 1 }
  seen && /restarted FIPS private mesh/ { restarted = 1 }
  END { exit (changed && rebound && !restarted) ? 0 : 1 }
' /root/.config/nvpn/daemon.log
SH
    then
      return 0
    fi
    sleep 1
  done

  echo "fips roaming e2e failed: $label did not rebind its underlay carrier while preserving the FIPS endpoint" >&2
  "${COMPOSE[@]}" exec -T "$node" sh -lc 'tail -n 180 /root/.config/nvpn/daemon.log' >&2 || true
  exit 1
}

mark_daemon_log() {
  local node="$1"
  local marker="$2"
  "${COMPOSE[@]}" exec -T "$node" sh -s -- "$marker" <<'SH'
set -eu
marker="$1"
printf 'NVPN_E2E_MARKER %s\n' "$marker" >> /root/.config/nvpn/daemon.log
SH
}

assert_local_route_handshake_failures_bounded() {
  local node="$1"
  local marker="$2"
  local label="$3"
  local count
  count="$("${COMPOSE[@]}" exec -T "$node" sh -s -- "$marker" <<'SH'
set -eu
marker="$1"
awk -v marker="$marker" '
  $0 ~ "NVPN_E2E_MARKER " marker { seen = 1; next }
  seen && /Failed to send handshake message/ && /(Network is unreachable|No route to host|Host is unreachable|Can.t assign requested address|AddrNotAvailable|os error 49|os error 51|os error 65)/ {
    count++
  }
  END { print count + 0 }
' /root/.config/nvpn/daemon.log
SH
  )"
  count="${count//$'\r'/}"
  if (( count > LOCAL_ROUTE_HANDSHAKE_FAILURE_MAX )); then
    echo "fips roaming e2e failed: $label saw $count local-route handshake failures after churn marker, expected <= $LOCAL_ROUTE_HANDSHAKE_FAILURE_MAX" >&2
    "${COMPOSE[@]}" exec -T "$node" sh -s -- "$marker" <<'SH' >&2 || true
set -eu
marker="$1"
awk -v marker="$marker" '
  $0 ~ "NVPN_E2E_MARKER " marker { seen = 1; print; next }
  seen && (/Failed to send handshake message/ || /Local route unavailable/ || /request.*stale|stale.*advert/) { print }
' /root/.config/nvpn/daemon.log | tail -n 120
SH
    exit 1
  fi
}

assert_payload_probe_failure_run_bounded() {
  local node="$1"
  local output="$2"
  local since="$3"
  local until="$4"
  local label="$5"
  local worst
  worst="$("${COMPOSE[@]}" exec -T "$node" sh -s -- "$output" "$since" "$until" <<'SH'
set -eu
output="$1"
since="$2"
until="$3"
awk -v since="$since" -v until="$until" '
  $1 >= since && $1 <= until {
    if ($2 == "fail") {
      run++
      if (run > worst) worst = run
    } else if ($2 == "ok") {
      run = 0
    }
  }
  END { print worst + 0 }
' "$output"
SH
  )"
  worst="${worst//$'\r'/}"
  if (( worst > NETWORK_CHANGE_MAX_CONSECUTIVE_PAYLOAD_FAILURES )); then
    echo "fips roaming e2e failed: $label had $worst consecutive payload failures, expected <= $NETWORK_CHANGE_MAX_CONSECUTIVE_PAYLOAD_FAILURES" >&2
    "${COMPOSE[@]}" exec -T "$node" sh -lc "cat '$output' 2>/dev/null || true" >&2 || true
    exit 1
  fi
}

resolve_magic_dns() {
  local node="$1"
  local name="$2"
  "${COMPOSE[@]}" exec -T "$node" sh -lc \
    "dig +short @127.0.0.1 -p 1053 '$name' A | tail -n1" | tr -d '\r'
}

assert_tunnel_mtu() {
  local node="$1"
  local actual
  actual="$("${COMPOSE[@]}" exec -T "$node" sh -lc \
    "ip -o link show utun100 | awk -F ' mtu ' '{ print \$2 }' | awk '{ print \$1 }'" | tr -d '\r')"
  if [[ "$actual" != "$SAFE_TUNNEL_MTU" ]]; then
    echo "fips roaming e2e failed: $node utun100 MTU was '$actual', expected '$SAFE_TUNNEL_MTU'" >&2
    exit 1
  fi
}

ping_tunnel_payload() {
  local node="$1"
  local target_ip="$2"
  local log_path="$3"
  for _ in $(seq 1 10); do
    if "${COMPOSE[@]}" exec -T "$node" ping -M do -s "$PING_PAYLOAD_SIZE" -c 2 -W 2 "$target_ip" >"$log_path"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

assert_ping_tunnel() {
  local node="$1"
  local target_ip="$2"
  local label="$3"
  local log_path="$4"
  if ! ping_tunnel_payload "$node" "$target_ip" "$log_path"; then
    echo "fips roaming e2e failed: $label could not move $PING_PAYLOAD_SIZE-byte no-fragment ping payload" >&2
    cat "$log_path" >&2 2>/dev/null || true
    exit 1
  fi
}

ping_count_for_loaded_latency() {
  awk -v duration="$LOADED_LATENCY_DURATION_SECS" -v interval="$LOADED_LATENCY_PING_INTERVAL_SECS" '
    BEGIN {
      if (interval <= 0) interval = 1;
      count = int((duration / interval) + 0.999);
      if (count < 1) count = 1;
      print count;
    }'
}

parse_loaded_latency_ping() {
  local file="$1"
  sed -nE 's/.*time[=<][[:space:]]*([0-9.]+).*/\1/p' "$file" | sort -n | awk '
    NF {
      v[++n] = $1 + 0;
      if (v[n] > 1000) gt1000++;
    }
    END {
      if (n == 0) {
        printf "0\t100\tnull\tnull\t0\n";
        exit;
      }
      p99i = int((n * 99 + 99) / 100);
      if (p99i < 1) p99i = 1;
      if (p99i > n) p99i = n;
      printf "%d\t0\t%.3f\t%.3f\t%d\n", n, v[p99i], v[n], gt1000 + 0;
    }'
}

iperf_mbps_from_json() {
  local file="$1"
  jq -r '
    [.end.sum_received.bits_per_second?, .end.sum.bits_per_second?, .end.sum_sent.bits_per_second?]
    | map(select(type == "number"))
    | if length == 0 then "null" else (.[0] / 1000000) end
  ' "$file" 2>/dev/null || printf 'null\n'
}

assert_float_at_least() {
  local actual="$1"
  local min="$2"
  local label="$3"
  awk -v actual="$actual" -v min="$min" -v label="$label" '
    BEGIN {
      if (actual == "" || actual == "null" || (actual + 0) < (min + 0)) {
        printf("fips roaming e2e failed: %s %s below %s\n", label, actual, min) > "/dev/stderr";
        exit 1;
      }
    }'
}

assert_float_at_most() {
  local actual="$1"
  local max="$2"
  local label="$3"
  awk -v actual="$actual" -v max="$max" -v label="$label" '
    BEGIN {
      if (actual == "" || actual == "null" || (actual + 0) > (max + 0)) {
        printf("fips roaming e2e failed: %s %s exceeds %s\n", label, actual, max) > "/dev/stderr";
        exit 1;
      }
    }'
}

run_loaded_latency_probe() {
  local label="$1"
  local source_node="$2"
  local target_node="$3"
  local target_ip="$4"
  local ping_count ping_log iperf_json mbps count loss p99 max gt1000 reply_pct

  case "$LOADED_LATENCY_ENABLED" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "--- $label: skipping loaded latency probe ---"
      return 0
      ;;
  esac

  ping_count="$(ping_count_for_loaded_latency)"
  ping_log="/tmp/${label}-loaded-latency-ping.log"
  iperf_json="/tmp/${label}-loaded-latency-iperf.json"
  echo "--- $label: loaded latency probe (${LOADED_LATENCY_DURATION_SECS}s TCP load + ping) ---"
  "${COMPOSE[@]}" exec -T "$target_node" sh -lc \
    "pkill -9 iperf3 >/dev/null 2>&1 || true; iperf3 -s -D --logfile /tmp/${label}-iperf3-server.log"
  "${COMPOSE[@]}" exec -T "$source_node" sh -lc \
    "ping -c '$ping_count' -i '$LOADED_LATENCY_PING_INTERVAL_SECS' -W 1 '$target_ip' > '$ping_log' 2>&1 || true" &
  local ping_pid=$!
  "${COMPOSE[@]}" exec -T "$source_node" sh -lc \
    "iperf3 -J -c '$target_ip' -t '$LOADED_LATENCY_DURATION_SECS' -O 1 --connect-timeout 3000 > '$iperf_json' 2>'$iperf_json.err' || true"
  wait "$ping_pid" || true
  "${COMPOSE[@]}" exec -T "$target_node" sh -lc 'pkill -9 iperf3 >/dev/null 2>&1 || true'

  "${COMPOSE[@]}" exec -T "$source_node" sh -lc "cat '$ping_log'" >"/tmp/${label}-loaded-latency-ping.host.log" || true
  "${COMPOSE[@]}" exec -T "$source_node" sh -lc "cat '$iperf_json'" >"/tmp/${label}-loaded-latency-iperf.host.json" || true
  read -r count loss p99 max gt1000 < <(parse_loaded_latency_ping "/tmp/${label}-loaded-latency-ping.host.log")
  mbps="$(iperf_mbps_from_json "/tmp/${label}-loaded-latency-iperf.host.json")"
  reply_pct="$(awk -v count="$count" -v expected="$ping_count" 'BEGIN {
    if (expected <= 0) {
      print 0;
    } else {
      printf "%.3f\n", (count * 100.0) / expected;
    }
  }')"

  echo "$label loaded latency: ping_replies=$count/$ping_count reply_pct=$reply_pct p99_ms=$p99 max_ms=$max gt1000=$gt1000 iperf_mbps=$mbps"
  assert_float_at_least "$mbps" "$LOADED_LATENCY_MIN_MBPS" "$label iperf Mbps"
  assert_float_at_least "$reply_pct" "$LOADED_LATENCY_MIN_PING_REPLY_PERCENT" "$label ping reply percent under load"
  assert_float_at_most "$p99" "$LOADED_LATENCY_MAX_P99_MS" "$label ping p99 ms under load"
  if (( gt1000 > LOADED_LATENCY_MAX_GT1000 )); then
    echo "fips roaming e2e failed: $label ping spikes >1000 ms $gt1000 exceeds $LOADED_LATENCY_MAX_GT1000" >&2
    cat "/tmp/${label}-loaded-latency-ping.host.log" >&2
    exit 1
  fi
}

run_udp_roundtrip() {
  local source_node="$1"
  local target_node="$2"
  local target_ip="$3"
  local payload="$4"
  local output="$5"
  "${COMPOSE[@]}" exec -T "$target_node" sh -lc \
    "rm -f '$output'; timeout 20 nc -u -l -p '$UDP_PORT' > '$output' & echo \$! > '${output}.pid'"
  "${COMPOSE[@]}" exec -T "$source_node" sh -lc \
    "printf '%s' '$payload' | nc -u -w 2 '$target_ip' '$UDP_PORT'"
  for _ in $(seq 1 20); do
    if "${COMPOSE[@]}" exec -T "$target_node" sh -lc "grep -q '$payload' '$output' 2>/dev/null"; then
      return 0
    fi
    sleep 1
  done
  echo "fips roaming e2e failed: UDP payload '$payload' did not arrive at $target_node" >&2
  exit 1
}

assert_no_transit_roster_peer() {
  local status="$1"
  local peer_key="$2"
  local label="$3"
  if jq -e --arg peer_key "$peer_key" '
    .daemon.state.peers
    | any(.participant_pubkey == $peer_key or .fips_endpoint_npub == $peer_key)
  ' >/dev/null <<<"$status"; then
    echo "fips roaming e2e failed: $label exposed transit hop as a data-plane peer" >&2
    printf '%s\n' "$status" >&2
    exit 1
  fi
}

run_roam_flap() {
  local flap_name="$1"
  local alice_direct_addr="$NVPN_E2E_NODE_B_UNDERLAY_IP:51820"
  local bob_direct_addr="$NVPN_E2E_NODE_A_UNDERLAY_IP:51820"
  local alice_probe="/tmp/${flap_name}-alice-payload-probe.log"
  local bob_probe="/tmp/${flap_name}-bob-payload-probe.log"
  local alice_marker="${flap_name}-alice-$(date +%s)"
  local bob_marker="${flap_name}-bob-$(date +%s)"
  local churn_started

  echo "--- $flap_name: drop direct Alice<->Bob path, expect FIPS fallback plus direct probe ---"
  mark_daemon_log node-a "$alice_marker"
  mark_daemon_log node-b "$bob_marker"
  start_payload_probe node-a "$BOB_TUNNEL_IP" "$alice_probe"
  start_payload_probe node-b "$ALICE_TUNNEL_IP" "$bob_probe"
  churn_started="$(date +%s)"
  block_direct_alice_bob_udp

  local alice_fallback bob_fallback
  alice_fallback="$(wait_for_fallback_probe_peer node-a "$BOB_NPUB" "$alice_direct_addr" "alice during $flap_name" "$FALLBACK_DEADLINE_SECS" "$churn_started")"
  bob_fallback="$(wait_for_fallback_probe_peer node-b "$ALICE_NPUB" "$bob_direct_addr" "bob during $flap_name" "$FALLBACK_DEADLINE_SECS" "$churn_started")"
  local fallback_payload_check_started
  fallback_payload_check_started="$(date +%s)"
  assert_payload_probe_success_since node-a "$alice_probe" "$fallback_payload_check_started" "alice payload on fallback during $flap_name"
  assert_payload_probe_success_since node-b "$bob_probe" "$fallback_payload_check_started" "bob payload on fallback during $flap_name"
  assert_local_route_handshake_failures_bounded node-a "$alice_marker" "alice during $flap_name"
  assert_local_route_handshake_failures_bounded node-b "$bob_marker" "bob during $flap_name"

  assert_ping_tunnel node-a "$BOB_TUNNEL_IP" "alice-to-bob during $flap_name fallback" "/tmp/${flap_name}-alice-to-bob-fallback-ping.log"
  assert_ping_tunnel node-b "$ALICE_TUNNEL_IP" "bob-to-alice during $flap_name fallback" "/tmp/${flap_name}-bob-to-alice-fallback-ping.log"
  sleep "$FALLBACK_HOLD_SECS"

  alice_fallback="$(wait_for_fallback_probe_peer node-a "$BOB_NPUB" "$alice_direct_addr" "alice after $flap_name hold" "$FALLBACK_DEADLINE_SECS" "$churn_started")"
  bob_fallback="$(wait_for_fallback_probe_peer node-b "$ALICE_NPUB" "$bob_direct_addr" "bob after $flap_name hold" "$FALLBACK_DEADLINE_SECS" "$churn_started")"

  echo "--- $flap_name: restore LAN/direct path, expect quick upgrade away from fallback ---"
  local restore_started
  restore_started="$(date +%s)"
  unblock_direct_alice_bob_udp

  local alice_direct bob_direct
  alice_direct="$(wait_for_direct_peer node-a "$BOB_NPUB" "$alice_direct_addr" "alice after $flap_name restore" "$DIRECT_RECOVERY_DEADLINE_SECS" "$restore_started")"
  bob_direct="$(wait_for_direct_peer node-b "$ALICE_NPUB" "$bob_direct_addr" "bob after $flap_name restore" "$DIRECT_RECOVERY_DEADLINE_SECS" "$restore_started")"
  echo "$flap_name direct payload recovery completed in $(( $(date +%s) - restore_started ))s"
  local direct_payload_check_started
  direct_payload_check_started="$(date +%s)"
  assert_payload_probe_success_since node-a "$alice_probe" "$direct_payload_check_started" "alice payload on restored direct path after $flap_name"
  assert_payload_probe_success_since node-b "$bob_probe" "$direct_payload_check_started" "bob payload on restored direct path after $flap_name"
  local alice_probe_log bob_probe_log
  alice_probe_log="$(stop_payload_probe node-a "$alice_probe")"
  bob_probe_log="$(stop_payload_probe node-b "$bob_probe")"

  assert_ping_tunnel node-a "$BOB_TUNNEL_IP" "alice-to-bob after $flap_name direct restore" "/tmp/${flap_name}-alice-to-bob-direct-ping.log"
  assert_ping_tunnel node-b "$ALICE_TUNNEL_IP" "bob-to-alice after $flap_name direct restore" "/tmp/${flap_name}-bob-to-alice-direct-ping.log"

  echo "--- $flap_name fallback status: alice ---"
  echo "$alice_fallback"
  echo "--- $flap_name fallback status: bob ---"
  echo "$bob_fallback"
  echo "--- $flap_name restored direct status: alice ---"
  echo "$alice_direct"
  echo "--- $flap_name restored direct status: bob ---"
  echo "$bob_direct"
  echo "--- $flap_name continuous payload probe: alice ---"
  echo "$alice_probe_log"
  echo "--- $flap_name continuous payload probe: bob ---"
  echo "$bob_probe_log"
}

replace_node_address() {
  local service="$1"
  local interface="$2"
  local old_ip="$3"
  local new_ip="$4"
  local gateway_ip="$5"
  "${COMPOSE[@]}" exec -T "$service" sh -s -- \
    "$interface" "$old_ip" "$new_ip" "$gateway_ip" <<'SH'
set -eu
interface="$1"
old_ip="$2"
new_ip="$3"
gateway_ip="$4"

# Removing the primary address can also remove its default route. docker exec
# stays available through the container runtime while the new address and route
# are installed in the same network namespace.
ip addr del "$old_ip/24" dev "$interface"
ip addr add "$new_ip/24" dev "$interface"
ip route replace default via "$gateway_ip" dev "$interface" src "$new_ip"
SH
}

run_underlay_network_change() {
  local roam_marker="underlay-to-roam-$(date +%s)"
  local home_marker="underlay-to-home-$(date +%s)"
  local alice_probe="/tmp/underlay-move-alice-payload-probe.log"
  local bob_probe="/tmp/underlay-move-bob-payload-probe.log"
  local alice_pid_before alice_pid_after bob_pid_before bob_pid_after change_started restore_started

  alice_pid_before="$(daemon_process_id node-a)"
  bob_pid_before="$(daemon_process_id node-b)"
  mark_daemon_log node-a "$roam_marker"
  start_payload_probe node-a "$BOB_TUNNEL_IP" "$alice_probe"
  start_payload_probe node-b "$ALICE_TUNNEL_IP" "$bob_probe"

  echo "--- underlay-network-change: change Alice's source address while Bob remains stationary ---"
  change_started="$(date +%s)"
  replace_node_address \
    node-a eth0 "$NVPN_E2E_NODE_A_UNDERLAY_IP" "$MIGRATED_NODE_A_IP" "$UNDERLAY_PREFIX.1"

  wait_for_network_change_rebind_after_marker node-a "$roam_marker" "alice changing source address"
  local alice_roam_direct bob_roam_direct
  alice_roam_direct="$(wait_for_direct_peer node-a "$BOB_NPUB" "$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" "alice after source-address change" "$NETWORK_CHANGE_RECOVERY_DEADLINE_SECS" "$change_started")"
  bob_roam_direct="$(wait_for_direct_peer node-b "$ALICE_NPUB" "$MIGRATED_NODE_A_IP:51820" "bob after alice source-address change" "$NETWORK_CHANGE_RECOVERY_DEADLINE_SECS" "$change_started")"
  local roam_payload_check_started roam_payload_checked_at
  roam_payload_check_started="$(date +%s)"
  assert_payload_probe_success_since node-a "$alice_probe" "$roam_payload_check_started" "alice payload after source-address change"
  assert_payload_probe_success_since node-b "$bob_probe" "$roam_payload_check_started" "bob payload after alice source-address change"
  roam_payload_checked_at="$(date +%s)"
  assert_payload_probe_failure_run_bounded node-a "$alice_probe" "$change_started" "$roam_payload_checked_at" "alice source-address roam"
  assert_payload_probe_failure_run_bounded node-b "$bob_probe" "$change_started" "$roam_payload_checked_at" "bob observing alice source-address roam"
  assert_ping_tunnel node-a "$BOB_TUNNEL_IP" "alice-to-bob after source-address change" /tmp/underlay-move-alice-to-bob-ping.log
  assert_ping_tunnel node-b "$ALICE_TUNNEL_IP" "bob-to-alice after source-address change" /tmp/underlay-move-bob-to-alice-ping.log
  alice_pid_after="$(daemon_process_id node-a)"
  bob_pid_after="$(daemon_process_id node-b)"
  if [[ "$alice_pid_after" != "$alice_pid_before" ]]; then
    echo "fips roaming e2e failed: alice nvpn daemon restarted during underlay move ($alice_pid_before -> $alice_pid_after)" >&2
    exit 1
  fi
  if [[ "$bob_pid_after" != "$bob_pid_before" ]]; then
    echo "fips roaming e2e failed: bob nvpn daemon restarted during underlay move ($bob_pid_before -> $bob_pid_after)" >&2
    exit 1
  fi

  echo "--- underlay-network-change: restore Alice's original source address ---"
  mark_daemon_log node-a "$home_marker"
  restore_started="$(date +%s)"
  replace_node_address \
    node-a eth0 "$MIGRATED_NODE_A_IP" "$NVPN_E2E_NODE_A_UNDERLAY_IP" "$UNDERLAY_PREFIX.1"

  wait_for_network_change_rebind_after_marker node-a "$home_marker" "alice returning to original underlay"
  local alice_home_direct bob_home_direct
  alice_home_direct="$(wait_for_direct_peer node-a "$BOB_NPUB" "$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" "alice after original-underlay restore" "$NETWORK_CHANGE_RECOVERY_DEADLINE_SECS" "$restore_started")"
  bob_home_direct="$(wait_for_direct_peer node-b "$ALICE_NPUB" "$NVPN_E2E_NODE_A_UNDERLAY_IP:51820" "bob after alice original-underlay restore" "$NETWORK_CHANGE_RECOVERY_DEADLINE_SECS" "$restore_started")"
  local home_payload_check_started home_payload_checked_at
  home_payload_check_started="$(date +%s)"
  assert_payload_probe_success_since node-a "$alice_probe" "$home_payload_check_started" "alice payload after original-underlay restore"
  assert_payload_probe_success_since node-b "$bob_probe" "$home_payload_check_started" "bob payload after alice original-underlay restore"
  home_payload_checked_at="$(date +%s)"
  assert_payload_probe_failure_run_bounded node-a "$alice_probe" "$restore_started" "$home_payload_checked_at" "alice original-underlay restore"
  assert_payload_probe_failure_run_bounded node-b "$bob_probe" "$restore_started" "$home_payload_checked_at" "bob observing alice original-underlay restore"
  assert_ping_tunnel node-a "$BOB_TUNNEL_IP" "alice-to-bob after original-underlay restore" /tmp/underlay-restore-alice-to-bob-ping.log
  assert_ping_tunnel node-b "$ALICE_TUNNEL_IP" "bob-to-alice after original-underlay restore" /tmp/underlay-restore-bob-to-alice-ping.log
  alice_pid_after="$(daemon_process_id node-a)"
  bob_pid_after="$(daemon_process_id node-b)"
  if [[ "$alice_pid_after" != "$alice_pid_before" ]]; then
    echo "fips roaming e2e failed: alice nvpn daemon restarted while restoring the underlay ($alice_pid_before -> $alice_pid_after)" >&2
    exit 1
  fi
  if [[ "$bob_pid_after" != "$bob_pid_before" ]]; then
    echo "fips roaming e2e failed: bob nvpn daemon restarted while restoring the underlay ($bob_pid_before -> $bob_pid_after)" >&2
    exit 1
  fi

  local alice_probe_log bob_probe_log
  alice_probe_log="$(stop_payload_probe node-a "$alice_probe")"
  bob_probe_log="$(stop_payload_probe node-b "$bob_probe")"
  echo "--- Alternate-underlay direct status: alice ---"
  echo "$alice_roam_direct"
  echo "--- Alternate-underlay direct status: bob ---"
  echo "$bob_roam_direct"
  echo "--- Restored-underlay direct status: alice ---"
  echo "$alice_home_direct"
  echo "--- Restored-underlay direct status: bob ---"
  echo "$bob_home_direct"
  echo "--- Underlay move continuous payload probe: alice ---"
  echo "$alice_probe_log"
  echo "--- Underlay move continuous payload probe: bob ---"
  echo "$bob_probe_log"
}

cleanup

# All three nodes run the same artifact. Build one service/image rather than
# asking BuildKit to perform three identical release compilations in parallel.
case "${NVPN_E2E_SKIP_NODE_BUILD:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    ;;
  *)
    "${COMPOSE[@]}" build node-a >/dev/null
    ;;
esac
"${COMPOSE[@]}" up -d --no-build node-a node-b node-c >/dev/null
for service in node-a node-b node-c; do
  wait_for_service "$service"
done

for node in node-a node-b node-c; do
  "${COMPOSE[@]}" exec -T "$node" nvpn init --force >/dev/null
done

ALICE_NPUB="$(nostr_pubkey_from_config node-a)"
BOB_NPUB="$(nostr_pubkey_from_config node-b)"
CHARLIE_NPUB="$(nostr_pubkey_from_config node-c)"

if [[ -z "$ALICE_NPUB" || -z "$BOB_NPUB" || -z "$CHARLIE_NPUB" ]]; then
  echo "fips roaming e2e failed: unable to resolve node npubs from config" >&2
  exit 1
fi

"${COMPOSE[@]}" exec -T node-a nvpn set --participant "$ALICE_NPUB" >/dev/null
"${COMPOSE[@]}" exec -T node-b nvpn set --participant "$BOB_NPUB" >/dev/null
"${COMPOSE[@]}" exec -T node-c nvpn set --participant "$CHARLIE_NPUB" >/dev/null

"${COMPOSE[@]}" exec -T node-a nvpn set \
  --network-id "$NETWORK_ID" \
  --node-name alice \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --fips-peer-endpoint "$BOB_NPUB=$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" \
  --fips-peer-endpoint "$CHARLIE_NPUB=$NVPN_E2E_NODE_C_UNDERLAY_IP:51820" \
  --endpoint "$NVPN_E2E_NODE_A_UNDERLAY_IP:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false >/dev/null

"${COMPOSE[@]}" exec -T node-b nvpn set \
  --network-id "$NETWORK_ID" \
  --node-name bob \
  --participant "$ALICE_NPUB" \
  --participant "$BOB_NPUB" \
  --fips-peer-endpoint "$ALICE_NPUB=$NVPN_E2E_NODE_A_UNDERLAY_IP:51820" \
  --fips-peer-endpoint "$CHARLIE_NPUB=$NVPN_E2E_NODE_C_UNDERLAY_IP:51820" \
  --endpoint "$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false >/dev/null

"${COMPOSE[@]}" exec -T node-c nvpn set \
  --network-id "$NETWORK_ID" \
  --node-name charlie \
  --fips-peer-endpoint "$ALICE_NPUB=$NVPN_E2E_NODE_A_UNDERLAY_IP:51820" \
  --fips-peer-endpoint "$BOB_NPUB=$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" \
  --endpoint "$NVPN_E2E_NODE_C_UNDERLAY_IP:51820" \
  --listen-port 51820 \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false \
  --fips-bootstrap-enabled false >/dev/null

for node in node-a node-b node-c; do
  replace_peer_aliases "$node"
  disable_nat_discovery "$node"
  start_nvpn_daemon "$node"
done

ALICE_STATUS="$(wait_for_mesh node-a 1)" || {
  echo "fips roaming e2e failed: alice mesh did not reach 1/1" >&2
  echo "$ALICE_STATUS"
  exit 1
}
BOB_STATUS="$(wait_for_mesh node-b 1)" || {
  echo "fips roaming e2e failed: bob mesh did not reach 1/1" >&2
  echo "$BOB_STATUS"
  exit 1
}

assert_no_transit_roster_peer "$ALICE_STATUS" "$CHARLIE_NPUB" "alice"
assert_no_transit_roster_peer "$BOB_STATUS" "$CHARLIE_NPUB" "bob"

ALICE_DIRECT="$(wait_for_direct_peer node-a "$BOB_NPUB" "$NVPN_E2E_NODE_B_UNDERLAY_IP:51820" "alice initial LAN" "$DIRECT_RECOVERY_DEADLINE_SECS")"
BOB_DIRECT="$(wait_for_direct_peer node-b "$ALICE_NPUB" "$NVPN_E2E_NODE_A_UNDERLAY_IP:51820" "bob initial LAN" "$DIRECT_RECOVERY_DEADLINE_SECS")"

BOB_TUNNEL_IP="$(resolve_magic_dns node-a bob.nvpn)"
ALICE_TUNNEL_IP="$(resolve_magic_dns node-b alice.nvpn)"

if [[ -z "$BOB_TUNNEL_IP" || -z "$ALICE_TUNNEL_IP" ]]; then
  echo "fips roaming e2e failed: magic dns did not resolve alice.nvpn/bob.nvpn" >&2
  exit 1
fi

assert_tunnel_mtu node-a
assert_tunnel_mtu node-b
assert_ping_tunnel node-a "$BOB_TUNNEL_IP" "initial alice-to-bob direct LAN" /tmp/initial-alice-to-bob-ping.log
assert_ping_tunnel node-b "$ALICE_TUNNEL_IP" "initial bob-to-alice direct LAN" /tmp/initial-bob-to-alice-ping.log
run_udp_roundtrip node-a node-b "$BOB_TUNNEL_IP" "alice-to-bob-roaming-initial" /tmp/bob-roaming-initial-udp.out
if [[ "$SCENARIOS" == "all" || "$SCENARIOS" == "latency" ]]; then
  run_loaded_latency_probe "initial-direct" node-a node-b "$BOB_TUNNEL_IP"
fi
if [[ "$SCENARIOS" == "all" || "$SCENARIOS" == "fallback" ]]; then
  run_roam_flap "mobile-flap-1"
  run_roam_flap "mobile-flap-2"
fi
if [[ "$SCENARIOS" == "all" || "$SCENARIOS" == "network-change" ]]; then
  run_underlay_network_change
fi
if [[ "$SCENARIOS" == "all" ]]; then
  run_loaded_latency_probe "restored-direct" node-a node-b "$BOB_TUNNEL_IP"
fi

echo "--- Initial direct status: alice ---"
echo "$ALICE_DIRECT"
echo "--- Initial direct status: bob ---"
echo "$BOB_DIRECT"
echo "--- Magic DNS ---"
echo "node-a bob.nvpn -> $BOB_TUNNEL_IP"
echo "node-b alice.nvpn -> $ALICE_TUNNEL_IP"
echo "--- Initial pings ---"
cat /tmp/initial-alice-to-bob-ping.log
cat /tmp/initial-bob-to-alice-ping.log
echo "--- Initial UDP payload ---"
"${COMPOSE[@]}" exec -T node-b sh -lc 'cat /tmp/bob-roaming-initial-udp.out'

if [[ "$SCENARIOS" == "all" ]]; then
  case "$LOADED_LATENCY_ENABLED" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "fips roaming docker e2e passed: direct LAN path established, repeated mobile/WiFi-style direct drops used FIPS fallback, one live daemon changed source address while its peer remained stationary, continuous payload recovered during churn, and each restore upgraded back to direct; host-calibrated loaded-latency probes were skipped"
      ;;
    *)
      echo "fips roaming docker e2e passed: direct LAN path established, loaded-latency probes stayed bounded, repeated mobile/WiFi-style direct drops used FIPS fallback, one live daemon changed source address while its peer remained stationary, continuous payload recovered during churn, and each restore upgraded back to direct"
      ;;
  esac
elif [[ "$SCENARIOS" == "fallback" ]]; then
  echo "fips roaming docker e2e passed: repeated direct drops used FIPS fallback, continuous bidirectional payload recovered, and each restore upgraded back to direct"
elif [[ "$SCENARIOS" == "latency" ]]; then
  echo "fips roaming docker e2e passed: direct LAN path established and the focused loaded-latency probe stayed bounded"
else
  echo "fips roaming docker e2e passed: one live daemon changed source address in both directions while its peer remained stationary, continuous bidirectional payload recovered, and both daemon processes stayed alive"
fi
