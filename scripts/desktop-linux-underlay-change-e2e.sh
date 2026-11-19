#!/usr/bin/env bash
# Guest-side half of the real Linux dual-NIC underlay-change gate.
set -euo pipefail

ACTION="${1:-}"
BINARY="${NVPN_UNDERLAY_BINARY:?set NVPN_UNDERLAY_BINARY}"
STATE_DIR="${NVPN_UNDERLAY_STATE_DIR:?set NVPN_UNDERLAY_STATE_DIR}"
CONFIG="$STATE_DIR/config.toml"
SECONDARY_PROFILE_UUID_FILE="$STATE_DIR/secondary.nm-uuid"
SECONDARY_PROFILE_NAME_FILE="$STATE_DIR/secondary.nm-name"
PRIMARY_MAC="${NVPN_UNDERLAY_PRIMARY_MAC:-}"
SECONDARY_MAC="${NVPN_UNDERLAY_SECONDARY_MAC:-}"
SECONDARY_ADDRESS="${NVPN_UNDERLAY_SECONDARY_ADDRESS:-}"
SECONDARY_PREFIX="${NVPN_UNDERLAY_SECONDARY_PREFIX:-24}"
SECONDARY_GATEWAY="${NVPN_UNDERLAY_SECONDARY_GATEWAY:-}"
NETWORK_ID="${NVPN_UNDERLAY_NETWORK_ID:-}"
PEER_NPUB="${NVPN_UNDERLAY_PEER_NPUB:-}"
PEER_ENDPOINT="${NVPN_UNDERLAY_PEER_ENDPOINT:-}"
PEER_TUNNEL_IP="${NVPN_UNDERLAY_PEER_TUNNEL_IP:-}"
FIXTURE_DNS_NAME="${NVPN_UNDERLAY_FIXTURE_DNS_NAME:-underlay-gate.nvpn.test}"
PROBE_URL="${NVPN_UNDERLAY_PROBE_URL:-https://example.com/}"
TUN_IFACE="${NVPN_UNDERLAY_TUN_IFACE:-nvu-underlay}"
LISTEN_PORT="${NVPN_UNDERLAY_LISTEN_PORT:-45821}"
RECOVERY_DEADLINE_MS="${NVPN_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"
EXPECTED_FIPS_REV="${NVPN_UNDERLAY_EXPECTED_FIPS_REV:-}"
WG_IFACE="${NVPN_UNDERLAY_WG_INTERFACE:-nvpn-wg-exit}"
CARRIER_MARK=0x4e56
WG_PEER_PUBLIC_KEY="${NVPN_UNDERLAY_WG_PEER_PUBLIC_KEY:-}"
WG_ENDPOINT="${NVPN_UNDERLAY_WG_ENDPOINT:-}"
WG_CLIENT_ADDRESS="${NVPN_UNDERLAY_WG_CLIENT_ADDRESS:-10.232.0.2/32}"
WG_SERVER_IP="${NVPN_UNDERLAY_WG_SERVER_IP:-}"
WG_PRIVATE_KEY_FILE="$STATE_DIR/wg-client-private.key"
WG_CONFIG_FILE="$STATE_DIR/wg-client.conf"
CLEANUP_JOURNAL="$STATE_DIR/.nvpn-network-cleanup/daemon.cleanup.json"
ORIGINAL_NPUB=""
ORIGINAL_TUNNEL_IP=""
CRASH_CONNECT_PID=""
CRASH_RESTART_PID=""
RECOVERY_NETWORK_PROBE_PID=""
RECOVERY_NETWORK_PROBE_ARM=""

fail() {
  echo "Linux underlay network-change e2e failed: $*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || fail "the guest runner requires root"
}

normalize_mac() {
  tr '[:upper:]' '[:lower:]' <<<"$1"
}

iface_for_mac() {
  local wanted="$1"
  local path
  wanted="$(normalize_mac "$wanted")"
  for path in /sys/class/net/*/address; do
    [[ "$(<"$path")" == "$wanted" ]] && basename "$(dirname "$path")"
  done
  return 0
}

require_iface_for_mac() {
  local mac="$1"
  local matches
  matches="$(iface_for_mac "$mac")"
  [[ "$(grep -c . <<<"$matches" || true)" == "1" ]] \
    || fail "expected exactly one Linux interface for the supplied MAC"
  printf '%s\n' "$matches"
}

read_npub() {
  awk '
    /^\[nostr\]$/ { in_nostr = 1; next }
    /^\[/ { in_nostr = 0 }
    in_nostr && /^public_key[[:space:]]*=/ {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$CONFIG"
}

status_json() {
  gate_command "$BINARY" status --config "$CONFIG" --json --discover-secs 0
}

gate_command() {
  if [[ -n "${RECOVERY_STARTED_MS:-}" ]]; then
    recovery_command "$RECOVERY_STARTED_MS" "$@"
  else
    "$@"
  fi
}

status_summary() {
  status_json | jq -c '{
    status_source,
    daemon_running: (.daemon.running // false),
    daemon_pid: (.daemon.pid // null),
    mesh_ready: (.daemon.state.mesh_ready // false),
    connected_peer_count: (.daemon.state.connected_peer_count // 0),
    vpn_status: (.daemon.state.vpn_status // null),
    fips_core_version: (.daemon.state.fips_core_version // null)
  }'
}

daemon_pid() {
  status_json | jq -er '
    select(.status_source == "daemon")
    | select(.daemon.running == true)
    | .daemon.pid
  '
}

route_dev() {
  gate_command ip -j -4 route get "$1" | jq -er '.[0].dev'
}

carrier_route_json() {
  gate_command ip -j -4 route get "$(endpoint_host)" mark "$CARRIER_MARK"
}

carrier_route_dev() {
  carrier_route_json | jq -er '.[0].dev'
}

egress_policy_installed() {
  local intent owner
  intent="/var/lib/nvpn/egress/$(printf %s "$CONFIG" | sha256sum | cut -d ' ' -f 1).json"
  owner="$(jq -er 'select(.version == 1 and .protection == true) | .owner' "$intent")" || return 1
  gate_command nft -j list table inet nvpn_egress | jq -e --arg owner "owner_$owner" '
    any(.nftables[]; .chain.name? == $owner)
    and any(.nftables[]; .chain.name? == "output" and .chain.policy? == "drop")
  ' >/dev/null || return 1
  gate_command ip -j -4 route show table 20054 default | jq -e --arg interface "$WG_IFACE" '
    any(.[]; .dev? == $interface) and any(.[]; .type? == "unreachable")
  ' >/dev/null
}

egress_policy_removed() {
  local family
  ! nft list table inet nvpn_egress >/dev/null 2>&1 || return 1
  for family in -4 -6; do
    ip -j "$family" rule show | jq -e '
      all(.[]; (.table? | tostring) != "20054" and .priority != 106)
    ' >/dev/null || return 1
    ip -j "$family" route show table all | jq -e '
      all(.[]; (.table? | tostring) != "20054")
    ' >/dev/null || return 1
  done
}

endpoint_host() {
  printf '%s\n' "${PEER_ENDPOINT%:*}"
}

probe_host() {
  local host="${PROBE_URL#*://}"
  host="${host%%/*}"
  printf '%s\n' "${host%%:*}"
}

marker_path() {
  printf '%s/%s\n' "$STATE_DIR" "$1"
}

write_marker() {
  printf '%s' "${2:-ok}" >"$(marker_path "$1")"
}

wait_for_marker() {
  local name="$1"
  local deadline="$((SECONDS + 30))"
  while ((SECONDS < deadline)); do
    [[ -e "$(marker_path "$name")" ]] && return 0
    sleep 0.1
  done
  fail "timed out waiting for host signal $name"
}

rebind_count() {
  grep -Fc 'underlay carrier(s) rebound' "$STATE_DIR/daemon.stderr.log" 2>/dev/null || true
}

endpoint_start_count() {
  grep -Ec \
    'daemon: (FIPS private mesh on|restarted FIPS private mesh on|rebuilt FIPS private mesh on)' \
    "$STATE_DIR/daemon.stderr.log" 2>/dev/null || true
}

payload_success_count() {
  grep -Fc 'bytes from' "$STATE_DIR/payload.log" 2>/dev/null || true
}

wireguard_payload_success_count() {
  grep -c . "$STATE_DIR/wireguard-payload.log" 2>/dev/null || true
}

wireguard_handshake_active() {
  gate_command wg show "$WG_IFACE" latest-handshakes 2>/dev/null \
    | awk 'NF == 2 && $2 + 0 > 0 { found = 1 } END { exit !found }'
}

wireguard_latest_handshake() {
  wg show "$WG_IFACE" latest-handshakes 2>/dev/null \
    | awk 'NF == 2 && $2 + 0 > latest { latest = $2 } END { print latest + 0 }'
}

wireguard_payload_loop() {
  while :; do
    if [[ -e "$STATE_DIR/wireguard-payload.pause" ]]; then
      : >"$STATE_DIR/wireguard-payload.paused"
      while [[ -e "$STATE_DIR/wireguard-payload.pause" ]]; do
        sleep 0.05
      done
      rm -f "$STATE_DIR/wireguard-payload.paused"
      continue
    fi
    if curl -4 --fail --silent --max-time 2 --output /dev/null "$PROBE_URL"; then
      monotonic_milliseconds >>"$STATE_DIR/wireguard-payload.log"
    fi
    sleep 0.1
  done
}

pause_wireguard_payload_loop() {
  local pid deadline
  [[ -s "$STATE_DIR/wireguard-probe.pid" ]] \
    || fail "WireGuard payload loop has no PID receipt"
  pid="$(<"$STATE_DIR/wireguard-probe.pid")"
  kill -0 "$pid" >/dev/null 2>&1 \
    || fail "WireGuard payload loop exited before the DNS matrix"
  : >"$STATE_DIR/wireguard-payload.pause"
  deadline="$((SECONDS + 5))"
  while ((SECONDS < deadline)); do
    [[ -e "$STATE_DIR/wireguard-payload.paused" ]] && return 0
    kill -0 "$pid" >/dev/null 2>&1 \
      || fail "WireGuard payload loop exited while pausing"
    sleep 0.05
  done
  fail "WireGuard payload loop did not pause before DNS evidence"
}

resume_wireguard_payload_loop() {
  local deadline="$((SECONDS + 5))"
  rm -f "$STATE_DIR/wireguard-payload.pause"
  while ((SECONDS < deadline)); do
    [[ ! -e "$STATE_DIR/wireguard-payload.paused" ]] && return 0
    sleep 0.05
  done
  fail "WireGuard payload loop did not resume after DNS evidence"
}

wireguard_endpoint_route_matches() {
  local route_json="$1"
  local expected_iface="$2"
  local expected_gateway="$3"
  local expected_source="$4"
  local host="$5"
  jq -e \
    --arg dev "$expected_iface" \
    --arg gateway "$expected_gateway" \
    --arg source "$expected_source" \
    --arg host "$host" \
    'length == 1
     and (.[0].dst == $host or .[0].dst == ($host + "/32"))
     and .[0].dev == $dev
     and .[0].gateway == $gateway
     and .[0].prefsrc == $source
     and .[0].mark == 20054' <<<"$route_json" >/dev/null
}

assert_wireguard_endpoint_route() {
  local expected_iface="$1"
  local host expected_gateway expected_source route_json
  host="$(endpoint_host)"
  [[ "$(gate_command wg show "$WG_IFACE" fwmark)" == "$CARRIER_MARK" ]] || return 1
  expected_gateway="$(
    gate_command ip -j -4 route show table main default dev "$expected_iface" \
      | jq -er 'min_by(.metric // 0).gateway'
  )"
  expected_source="$(
    gate_command ip -j -4 address show dev "$expected_iface" scope global \
      | jq -er '.[].addr_info[] | select(.family == "inet" and .scope == "global") | .local' \
      | head -n1
  )"
  route_json="$(carrier_route_json)"
  wireguard_endpoint_route_matches \
    "$route_json" "$expected_iface" "$expected_gateway" "$expected_source" "$host"
}

monotonic_milliseconds() {
  awk '{ printf "%.0f\n", $1 * 1000 }' /proc/uptime
}

unix_milliseconds() {
  local nanoseconds
  nanoseconds="$(date +%s%N)"
  [[ "$nanoseconds" =~ ^[0-9]+$ ]] \
    || fail "date did not return a numeric Unix nanosecond timestamp"
  echo "$((10#$nanoseconds / 1000000))"
}

flush_dns_cache() {
  gate_command resolvectl flush-caches >/dev/null
}

resolve_name() {
  local name="$1"
  flush_dns_cache
  resolve_name_without_flush "$name"
}

resolve_name_without_flush() {
  local name="$1"
  gate_command resolvectl query --type=A "$name" >/dev/null 2>&1 \
    && gate_command getent ahostsv4 "$name" >/dev/null 2>&1
}

resolve_fixture() {
  local addresses
  flush_dns_cache
  gate_command resolvectl query --type=A "$FIXTURE_DNS_NAME" \
    >/dev/null 2>&1 || return 1
  addresses="$(
    gate_command getent ahostsv4 "$FIXTURE_DNS_NAME" 2>/dev/null \
      | awk '{ print $1 }'
  )"
  grep -Fxq "$PEER_TUNNEL_IP" <<<"$addresses"
}

test_https() {
  gate_command curl -4 --fail --silent --show-error --max-time 8 \
    --output /dev/null "$PROBE_URL"
}

probe_production_platform_network_monitor() (
  local interface="$1"
  # Keep the production join-request Unix socket below Linux's 107-byte limit.
  local probe_dir="/tmp/nvpn-pnm-$$-${RANDOM}"
  local probe_config="$probe_dir/config.toml"
  local probe_iface="nvmp${RANDOM}"
  local probe_pid=""
  local join_socket_probe="$probe_dir/.nvpn-runtime/join-0000000000000000.sock"
  case "$probe_dir" in
    /tmp/nvpn-pnm-*) ;;
    *) fail "unsafe platform-network monitor probe directory" ;;
  esac
  ((${#join_socket_probe} <= 107)) \
    || fail "platform-network monitor probe Unix socket path is too long"
  [[ ! -e "$probe_dir" ]] \
    || fail "platform-network monitor probe directory already exists"
  cleanup_probe() {
    if [[ -n "$probe_pid" ]]; then
      "$BINARY" stop --config "$probe_config" --timeout-secs 3 --force \
        >/dev/null 2>&1 || true
      kill "$probe_pid" >/dev/null 2>&1 || true
      wait "$probe_pid" >/dev/null 2>&1 || true
    fi
    if [[ -d "$probe_dir" && -O "$probe_dir" && ! -L "$probe_dir" ]]; then
      rm -rf "$probe_dir"
    fi
  }
  trap cleanup_probe EXIT

  mkdir -p "$probe_dir"
  chmod 700 "$probe_dir"
  [[ -d "$probe_dir" && -O "$probe_dir" && ! -L "$probe_dir" ]] \
    || fail "platform-network monitor probe directory ownership is unsafe"
  "$BINARY" init --config "$probe_config" --force >/dev/null
  "$BINARY" daemon \
    --paused \
    --config "$probe_config" \
    --iface "$probe_iface" \
    >"$probe_dir/daemon.stdout.log" \
    2>"$probe_dir/daemon.stderr.log" &
  probe_pid="$!"

  local deadline="$((SECONDS + 10))"
  while ((SECONDS < deadline)); do
    if "$BINARY" status --config "$probe_config" --json --discover-secs 0 \
      | jq -e --argjson pid "$probe_pid" '
          .status_source == "daemon"
          and .daemon.running == true
          and .daemon.pid == $pid
        ' >/dev/null 2>&1
    then
      break
    fi
    sleep 0.1
  done
  ((SECONDS < deadline)) \
    || fail "production platform-network monitor probe daemon did not become ready"

  ip link set dev "$interface" down
  sleep 0.1
  ip link set dev "$interface" up
  deadline="$((SECONDS + 3))"
  while ((SECONDS < deadline)); do
    if grep -Fq \
      'daemon: platform network change event; sampling physical route' \
      "$probe_dir/daemon.stderr.log"
    then
      cp "$probe_dir/daemon.stderr.log" "$STATE_DIR/platform-network-monitor-probe.log"
      return 0
    fi
    sleep 0.05
  done
  fail "production daemon did not receive a real Linux netlink link event"
)

assert_same_daemon_ready() {
  local expected_pid="$1"
  local current_status
  [[ -n "$ORIGINAL_NPUB" && -n "$ORIGINAL_TUNNEL_IP" ]] \
    || fail "original daemon identity receipt is missing"
  current_status="$(status_json)"
  jq -e \
    --argjson pid "$expected_pid" \
    --arg rev "$EXPECTED_FIPS_REV" \
    --arg npub "$ORIGINAL_NPUB" \
    --arg tunnel_ip "$ORIGINAL_TUNNEL_IP" \
    --arg peer "$PEER_NPUB" '
    .status_source == "daemon"
    and .device_id == $npub
    and (.tunnel_ip | split("/")[0]) == $tunnel_ip
    and .daemon.running == true
    and .daemon.pid == $pid
    and .daemon.state.mesh_ready == true
    and .daemon.state.connected_peer_count >= 1
    and (.daemon.state.fips_core_version | endswith("(rev " + $rev + ")"))
    and ((.daemon.state.fips_endpoint_peers // []) as $peers
      | ($peers | length) == 1 and $peers[0].npub == $peer)
  ' <<<"$current_status" >/dev/null
}

assert_secure_dns() {
  gate_command resolvectl dns "$TUN_IFACE" \
    | grep -Eq '(^|[[:space:]])127\.0\.0\.55([[:space:]]|$)'
  gate_command resolvectl domain "$TUN_IFACE" | grep -Fq '~.'
}

ACTIVE_EXIT_LAST_PREDICATE=not_started

assert_active_exit_state() {
  local expected_iface="$1"
  local expected_pid="$2"
  ACTIVE_EXIT_LAST_PREDICATE=daemon_identity
  assert_same_daemon_ready "$expected_pid" || return 1
  ACTIVE_EXIT_LAST_PREDICATE=wireguard_default_route
  [[ "$(route_dev 1.1.1.1)" == "$WG_IFACE" ]] || return 1
  ACTIVE_EXIT_LAST_PREDICATE=wireguard_endpoint_interface
  [[ "$(carrier_route_dev)" == "$expected_iface" ]] || return 1
  ACTIVE_EXIT_LAST_PREDICATE=no_unmarked_endpoint_bypass
  [[ "$(route_dev "$(endpoint_host)")" == "$WG_IFACE" ]] || return 1
  ACTIVE_EXIT_LAST_PREDICATE=wireguard_endpoint_tuple
  assert_wireguard_endpoint_route "$expected_iface" || return 1
  ACTIVE_EXIT_LAST_PREDICATE=durable_egress_protection
  egress_policy_installed || return 1
  ACTIVE_EXIT_LAST_PREDICATE=wireguard_handshake
  wireguard_handshake_active || return 1
  ACTIVE_EXIT_LAST_PREDICATE=secure_dns
  assert_secure_dns || return 1
  ACTIVE_EXIT_LAST_PREDICATE=active_exit_state_ready
}

assert_active_exit() {
  local expected_iface="$1"
  local expected_pid="$2"
  local require_fixture="${3:-1}"
  assert_active_exit_state "$expected_iface" "$expected_pid" || return 1
  if [[ "$require_fixture" == "1" ]]; then
    ACTIVE_EXIT_LAST_PREDICATE=fixture_dns
    resolve_fixture || return 1
  fi
  ACTIVE_EXIT_LAST_PREDICATE=public_dns
  resolve_name "$(probe_host)" || return 1
  ACTIVE_EXIT_LAST_PREDICATE=https
  test_https || return 1
  ACTIVE_EXIT_LAST_PREDICATE=active_exit_ready
}

assert_single_nvpn_process() {
  local expected_pid="$1"
  local processes
  processes="$(pgrep -x nvpn 2>/dev/null || true)"
  [[ "$processes" == "$expected_pid" ]] \
    || fail "expected exactly one nvpn process ($expected_pid), found: ${processes:-none}"
}

initial_ready() {
  local primary_iface="$1"
  local expected_pid="$2"
  assert_active_exit "$primary_iface" "$expected_pid" 1 || return 1
  ACTIVE_EXIT_LAST_PREDICATE=fips_payload_progress
  (( $(payload_success_count) > 2 )) || return 1
  ACTIVE_EXIT_LAST_PREDICATE=wireguard_payload_progress
  (( $(wireguard_payload_success_count) > 1 )) || return 1
  ACTIVE_EXIT_LAST_PREDICATE=single_endpoint_start
  [[ "$(endpoint_start_count)" == 1 ]] || return 1
  ACTIVE_EXIT_LAST_PREDICATE=ready
}

wait_initial_ready() {
  local primary_iface="$1"
  local expected_pid="$2"
  local deadline="$((SECONDS + 30))"
  local stable_rebinds="" stable_since=0 count now
  while ((SECONDS < deadline)); do
    if initial_ready "$primary_iface" "$expected_pid"; then
      count="$(rebind_count)"
      now="$(monotonic_milliseconds)"
      if [[ "$count" != "$stable_rebinds" ]]; then
        stable_rebinds="$count"
        stable_since="$now"
      elif ((now - stable_since >= 1000)); then
        return 0
      fi
    else
      stable_rebinds=""
    fi
    sleep 0.25
  done
  {
    echo "initial_last_predicate=$ACTIVE_EXIT_LAST_PREDICATE"
    echo "initial_route=$(route_dev 1.1.1.1 2>/dev/null || echo unavailable)"
    echo "initial_endpoint_route=$(carrier_route_dev 2>/dev/null || echo unavailable)"
    echo "initial_endpoint_route_json=$(
      carrier_route_json 2>/dev/null \
        | jq -c . 2>/dev/null || echo unavailable
    )"
    echo "initial_payload_successes=$(payload_success_count)"
    echo "initial_wireguard_payload_successes=$(wireguard_payload_success_count)"
    echo "initial_rebind_receipts=$(rebind_count)"
    status_summary || true
    resolvectl status "$TUN_IFACE" 2>/dev/null || true
    tail -n 80 "$STATE_DIR/daemon.stderr.log" 2>/dev/null || true
  } >&2
  fail "initial FIPS exit, DNS, HTTPS, and payload did not become ready"
}

dump_recovery_failure() {
  local label="$1"
  local expected_iface="$2"
  local expected_carrier_iface="$3"
  {
    echo "recovery_label=$label"
    echo "expected_interface=$expected_iface"
    echo "last_route=$(carrier_route_dev 2>/dev/null || echo unavailable)"
    echo "last_carrier=$(<"/sys/class/net/$expected_carrier_iface/carrier")"
    echo "last_payload_successes=$(payload_success_count)"
    echo "last_wireguard_payload_successes=$(wireguard_payload_success_count)"
    echo "last_rebind_receipts=$(rebind_count)"
    ip -4 route show
    status_summary || true
    tail -n 120 "$STATE_DIR/daemon.stderr.log" 2>/dev/null || true
  } >&2
}

recovery_command() {
  local started="$1"
  shift
  local now remaining duration
  now="$(monotonic_milliseconds)"
  remaining="$((RECOVERY_DEADLINE_MS - (now - started)))"
  ((remaining > 0)) || return 124
  duration="$(awk -v milliseconds="$remaining" \
    'BEGIN { printf "%.3fs", milliseconds / 1000 }')"
  timeout --foreground --signal=KILL "$duration" "$@"
}

recovery_network_probe() (
  local arm="$1"
  local receipt="$2"
  local started=""
  local https_at now
  local temporary="$receipt.tmp.$$"
  cleanup_recovery_network_probe_worker() {
    rm -f "$temporary"
  }
  probe_once() {
    resolve_fixture || return 1
    resolve_name_without_flush "$(probe_host)" || return 1
    test_https || return 1
    https_at="$(monotonic_milliseconds)"
  }
  trap cleanup_recovery_network_probe_worker EXIT

  while [[ ! -s "$arm" ]]; do
    sleep 0.005
  done
  read -r started <"$arm"
  [[ "$started" =~ ^[0-9]+$ ]] || return 1
  local RECOVERY_STARTED_MS="$started"

  while :; do
    if probe_once && ((https_at - started <= RECOVERY_DEADLINE_MS)); then
      printf '%s\n' "$https_at" >"$temporary"
      mv "$temporary" "$receipt"
      return 0
    fi
    now="$(monotonic_milliseconds)"
    ((now - started < RECOVERY_DEADLINE_MS)) || return 1
    sleep 0.025
  done
)

stop_recovery_network_probe() {
  if [[ -n "$RECOVERY_NETWORK_PROBE_PID" ]]; then
    kill "$RECOVERY_NETWORK_PROBE_PID" >/dev/null 2>&1 || true
    wait "$RECOVERY_NETWORK_PROBE_PID" >/dev/null 2>&1 || true
    RECOVERY_NETWORK_PROBE_PID=""
  fi
  if [[ -n "$RECOVERY_NETWORK_PROBE_ARM" ]]; then
    rm -f "$RECOVERY_NETWORK_PROBE_ARM"
    RECOVERY_NETWORK_PROBE_ARM=""
  fi
}

observe_recovery() {
  local label="$1"
  local expected_iface="$2"
  local expected_carrier_iface="$3"
  local expected_carrier="$4"
  local expected_pid="$5"
  local probe_before wg_probe_before rebind_before endpoint_starts_before
  local route_usable_at route_usable_monotonic started now
  local rebind_at="" payload_at="" wg_payload_at="" network_at=""
  local rebind_after payload_after wg_payload_after endpoint_starts_after
  local recovered_elapsed recovered_at recovered_monotonic endpoint_route evidence_at
  local deadline_edge_read=0
  local recovery_last_predicate=timestamped_recovery_evidence
  local network_probe_arm network_probe_receipt
  rebind_before="$(rebind_count)"
  endpoint_starts_before="$(endpoint_start_count)"
  [[ "$endpoint_starts_before" == "1" ]] \
    || fail "$label expected exactly one original FIPS endpoint start"

  network_probe_arm="$(marker_path "$label.network-probe.arm")"
  network_probe_receipt="$(marker_path "$label.network-probe.receipt.json")"
  rm -f "$network_probe_arm" "$network_probe_receipt"
  recovery_network_probe "$network_probe_arm" "$network_probe_receipt" &
  RECOVERY_NETWORK_PROBE_PID="$!"
  RECOVERY_NETWORK_PROBE_ARM="$network_probe_arm"
  write_marker "armed-$label"

  local carrier_deadline="$((SECONDS + 30))"
  while ((SECONDS < carrier_deadline)); do
    if [[ "$(<"/sys/class/net/$expected_carrier_iface/carrier")" == "$expected_carrier" ]]; then
      break
    fi
    sleep 0.025
  done
  if [[ "$(<"/sys/class/net/$expected_carrier_iface/carrier")" != "$expected_carrier" ]]; then
    dump_recovery_failure "$label" "$expected_iface" "$expected_carrier_iface"
    fail "$label physical carrier did not reach its expected state"
  fi

  local route_deadline="$((SECONDS + 15))"
  while ((SECONDS < route_deadline)); do
    if [[ "$(carrier_route_dev 2>/dev/null || true)" == "$expected_iface" ]]; then
      break
    fi
    sleep 0.025
  done
  if [[ "$(carrier_route_dev 2>/dev/null || true)" != "$expected_iface" ]]; then
    dump_recovery_failure "$label" "$expected_iface" "$expected_carrier_iface"
    fail "$label physical endpoint route did not become usable within 15s"
  fi

  route_usable_at="$(unix_milliseconds)"
  route_usable_monotonic="$(monotonic_milliseconds)"
  probe_before="$(payload_success_count)"
  wg_probe_before="$(wireguard_payload_success_count)"
  started="$route_usable_monotonic"
  printf '%s\n' "$started" >"$network_probe_arm"

  while :; do
    rebind_after="$(rebind_count)"
    payload_after="$(payload_success_count)"
    wg_payload_after="$(wireguard_payload_success_count)"
    endpoint_starts_after="$(endpoint_start_count)"
    now="$(monotonic_milliseconds)"
    if ((rebind_after > rebind_before + 1)); then
      recovery_last_predicate=single_rebind
      break
    fi
    if [[ "$endpoint_starts_after" != "$endpoint_starts_before" ]]; then
      recovery_last_predicate=endpoint_continuity
      break
    fi
    [[ -n "$rebind_at" || "$rebind_after" -ne $((rebind_before + 1)) ]] \
      || rebind_at="$now"
    [[ -n "$payload_at" || "$payload_after" -le "$probe_before" ]] \
      || payload_at="$now"
    [[ -n "$wg_payload_at" || "$wg_payload_after" -le "$wg_probe_before" ]] \
      || wg_payload_at="$now"
    if [[ -z "$network_at" && -s "$network_probe_receipt" ]]; then
      read -r network_at <"$network_probe_receipt"
      [[ "$network_at" =~ ^[0-9]+$ && "$network_at" -ge "$started" ]] \
        || network_at=""
    fi
    if [[ -n "$rebind_at" && -n "$payload_at" \
      && -n "$wg_payload_at" && -n "$network_at" ]]
    then
      recovered_monotonic="$started"
      for evidence_at in \
        "$rebind_at" "$payload_at" "$wg_payload_at" "$network_at"
      do
        ((evidence_at > recovered_monotonic)) \
          && recovered_monotonic="$evidence_at"
      done
      recovered_elapsed="$((recovered_monotonic - started))"
      ((recovered_elapsed <= RECOVERY_DEADLINE_MS)) \
        || recovery_last_predicate=timestamped_recovery_completed_late
      break
    fi
    if ((deadline_edge_read == 1)); then
      break
    fi
    now="$(monotonic_milliseconds)"
    if ((now - started >= RECOVERY_DEADLINE_MS)); then
      # Permit one last read: log/receipt writes may trail evidence whose own
      # timestamp was within the product deadline.
      deadline_edge_read=1
    else
      sleep 0.025
    fi
  done

  if [[ -z "$recovered_elapsed" ]] \
    || ((recovered_elapsed > RECOVERY_DEADLINE_MS))
  then
    dump_recovery_failure "$label" "$expected_iface" "$expected_carrier_iface"
    {
      echo "payload_successes_before=$probe_before"
      echo "wireguard_payload_successes_before=$wg_probe_before"
      echo "rebind_receipts_before=$rebind_before"
      echo "route_usable_unix_milliseconds=$route_usable_at"
      echo "route_usable_monotonic_milliseconds=$route_usable_monotonic"
      echo "rebind_observed_monotonic_milliseconds=${rebind_at:-missing}"
      echo "payload_success_observed_monotonic_milliseconds=${payload_at:-missing}"
      echo "wireguard_payload_success_monotonic_milliseconds=${wg_payload_at:-missing}"
      echo "network_probe_success_monotonic_milliseconds=${network_at:-missing}"
      echo "recovery_last_predicate=$recovery_last_predicate"
      echo "recovery_elapsed_milliseconds=${recovered_elapsed:-missing}"
    } >&2
    fail "$label recovery predicate $recovery_last_predicate exceeded ${RECOVERY_DEADLINE_MS}ms"
  fi
  wait "$RECOVERY_NETWORK_PROBE_PID" \
    || fail "$label fresh DNS and HTTPS recovery probe failed"
  RECOVERY_NETWORK_PROBE_PID=""
  rm -f "$RECOVERY_NETWORK_PROBE_ARM"
  RECOVERY_NETWORK_PROBE_ARM=""

  # Stable state is audited after all timestamped recovery evidence is sealed;
  # subprocess latency here is not product recovery latency.
  if ! assert_active_exit_state "$expected_iface" "$expected_pid"; then
    dump_recovery_failure "$label" "$expected_iface" "$expected_carrier_iface"
    fail "$label stable active-exit audit failed at $ACTIVE_EXIT_LAST_PREDICATE"
  fi
  [[ "$(endpoint_start_count)" == "$endpoint_starts_before" ]] \
    || fail "$label restarted the FIPS endpoint"
  (( $(rebind_count) == rebind_before + 1 )) \
    || fail "$label did not produce exactly one FIPS carrier rebind"
  ! grep -Eq 'daemon: (restarted|rebuilt) FIPS private mesh on' \
    "$STATE_DIR/daemon.stderr.log" \
    || fail "$label replaced the FIPS endpoint"
  recovered_at="$((route_usable_at + recovered_elapsed))"
  endpoint_route="$(carrier_route_json)"
  jq -cn \
    --argjson recovery_milliseconds "$recovered_elapsed" \
    --argjson route_usable_unix_milliseconds "$route_usable_at" \
    --argjson route_usable_monotonic_milliseconds "$route_usable_monotonic" \
    --argjson recovered_unix_milliseconds "$recovered_at" \
    --argjson recovered_monotonic_milliseconds "$recovered_monotonic" \
    --argjson rebind_observed_monotonic_milliseconds "$rebind_at" \
    --argjson payload_success_observed_monotonic_milliseconds "$payload_at" \
    --argjson wireguard_payload_success_monotonic_milliseconds "$wg_payload_at" \
    --argjson network_probe_success_monotonic_milliseconds "$network_at" \
    --argjson daemon_pid "$expected_pid" \
    --arg physical_interface "$expected_iface" \
    --argjson payload_successes_before "$probe_before" \
    --argjson payload_successes_after "$(payload_success_count)" \
    --argjson wireguard_payload_successes_before "$wg_probe_before" \
    --argjson wireguard_payload_successes_after "$(wireguard_payload_success_count)" \
    --argjson rebind_receipts_before "$rebind_before" \
    --argjson rebind_receipts_after "$(rebind_count)" \
    --argjson endpoint_starts_before "$endpoint_starts_before" \
    --argjson endpoint_starts_after "$(endpoint_start_count)" \
    --arg identity_npub "$ORIGINAL_NPUB" \
    --arg tunnel_ip "$ORIGINAL_TUNNEL_IP" \
    --arg participant_npub "$PEER_NPUB" \
    --argjson wireguard_endpoint_route "$endpoint_route" \
    '{
      recovery_milliseconds: $recovery_milliseconds,
      route_usable_unix_milliseconds: $route_usable_unix_milliseconds,
      route_usable_monotonic_milliseconds: $route_usable_monotonic_milliseconds,
      recovered_unix_milliseconds: $recovered_unix_milliseconds,
      recovered_monotonic_milliseconds: $recovered_monotonic_milliseconds,
      rebind_observed_monotonic_milliseconds:
        $rebind_observed_monotonic_milliseconds,
      payload_success_observed_monotonic_milliseconds:
        $payload_success_observed_monotonic_milliseconds,
      wireguard_payload_success_monotonic_milliseconds:
        $wireguard_payload_success_monotonic_milliseconds,
      network_probe_success_monotonic_milliseconds:
        $network_probe_success_monotonic_milliseconds,
      daemon_pid: $daemon_pid,
      physical_interface: $physical_interface,
      payload_successes_before: $payload_successes_before,
      payload_successes_after: $payload_successes_after,
      wireguard_payload_successes_before: $wireguard_payload_successes_before,
      wireguard_payload_successes_after: $wireguard_payload_successes_after,
      rebind_receipts_before: $rebind_receipts_before,
      rebind_receipts_after: $rebind_receipts_after,
      endpoint_starts_before: $endpoint_starts_before,
      endpoint_starts_after: $endpoint_starts_after,
      fixture_dns_recovered: true,
      public_dns_recovered: true,
      verified_https: true,
      identity_npub: $identity_npub,
      tunnel_ip: $tunnel_ip,
      participant_npub: $participant_npub,
      wireguard_endpoint_route: $wireguard_endpoint_route
    }' >"$(marker_path "$label.receipt.json")"
}

run_dns_case() {
  local name="$1"
  local lookup_name="$2"
  local expected_pid="$3"
  local expected_iface="$4"
  shift 4
  wait_for_marker "dns-$name.go"
  pause_wireguard_payload_loop
  "$BINARY" set --config "$CONFIG" "$@" >/dev/null
  write_marker "dns-$name.configured"
  wait_for_marker "dns-$name.query"

  local deadline="$((SECONDS + 30))"
  while ((SECONDS < deadline)); do
    if [[ "$lookup_name" == "$FIXTURE_DNS_NAME" ]]; then
      resolve_fixture && assert_active_exit "$expected_iface" "$expected_pid" 0 \
        && break
    elif resolve_name "$lookup_name" \
      && assert_active_exit "$expected_iface" "$expected_pid" 0
    then
      break
    fi
    sleep 0.25
  done
  ((SECONDS < deadline)) || fail "real $name DNS lookup did not succeed"
  write_marker "dns-$name.receipt" "$lookup_name"
  wait_for_marker "dns-$name.snapshotted"
  resume_wireguard_payload_loop
  write_marker "dns-$name.resumed"
}

stop_pid_file() {
  local path="$1"
  [[ -s "$path" ]] || return 0
  local pid
  pid="$(<"$path")"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 50); do
    kill -0 "$pid" >/dev/null 2>&1 || return 0
    sleep 0.1
  done
  kill -KILL "$pid" >/dev/null 2>&1 || true
}

restore_network() {
  local failed=0 cleanup_pid=""
  stop_recovery_network_probe
  if [[ -x "$BINARY" && -e "$CONFIG" ]]; then
    "$BINARY" pause --config "$CONFIG" >"$STATE_DIR/cleanup-control.log" 2>&1 || failed=1
    if ! daemon_pid >/dev/null 2>&1 && ! egress_policy_removed; then
      "$BINARY" daemon --paused --config "$CONFIG" --iface "$TUN_IFACE" \
        >"$STATE_DIR/cleanup-daemon.stdout.log" 2>"$STATE_DIR/cleanup-daemon.stderr.log" &
      cleanup_pid="$!"
    fi
    local deadline="$((SECONDS + 15))"
    while ((SECONDS < deadline)); do
      if egress_policy_removed; then
        [[ -z "$cleanup_pid" || "$(daemon_pid 2>/dev/null || true)" == "$cleanup_pid" ]] && break
      fi
      sleep 0.1
    done
    ((SECONDS < deadline)) || failed=1
    egress_policy_removed || failed=1
    "$BINARY" stop --config "$CONFIG" --timeout-secs 5 --force >>"$STATE_DIR/cleanup-control.log" 2>&1 \
      || failed=1
  fi
  if [[ -n "$cleanup_pid" ]]; then
    wait "$cleanup_pid" || failed=1
  fi
  stop_pid_file "$STATE_DIR/probe.pid"
  stop_pid_file "$STATE_DIR/wireguard-probe.pid"
  stop_pid_file "$STATE_DIR/runner-daemon.pid"
  if [[ -s "$SECONDARY_PROFILE_UUID_FILE" ]]; then
    nmcli connection delete uuid "$(<"$SECONDARY_PROFILE_UUID_FILE")" \
      >/dev/null 2>&1 || true
  elif [[ -s "$SECONDARY_PROFILE_NAME_FILE" ]]; then
    nmcli connection delete "$(<"$SECONDARY_PROFILE_NAME_FILE")" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$PRIMARY_MAC" ]]; then
    local primary_iface
    primary_iface="$(iface_for_mac "$PRIMARY_MAC" | head -n1)"
    [[ -n "$primary_iface" ]] || failed=1
    [[ "$(route_dev 1.1.1.1 2>/dev/null || true)" == "$primary_iface" ]] || failed=1
    resolve_name "$(probe_host)" || failed=1
    test_https || failed=1
  fi
  return "$failed"
}

emergency_restore_network() {
  if restore_network; then
    return 0
  fi
  write_marker "emergency-repair-invoked"
  if [[ -x "$BINARY" && -e "$CONFIG" ]]; then
    "$BINARY" repair-network --config "$CONFIG" >/dev/null 2>&1 || true
  fi
  return 1
}

finish_run_cleanup() {
  local status="$?"
  trap - EXIT
  restore_network || status=1
  exit "$status"
}

finish_crash_repair_cleanup() {
  local status="$?"
  trap - EXIT
  if [[ -n "$CRASH_RESTART_PID" ]]; then
    "$BINARY" stop --config "$CONFIG" --timeout-secs 5 --force >/dev/null 2>&1 || true
    kill "$CRASH_RESTART_PID" >/dev/null 2>&1 || true
    wait "$CRASH_RESTART_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$CRASH_CONNECT_PID" ]]; then
    kill -KILL "$CRASH_CONNECT_PID" >/dev/null 2>&1 || true
    wait "$CRASH_CONNECT_PID" >/dev/null 2>&1 || true
  fi
  emergency_restore_network >/dev/null 2>&1 || true
  exit "$status"
}

initialize() {
  require_root
  for value in \
    "$PRIMARY_MAC" "$SECONDARY_MAC" "$SECONDARY_ADDRESS" \
    "$SECONDARY_GATEWAY" "$NETWORK_ID"
  do
    [[ -n "$value" ]] || fail "Initialize is missing a required argument"
  done
  [[ -x "$BINARY" ]] || fail "candidate Linux nvpn binary is missing"
  command -v nmcli >/dev/null \
    || fail "NetworkManager CLI is required for the transient real NIC"
  command -v wg >/dev/null \
    || fail "WireGuard tools are required for the real upstream profile"
  if pgrep -x nvpn >/dev/null; then
    fail "another nvpn process is already running before the isolated gate"
  fi
  local primary_iface secondary_iface primary_metric secondary_metric
  local primary_gateway primary_address
  local profile_name profile_uuid uuid
  local -a secondary_connections
  primary_iface="$(require_iface_for_mac "$PRIMARY_MAC")"
  secondary_iface="$(require_iface_for_mac "$SECONDARY_MAC")"
  mapfile -t secondary_connections < <(
    nmcli -t -f UUID,DEVICE connection show --active \
      | awk -F: -v iface="$secondary_iface" '$2 == iface { print $1 }'
  )
  for uuid in "${secondary_connections[@]}"; do
    nmcli connection delete uuid "$uuid" >/dev/null
  done
  nmcli device set "$secondary_iface" managed no
  primary_metric="$(
    ip -4 route show default dev "$primary_iface" \
      | awk '{
          for (i = 1; i <= NF; i++) if ($i == "metric") { print $(i + 1); exit }
          print 0
        }' \
      | head -n1
  )"
  [[ "$primary_metric" =~ ^[0-9]+$ ]] || fail "could not read the primary route metric"
  primary_gateway="$(
    ip -j -4 route show default dev "$primary_iface" \
      | jq -er 'sort_by(.metric // 0) | .[0].gateway'
  )"
  primary_address="$(
    ip -j -4 address show dev "$primary_iface" scope global \
      | jq -er '.[].addr_info[]
          | select(.family == "inet" and .scope == "global")
          | .local' \
      | head -n1
  )"
  secondary_metric="$((primary_metric + 500))"

  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  restore_network
  rm -rf "$STATE_DIR"
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  # Exercise the production netlink monitor before installing the disposable
  # NetworkManager profile. The gate itself then uses the ordinary Linux
  # network-management path for the replacement underlay.
  probe_production_platform_network_monitor "$secondary_iface"

  profile_name="nvpn-underlay-$secondary_iface-$$"
  printf '%s\n' "$profile_name" >"$SECONDARY_PROFILE_NAME_FILE"
  nmcli connection add \
    type ethernet \
    ifname "$secondary_iface" \
    con-name "$profile_name" \
    connection.autoconnect no \
    ipv4.method manual \
    ipv4.addresses "$SECONDARY_ADDRESS/$SECONDARY_PREFIX" \
    ipv4.gateway "$SECONDARY_GATEWAY" \
    ipv4.route-metric "$secondary_metric" \
    ipv4.ignore-auto-dns yes \
    ipv6.method disabled \
    >/dev/null
  profile_uuid="$(nmcli -g connection.uuid connection show "$profile_name")"
  [[ -n "$profile_uuid" ]] || fail "transient NetworkManager profile has no UUID"
  printf '%s\n' "$profile_uuid" >"$SECONDARY_PROFILE_UUID_FILE"
  nmcli device set "$secondary_iface" managed yes
  nmcli connection up uuid "$profile_uuid" >/dev/null

  "$BINARY" init --config "$CONFIG" --force >/dev/null
  "$BINARY" set --config "$CONFIG" --network-id "$NETWORK_ID" >/dev/null
  umask 077
  wg genkey >"$WG_PRIVATE_KEY_FILE"
  jq -cn \
    --arg npub "$(read_npub)" \
    --arg tunnel_ip "$("$BINARY" ip --config "$CONFIG")" \
    --arg primary_interface "$primary_iface" \
    --arg primary_gateway "$primary_gateway" \
    --arg primary_address "$primary_address" \
    --arg secondary_interface "$secondary_iface" \
    --arg secondary_profile_uuid "$profile_uuid" \
    --arg wireguard_public_key "$(wg pubkey <"$WG_PRIVATE_KEY_FILE")" \
    --argjson primary_metric "$primary_metric" \
    --argjson secondary_metric "$secondary_metric" \
    '{
      npub: $npub,
      tunnel_ip: $tunnel_ip,
      primary_interface: $primary_interface,
      primary_gateway: $primary_gateway,
      primary_address: $primary_address,
      secondary_interface: $secondary_interface,
      secondary_profile_uuid: $secondary_profile_uuid,
      wireguard_public_key: $wireguard_public_key,
      primary_metric: $primary_metric,
      secondary_metric: $secondary_metric
    }' | tee "$STATE_DIR/identity.json"
}

assert_secondary_underlay_ready() {
  local interface="$1"
  local profile_uuid active_uuid defaults_json
  [[ -s "$SECONDARY_PROFILE_UUID_FILE" ]] \
    || fail "secondary NetworkManager profile receipt is missing"
  profile_uuid="$(<"$SECONDARY_PROFILE_UUID_FILE")"
  active_uuid="$(
    nmcli -t -f UUID,DEVICE connection show --active \
      | awk -F: -v iface="$interface" '$2 == iface { print $1 }'
  )"
  [[ "$active_uuid" == "$profile_uuid" ]] \
    || fail "secondary NetworkManager profile is not the active connection"
  [[ "$(<"/sys/class/net/$interface/carrier")" == "1" ]] \
    || fail "secondary physical carrier is not usable before the host cut"
  ip -j -4 address show dev "$interface" scope global \
    | jq -e --arg address "$SECONDARY_ADDRESS" --argjson prefix "$SECONDARY_PREFIX" '
        any(.[].addr_info[]?;
          .local == $address and .prefixlen == $prefix and .scope == "global"
        )
      ' >/dev/null \
    || fail "secondary global IPv4 address is missing before the host cut"
  egress_policy_installed \
    || fail "durable strict egress protection is missing before the host cut"
  defaults_json="$(ip -j -4 route show table main default)"
  jq -e --arg interface "$interface" --arg gateway "$SECONDARY_GATEWAY" \
    --arg wireguard "$WG_IFACE" '
    any(.[]; .dev == $interface and .gateway == $gateway)
    and all(.[]; .dev != $wireguard)
  ' <<<"$defaults_json" >/dev/null \
    || fail "network-manager physical defaults changed under strict exit"
  jq -cn \
    --arg interface "$interface" \
    --arg profile_uuid "$profile_uuid" \
    --arg address "$SECONDARY_ADDRESS/$SECONDARY_PREFIX" \
    --arg gateway "$SECONDARY_GATEWAY" \
    '{
      interface: $interface,
      profile_uuid: $profile_uuid,
      address: $address,
      gateway: $gateway,
      carrier: true,
      active_profile: true,
      physical_default_route: true,
      egress_policy_protected: true,
      application_endpoint_bypass: false
    }' >"$STATE_DIR/secondary-underlay-ready.json"
}

run_gate() {
  require_root
  for value in \
    "$PRIMARY_MAC" "$SECONDARY_MAC" "$SECONDARY_ADDRESS" "$SECONDARY_GATEWAY" \
    "$NETWORK_ID" "$PEER_NPUB" \
    "$PEER_ENDPOINT" "$PEER_TUNNEL_IP" "$EXPECTED_FIPS_REV" \
    "$WG_PEER_PUBLIC_KEY" "$WG_ENDPOINT" "$WG_CLIENT_ADDRESS" "$WG_SERVER_IP"
  do
    [[ -n "$value" ]] || fail "Run is missing a required peer/underlay argument"
  done
  local primary_iface secondary_iface daemon_process daemon_receipt
  primary_iface="$(require_iface_for_mac "$PRIMARY_MAC")"
  secondary_iface="$(require_iface_for_mac "$SECONDARY_MAC")"
  trap finish_run_cleanup EXIT
  [[ -s "$WG_PRIVATE_KEY_FILE" ]] || fail "WireGuard client private key is missing"
  umask 077
  {
    printf '[Interface]\n'
    printf 'PrivateKey = %s\n' "$(<"$WG_PRIVATE_KEY_FILE")"
    printf 'Address = %s\n' "$WG_CLIENT_ADDRESS"
    printf 'DNS = 1.1.1.1\n\n'
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "$WG_PEER_PUBLIC_KEY"
    printf 'AllowedIPs = 0.0.0.0/0\n'
    printf 'Endpoint = %s\n' "$WG_ENDPOINT"
    printf 'PersistentKeepalive = 1\n'
  } >"$WG_CONFIG_FILE"

  "$BINARY" set \
    --config "$CONFIG" \
    --network-id "$NETWORK_ID" \
    --participant "$PEER_NPUB" \
    --listen-port "$LISTEN_PORT" \
    --fips-advertise-public-endpoint false \
    --fips-nostr-discovery-enabled false \
    --lan-discovery-enabled false \
    --fips-webrtc-enabled false \
    --fips-bootstrap-enabled false \
    --fips-peer-endpoint "${PEER_NPUB}=${PEER_ENDPOINT}" \
    --wireguard-exit-config-file "$WG_CONFIG_FILE" \
    --wireguard-exit-enabled true \
    --exit-node-leak-protection true \
    --exit-dns-mode through_exit \
    --exit-dns-through-exit-servers "$WG_SERVER_IP" \
    --autoconnect true \
    >/dev/null
  ORIGINAL_NPUB="$(read_npub)"
  ORIGINAL_TUNNEL_IP="$("$BINARY" ip --config "$CONFIG")"
  [[ -n "$ORIGINAL_NPUB" && -n "$ORIGINAL_TUNNEL_IP" ]] \
    || fail "failed to pin original daemon identity"

  env RUST_LOG=info "$BINARY" daemon \
    --config "$CONFIG" \
    --iface "$TUN_IFACE" \
    --mesh-refresh-interval-secs 2 \
    >"$STATE_DIR/daemon.stdout.log" \
    2>"$STATE_DIR/daemon.stderr.log" &
  daemon_process="$!"
  printf '%s\n' "$daemon_process" >"$STATE_DIR/runner-daemon.pid"

  local deadline="$((SECONDS + 30))"
  while ((SECONDS < deadline)); do
    daemon_receipt="$(daemon_pid 2>/dev/null || true)"
    [[ "$daemon_receipt" == "$daemon_process" ]] && break
    sleep 0.1
  done
  [[ "$daemon_receipt" == "$daemon_process" ]] \
    || fail "production daemon receipt did not match its process"

  ping -D -n -i 0.1 -W 1 "$PEER_TUNNEL_IP" \
    >"$STATE_DIR/payload.log" 2>&1 &
  printf '%s\n' "$!" >"$STATE_DIR/probe.pid"
  : >"$STATE_DIR/wireguard-payload.log"
  wireguard_payload_loop &
  printf '%s\n' "$!" >"$STATE_DIR/wireguard-probe.pid"
  wait_initial_ready "$primary_iface" "$daemon_process"
  assert_secondary_underlay_ready "$secondary_iface"
  write_marker ready "$daemon_process"

  wait_for_marker arm-secondary
  observe_recovery secondary "$secondary_iface" "$primary_iface" 0 "$daemon_process"

  wait_for_marker arm-primary
  observe_recovery primary "$primary_iface" "$primary_iface" 1 "$daemon_process"

  run_dns_case automatic example.com "$daemon_process" "$primary_iface" \
    --exit-dns-mode automatic
  run_dns_case cloudflare www.cloudflare.com "$daemon_process" "$primary_iface" \
    --exit-dns-mode encrypted \
    --exit-dns-doh-provider cloudflare
  run_dns_case quad9 www.quad9.net "$daemon_process" "$primary_iface" \
    --exit-dns-mode encrypted \
    --exit-dns-doh-provider quad9
  run_dns_case custom iana.org "$daemon_process" "$primary_iface" \
    --exit-dns-mode encrypted \
    --exit-dns-doh-provider custom \
    --exit-dns-custom-doh-url https://dns.google/dns-query \
    --exit-dns-custom-doh-bootstrap-ips 8.8.8.8,8.8.4.4
  run_dns_case through-exit "$FIXTURE_DNS_NAME" "$daemon_process" "$primary_iface" \
    --exit-dns-mode through_exit \
    --exit-dns-through-exit-servers "$WG_SERVER_IP"

  wait_for_marker select-direct
  "$BINARY" set \
    --config "$CONFIG" \
    --wireguard-exit-enabled false \
    --exit-dns-mode automatic \
    >/dev/null
  deadline="$((SECONDS + 30))"
  while ((SECONDS < deadline)); do
    if [[ "$(route_dev 1.1.1.1 2>/dev/null || true)" == "$primary_iface" ]] \
      && assert_same_daemon_ready "$daemon_process" \
      && resolve_name "$(probe_host)" \
      && test_https \
      && ! ip link show dev "$WG_IFACE" >/dev/null 2>&1 \
      && egress_policy_removed \
      && ! ip -4 rule show | grep -Eq '^10888:.*from .* lookup 51888$' \
      && [[ -z "$(ip -4 route show exact "$(endpoint_host)/32")" ]]
    then
      break
    fi
    sleep 0.25
  done
  ((SECONDS < deadline)) || fail "native Direct route, DNS, and HTTPS did not restore"
  if resolvectl dns "$TUN_IFACE" 2>/dev/null | grep -Eq '127\.0\.0\.(1|55)([[:space:]]|$)'; then
    fail "secure exit DNS remained installed after selecting Direct"
  fi
  if ip -4 route show table 51888 >"$STATE_DIR/direct-policy-table.txt" 2>&1 \
    && grep -q . "$STATE_DIR/direct-policy-table.txt"
  then
    fail "WireGuard policy table retained routes after selecting Direct"
  elif ! grep -Fq 'FIB table does not exist' "$STATE_DIR/direct-policy-table.txt" \
    && grep -q . "$STATE_DIR/direct-policy-table.txt"
  then
    fail "WireGuard policy-table cleanup returned an unexpected error"
  fi
  jq -cn \
    --argjson daemon_pid "$daemon_process" \
    --arg physical_interface "$primary_iface" \
    --arg identity_npub "$ORIGINAL_NPUB" \
    --arg tunnel_ip "$ORIGINAL_TUNNEL_IP" \
    --arg participant_npub "$PEER_NPUB" \
    --argjson endpoint_start_count "$(endpoint_start_count)" \
    '{
      daemon_pid: $daemon_pid,
      physical_interface: $physical_interface,
      identity_npub: $identity_npub,
      tunnel_ip: $tunnel_ip,
      participant_npub: $participant_npub,
      endpoint_start_count: $endpoint_start_count,
      wireguard_interface_removed: true,
      wireguard_endpoint_route_removed: true,
      wireguard_policy_rule_removed: true,
      wireguard_policy_table_empty: true,
      egress_policy_removed: true,
      public_dns: true,
      verified_https: true
    }' >"$(marker_path direct.receipt.json)"
  write_marker "done"
}

crash_repair_gate() {
  require_root
  for value in \
    "$PRIMARY_MAC" "$NETWORK_ID" "$PEER_NPUB" "$PEER_ENDPOINT" \
    "$PEER_TUNNEL_IP" "$EXPECTED_FIPS_REV" "$WG_PEER_PUBLIC_KEY" \
    "$WG_ENDPOINT" "$WG_CLIENT_ADDRESS" "$WG_SERVER_IP"
  do
    [[ -n "$value" ]] || fail "Crash repair is missing a required peer/underlay argument"
  done
  [[ -x "$BINARY" && -s "$CONFIG" && -s "$WG_CONFIG_FILE" ]] \
    || fail "Crash repair requires the initialized exact candidate and WireGuard profile"
  if pgrep -x nvpn >/dev/null 2>&1; then
    fail "another nvpn process is already running before crash recovery"
  fi

  local primary_iface crash_started handshake deadline killed_status
  local journal_sha restart_started restart_repaired_at restart_elapsed
  local daemon_status policy_table binary_sha
  primary_iface="$(require_iface_for_mac "$PRIMARY_MAC")"
  ORIGINAL_NPUB="$(read_npub)"
  ORIGINAL_TUNNEL_IP="$("$BINARY" ip --config "$CONFIG")"
  [[ -n "$ORIGINAL_NPUB" && -n "$ORIGINAL_TUNNEL_IP" ]] \
    || fail "Crash repair could not pin the initialized identity"
  trap finish_crash_repair_cleanup EXIT
  rm -f \
    "$STATE_DIR/crash-connect.pid" \
    "$STATE_DIR/crash-restart-daemon.pid" \
    "$STATE_DIR/crash-repair.receipt.json" \
    "$STATE_DIR/crash-journal-ownership.json"

  # The foreground production path intentionally ignores autoconnect. Persist
  # false first so the post-SIGKILL daemon can repair ownership while paused.
  "$BINARY" set \
    --config "$CONFIG" \
    --wireguard-exit-enabled true \
    --exit-node-leak-protection true \
    --exit-dns-mode through_exit \
    --exit-dns-through-exit-servers "$WG_SERVER_IP" \
    --autoconnect false \
    >/dev/null
  crash_started="$(date +%s)"
  env RUST_LOG=info "$BINARY" connect \
    --config "$CONFIG" \
    --iface "$TUN_IFACE" \
    --mesh-refresh-interval-secs 2 \
    >"$STATE_DIR/crash-connect.stdout.log" \
    2>"$STATE_DIR/crash-connect.stderr.log" &
  CRASH_CONNECT_PID="$!"
  printf '%s\n' "$CRASH_CONNECT_PID" >"$STATE_DIR/crash-connect.pid"

  deadline="$((SECONDS + 30))"
  while ((SECONDS < deadline)); do
    handshake="$(wireguard_latest_handshake 2>/dev/null || echo 0)"
    if kill -0 "$CRASH_CONNECT_PID" >/dev/null 2>&1 \
      && [[ "$(route_dev 1.1.1.1 2>/dev/null || true)" == "$WG_IFACE" ]] \
      && [[ "$(carrier_route_dev 2>/dev/null || true)" == "$primary_iface" ]] \
      && assert_wireguard_endpoint_route "$primary_iface" \
      && [[ "$handshake" =~ ^[0-9]+$ && "$handshake" -ge "$crash_started" ]] \
      && assert_secure_dns \
      && resolve_fixture \
      && resolve_name "$(probe_host)" \
      && test_https \
      && ping -n -c 1 -W 1 "$PEER_TUNNEL_IP" >/dev/null 2>&1
    then
      break
    fi
    sleep 0.2
  done
  if ((SECONDS >= deadline)); then
    {
      echo "crash_connect_route=$(route_dev 1.1.1.1 2>/dev/null || echo unavailable)"
      echo "crash_connect_endpoint_route=$(carrier_route_dev 2>/dev/null || echo unavailable)"
      echo "crash_connect_handshake=$(wireguard_latest_handshake 2>/dev/null || echo unavailable)"
      resolvectl status "$TUN_IFACE" 2>/dev/null || true
      tail -n 100 "$STATE_DIR/crash-connect.stderr.log" 2>/dev/null || true
    } >&2
    fail "foreground exit, through-exit DNS, HTTPS, and fresh handshake did not become ready"
  fi
  assert_single_nvpn_process "$CRASH_CONNECT_PID"
  [[ -s "$CLEANUP_JOURNAL" ]] \
    || fail "foreground exit did not durably persist network cleanup ownership"
  jq -e \
    --arg iface "$TUN_IFACE" \
    --arg wireguard "$WG_IFACE" '
      .iface == $iface
      and .exit_node_runtime.wireguard_exit.interface == $wireguard
      and .exit_node_runtime.wireguard_exit.table == 51888
      and .exit_node_runtime.wireguard_exit.priority == 10888
      and .exit_node_runtime.wireguard_exit.main_defaults_owned == false
      and .exit_node_runtime.wireguard_exit.policy_rule_owned == true
      and (.exit_node_runtime.wireguard_exit.endpoint_routes | length) == 0
      and .secure_dns.Resolved.interface == $iface
    ' "$CLEANUP_JOURNAL" >/dev/null \
    || fail "cleanup journal lacks exact WireGuard and secure-DNS ownership"

  kill -KILL "$CRASH_CONNECT_PID"
  set +e
  wait "$CRASH_CONNECT_PID"
  killed_status="$?"
  set -e
  CRASH_CONNECT_PID=""
  [[ "$killed_status" == "137" ]] \
    || fail "foreground connect did not exit from SIGKILL (status $killed_status)"
  [[ -z "$(pgrep -x nvpn 2>/dev/null || true)" ]] \
    || fail "SIGKILL left an nvpn process running"

  # Prove the real owned state and exact durable journal survived the crash.
  [[ -s "$CLEANUP_JOURNAL" ]] \
    || fail "SIGKILL removed the durable cleanup journal"
  journal_sha="$(sha256sum "$CLEANUP_JOURNAL" | awk '{ print $1 }')"
  jq -e \
    --arg iface "$TUN_IFACE" \
    --arg wireguard "$WG_IFACE" '
      .iface == $iface
      and .exit_node_runtime.wireguard_exit.interface == $wireguard
      and .exit_node_runtime.wireguard_exit.table == 51888
      and .exit_node_runtime.wireguard_exit.priority == 10888
      and .exit_node_runtime.wireguard_exit.main_defaults_owned == false
      and .exit_node_runtime.wireguard_exit.policy_rule_owned == true
      and (.exit_node_runtime.wireguard_exit.endpoint_routes | length) == 0
      and .secure_dns.Resolved.interface == $iface
    ' "$CLEANUP_JOURNAL" >/dev/null \
    || fail "SIGKILL journal lost exact WireGuard or secure-DNS ownership"
  jq \
    --arg iface "$TUN_IFACE" \
    --arg wireguard "$WG_IFACE" '
      {
        iface: .iface,
        original_default_route_owned: (.original_default_route != null),
        endpoint_bypass_route_count: (.endpoint_bypass_routes | length),
        wireguard: {
          interface: .exit_node_runtime.wireguard_exit.interface,
          table: .exit_node_runtime.wireguard_exit.table,
          priority: .exit_node_runtime.wireguard_exit.priority
        },
        secure_dns: {
          interface: .secure_dns.Resolved.interface
        }
      }
      | select(.iface == $iface and .wireguard.interface == $wireguard)
    ' "$CLEANUP_JOURNAL" >"$STATE_DIR/crash-journal-ownership.json"
  [[ "$(route_dev 1.1.1.1)" == "$WG_IFACE" ]] \
    || fail "SIGKILL did not retain the owned WireGuard default"
  [[ "$(carrier_route_dev)" == "$primary_iface" ]] \
    || fail "SIGKILL did not retain the owned endpoint bypass"
  assert_wireguard_endpoint_route "$primary_iface"
  ip link show dev "$WG_IFACE" >/dev/null 2>&1 \
    || fail "SIGKILL removed the owned WireGuard interface"
  egress_policy_installed \
    || fail "SIGKILL removed the durable egress protection"
  ip -4 rule show | grep -Eq '^10888:.*from .* lookup 51888$' \
    || fail "SIGKILL removed the owned WireGuard policy rule"
  ip -4 route show table 51888 | grep -q . \
    || fail "SIGKILL removed the owned WireGuard policy table"

  # Starting the same exact candidate paused must run startup repair before it
  # publishes daemon readiness. No explicit recovery command is used.
  restart_started="$(monotonic_milliseconds)"
  env RUST_LOG=info "$BINARY" daemon \
    --paused \
    --config "$CONFIG" \
    --iface "$TUN_IFACE" \
    --mesh-refresh-interval-secs 2 \
    >"$STATE_DIR/crash-restart-daemon.stdout.log" \
    2>"$STATE_DIR/crash-restart-daemon.stderr.log" &
  CRASH_RESTART_PID="$!"
  printf '%s\n' "$CRASH_RESTART_PID" >"$STATE_DIR/crash-restart-daemon.pid"

  while :; do
    restart_repaired_at="$(monotonic_milliseconds)"
    restart_elapsed="$((restart_repaired_at - restart_started))"
    if ((restart_elapsed > RECOVERY_DEADLINE_MS)); then
      {
        echo "restart_repair_elapsed_milliseconds=$restart_elapsed"
        echo "restart_route=$(route_dev 1.1.1.1 2>/dev/null || echo unavailable)"
        echo "restart_journal_present=$([[ -e "$CLEANUP_JOURNAL" ]] && echo true || echo false)"
        ip -4 route show
        ip -4 rule show
        resolvectl status "$TUN_IFACE" 2>/dev/null || true
        tail -n 100 "$STATE_DIR/crash-restart-daemon.stderr.log" 2>/dev/null || true
      } >&2
      fail "paused daemon startup repair exceeded ${RECOVERY_DEADLINE_MS}ms"
    fi
    policy_table="$(ip -4 route show table 51888 2>&1 || true)"
    if [[ ! -e "$CLEANUP_JOURNAL" ]] \
      && [[ "$(route_dev 1.1.1.1 2>/dev/null || true)" == "$primary_iface" ]] \
      && ! ip link show dev "$WG_IFACE" >/dev/null 2>&1 \
      && egress_policy_removed \
      && ! ip -4 rule show | grep -Eq '^10888:.*from .* lookup 51888$' \
      && [[ -z "$(ip -4 route show exact "$(endpoint_host)/32")" ]] \
      && { [[ -z "$policy_table" ]] || grep -Fq 'FIB table does not exist' <<<"$policy_table"; } \
      && ! resolvectl dns "$TUN_IFACE" 2>/dev/null | grep -Eq '127\.0\.0\.(1|55)([[:space:]]|$)' \
      && resolve_name "$(probe_host)" \
      && test_https
    then
      restart_repaired_at="$(monotonic_milliseconds)"
      restart_elapsed="$((restart_repaired_at - restart_started))"
      ((restart_elapsed <= RECOVERY_DEADLINE_MS)) \
        || fail "paused daemon startup repair exceeded ${RECOVERY_DEADLINE_MS}ms"
      break
    fi
    sleep 0.05
  done

  deadline="$((SECONDS + 15))"
  while ((SECONDS < deadline)); do
    daemon_status="$(status_json 2>/dev/null || true)"
    if jq -e --argjson pid "$CRASH_RESTART_PID" '
      .status_source == "daemon"
      and .daemon.running == true
      and .daemon.pid == $pid
      and .daemon.state.vpn_enabled == false
      and .daemon.state.vpn_active == false
      and (
        .daemon.state.vpn_status == "Paused"
        or .daemon.state.vpn_status == "Listening for join requests"
      )
    ' <<<"$daemon_status" >/dev/null 2>&1
    then
      break
    fi
    sleep 0.1
  done
  ((SECONDS < deadline)) \
    || fail "paused daemon did not publish repaired inactive state"
  assert_single_nvpn_process "$CRASH_RESTART_PID"
  binary_sha="$(sha256sum "$BINARY" | awk '{ print $1 }')"
  jq -cn \
    --arg binary_sha256 "$binary_sha" \
    --arg cleanup_journal_sha256 "$journal_sha" \
    --arg physical_interface "$primary_iface" \
    --arg wireguard_interface "$WG_IFACE" \
    --argjson sigkill_exit_code "$killed_status" \
    --argjson restart_daemon_pid "$CRASH_RESTART_PID" \
    --argjson restart_daemon_count 1 \
    --argjson restart_repair_milliseconds "$restart_elapsed" \
    '{
      binary_sha256: $binary_sha256,
      cleanup_journal_sha256: $cleanup_journal_sha256,
      physical_interface: $physical_interface,
      wireguard_interface: $wireguard_interface,
      sigkill_exit_code: $sigkill_exit_code,
      fresh_wireguard_handshake: true,
      through_exit_dns_before_crash: true,
      verified_https_before_crash: true,
      cleanup_journal_survived_sigkill: true,
      wireguard_interface_survived_sigkill: true,
      wireguard_endpoint_route_survived_sigkill: true,
      wireguard_policy_rule_survived_sigkill: true,
      wireguard_policy_table_survived_sigkill: true,
      durable_egress_protection_survived_sigkill: true,
      secure_dns_cleanup_ownership_survived_sigkill: true,
      startup_repair_without_explicit_command: true,
      cleanup_journal_removed: true,
      wireguard_interface_removed: true,
      wireguard_endpoint_route_removed: true,
      wireguard_policy_rule_removed: true,
      wireguard_policy_table_empty: true,
      egress_policy_removed: true,
      secure_dns_cleanup_ownership_removed: true,
      physical_default_restored: true,
      public_dns_restored: true,
      verified_https_after_restart: true,
      restart_daemon_paused: true,
      restart_daemon_pid: $restart_daemon_pid,
      restart_daemon_count: $restart_daemon_count,
      restart_repair_milliseconds: $restart_repair_milliseconds
    }' >"$STATE_DIR/crash-repair.receipt.json"

  "$BINARY" stop --config "$CONFIG" --timeout-secs 5 --force >/dev/null
  wait "$CRASH_RESTART_PID" >/dev/null 2>&1 || true
  CRASH_RESTART_PID=""
  [[ -z "$(pgrep -x nvpn 2>/dev/null || true)" ]] \
    || fail "clean stop after crash repair left an nvpn process"
  "$BINARY" set \
    --config "$CONFIG" \
    --wireguard-exit-enabled false \
    --exit-dns-mode automatic \
    --autoconnect true \
    >/dev/null
  rm -f "$STATE_DIR/crash-connect.pid" "$STATE_DIR/crash-restart-daemon.pid"
  trap - EXIT
}

cleanup_gate() {
  require_root
  mkdir -p "$STATE_DIR"
  emergency_restore_network
}

case "$ACTION" in
  initialize) initialize ;;
  run) run_gate ;;
  crash-repair) crash_repair_gate ;;
  cleanup-fault)
    require_root
    exec "$(dirname "$0")/desktop-linux-cleanup-fault-e2e.sh"
    ;;
  cleanup) cleanup_gate ;;
  *) echo "usage: $0 {initialize|run|crash-repair|cleanup-fault|cleanup}" >&2; exit 2 ;;
esac
