#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
: "${NVPN_MOBILE_WG_REMOTE_STATE_DIR:?remote fixture state dir is required}"
: "${NVPN_MOBILE_WG_REMOTE_INTERFACE:?remote fixture interface is required}"
: "${NVPN_MOBILE_WG_REMOTE_NFT_TABLE:?remote fixture nft table is required}"
state_dir="$NVPN_MOBILE_WG_REMOTE_STATE_DIR"
interface="$NVPN_MOBILE_WG_REMOTE_INTERFACE"
nft_table="$NVPN_MOBILE_WG_REMOTE_NFT_TABLE"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
endpoint_family="${NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY:-dns}"

validate_names() {
  [[ "$state_dir" =~ ^(/var)?/tmp/nvpn-mobile-wg-exit\.[a-zA-Z0-9][a-zA-Z0-9._-]*(/fixture)?$ \
      && -d "$state_dir" && ! -L "$state_dir" \
      && ( "$state_dir" != */fixture || ! -L "${state_dir%/*}" ) ]] \
    && [[ "$interface" =~ ^[a-zA-Z][a-zA-Z0-9]{1,14}$ ]] \
    && [[ "$nft_table" =~ ^[a-zA-Z][a-zA-Z0-9]{1,20}$ ]]
}
validate_names || {
  echo "remote native fixture received an unsafe resource name" >&2
  exit 2
}
case "$endpoint_family" in
  ipv4|ipv6|dns) ;;
  *)
    echo "remote native fixture endpoint family is invalid" >&2
    exit 2
    ;;
esac

system_firewall_rules="$state_dir/system-firewall-rules.tsv"
ip_forward_lock="/run/lock/nvpn-mobile-wg-exit-ip-forward.lock"
ip_forward_state="/run/nvpn-mobile-wg-exit-ip-forward"
ip_forward_leases="$ip_forward_state/leases"
ip_forward_original="$ip_forward_state/original"
ip_forward_sysctl="/proc/sys/net/ipv4/ip_forward"

read_ip_forwarding() {
  local value
  value="$(cat "$ip_forward_sysctl" 2>/dev/null)" || return 1
  [[ "$value" == "0" || "$value" == "1" ]] || return 1
  printf '%s\n' "$value"
}

write_ip_forwarding() {
  local value="$1" current
  [[ "$value" == "0" || "$value" == "1" ]] || return 1
  printf '%s\n' "$value" >"$ip_forward_sysctl" || return 1
  current="$(read_ip_forwarding)" || return 1
  [[ "$current" == "$value" ]]
}

ip_forward_state_valid_locked() {
  [[ -d "$ip_forward_state" \
    && -d "$ip_forward_leases" \
    && -f "$ip_forward_original" ]] || return 1
  local current original lease_file lease_interface lease_owner
  local lease_count=0 seen_owners=""
  current="$(read_ip_forwarding)" || return 1
  original="$(<"$ip_forward_original")"
  [[ "$current" == "1" \
    && ("$original" == "0" || "$original" == "1") ]] || return 1
  for lease_file in "$ip_forward_leases"/*; do
    [[ -f "$lease_file" ]] || continue
    lease_interface="${lease_file##*/}"
    lease_owner="$(<"$lease_file")"
    [[ "$lease_interface" =~ ^[a-zA-Z][a-zA-Z0-9]{1,14}$ \
      && "$lease_owner" =~ ^(/var)?/tmp/nvpn-mobile-wg-exit\.[a-zA-Z0-9][a-zA-Z0-9._-]*(/fixture)?$ \
      && -d "$lease_owner" && ! -L "$lease_owner" \
      && ( "$lease_owner" != */fixture || ! -L "${lease_owner%/*}" ) ]] || return 1
    case $'\n'"$seen_owners"$'\n' in
      *$'\n'"$lease_owner"$'\n'*) return 1 ;;
    esac
    seen_owners="${seen_owners}${seen_owners:+$'\n'}$lease_owner"
    ip link show "$lease_interface" >/dev/null 2>&1 || return 1
    lease_count=$((lease_count + 1))
  done
  (( lease_count > 0 ))
}

with_ip_forward_lock() {
  local callback="$1" status=0
  exec 9>"$ip_forward_lock" || return 1
  flock -x 9 || {
    exec 9>&-
    return 1
  }
  if "$callback"; then
    status=0
  else
    status=$?
  fi
  flock -u 9 || status=1
  exec 9>&-
  return "$status"
}

rollback_first_ip_forward_lease_locked() {
  local original="$1"
  if write_ip_forwarding "$original"; then
    rm -f "$ip_forward_original"
    rmdir "$ip_forward_leases" "$ip_forward_state" >/dev/null 2>&1 || true
  fi
}

acquire_ip_forward_lease_locked() {
  local first_lease=0 current lease_file lease_owner
  local own_lease="$ip_forward_leases/$interface"
  if [[ -e "$ip_forward_state" ]]; then
    ip_forward_state_valid_locked || return 1
  else
    current="$(read_ip_forwarding)" || return 1
    mkdir -m 700 "$ip_forward_state" || return 1
    mkdir -m 700 "$ip_forward_leases" || {
      rmdir "$ip_forward_state" >/dev/null 2>&1 || true
      return 1
    }
    if ! printf '%s\n' "$current" >"$ip_forward_original"; then
      rmdir "$ip_forward_leases" "$ip_forward_state" >/dev/null 2>&1 || true
      return 1
    fi
    first_lease=1
  fi
  [[ ! -e "$own_lease" ]] || return 1
  for lease_file in "$ip_forward_leases"/*; do
    [[ -f "$lease_file" ]] || continue
    lease_owner="$(<"$lease_file")"
    [[ "$lease_owner" != "$state_dir" ]] || return 1
  done
  if [[ "$first_lease" -eq 1 ]] && ! write_ip_forwarding 1; then
    rollback_first_ip_forward_lease_locked "$current"
    return 1
  fi
  if ! printf '%s\n' "$state_dir" >"$own_lease"; then
    rm -f "$own_lease"
    if [[ "$first_lease" -eq 1 ]]; then
      rollback_first_ip_forward_lease_locked "$current"
    fi
    return 1
  fi
  if ! ip_forward_state_valid_locked; then
    rm -f "$own_lease"
    if [[ "$first_lease" -eq 1 ]]; then
      rollback_first_ip_forward_lease_locked "$current"
    fi
    return 1
  fi
}

acquire_ip_forward_lease() {
  with_ip_forward_lock acquire_ip_forward_lease_locked || {
    echo "remote fixture could not acquire the shared IPv4 forwarding lease" >&2
    return 1
  }
}

release_ip_forward_lease_locked() {
  [[ -e "$ip_forward_state" ]] || return 0
  ip_forward_state_valid_locked || return 1
  local own_lease="$ip_forward_leases/$interface"
  local original lease_file lease_owner remaining=0
  if [[ ! -f "$own_lease" ]]; then
    for lease_file in "$ip_forward_leases"/*; do
      [[ -f "$lease_file" ]] || continue
      lease_owner="$(<"$lease_file")"
      [[ "$lease_owner" != "$state_dir" ]] || return 1
    done
    return 0
  fi
  lease_owner="$(<"$own_lease")"
  [[ "$lease_owner" == "$state_dir" ]] || return 1
  original="$(<"$ip_forward_original")"
  rm -f "$own_lease" || return 1
  for lease_file in "$ip_forward_leases"/*; do
    [[ -f "$lease_file" ]] || continue
    remaining=1
    break
  done
  if [[ "$remaining" -eq 1 ]]; then
    if ip_forward_state_valid_locked; then
      return 0
    fi
    printf '%s\n' "$state_dir" >"$own_lease" || true
    return 1
  fi
  if ! write_ip_forwarding "$original"; then
    write_ip_forwarding 1 >/dev/null 2>&1 || true
    printf '%s\n' "$state_dir" >"$own_lease" || true
    return 1
  fi
  rm -f "$ip_forward_original" || return 1
  rmdir "$ip_forward_leases" "$ip_forward_state" || return 1
}

release_ip_forward_lease() {
  with_ip_forward_lock release_ip_forward_lease_locked
}

release_ip_forward_lease_and_delete_interface_locked() {
  release_ip_forward_lease_locked || return 1
  if ip link show "$interface" >/dev/null 2>&1; then
    ip link delete "$interface" >/dev/null 2>&1 || return 1
  fi
  ! ip link show "$interface" >/dev/null 2>&1
}

release_ip_forward_lease_and_delete_interface() {
  with_ip_forward_lock release_ip_forward_lease_and_delete_interface_locked || {
    echo "remote fixture could not release its IPv4 forwarding lease safely" >&2
    return 1
  }
}

ip_forward_lease_clean_locked() {
  [[ -e "$ip_forward_state" ]] || return 0
  ip_forward_state_valid_locked || return 1
  local lease_file lease_owner
  [[ ! -e "$ip_forward_leases/$interface" ]] || return 1
  for lease_file in "$ip_forward_leases"/*; do
    [[ -f "$lease_file" ]] || continue
    lease_owner="$(<"$lease_file")"
    [[ "$lease_owner" != "$state_dir" ]] || return 1
  done
}

ip_forward_lease_clean() {
  with_ip_forward_lock ip_forward_lease_clean_locked
}

system_firewall_marker_handle() {
  local family="$1" table="$2" chain="$3" marker="$4"
  local rules="" handle="" status=0
  rules="$(
    nft -a list chain "$family" "$table" "$chain" 2>/dev/null
  )" || return 3
  if handle="$(
    awk -v expected_marker="comment \042$marker\042" '
        index($0, expected_marker) {
          for (field = 1; field <= NF; field++) {
            if ($field == "handle") {
              if (!found) {
                handle = $(field + 1)
              }
              found++
            }
          }
        }
        END {
          if (found == 1) {
            print handle
            exit 0
          }
          exit(found == 0 ? 1 : 2)
        }
      ' <<<"$rules"
  )"
  then
    status=0
  else
    status=$?
  fi
  [[ -z "$handle" ]] || printf '%s\n' "$handle"
  return "$status"
}

add_system_firewall_rule() {
  local family="$1" table="$2" chain="$3" marker="$4"
  shift 4
  nft list chain "$family" "$table" "$chain" >/dev/null 2>&1 || return 0
  local existing_status=0
  system_firewall_marker_handle \
    "$family" "$table" "$chain" "$marker" >/dev/null 2>&1 \
    || existing_status=$?
  if [[ "$existing_status" -eq 0 ]]; then
    echo "remote fixture found a stale temporary firewall marker" >&2
    return 1
  elif [[ "$existing_status" -ne 1 ]]; then
    echo "remote fixture could not prove its firewall marker is unique" >&2
    return 1
  fi
  printf '%s\t%s\t%s\tpending\t%s\n' \
    "$family" "$table" "$chain" "$marker" \
    >>"$system_firewall_rules"
  nft insert rule "$family" "$table" "$chain" "$@" comment "$marker"
  local handle
  handle="$(
    system_firewall_marker_handle "$family" "$table" "$chain" "$marker"
  )" || {
    echo "remote fixture could not locate its temporary firewall rule" >&2
    return 1
  }
  [[ "$handle" =~ ^[1-9][0-9]*$ ]] || {
    echo "remote fixture could not record its temporary firewall rule" >&2
    return 1
  }
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$family" "$table" "$chain" "$handle" "$marker" \
    >>"$system_firewall_rules"
}

system_firewall_rule_exists() {
  local family="$1" table="$2" chain="$3" handle="$4" marker="$5"
  nft -a list chain "$family" "$table" "$chain" 2>/dev/null \
    | awk \
      -v expected_handle="$handle" \
      -v expected_marker="comment \042$marker\042" '
        {
          if (index($0, expected_marker)) {
            for (field = 1; field <= NF; field++) {
              if ($field == "handle" && $(field + 1) == expected_handle) {
                found = 1
              }
            }
          }
        }
        END { exit !found }
      '
}

system_firewall_marker_rules_clean() {
  local ruleset marker_prefix
  marker_prefix="comment \"nvpn-mobile-$interface-"
  ruleset="$(nft -a list ruleset 2>/dev/null)" || return 1
  ! grep -Fq "$marker_prefix" <<<"$ruleset"
}

delete_system_firewall_marker() {
  local family="$1" table="$2" chain="$3" marker="$4"
  local handle="" status=0
  handle="$(
    system_firewall_marker_handle "$family" "$table" "$chain" "$marker"
  )" || status=$?
  if [[ "$status" -eq 0 && "$handle" =~ ^[1-9][0-9]*$ ]]; then
    nft delete rule "$family" "$table" "$chain" handle "$handle" \
      >/dev/null 2>&1 || true
  elif [[ "$status" -ne 1 ]]; then
    return 1
  fi
  status=0
  system_firewall_marker_handle \
    "$family" "$table" "$chain" "$marker" >/dev/null 2>&1 \
    || status=$?
  [[ "$status" -eq 1 ]]
}

remove_system_firewall_rules() {
  [[ -f "$system_firewall_rules" ]] || return 0
  local family table chain handle marker failed=0
  while IFS=$'\t' read -r family table chain handle marker; do
    if [[ ! "$family" =~ ^(inet|ip|ip6)$ \
      || ! "$table" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ \
      || ! "$chain" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ \
      || ! "$marker" =~ ^nvpn-mobile-[a-zA-Z0-9_-]+$ ]]
    then
      failed=1
      continue
    fi
    if [[ "$handle" == "pending" ]]; then
      delete_system_firewall_marker \
        "$family" "$table" "$chain" "$marker" || failed=1
      continue
    elif [[ ! "$handle" =~ ^[1-9][0-9]*$ ]]; then
      failed=1
      continue
    fi
    if system_firewall_rule_exists \
        "$family" "$table" "$chain" "$handle" "$marker"
    then
      nft delete rule "$family" "$table" "$chain" handle "$handle" \
        >/dev/null 2>&1 || true
    fi
    if system_firewall_rule_exists \
        "$family" "$table" "$chain" "$handle" "$marker"
    then
      failed=1
    fi
  done <"$system_firewall_rules"
  system_firewall_marker_rules_clean || failed=1
  if [[ "$failed" -eq 0 ]]; then
    rm -f "$system_firewall_rules"
  fi
  return "$failed"
}

pid_matches_fixture() {
  local pid="$1" needle="$2"
  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/cmdline" ]] \
    && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -Fq "$needle"
}

wireguard_listener_ready() {
  local listeners
  [[ "${NVPN_MOBILE_WG_LISTEN_PORT:-}" =~ ^[1-9][0-9]{0,4}$ ]] \
    || return 1
  case "$endpoint_family" in
    ipv4) listeners="$(ss -H -lun4 2>/dev/null)" ;;
    ipv6) listeners="$(ss -H -lun6 2>/dev/null)" ;;
    dns) listeners="$(ss -H -lun 2>/dev/null)" ;;
  esac
  python3 - "$NVPN_MOBILE_WG_LISTEN_PORT" "$listeners" <<'PY'
import re
import sys

port, listeners = sys.argv[1:]
for line in listeners.splitlines():
    if any(
        re.search(rf"[\].:]{re.escape(port)}$", field)
        for field in line.split()
    ):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

fixture_processes_clean() {
  local name pid
  for name in dnsmasq udp-echo http-probe tls-capture; do
    if [[ -s "$state_dir/$name.pid" ]]; then
      pid="$(<"$state_dir/$name.pid")"
      pid_matches_fixture "$pid" "$state_dir" && return 1
    fi
  done
  return 0
}

system_firewall_rules_clean() {
  [[ -f "$system_firewall_rules" ]] || return 0
  local family table chain handle marker
  while IFS=$'\t' read -r family table chain handle marker; do
    [[ "$family" =~ ^(inet|ip|ip6)$ \
      && "$table" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ \
      && "$chain" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ \
      && "$marker" =~ ^nvpn-mobile-[a-zA-Z0-9_-]+$ ]] \
      || return 1
    if [[ "$handle" == "pending" ]]; then
      local status=0
      system_firewall_marker_handle \
        "$family" "$table" "$chain" "$marker" >/dev/null 2>&1 \
        || status=$?
      [[ "$status" -eq 1 ]] || return 1
    elif [[ "$handle" =~ ^[1-9][0-9]*$ ]]; then
      if system_firewall_rule_exists \
          "$family" "$table" "$chain" "$handle" "$marker"
      then
        return 1
      fi
    else
      return 1
    fi
  done <"$system_firewall_rules"
}

assert_fixture_clean() {
  local failed=0
  fixture_processes_clean || failed=1
  system_firewall_rules_clean || failed=1
  system_firewall_marker_rules_clean || failed=1
  if nft list table inet "$nft_table" >/dev/null 2>&1; then
    failed=1
  fi
  if ip link show "$interface" >/dev/null 2>&1; then
    failed=1
  fi
  ip_forward_lease_clean || failed=1
  return "$failed"
}

stop_fixture() {
  local name pid failed=0
  for name in dnsmasq udp-echo http-probe tls-capture; do
    if [[ -s "$state_dir/$name.pid" ]]; then
      pid="$(<"$state_dir/$name.pid")"
      if pid_matches_fixture "$pid" "$state_dir"; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null && pid_matches_fixture "$pid" "$state_dir"; then
          kill -KILL "$pid" 2>/dev/null || true
        fi
        if pid_matches_fixture "$pid" "$state_dir"; then
          failed=1
        fi
      fi
    fi
  done
  rm -f "$state_dir/ready" || failed=1
  remove_system_firewall_rules || failed=1
  if nft list table inet "$nft_table" >/dev/null 2>&1; then
    nft delete table inet "$nft_table" >/dev/null 2>&1 || true
  fi
  if nft list table inet "$nft_table" >/dev/null 2>&1; then
    failed=1
  fi
  # Keep the global forwarding lease lock held until this lease's interface
  # is gone, so another fixture cannot observe a half-completed stop.
  release_ip_forward_lease_and_delete_interface || failed=1
  assert_fixture_clean || failed=1
  return "$failed"
}

install_fixture_cleanup_trap() {
  trap 'status=$?; stop_fixture; exit "$status"' ERR HUP INT TERM
}

fixture_ready() {
  local dns_pid echo_pid capture_pid server_ip through_dns_ip
  server_ip="${NVPN_MOBILE_WG_TUNNEL_CIDR%/*}"
  through_dns_ip="${NVPN_MOBILE_WG_THROUGH_DNS_IP:?}"
  [[ -s "$state_dir/dnsmasq.pid" \
    && -s "$state_dir/udp-echo.pid" \
    && -s "$state_dir/http-probe.pid" \
    && -s "$state_dir/tls-capture.pid" ]] || return 1
  dns_pid="$(<"$state_dir/dnsmasq.pid")"
  echo_pid="$(<"$state_dir/udp-echo.pid")"
  local http_pid
  http_pid="$(<"$state_dir/http-probe.pid")"
  capture_pid="$(<"$state_dir/tls-capture.pid")"
  pid_matches_fixture "$dns_pid" "$state_dir" \
    && pid_matches_fixture "$echo_pid" "$state_dir" \
    && pid_matches_fixture "$http_pid" "$state_dir" \
    && pid_matches_fixture "$capture_pid" "$state_dir" \
    && ip link show "$interface" >/dev/null 2>&1 \
    && wg show "$interface" >/dev/null 2>&1 \
    && wireguard_listener_ready \
    && nft list table inet "$nft_table" >/dev/null 2>&1 \
    && ss -H -lun | grep -Fq "$server_ip:53" \
    && ss -H -lun | grep -Fq "$through_dns_ip:53" \
    && ss -H -lun | grep -Fq "$server_ip:9" \
    && ss -H -ltn | grep -Fq "$server_ip:$NVPN_MOBILE_WG_HTTP_PROBE_PORT"
}

counter_packets() {
  local counter="$1"
  nft list counter inet "$nft_table" "$counter" \
    | awk '/packets/ {
        for (field = 1; field <= NF; field++) {
          if ($field == "packets") {
            value = $(field + 1)
            gsub(/[^0-9]/, "", value)
            print value + 0
            exit
          }
        }
      }'
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

case "$action" in
  start)
    : "${NVPN_MOBILE_WG_SERVER_PRIVATE_KEY_FILE:?server key is required}"
    : "${NVPN_MOBILE_WG_CLIENT_PUBLIC_KEY_FILE:?client public key is required}"
    : "${NVPN_MOBILE_WG_TUNNEL_CIDR:?tunnel CIDR is required}"
    : "${NVPN_MOBILE_WG_CLIENT_IP:?client address is required}"
    : "${NVPN_MOBILE_WG_THROUGH_DNS_IP:?through-exit DNS address is required}"
    : "${NVPN_MOBILE_WG_LISTEN_PORT:?listen port is required}"
    : "${NVPN_MOBILE_WG_DNS_NAME:?DNS fixture name is required}"
    : "${NVPN_MOBILE_WG_HTTP_PROBE_PORT:?HTTP fixture port is required}"
    : "${NVPN_MOBILE_WG_HTTP_TOKEN:?HTTP fixture token is required}"
    [[ "$NVPN_MOBILE_WG_LISTEN_PORT" =~ ^[1-9][0-9]{0,4}$ ]] \
      && (( NVPN_MOBILE_WG_LISTEN_PORT <= 65535 )) \
      || {
        echo "remote fixture listen port is invalid" >&2
        exit 2
      }
    for command in ip wg nft dnsmasq python3 ss flock tcpdump; do
      command -v "$command" >/dev/null 2>&1 \
        || { echo "remote fixture requires $command" >&2; exit 2; }
    done
    if ip link show "$interface" >/dev/null 2>&1 \
      || nft list table inet "$nft_table" >/dev/null 2>&1
    then
      echo "remote fixture interface or nft table already exists" >&2
      exit 1
    fi
    mkdir -p "$state_dir"
    chmod 700 "$state_dir"
    : >"$system_firewall_rules"
    install_fixture_cleanup_trap
    local_server_ip="${NVPN_MOBILE_WG_TUNNEL_CIDR%/*}"
    through_dns_ip="$NVPN_MOBILE_WG_THROUGH_DNS_IP"
    tunnel_subnet="$(
      python3 - "$NVPN_MOBILE_WG_TUNNEL_CIDR" <<'PY'
import ipaddress
import sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
    )"
    egress_interface="$(
      ip -4 route get 1.1.1.1 \
        | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
    )"
    [[ -n "$egress_interface" ]] \
      || { echo "remote fixture cannot resolve its public egress interface" >&2; exit 1; }

    ip link add "$interface" type wireguard
    ip address add "$NVPN_MOBILE_WG_TUNNEL_CIDR" dev "$interface"
    ip address add "$through_dns_ip/32" dev "$interface"
    cat "$NVPN_MOBILE_WG_SERVER_PRIVATE_KEY_FILE" \
      | wg set "$interface" \
        listen-port "$NVPN_MOBILE_WG_LISTEN_PORT" \
        private-key /dev/stdin \
        peer "$(tr -d '\r\n' <"$NVPN_MOBILE_WG_CLIENT_PUBLIC_KEY_FILE")" \
        allowed-ips "$NVPN_MOBILE_WG_CLIENT_IP/32"
    ip link set "$interface" up

    nft add table inet "$nft_table"
    nft add counter inet "$nft_table" forward_in
    nft add counter inet "$nft_table" forward_out
    nft add counter inet "$nft_table" dns_profile
    nft add counter inet "$nft_table" dns_through
    nft add counter inet "$nft_table" dns_forward
    nft add counter inet "$nft_table" http_probe
    nft add chain inet "$nft_table" input \
      '{ type filter hook input priority -10; policy accept; }'
    nft add chain inet "$nft_table" forward \
      '{ type filter hook forward priority -10; policy accept; }'
    nft add chain inet "$nft_table" postrouting \
      '{ type nat hook postrouting priority srcnat; policy accept; }'
    nft add rule inet "$nft_table" input \
      udp dport "$NVPN_MOBILE_WG_LISTEN_PORT" accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" ip daddr "$local_server_ip" \
      udp dport 53 counter name dns_profile accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" ip daddr "$local_server_ip" \
      tcp dport 53 counter name dns_profile accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" ip daddr "$through_dns_ip" \
      udp dport 53 counter name dns_through accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" ip daddr "$through_dns_ip" \
      tcp dport 53 counter name dns_through accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" udp dport '{ 9, 53 }' accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" tcp dport 53 accept
    nft add rule inet "$nft_table" input \
      iifname "$interface" tcp dport "$NVPN_MOBILE_WG_HTTP_PROBE_PORT" \
      counter name http_probe accept
    nft add rule inet "$nft_table" forward \
      iifname "$interface" udp dport 53 counter name dns_forward accept
    nft add rule inet "$nft_table" forward \
      iifname "$interface" tcp dport 53 counter name dns_forward accept
    nft add rule inet "$nft_table" forward \
      iifname "$interface" counter name forward_in accept
    nft add rule inet "$nft_table" forward \
      oifname "$interface" ct state established,related \
      counter name forward_out accept
    nft add rule inet "$nft_table" postrouting \
      ip saddr "$tunnel_subnet" oifname "$egress_interface" masquerade

    resolver_tls_capture_filter='tcp dst port 443 and (dst host 1.1.1.1 or dst host 1.0.0.1 or dst host 9.9.9.9 or dst host 149.112.112.112 or dst host 8.8.8.8 or dst host 8.8.4.4)'
    tcpdump -i "$interface" -nn -U -s 0 -C 1 -W 1 -Z root \
      -w "$state_dir/resolver-clienthello.pcap" "$resolver_tls_capture_filter" \
      >"$state_dir/tcpdump.log" 2>&1 &
    echo "$!" >"$state_dir/tls-capture.pid"
    # A separate accepting base chain cannot override a later host chain with
    # policy drop. Insert narrowly scoped, handle-tracked rules into the
    # standard system chains when present, then remove those exact handles.
    firewall_marker="nvpn-mobile-$interface"
    endpoint_inet_match=()
    case "$endpoint_family" in
      ipv4) endpoint_inet_match=(meta nfproto ipv4) ;;
      ipv6) endpoint_inet_match=(meta nfproto ipv6) ;;
      dns) ;;
    esac
    add_system_firewall_rule \
      inet filter input "$firewall_marker-input" \
      "${endpoint_inet_match[@]}" \
      udp dport "$NVPN_MOBILE_WG_LISTEN_PORT" accept
    if [[ "$endpoint_family" != "ipv6" ]]; then
      add_system_firewall_rule \
        ip filter INPUT "$firewall_marker-input-v4" \
        udp dport "$NVPN_MOBILE_WG_LISTEN_PORT" accept
    fi
    if [[ "$endpoint_family" != "ipv4" ]]; then
      add_system_firewall_rule \
        ip6 filter INPUT "$firewall_marker-input-v6" \
        udp dport "$NVPN_MOBILE_WG_LISTEN_PORT" accept
    fi
    add_system_firewall_rule \
      inet filter input "$firewall_marker-services" \
      meta nfproto ipv4 iifname "$interface" accept
    add_system_firewall_rule \
      ip filter INPUT "$firewall_marker-services-v4" \
      iifname "$interface" accept
    add_system_firewall_rule \
      inet filter forward "$firewall_marker-forward-in" \
      meta nfproto ipv4 iifname "$interface" accept
    add_system_firewall_rule \
      ip filter FORWARD "$firewall_marker-forward-in-v4" \
      iifname "$interface" accept
    add_system_firewall_rule \
      inet filter forward "$firewall_marker-forward-out" \
      meta nfproto ipv4 oifname "$interface" \
      ct state established,related accept
    add_system_firewall_rule \
      ip filter FORWARD "$firewall_marker-forward-out-v4" \
      oifname "$interface" ct state established,related accept
    acquire_ip_forward_lease

    dnsmasq \
      --bind-interfaces \
      --listen-address="$local_server_ip" \
      --listen-address="$through_dns_ip" \
      --no-hosts \
      --no-resolv \
      --server=1.1.1.1 \
      --server=8.8.8.8 \
      --address="/$NVPN_MOBILE_WG_DNS_NAME/$local_server_ip" \
      --log-queries \
      --log-facility="$state_dir/dns.log" \
      --pid-file="$state_dir/dnsmasq.pid"
    python3 "$script_dir/mobile-wireguard-udp-echo.py" \
      "$local_server_ip" 9 "$state_dir/udp-echo.pid" \
      >"$state_dir/udp-echo.log" 2>&1 &
    python3 "$script_dir/mobile-wireguard-http-probe.py" \
      "$local_server_ip" "$NVPN_MOBILE_WG_HTTP_PROBE_PORT" \
      "$state_dir/http-probe.pid" "$NVPN_MOBILE_WG_HTTP_TOKEN" \
      >"$state_dir/http-probe.log" 2>&1 &
    for _ in $(seq 1 50); do
      fixture_ready && {
        trap - ERR HUP INT TERM
        touch "$state_dir/ready"
        exit 0
      }
      sleep 0.1
    done
    echo "remote native fixture did not become ready" >&2
    stop_fixture
    trap - ERR HUP INT TERM
    exit 1
    ;;
  stop)
    stop_fixture
    ;;
  clean)
    assert_fixture_clean
    ;;
  ready)
    fixture_ready
    ;;
  wg-bytes)
    wg show "$interface" transfer \
      | awk '{ rx += $2; tx += $3 } END { printf "%d\t%d\n", rx, tx }'
    ;;
  forward-packets)
    counter_packets forward_in
    ;;
  through-dns-count)
    counter_packets dns_through
    ;;
  profile-dns-count)
    counter_packets dns_profile
    ;;
  forward-dns-count)
    counter_packets dns_forward
    ;;
  dns-evidence-snapshot)
    probe_host="${2:?DNS name is required}"
    query_count="$(grep -Fci "$probe_host" "$state_dir/dns.log" 2>/dev/null || true)"
    sni_counts="$(
      python3 "$script_dir/mobile-wireguard-tls-sni-count.py" \
        "$state_dir/resolver-clienthello.pcap" \
        cloudflare-dns.com dns.quad9.net dns.google
    )"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$query_count" \
      "$(counter_packets dns_profile)" \
      "$sni_counts" \
      "$(counter_packets dns_through)" \
      "$(counter_packets dns_forward)"
    ;;
  dns-count)
    grep -Fci "${2:?DNS name is required}" "$state_dir/dns.log" 2>/dev/null || true
    ;;
  *)
    echo "usage: mobile-wireguard-exit-remote-native.sh start|stop|clean|ready|wg-bytes|forward-packets|dns-count|profile-dns-count|through-dns-count|forward-dns-count|dns-evidence-snapshot" >&2
    exit 2
    ;;
esac
