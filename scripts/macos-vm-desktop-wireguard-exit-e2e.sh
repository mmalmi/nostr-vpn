#!/usr/bin/env bash
# Import the exact host-built macOS Release package, run its production nvpn
# binary in macos-utm, and use a one-shot WireGuard/DNS/NAT fixture in local
# Docker. The host Mac's routes and network services are never changed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-vm-imported-release.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"

load_release_env "$ROOT"
load_mobile_env "$ROOT"

SSH_HOST="${NVPN_MACOS_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_MACOS_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn"
HOST_PORT="${NVPN_MACOS_WG_FIXTURE_PORT:-51889}"
FIPS_CLIENT_LISTEN_PORT="${NVPN_MACOS_FIPS_CLIENT_LISTEN_PORT:-51990}"
TUNNEL_SERVER_IP="${NVPN_MACOS_WG_SERVER_IP:-10.99.79.1}"
TUNNEL_CLIENT_IP="${NVPN_MACOS_WG_CLIENT_IP:-10.99.79.2}"
THROUGH_DNS_IP="${NVPN_MACOS_WG_THROUGH_DNS_IP:-10.99.79.53}"
DNS_NAME="${NVPN_MACOS_WG_DNS_NAME:-macos-wireguard-exit.nvpn-e2e.test}"
# Use the fixture's already-reserved numeric port by default. WireGuard owns
# UDP while the captured HTTP probe owns TCP, so this avoids colliding with
# unrelated long-lived services on conventional ports such as 8080.
HTTP_PROBE_PORT="${NVPN_MACOS_WG_HTTP_PROBE_PORT:-$HOST_PORT}"
HTTP_PROBE_TOKEN="${NVPN_MACOS_WG_HTTP_TOKEN:-nvpn-macos-$PPID-$$-$RANDOM}"
PRIMARY_SERVICE="${NVPN_MACOS_PRIMARY_NETWORK_SERVICE:-Ethernet}"
SECONDARY_SERVICE="${NVPN_MACOS_SECONDARY_NETWORK_SERVICE:-Roaming Underlay}"
PRIMARY_IFACE="${NVPN_MACOS_PRIMARY_INTERFACE:-en0}"
SECONDARY_IFACE="${NVPN_MACOS_SECONDARY_INTERFACE:-en2}"
RECOVERY_DEADLINE_MS="${NVPN_MACOS_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"
FIPS_NETWORK_ID="${NVPN_MACOS_FIPS_NETWORK_ID:-macos-release-roaming-$PPID-$$}"
IMAGE="${NVPN_MACOS_WG_FIXTURE_IMAGE:-nostr-vpn-macos-wireguard-exit-e2e}"
CONTAINER="${NVPN_MACOS_WG_FIXTURE_CONTAINER:-nostr-vpn-macos-wireguard-exit-e2e-$$}"
TARGET_CONTAINER="${NVPN_MACOS_WG_TARGET_CONTAINER:-$CONTAINER-target}"
# The numeric IPv4 endpoint must follow the split default in the guest, which
# proves the production Apple IP_BOUND_IF path and endpoint bypass ownership.
FIXTURE_HOST="${NVPN_MACOS_WG_FIXTURE_HOST_IP:-}"
FIXTURE_DIR=""
REMOTE_DIR=""
SECONDARY_IP=""
FORWARDED_PROBE_IP=""
PACKAGE=""
ARTIFACT_DIR="${NVPN_MACOS_NETWORK_ARTIFACT_DIR:-${ARTIFACT_ROOT:-$ROOT/artifacts}/macos-release-network-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
PRIMARY_CONTROL_PATH="/tmp/nvpn-macos-network-primary-$PPID-$$"
SECONDARY_CONTROL_PATH="/tmp/nvpn-macos-network-secondary-$PPID-$$"
MOBILE_WG_FIXTURE_REMOTE_MODE=""
MOBILE_WG_FIXTURE_ENDPOINT_FAMILY=""
WIREGUARD_ENDPOINT_AUTHORITY=""
MACOS_NPUB=""
MACOS_TUNNEL_IP=""
APP_GIT_SHA=""
APP_GIT_TREE=""
INSTALLED_STATE_SNAPSHOT_STARTED=0
GUEST_NETWORK_CLEANED=0
INSTALLED_STATE_RESTORED=0

fail() {
  echo "macOS VM Release network gate failed: $*" >&2
  return 1
}

valid_npub() {
  [[ "$1" =~ ^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]
}

[[ -n "$SSH_HOST" ]] \
  || { echo "set NVPN_MACOS_SSH_HOST or pass the macOS VM SSH target" >&2; exit 2; }
macos_vm_require_isolated_target "$SSH_HOST"
for command in docker curl ssh scp wg; do
  command -v "$command" >/dev/null 2>&1 \
    || { echo "macOS Release network gate requires $command" >&2; exit 2; }
done
for port in "$HOST_PORT" "$FIPS_CLIENT_LISTEN_PORT"; do
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && ((port <= 65535)) \
    || { echo "macOS Release network gate received an invalid UDP port" >&2; exit 2; }
done
[[ "$HOST_PORT" != "$FIPS_CLIENT_LISTEN_PORT" ]] \
  || { echo "WireGuard and client FIPS ports must be distinct" >&2; exit 2; }

python3 - "$TUNNEL_SERVER_IP" "$TUNNEL_CLIENT_IP" "$THROUGH_DNS_IP" <<'PY'
import ipaddress
import sys

server, client, through = map(ipaddress.ip_address, sys.argv[1:])
network = ipaddress.ip_network(f"{server}/24", strict=False)
if (
    any(address.version != 4 for address in (server, client, through))
    or through not in network
    or len({server, client, through}) != 3
):
    raise SystemExit(
        "WireGuard server, client, and through-exit DNS addresses must be "
        "distinct IPv4 addresses in one /24"
    )
PY

ssh_args() {
  local lane="$1"
  printf '%s\n' \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    -o ConnectionAttempts=1 \
    -o ServerAliveInterval=2 \
    -o ServerAliveCountMax=2 \
    -o ControlMaster=auto \
    -o ControlPersist=45
  if [[ "$lane" == "secondary" ]]; then
    printf '%s\n' \
      -o "ControlPath=$SECONDARY_CONTROL_PATH" \
      -o "Hostname=$SECONDARY_IP" \
      -o "HostKeyAlias=${SSH_HOST#*@}"
  else
    printf '%s\n' -o "ControlPath=$PRIMARY_CONTROL_PATH"
  fi
}

remote_shell() {
  local lane="$1" command="$2"
  local -a options=()
  while IFS= read -r option; do
    options+=("$option")
  done < <(ssh_args "$lane")
  ssh "${options[@]}" "$SSH_HOST" "$command"
}

remote_phase() {
  local lane="$1" action="$2"
  local -a options=() remote_env=()
  local remote_command quoted assignment
  while IFS= read -r option; do
    options+=("$option")
  done < <(ssh_args "$lane")
  remote_env=(
    NVPN_MACOS_VM_IMPORT_ONLY=1
    RUST_LOG=info,nvpn::secure_dns_runtime=debug
    "NVPN_E2E_BINARY=$PACKAGE/Nostr VPN.app/Contents/Resources/nvpn"
    "NVPN_MACOS_NETWORK_STATE_DIR=$REMOTE_DIR"
    "NVPN_E2E_CONFIG=$REMOTE_DIR/config.toml"
    "NVPN_WG_EXIT_CONFIG_FILE=$REMOTE_DIR/client.conf"
    "NVPN_MACOS_WG_ENDPOINT_HOST=$FIXTURE_HOST"
    "NVPN_MACOS_WG_ENDPOINT_FAMILY=$MOBILE_WG_FIXTURE_ENDPOINT_FAMILY"
    "NVPN_MACOS_WG_SERVER_IP=$TUNNEL_SERVER_IP"
    "NVPN_MACOS_CAPTURED_PROBE_URL=http://$FORWARDED_PROBE_IP:$HTTP_PROBE_PORT/$HTTP_PROBE_TOKEN"
    "NVPN_MACOS_CAPTURED_PROBE_TOKEN=$HTTP_PROBE_TOKEN"
    "NVPN_MACOS_PRIMARY_NETWORK_SERVICE=$PRIMARY_SERVICE"
    "NVPN_MACOS_SECONDARY_NETWORK_SERVICE=$SECONDARY_SERVICE"
    "NVPN_MACOS_PRIMARY_INTERFACE=$PRIMARY_IFACE"
    "NVPN_MACOS_SECONDARY_INTERFACE=$SECONDARY_IFACE"
    "NVPN_MACOS_UNDERLAY_RECOVERY_DEADLINE_MS=$RECOVERY_DEADLINE_MS"
    "NVPN_MACOS_FIPS_NETWORK_ID=$FIPS_NETWORK_ID"
    "NVPN_MACOS_FIPS_CLIENT_LISTEN_PORT=$FIPS_CLIENT_LISTEN_PORT"
    "NVPN_MACOS_FIPS_EXPECTED_REV=${RELEASE_JOIN_FIPS_SHA:0:10}"
    "NVPN_MACOS_DNS_LABEL=${DNS_CASE_LABEL:-direct-baseline}"
    "NVPN_MACOS_DNS_MODE=${DNS_CASE_MODE:-automatic}"
    "NVPN_MACOS_DNS_PROVIDER=${DNS_CASE_PROVIDER:-cloudflare}"
    "NVPN_MACOS_DNS_CUSTOM_URL=${DNS_CASE_CUSTOM_URL:-}"
    "NVPN_MACOS_DNS_BOOTSTRAP_IPS=${DNS_CASE_BOOTSTRAP_IPS:-}"
    "NVPN_MACOS_DNS_THROUGH_SERVERS=${DNS_CASE_THROUGH_SERVERS:-}"
    "NVPN_MACOS_DNS_PROBE_HOST=${DNS_CASE_PROBE_HOST:-example.com}"
    "NVPN_MACOS_DNS_EXPECTED_IP=${DNS_CASE_EXPECTED_IP:-}"
  )
  printf -v quoted '%q' "$GUEST_REPO"
  remote_command="cd $quoted && env"
  for assignment in "${remote_env[@]}"; do
    printf -v quoted '%q' "$assignment"
    remote_command+=" $quoted"
  done
  printf -v quoted '%q' "$action"
  remote_command+=" ./scripts/e2e-macos-release-network.sh $quoted"
  ssh "${options[@]}" "$SSH_HOST" "$remote_command"
}

poll_remote_underlay_status() {
  remote_shell secondary "
    for ignored in {1..300}; do
      phase_result=\$(cat '$REMOTE_DIR/underlay.status' 2>/dev/null || true)
      case \"\$phase_result\" in
        pass|fail:*) printf '%s\\n' \"\$phase_result\"; exit 0 ;;
      esac
      sleep 0.1
    done
    echo timeout
  "
}

wait_for_fixture_dns_quiet() {
  local probe_host="$1" previous current
  local remaining=10
  previous="$(
    mobile_wg_fixture_dns_evidence_snapshot "$CONTAINER" "$probe_host"
  )" || return 1
  while ((remaining > 0)); do
    sleep 1
    current="$(
      mobile_wg_fixture_dns_evidence_snapshot "$CONTAINER" "$probe_host"
    )" || return 1
    if [[ "$current" == "$previous" ]]; then
      printf '%s\n' "$current"
      return 0
    fi
    previous="$current"
    remaining=$((remaining - 1))
  done
  echo "fixture DNS counters did not quiesce after policy transition" >&2
  return 1
}

copy_guest_results() {
  [[ -n "$REMOTE_DIR" ]] || return 0
  mkdir -p "$ARTIFACT_DIR"
  local lane=primary
  [[ -n "$SECONDARY_IP" ]] && lane=secondary
  local -a options=()
  while IFS= read -r option; do
    options+=("$option")
  done < <(ssh_args "$lane")
  scp -q "${options[@]}" -r \
    "$SSH_HOST:$REMOTE_DIR/results/." "$ARTIFACT_DIR/"
}

capture_fixture_failure() {
  mkdir -p "$ARTIFACT_DIR"
  {
    printf 'wireguard_bytes='
    mobile_wg_fixture_wg_bytes "$CONTAINER"
    printf 'forward_packets='
    mobile_wg_fixture_forward_packets "$CONTAINER"
  } >"$ARTIFACT_DIR/fixture-failure-counters.txt" 2>&1 || true
  if [[ "$MOBILE_WG_FIXTURE_REMOTE_MODE" == "native" ]]; then
    mobile_wg_fixture_logs "$CONTAINER" \
      >"$ARTIFACT_DIR/fixture-failure-logs.txt" 2>&1 || true
    return
  fi
  mobile_wg_fixture_docker exec "$CONTAINER" wg show \
    >"$ARTIFACT_DIR/fixture-failure-wireguard.txt" 2>&1 || true
  mobile_wg_fixture_docker exec "$CONTAINER" ip -4 route show table all \
    >"$ARTIFACT_DIR/fixture-failure-routes.txt" 2>&1 || true
  mobile_wg_fixture_docker exec "$CONTAINER" iptables-save -c \
    >"$ARTIFACT_DIR/fixture-failure-iptables.txt" 2>&1 || true
  mobile_wg_fixture_docker exec "$CONTAINER" \
    tcpdump -nn -tttt -r /fixture/wg0-all.pcap \
    >"$ARTIFACT_DIR/fixture-failure-packets.txt" 2>&1 || true
  mobile_wg_fixture_logs "$CONTAINER" \
    >"$ARTIFACT_DIR/fixture-failure-logs.txt" 2>&1 || true
  mobile_wg_fixture_docker logs "$TARGET_CONTAINER" \
    >"$ARTIFACT_DIR/fixture-failure-target-logs.txt" 2>&1 || true
}

remove_forward_target() {
  [[ -n "$TARGET_CONTAINER" ]] || return 0
  if mobile_wg_fixture_docker container inspect "$TARGET_CONTAINER" \
    >/dev/null 2>&1
  then
    mobile_wg_fixture_docker rm -f "$TARGET_CONTAINER" >/dev/null || return 1
  fi
  ! mobile_wg_fixture_docker container inspect "$TARGET_CONTAINER" \
    >/dev/null 2>&1
}

remove_remote_dir() {
  [[ -n "$REMOTE_DIR" ]] || return 0
  case "$REMOTE_DIR" in
    /tmp/nvpn-macos-release-network.*) ;;
    *) fail "refusing to remove an unsafe macOS guest state path" ;;
  esac
  local lane=primary
  [[ -n "$SECONDARY_IP" ]] && lane=secondary
  local quoted
  printf -v quoted '%q' "$REMOTE_DIR"
  remote_shell "$lane" \
    "test -d $quoted && test ! -L $quoted \
      && sudo -n /bin/rm -rf -- $quoted" >/dev/null
  remote_shell "$lane" "test ! -e $quoted"
  REMOTE_DIR=""
}

close_ssh_controls() {
  ssh -o "ControlPath=$PRIMARY_CONTROL_PATH" -O exit "$SSH_HOST" \
    >/dev/null 2>&1 || true
  if [[ -n "$SECONDARY_IP" ]]; then
    ssh -o "ControlPath=$SECONDARY_CONTROL_PATH" \
      -o "Hostname=$SECONDARY_IP" \
      -o "HostKeyAlias=${SSH_HOST#*@}" \
      -O exit "$SSH_HOST" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  local status="$?" cleanup_failed=0
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 && "$MOBILE_WG_FIXTURE_STARTED" -eq 1 ]]; then
    capture_fixture_failure
  fi
  if [[ -n "$REMOTE_DIR" ]]; then
    local lane=primary
    [[ -n "$SECONDARY_IP" ]] && lane=secondary
    if [[ "$GUEST_NETWORK_CLEANED" -eq 1 ]]; then
      :
    elif remote_phase "$lane" cleanup; then
      GUEST_NETWORK_CLEANED=1
    else
      echo "macOS guest production cleanup failed" >&2
      cleanup_failed=1
    fi
    if [[ "$INSTALLED_STATE_SNAPSHOT_STARTED" -eq 1 \
      && "$INSTALLED_STATE_RESTORED" -eq 0 ]]
    then
      if remote_phase "$lane" restore-installed-state; then
        INSTALLED_STATE_RESTORED=1
      else
        echo "preexisting macOS installed state could not be restored" >&2
        cleanup_failed=1
      fi
    fi
    if ! copy_guest_results; then
      echo "macOS guest network receipts could not be copied" >&2
      cleanup_failed=1
    fi
    if ! remove_remote_dir; then
      echo "macOS guest private fixture state survived cleanup" >&2
      cleanup_failed=1
    fi
  fi
  if remove_forward_target; then
    :
  else
    cleanup_failed=1
  fi
  if mobile_wg_fixture_cleanup "$CONTAINER" "$IMAGE"; then
    :
  else
    cleanup_failed=1
  fi
  if [[ -n "$FIXTURE_DIR" ]]; then
    rm -rf "$FIXTURE_DIR"
    [[ ! -e "$FIXTURE_DIR" ]] || cleanup_failed=1
    FIXTURE_DIR=""
  fi
  close_ssh_controls
  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

transfer_total() {
  awk '{ print ($1 + 0) + ($2 + 0) }'
}

assert_increased() {
  local label="$1" before="$2" after="$3"
  [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ \
    && "$after" -gt "$before" ]] \
    || fail "$label did not increase ($before->$after)"
}

parse_key_value() {
  local key="$1"
  awk -F= -v key="$key" \
    '$1 == key { value = substr($0, length(key) + 2) } END { print value }'
}

release_join_require_clean_fips
APP_GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
APP_GIT_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"

macos_vm_prepare_or_verify_imported_release "$ROOT" "$SSH_HOST"
PACKAGE="$(macos_vm_imported_release_package "$GUEST_REPO")"

if [[ -z "$FIXTURE_HOST" ]]; then
  FIXTURE_HOST="$(ipconfig getifaddr en0 2>/dev/null || true)"
fi
ENDPOINT_FIELDS="$(
  mobile_wg_endpoint_fields "$FIXTURE_HOST" "$HOST_PORT"
)" || fail "local WireGuard fixture endpoint is malformed"
IFS=$'\t' read -r \
  MOBILE_WG_FIXTURE_ENDPOINT_FAMILY \
  FIXTURE_HOST \
  WIREGUARD_ENDPOINT_AUTHORITY <<<"$ENDPOINT_FIELDS"
[[ "$MOBILE_WG_FIXTURE_ENDPOINT_FAMILY" == "ipv4" ]] \
  || fail "macOS underlay gate requires a reachable numeric IPv4 WireGuard endpoint"
unset NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST
unset NVPN_MOBILE_WG_EXIT_REMOTE_MODE
export NVPN_MOBILE_WG_EXIT_HOST_IP="$FIXTURE_HOST"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-wg-exit.XXXXXX")"
chmod 700 "$FIXTURE_DIR"
umask 077
wg genkey >"$FIXTURE_DIR/server.key"
wg pubkey <"$FIXTURE_DIR/server.key" >"$FIXTURE_DIR/server.pub"
wg genkey >"$FIXTURE_DIR/client.key"
wg pubkey <"$FIXTURE_DIR/client.key" >"$FIXTURE_DIR/client.pub"

mobile_wg_fixture_initialize "$ROOT" "$FIXTURE_DIR"
mobile_wg_fixture_assert_available "$CONTAINER" "$HOST_PORT"
mobile_wg_fixture_build "$ROOT" "$IMAGE" 0
cat >"$FIXTURE_DIR/client.conf" <<EOF
[Interface]
PrivateKey = $(<"$FIXTURE_DIR/client.key")
Address = $TUNNEL_CLIENT_IP/32
DNS = $TUNNEL_SERVER_IP
MTU = 1280

[Peer]
PublicKey = $(<"$FIXTURE_DIR/server.pub")
Endpoint = $WIREGUARD_ENDPOINT_AUTHORITY
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 2
EOF
grep -Fxq "DNS = $TUNNEL_SERVER_IP" "$FIXTURE_DIR/client.conf" \
  || fail "Automatic/profile WireGuard config lost the fixture DNS server"

mobile_wg_fixture_run "$IMAGE" "$CONTAINER" "$MOBILE_WG_FIXTURE_VOLUME_DIR"
for _ in $(seq 1 100); do
  mobile_wg_fixture_ready "$CONTAINER" >/dev/null 2>&1 && break
  mobile_wg_fixture_running "$CONTAINER" \
    || fail "local fixture stopped during readiness"
  sleep 0.1
done
mobile_wg_fixture_ready "$CONTAINER" \
  || { mobile_wg_fixture_logs "$CONTAINER" >&2; fail "local fixture is not ready"; }

mobile_wg_fixture_docker container inspect "$TARGET_CONTAINER" \
  >/dev/null 2>&1 \
  && fail "local forwarded target container name is already in use"
mobile_wg_fixture_docker run -d \
  --name "$TARGET_CONTAINER" \
  --entrypoint python3 \
  "$IMAGE" \
  /usr/local/bin/mobile-wireguard-http-probe.py \
  0.0.0.0 "$HTTP_PROBE_PORT" /tmp/http-probe.pid "$HTTP_PROBE_TOKEN" \
  >/dev/null
for _ in $(seq 1 50); do
  mobile_wg_fixture_docker exec "$TARGET_CONTAINER" \
    test -s /tmp/http-probe.pid >/dev/null 2>&1 && break
  sleep 0.1
done
mobile_wg_fixture_docker exec "$TARGET_CONTAINER" \
  test -s /tmp/http-probe.pid \
  || fail "local forwarded target did not become ready"
FORWARDED_PROBE_IP="$(
  mobile_wg_fixture_docker inspect \
    -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$TARGET_CONTAINER"
)"
[[ "$FORWARDED_PROBE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "local forwarded target has no Docker IPv4 address"
mobile_wg_fixture_docker exec "$CONTAINER" python3 - \
  "http://$FORWARDED_PROBE_IP:$HTTP_PROBE_PORT/$HTTP_PROBE_TOKEN" \
  "$HTTP_PROBE_TOKEN" <<'PY'
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    body = response.read().decode()
if sys.argv[2] not in body:
    raise SystemExit("forwarded target returned the wrong receipt")
PY

REMOTE_DIR="$(
  remote_shell primary 'mktemp -d /tmp/nvpn-macos-release-network.XXXXXX'
)"
case "$REMOTE_DIR" in
  /tmp/nvpn-macos-release-network.*) ;;
  *) fail "macos-utm returned an unsafe temporary path" ;;
esac
remote_shell primary "chmod 700 '$REMOTE_DIR'"
scp -q -o BatchMode=yes \
  -o "ControlPath=$PRIMARY_CONTROL_PATH" \
  "$FIXTURE_DIR/client.conf" "$SSH_HOST:$REMOTE_DIR/client.conf"

SECONDARY_IP="$(
  remote_shell primary \
    "/usr/sbin/networksetup -getinfo '$SECONDARY_SERVICE'" \
    | awk -F': ' '/^IP address:/ { print $2; exit }'
)"
[[ "$SECONDARY_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "could not resolve macos-utm's secondary guest address"
remote_shell secondary 'true'

mkdir -p "$ARTIFACT_DIR"
INSTALLED_STATE_SNAPSHOT_STARTED=1
remote_phase primary quiesce-installed-state
macos_identity_output="$(remote_phase primary initialize)"
printf '%s\n' "$macos_identity_output" \
  >"$ARTIFACT_DIR/macos-fips-identity.txt"
MACOS_NPUB="$(parse_key_value npub <<<"$macos_identity_output")"
MACOS_TUNNEL_IP="$(parse_key_value tunnel_ip <<<"$macos_identity_output")"
valid_npub "$MACOS_NPUB" \
  || fail "macos-utm returned an invalid imported-Release identity"
[[ -n "$MACOS_TUNNEL_IP" ]] \
  || fail "macos-utm returned no private tunnel address"
DNS_CASE_LABEL=direct-baseline
DNS_CASE_PROBE_HOST=example.com
remote_phase primary prepare

for DNS_CASE_LABEL in \
  automatic-profile cloudflare-doh quad9-doh custom-doh through-exit
do
  transition_probe_host=""
  IFS='|' read -r \
    DNS_CASE_MODE \
    DNS_CASE_PROVIDER \
    DNS_CASE_CUSTOM_URL \
    DNS_CASE_BOOTSTRAP_IPS \
    DNS_CASE_THROUGH_SERVERS \
    DNS_CASE_PROBE_HOST \
    DNS_CASE_EXPECTED_IP \
    evidence <<<"$(
      mobile_wg_dns_case_fields \
        "$DNS_CASE_LABEL" "$DNS_NAME" "$TUNNEL_SERVER_IP" "$THROUGH_DNS_IP"
    )"
  # Apply the new policy once before opening its counter window. Changing DNS
  # policy can legitimately finish queries that were already in flight on the
  # old resolver; counting those against the new policy produces a false leak.
  # The second identical production probe below is the measured one, and the
  # forbidden-path assertions remain strict inside that quiescent window.
  remote_phase primary dns-case
  transition_probe_host="$DNS_CASE_PROBE_HOST"
  wait_for_fixture_dns_quiet "$transition_probe_host" >/dev/null \
    || fail "$DNS_CASE_LABEL DNS counters did not settle after transition"
  DNS_CASE_PROBE_HOST="measure-$PPID-$RANDOM.$transition_probe_host"
  before_evidence="$(
    mobile_wg_fixture_dns_evidence_snapshot \
      "$CONTAINER" "$DNS_CASE_PROBE_HOST"
  )"
  before_transfer="$(
    mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
  )"
  before_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
  remote_phase primary dns-case
  after_transfer="$(
    mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
  )"
  after_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
  after_evidence="$(
    mobile_wg_fixture_wait_for_dns_case_evidence \
      macOS "$DNS_CASE_LABEL" "$evidence" "$before_evidence" \
      "$CONTAINER" "$DNS_CASE_PROBE_HOST" 8
  )"
  assert_increased "$DNS_CASE_LABEL WireGuard bytes" \
    "$before_transfer" "$after_transfer"
  assert_increased "$DNS_CASE_LABEL forwarded packets" \
    "$before_forward" "$after_forward"
  mobile_wg_fixture_assert_dns_case_evidence \
    macOS "$DNS_CASE_LABEL" "$evidence" "$before_evidence" "$after_evidence"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$DNS_CASE_LABEL" \
    "$before_transfer" "$after_transfer" \
    "$before_forward" "$after_forward" \
    "$before_evidence" "$after_evidence" \
    >>"$ARTIFACT_DIR/fixture-dns-counters.tsv"
done

before_transfer="$(
  mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
)"
before_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
remote_phase primary underlay-start
underlay_status="$(poll_remote_underlay_status)"
if [[ "$underlay_status" != "pass" ]]; then
  remote_shell secondary \
    "tail -n 120 '$REMOTE_DIR/results/underlay-run.log'" >&2 || true
  fail "macos-utm underlay action ended with $underlay_status"
fi
after_transfer="$(
  mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
)"
after_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
assert_increased "macOS underlay WireGuard bytes" \
  "$before_transfer" "$after_transfer"
assert_increased "macOS underlay forwarded packets" \
  "$before_forward" "$after_forward"

before_transfer="$(
  mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
)"
before_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
remote_phase secondary crash-restart
after_transfer="$(
  mobile_wg_fixture_wg_bytes "$CONTAINER" | transfer_total
)"
after_forward="$(mobile_wg_fixture_forward_packets "$CONTAINER")"
assert_increased "macOS SIGKILL/restart WireGuard bytes" \
  "$before_transfer" "$after_transfer"
assert_increased "macOS SIGKILL/restart forwarded packets" \
  "$before_forward" "$after_forward"

DNS_CASE_LABEL=direct-restore
DNS_CASE_MODE=automatic
DNS_CASE_PROVIDER=cloudflare
DNS_CASE_CUSTOM_URL=""
DNS_CASE_BOOTSTRAP_IPS=""
DNS_CASE_THROUGH_SERVERS=""
DNS_CASE_PROBE_HOST=example.com
DNS_CASE_EXPECTED_IP=""
remote_phase secondary direct
remote_phase secondary cleanup
GUEST_NETWORK_CLEANED=1
remote_phase secondary restore-installed-state
INSTALLED_STATE_RESTORED=1
copy_guest_results
remove_remote_dir
remove_forward_target
mobile_wg_fixture_cleanup "$CONTAINER" "$IMAGE"

echo "MACOS_VM_WIREGUARD_EXIT_E2E_OK"
echo "Real Direct -> local IPv4 WireGuard exit -> two-underlay handoff -> SIGKILL/restart -> Direct and all five DNS modes passed"
